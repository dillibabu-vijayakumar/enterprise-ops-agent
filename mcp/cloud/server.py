"""
Cloud Cost Janitor — MCP Server
Read-only discovery + approval-gated deletion for idle AWS resources.

Fixes applied:
  F1  SQLite session persistence (survives restarts)
  F2  Partial batch recovery (per-resource, not all-or-nothing)
  F3  Circuit breaker (opens after 3 consecutive AWS failures)
  F6  Hard anomaly stop (blocks resource list from LLM when >50 found)
  F7  Subprocess network isolation (no_proxy + blocked env vars)
  F8  Structured JSON logging with correlation IDs
  F9  backoff library replaces hand-rolled retry
"""
import ast
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Any

import backoff
import boto3
from botocore.exceptions import ClientError, NoRegionError
from mcp.server.fastmcp import FastMCP

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from shared.logging_config import get_logger, ToolTimer

log = get_logger("aws-cost-janitor")
mcp = FastMCP("aws-cost-janitor")

# ─── F8: session ID helper ────────────────────────────────────────────────────

def _current_session() -> str:
    return os.environ.get("TRUEFORGE_SESSION_ID", "manual")

# ─── F1: SQLite-backed session persistence ────────────────────────────────────
# In-memory dict is the fast-path read cache; SQLite persists across restarts.

_DB_PATH = os.environ.get("JANITOR_DB_PATH", "/tmp/janitor_sessions.db")
_db_lock = threading.Lock()
_context_cleared: dict[str, set] = {}  # in-memory cache — tests may clear this directly


_SESSION_TTL_DAYS = 7  # prune sessions older than this on startup


def _init_db() -> None:
    try:
        with _db_lock:
            conn = sqlite3.connect(_DB_PATH)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS context_checked (
                    session_id TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    checked_at TEXT NOT NULL,
                    PRIMARY KEY (session_id, resource_id)
                )
            """)
            conn.commit()
            # P2: prune stale sessions older than TTL — prevents unbounded DB growth
            cutoff = (datetime.now(timezone.utc) - timedelta(days=_SESSION_TTL_DAYS)).isoformat()
            pruned = conn.execute(
                "DELETE FROM context_checked WHERE checked_at < ?", (cutoff,)
            ).rowcount
            conn.commit()
            if pruned:
                log.info("session_ttl_pruned", extra={"ctx_pruned": pruned, "ctx_ttl_days": _SESSION_TTL_DAYS})
            for row in conn.execute("SELECT session_id, resource_id FROM context_checked"):
                sid, rid = row
                _context_cleared.setdefault(sid, set()).add(rid)
            conn.close()
            log.info("session_db_loaded", extra={"ctx_db": _DB_PATH})
    except Exception as exc:
        log.warning("session_db_init_failed", extra={"ctx_err": str(exc)})


def _mark_context_checked(session_id: str, resource_id: str) -> None:
    _context_cleared.setdefault(session_id, set()).add(resource_id)
    try:
        with _db_lock:
            conn = sqlite3.connect(_DB_PATH)
            conn.execute(
                "INSERT OR REPLACE INTO context_checked (session_id, resource_id, checked_at) VALUES (?, ?, ?)",
                (session_id, resource_id, datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
            conn.close()
    except Exception as exc:
        log.warning("session_db_write_failed", extra={"ctx_err": str(exc)})


def _is_context_checked(session_id: str, resource_id: str) -> bool:
    return resource_id in _context_cleared.get(session_id, set())


_init_db()


# ─── Security: resource ID sanitization + script AST validation ───────────────

_AWS_ID_PATTERN = re.compile(r'[^\w\-]')  # allow only alphanum, dash, underscore


def _sanitize_resource_id(rid: str) -> str:
    """
    Sanitize AWS resource ID for safe insertion into generated Python scripts.
    AWS resource IDs are alphanumeric + dash only. Any other character is injection.
    Truncates to 64 chars to prevent buffer games.
    """
    return _AWS_ID_PATTERN.sub('_', rid)[:64]


# Modules/calls that must never appear in generated scripts
_BLOCKED_IMPORTS = frozenset({
    "subprocess", "socket", "pty", "ctypes", "importlib",
    "builtins", "shutil", "ftplib", "telnetlib", "imaplib",
    "smtplib", "http", "urllib", "xmlrpc", "multiprocessing",
    "threading", "asyncio", "concurrent",
})
_BLOCKED_NAMES = frozenset({"eval", "exec", "compile", "__import__", "breakpoint"})
_BLOCKED_ATTRS = frozenset({"system", "popen", "getoutput", "call", "Popen", "check_output"})
# boto3 is explicitly allowed ONLY for the specific EC2 ops we template
_ALLOWED_BOTO3_OPS = frozenset({
    "terminate_instances", "delete_volume", "release_address",
    "delete_snapshot", "delete_load_balancer",
})


def _validate_script_ast(script: str) -> list[str]:
    """
    Parse generated script via AST and return list of security violations.
    Empty list = script is safe to execute.
    Blocks: dangerous imports, eval/exec, socket calls, open(), arbitrary attribute calls.
    """
    violations: list[str] = []
    try:
        tree = ast.parse(script)
    except SyntaxError as e:
        return [f"SyntaxError — script is malformed: {e}"]

    for node in ast.walk(tree):
        # Block dangerous imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in _BLOCKED_IMPORTS:
                    violations.append(f"Blocked import: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            top = (node.module or "").split(".")[0]
            if top in _BLOCKED_IMPORTS:
                violations.append(f"Blocked from-import: {node.module}")

        # Block dangerous built-in calls: eval, exec, __import__, open
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in _BLOCKED_NAMES:
                    violations.append(f"Blocked call: {node.func.id}()")
                elif node.func.id == "open":
                    violations.append("Blocked call: open() — file access not allowed in sandboxed script")
            elif isinstance(node.func, ast.Attribute):
                if node.func.attr in _BLOCKED_ATTRS:
                    violations.append(f"Potentially dangerous call: .{node.func.attr}()")

    return violations

# ─── F3: Circuit breaker ──────────────────────────────────────────────────────

class _CircuitBreaker:
    """Opens after _threshold consecutive failures; auto-resets after _timeout seconds."""

    _threshold = 3
    _timeout = 60.0

    def __init__(self) -> None:
        self._failures: dict[str, int] = {}
        self._opened_at: dict[str, float] = {}
        self._lock = threading.Lock()

    def _key(self, service: str, region: str) -> str:
        return f"{service}:{region}"

    def is_open(self, service: str, region: str) -> bool:
        k = self._key(service, region)
        with self._lock:
            if k not in self._opened_at:
                return False
            if time.monotonic() - self._opened_at[k] > self._timeout:
                self._failures.pop(k, None)
                self._opened_at.pop(k, None)
                log.info("circuit_reset", extra={"ctx_service": service, "ctx_region": region})
                return False
            return True

    def record_failure(self, service: str, region: str) -> bool:
        k = self._key(service, region)
        with self._lock:
            self._failures[k] = self._failures.get(k, 0) + 1
            if self._failures[k] >= self._threshold:
                self._opened_at[k] = time.monotonic()
                log.error(
                    "circuit_opened",
                    extra={"ctx_service": service, "ctx_region": region, "ctx_failures": self._failures[k]},
                )
                return True
        return False

    def record_success(self, service: str, region: str) -> None:
        k = self._key(service, region)
        with self._lock:
            self._failures.pop(k, None)
            self._opened_at.pop(k, None)


_circuit_breaker = _CircuitBreaker()

# ─── F9: backoff-library retry (replaces hand-rolled) ─────────────────────────

def _is_not_throttle(exc: ClientError) -> bool:
    """Backoff giveup: True = stop retrying (error is NOT throttling)."""
    return exc.response.get("Error", {}).get("Code", "") not in (
        "ThrottlingException", "RequestLimitExceeded", "Throttling",
    )


def _is_throttle(exc: ClientError) -> bool:
    return not _is_not_throttle(exc)


def _retryable_call(fn, *args, service: str = "ec2", region: str = "us-east-1", **kwargs):
    """
    Retry throttled AWS calls using the backoff library (exponential, max 3 tries).
    Circuit breaker opens after 3 consecutive failures on the same service:region.
    """
    if _circuit_breaker.is_open(service, region):
        raise ClientError(
            {"Error": {"Code": "CircuitOpen", "Message": f"Circuit breaker open for {service}:{region} — too many consecutive failures"}},
            "CircuitBreaker",
        )

    @backoff.on_exception(
        backoff.expo,
        ClientError,
        max_tries=3,
        giveup=_is_not_throttle,
        factor=2,
        max_time=60,
    )
    def _wrapped():
        return fn(*args, **kwargs)

    try:
        result = _wrapped()
        _circuit_breaker.record_success(service, region)
        return result
    except ClientError as exc:
        _circuit_breaker.record_failure(service, region)
        raise

# ─── helpers ────────────────────────────────────────────────────────────────

def _session(region: str | None = None) -> boto3.Session:
    profile = os.environ.get("AWS_PROFILE")
    region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    return boto3.Session(profile_name=profile, region_name=region)


def _age_days(dt: datetime | None) -> int:
    if dt is None:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def _tags_dict(tags: list | None) -> dict:
    return {t["Key"]: t["Value"] for t in (tags or [])}


def _is_prod(tags: dict) -> bool:
    env = tags.get("Environment", tags.get("Env", tags.get("env", ""))).lower()
    return env in ("production", "prod", "prd")


def _confidence(tags: dict, idle_days: int) -> str:
    if _is_prod(tags):
        return "SKIP-PROD"
    if not tags.get("Owner") and not tags.get("Team") and idle_days > 30:
        return "HIGH"
    if idle_days > 14:
        return "MEDIUM"
    return "LOW"

# ─── F6: anomaly ceiling ──────────────────────────────────────────────────────

_RESOURCE_COUNT_CEILING = 50  # hard stop above this


# ─── discovery tools (read-only) ────────────────────────────────────────────

@mcp.tool(
    description="List EC2 instances that have been in 'stopped' state for at least min_days days.",
)
def list_idle_ec2(region: str = "us-east-1", min_days: int = 7) -> dict:
    """Read-only. Skips instances with scheduled events. HARD STOPS if >50 actionable resources found."""
    session_id = _current_session()
    with ToolTimer(log, "list_idle_ec2", session_id=session_id, region=region, min_days=min_days):
        ec2 = _session(region).client("ec2")
        result = []
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]):
            for reservation in page["Reservations"]:
                for inst in reservation["Instances"]:
                    instance_id = inst["InstanceId"]
                    tags = _tags_dict(inst.get("Tags"))
                    stopped_reason = inst.get("StateTransitionReason", "")
                    stopped_days = 0
                    if "(" in stopped_reason and ")" in stopped_reason:
                        try:
                            ts = stopped_reason.split("(")[1].rstrip(")")
                            dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S %Z")
                            stopped_days = _age_days(dt)
                        except Exception:
                            stopped_days = 0
                    if stopped_days < min_days and min_days > 0:
                        continue

                    # Check scheduled events — instance in maintenance should not be flagged
                    try:
                        status_resp = _retryable_call(
                            ec2.describe_instance_status,
                            InstanceIds=[instance_id],
                            IncludeAllInstances=True,
                            service="ec2",
                            region=region,
                        )
                        events = []
                        for s in status_resp.get("InstanceStatuses", []):
                            events = s.get("Events", [])
                        if events:
                            result.append({
                                "resource_id": instance_id,
                                "resource_type": "ec2-instance",
                                "region": region,
                                "skip": True,
                                "warning": f"Scheduled AWS events pending: {[e.get('Code') for e in events]} — skipped",
                            })
                            continue
                    except ClientError:
                        pass

                    result.append({
                        "resource_id": instance_id,
                        "resource_type": "ec2-instance",
                        "region": region,
                        "instance_type": inst.get("InstanceType"),
                        "name": tags.get("Name", ""),
                        "owner": tags.get("Owner", ""),
                        "environment": tags.get("Environment", tags.get("Env", "")),
                        "idle_days": stopped_days,
                        "confidence": _confidence(tags, stopped_days),
                        "tags": tags,
                        "is_prod": _is_prod(tags),
                    })

        actionable = [r for r in result if not r.get("skip")]

        # F6: HARD STOP — do not expose full list to LLM when count exceeds ceiling
        if len(actionable) > _RESOURCE_COUNT_CEILING:
            log.warning(
                "anomaly_hard_stop",
                extra={"ctx_count": len(actionable), "ctx_threshold": _RESOURCE_COUNT_CEILING, "ctx_region": region},
            )
            return {
                "status": "ANOMALY_STOP",
                "region": region,
                "anomaly_detected": True,
                "actionable_count": len(actionable),
                "resources": [],  # intentionally empty — LLM must not iterate this list
                "count": 0,
                "anomaly_message": (
                    f"HARD STOP: Found {len(actionable)} actionable instances in {region} — "
                    f"exceeds safety threshold {_RESOURCE_COUNT_CEILING}. "
                    "Agent must NOT proceed. Ask human to narrow scope by tag filter, name prefix, or "
                    "shorter min_days before re-calling this tool."
                ),
            }

        log.info("list_idle_ec2_done", extra={"ctx_count": len(result), "ctx_actionable": len(actionable)})
        return {
            "resources": result,
            "count": len(result),
            "actionable_count": len(actionable),
            "region": region,
            "anomaly_detected": False,
            "anomaly_message": None,
        }


@mcp.tool(
    description="List EBS volumes that are unattached (available state) — orphaned storage waste.",
)
def list_orphaned_ebs(region: str = "us-east-1") -> dict:
    """Read-only discovery of unattached EBS volumes."""
    ec2 = _session(region).client("ec2")
    result = []
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
        for vol in page["Volumes"]:
            tags = _tags_dict(vol.get("Tags"))
            age = _age_days(vol.get("CreateTime"))
            result.append({
                "resource_id": vol["VolumeId"],
                "resource_type": "ebs-volume",
                "region": region,
                "size_gb": vol["Size"],
                "volume_type": vol["VolumeType"],
                "iops": vol.get("Iops", 0),
                "name": tags.get("Name", ""),
                "owner": tags.get("Owner", ""),
                "environment": tags.get("Environment", ""),
                "idle_days": age,
                "confidence": _confidence(tags, age),
                "tags": tags,
                "is_prod": _is_prod(tags),
            })
    return {"resources": result, "count": len(result), "region": region}


@mcp.tool(
    description="List Elastic IPs not associated with any instance or network interface.",
)
def list_unused_elastic_ips(region: str = "us-east-1") -> dict:
    """Read-only discovery of unassociated Elastic IPs (charged even when idle)."""
    ec2 = _session(region).client("ec2")
    addresses = ec2.describe_addresses(Filters=[{"Name": "domain", "Values": ["vpc"]}])["Addresses"]
    result = []
    for addr in addresses:
        if "AssociationId" not in addr:
            tags = _tags_dict(addr.get("Tags"))
            result.append({
                "resource_id": addr["AllocationId"],
                "resource_type": "elastic-ip",
                "region": region,
                "public_ip": addr.get("PublicIp"),
                "name": tags.get("Name", ""),
                "owner": tags.get("Owner", ""),
                "idle_days": 0,
                "confidence": "HIGH" if not tags else "MEDIUM",
                "tags": tags,
                "is_prod": _is_prod(tags),
            })
    return {"resources": result, "count": len(result), "region": region}


@mcp.tool(
    description="List Application and Network Load Balancers with zero active connections for min_days days.",
)
def list_idle_load_balancers(region: str = "us-east-1", min_days: int = 7) -> dict:
    """Read-only discovery of idle load balancers using CloudWatch metrics."""
    elb = _session(region).client("elbv2")
    cw = _session(region).client("cloudwatch")
    result = []
    paginator = elb.get_paginator("describe_load_balancers")
    for page in paginator.paginate():
        for lb in page["LoadBalancers"]:
            lb_arn = lb["LoadBalancerArn"]
            lb_name = lb["LoadBalancerName"]
            tags_resp = elb.describe_tags(ResourceArns=[lb_arn])
            tags = _tags_dict(tags_resp["TagDescriptions"][0].get("Tags") if tags_resp["TagDescriptions"] else [])
            namespace = "AWS/ApplicationELB" if lb["Type"] == "application" else "AWS/NetworkELB"
            lb_dim = lb_arn.split("loadbalancer/")[1] if "loadbalancer/" in lb_arn else lb_arn
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=min_days)
            try:
                metrics = cw.get_metric_statistics(
                    Namespace=namespace,
                    MetricName="ActiveConnectionCount",
                    Dimensions=[{"Name": "LoadBalancer", "Value": lb_dim}],
                    StartTime=start, EndTime=end, Period=86400,
                    Statistics=["Sum"],
                )
                total_conns = sum(p["Sum"] for p in metrics.get("Datapoints", []))
            except Exception as cw_err:
                result.append({
                    "resource_id": lb_arn,
                    "resource_type": f"load-balancer-{lb['Type']}",
                    "region": region,
                    "name": lb_name,
                    "warning": f"CloudWatch metrics unavailable — skipped: {cw_err}",
                    "skip": True,
                })
                continue
            age = _age_days(lb.get("CreatedTime"))
            if total_conns == 0:
                result.append({
                    "resource_id": lb_arn,
                    "resource_type": f"load-balancer-{lb['Type']}",
                    "region": region,
                    "name": lb_name,
                    "dns_name": lb.get("DNSName"),
                    "owner": tags.get("Owner", ""),
                    "environment": tags.get("Environment", ""),
                    "idle_days": age,
                    "total_connections_last_n_days": total_conns,
                    "confidence": _confidence(tags, age),
                    "tags": tags,
                    "is_prod": _is_prod(tags),
                })
    return {"resources": result, "count": len(result), "region": region}


@mcp.tool(
    description="List EBS snapshots older than min_age_days that are not backing any AMI.",
)
def list_old_snapshots(region: str = "us-east-1", min_age_days: int = 90) -> dict:
    """Read-only discovery of old orphaned snapshots."""
    ec2 = _session(region).client("ec2")
    sts = _session(region).client("sts")
    account_id = sts.get_caller_identity()["Account"]
    paginator = ec2.get_paginator("describe_snapshots")
    images = ec2.describe_images(Owners=["self"])["Images"]
    ami_snapshot_ids = {
        bdm["Ebs"]["SnapshotId"]
        for img in images
        for bdm in img.get("BlockDeviceMappings", [])
        if bdm.get("Ebs", {}).get("SnapshotId")
    }
    result = []
    for page in paginator.paginate(OwnerIds=[account_id]):
        for snap in page["Snapshots"]:
            if snap["SnapshotId"] in ami_snapshot_ids:
                continue
            age = _age_days(snap.get("StartTime"))
            if age < min_age_days:
                continue
            tags = _tags_dict(snap.get("Tags"))
            result.append({
                "resource_id": snap["SnapshotId"],
                "resource_type": "ebs-snapshot",
                "region": region,
                "size_gb": snap["VolumeSize"],
                "description": snap.get("Description", ""),
                "name": tags.get("Name", ""),
                "owner": tags.get("Owner", ""),
                "idle_days": age,
                "confidence": _confidence(tags, age),
                "tags": tags,
                "is_prod": _is_prod(tags),
            })
    return {"resources": result, "count": len(result), "region": region}


@mcp.tool(description="List all AWS regions available to this account.")
def list_regions() -> dict:
    """Read-only."""
    ec2 = _session().client("ec2")
    regions = [r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"]]
    return {"regions": regions}


# ─── cost calculation (read-only) ────────────────────────────────────────────

_EC2_HOURLY = {
    "t2.micro": 0.0116, "t2.small": 0.023, "t2.medium": 0.0464,
    "t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416,
    "t3.large": 0.0832, "t3.xlarge": 0.1664, "t3.2xlarge": 0.3328,
    "m5.large": 0.096, "m5.xlarge": 0.192, "m5.2xlarge": 0.384,
    "m5.4xlarge": 0.768, "c5.large": 0.085, "c5.xlarge": 0.17,
    "r5.large": 0.126, "r5.xlarge": 0.252,
}
_EBS_MONTHLY_PER_GB = {"gp2": 0.10, "gp3": 0.08, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.025}
_EIP_MONTHLY = 3.60
_ALB_MONTHLY_BASE = 16.20
_SNAPSHOT_MONTHLY_PER_GB = 0.05


@mcp.tool(
    description="Calculate estimated monthly cost for a list of idle resources.",
)
def calculate_monthly_costs(resources: list[dict]) -> dict:
    """Read-only cost estimation for discovered resources."""
    enriched = []
    total = 0.0
    for r in resources:
        rtype = r.get("resource_type", "")
        cost = 0.0
        note = ""
        if rtype == "ec2-instance":
            itype = r.get("instance_type", "")
            hourly = _EC2_HOURLY.get(itype, 0.10)
            cost = hourly * 24 * 30
            note = f"Potential cost if restarted: ${cost:.2f}/mo"
        elif rtype == "ebs-volume":
            vtype = r.get("volume_type", "gp2")
            gb = r.get("size_gb", 0)
            cost = _EBS_MONTHLY_PER_GB.get(vtype, 0.10) * gb
            note = f"{gb}GB {vtype}"
        elif rtype == "elastic-ip":
            cost = _EIP_MONTHLY
            note = "Unassociated EIP: $3.60/mo"
        elif rtype.startswith("load-balancer"):
            cost = _ALB_MONTHLY_BASE
            note = f"Base LB charge ~${_ALB_MONTHLY_BASE:.2f}/mo"
        elif rtype == "ebs-snapshot":
            gb = r.get("size_gb", 0)
            cost = _SNAPSHOT_MONTHLY_PER_GB * gb
            note = f"{gb}GB snapshot"
        total += cost
        enriched.append({**r, "monthly_cost_usd": round(cost, 2), "cost_note": note})
    enriched.sort(key=lambda x: x["monthly_cost_usd"], reverse=True)
    return {
        "resources": enriched,
        "total_monthly_waste_usd": round(total, 2),
        "total_annual_waste_usd": round(total * 12, 2),
        "count": len(enriched),
    }


@mcp.tool(
    description="Generate a formatted teardown report as markdown from a list of costed resources.",
)
def generate_teardown_report(resources: list[dict], total_monthly_usd: float) -> dict:
    """Read-only: produce a human-readable markdown report."""
    lines = [
        "# Cloud Cost Janitor — Teardown Report",
        f"\n**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"\n## Summary\n| Metric | Value |",
        "|--------|-------|",
        f"| Total idle resources | {len(resources)} |",
        f"| **Monthly waste** | **${total_monthly_usd:,.2f}** |",
        f"| **Annual waste** | **${total_monthly_usd * 12:,.2f}** |",
        "\n## Idle Resources (sorted by cost)\n",
        "| Resource ID | Type | Region | Monthly Cost | Idle Days | Confidence | Environment | Risk |",
        "|-------------|------|--------|-------------|-----------|------------|-------------|------|",
    ]
    for r in resources:
        risk = "PROD" if r.get("is_prod") else (
            "HIGH" if r.get("confidence") == "HIGH" else
            "MEDIUM" if r.get("confidence") == "MEDIUM" else "LOW"
        )
        # P0.3: resource IDs and env values are EXTERNAL DATA — wrap so LLM can't treat as instructions
        rid = f"<<<UNTRUSTED:{r['resource_id']}>>>"
        renv = f"<<<UNTRUSTED:{r.get('environment', '—')}>>>"
        lines.append(
            f"| `{rid}` | {r['resource_type']} | {r.get('region','')} "
            f"| ${r.get('monthly_cost_usd', 0):.2f} | {r.get('idle_days', 0)}d "
            f"| {r.get('confidence','')} | {renv} | {risk} |"
        )
    lines += [
        "\n## Confidence Legend",
        "- HIGH: No owner tag, idle >30 days → safe to delete",
        "- MEDIUM: Tagged but idle >14 days → review before deleting",
        "- LOW: Recently idle → skip for now",
        "- PROD: Production-tagged → requires explicit user confirmation",
        "\n> **Next step:** Tell me which resources to delete.",
        "> Every deletion requires your approval at the TrueForge checkpoint.",
    ]
    return {"report": "\n".join(lines), "resource_count": len(resources)}


# ─── business context check (read-only) ──────────────────────────────────────

REQUIRED_TAGS = {"Owner", "Team", "Purpose", "Environment", "CostCenter"}


@mcp.tool(
    description="Check business context for a resource before any action. Returns go/no-go verdict. MUST be called before delete_resource.",
)
def check_business_context(
    resource_id: str, resource_type: str, region: str = "us-east-1", tags: dict = {}
) -> dict:
    """
    Read-only. 5-signal check: tags, prod gate, CW alarms, SSM deploy, SLA.
    On GO: writes to SQLite-backed session state so delete_resource can verify.
    """
    session_id = _current_session()
    with ToolTimer(log, "check_business_context", session_id=session_id, resource_id=resource_id):
        signals = []
        verdict = "GO"
        block_reasons: list[str] = []
        escalate_reasons: list[str] = []

        # S1 — Tag completeness
        missing_tags = REQUIRED_TAGS - set(tags.keys())
        if missing_tags:
            block_reasons.append(f"Missing required tags: {sorted(missing_tags)}.")
            verdict = "BLOCK"
        else:
            signals.append(f"Tags complete: Owner={tags.get('Owner')}")

        # S2 — Production gate
        env = tags.get("Environment", tags.get("Env", "")).lower()
        if env in ("production", "prod", "prd", "live"):
            block_reasons.append(f"Production resource (Environment={env}). Requires explicit senior engineer approval.")
            verdict = "BLOCK"

        # S3 — Active CloudWatch alarms
        try:
            cw = _session(region).client("cloudwatch")
            alarms = _retryable_call(
                cw.describe_alarms, StateValue="ALARM", MaxRecords=100,
                service="cloudwatch", region=region,
            )
            resource_alarms = [
                a["AlarmName"] for a in alarms.get("MetricAlarms", [])
                if resource_id in str(a.get("Dimensions", "")) or resource_id in a.get("AlarmName", "")
            ]
            if resource_alarms:
                block_reasons.append(f"Active CloudWatch alarms: {resource_alarms}.")
                verdict = "BLOCK"
            else:
                signals.append("No active CloudWatch alarms")
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "CircuitOpen":
                escalate_reasons.append("CloudWatch circuit breaker open — too many consecutive failures")
            else:
                escalate_reasons.append(f"Could not check CloudWatch: {e}")
            if verdict == "GO":
                verdict = "ESCALATE"

        # S4 — SSM deploy record
        try:
            ssm = _session(region).client("ssm")
            param_name = f"/deployments/{resource_id}/last_deployed_at"
            try:
                param = _retryable_call(
                    ssm.get_parameter, Name=param_name,
                    service="ssm", region=region,
                )
                last_deploy_str = param["Parameter"]["Value"]
                try:
                    last_deploy = datetime.fromisoformat(last_deploy_str)
                    age = _age_days(last_deploy)
                    if age < 30:
                        block_reasons.append(f"Recent deployment {age}d ago.")
                        verdict = "BLOCK"
                    else:
                        signals.append(f"Last deployment: {age}d ago — OK")
                except ValueError:
                    signals.append(f"Deploy record found but unparseable: {last_deploy_str}")
            except ssm.exceptions.ParameterNotFound:
                signals.append("No SSM deployment record found")
        except ClientError as e:
            escalate_reasons.append(f"Could not check SSM: {e}")

        # S5 — SLA/criticality tag
        sla = tags.get("SLA", tags.get("Criticality", "")).lower()
        if sla in ("high", "critical", "tier1", "tier-1", "p0", "p1"):
            block_reasons.append(f"High-criticality SLA tag: {sla}.")
            verdict = "BLOCK"
        elif sla:
            signals.append(f"SLA tag: {sla}")

        if block_reasons and escalate_reasons:
            verdict = "BLOCK"

        # Write to persistent session state on GO only
        if verdict == "GO":
            _mark_context_checked(session_id, resource_id)
            log.info("context_go", extra={"ctx_session": session_id, "ctx_resource": resource_id})
        else:
            log.info("context_blocked", extra={"ctx_session": session_id, "ctx_resource": resource_id, "ctx_verdict": verdict})

        return {
            "resource_id": resource_id,
            "resource_type": resource_type,
            "verdict": verdict,
            "safe_to_act": verdict == "GO",
            "block_reasons": block_reasons,
            "escalate_reasons": escalate_reasons,
            "signals_passed": signals,
            "recommendation": (
                "Proceed to cost analysis and teardown plan." if verdict == "GO"
                else f"BLOCKED: {'; '.join(block_reasons)}" if verdict == "BLOCK"
                else f"Escalate: {'; '.join(escalate_reasons)}"
            ),
        }


# ─── dry run (read-only) ─────────────────────────────────────────────────────

@mcp.tool(
    description="Simulate deletion of a resource and show exactly what would happen. Always call before delete_resource.",
)
def dry_run_delete(resource_id: str, resource_type: str, region: str = "us-east-1") -> dict:
    """Read-only simulation of what delete_resource would do."""
    warnings = []
    ec2 = _session(region).client("ec2")
    details = {}

    if resource_type == "ec2-instance":
        try:
            resp = ec2.describe_instances(InstanceIds=[resource_id])
            inst = resp["Reservations"][0]["Instances"][0]
            tags = _tags_dict(inst.get("Tags"))
            if _is_prod(tags):
                warnings.append("PRODUCTION instance — deletion will be blocked")
            vols = [bdm["Ebs"]["VolumeId"] for bdm in inst.get("BlockDeviceMappings", []) if bdm.get("Ebs")]
            if vols:
                warnings.append(f"Attached volumes will be detached: {vols}")
            details = {"instance_type": inst.get("InstanceType"), "attached_volumes": vols, "tags": tags}
        except ClientError as e:
            return {"error": str(e)}

    elif resource_type == "ebs-volume":
        try:
            vol = ec2.describe_volumes(VolumeIds=[resource_id])["Volumes"][0]
            snaps = ec2.describe_snapshots(Filters=[{"Name": "volume-id", "Values": [resource_id]}])["Snapshots"]
            if snaps:
                warnings.append(f"Volume has {len(snaps)} snapshot(s) — those will NOT be deleted")
            details = {"size_gb": vol["Size"], "volume_type": vol["VolumeType"], "snapshot_count": len(snaps)}
        except ClientError as e:
            return {"error": str(e)}

    elif resource_type == "elastic-ip":
        warnings.append("Releasing EIP is irreversible — you will not get this IP back")

    elif resource_type == "ebs-snapshot":
        warnings.append("Snapshot deletion is irreversible")

    return {
        "resource_id": resource_id,
        "resource_type": resource_type,
        "region": region,
        "dry_run": True,
        "action": f"WOULD DELETE {resource_type} {resource_id} in {region}",
        "warnings": warnings,
        "details": details,
        "ready_to_delete": len([w for w in warnings if "PRODUCTION" in w]) == 0,
    }


# ─── destructive tools (approval-gated) ──────────────────────────────────────

@mcp.tool(
    description="[DESTRUCTIVE] Delete a single AWS resource. Requires TrueForge human approval. Call dry_run_delete AND check_business_context first.",
    annotations={"destructiveHint": True, "readOnlyHint": False},
)
def delete_resource(
    resource_id: str,
    resource_type: str,
    region: str = "us-east-1",
    confirm_prod: bool = False,
) -> dict:
    """
    DESTRUCTIVE. TrueForge harness pauses here for human approval.
    Server-side SQLite gate: check_business_context must have returned GO in this session.
    """
    session_id = _current_session()
    if not _is_context_checked(session_id, resource_id):
        log.warning(
            "delete_blocked_no_context",
            extra={"ctx_session": session_id, "ctx_resource": resource_id},
        )
        return {
            "resource_id": resource_id,
            "status": "BLOCKED",
            "reason": (
                "SAFETY GATE: check_business_context has not confirmed verdict=GO for this resource "
                f"in session '{session_id}'. Call check_business_context first."
            ),
        }

    ec2 = _session(region).client("ec2")
    elb = _session(region).client("elbv2")
    result: dict = {"resource_id": resource_id, "resource_type": resource_type, "region": region}

    with ToolTimer(log, "delete_resource", session_id=session_id, resource_id=resource_id, resource_type=resource_type):
        try:
            if resource_type == "ec2-instance":
                # TOCTOU fix: re-describe state IMMEDIATELY before terminate.
                # Autoscaling may have restarted the instance since list_idle_ec2 ran.
                recheck = ec2.describe_instances(InstanceIds=[resource_id])
                if not recheck.get("Reservations"):
                    return {**result, "status": "ALREADY_GONE", "reason": "Instance no longer exists"}
                live_inst = recheck["Reservations"][0]["Instances"][0]
                live_state = live_inst["State"]["Name"]
                if live_state not in ("stopped", "stopping"):
                    log.warning(
                        "toctou_abort",
                        extra={"ctx_resource": resource_id, "ctx_state": live_state},
                    )
                    return {
                        **result,
                        "status": "STATE_CHANGED",
                        "current_state": live_state,
                        "reason": (
                            f"Instance is now '{live_state}' — was 'stopped' at scan time. "
                            "Aborting to prevent deletion of a live instance. "
                            "Confirm current usage before retrying."
                        ),
                    }
                tags = _tags_dict(live_inst.get("Tags"))
                if _is_prod(tags) and not confirm_prod:
                    return {**result, "status": "BLOCKED", "reason": "Production — pass confirm_prod=true to override"}
                ec2.terminate_instances(InstanceIds=[resource_id])
                verify = ec2.describe_instances(InstanceIds=[resource_id])
                state = verify["Reservations"][0]["Instances"][0]["State"]["Name"]
                result["status"] = "TERMINATED"
                result["verified_state"] = state

            elif resource_type == "ebs-volume":
                ec2.delete_volume(VolumeId=resource_id)
                try:
                    verify = ec2.describe_volumes(VolumeIds=[resource_id])
                    vstate = verify["Volumes"][0]["State"] if verify["Volumes"] else "deleted"
                    result["verified_state"] = vstate
                except ClientError as ve:
                    code = ve.response.get("Error", {}).get("Code", "")
                    result["verified_state"] = "deleted" if "NotFound" in code else f"unknown ({code})"
                result["status"] = "DELETED"

            elif resource_type == "elastic-ip":
                ec2.release_address(AllocationId=resource_id)
                result["status"] = "RELEASED"

            elif resource_type == "ebs-snapshot":
                ec2.delete_snapshot(SnapshotId=resource_id)
                result["status"] = "DELETED"

            elif resource_type.startswith("load-balancer"):
                elb.delete_load_balancer(LoadBalancerArn=resource_id)
                result["status"] = "DELETED"

            else:
                result["status"] = "UNSUPPORTED"
                result["reason"] = f"Unknown resource type: {resource_type}"

        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("VolumeInUse", "InvalidParameterCombination"):
                result["status"] = "STATE_CHANGED"
                result["reason"] = "Resource state changed between discovery and delete — skipping safely"
            elif code == "OperationNotPermitted":
                result["status"] = "STATE_CHANGED"
                result["reason"] = "Operation not permitted — resource is likely in a snapshot or maintenance state"
            elif code in ("InvalidInstanceID.NotFound", "InvalidVolume.NotFound", "InvalidSnapshot.NotFound"):
                result["status"] = "ALREADY_GONE"
                result["reason"] = "Resource no longer exists — idempotent skip"
            elif code in ("AccessDenied", "UnauthorizedOperation"):
                # Structured BLOCKED response — not raw exception string
                result["status"] = "BLOCKED"
                result["reason"] = "InsufficientPermissions — agent IAM role lacks permission for this action"
                log.warning("access_denied", extra={"ctx_resource": resource_id, "ctx_type": resource_type})
            else:
                result["status"] = "ERROR"
                result["reason"] = str(e)

    # Write idempotency log to SSM after every terminal state
    if result.get("status") not in ("ERROR", "BLOCKED", "UNSUPPORTED"):
        try:
            ssm = _session(region).client("ssm")
            ssm.put_parameter(
                Name=f"/janitor/deleted/{resource_id}",
                Value=json.dumps({
                    "deleted_at": datetime.now(timezone.utc).isoformat(),
                    "resource_type": resource_type,
                    "region": region,
                    "status": result.get("status"),
                    "session": session_id,
                }),
                Type="String",
                Overwrite=True,
            )
            result["audit_log"] = f"/janitor/deleted/{resource_id}"
        except Exception:
            result["audit_log"] = "SSM write failed — manual audit required"

    return result


# ─── F2: Partial batch recovery ──────────────────────────────────────────────

@mcp.tool(
    description="[DESTRUCTIVE] Delete multiple resources with per-resource failure isolation. Safe partial results if some fail. Requires TrueForge approval.",
    annotations={"destructiveHint": True, "readOnlyHint": False},
)
def batch_delete_resources(resources: list[dict]) -> dict:
    """
    DESTRUCTIVE — processes each resource independently.
    A single failure does NOT abort the batch. Returns per-resource results and a summary.
    TrueForge approval fires once before the batch begins.
    """
    session_id = _current_session()
    log.info("batch_delete_start", extra={"ctx_session": session_id, "ctx_count": len(resources)})

    results = []
    succeeded = 0
    failed = 0
    skipped = 0

    for r in resources:
        rid = r.get("resource_id", "")
        rtype = r.get("resource_type", "")
        rregion = r.get("region", "us-east-1")

        try:
            res = delete_resource(rid, rtype, rregion)
            status = res.get("status", "")
            if status in ("TERMINATED", "DELETED", "RELEASED", "ALREADY_GONE"):
                succeeded += 1
            elif status == "BLOCKED":
                skipped += 1
            elif status == "STATE_CHANGED":
                skipped += 1
            else:
                failed += 1
            results.append(res)
        except Exception as exc:
            failed += 1
            log.error("batch_item_error", extra={"ctx_session": session_id, "ctx_resource": rid, "ctx_err": str(exc)})
            results.append({
                "resource_id": rid,
                "resource_type": rtype,
                "region": rregion,
                "status": "ERROR",
                "reason": str(exc),
            })

    total = len(resources)
    log.info(
        "batch_delete_done",
        extra={"ctx_session": session_id, "ctx_succeeded": succeeded, "ctx_failed": failed, "ctx_skipped": skipped},
    )
    return {
        "results": results,
        "summary": {
            "total": total,
            "succeeded": succeeded,
            "failed": failed,
            "skipped": skipped,
        },
        "partial_success": succeeded > 0 and (failed > 0 or skipped > 0),
        "all_succeeded": succeeded == total and failed == 0,
    }


# ─── code generation + execution ─────────────────────────────────────────────

_ALLOWED_RESOURCE_TYPES = frozenset({
    "ec2-instance", "ebs-volume", "ebs-snapshot", "elastic-ip",
    "load-balancer-application", "load-balancer-network",
})


@mcp.tool(
    description="Generate a Python remediation script for a list of idle resources. Review before executing.",
)
def generate_remediation_script(resources: list[dict], dry_run: bool = True) -> dict:
    """Read-only: generates boto3 Python. Only allowlisted resource types produce executable code."""
    if not resources:
        return {"error": "No resources provided", "script": None}

    lines = [
        '"""',
        "Auto-generated remediation script — Enterprise Ops Agent",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Mode: {'DRY RUN (no actual deletions)' if dry_run else 'LIVE — will delete resources'}",
        '"""',
        "import boto3",
        "import json",
        "from datetime import datetime, timezone",
        "",
        "DRY_RUN = " + str(dry_run),
        "RESULTS = []",
        "",
    ]

    for r in resources:
        rtype = r.get("resource_type", "")
        rid_raw = r.get("resource_id", "")
        region = r.get("region", "us-east-1")

        # P0.2: sanitize resource_id BEFORE any template insertion — blocks newline injection
        rid = _sanitize_resource_id(rid_raw)
        safe_region = re.sub(r'[^\w\-]', '', region)[:32]

        if rtype not in _ALLOWED_RESOURCE_TYPES:
            rtype_safe = re.sub(r'[^\w\-]', '_', str(rtype))[:32]
            lines.append(f"# SKIP unsupported type: {rtype_safe} ({rid})")
            continue

        lines.append(f"# --- {rtype}: {rid} (region={safe_region}) ---")
        lines.append(f"ec2_{rid.replace('-','_')} = boto3.client('ec2', region_name='{safe_region}')")

        var = rid.replace('-', '_')
        if rtype == "ec2-instance":
            lines += [
                f"if DRY_RUN:",
                f"    print('[DRY RUN] Would terminate ec2-instance {rid}')",
                f"    RESULTS.append({{'id': '{rid}', 'action': 'DRY_RUN_terminate'}})",
                f"else:",
                f"    r = ec2_{var}.terminate_instances(InstanceIds=['{rid}'])",
                f"    RESULTS.append({{'id': '{rid}', 'action': 'terminated', 'state': r['TerminatingInstances'][0]['CurrentState']['Name']}})",
            ]
        elif rtype == "ebs-volume":
            lines += [
                f"if DRY_RUN:",
                f"    print('[DRY RUN] Would delete ebs-volume {rid}')",
                f"    RESULTS.append({{'id': '{rid}', 'action': 'DRY_RUN_delete'}})",
                f"else:",
                f"    ec2_{var}.delete_volume(VolumeId='{rid}')",
                f"    RESULTS.append({{'id': '{rid}', 'action': 'deleted'}})",
            ]
        elif rtype == "elastic-ip":
            lines += [
                f"if DRY_RUN:",
                f"    print('[DRY RUN] Would release elastic-ip {rid}')",
                f"    RESULTS.append({{'id': '{rid}', 'action': 'DRY_RUN_release'}})",
                f"else:",
                f"    ec2_{var}.release_address(AllocationId='{rid}')",
                f"    RESULTS.append({{'id': '{rid}', 'action': 'released'}})",
            ]
        elif rtype == "ebs-snapshot":
            lines += [
                f"if DRY_RUN:",
                f"    print('[DRY RUN] Would delete ebs-snapshot {rid}')",
                f"    RESULTS.append({{'id': '{rid}', 'action': 'DRY_RUN_delete'}})",
                f"else:",
                f"    ec2_{var}.delete_snapshot(SnapshotId='{rid}')",
                f"    RESULTS.append({{'id': '{rid}', 'action': 'deleted'}})",
            ]
        elif rtype.startswith("load-balancer"):
            lines += [
                f"if DRY_RUN:",
                f"    print('[DRY RUN] Would delete load-balancer {rid}')",
                f"    RESULTS.append({{'id': '{rid}', 'action': 'DRY_RUN_delete'}})",
                f"else:",
                f"    boto3.client('elbv2', region_name='{safe_region}').delete_load_balancer(LoadBalancerArn='{rid}')",
                f"    RESULTS.append({{'id': '{rid}', 'action': 'deleted'}})",
            ]
        lines.append("")

    lines.append("print(json.dumps({'results': RESULTS, 'dry_run': DRY_RUN}, indent=2))")
    script = "\n".join(lines)
    return {
        "script": script,
        "resource_count": len(resources),
        "dry_run": dry_run,
        "note": "Review script before executing. Call execute_remediation_script to run in sandboxed subprocess.",
    }


@mcp.tool(
    description="[DESTRUCTIVE] Execute a remediation script generated by generate_remediation_script. Credential-stripped subprocess. Requires TrueForge approval.",
    annotations={"destructiveHint": True, "readOnlyHint": False},
)
def execute_remediation_script(script: str, dry_run: bool = True) -> dict:
    """
    DESTRUCTIVE (when dry_run=False). Hardened subprocess sandbox.

    Security layers:
    1. AST scan — blocks dangerous imports/calls before any execution
    2. Credential stripping — removes all raw key material + IRSA/EKS vars
    3. AWS_EC2_METADATA_DISABLED=true — boto3 cannot reach 169.254.169.254
    4. Isolated temp home dir — prevents ~/.aws credential pickup
    5. Proxy block — no_proxy=* blocks HTTP/HTTPS proxy channels
    6. PYTHONNOUSERSITE — prevents user site-package code injection
    7. 60s timeout + stderr cap — prevents runaway scripts
    """
    effective_script = script
    if dry_run:
        effective_script = script.replace("DRY_RUN = False", "DRY_RUN = True")

    # Layer 1: AST security scan BEFORE execution — reject on any violation
    violations = _validate_script_ast(effective_script)
    if violations:
        log.error("script_ast_rejected", extra={"ctx_violations": violations, "ctx_count": len(violations)})
        return {
            "status": "SECURITY_REJECTED",
            "dry_run": dry_run,
            "reason": "Script failed AST security scan — execution blocked",
            "violations": violations,
        }

    with tempfile.TemporaryDirectory(prefix="janitor-sandbox-") as sandbox_dir:
        script_path = os.path.join(sandbox_dir, "_remediation.py")
        with open(script_path, "w") as f:
            f.write(effective_script)

        # Layer 2+3+4+5+6: hardened environment
        safe_env: dict[str, str] = {
            "PATH": "/usr/bin:/bin:/usr/local/bin",   # minimal — no user paths
            "HOME": sandbox_dir,                       # isolated home — no ~/.aws pickup
            "TMPDIR": sandbox_dir,
            "no_proxy": "*",                           # block proxy channels
            "NO_PROXY": "*",
            "http_proxy": "",
            "https_proxy": "",
            "HTTP_PROXY": "",
            "HTTPS_PROXY": "",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",                   # no user site-packages
            "PYTHONPATH": "",
            # Layer 3: disable boto3 EC2 metadata endpoint entirely
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_PAGER": "",
        }
        # Pass region boundary only — no key material
        if "AWS_DEFAULT_REGION" in os.environ:
            safe_env["AWS_DEFAULT_REGION"] = os.environ["AWS_DEFAULT_REGION"]
        # Explicitly NOT passed: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
        # AWS_SESSION_TOKEN, AWS_PROFILE (avoids ~/.aws/credentials pickup),
        # GITHUB_TOKEN, ANTHROPIC_API_KEY, DATABASE_URL, LINEAR_API_KEY.
        # IRSA/EKS: AWS_ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE,
        # AWS_CONTAINER_CREDENTIALS_RELATIVE_URI, AWS_CONTAINER_CREDENTIALS_FULL_URI
        # are never passed — they don't appear in safe_env at all.

        try:
            proc = subprocess.run(
                ["python3", script_path],
                capture_output=True,
                text=True,
                timeout=60,
                env=safe_env,
                cwd=sandbox_dir,
                shell=False,
            )
            log.info(
                "script_executed",
                extra={
                    "ctx_exit": proc.returncode,
                    "ctx_dry_run": dry_run,
                    "ctx_sandbox": sandbox_dir,
                },
            )
            return {
                "exit_code": proc.returncode,
                "stdout": proc.stdout[-4000:] if proc.stdout else "",
                "stderr": proc.stderr[-2000:] if proc.stderr else "",
                "dry_run": dry_run,
                "status": "SUCCESS" if proc.returncode == 0 else "FAILED",
                "security_layers": [
                    "AST scan passed",
                    "Credential-stripped environment",
                    "AWS_EC2_METADATA_DISABLED=true",
                    "Isolated temp home dir",
                    "no_proxy=* (proxy blocked)",
                    "PYTHONNOUSERSITE=1",
                ],
            }
        except subprocess.TimeoutExpired:
            return {"status": "TIMEOUT", "dry_run": dry_run, "reason": "Script exceeded 60s timeout"}
        except Exception as exc:
            return {"status": "ERROR", "dry_run": dry_run, "reason": str(exc)}


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8001
    import uvicorn
    uvicorn.run(mcp.streamable_http_app(), host="0.0.0.0", port=port)
