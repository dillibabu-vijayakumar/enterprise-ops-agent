"""
Shared Business Context Checker — used by ALL subagent MCP servers.
Every subagent imports this before any action.
"""
import os
from datetime import datetime, timezone
from typing import Any

import backoff
import boto3
from botocore.exceptions import ClientError


def _is_not_throttle(exc: ClientError) -> bool:
    """Backoff giveup callback: give up immediately on non-throttle errors."""
    return exc.response.get("Error", {}).get("Code", "") not in (
        "ThrottlingException", "RequestLimitExceeded", "Throttling",
    )


def _retryable_call(fn, *args, **kwargs):
    """Retry throttled boto3 calls via backoff library (exponential, max 3 tries)."""
    @backoff.on_exception(backoff.expo, ClientError, max_tries=3, giveup=_is_not_throttle, factor=2)
    def _wrapped():
        return fn(*args, **kwargs)
    return _wrapped()

REQUIRED_TAGS = {"Owner", "Team", "Purpose", "Environment", "CostCenter"}

def _age_days(dt: datetime | None) -> int:
    if dt is None:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days

def _session(region: str = "us-east-1") -> boto3.Session:
    profile = os.environ.get("AWS_PROFILE")
    return boto3.Session(profile_name=profile, region_name=region)

def check_business_context(
    resource_id: str,
    resource_type: str,
    region: str,
    tags: dict,
    caller_role: str = "viewer",
) -> dict:
    """
    5-signal business context check.
    Returns verdict: GO | BLOCK | ESCALATE
    Called by every subagent before any mutating action.
    """
    block_reasons: list[str] = []
    escalate_reasons: list[str] = []
    signals_passed: list[str] = []

    # S1 — Tag completeness
    missing = REQUIRED_TAGS - set(tags.keys())
    if missing:
        block_reasons.append(f"Missing tags: {sorted(missing)} — cannot identify owner")
    else:
        signals_passed.append(f"Tags complete: owner={tags.get('Owner')}, team={tags.get('Team')}")

    # S2 — Production gate
    env = tags.get("Environment", tags.get("Env", "")).lower()
    if env in ("production", "prod", "prd", "live"):
        block_reasons.append(f"Production resource (env={env}) — requires admin role")
        if caller_role not in ("admin", "sre"):
            block_reasons.append(f"Caller role '{caller_role}' cannot override prod block")

    # S3 — Active CloudWatch alarms (with retry)
    try:
        cw = _session(region).client("cloudwatch")
        alarms = _retryable_call(cw.describe_alarms, StateValue="ALARM", MaxRecords=100)
        active = [
            a["AlarmName"] for a in alarms.get("MetricAlarms", [])
            if resource_id in str(a.get("Dimensions", "")) or resource_id in a.get("AlarmName", "")
        ]
        if active:
            block_reasons.append(f"Active CW alarms: {active} — resource is monitored")
        else:
            signals_passed.append("No active CloudWatch alarms")
    except Exception as e:
        escalate_reasons.append(f"CW check failed: {e}")

    # S4 — SSM deploy record (with retry)
    try:
        ssm = _session(region).client("ssm")
        try:
            param = _retryable_call(ssm.get_parameter, Name=f"/deployments/{resource_id}/last_deployed_at")
            val = param["Parameter"]["Value"]
            dt = datetime.fromisoformat(val)
            age = _age_days(dt)
            if age < 30:
                block_reasons.append(f"Deployed {age}d ago — may be active")
            else:
                signals_passed.append(f"Last deploy {age}d ago — OK")
        except ssm.exceptions.ParameterNotFound:
            signals_passed.append("No SSM deploy record")
    except Exception as e:
        escalate_reasons.append(f"SSM check failed: {e}")

    # S5 — SLA/criticality tag
    sla = tags.get("SLA", tags.get("Criticality", "")).lower()
    if sla in ("high", "critical", "tier1", "tier-1", "p0", "p1"):
        block_reasons.append(f"High-criticality SLA tag: {sla}")
    elif sla:
        signals_passed.append(f"SLA: {sla}")

    # RBAC check
    if caller_role == "viewer" and resource_type not in ("readonly",):
        block_reasons.append(f"Role 'viewer' cannot mutate {resource_type}")

    verdict = "BLOCK" if block_reasons else ("ESCALATE" if escalate_reasons else "GO")

    return {
        "resource_id": resource_id,
        "resource_type": resource_type,
        "verdict": verdict,
        "safe_to_act": verdict == "GO",
        "block_reasons": block_reasons,
        "escalate_reasons": escalate_reasons,
        "signals_passed": signals_passed,
        "caller_role": caller_role,
    }
