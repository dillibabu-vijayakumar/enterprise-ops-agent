"""
Unit tests for Enterprise Ops Agent core logic.
Uses moto to mock AWS APIs — no real AWS calls made.
Run with: python -m pytest tests/test_core.py -v
"""
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

# Ensure mcp/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "mcp"))

# ─── fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    """Ensure boto3 uses moto mock region — no real credentials needed."""
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.delenv("AWS_PROFILE", raising=False)


# ─── list_idle_ec2 ────────────────────────────────────────────────────────────

@mock_aws
def test_list_idle_ec2_returns_stopped_instances():
    """Stopped instance older than min_days appears in results."""
    from cloud.server import list_idle_ec2

    ec2 = boto3.client("ec2", region_name="us-east-1")
    # launch and stop an instance
    ami = ec2.describe_images(Owners=["amazon"])["Images"]
    # moto provides a fake AMI
    ami_id = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1,
                                InstanceType="t3.micro")["Instances"][0]["ImageId"]
    iid = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1,
                             InstanceType="t3.micro",
                             TagSpecifications=[{
                                 "ResourceType": "instance",
                                 "Tags": [{"Key": "Name", "Value": "test-idle"}],
                             }])["Instances"][0]["InstanceId"]
    ec2.stop_instances(InstanceIds=[iid])

    result = list_idle_ec2(region="us-east-1", min_days=0)
    ids = [r["resource_id"] for r in result["resources"] if not r.get("skip")]
    assert iid in ids


@mock_aws
def test_list_idle_ec2_anomaly_flag():
    """Returns anomaly_detected=True when count exceeds ceiling."""
    from cloud.server import list_idle_ec2, _RESOURCE_COUNT_CEILING

    ec2 = boto3.client("ec2", region_name="us-east-1")
    # launch _RESOURCE_COUNT_CEILING + 1 instances and stop them
    count = _RESOURCE_COUNT_CEILING + 1
    for _ in range(count):
        iid = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1,
                                 InstanceType="t3.micro")["Instances"][0]["InstanceId"]
        ec2.stop_instances(InstanceIds=[iid])

    result = list_idle_ec2(region="us-east-1", min_days=0)
    assert result["anomaly_detected"] is True
    assert result["anomaly_message"] is not None


# ─── check_business_context (S2 prod gate) ───────────────────────────────────

@mock_aws
def test_check_business_context_blocks_prod():
    """Prod-tagged resource → verdict=BLOCK."""
    from cloud.server import check_business_context

    result = check_business_context(
        resource_id="i-prod001",
        resource_type="ec2-instance",
        region="us-east-1",
        tags={
            "Owner": "alice", "Team": "platform", "Purpose": "api",
            "Environment": "production", "CostCenter": "eng",
        },
    )
    assert result["verdict"] == "BLOCK"
    assert any("prod" in r.lower() or "production" in r.lower() for r in result["block_reasons"])


@mock_aws
def test_check_business_context_go_marks_session_state():
    """GO verdict marks resource in server-side session state."""
    from cloud.server import check_business_context, _is_context_checked, _context_cleared, _current_session
    import cloud.server as srv

    resource_id = "vol-abc123"
    # clear state for isolation
    _context_cleared.clear()

    with patch.dict(os.environ, {"TRUEFORGE_SESSION_ID": "test-session-01"}):
        result = check_business_context(
            resource_id=resource_id,
            resource_type="ebs-volume",
            region="us-east-1",
            tags={
                "Owner": "bob", "Team": "storage", "Purpose": "backup",
                "Environment": "staging", "CostCenter": "ops",
            },
        )
    if result["verdict"] == "GO":
        assert _is_context_checked("test-session-01", resource_id)


# ─── delete_resource — BLOCKED without context check ─────────────────────────

@mock_aws
def test_delete_resource_blocked_without_context_check():
    """delete_resource returns BLOCKED when context not checked in this session."""
    from cloud.server import delete_resource, _context_cleared

    _context_cleared.clear()
    with patch.dict(os.environ, {"TRUEFORGE_SESSION_ID": "fresh-session-999"}):
        result = delete_resource(
            resource_id="i-notchecked",
            resource_type="ec2-instance",
            region="us-east-1",
        )
    assert result["status"] == "BLOCKED"
    assert "check_business_context" in result["reason"]


@mock_aws
def test_delete_resource_proceeds_after_context_check():
    """delete_resource proceeds when server-side state confirms context was checked."""
    from cloud.server import delete_resource, _mark_context_checked, _context_cleared

    ec2 = boto3.client("ec2", region_name="us-east-1")
    iid = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1,
                             InstanceType="t3.micro")["Instances"][0]["InstanceId"]
    ec2.stop_instances(InstanceIds=[iid])

    session_id = "test-delete-session"
    _context_cleared.clear()
    _mark_context_checked(session_id, iid)

    with patch.dict(os.environ, {"TRUEFORGE_SESSION_ID": session_id}):
        result = delete_resource(
            resource_id=iid,
            resource_type="ec2-instance",
            region="us-east-1",
        )
    # Should not be BLOCKED — may be TERMINATED or ALREADY_GONE
    assert result["status"] != "BLOCKED"


# ─── TOCTOU: VolumeInUse handling ────────────────────────────────────────────

@mock_aws
def test_delete_resource_handles_volume_in_use():
    """delete_resource handles VolumeInUse gracefully (STATE_CHANGED)."""
    from cloud.server import delete_resource, _mark_context_checked, _context_cleared
    from unittest.mock import MagicMock
    from botocore.exceptions import ClientError

    session_id = "toctou-session"
    resource_id = "vol-toctou001"
    _context_cleared.clear()
    _mark_context_checked(session_id, resource_id)

    error_resp = {"Error": {"Code": "VolumeInUse", "Message": "Volume is in use"}}
    with patch.dict(os.environ, {"TRUEFORGE_SESSION_ID": session_id}):
        with patch("cloud.server._session") as mock_sess:
            mock_ec2 = MagicMock()
            mock_ec2.delete_volume.side_effect = ClientError(error_resp, "DeleteVolume")
            mock_sess.return_value.client.return_value = mock_ec2
            result = delete_resource(
                resource_id=resource_id,
                resource_type="ebs-volume",
                region="us-east-1",
            )
    assert result["status"] == "STATE_CHANGED"


# ─── generate_remediation_script ─────────────────────────────────────────────

def test_generate_remediation_script_dry_run():
    """Script generated with dry_run=True contains DRY_RUN = True."""
    from cloud.server import generate_remediation_script

    resources = [
        {"resource_id": "i-abc123", "resource_type": "ec2-instance", "region": "us-east-1"},
        {"resource_id": "vol-xyz", "resource_type": "ebs-volume", "region": "us-east-1"},
    ]
    result = generate_remediation_script(resources, dry_run=True)
    assert result["script"] is not None
    assert "DRY_RUN = True" in result["script"]
    assert "i-abc123" in result["script"]
    assert "vol-xyz" in result["script"]


def test_generate_remediation_script_rejects_unknown_type():
    """Unknown resource type is commented out, not executed."""
    from cloud.server import generate_remediation_script

    resources = [
        {"resource_id": "rds-abc", "resource_type": "rds-instance", "region": "us-east-1"},
    ]
    result = generate_remediation_script(resources, dry_run=True)
    assert "SKIP" in result["script"]
    assert "rds-instance" in result["script"]


# ─── F1: SQLite session persistence ──────────────────────────────────────────

@mock_aws
def test_sqlite_persistence_survives_reimport():
    """Session state written to SQLite is loadable after clearing in-memory dict."""
    from cloud.server import _mark_context_checked, _is_context_checked, _context_cleared

    _context_cleared.clear()
    session_id = "sqlite-test-session"
    resource_id = "vol-sqlite001"

    _mark_context_checked(session_id, resource_id)
    assert _is_context_checked(session_id, resource_id)

    # Clear in-memory cache (simulates restart)
    _context_cleared.clear()

    # Re-init from SQLite
    from cloud.server import _init_db
    _init_db()

    assert _is_context_checked(session_id, resource_id), "Session state must survive in-memory clear via SQLite reload"


# ─── F2: Partial batch recovery ──────────────────────────────────────────────

@mock_aws
def test_batch_delete_partial_recovery():
    """batch_delete_resources returns partial success when some resources fail."""
    from cloud.server import batch_delete_resources, _mark_context_checked, _context_cleared
    from unittest.mock import MagicMock, patch
    from botocore.exceptions import ClientError

    _context_cleared.clear()
    session_id = "batch-test"

    ec2 = boto3.client("ec2", region_name="us-east-1")
    # Create a real instance to delete
    iid = ec2.run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t3.micro"
    )["Instances"][0]["InstanceId"]
    ec2.stop_instances(InstanceIds=[iid])
    _mark_context_checked(session_id, iid)
    # Second resource NOT context-checked → will be BLOCKED
    nonexistent_rid = "vol-NOTCHECKED"

    with patch.dict(os.environ, {"TRUEFORGE_SESSION_ID": session_id}):
        result = batch_delete_resources([
            {"resource_id": iid, "resource_type": "ec2-instance", "region": "us-east-1"},
            {"resource_id": nonexistent_rid, "resource_type": "ebs-volume", "region": "us-east-1"},
        ])

    assert result["summary"]["total"] == 2
    assert result["summary"]["succeeded"] >= 1
    assert result["summary"]["skipped"] >= 1
    assert result["partial_success"] is True
    assert result["all_succeeded"] is False


# ─── F3: Circuit breaker ─────────────────────────────────────────────────────

def test_circuit_breaker_opens_after_threshold():
    """Circuit opens after _threshold consecutive failure recordings."""
    from cloud.server import _circuit_breaker, _CircuitBreaker

    cb = _CircuitBreaker()
    service, region = "ec2-test", "us-east-1"

    assert not cb.is_open(service, region)
    for _ in range(cb._threshold - 1):
        cb.record_failure(service, region)
    assert not cb.is_open(service, region)  # not yet
    cb.record_failure(service, region)
    assert cb.is_open(service, region)  # now open

    cb.record_success(service, region)
    assert not cb.is_open(service, region)  # reset on success


# ─── F6: Hard anomaly stop ────────────────────────────────────────────────────

@mock_aws
def test_list_idle_ec2_hard_stop_returns_empty_resources():
    """Hard anomaly stop returns status=ANOMALY_STOP and empty resources list."""
    from cloud.server import list_idle_ec2, _RESOURCE_COUNT_CEILING

    ec2 = boto3.client("ec2", region_name="us-east-1")
    for _ in range(_RESOURCE_COUNT_CEILING + 1):
        iid = ec2.run_instances(
            ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t3.micro"
        )["Instances"][0]["InstanceId"]
        ec2.stop_instances(InstanceIds=[iid])

    result = list_idle_ec2(region="us-east-1", min_days=0)
    assert result["status"] == "ANOMALY_STOP"
    assert result["anomaly_detected"] is True
    assert result["resources"] == []  # empty — LLM cannot iterate
    assert result["count"] == 0
    assert "HARD STOP" in result["anomaly_message"]


# ─── Migration Rehearsal MCP ──────────────────────────────────────────────────

def test_restore_db_sandbox_creates_tables():
    """restore_db_sandbox creates tables and snapshots schema."""
    import os
    import tempfile
    db_path = tempfile.mktemp(suffix=".db")
    os.environ["DATABASE_SANDBOX_PATH"] = db_path

    import sys
    for mod in list(sys.modules.keys()):
        if "database.server" in mod:
            del sys.modules[mod]

    from database.server import restore_db_sandbox
    result = restore_db_sandbox(
        schema_ddl="CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL);",
        seed_sql="INSERT INTO users VALUES (1, 'alice'); INSERT INTO users VALUES (2, 'bob');",
        description="test sandbox",
    )
    assert result["status"] == "RESTORED"
    assert "users" in result["tables"]
    assert result["row_counts"]["users"] == 2

    os.unlink(db_path)


def test_run_migration_adds_column():
    """run_migration_in_sandbox detects schema change (new column)."""
    import os
    import tempfile
    db_path = tempfile.mktemp(suffix=".db")
    os.environ["DATABASE_SANDBOX_PATH"] = db_path

    import sys
    for mod in list(sys.modules.keys()):
        if "database.server" in mod:
            del sys.modules[mod]

    from database.server import restore_db_sandbox, run_migration_in_sandbox
    restore_db_sandbox(
        schema_ddl="CREATE TABLE orders (id INTEGER PRIMARY KEY, amount REAL);",
        seed_sql="INSERT INTO orders VALUES (1, 9.99);",
    )
    result = run_migration_in_sandbox(
        migration_sql="ALTER TABLE orders ADD COLUMN currency TEXT DEFAULT 'USD';",
        migration_name="add-currency-column",
    )
    assert result["status"] == "COMPLETED_IN_SANDBOX"
    assert "orders" in result["schema_diff"]["modified_tables"]
    assert result["data_loss_detected"] is False
    assert result["verdict"].startswith("SAFE")

    os.unlink(db_path)


def test_detect_risky_ops_drop_table():
    """_detect_risky_ops flags DROP TABLE as risky."""
    import sys
    for mod in list(sys.modules.keys()):
        if "database.server" in mod:
            del sys.modules[mod]

    from database.server import _detect_risky_ops
    risks = _detect_risky_ops("DROP TABLE users;")
    assert any("DROP TABLE" in r for r in risks)


def test_smoke_queries_rejects_non_select():
    """run_smoke_queries rejects non-SELECT SQL."""
    import os
    import tempfile
    db_path = tempfile.mktemp(suffix=".db")
    os.environ["DATABASE_SANDBOX_PATH"] = db_path

    import sys
    for mod in list(sys.modules.keys()):
        if "database.server" in mod:
            del sys.modules[mod]

    from database.server import restore_db_sandbox, run_smoke_queries
    restore_db_sandbox(schema_ddl="CREATE TABLE t (id INTEGER PRIMARY KEY);")
    result = run_smoke_queries([{"name": "bad", "sql": "DELETE FROM t", "expected_count": None}])
    assert result["all_passed"] is False
    assert result["results"][0]["status"] == "REJECTED"

    os.unlink(db_path)


# ─── Security / Adversarial Tests ────────────────────────────────────────────

def test_resource_id_sanitization_blocks_injection():
    """_sanitize_resource_id strips non-word chars that could break script template."""
    from cloud.server import _sanitize_resource_id

    # Newline injection attempt — must be stripped
    malicious = "i-abc123\nDRY_RUN=False\nos.system('rm -rf /')"
    sanitized = _sanitize_resource_id(malicious)
    assert "\n" not in sanitized
    assert "os.system" not in sanitized
    assert len(sanitized) <= 64


def test_resource_id_sanitization_preserves_valid_ids():
    """_sanitize_resource_id passes through normal AWS IDs unchanged."""
    from cloud.server import _sanitize_resource_id

    normal_ids = ["i-abc1234567890", "vol-0123456789abcdef0", "sg-aabbccdd"]
    for rid in normal_ids:
        assert _sanitize_resource_id(rid) == rid


@mock_aws
def test_toctou_blocks_running_instance():
    """delete_resource aborts if instance state changed to running since scan."""
    from cloud.server import delete_resource, _mark_context_checked, _context_cleared
    from unittest.mock import patch, MagicMock

    ec2 = boto3.client("ec2", region_name="us-east-1")
    iid = ec2.run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t3.micro"
    )["Instances"][0]["InstanceId"]
    # Instance is RUNNING — not stopped

    session_id = "toctou-running"
    _context_cleared.clear()
    _mark_context_checked(session_id, iid)

    with patch.dict(os.environ, {"TRUEFORGE_SESSION_ID": session_id}):
        result = delete_resource(
            resource_id=iid,
            resource_type="ec2-instance",
            region="us-east-1",
        )
    # Running instance must be blocked — not deleted
    assert result["status"] in ("STATE_CHANGED", "BLOCKED", "SKIPPED")


@mock_aws
def test_access_denied_returns_structured_blocked():
    """AccessDenied ClientError produces status=BLOCKED, not raw exception."""
    from cloud.server import delete_resource, _mark_context_checked, _context_cleared
    from unittest.mock import patch, MagicMock
    from botocore.exceptions import ClientError

    session_id = "access-denied-session"
    resource_id = "vol-accessdenied"
    _context_cleared.clear()
    _mark_context_checked(session_id, resource_id)

    error_resp = {"Error": {"Code": "UnauthorizedOperation", "Message": "You are not authorized"}}
    with patch.dict(os.environ, {"TRUEFORGE_SESSION_ID": session_id}):
        with patch("cloud.server._session") as mock_sess:
            mock_ec2 = MagicMock()
            mock_ec2.delete_volume.side_effect = ClientError(error_resp, "DeleteVolume")
            mock_sess.return_value.client.return_value = mock_ec2
            result = delete_resource(
                resource_id=resource_id,
                resource_type="ebs-volume",
                region="us-east-1",
            )
    assert result["status"] == "BLOCKED"
    assert "InsufficientPermissions" in result.get("reason", "")


def test_ast_validation_blocks_subprocess_import():
    """_validate_script_ast returns violations for 'import subprocess'."""
    from cloud.server import _validate_script_ast

    script = "import subprocess\nsubprocess.run(['rm', '-rf', '/'])"
    violations = _validate_script_ast(script)
    assert len(violations) > 0
    assert any("subprocess" in v for v in violations)


def test_ast_validation_blocks_eval():
    """_validate_script_ast catches eval() calls."""
    from cloud.server import _validate_script_ast

    script = "eval(input('cmd> '))"
    violations = _validate_script_ast(script)
    assert any("eval" in v for v in violations)


def test_ast_validation_passes_safe_script():
    """_validate_script_ast returns no violations for a clean boto3 script."""
    from cloud.server import _validate_script_ast

    safe = """
import boto3
ec2 = boto3.client('ec2', region_name='us-east-1')
resp = ec2.describe_instances()
print(resp)
"""
    violations = _validate_script_ast(safe)
    assert violations == []


def test_escalate_is_final_no_retry():
    """invoke_subagent_with_retry stops immediately on ESCALATE — never retries."""
    from router.server import invoke_subagent_with_retry
    from unittest.mock import patch

    call_count = 0

    def mock_invoke(name, task, context, token=""):
        nonlocal call_count
        call_count += 1
        return {"status": "ESCALATE", "output": "ESCALATE — CloudWatch unavailable"}

    with patch("router.server.invoke_subagent", side_effect=mock_invoke):
        result = invoke_subagent_with_retry(
            subagent_name="cloud-cost",
            task="clean idle EC2",
            context={},
            max_retries=3,
            approval_token="",
        )

    # Must stop after first call — not retry 3 more times
    assert call_count == 1
    assert result.get("escalate_final") is True
    assert result.get("escalated") is True


def test_approval_token_single_use():
    """Approval token consumed on first use — second use rejected."""
    from router.server import request_approval_token, invoke_subagent
    from unittest.mock import patch

    token_result = request_approval_token(
        subagent_name="cloud-cost",
        task_preview="delete idle EC2 in us-east-1",
    )
    token = token_result["approval_token"]

    def mock_invoke_success(name, task, ctx, tok=""):
        # Simulate subagent completing (after token consumed by router logic)
        return {"status": "completed", "output": "done"}

    # First invocation — should pass token validation (then go to TrueForge lookup which will fail)
    # We patch _get_agent_id to skip TrueForge HTTP call
    with patch("router.server._get_agent_id", return_value=None):
        first = invoke_subagent(
            subagent_name="cloud-cost",
            task="delete idle EC2",
            context={},
            approval_token=token,
        )
    # Token consumed — second attempt must fail
    with patch("router.server._get_agent_id", return_value=None):
        second = invoke_subagent(
            subagent_name="cloud-cost",
            task="delete idle EC2",
            context={},
            approval_token=token,
        )
    assert second["status"] == "INVALID_APPROVAL_TOKEN"
    assert "already consumed" in second["reason"].lower()


def test_approval_token_wrong_subagent_rejected():
    """Token issued for cloud-cost cannot be used for access-reviewer."""
    from router.server import request_approval_token, invoke_subagent
    from unittest.mock import patch

    token_result = request_approval_token(
        subagent_name="cloud-cost",
        task_preview="delete idle EC2",
    )
    token = token_result["approval_token"]

    with patch("router.server._get_agent_id", return_value=None):
        result = invoke_subagent(
            subagent_name="access-reviewer",
            task="review IAM users",
            context={},
            approval_token=token,
        )
    assert result["status"] == "INVALID_APPROVAL_TOKEN"
    assert "cloud-cost" in result["reason"]


def test_classify_intent_low_confidence_requires_clarification():
    """Completely unrecognized request → clarification_required=True."""
    from router.server import classify_intent

    result = classify_intent("please make me a sandwich with extra cheese")
    assert result["clarification_required"] is True
    assert result["primary"] is None


def test_classify_intent_single_match_routes_correctly():
    """Clear IAM request → access-reviewer with high confidence."""
    from router.server import classify_intent

    result = classify_intent("review IAM roles and overprivileged users")
    assert result["clarification_required"] is False
    assert result["primary"]["subagent"] == "access-reviewer"
    assert result["confidence"] > 0.3


def test_session_ttl_pruning():
    """Sessions older than TTL are pruned from SQLite on _init_db."""
    from cloud.server import _mark_context_checked, _is_context_checked, _context_cleared
    import cloud.server as srv

    _context_cleared.clear()
    session_id = "ttl-prune-session"
    resource_id = "vol-ttl001"

    # Write old record directly into SQLite with a past timestamp
    import sqlite3
    db_path = srv._DB_PATH
    conn = sqlite3.connect(db_path)
    old_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO context_checked (session_id, resource_id, checked_at) VALUES (?, ?, ?)",
        (session_id, resource_id, old_ts),
    )
    conn.commit()
    conn.close()

    # _init_db prunes stale records
    _context_cleared.clear()
    srv._init_db()

    # The old record must be gone
    assert not _is_context_checked(session_id, resource_id), \
        "Stale session older than TTL must be pruned by _init_db"
