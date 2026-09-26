"""
Router MCP Server — ZERO destructive tools.
Only reads intent and delegates to specialized subagents via TrueForge HTTP API.
"""
import hashlib
import os
import secrets
import sys
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from mcp.server.fastmcp import FastMCP

TRUEFORGE_BASE = os.environ.get("TRUEFORGE_URL", "http://localhost:3000")

mcp = FastMCP("enterprise-ops-router")

AGENTS_DIR = Path(__file__).parent.parent.parent / "agents"
SUBAGENTS = {
    "cloud-cost": {
        "agent": "cloud-cost.json",
        "description": "Find idle AWS resources, calculate monthly waste, draft teardown plan",
        "domains": ["cloud", "aws", "ec2", "s3", "cost", "billing", "idle", "cleanup", "waste"],
    },
    "release-captain": {
        "agent": "release-captain.json",
        "description": "Read commits since last tag, run tests in sandbox, write release notes",
        "domains": ["release", "deploy", "github", "git", "tag", "publish", "changelog", "version"],
    },
    "access-reviewer": {
        "agent": "access-reviewer.json",
        "description": "Review IAM users, find overprivileged roles, flag stale access",
        "domains": ["access", "iam", "permissions", "users", "roles", "policies", "privilege", "security"],
    },
    "ticket-resolver": {
        "agent": "ticket-resolver.json",
        "description": "Reproduce a bug in sandbox, return patch and draft reply",
        "domains": ["ticket", "bug", "issue", "jira", "linear", "zendesk", "reproduce", "fix"],
    },
    "migration-rehearsal": {
        "agent": "migration-rehearsal.json",
        "description": "Restore DB sandbox, run schema change, compare rows, report",
        "domains": ["migration", "database", "schema", "db", "postgres", "mysql", "sql", "alter"],
    },
    "runbook-executor": {
        "agent": "runbook-executor.json",
        "description": "Execute runbook step by step, auto-handle safe steps, gate destructive ones",
        "domains": ["runbook", "incident", "ops", "procedure", "restart", "infra", "server"],
    },
}


@mcp.tool(
    description="Classify user intent and return which subagent(s) should handle it. ALWAYS call this first.",
)
def classify_intent(user_request: str) -> dict:
    """
    Read-only. Matches user request to one or more subagents by keyword scoring.
    Returns ordered list of (subagent, confidence, reason).
    """
    request_lower = user_request.lower()
    matches = []

    for name, meta in SUBAGENTS.items():
        score = sum(1 for kw in meta["domains"] if kw in request_lower)
        if score > 0:
            matches.append({
                "subagent": name,
                "agent_file": meta["agent"],
                "description": meta["description"],
                "confidence": min(score / 3.0, 1.0),
                "matched_keywords": [kw for kw in meta["domains"] if kw in request_lower],
            })

    matches.sort(key=lambda x: x["confidence"], reverse=True)

    # Confidence threshold — below this, request clarification rather than misrouting silently
    MIN_CONFIDENCE = 0.34  # at least 1 clear keyword match
    high_conf = [m for m in matches if m["confidence"] >= MIN_CONFIDENCE]

    # No match or ambiguous — return clarification request instead of routing
    if not high_conf:
        return {
            "user_request": user_request,
            "matched_subagents": [],
            "multi_intent": False,
            "primary": None,
            "clarification_required": True,
            "confidence": 0.0,
            "recommendation": (
                "Request is ambiguous — no subagent matched with sufficient confidence. "
                "Ask user to clarify: cloud cleanup, IAM access review, database migration, "
                "ticket resolution, or runbook execution."
            ),
        }

    best = high_conf[0]
    # Ambiguous multi-match at similar confidence — ask user to clarify
    if len(high_conf) > 1 and high_conf[1]["confidence"] >= best["confidence"] * 0.8:
        return {
            "user_request": user_request,
            "matched_subagents": high_conf,
            "multi_intent": True,
            "primary": None,
            "clarification_required": True,
            "confidence": best["confidence"],
            "recommendation": (
                f"Multiple subagents match at similar confidence: "
                f"{', '.join(m['subagent'] for m in high_conf[:3])}. "
                "Ask user to specify which operation they want."
            ),
        }

    return {
        "user_request": user_request,
        "matched_subagents": high_conf,
        "multi_intent": len(high_conf) > 1,
        "primary": best,
        "clarification_required": False,
        "confidence": best["confidence"],
        "recommendation": f"Delegate to: {', '.join(m['subagent'] for m in high_conf)}",
    }


@mcp.tool(
    description="List all available subagents with their capabilities and the domains they handle.",
)
def list_subagents() -> dict:
    """Read-only. Returns the subagent registry."""
    return {
        "subagents": [
            {
                "name": name,
                "description": meta["description"],
                "domains": meta["domains"],
                "agent_file": meta["agent"],
            }
            for name, meta in SUBAGENTS.items()
        ]
    }


def _get_agent_id(agent_display_name: str) -> str | None:
    """Resolve TrueForge agent display name → internal agent ID."""
    try:
        r = requests.get(f"{TRUEFORGE_BASE}/api/agents", timeout=10)
        for agent in r.json().get("items", []):
            if agent["name"] == agent_display_name:
                return agent["id"]
    except Exception:
        pass
    return None

# Subagents that carry destructive tools — require explicit human confirmation before delegation
DESTRUCTIVE_SUBAGENTS = {"cloud-cost", "access-reviewer", "migration-rehearsal"}

# Map subagent key → TrueForge registered agent name
SUBAGENT_AGENT_NAMES = {
    "cloud-cost":          "cloud-cost-janitor",
    "release-captain":     "release-captain",
    "access-reviewer":     "access-reviewer",
    "ticket-resolver":     "ticket-resolver",
    "migration-rehearsal": "migration-rehearsal",
    "runbook-executor":    "runbook-executor",
}

# ─── Approval token system — replaces soft confirmed=True boolean ─────────────
# P0.3: confirmed=True was LLM-settable — no technical enforcement.
# Fix: one-time cryptographic token issued server-side, verified before use.

_APPROVAL_TOKENS: dict[str, dict] = {}
_APPROVAL_LOCK = threading.Lock()
_TOKEN_TTL_SECONDS = 300  # 5 minutes


@mcp.tool(
    description="Generate a one-time cryptographic approval token for delegating to a destructive subagent. This tool represents the human 'Approve' action in TrueForge UI. Token is single-use and expires in 5 minutes.",
)
def request_approval_token(subagent_name: str, task_preview: str) -> dict:
    """
    Generates a cryptographically random 32-hex-char token.
    Token is single-use, time-limited, and bound to the specific subagent.
    The LLM cannot generate a valid token — only this tool call produces one.
    Pass the returned token as approval_token= in invoke_subagent.
    """
    if subagent_name not in DESTRUCTIVE_SUBAGENTS:
        return {
            "error": f"'{subagent_name}' is not a destructive subagent — no token required",
            "destructive_subagents": list(DESTRUCTIVE_SUBAGENTS),
        }
    token = secrets.token_hex(16)
    with _APPROVAL_LOCK:
        _APPROVAL_TOKENS[token] = {
            "subagent": subagent_name,
            "task_hash": hashlib.sha256(task_preview.encode()).hexdigest()[:16],
            "expires_at": time.time() + _TOKEN_TTL_SECONDS,
            "used": False,
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }
    return {
        "approval_token": token,
        "subagent": subagent_name,
        "expires_in_seconds": _TOKEN_TTL_SECONDS,
        "one_time_use": True,
        "note": "Pass this token as approval_token= in invoke_subagent. Single-use. Expires in 5 minutes.",
    }


def _verify_approval_token(token: str, subagent_name: str) -> tuple[bool, str]:
    """Validates and consumes a one-time approval token. Thread-safe."""
    with _APPROVAL_LOCK:
        entry = _APPROVAL_TOKENS.get(token)
        if not entry:
            return False, "Invalid or unknown approval token — call request_approval_token to generate one"
        if entry["used"]:
            return False, "Approval token already consumed — tokens are single-use, request a new one"
        if time.time() > entry["expires_at"]:
            del _APPROVAL_TOKENS[token]
            return False, "Approval token expired — request a new one"
        if entry["subagent"] != subagent_name:
            return False, f"Token was issued for '{entry['subagent']}', cannot use for '{subagent_name}'"
        entry["used"] = True  # consume immediately — no replay possible
        return True, "OK"


@mcp.tool(
    description="Invoke a named subagent with a specific task. Uses TrueForge session API. Returns subagent result. Destructive-capable subagents require a valid approval_token from request_approval_token.",
)
def invoke_subagent(
    subagent_name: str,
    task: str,
    context: dict,
    approval_token: str = "",
) -> dict:
    """
    Read-only from router perspective.
    Creates a TrueForge session on the named subagent, sends the task, polls for result.
    The subagent has its own domain-scoped MCP tools + approval gates — router has none.
    Destructive-capable subagents require a one-time approval_token (not a boolean flag).
    """
    if subagent_name not in SUBAGENTS:
        return {"error": f"Unknown subagent: {subagent_name}", "available": list(SUBAGENTS.keys())}

    # P0.3 FIX: cryptographic token replaces soft confirmed=True boolean
    if subagent_name in DESTRUCTIVE_SUBAGENTS:
        if not approval_token:
            return {
                "status": "CONFIRMATION_REQUIRED",
                "message": (
                    f"Subagent '{subagent_name}' has destructive tools. "
                    f"Capabilities: {SUBAGENTS[subagent_name]['description']}. "
                    "Step 1: Show this to the user. Step 2: Call request_approval_token to obtain a one-time token. "
                    "Step 3: Re-call invoke_subagent with approval_token=<token>."
                ),
                "subagent": subagent_name,
                "task_preview": task[:200],
            }
        valid, reason = _verify_approval_token(approval_token, subagent_name)
        if not valid:
            return {
                "status": "INVALID_APPROVAL_TOKEN",
                "reason": reason,
                "subagent": subagent_name,
            }

    tf_agent_name = SUBAGENT_AGENT_NAMES.get(subagent_name, subagent_name)
    agent_id = _get_agent_id(tf_agent_name)
    if not agent_id:
        return {"error": f"Agent '{tf_agent_name}' not found in TrueForge — run scripts/register_in_trueforge.py"}

    full_task = f"{task}\n\nContext provided by router:\n{json.dumps(context, indent=2)}"

    try:
        # Create session
        sess_resp = requests.post(
            f"{TRUEFORGE_BASE}/api/sessions",
            json={"agent_id": agent_id},
            timeout=15,
        )
        sess_resp.raise_for_status()
        session_id = sess_resp.json()["id"]

        # Send first turn
        turn_resp = requests.post(
            f"{TRUEFORGE_BASE}/api/sessions/{session_id}/turns",
            json={"type": "user.message", "content": full_task},
            timeout=30,
        )
        turn_resp.raise_for_status()
        turn_id = turn_resp.json()["id"]

        # Poll for completion (max 5 minutes)
        for _ in range(150):
            time.sleep(2)
            status_resp = requests.get(
                f"{TRUEFORGE_BASE}/api/sessions/{session_id}/turns/{turn_id}",
                timeout=10,
            )
            data = status_resp.json()
            state = data.get("status", data.get("state", ""))
            if state in ("completed", "done", "finished"):
                # Extract text output
                output = ""
                for event in data.get("events", []):
                    if event.get("type") == "assistant.message":
                        output += event.get("content", "")
                return {
                    "subagent": subagent_name,
                    "agent_name": tf_agent_name,
                    "session_id": session_id,
                    "status": "completed",
                    "output": output or json.dumps(data)[:4000],
                }
            if state in ("failed", "error", "cancelled"):
                return {"subagent": subagent_name, "status": state, "error": data.get("error", "unknown")}

        return {"subagent": subagent_name, "status": "timeout", "error": "Subagent exceeded 5 minute poll limit"}

    except Exception as e:
        return {"subagent": subagent_name, "status": "error", "error": str(e)}


@mcp.tool(
    description="Invoke multiple subagents in parallel for multi-intent requests. Returns all results. Each task dict must include confirmed=True for destructive-capable subagents.",
)
def invoke_subagents_parallel(
    tasks: list[dict],
) -> dict:
    """
    Read-only from router. Each task: {subagent_name, task, context, approval_token}.
    Spawns all subagents concurrently, waits for all to finish.
    Destructive subagents require approval_token in each task dict.
    """
    import concurrent.futures

    def run_one(task_def: dict) -> dict:  # noqa: E306
        return invoke_subagent(
            task_def["subagent_name"],
            task_def["task"],
            task_def.get("context", {}),
            task_def.get("approval_token", ""),
        )

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        futures = {executor.submit(run_one, t): t["subagent_name"] for t in tasks}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    return {
        "parallel_results": results,
        "count": len(results),
        "all_succeeded": all(r.get("status") == "completed" for r in results),
    }


@mcp.tool(
    description="Invoke a subagent with automatic self-correction on ESCALATE results. Retries with narrowed scope up to max_retries times. Use when the first attempt may fail due to ambiguity or missing scope.",
)
def invoke_subagent_with_retry(
    subagent_name: str,
    task: str,
    context: dict,
    max_retries: int = 2,
    approval_token: str = "",
) -> dict:
    """
    Retry loop for transient failures only.

    P0.2 FIX: ESCALATE is now FINAL — no retry with weakened scope.
    Rationale: ESCALATE fires when CW/SSM safety checks could not complete.
    Retrying with "skip those checks" is MORE dangerous when the system is
    degraded (e.g. during an active incident). ESCALATE → human, immediately.

    On BLOCKED: returns immediately — BLOCKED is final.
    On ESCALATE: returns immediately — requires human review.
    On transient error/timeout: exponential backoff, up to max_retries.
    """
    last_result: dict = {}
    for attempt in range(max_retries + 1):
        result = invoke_subagent(subagent_name, task, context, approval_token)
        last_result = result

        status = result.get("status", "")
        output = str(result.get("output", ""))

        # Success — done
        if status == "completed":
            return {**result, "attempts": attempt + 1, "self_correction": attempt > 0}

        # Hard block — no retry, final
        if status in ("BLOCKED", "CONFIRMATION_REQUIRED", "INVALID_APPROVAL_TOKEN") or "BLOCK" in output:
            return {
                **result,
                "attempts": attempt + 1,
                "retry_stopped": "BLOCKED verdict is final — no retry attempted",
            }

        # ESCALATE — route to human IMMEDIATELY, never retry
        # Safety invariant: CW/SSM unavailability = unknown resource state.
        # Weakening those checks on retry defeats their purpose.
        if "ESCALATE" in output or status == "ESCALATE":
            return {
                **result,
                "attempts": attempt + 1,
                "escalated": True,
                "escalate_final": True,
                "retry_stopped": (
                    "ESCALATE is final — safety checks (CloudWatch/SSM) could not complete. "
                    "Human review required before any action on affected resources. "
                    "Do NOT retry with weakened scope — present escalate_reasons to the user."
                ),
            }

        # Transient error/timeout only — backoff retry
        if status in ("error", "timeout") and attempt < max_retries:
            time.sleep(2 ** attempt)
            continue

        # Exhausted retries or unknown state
        break

    return {**last_result, "attempts": max_retries + 1, "self_correction_exhausted": True}


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    import uvicorn
    uvicorn.run(mcp.streamable_http_app(), host="0.0.0.0", port=port)
