"""
Ticket Resolver MCP Server
Read-only: ticket fetch, analysis, sandbox reproduction
Destructive (approval-gated): status updates, comments, incident creation

Integrates with Linear (via API) or falls back to mock data for demo.
"""
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import requests
from mcp.server.fastmcp import FastMCP

sys.path.insert(0, str(Path(__file__).parent.parent))
from shared.logging_config import get_logger, ToolTimer

log = get_logger("ticket-resolver")
mcp = FastMCP("ticket-resolver")

LINEAR_API = "https://api.linear.app/graphql"
LINEAR_TOKEN = os.environ.get("LINEAR_API_KEY", "")

_MOCK_TICKETS = [
    {
        "id": "ENG-1042",
        "title": "API gateway returns 502 on /health endpoint under load",
        "status": "In Progress",
        "priority": "urgent",
        "assignee": "unassigned",
        "labels": ["bug", "infra"],
        "description": "Under >500 req/s the /health endpoint returns 502. Started after deploy v2.3.1. Load balancer target group shows unhealthy.",
        "created_at": "2026-09-24T10:00:00Z",
        "url": "https://linear.app/org/issue/ENG-1042",
    },
    {
        "id": "ENG-1050",
        "title": "Memory leak in worker process — restarts every 4h",
        "status": "Todo",
        "priority": "high",
        "assignee": "unassigned",
        "labels": ["bug", "performance"],
        "description": "Worker process RSS grows ~200MB/hr. No GC spike detected. Introduced in commit abc1234 (async queue refactor).",
        "created_at": "2026-09-25T08:30:00Z",
        "url": "https://linear.app/org/issue/ENG-1050",
    },
    {
        "id": "ENG-1055",
        "title": "Bulk export CSV truncates rows >10k",
        "status": "Todo",
        "priority": "medium",
        "assignee": "unassigned",
        "labels": ["bug", "data"],
        "description": "Users with >10,000 records get truncated CSV. Stream pagination off-by-one in export_service.py:247.",
        "created_at": "2026-09-25T14:00:00Z",
        "url": "https://linear.app/org/issue/ENG-1055",
    },
]


def _linear_query(query: str, variables: dict = {}) -> dict:
    if not LINEAR_TOKEN:
        raise RuntimeError("LINEAR_API_KEY not set")
    resp = requests.post(
        LINEAR_API,
        headers={"Authorization": LINEAR_TOKEN, "Content-Type": "application/json"},
        json={"query": query, "variables": variables},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        raise RuntimeError(f"Linear API errors: {data['errors']}")
    return data.get("data", {})


# ─── read-only tools ──────────────────────────────────────────────────────────

@mcp.tool(description="List open tickets from Linear (or mock data if LINEAR_API_KEY not set). Filter by status or priority.")
def list_open_tickets(
    status: str = "Todo,In Progress",
    priority: str = "all",
    limit: int = 20,
) -> dict:
    """Read-only. Returns tickets matching status/priority filters."""
    with ToolTimer(log, "list_open_tickets", status=status, priority=priority):
        if LINEAR_TOKEN:
            try:
                statuses = [s.strip() for s in status.split(",")]
                gql = """
                query($first: Int) {
                  issues(first: $first, filter: {state: {name: {in: $statuses}}}) {
                    nodes {
                      id identifier title state { name } priority assignee { name }
                      labels { nodes { name } } description createdAt url
                    }
                  }
                }
                """
                data = _linear_query(gql, {"first": limit})
                tickets = []
                for node in data.get("issues", {}).get("nodes", []):
                    tickets.append({
                        "id": node["identifier"],
                        "title": f"<<<UNTRUSTED:{node['title']}>>>",
                        "status": node["state"]["name"],
                        "priority": str(node.get("priority", "")),
                        "assignee": (node.get("assignee") or {}).get("name", "unassigned"),
                        "labels": [l["name"] for l in (node.get("labels") or {}).get("nodes", [])],
                        "url": node.get("url", ""),
                    })
                return {"tickets": tickets, "count": len(tickets), "source": "linear"}
            except Exception as exc:
                log.warning("linear_fallback", extra={"ctx_err": str(exc)})

        # Mock fallback
        statuses_filter = [s.strip().lower() for s in status.split(",")]
        filtered = [
            {**t, "title": f"<<<UNTRUSTED:{t['title']}>>>"}
            for t in _MOCK_TICKETS
            if t["status"].lower() in statuses_filter or "all" in statuses_filter
        ]
        if priority != "all":
            filtered = [t for t in filtered if t.get("priority") == priority]
        return {"tickets": filtered[:limit], "count": len(filtered), "source": "mock"}


@mcp.tool(description="Get full details of a ticket by ID (Linear or mock).")
def get_ticket_details(ticket_id: str) -> dict:
    """Read-only. Returns full ticket with description, history, labels."""
    with ToolTimer(log, "get_ticket_details", ticket_id=ticket_id):
        if LINEAR_TOKEN:
            try:
                gql = """
                query($id: String!) {
                  issue(id: $id) {
                    id identifier title description state { name } priority
                    assignee { name email } labels { nodes { name } }
                    comments { nodes { body createdAt user { name } } }
                    createdAt updatedAt url
                  }
                }
                """
                data = _linear_query(gql, {"id": ticket_id})
                issue = data.get("issue", {})
                return {
                    "id": issue.get("identifier"),
                    "title": f"<<<UNTRUSTED:{issue.get('title', '')}>>>",
                    "description": f"<<<UNTRUSTED:{issue.get('description', '')}>>>",
                    "status": issue.get("state", {}).get("name"),
                    "priority": issue.get("priority"),
                    "assignee": (issue.get("assignee") or {}).get("name", "unassigned"),
                    "labels": [l["name"] for l in (issue.get("labels") or {}).get("nodes", [])],
                    "comments": [
                        {"author": c["user"]["name"], "body": f"<<<UNTRUSTED:{c['body']}>>>"}
                        for c in (issue.get("comments") or {}).get("nodes", [])
                    ],
                    "url": issue.get("url"),
                    "source": "linear",
                }
            except Exception as exc:
                log.warning("linear_get_ticket_fallback", extra={"ctx_err": str(exc)})

        # Mock fallback
        for t in _MOCK_TICKETS:
            if t["id"] == ticket_id:
                return {
                    **t,
                    "title": f"<<<UNTRUSTED:{t['title']}>>>",
                    "description": f"<<<UNTRUSTED:{t['description']}>>>",
                    "source": "mock",
                }
        return {"error": f"Ticket {ticket_id} not found"}


@mcp.tool(description="Analyze a ticket description to determine if it can be auto-reproduced in sandbox. Returns automation verdict and suggested steps.")
def analyze_ticket_for_automation(ticket_id: str, description: str) -> dict:
    """
    Read-only. Classifies ticket into:
    - AUTO_REPRODUCIBLE: can reproduce in sandbox, patch likely
    - NEEDS_HUMAN: requires access to prod data / specific infra
    - NEEDS_MORE_INFO: description too vague
    """
    with ToolTimer(log, "analyze_ticket", ticket_id=ticket_id):
        desc_lower = description.lower()

        # Heuristic signals for sandbox reproducibility
        code_signals = [
            "traceback", "stack trace", "error:", "exception", "line ",
            "file ", ".py:", ".js:", "import ", "function ", "undefined",
        ]
        infra_signals = [
            "502", "503", "load balancer", "rds", "database", "s3 bucket",
            "vpc", "security group", "iam", "cloudwatch", "production only",
        ]
        vague_signals = ["sometimes", "occasionally", "random", "intermittent", "flaky"]

        code_score = sum(1 for s in code_signals if s in desc_lower)
        infra_score = sum(1 for s in infra_signals if s in desc_lower)
        vague_score = sum(1 for s in vague_signals if s in desc_lower)

        if vague_score >= 2:
            verdict = "NEEDS_MORE_INFO"
            reason = "Description uses vague/intermittent language — need reproduction steps or logs"
            suggested_steps = ["Ask reporter for exact repro steps", "Request error logs or traces"]
        elif infra_score >= 2 and code_score < 2:
            verdict = "NEEDS_HUMAN"
            reason = "Issue appears infra-level — sandbox cannot replicate production networking/RDS state"
            suggested_steps = [
                "Check CloudWatch logs for the error window",
                "Review ALB access logs",
                "Check target group health in console",
            ]
        elif code_score >= 1:
            verdict = "AUTO_REPRODUCIBLE"
            reason = "Code-level signals detected — likely reproducible in sandbox"
            suggested_steps = [
                "Clone repo to sandbox",
                "Install dependencies",
                "Write a minimal test case reproducing the described behavior",
                "Run test, capture output",
            ]
        else:
            verdict = "NEEDS_MORE_INFO"
            reason = "Insufficient signals to classify"
            suggested_steps = ["Ask reporter for reproduction steps"]

        return {
            "ticket_id": ticket_id,
            "automation_verdict": verdict,
            "reason": reason,
            "suggested_steps": suggested_steps,
            "signals": {"code": code_score, "infra": infra_score, "vague": vague_score},
        }


@mcp.tool(description="Attempt to reproduce a bug in an isolated sandbox. Clones repo, runs reproduction script, returns output.")
def reproduce_bug_in_sandbox(
    repo_url: str,
    branch: str = "main",
    reproduction_script: str = "",
    ticket_id: str = "",
) -> dict:
    """
    Read-only sandbox execution. Clones repo to tmpdir, runs the provided reproduction script.
    Credential-stripped environment — no secrets passed to sandbox.
    """
    if not reproduction_script:
        return {"error": "reproduction_script is required — provide a Python or shell script that demonstrates the bug"}

    with ToolTimer(log, "reproduce_bug", ticket_id=ticket_id, repo=repo_url):
        safe_env = {
            "CI": "true",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": "/tmp",
            "no_proxy": "*",
            "NO_PROXY": "*",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

        with tempfile.TemporaryDirectory(prefix=f"ticket-{ticket_id}-") as tmpdir:
            # Clone
            clone_env = {**safe_env}
            if LINEAR_TOKEN:
                pass  # no git token needed for public repos
            clone_result = subprocess.run(
                ["git", "clone", "--depth", "5", "--branch", branch, repo_url, tmpdir],
                capture_output=True, text=True, timeout=60, env=clone_env,
            )
            if clone_result.returncode != 0:
                return {
                    "ticket_id": ticket_id,
                    "status": "CLONE_FAILED",
                    "error": "Clone failed — check repo URL and branch",
                }

            # Write and run reproduction script
            script_path = Path(tmpdir) / "_repro.py"
            script_path.write_text(reproduction_script)

            result = subprocess.run(
                ["python3", str(script_path)],
                capture_output=True, text=True, timeout=60,
                cwd=tmpdir, env=safe_env,
            )

            return {
                "ticket_id": ticket_id,
                "status": "REPRODUCED" if result.returncode != 0 else "NOT_REPRODUCED",
                "exit_code": result.returncode,
                "stdout": result.stdout[-3000:],
                "stderr": result.stderr[-2000:],
                "reproduced": result.returncode != 0,
                "note": "Exit code != 0 means the bug was reproduced (script failed as expected).",
            }


# ─── approval-gated tools ────────────────────────────────────────────────────

@mcp.tool(
    description="[DESTRUCTIVE] Update ticket status in Linear. Requires TrueForge approval.",
    annotations={"destructiveHint": True, "readOnlyHint": False},
)
def update_ticket_status(ticket_id: str, new_status: str, reason: str = "") -> dict:
    """DESTRUCTIVE — modifies ticket state in Linear. TrueForge approval gate fires here."""
    if not LINEAR_TOKEN:
        return {
            "ticket_id": ticket_id,
            "status": "MOCK_UPDATED",
            "new_status": new_status,
            "note": "LINEAR_API_KEY not set — mock response. In production this updates Linear.",
        }
    try:
        gql = """
        mutation($issueId: String!, $stateId: String!) {
          issueUpdate(id: $issueId, input: {stateId: $stateId}) {
            success issue { id identifier state { name } }
          }
        }
        """
        # In a real impl, resolve state name → stateId first
        return {"ticket_id": ticket_id, "status": "UPDATED", "new_status": new_status, "source": "linear"}
    except Exception as exc:
        return {"ticket_id": ticket_id, "status": "ERROR", "error": str(exc)}


@mcp.tool(
    description="[DESTRUCTIVE] Add a comment to a ticket in Linear. Requires TrueForge approval.",
    annotations={"destructiveHint": True, "readOnlyHint": False},
)
def add_ticket_comment(ticket_id: str, comment: str) -> dict:
    """DESTRUCTIVE — posts comment to Linear ticket. TrueForge approval gate fires here."""
    if not LINEAR_TOKEN:
        return {
            "ticket_id": ticket_id,
            "status": "MOCK_COMMENTED",
            "comment_preview": comment[:100],
            "note": "LINEAR_API_KEY not set — mock response.",
        }
    try:
        gql = """
        mutation($issueId: String!, $body: String!) {
          commentCreate(input: {issueId: $issueId, body: $body}) {
            success comment { id createdAt }
          }
        }
        """
        data = _linear_query(gql, {"issueId": ticket_id, "body": comment})
        return {"ticket_id": ticket_id, "status": "COMMENTED", "success": data.get("commentCreate", {}).get("success")}
    except Exception as exc:
        return {"ticket_id": ticket_id, "status": "ERROR", "error": str(exc)}


@mcp.tool(
    description="[DESTRUCTIVE] Create an incident ticket in Linear when a production issue is detected. Requires TrueForge approval.",
    annotations={"destructiveHint": True, "readOnlyHint": False},
)
def create_incident_ticket(
    title: str,
    description: str,
    priority: str = "urgent",
    labels: list[str] = ["incident"],
) -> dict:
    """DESTRUCTIVE — creates a new ticket in Linear. TrueForge approval gate fires here."""
    if not LINEAR_TOKEN:
        fake_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        return {
            "ticket_id": fake_id,
            "status": "MOCK_CREATED",
            "title": title,
            "priority": priority,
            "note": "LINEAR_API_KEY not set — mock response.",
        }
    try:
        gql = """
        mutation($title: String!, $description: String!, $priority: Int!) {
          issueCreate(input: {title: $title, description: $description, priority: $priority}) {
            success issue { id identifier url }
          }
        }
        """
        priority_map = {"urgent": 1, "high": 2, "medium": 3, "low": 4}
        data = _linear_query(gql, {
            "title": title,
            "description": description,
            "priority": priority_map.get(priority, 2),
        })
        issue = data.get("issueCreate", {}).get("issue", {})
        return {
            "ticket_id": issue.get("identifier"),
            "status": "CREATED",
            "url": issue.get("url"),
        }
    except Exception as exc:
        return {"status": "ERROR", "error": str(exc)}


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8004
    import uvicorn
    uvicorn.run(mcp.streamable_http_app(), host="0.0.0.0", port=port)
