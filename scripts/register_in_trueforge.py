"""
Registers all MCP servers and creates all agents in TrueForge via its HTTP API.
Run AFTER TrueForge is up (with ALLOWED_HOSTS set so it can reach local MCP servers).

Usage:
    # Start TrueForge with local host allowed:
    ALLOWED_HOSTS='["localhost","127.0.0.1"]' npx @truefoundry/trueforge@latest

    # Then in another terminal:
    ANTHROPIC_API_KEY=sk-ant-... python3 scripts/register_in_trueforge.py

    # Override host if needed:
    python3 scripts/register_in_trueforge.py --mcp-host 192.168.1.10
"""
import argparse
import json
import socket
import sys
import time
from pathlib import Path

import requests

AGENTS_DIR = Path(__file__).parent.parent / "agents"
BASE = "http://localhost:8790"


def _get_host_ip() -> str:
    """Return the machine's primary non-loopback IP (for TrueForge → Docker port reach)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _build_mcp_servers(host: str) -> dict:
    return {
        "ops-router":                (f"http://{host}:8000/mcp", "Router: intent classification and subagent dispatch"),
        "cloud-cost-tools":          (f"http://{host}:8001/mcp", "Cloud Cost Janitor: AWS EC2/EBS/EIP/ELB idle resource cleanup"),
        "release-captain-tools":     (f"http://{host}:8002/mcp", "Release Captain: GitHub tag, release, and publish management"),
        "access-reviewer-tools":     (f"http://{host}:8003/mcp", "Access Reviewer: AWS IAM user and role access review"),
        "ticket-resolver-tools":     (f"http://{host}:8004/mcp", "Ticket Resolver: Linear/Jira ticket triage and patch application"),
        "migration-rehearsal-tools": (f"http://{host}:8005/mcp", "Migration Rehearsal: DB schema sandbox and production apply"),
        "runbook-executor-tools":    (f"http://{host}:8006/mcp", "Runbook Executor: infra procedure execution"),
    }

AGENTS = {
    "enterprise-ops-router": ("router.json",           "Multi-domain ops router: cloud cost, releases, IAM, tickets"),
    "cloud-cost-janitor":    ("cloud-cost.json",       "AWS idle resource cleanup with 5-signal safety gate"),
    "release-captain":       ("release-captain.json",  "GitHub release and tag management"),
    "access-reviewer":       ("access-reviewer.json",  "AWS IAM stale access review and disable"),
    "ticket-resolver":       ("ticket-resolver.json",  "Linear/Jira ticket triage and sandbox patch"),
    "migration-rehearsal":   ("migration-rehearsal.json", "DB schema sandbox and production migration"),
    "runbook-executor":      ("runbook-executor.json", "Infra runbook procedure execution"),
}


ANTHROPIC_API_KEY = None  # set via --anthropic-api-key or ANTHROPIC_API_KEY env var


def register_model_provider(base: str, api_key: str) -> None:
    print("\n── Registering Anthropic model provider ──")
    try:
        existing = requests.get(f"{base}/api/v1/settings/model-providers", timeout=10).json()
        for p in existing.get("data", []):
            if p.get("manifest", {}).get("type") == "anthropic":
                print("  ⏭  Anthropic provider already configured")
                return
    except Exception:
        pass

    payload = {
        "manifest": {
            "type": "anthropic",
            "auth": {"api_key": api_key},
            "models": [
                {
                    "model_id": "claude-sonnet-4-6",
                    "name": "claude-sonnet-4-6",
                    "properties": {
                        "context_length": 200000,
                        "max_output_tokens": 8096,
                    },
                }
            ],
        }
    }
    try:
        r = requests.post(f"{base}/api/v1/settings/model-providers", json=payload, timeout=10)
        if r.status_code in (200, 201):
            print("  ✅ Anthropic provider registered (claude-sonnet-4-6)")
        else:
            print(f"  ❌ Anthropic provider: HTTP {r.status_code} — {r.text[:300]}")
    except Exception as e:
        print(f"  ❌ Anthropic provider: {e}")


def wait_for_trueforge(base: str, timeout: int = 30) -> bool:
    print(f"Waiting for TrueForge at {base}...")
    for _ in range(timeout):
        try:
            r = requests.get(f"{base}/api/v1/agents", timeout=2)
            if r.status_code < 500:
                print("  ✅ TrueForge is up")
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def register_mcp_servers(base: str, mcp_servers: dict) -> None:
    print("\n── Registering MCP servers ──")
    try:
        existing_resp = requests.get(f"{base}/api/v1/settings/mcp-servers", timeout=10)
        existing = {s["manifest"]["name"]: s for s in existing_resp.json().get("data", [])}
    except Exception:
        existing = {}

    for name, (url, description) in mcp_servers.items():
        if name in existing:
            print(f"  ⏭  {name} already registered")
            continue

        payload = {
            "manifest": {
                "type": "remote",
                "name": name,
                "url": url,
                "description": description,
            }
        }
        try:
            r = requests.post(f"{base}/api/v1/settings/mcp-servers", json=payload, timeout=10)
            if r.status_code in (200, 201):
                print(f"  ✅ {name} → {url}")
            else:
                print(f"  ❌ {name}: HTTP {r.status_code} — {r.text[:300]}")
        except Exception as e:
            print(f"  ❌ {name}: {e}")


def create_agents(base: str, model: str | None = None) -> None:
    print("\n── Creating agents ──")
    if model:
        print(f"  Model override: {model}")
    try:
        existing_resp = requests.get(f"{base}/api/v1/agents", timeout=10)
        existing = {a["name"]: a["id"] for a in existing_resp.json().get("data", [])}
    except Exception:
        existing = {}

    for agent_name, (agent_file, description) in AGENTS.items():
        config_path = AGENTS_DIR / agent_file
        if not config_path.exists():
            print(f"  ⚠️  {agent_name}: config not found at {config_path}, skipping")
            continue

        with open(config_path) as f:
            spec = json.load(f)

        if model:
            spec.setdefault("model", {})["name"] = model

        payload = {
            "name": agent_name,
            "description": description,
            "manifest": spec,
        }

        if agent_name in existing:
            agent_id = existing[agent_name]
            update_payload = {"description": description, "manifest": spec}
            try:
                r = requests.put(f"{base}/api/v1/agents/{agent_id}", json=update_payload, timeout=10)
                if r.status_code in (200, 204):
                    print(f"  🔄 {agent_name} updated")
                else:
                    print(f"  ❌ {agent_name} update: HTTP {r.status_code} — {r.text[:300]}")
            except Exception as e:
                print(f"  ❌ {agent_name} update: {e}")
        else:
            try:
                r = requests.post(f"{base}/api/v1/agents", json=payload, timeout=10)
                if r.status_code in (200, 201):
                    data = r.json()
                    agent_id = data.get("id", data.get("data", {}).get("id", "?"))
                    print(f"  ✅ {agent_name} created (id={agent_id})")
                else:
                    print(f"  ❌ {agent_name}: HTTP {r.status_code} — {r.text[:300]}")
            except Exception as e:
                print(f"  ❌ {agent_name}: {e}")


def main():
    import os
    parser = argparse.ArgumentParser()
    parser.add_argument("--trueforge-url", default=BASE)
    parser.add_argument("--anthropic-api-key", default=os.environ.get("ANTHROPIC_API_KEY", ""))
    parser.add_argument("--mcp-host", default=None,
                        help="Host IP for MCP server URLs (auto-detected if not set)")
    parser.add_argument("--model", default=None,
                        help="Override agent model, e.g. openrouter/gpt-4o-mini or anthropic/claude-sonnet-4-6 "
                             "(falls back to AGENT_MODEL env var, then value in each agent JSON)")
    args = parser.parse_args()
    base = args.trueforge_url.rstrip("/")
    api_key = args.anthropic_api_key

    mcp_host = args.mcp_host or _get_host_ip()
    mcp_servers = _build_mcp_servers(mcp_host)
    print(f"MCP server host: {mcp_host}")

    if not wait_for_trueforge(base):
        print(f"❌ TrueForge not reachable at {base}. Start: npx @truefoundry/trueforge")
        sys.exit(1)

    if api_key:
        register_model_provider(base, api_key)
    else:
        print("\n⚠️  No ANTHROPIC_API_KEY — skipping model provider registration (agents may fail)")

    register_mcp_servers(base, mcp_servers)
    create_agents(base, model=args.model or os.environ.get("AGENT_MODEL"))

    print("\n── Done ──")
    print(f"Open TrueForge at: {base}")
    print("Start a session with the 'enterprise-ops-router' agent.")


if __name__ == "__main__":
    main()
