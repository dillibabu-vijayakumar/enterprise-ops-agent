# Port assignments for all MCP servers
# Each server runs independently; TrueForge connects via http://localhost:PORT/sse

PORTS = {
    "ops-router":             8000,
    "cloud-cost-tools":       8001,
    "release-captain-tools":  8002,
    "access-reviewer-tools":  8003,
    "ticket-resolver-tools":  8004,
    "migration-rehearsal-tools": 8005,
    "runbook-executor-tools": 8006,
}

def server_url(name: str) -> str:
    return f"http://localhost:{PORTS[name]}/sse"
