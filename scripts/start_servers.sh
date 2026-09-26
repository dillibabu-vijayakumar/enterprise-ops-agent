#!/usr/bin/env bash
# Starts all MCP servers in background, then TrueForge.
# Each server runs on its own port (8000-8006).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$ROOT/logs"
mkdir -p "$LOG_DIR"

echo "=== Starting MCP servers ==="

start_server() {
  local name="$1"
  local script="$2"
  local port="$3"
  echo "  Starting $name on :$port..."
  PYTHONPATH="$ROOT/mcp" python3 "$ROOT/mcp/$script" "$port" \
    > "$LOG_DIR/$name.log" 2>&1 &
  echo $! > "$LOG_DIR/$name.pid"
  echo "  ✅ $name (pid=$!, log=$LOG_DIR/$name.log)"
}

start_server "ops-router"             "router/server.py"  8000
start_server "cloud-cost-tools"       "cloud/server.py"   8001
start_server "release-captain-tools"  "github/server.py"  8002
start_server "access-reviewer-tools"  "iam/server.py"     8003
# Skeleton servers — write minimal stubs if files exist
[ -f "$ROOT/mcp/tickets/server.py" ] && start_server "ticket-resolver-tools"  "tickets/server.py"  8004
[ -f "$ROOT/mcp/database/server.py" ] && start_server "migration-rehearsal-tools" "database/server.py" 8005
[ -f "$ROOT/mcp/runbook/server.py" ] && start_server "runbook-executor-tools" "runbook/server.py"  8006

echo ""
echo "Waiting 3s for servers to start..."
sleep 3

# Health check each server
for port in 8000 8001 8002 8003; do
  if curl -sf "http://localhost:$port/sse" -o /dev/null --max-time 2 2>/dev/null || \
     curl -sf "http://localhost:$port/health" -o /dev/null --max-time 2 2>/dev/null || \
     curl -sf "http://localhost:$port/" -o /dev/null --max-time 2 2>/dev/null; then
    echo "  ✅ :$port responding"
  else
    echo "  ⚠️  :$port not yet responding (may still be starting)"
  fi
done

echo ""
echo "=== Starting TrueForge ==="
echo "  ANTHROPIC_API_KEY must be set in env."
echo ""

cd "$ROOT"
npx @truefoundry/trueforge@latest &
TF_PID=$!
echo "TrueForge starting (pid=$TF_PID)..."
sleep 5

echo ""
echo "=== Registering MCP servers + agents in TrueForge ==="
python3 "$ROOT/scripts/register_in_trueforge.py"

echo ""
echo "=== ALL SYSTEMS UP ==="
echo "TrueForge UI: http://localhost:3000"
echo "Start with agent: enterprise-ops-router"
echo ""
echo "Try: 'Scan us-east-1 for idle resources and check if myrepo is ready to release'"
echo ""
echo "To stop all: bash scripts/stop_servers.sh"

wait $TF_PID
