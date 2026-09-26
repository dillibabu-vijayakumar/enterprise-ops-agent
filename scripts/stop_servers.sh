#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG_DIR="$ROOT/logs"

echo "Stopping all MCP servers..."
for pidfile in "$LOG_DIR"/*.pid; do
  [ -f "$pidfile" ] || continue
  pid=$(cat "$pidfile")
  name=$(basename "$pidfile" .pid)
  if kill "$pid" 2>/dev/null; then
    echo "  stopped $name (pid=$pid)"
  fi
  rm -f "$pidfile"
done

pkill -f "truefoundry/trueforge" 2>/dev/null || true
echo "Done."
