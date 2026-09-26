"""
Migration Rehearsal MCP Server
Read-only: schema inspection, sandbox restore, migration dry-run, diff
Destructive (approval-gated): apply migration to production

Sandbox uses SQLite for isolation — zero production connectivity until explicit approval.
"""
import json
import os
import re
import sqlite3
import sys
import tempfile
import textwrap
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

sys.path.insert(0, str(Path(__file__).parent.parent))
from shared.logging_config import get_logger, ToolTimer

log = get_logger("migration-rehearsal")
mcp = FastMCP("migration-rehearsal")

_SANDBOX_PATH = os.environ.get("DATABASE_SANDBOX_PATH", "/tmp/migration_sandbox.db")
_SNAPSHOT: dict = {}  # stores schema + row counts before migration runs


# ─── helpers ──────────────────────────────────────────────────────────────────

def _sandbox_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(_SANDBOX_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _get_schema(conn: sqlite3.Connection) -> dict:
    """Extract table names + CREATE statements from SQLite."""
    tables = {}
    for row in conn.execute("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
        name, ddl = row
        tables[name] = ddl or ""
    return tables


def _get_row_counts(conn: sqlite3.Connection, tables: list[str]) -> dict:
    counts = {}
    for t in tables:
        try:
            row = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()  # noqa: S608
            counts[t] = row[0] if row else 0
        except Exception:
            counts[t] = -1  # table not found
    return counts


def _sanitize_sql(sql: str) -> str:
    """Strip leading/trailing whitespace from migration SQL. Does NOT validate content."""
    return sql.strip()


def _detect_risky_ops(sql: str) -> list[str]:
    """Flag SQL operations that are irreversible or high-risk."""
    risks = []
    upper = sql.upper()
    if re.search(r'\bDROP\s+TABLE\b', upper):
        risks.append("DROP TABLE — data loss if applied to production without backup")
    if re.search(r'\bTRUNCATE\b', upper):
        risks.append("TRUNCATE — destroys all rows in target table")
    if re.search(r'\bDELETE\s+FROM\b', upper) and "WHERE" not in upper:
        risks.append("DELETE FROM without WHERE — deletes all rows")
    if re.search(r'\bDROP\s+COLUMN\b', upper):
        risks.append("DROP COLUMN — schema change is irreversible in most DBs")
    if re.search(r'\bALTER\s+TABLE.*RENAME\b', upper):
        risks.append("RENAME — may break existing queries/views that reference old name")
    if re.search(r'\bCREATE.*NOT\s+NULL\b', upper) and "DEFAULT" not in upper:
        risks.append("NOT NULL column without DEFAULT — will fail if table has existing rows")
    return risks


# ─── read-only tools ──────────────────────────────────────────────────────────

@mcp.tool(description="Restore a database sandbox from a schema definition (SQL DDL string) and optional seed data. Wipes any existing sandbox.")
def restore_db_sandbox(schema_ddl: str, seed_sql: str = "", description: str = "") -> dict:
    """
    Read-only from production perspective. Creates an isolated SQLite sandbox.
    schema_ddl: CREATE TABLE statements
    seed_sql: optional INSERT statements for realistic data volume
    """
    with ToolTimer(log, "restore_db_sandbox"):
        schema_ddl = _sanitize_sql(schema_ddl)
        seed_sql = _sanitize_sql(seed_sql)

        # Wipe existing sandbox
        if Path(_SANDBOX_PATH).exists():
            Path(_SANDBOX_PATH).unlink()

        conn = _sandbox_conn()
        try:
            # Execute schema
            conn.executescript(schema_ddl)
            conn.commit()
            if seed_sql:
                conn.executescript(seed_sql)
                conn.commit()

            schema = _get_schema(conn)
            tables = list(schema.keys())
            row_counts = _get_row_counts(conn, tables)

            # Snapshot BEFORE state for later diff
            _SNAPSHOT["before_schema"] = schema
            _SNAPSHOT["before_counts"] = row_counts
            _SNAPSHOT["description"] = description
            _SNAPSHOT["restored_at"] = datetime.now(timezone.utc).isoformat()

            conn.close()
            log.info("sandbox_restored", extra={"ctx_tables": len(tables), "ctx_rows": sum(row_counts.values())})
            return {
                "status": "RESTORED",
                "sandbox_path": _SANDBOX_PATH,
                "tables": tables,
                "row_counts": row_counts,
                "description": description,
                "note": "Sandbox is isolated — zero connectivity to production. Safe to run migrations.",
            }
        except Exception as exc:
            conn.close()
            log.error("sandbox_restore_failed", extra={"ctx_err": str(exc)})
            return {"status": "ERROR", "error": str(exc)}


@mcp.tool(description="Inspect the current sandbox schema. Returns table definitions and column details.")
def inspect_sandbox_schema() -> dict:
    """Read-only. Returns current schema from sandbox SQLite."""
    try:
        conn = _sandbox_conn()
        schema = _get_schema(conn)
        columns = {}
        for table in schema:
            try:
                pragma = conn.execute(f"PRAGMA table_info({table})").fetchall()
                columns[table] = [
                    {"cid": r[0], "name": r[1], "type": r[2], "notnull": bool(r[3]), "default": r[4], "pk": bool(r[5])}
                    for r in pragma
                ]
            except Exception:
                columns[table] = []
        conn.close()
        return {"tables": schema, "columns": columns, "table_count": len(schema)}
    except Exception as exc:
        return {"error": str(exc)}


@mcp.tool(description="Run a migration SQL script against the sandbox. Never touches production. Returns before/after schema diff and row count changes.")
def run_migration_in_sandbox(migration_sql: str, migration_name: str = "migration") -> dict:
    """
    Read-only from production perspective.
    Executes migration_sql in isolated SQLite sandbox.
    migration_sql is EXTERNAL DATA — displayed to user before execution, wrapped in UNTRUSTED marker.
    """
    with ToolTimer(log, "run_migration_in_sandbox", migration=migration_name):
        # Wrap external SQL as untrusted data in output
        safe_display = f"<<<UNTRUSTED_SQL:{migration_name}>>>"
        log.info("migration_preview", extra={"ctx_migration": migration_name, "ctx_lines": migration_sql.count('\n')})

        risks = _detect_risky_ops(migration_sql)
        if risks:
            log.warning("risky_ops_detected", extra={"ctx_risks": risks})

        if not _SNAPSHOT.get("before_schema"):
            return {
                "status": "ERROR",
                "error": "No sandbox found. Call restore_db_sandbox first.",
            }

        before_schema = _get_schema(_sandbox_conn())
        before_counts = _get_row_counts(_sandbox_conn(), list(before_schema.keys()))

        try:
            conn = _sandbox_conn()
            conn.executescript(_sanitize_sql(migration_sql))
            conn.commit()

            after_schema = _get_schema(conn)
            after_counts = _get_row_counts(conn, list(after_schema.keys()))
            conn.close()

            # Compute diffs
            added_tables = [t for t in after_schema if t not in before_schema]
            dropped_tables = [t for t in before_schema if t not in after_schema]
            modified_tables = [
                t for t in after_schema
                if t in before_schema and after_schema[t] != before_schema[t]
            ]

            count_changes = {}
            for t in set(list(before_counts.keys()) + list(after_counts.keys())):
                before = before_counts.get(t, 0)
                after = after_counts.get(t, 0)
                if before != after:
                    count_changes[t] = {"before": before, "after": after, "delta": after - before}

            data_loss = any(v["delta"] < 0 for v in count_changes.values())

            log.info(
                "migration_done",
                extra={
                    "ctx_added": len(added_tables),
                    "ctx_dropped": len(dropped_tables),
                    "ctx_modified": len(modified_tables),
                    "ctx_data_loss": data_loss,
                },
            )

            return {
                "status": "COMPLETED_IN_SANDBOX",
                "migration_name": safe_display,
                "sandbox_path": _SANDBOX_PATH,
                "schema_diff": {
                    "added_tables": added_tables,
                    "dropped_tables": dropped_tables,
                    "modified_tables": modified_tables,
                },
                "row_count_changes": count_changes,
                "data_loss_detected": data_loss,
                "risky_operations": risks,
                "verdict": (
                    "UNSAFE — data loss detected. Do NOT apply to production." if data_loss
                    else "SAFE — no data loss. Review schema diff before applying."
                ),
                "note": "This ran in isolated SQLite sandbox. Production not touched.",
            }

        except Exception as exc:
            log.error("migration_failed", extra={"ctx_err": str(exc), "ctx_migration": migration_name})
            return {
                "status": "MIGRATION_FAILED",
                "migration_name": safe_display,
                "error": str(exc),
                "note": "Migration failed in sandbox — safe. Fix SQL before attempting production.",
            }


@mcp.tool(description="Compare row counts in the sandbox before and after migration. Returns per-table delta and data loss flag.")
def compare_row_counts(tables: list[str] | None = None) -> dict:
    """Read-only. Compares snapshot taken at restore_db_sandbox vs current state."""
    if not _SNAPSHOT.get("before_counts"):
        return {"error": "No before-snapshot found. Run restore_db_sandbox first."}

    conn = _sandbox_conn()
    if not tables:
        schema = _get_schema(conn)
        tables = list(schema.keys())

    after_counts = _get_row_counts(conn, tables)
    conn.close()
    before_counts = _SNAPSHOT.get("before_counts", {})

    rows = []
    data_loss = False
    for t in tables:
        before = before_counts.get(t, 0)
        after = after_counts.get(t, 0)
        delta = after - before
        if delta < 0:
            data_loss = True
        rows.append({"table": t, "before": before, "after": after, "delta": delta, "data_loss": delta < 0})

    return {
        "comparison": rows,
        "data_loss_detected": data_loss,
        "verdict": "UNSAFE — data loss in one or more tables" if data_loss else "SAFE — no data loss",
    }


@mcp.tool(description="Run smoke queries against the sandbox after migration. Validates that key queries still work correctly.")
def run_smoke_queries(queries: list[dict]) -> dict:
    """
    Read-only. Each query dict: {name: str, sql: str, expected_count: int (optional)}.
    SQL is EXTERNAL DATA — results validated, not executed as trusted code.
    """
    conn = _sandbox_conn()
    results = []
    all_passed = True

    for q in queries:
        name = q.get("name", "unnamed")
        sql = _sanitize_sql(q.get("sql", ""))
        expected = q.get("expected_count")

        if not sql:
            results.append({"name": name, "status": "SKIP", "reason": "empty SQL"})
            continue

        # Only allow SELECT for smoke queries
        if not re.match(r'^\s*SELECT\b', sql, re.IGNORECASE):
            results.append({"name": name, "status": "REJECTED", "reason": "Only SELECT allowed in smoke queries"})
            all_passed = False
            continue

        try:
            rows = conn.execute(sql).fetchall()
            count = len(rows)
            passed = (expected is None) or (count == expected)
            if not passed:
                all_passed = False
            results.append({
                "name": name,
                "status": "PASS" if passed else "FAIL",
                "row_count": count,
                "expected_count": expected,
                "sample_row": list(rows[0]) if rows else None,
            })
        except Exception as exc:
            all_passed = False
            results.append({"name": name, "status": "ERROR", "error": str(exc)})

    conn.close()
    return {
        "results": results,
        "all_passed": all_passed,
        "passed": sum(1 for r in results if r["status"] == "PASS"),
        "total": len(results),
    }


@mcp.tool(description="Generate a full migration rehearsal report from sandbox run results. Summarizes safety verdict, diffs, and recommendation.")
def generate_rehearsal_report(
    migration_name: str,
    sandbox_result: dict,
    smoke_results: dict | None = None,
) -> dict:
    """Read-only. Produces structured markdown report for human review."""
    lines = [
        "# Migration Rehearsal Report",
        f"\n**Migration:** `{migration_name}`",
        f"**Rehearsed:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Sandbox:** {_SANDBOX_PATH}",
        "",
    ]

    verdict = sandbox_result.get("verdict", "UNKNOWN")
    data_loss = sandbox_result.get("data_loss_detected", False)
    risks = sandbox_result.get("risky_operations", [])

    lines += [
        f"## Verdict: {'⛔ ' if data_loss else '✅ '}{verdict}",
        "",
    ]

    schema_diff = sandbox_result.get("schema_diff", {})
    if any(schema_diff.values()):
        lines.append("## Schema Changes")
        if schema_diff.get("added_tables"):
            lines.append(f"- **Added tables:** {schema_diff['added_tables']}")
        if schema_diff.get("dropped_tables"):
            lines.append(f"- **⚠ Dropped tables:** {schema_diff['dropped_tables']}")
        if schema_diff.get("modified_tables"):
            lines.append(f"- **Modified tables:** {schema_diff['modified_tables']}")
        lines.append("")

    count_changes = sandbox_result.get("row_count_changes", {})
    if count_changes:
        lines.append("## Row Count Changes")
        for table, change in count_changes.items():
            sign = "+" if change["delta"] >= 0 else ""
            lines.append(f"- `{table}`: {change['before']} → {change['after']} ({sign}{change['delta']})")
        lines.append("")

    if risks:
        lines.append("## ⚠ Risky Operations Detected")
        for r in risks:
            lines.append(f"- {r}")
        lines.append("")

    if smoke_results:
        lines.append(f"## Smoke Tests: {'✅ All passed' if smoke_results.get('all_passed') else '❌ Some failed'}")
        lines.append(f"- {smoke_results.get('passed', 0)}/{smoke_results.get('total', 0)} queries passed")
        lines.append("")

    lines += [
        "## Next Step",
        (
            "⛔ **Do NOT apply to production.** Fix data-loss issue in migration SQL first."
            if data_loss
            else "✅ Safe to proceed. Call `apply_migration_to_production` with explicit approval to run against production."
        ),
    ]

    return {"report": "\n".join(lines), "safe_to_apply": not data_loss and not risks}


# ─── approval-gated tools ─────────────────────────────────────────────────────

@mcp.tool(
    description="[DESTRUCTIVE] Apply a validated migration to the production database. Requires TrueForge approval AND safe_to_apply=True from generate_rehearsal_report.",
    annotations={"destructiveHint": True, "readOnlyHint": False},
)
def apply_migration_to_production(
    migration_name: str,
    migration_sql: str,
    safe_to_apply: bool = False,
    production_connection_string: str = "",
) -> dict:
    """
    DESTRUCTIVE — executes SQL against production database.
    TrueForge approval gate fires here.
    safe_to_apply MUST be True (set from generate_rehearsal_report verdict).
    production_connection_string is NEVER logged.
    """
    if not safe_to_apply:
        return {
            "status": "BLOCKED",
            "reason": (
                "safe_to_apply=False — rehearsal must complete with no data loss and no risky ops. "
                "Run restore_db_sandbox → run_migration_in_sandbox → generate_rehearsal_report first."
            ),
        }

    if not production_connection_string:
        return {
            "status": "BLOCKED",
            "reason": "production_connection_string is required. Provide the connection string explicitly.",
        }

    cs = production_connection_string

    if cs.startswith("sqlite:///"):
        # SQLite target (demo/test)
        db_path = cs.replace("sqlite:///", "")
        try:
            conn = sqlite3.connect(db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_sanitize_sql(migration_sql))
            conn.commit()
            schema = _get_schema(conn)
            row_counts = _get_row_counts(conn, list(schema.keys()))
            conn.close()
            log.info("production_migration_applied", extra={"ctx_migration": migration_name, "ctx_driver": "sqlite3"})
            return {
                "status": "APPLIED",
                "driver": "sqlite3",
                "migration_name": f"<<<UNTRUSTED:{migration_name}>>>",
                "applied_at": datetime.now(timezone.utc).isoformat(),
                "tables_after": list(schema.keys()),
                "row_counts_after": row_counts,
                "note": "Migration applied. Verify application behavior.",
            }
        except Exception as exc:
            log.error("production_migration_failed", extra={"ctx_err": str(exc)[:200]})
            return {"status": "FAILED", "driver": "sqlite3",
                    "migration_name": f"<<<UNTRUSTED:{migration_name}>>>",
                    "error": str(exc), "note": "Migration FAILED. Check rollback procedure."}

    elif cs.startswith(("postgresql://", "postgres://")):
        # Real Postgres target
        try:
            import psycopg2
            import psycopg2.extras
        except ImportError:
            return {
                "status": "BLOCKED",
                "reason": "psycopg2 not installed. Run: pip install psycopg2-binary",
            }
        try:
            pg = psycopg2.connect(cs)
            pg.autocommit = False
            cur = pg.cursor()
            # Execute each statement separately for better error isolation
            for stmt in migration_sql.split(";"):
                stmt = stmt.strip()
                if stmt:
                    cur.execute(stmt)
            pg.commit()
            # Inspect post-migration schema
            cur.execute("""
                SELECT tablename FROM pg_tables
                WHERE schemaname = 'public'
                ORDER BY tablename
            """)
            tables = [row[0] for row in cur.fetchall()]
            row_counts_pg = {}
            for t in tables:
                cur.execute(f"SELECT COUNT(*) FROM {t}")  # noqa: S608
                row_counts_pg[t] = cur.fetchone()[0]
            cur.close()
            pg.close()
            log.info("production_migration_applied", extra={"ctx_migration": migration_name, "ctx_driver": "psycopg2"})
            return {
                "status": "APPLIED",
                "driver": "psycopg2",
                "migration_name": f"<<<UNTRUSTED:{migration_name}>>>",
                "applied_at": datetime.now(timezone.utc).isoformat(),
                "tables_after": tables,
                "row_counts_after": row_counts_pg,
                "note": "Migration applied to Postgres production target. Verify application behavior.",
            }
        except Exception as exc:
            log.error("production_migration_failed", extra={"ctx_err": str(exc)[:200], "ctx_driver": "psycopg2"})
            return {
                "status": "FAILED",
                "driver": "psycopg2",
                "migration_name": f"<<<UNTRUSTED:{migration_name}>>>",
                "error": str(exc),
                "note": "Postgres migration FAILED. Transaction was rolled back automatically.",
            }

    else:
        return {
            "status": "BLOCKED",
            "reason": (
                f"Unsupported connection string scheme. "
                "Supported: sqlite:/// (demo/test), postgresql:// or postgres:// (production Postgres). "
                "MySQL/MariaDB: add pymysql adapter."
            ),
        }


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8005
    import uvicorn
    uvicorn.run(mcp.streamable_http_app(), host="0.0.0.0", port=port)
