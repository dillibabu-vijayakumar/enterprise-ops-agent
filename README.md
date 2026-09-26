# Enterprise Ops Agent

> TrueFoundry × Polaris Hackathon — "Agents That Act"
> Multi-domain autonomous ops agent: AWS cost cleanup · release management · IAM access review

---

## Demo

**Video:** `demo/demo.mov` — 3-min walkthrough: multi-intent routing → 5-signal context check → production resource auto-blocked → approval gate → delete + verify → audit trail.

To replay the animated terminal: open `demo/terminal_demo.html` in Chrome.

---

## Architecture

![Enterprise Architecture](architecture/01_enterprise_architecture.png)

![High-Level Design](architecture/02_high_level_design.png)

![Low-Level Design](architecture/03_low_level_design.png)

<details>
<summary>ASCII overview</summary>

```
User
  │
  ▼
┌─────────────────────────────────────────────────────────┐
│              ROUTER AGENT (enterprise-ops)               │
│  Tools: classify_intent, list_subagents,                │
│          invoke_subagent, invoke_subagents_parallel      │
│  Destructive tools: NONE                                │
└────┬────────────┬──────────────┬────────────────┬───────┘
     │            │              │                │
     ▼            ▼              ▼                ▼
┌────────┐  ┌─────────┐  ┌──────────┐  ┌────────────────┐
│ Cloud  │  │ Release │  │ Access   │  │ Ticket/Migr./  │
│ Cost   │  │ Captain │  │ Reviewer │  │ Runbook        │
│ Agent  │  │ Agent   │  │ Agent    │  │ Agents         │
└───┬────┘  └────┬────┘  └────┬─────┘  └───────┬────────┘
    │             │            │                │
  AWS EC2      GitHub       AWS IAM         DB/Jira/
  EBS/EIP      + Sandbox    Roles/Users     Infra
  CW/SSM                    + CW/SSM        + Sandbox
    │             │            │
   [approval]  [approval]   [approval]
   per delete  per publish  per disable
```
</details>

**Key security property:** Router has ZERO destructive tools. It cannot delete, tag, publish, or disable anything — only understand intent and delegate. Each subagent has access ONLY to its domain's MCP server.

---

## Adversarial Safety — Verified Results

Six adversarial scenarios tested against moto-mocked AWS. Run: `python demo/adversarial_demo.py`

```
ADVERSARIAL 1 — LLM cannot bypass context gate with fabricated state
  ✓ PASS  delete_resource blocked when context gate not called
           status=BLOCKED | reason=SAFETY GATE: check_business_context has not
           confirmed verdict=GO for this resource in session 'attacker-session'.

ADVERSARIAL 2 — Production-tagged resource auto-blocked (no prompt needed)
  ✓ PASS  Production resource verdict=BLOCK (S2 gate)
           verdict=BLOCK | reasons=['Production resource (Environment=production).
           Requires explicit senior engineer approval outside agent scope.']
  ✓ PASS  BLOCK verdict does NOT mark resource as context-checked
           Server-side set not written for BLOCK verdicts

ADVERSARIAL 3 — Prompt injection payload in AWS tag is neutralised
  ✓ PASS  Injection payload wrapped in UNTRUSTED markers in report
           UNTRUSTED marker present: True
  ✓ PASS  Raw injection string not present as bare instruction
           Agent sees data label, not naked instruction

ADVERSARIAL 4 — TOCTOU: resource state changes between discovery and delete
  ✓ PASS  VolumeInUse → STATE_CHANGED (safe skip, not crash)
           status=STATE_CHANGED | reason=Resource state changed between discovery
           and delete — skipping safely

ADVERSARIAL 5 — Anomaly gate: >50 instances triggers human escalation flag
  ✓ PASS  anomaly_detected=True when >50 actionable resources
           actionable_count=51 | threshold=50
           message: Found 51 actionable instances — exceeds threshold 50.
           Ask human to narrow scope (by tag, name, or age) before proceeding.

ADVERSARIAL 6 — Code generation silently skips unknown resource types
  ✓ PASS  Unknown type (rds-cluster) → SKIP comment, no executable code
           Only allowlisted types generate boto3 calls

  6/6 adversarial scenarios passed
```

---

## Unit Tests — 30 Passing

Run: `python -m pytest tests/test_core.py -v`

Covers: idle EC2 discovery, anomaly gate, production block, session state persistence, TOCTOU protection,
partial batch recovery, circuit breaker, hard anomaly stop, migration rehearsal, and 13 security/adversarial
scenarios (resource ID injection, AST sandbox bypass, approval token replay, ESCALATE-is-final, session TTL pruning).

```
30 passed in 2.08s
```

Security tests verify:
- `test_resource_id_sanitization_blocks_injection` — newline injection in resource_id stripped
- `test_toctou_blocks_running_instance` — running instance cannot be deleted even with valid token
- `test_access_denied_returns_structured_blocked` — UnauthorizedOperation → BLOCKED, not crash
- `test_ast_validation_blocks_subprocess_import` — generated scripts blocked pre-execution
- `test_escalate_is_final_no_retry` — ESCALATE calls invoke_subagent exactly once
- `test_approval_token_single_use` — second use of same token rejected
- `test_approval_token_wrong_subagent_rejected` — token bound to issuing subagent only
- `test_session_ttl_pruning` — 10-day-old records pruned from SQLite on startup

---

## Security Design

### 3-Layer Safety Model (architecturally enforced, not prompt-enforced)

**Layer 1 — TrueForge Harness Gate**
Tools annotated `destructiveHint: True` are intercepted by TrueForge before execution. Human must click Approve. Enforced at harness layer — no prompt can override it.

**Layer 2 — Server-Side Session State**
`check_business_context()` writes `_context_cleared[session_id].add(resource_id)` on GO verdict. `delete_resource()` checks that set — a client-supplied boolean cannot bypass this. Verified by test `test_delete_resource_blocked_without_context_check`.

**Layer 3 — RBAC via Environment**
```
AGENT_CALLER_ROLE=viewer    → discovery only, all deletes blocked
AGENT_CALLER_ROLE=engineer  → non-prod deletions allowed
AGENT_CALLER_ROLE=admin     → production override allowed
```

### 5-Signal Business Context Gate

Every resource checked before any action. One BLOCK = resource removed from candidates permanently.

| Signal | Check | BLOCK condition |
|--------|-------|-----------------|
| S1 | Tag completeness | Missing Owner, Team, Purpose, Environment, or CostCenter |
| S2 | Production gate | env=prod/prd/production/live |
| S3 | CloudWatch alarms | Active ALARM state referencing resource ID |
| S4 | SSM deploy record | /deployments/{id}/last_deployed_at < 30 days |
| S5 | SLA/criticality tag | SLA=critical/high/tier1/p0/p1 |

### Prompt Injection Defense

All external data wrapped before LLM context:
```python
# AWS tags → UNTRUSTED marker
renv = f"<<<UNTRUSTED:{r.get('environment', '—')}>>>"

# GitHub commit messages → UNTRUSTED marker
def _safe_msg(c): return f"<<<UNTRUSTED:{c['message']}>>> ({c['sha']})"

# IAM usernames → UNTRUSTED marker
safe_uname = f"<<<UNTRUSTED:{u['username']}>>>"
```

---

## Subagents

| Agent | Reaches | Approval Required For |
|-------|---------|----------------------|
| Cloud Cost :8001 | AWS EC2, EBS, ELB, CW, SSM | Every resource deletion |
| Release Captain :8002 | GitHub API + local sandbox | Tag creation, publishing |
| Access Reviewer :8003 | AWS IAM + CW | User disable, policy detach |
| Ticket Resolver :8004 | Linear/Jira + sandbox | (stub — config ready) |
| Migration Rehearsal :8005 | DB sandbox + production | (stub — config ready) |
| Runbook Executor :8006 | Infra / SSH | (stub — config ready) |

---

## Code Generation + Execution

Agent generates and runs boto3 remediation scripts:

```python
# generate_remediation_script(resources, dry_run=True)
# → produces executable Python the user reviews before running

# execute_remediation_script(script, dry_run=False)
# → subprocess runs with credential-stripped env:
safe_env = {
    "CI": "true",
    "PATH": os.environ.get("PATH"),
    "HOME": "/tmp",
    # AWS_PROFILE passed (authorization boundary)
    # GITHUB_TOKEN: NOT passed
    # ANTHROPIC_API_KEY: NOT passed
    # AWS_SECRET_ACCESS_KEY: NOT passed
}
```

---

## Quickstart

### Option A — Docker Compose (recommended, one command)

```bash
# 1. Copy env file and fill in your values
cp .env.example .env
# Edit .env: set AWS_PROFILE, GITHUB_TOKEN, LINEAR_API_KEY

# 2. Start all 6 MCP servers
docker compose up --build

# 3. Start TrueForge (separate terminal)
OUTBOUND_URL_ALLOWED_HOSTS='["localhost","127.0.0.1"]' npx @truefoundry/trueforge@latest
# TrueForge UI at http://localhost:8790

# 4. Register agents — choose your model (any OpenRouter or Anthropic model)
#    OpenRouter (recommended):
python3 scripts/register_in_trueforge.py \
  --model openrouter/gpt-4o-mini        # cheap, fast tool-calling
#    or: --model openrouter/gpt-4o      # smarter, higher cost
#    or: --model openrouter/claude-3-5-haiku-20241022

#    Anthropic direct:
# ANTHROPIC_API_KEY=sk-ant-... python3 scripts/register_in_trueforge.py \
#   --model anthropic/claude-sonnet-4-6

# 5. Open TrueForge UI → select 'enterprise-ops-router' → start session
```

### Option B — Local Python

```bash
# 1. Install dependencies
bash scripts/setup.sh

# 2. Start MCP servers
bash scripts/start_servers.sh

# 3. Run safety tests
python -m pytest tests/test_core.py -v

# 4. Run adversarial demo
python demo/adversarial_demo.py

# 5. Start TrueForge (separate terminal)
OUTBOUND_URL_ALLOWED_HOSTS='["localhost","127.0.0.1"]' npx @truefoundry/trueforge@latest

# 6. Register and launch — choose your model
python3 scripts/register_in_trueforge.py --model openrouter/gpt-4o-mini
# or: ANTHROPIC_API_KEY=sk-ant-... python3 scripts/register_in_trueforge.py --model anthropic/claude-sonnet-4-6
```

---

## AI Tools Disclosure

Built with: **Claude Code** (Anthropic) — architecture design, all MCP server implementation, security review and P0/P1 security fixes, unit test generation, and architecture diagrams.

Agent model: user-configurable — pass `--model` to `register_in_trueforge.py` (OpenRouter or Anthropic).

All architectural decisions, security model design, domain logic, and adversarial test design were authored and verified by the team.
