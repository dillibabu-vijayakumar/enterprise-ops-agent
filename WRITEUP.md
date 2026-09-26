# Enterprise Ops Agent — Solution Writeup

**Hackathon:** TrueFoundry × Polaris — Agents That Act  
**Theme:** Cloud Cost Janitor  
**Team:** Vijayakumar

---

## The Problem

Cloud ops teams spend 10–15 hours/week on tasks that are high-stakes but repetitive: hunting idle AWS resources, reviewing stale IAM access, rehearsing DB migrations, and cutting releases. Each task requires inspecting live system state, making risk judgments, and obtaining human sign-off before irreversible steps. A chatbot can describe what to do. This agent does it.

## What the Agent Does (End to End)

Enterprise Ops Agent is a **6-subagent system orchestrated on TrueForge**. A zero-tool router classifies intent and delegates to domain specialists:

| Subagent | Domain | Approval Required For |
|---|---|---|
| Cloud Cost Janitor | AWS EC2/EBS/EIP/ELB/Snapshots | Every deletion |
| Access Reviewer | AWS IAM users + roles | User disable, policy detach |
| Migration Rehearsal | DB schema sandbox | Production apply |
| Release Captain | GitHub + sandbox | Tag create, publish |
| Ticket Resolver | Linear/Jira + sandbox | Reply + patch apply |
| Runbook Executor | Infra procedures | Each destructive step |

The Cloud Cost Janitor shows the full **Observe → Reason → Plan → Act → Verify** loop:

1. **Observe** — calls real AWS APIs (EC2, CloudWatch, SSM) to find idle resources
2. **Reason** — runs a 5-signal business context check per resource: tag completeness (S1), production gate/auto-block (S2), active CloudWatch alarms (S3), recent SSM deploy record (S4), SLA criticality tag (S5)
3. **Plan** — generates costed teardown plan; production resources removed from candidates automatically
4. **Act** — fires TrueForge `require_approval_for_tools: ["@destructive"]` gate; re-verifies EC2 state immediately before terminate (TOCTOU protection)
5. **Verify** — confirms deletion, returns structured audit log

## Where the Agent Stops

- Production-tagged resources: **auto-blocked at server layer** — no prompt can override
- >50 actionable resources: **ANOMALY_STOP** returned, empty resource list (LLM cannot iterate)
- CW/SSM unreachable: **ESCALATE** returned immediately, never retried with weakened checks
- Ambiguous intent below 34% confidence: **clarification requested**, not silently misrouted

## How TrueForge Is Used

- `require_approval_for_tools: ["@destructive"]` on all 6 subagents — platform-enforced HITL
- Sub-agent orchestration: router invokes subagents via TrueForge session API
- Sandbox execution: remediation scripts run inside TrueForge sandbox with credential isolation
- Context compaction: enabled at 60K tokens, `large_tool_response` handling for AWS paginator output
- `dynamic_sub_agents: true` on router for parallel multi-intent dispatch

## What Is Real vs Mocked

**Real:** AWS API calls (EC2, CloudWatch, SSM, IAM, ELB), all MCP server logic, approval token system, SQLite session persistence, AST script validation, Docker Compose deployment  
**Mocked in tests:** AWS APIs via `moto` (boto3-compatible mock); TrueForge session polling via HTTP stub  
**Requires live account for full demo:** actual idle EC2 instances, real CloudWatch metrics

## Known Limits

- Intent routing is keyword-based (not semantic) — ambiguous phrasing may need clarification
- EC2 cost estimates use hardcoded per-type pricing (~18 instance types; others default to $0.10/hr)
- No cross-region anomaly aggregation (each region checked independently)
- ESCALATE notification is in-response JSON — no PagerDuty/Slack integration

## Safety Architecture (30 tests passing)

Cryptographic one-time approval tokens (LLM cannot fabricate), TOCTOU re-verify before terminate, AST pre-validation of generated scripts, resource ID sanitization (injection prevention), `<<<UNTRUSTED:...>>>` markers on all external data (tags, commit messages, ticket bodies, IAM names).
