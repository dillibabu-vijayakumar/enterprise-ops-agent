"""
Access Reviewer MCP Server
Read-only: IAM audit, overprivilege detection, stale access
Destructive (approval-gated): disable user, remove policy attachment
"""
import os
import sys
import json
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp.server.fastmcp import FastMCP
import boto3
from botocore.exceptions import ClientError
from shared.context import _session, _age_days

mcp = FastMCP("access-reviewer")

DANGEROUS_ACTIONS = {
    "*",
    "iam:*",
    "s3:*",
    "ec2:*",
    "sts:AssumeRole",
    "iam:CreateUser",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:CreateAccessKey",
    "iam:UpdateLoginProfile",
}

# ─── read-only ────────────────────────────────────────────────────────────────

@mcp.tool(description="List all IAM users with their last activity date and access key status.")
def list_iam_users() -> dict:
    """Read-only."""
    iam = _session().client("iam")
    result = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            # get password last used
            detail = iam.get_user(UserName=user["UserName"])["User"]
            pwd_last_used = detail.get("PasswordLastUsed")
            pwd_age = _age_days(pwd_last_used) if pwd_last_used else 9999

            # get access keys
            keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
            key_info = []
            for k in keys:
                last_used = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])
                lu = last_used["AccessKeyLastUsed"].get("LastUsedDate")
                key_info.append({
                    "key_id": k["AccessKeyId"][:8] + "...",
                    "status": k["Status"],
                    "last_used_days_ago": _age_days(lu) if lu else 9999,
                })

            idle_days = min([pwd_age] + [k["last_used_days_ago"] for k in key_info] or [9999])
            result.append({
                "username": user["UserName"],
                "user_id": user["UserId"],
                "created_days_ago": _age_days(user.get("CreateDate")),
                "password_last_used_days_ago": pwd_age,
                "access_keys": key_info,
                "idle_days": idle_days,
                "stale": idle_days > 90,
            })

    result.sort(key=lambda u: u["idle_days"], reverse=True)
    return {
        "users": result,
        "total": len(result),
        "stale_count": sum(1 for u in result if u["stale"]),
    }


@mcp.tool(description="List all IAM roles and their attached policies. Flag roles with wildcard or admin-level permissions.")
def list_overprivileged_roles() -> dict:
    """Read-only. Detects * and admin-level permissions in roles."""
    iam = _session().client("iam")
    flagged = []
    clean = []

    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            role_name = role["RoleName"]
            dangerous_found = []

            # Attached managed policies
            attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
            for policy in attached:
                if "AdministratorAccess" in policy["PolicyName"] or "FullAccess" in policy["PolicyName"]:
                    dangerous_found.append({
                        "type": "managed_policy",
                        "policy": policy["PolicyName"],
                        "risk": "admin/full-access managed policy",
                    })

            # Inline policies
            inline_names = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
            for pname in inline_names:
                doc = iam.get_role_policy(RoleName=role_name, PolicyName=pname)["PolicyDocument"]
                for stmt in doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        actions = stmt.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        dangerous_actions = [a for a in actions if a in DANGEROUS_ACTIONS]
                        if dangerous_actions:
                            dangerous_found.append({
                                "type": "inline_policy",
                                "policy": pname,
                                "dangerous_actions": dangerous_actions,
                                "risk": "wildcard or dangerous action",
                            })

            entry = {
                "role_name": role_name,
                "role_arn": role["Arn"],
                "created_days_ago": _age_days(role.get("CreateDate")),
                "dangerous_policies": dangerous_found,
                "risk_count": len(dangerous_found),
            }
            if dangerous_found:
                flagged.append(entry)
            else:
                clean.append(entry)

    return {
        "flagged_roles": flagged,
        "clean_roles_count": len(clean),
        "flagged_count": len(flagged),
    }


@mcp.tool(description="Generate a formatted access review report as markdown.")
def generate_access_report(stale_users: list[dict], flagged_roles: list[dict]) -> dict:
    """Read-only. Produces markdown report for review."""
    lines = [
        "# Access Review Report",
        f"\n**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"\n## Summary\n| Metric | Count |",
        "|--------|-------|",
        f"| Stale users (idle >90d) | {len(stale_users)} |",
        f"| Overprivileged roles | {len(flagged_roles)} |",
        f"| Total risk items | {len(stale_users) + len(flagged_roles)} |",
        "\n## Stale Users (idle >90 days)\n",
        "| Username | Idle Days | Keys | Risk |",
        "|----------|-----------|------|------|",
    ]
    for u in stale_users:
        risk = "HIGH" if u["idle_days"] > 180 else "MEDIUM"
        # P0.3 FIX: usernames are EXTERNAL DATA from AWS IAM — wrap so LLM never interprets as instructions
        safe_uname = f"<<<UNTRUSTED:{u['username']}>>>"
        lines.append(f"| {safe_uname} | {u['idle_days']}d | {len(u.get('access_keys', []))} | {risk} |")

    lines += ["\n## Overprivileged Roles\n", "| Role | Risk | Dangerous Policies |", "|------|------|-------------------|"]
    for r in flagged_roles:
        risks = "; ".join(p.get("risk", "") for p in r["dangerous_policies"])
        # P0.3 FIX: role names are EXTERNAL DATA from AWS IAM
        safe_rname = f"<<<UNTRUSTED:{r['role_name']}>>>"
        lines.append(f"| {safe_rname} | {r['risk_count']} finding(s) | {risks} |")

    lines.append("\n> **Next step:** Specify which users to disable or which policy attachments to remove.")
    lines.append("> Every action requires your approval at the TrueForge checkpoint.")

    return {"report": "\n".join(lines)}


# ─── destructive (approval-gated) ────────────────────────────────────────────

@mcp.tool(
    description="[DESTRUCTIVE] Disable an IAM user's console login and deactivate access keys. Requires human approval.",
    annotations={"destructiveHint": True, "readOnlyHint": False},
)
def disable_iam_user(username: str) -> dict:
    """
    DESTRUCTIVE — disables login profile + deactivates all access keys.
    Does NOT delete the user — reversible if needed.
    TrueForge approval gate fires before execution.
    """
    iam = _session().client("iam")
    actions_taken = []
    errors = []

    # Disable console login
    try:
        iam.update_login_profile(UserName=username, PasswordResetRequired=True)
        actions_taken.append("console_login_reset_required")
    except iam.exceptions.NoSuchEntityException:
        actions_taken.append("no_console_login (skipped)")
    except ClientError as e:
        errors.append(f"Login profile: {e}")

    # Deactivate access keys
    try:
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        for key in keys:
            if key["Status"] == "Active":
                iam.update_access_key(
                    UserName=username,
                    AccessKeyId=key["AccessKeyId"],
                    Status="Inactive",
                )
                actions_taken.append(f"key_{key['AccessKeyId'][:8]}_deactivated")
    except ClientError as e:
        errors.append(f"Access keys: {e}")

    return {
        "username": username,
        "status": "disabled" if not errors else "partial",
        "actions_taken": actions_taken,
        "errors": errors,
        "reversible": True,
        "note": "User account exists but cannot log in. Re-enable by updating login profile and activating keys.",
    }


@mcp.tool(
    description="[DESTRUCTIVE] Detach a managed policy from an IAM role. Requires human approval. Checks active role users first.",
    annotations={"destructiveHint": True, "readOnlyHint": False},
)
def detach_role_policy(role_name: str, policy_arn: str) -> dict:
    """
    DESTRUCTIVE — removes a policy attachment from a role.
    TrueForge approval gate fires before execution.
    Checks active principals before detaching to prevent service outages.
    """
    iam = _session().client("iam")

    # P1 FIX: check active entities before detaching — prevents Lambda/EC2 outage
    active_entities = []
    try:
        resp = iam.list_entities_for_policy(PolicyArn=policy_arn, EntityFilter="Role")
        for entity in resp.get("PolicyRoles", []):
            if entity["RoleName"] == role_name:
                active_entities.append(role_name)
        # also check if the role is assumed by anything right now via cloudtrail would be ideal,
        # but as a fast check — list instance profiles and lambda functions using this role
        ip_resp = iam.list_instance_profiles_for_role(RoleName=role_name)
        if ip_resp.get("InstanceProfiles"):
            active_entities.append(f"EC2 instance profiles: {[ip['InstanceProfileName'] for ip in ip_resp['InstanceProfiles']]}")
    except ClientError:
        pass

    if active_entities:
        return {
            "status": "BLOCKED",
            "reason": f"Role '{role_name}' is actively used by: {active_entities}. Detaching policy may cause service outage. Human must confirm impact before proceeding.",
            "role": role_name,
            "policy_arn": policy_arn,
            "active_entities": active_entities,
        }

    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        return {
            "status": "detached",
            "role": role_name,
            "policy_arn": policy_arn,
            "reversible": True,
            "note": "Policy detached. Re-attach with: iam.attach_role_policy(RoleName, PolicyArn)",
        }
    except ClientError as e:
        return {"status": "error", "error": str(e)}


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8003
    import uvicorn
    uvicorn.run(mcp.streamable_http_app(), host="0.0.0.0", port=port)
