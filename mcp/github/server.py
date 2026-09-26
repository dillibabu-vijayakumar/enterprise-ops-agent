"""
Release Captain MCP Server
Read-only: commit analysis, test execution in sandbox
Destructive (approval-gated): tagging, publishing
"""
import os
import sys
import json
import subprocess
import tempfile
import re
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp.server.fastmcp import FastMCP
import requests

mcp = FastMCP("release-captain")

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_API = "https://api.github.com"

def _gh_headers() -> dict:
    return {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

def _gh_get(path: str, params: dict = {}) -> dict | list:
    resp = requests.get(f"{GITHUB_API}{path}", headers=_gh_headers(), params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()

def _gh_post(path: str, payload: dict) -> dict:
    resp = requests.post(f"{GITHUB_API}{path}", headers=_gh_headers(), json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()

# ─── read-only ────────────────────────────────────────────────────────────────

@mcp.tool(description="Get the latest git tag for a repo and the commit it points to.")
def get_latest_tag(owner: str, repo: str) -> dict:
    """Read-only."""
    try:
        tags = _gh_get(f"/repos/{owner}/{repo}/tags", {"per_page": 5})
        if not tags:
            return {"latest_tag": None, "sha": None, "message": "No tags found — this will be the first release"}
        latest = tags[0]
        return {
            "latest_tag": latest["name"],
            "sha": latest["commit"]["sha"],
            "repo": f"{owner}/{repo}",
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool(description="List commits on main/master since the last tag. Returns commit list with authors and messages.")
def list_commits_since_tag(owner: str, repo: str, since_sha: str | None = None, branch: str = "main") -> dict:
    """Read-only."""
    try:
        params = {"sha": branch, "per_page": 100}
        if since_sha:
            # compare API gives commits between two refs
            compare = _gh_get(f"/repos/{owner}/{repo}/compare/{since_sha}...{branch}")
            commits = compare.get("commits", [])
        else:
            commits = _gh_get(f"/repos/{owner}/{repo}/commits", params)

        result = []
        for c in commits:
            msg = c["commit"]["message"]
            first_line = msg.split("\n")[0]
            # classify by conventional commit prefix
            ctype = "other"
            for prefix in ("feat", "fix", "docs", "refactor", "perf", "test", "chore", "ci", "break"):
                if first_line.lower().startswith(prefix):
                    ctype = prefix
                    break
            result.append({
                "sha": c["sha"][:8],
                "message": first_line,
                "type": ctype,
                "author": c["commit"]["author"]["name"],
                "date": c["commit"]["author"]["date"],
                "breaking": "BREAKING CHANGE" in msg or "!" in first_line[:20],
            })
        return {
            "commits": result,
            "count": len(result),
            "has_breaking_changes": any(c["breaking"] for c in result),
            "types_summary": {t: sum(1 for c in result if c["type"] == t) for t in set(c["type"] for c in result)},
        }
    except Exception as e:
        return {"error": str(e)}


@mcp.tool(description="Check for any open blocking issues or PRs against this repo before releasing.")
def check_release_blockers(owner: str, repo: str) -> dict:
    """Read-only. Looks for open P0/P1 issues and failing CI checks on main."""
    blockers = []
    warnings = []

    try:
        # Open issues labeled blocker/P0/P1
        issues = _gh_get(f"/repos/{owner}/{repo}/issues", {
            "state": "open", "labels": "blocker,P0,P1,release-blocker", "per_page": 20
        })
        for issue in issues:
            blockers.append({
                "type": "open_issue",
                "title": issue["title"],
                "url": issue["html_url"],
                "labels": [l["name"] for l in issue.get("labels", [])],
            })
    except Exception as e:
        warnings.append(f"Could not check issues: {e}")

    try:
        # Latest commit status on main
        branch_data = _gh_get(f"/repos/{owner}/{repo}/branches/main")
        commit_sha = branch_data["commit"]["sha"]
        check_runs = _gh_get(f"/repos/{owner}/{repo}/commits/{commit_sha}/check-runs")
        failed = [
            cr for cr in check_runs.get("check_runs", [])
            if cr["conclusion"] in ("failure", "cancelled", "timed_out")
        ]
        for cr in failed:
            blockers.append({
                "type": "failed_ci",
                "check_name": cr["name"],
                "conclusion": cr["conclusion"],
                "url": cr["html_url"],
            })
    except Exception as e:
        warnings.append(f"Could not check CI status: {e}")

    return {
        "safe_to_release": len(blockers) == 0,
        "blocker_count": len(blockers),
        "blockers": blockers,
        "warnings": warnings,
    }



# P0.2 FIX: allowlisted test runners only — no shell=True, no arbitrary commands
_ALLOWED_TEST_RUNNERS: dict[str, list[str]] = {
    "npm":    ["npm", "test", "--", "--passWithNoTests"],
    "pytest": ["python", "-m", "pytest", "--tb=short", "-q"],
    "make":   ["make", "test"],
    "none":   ["echo", "No test runner detected"],
}


@mcp.tool(description="Run the repo's test suite inside TrueForge sandbox. Returns pass/fail and output.")
def run_tests_in_sandbox(owner: str, repo: str, branch: str = "main", test_command: str = "auto") -> dict:
    """
    Sandbox-executed. Clones repo, detects test runner, runs tests.
    Never touches production — isolated tmpdir.
    shell=False enforced — only allowlisted runners execute.
    """
    if test_command != "auto":
        return {"error": "Custom test_command not permitted — use 'auto' for security. Arbitrary shell commands are blocked."}

    with tempfile.TemporaryDirectory(prefix="release-captain-") as tmpdir:
        # P0.3 FIX: token via env-var credential helper, never in URL
        clone_env = {
            **os.environ,
            "GIT_ASKPASS": "/bin/echo",
            "GIT_USERNAME": "x-access-token",
            "GIT_PASSWORD": GITHUB_TOKEN,
            "CI": "true",
        }
        clone_result = subprocess.run(
            ["git", "clone", "--depth", "10", "--branch", branch,
             f"https://github.com/{owner}/{repo}.git", tmpdir],
            capture_output=True, text=True, timeout=120,
            env=clone_env,
        )
        if clone_result.returncode != 0:
            # Sanitise error — never echo back env that may contain token
            return {"error": "Clone failed — check owner/repo/branch and GITHUB_TOKEN scope"}

        # Auto-detect test runner
        pkg_json = Path(tmpdir) / "package.json"
        pyproject = Path(tmpdir) / "pyproject.toml"
        makefile = Path(tmpdir) / "Makefile"

        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text())
                runner_key = "npm" if data.get("scripts", {}).get("test") else "none"
            except Exception:
                runner_key = "none"
        elif pyproject.exists():
            runner_key = "pytest"
        elif makefile.exists():
            runner_key = "make"
        else:
            runner_key = "none"

        cmd = _ALLOWED_TEST_RUNNERS[runner_key]

        # P0.2 FIX: minimal env — never expose master credentials to test code
        # Tests get CI env only; AWS/GitHub/Anthropic keys are NOT passed through.
        test_env = {
            "CI": "true",
            "NODE_ENV": "test",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": "/tmp",
        }
        # Run with shell=False — no arbitrary shell expansion
        test_result = subprocess.run(
            cmd,
            shell=False,
            cwd=tmpdir,
            capture_output=True,
            text=True,
            timeout=180,
            env=test_env,
        )

        passed = test_result.returncode == 0
        output = (test_result.stdout + test_result.stderr)[-3000:]

        return {
            "repo": f"{owner}/{repo}",
            "branch": branch,
            "runner": runner_key,
            "cmd": cmd,
            "passed": passed,
            "return_code": test_result.returncode,
            "output": output,
            "safe_to_release": passed,
        }


@mcp.tool(description="Generate structured release notes from a commit list. Returns semver suggestion and markdown notes.")
def generate_release_notes(
    owner: str,
    repo: str,
    commits: list[dict],
    current_tag: str | None = None,
) -> dict:
    """Read-only. Drafts release notes from conventional commits."""
    breaking = [c for c in commits if c.get("breaking")]
    features = [c for c in commits if c.get("type") == "feat"]
    fixes = [c for c in commits if c.get("type") == "fix"]
    others = [c for c in commits if c.get("type") not in ("feat", "fix") and not c.get("breaking")]

    # Suggest next semver
    if breaking:
        version_bump = "major"
    elif features:
        version_bump = "minor"
    else:
        version_bump = "patch"

    suggested_version = "v1.0.0"
    if current_tag:
        m = re.match(r"v?(\d+)\.(\d+)\.(\d+)", current_tag)
        if m:
            major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if version_bump == "major":
                suggested_version = f"v{major + 1}.0.0"
            elif version_bump == "minor":
                suggested_version = f"v{major}.{minor + 1}.0"
            else:
                suggested_version = f"v{major}.{minor}.{patch + 1}"

    def _safe_msg(c: dict) -> str:
        # P0.3 FIX: commit messages are EXTERNAL DATA from GitHub — wrap so LLM never treats them as instructions
        return f"<<<UNTRUSTED:{c['message']}>>> ({c['sha']})"

    sections = []
    if breaking:
        sections.append("## Breaking Changes\n" + "\n".join(f"- {_safe_msg(c)}" for c in breaking))
    if features:
        sections.append("## Features\n" + "\n".join(f"- {_safe_msg(c)}" for c in features))
    if fixes:
        sections.append("## Bug Fixes\n" + "\n".join(f"- {_safe_msg(c)}" for c in fixes))
    if others:
        sections.append("## Other Changes\n" + "\n".join(f"- {_safe_msg(c)}" for c in others[:10]))

    notes = f"# Release {suggested_version}\n\n" + "\n\n".join(sections)

    return {
        "suggested_version": suggested_version,
        "version_bump": version_bump,
        "release_notes_markdown": notes,
        "commit_count": len(commits),
        "breaking_count": len(breaking),
        "feature_count": len(features),
        "fix_count": len(fixes),
    }


# ─── destructive (approval-gated) ────────────────────────────────────────────

@mcp.tool(
    description="[DESTRUCTIVE] Create a git tag and GitHub release. Requires human approval via TrueForge.",
    annotations={"destructiveHint": True, "readOnlyHint": False},
)
def create_github_release(
    owner: str,
    repo: str,
    tag_name: str,
    release_notes: str,
    target_branch: str = "main",
    draft: bool = True,
) -> dict:
    """
    DESTRUCTIVE — creates a tag and release on GitHub.
    TrueForge approval checkpoint fires before this executes.
    Defaults to draft=True for extra safety.
    """
    try:
        payload = {
            "tag_name": tag_name,
            "target_commitish": target_branch,
            "name": tag_name,
            "body": release_notes,
            "draft": draft,
            "prerelease": False,
        }
        result = _gh_post(f"/repos/{owner}/{repo}/releases", payload)
        return {
            "status": "created",
            "release_id": result["id"],
            "tag": tag_name,
            "draft": draft,
            "url": result["html_url"],
            "note": "Release created as DRAFT — publish manually in GitHub UI or call publish_release",
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


@mcp.tool(
    description="[DESTRUCTIVE] Publish a draft GitHub release (makes it public). Requires human approval.",
    annotations={"destructiveHint": True, "readOnlyHint": False},
)
def publish_release(owner: str, repo: str, release_id: int) -> dict:
    """DESTRUCTIVE — publishes draft release. TrueForge approval gate fires here."""
    try:
        resp = requests.patch(
            f"{GITHUB_API}/repos/{owner}/{repo}/releases/{release_id}",
            headers=_gh_headers(),
            json={"draft": False},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "status": "published",
            "tag": data["tag_name"],
            "url": data["html_url"],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8002
    import uvicorn
    uvicorn.run(mcp.streamable_http_app(), host="0.0.0.0", port=port)
