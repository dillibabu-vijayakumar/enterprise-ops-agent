#!/usr/bin/env bash
set -euo pipefail
echo "=== Enterprise Ops Agent Setup ==="

command -v python3 &>/dev/null || { echo "❌ Python 3 required"; exit 1; }
command -v node &>/dev/null    || { echo "❌ Node.js required"; exit 1; }
aws sts get-caller-identity &>/dev/null || { echo "❌ AWS credentials not configured"; exit 1; }

echo "✅ AWS: $(aws sts get-caller-identity --query Account --output text)"

python3 -m pip install -r mcp/requirements.txt -q
python3 -c "import boto3; import mcp; import requests; print('✅ Python deps OK')"

echo ""
echo "=== Run the router ==="
echo "  ANTHROPIC_API_KEY=sk-ant-... \\"
echo "  AWS_PROFILE=your-profile \\"
echo "  GITHUB_TOKEN=ghp_... \\"
echo "  npx @truefoundry/trueforge --agent agents/router.json"
echo ""
echo "Example prompts:"
echo "  'Scan ap-south-1 for idle AWS resources'"
echo "  'Check if github.com/myorg/myrepo is ready for release'"
echo "  'Review IAM access for stale users'"
echo "  'Do all three above' ← parallel subagent demo"
