#!/bin/bash

set -euo pipefail

FUNCTION_NAME="${1:-chainbreak-auditor}"
OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${GREEN}=== Invoking ${FUNCTION_NAME} ===${NC}"

# --log-type Tail returns the last 4KB of the invocation's logs inline, so there
# is no need to go hunting in CloudWatch for a quick check.
STATUS=$(aws lambda invoke \
  --function-name "$FUNCTION_NAME" \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  --log-type Tail \
  --query 'LogResult' \
  --output text \
  "$OUT")

echo -e "\n${YELLOW}--- Execution log ---${NC}"
echo "$STATUS" | base64 --decode

echo -e "\n${YELLOW}--- Response ---${NC}"
if command -v jq >/dev/null 2>&1; then
  # The body is a JSON string inside a JSON object, so it needs decoding twice.
  jq -r '.body' "$OUT" | jq '.'
else
  cat "$OUT"
  echo -e "\n${YELLOW}(install jq for formatted output)${NC}"
fi

echo -e "\n${YELLOW}--- What to look for ---${NC}"
cat <<'NOTES'
  highSeverity > 0          escalated to a human, deliberately not auto-fixed
  wouldRemediate > 0        dry run worked: it could fix this but did not
  remediated > 0            a rule was actually revoked
  remediationSuppressed     IAM scan failed, so fixing was disabled (fail closed)
  attackPaths > 0           a public instance with an over-broad role was found
  failedScanners non-empty  partial run; check the log above
NOTES

if grep -q '"statusCode":207' "$OUT" 2>/dev/null; then
  echo -e "\n${RED}Note: 207 means the scan completed WITH ERRORS.${NC}"
fi

echo -e "\n${GREEN}Done.${NC}"
