#!/usr/bin/env bash
# Riva hook: agent_detected
# Receives JSON context on stdin.
# Exit 0 for success, non-zero for failure.

set -euo pipefail

CONTEXT=$(cat)
echo "[riva:agent_detected] hook triggered"
