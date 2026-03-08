#!/usr/bin/env bash
# Riva hook: audit_finding
# Receives JSON context on stdin.
# Exit 0 for success, non-zero for failure.

set -euo pipefail

CONTEXT=$(cat)
echo "[riva:audit_finding] hook triggered"
