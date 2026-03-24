#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; exit 1; }

# 1) Help output should include named flag docs
HELP_OUT="$(./scripts/run_lab_checks.sh --help)"
echo "$HELP_OUT" | grep -q -- "--max-abs-delta" || fail "help missing --max-abs-delta"
echo "$HELP_OUT" | grep -q -- "--quick" || fail "help missing --quick"
pass "help output includes named flags"

# 2) Quick mode flags path should execute and print quick banner
QUICK_OUT="$(./scripts/run_lab_checks.sh --max-abs-delta 0 --quick --refresh-status --no-snapshot)"
echo "$QUICK_OUT" | grep -q "\[quick\] Skipping live preflight/regression/trend query steps" || fail "quick mode banner missing"
echo "$QUICK_OUT" | grep -q "All checks completed successfully." || fail "quick mode did not complete"
pass "quick mode named flags path"

# 3) Positional args path should still work (backward compatibility)
POS_OUT="$(./scripts/run_lab_checks.sh 0 0 1 1)"
echo "$POS_OUT" | grep -q "quick_mode=1" || fail "positional mode did not parse quick arg"
echo "$POS_OUT" | grep -q "All checks completed successfully." || fail "positional mode did not complete"
pass "positional args backward compatibility"

echo "ALL TESTS PASSED"
