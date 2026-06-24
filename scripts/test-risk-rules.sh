#!/usr/bin/env bash
# Enforce the custom risk rules with Threagile's cmd/script harness.
#
# Usage: scripts/test-risk-rules.sh [threagile-src-dir]
#   threagile-src-dir defaults to $THREAGILE_SRC, else /tmp/threagile-src
#
# Requires Go and a Threagile SOURCE tree (the harness + YAML script engine are NOT
# in the released Docker image). Each rule is run against the committed parsed-format
# fixture (model/custom-risk-rules/test/parsed-model.yaml) and asserted to fire on its
# intended asset and skip its negative control. The harness returns exit 0 even on
# errors, so correctness is asserted on its OUTPUT, not the exit code.
set -uo pipefail
SRC="${1:-${THREAGILE_SRC:-/tmp/threagile-src}}"
HERE="$(cd "$(dirname "$0")" && pwd)"
RULES="$HERE/../model/custom-risk-rules"

if [ ! -f "$SRC/cmd/script/main.go" ]; then
  echo "ERROR: Threagile source not found at '$SRC' (clone github.com/Threagile/threagile)." >&2
  exit 2
fi

cp "$RULES/test/parsed-model.yaml" "$SRC/test/parsed-model.yaml"
BIN="$(mktemp -d)/script"
echo "Building cmd/script harness..."
( cd "$SRC" && go build -o "$BIN" ./cmd/script ) || { echo "ERROR: harness build failed" >&2; exit 2; }

# rule | expected-positive-synthetic-id | negative-asset-id-that-must-NOT-match
CASES="
unauthenticated-safety-bus-link|unauthenticated-safety-bus-link@chassis-zone-controller|safe-chassis-gateway
internet-exposed-ecu-unencrypted|internet-exposed-ecu-unencrypted@telematics-unit|infotainment-offline
reachable-unauthenticated-diagnostics|reachable-unauthenticated-diagnostics@obd-tester|
missing-secoc-on-safety-bus|missing-secoc-on-safety-bus@token-auth-zone|safe-chassis-gateway
cross-domain-link-no-filter|cross-domain-link-no-filter@rogue-telematics|telematics-unit
"

fail=0
while IFS='|' read -r rule pos neg; do
  [ -z "$rule" ] && continue
  out="$( cd "$SRC" && "$BIN" -script "$RULES/$rule.yaml" 2>&1 )" || true
  if printf '%s\n' "$out" | grep -qiE "error (reading|parsing|generating|printing)"; then
    echo "FAIL  $rule: harness reported an error"; printf '%s\n' "$out" | grep -i error | head -3; fail=1; continue
  fi
  if ! printf '%s\n' "$out" | grep -qF "$pos"; then
    echo "FAIL  $rule: expected match '$pos' was not produced"; fail=1; continue
  fi
  if [ -n "$neg" ] && printf '%s\n' "$out" | grep -qF "@$neg"; then
    echo "FAIL  $rule: negative control '$neg' unexpectedly matched"; fail=1; continue
  fi
  echo "PASS  $rule -> $pos"
done <<CASESEOF
$CASES
CASESEOF

if [ "$fail" -eq 0 ]; then echo "All custom risk rules validated."; else echo "Rule validation FAILED."; fi
exit "$fail"
