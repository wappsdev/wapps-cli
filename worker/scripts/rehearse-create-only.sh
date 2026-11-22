#!/usr/bin/env bash
# Rehearse the create-only key write (E-M3, work item b7bbe826) against a deployed gate.
# Usage: scripts/rehearse-create-only.sh [gate-origin] [project]
# Needs a cloudflared Access login for the gate. Prints status codes only, never a value or token.
set -euo pipefail
G="${1:-https://gw-staging.meapps.dev}"; P="${2:-staging-test}"
T="$(cloudflared access token -app="$G" 2>/dev/null)"; [ -n "$T" ] || { echo "no Access token for $G" >&2; exit 2; }
K="REHEARSAL_CREATE_ONLY_$(date +%s)"
put() { curl -s -o /dev/null -w '%{http_code}' -X PUT -H "cf-access-token: $T" -H 'content-type: application/json' \
  -H 'x-wapps-intent: rehearsal' "$@" --data "{\"value\":\"rehearsal-$RANDOM\"}" "$G/v1/projects/$P/keys/$K"; }
fail=0; check() { if [ "$2" = "$3" ]; then echo "ok   $1: $2"; else echo "FAIL $1: got $2, want $3"; fail=1; fi; }
# 1. Two concurrent create-only writes of one new key: exactly one 201, one 409.
a=$(mktemp); b=$(mktemp)
put -H 'if-none-match: *' > "$a" & put -H 'if-none-match: *' > "$b" & wait
pair="$(sort <(cat "$a"; echo) <(cat "$b"; echo) | tr '\n' ' ' | xargs)"; rm -f "$a" "$b"
check "concurrent create-only pair" "$pair" "201 409"
# 2. Create-only on the existing key: 409, nothing written.
check "create-only of an existing key" "$(put -H 'if-none-match: *')" "409"
# 3. Any other If-None-Match on PUT is refused.
check "If-None-Match other than *" "$(put -H 'if-none-match: "abc"')" "400"
# 4. A plain write (the human's overwrite) still replaces the value.
check "plain overwrite" "$(put)" "200"
# 5. Delete, then create-only again: a deleted key counts as having no value.
d=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "cf-access-token: $T" -H 'x-wapps-intent: rehearsal' "$G/v1/projects/$P/keys/$K")
check "delete" "$d" "200"
check "create-only after delete" "$(put -H 'if-none-match: *')" "201"
curl -s -o /dev/null -X DELETE -H "cf-access-token: $T" -H 'x-wapps-intent: rehearsal' "$G/v1/projects/$P/keys/$K"
echo "key used: $K (deleted)"; exit $fail
