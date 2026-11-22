#!/usr/bin/env bash
# Rehearse the body caps (E-M4) against a deployed gate: an over-cap body is refused with 413.
# Usage: scripts/rehearse-body-caps.sh [gate-origin] [project]. Prints status codes only.
set -euo pipefail
G="${1:-https://gw-staging.meapps.dev}"; P="${2:-staging-test}"
T="$(cloudflared access token -app="$G" 2>/dev/null)"; [ -n "$T" ] || { echo "no Access token for $G" >&2; exit 2; }
fail=0; check() { if [ "$2" = "$3" ]; then echo "ok   $1: $2"; else echo "FAIL $1: got $2, want $3"; fail=1; fi; }
big() { python3 -c "import sys; sys.stdout.write('{\"keys\":[\"' + 'A'*$1 + '\"]}')"; }
code() { curl -s -o /dev/null -w '%{http_code}' -X POST -H "cf-access-token: $T" -H 'content-type: application/json' -H 'x-wapps-intent: rehearsal' --data-binary @- "$G$1"; }
check "read over 1 MiB" "$(big 1200000 | code "/v1/projects/$P/read")" "413"
check "read under the cap (unknown key: 404, not 413)" "$(printf '{"keys":["NO_SUCH_KEY"]}' | code "/v1/projects/$P/read")" "404"
exit $fail
