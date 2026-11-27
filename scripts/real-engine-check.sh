#!/usr/bin/env bash
# Real-engine check: run this checkout's CLI against a real Opengrep (not the
# test stubs) on copies of the deliberately vulnerable sample target.
#
# Needs `opengrep` 2.1.0+ on PATH and network access (it fetches the public
# p/default rule pack; no code is sent). It is not part of `npm test`, which
# stays offline. Exits non-zero if any expectation fails.
#
#   bash scripts/real-engine-check.sh
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export VULN_NO_OPEN=1 NO_COLOR=1
FAILURES=0

vulnicide() { node "$REPO/src/index.js" "$@"; }
expect() { # description, condition result (0 = ok)
    if [ "$2" -eq 0 ]; then echo "PASS: $1"; else echo "FAIL: $1"; FAILURES=$((FAILURES + 1)); fi
}
json() { # file, python expression over `d`
    python3 -I -c "import json,sys; d=json.load(open(sys.argv[1])); v=($2); print(v)" "$1"
}

case ":$PATH:" in *":$REPO/test/bin:"*) echo "test/bin stubs are on PATH; remove them first" >&2; exit 2 ;; esac
command -v opengrep >/dev/null || { echo "opengrep is not on PATH" >&2; exit 2; }
echo "opengrep $(opengrep --version) at $(command -v opengrep)"
echo "vulnicide $(vulnicide --version) at $(git -C "$REPO" rev-parse HEAD)"
echo

echo "## 1. Findings with the default rules (p/default)"
cp -R "$REPO/test/fixtures/sample-target" "$WORK/one"
vulnicide code build --target "$WORK/one"; status=$?
expect "exit code 1 (findings)" "$([ "$status" -eq 1 ]; echo $?)"
outcome="$(json "$WORK/one/build/code/scan-result.json" "d['engine'], d['engineVersion'], d['outcome'], d['counts']")"
echo "scan-result: $outcome"
expect "engine opengrep, outcome findings" "$(echo "$outcome" | grep -q "opengrep.*findings"; echo $?)"
rules="$(json "$WORK/one/build/code/audit-code.json" "sorted({r['ruleId'] for r in d['runs'][0]['results']})")"
echo "rules found: $rules"
expect "command injection in src/server.js is reported" "$(echo "$rules" | grep -q "detect-child-process"; echo $?)"
expect "report written" "$([ -s "$WORK/one/build/code/audit-code.html" ]; echo $?)"
expect "report is self-contained" "$([ -s "$WORK/one/build/code/audit-code.html" ] && ! grep -q -i -E '<link|src=|@import|url\(' "$WORK/one/build/code/audit-code.html"; echo $?)"
vulnicide code explain --target "$WORK/one" >/dev/null
packets="$(json "$WORK/one/build/code/remediation-packets.json" "d['schemaVersion'], d['source']['engine'], [(p['rule']['cwe'], p['classification']) for p in d['packets']]")"
echo "packets: $packets"
expect "v2 packets, engine opengrep, CWE-78 classified input-validation" "$(echo "$packets" | grep -q "^(2, 'opengrep'.*\['CWE-78'\], 'input-validation'"; echo $?)"
echo

echo "## 2. Unknown registry pack"
cp -R "$REPO/test/fixtures/sample-target" "$WORK/two"
printf '{"opengrepConfig": ["p/vulnicide-no-such-pack"]}\n' > "$WORK/two/.vulnrc.json"
vulnicide code build --target "$WORK/two"; status=$?
expect "exit code 2 (unavailable)" "$([ "$status" -eq 2 ]; echo $?)"
outcome="$(json "$WORK/two/build/code/scan-result.json" "d['outcome'], d['reason']")"
echo "scan-result: $outcome"
expect "unavailable / rules-unavailable" "$([ "$outcome" = "('unavailable', 'rules-unavailable')" ]; echo $?)"
expect "no audit files written" "$(ls "$WORK/two/build/code" | grep -q audit-code; [ $? -ne 0 ]; echo $?)"
echo

echo "## 3. .snyk exclusions"
cp -R "$REPO/test/fixtures/sample-target" "$WORK/three"
mkdir -p "$WORK/three/test" "$WORK/three/lib/vendor"
cp "$WORK/three/src/server.js" "$WORK/three/test/server.js"
cp "$WORK/three/src/server.js" "$WORK/three/lib/vendor/server.js"
printf "version: v1.25.0\nexclude:\n  code:\n    - test/**\n    - '**/vendor/**'\n" > "$WORK/three/.snyk"
vulnicide code build --target "$WORK/three"; status=$?
expect "exit code 1 (findings)" "$([ "$status" -eq 1 ]; echo $?)"
files="$(json "$WORK/three/build/code/audit-code.json" "sorted({r['locations'][0]['physicalLocation']['artifactLocation']['uri'] for r in d['runs'][0]['results']})")"
echo "files with results: $files"
expect "only src/server.js reported (test/** and **/vendor/** excluded)" "$([ "$files" = "['src/server.js']" ]; echo $?)"
echo

if [ "$FAILURES" -ne 0 ]; then echo "$FAILURES check(s) failed"; exit 1; fi
echo "All real-engine checks passed"
