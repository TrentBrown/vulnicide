#!/usr/bin/env bash
# Install @trentbrown/vulnicide globally into a throwaway npm prefix and exercise
# the installed binaries, as a fresh host would.
#
#   test/install-check.sh                 # install from `npm pack` of this checkout
#   test/install-check.sh <npm-spec>      # e.g. git+https://github.com/TrentBrown/vulnicide.git#<sha>
#
# The git form fetches the public repo; no credentials are needed.
# No Snyk calls are made.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/vulnicide-install-XXXXXX")"
trap 'rm -rf "$work"' EXIT

spec="${1:-}"
if [[ -z "$spec" ]]; then
  spec="$(cd "$repo" && npm pack --silent --pack-destination "$work")"
  spec="$work/$spec"
fi

echo "Installing $spec"
npm install -g --prefix "$work/prefix" "$spec" --no-audit --no-fund --loglevel=error
bin="$work/prefix/bin"
# Resolve through the installed bin, not `npm root`: npm masks UUID-like path
# segments in its output as "***", which breaks paths under some temp dirs.
pkgdir="$(node -e 'const fs = require("fs"), path = require("path"); console.log(path.resolve(path.dirname(fs.realpathSync(process.argv[1])), ".."))' "$bin/vulnicide")"
[[ -f "$pkgdir/package.json" ]] || { echo "installed package not found at $pkgdir" >&2; exit 1; }

expected="$(node -p "require('$repo/package.json').version")"
actual="$("$bin/vulnicide" --version)"
[[ "$actual" == "$expected" ]] || { echo "version $actual != $expected" >&2; exit 1; }
"$bin/vulnicide" help -r | grep -q "explain"

for file in assets/.snyk-template assets/vulnerability-remediation-log-template.md docs/remediation.md skills/remediate-vuln/SKILL.md scripts/install-skills.js; do
  [[ -f "$pkgdir/$file" ]] || { echo "missing $file in installed package" >&2; exit 1; }
done

target="$work/target"
mkdir -p "$target"
VULN_NO_OPEN=1 "$bin/vulnicide" policy init --target "$target" >/dev/null
VULN_NO_OPEN=1 "$bin/vulnicide" audit open --target "$target" >/dev/null
grep -q '^version: v1\.' "$target/.snyk"
[[ -f "$target/docs/vulnerability-remediation-log.md" ]]

echo "OK: vulnicide $actual installed from $spec; binaries, packaged assets, policy init and audit open verified"
