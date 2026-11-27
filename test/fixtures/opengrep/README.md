# Opengrep fixtures

SARIF replayed by the stub `test/bin/opengrep`, so `npm test` needs no
network and no real Opengrep.

## Real captures

Captured from Opengrep 2.1.0 (`opengrep --version` → `version.txt`) on
copies of `test/fixtures/sample-target` and `test/fixtures/python-target`,
with the flags vulnicide passes (`scan --sarif --dataflow-traces
--disable-nosem --x-ignore-semgrepignore-files`, `SEMGREP_SEND_METRICS=off`).

| File | Rules (`--config`) | Target | Real exit |
| --- | --- | --- | --- |
| `node.sarif.json` | `test/fixtures/opengrep-rules/rules.yaml` | sample-target | 0 |
| `python.sarif.json` | same | python-target | 0 |
| `node-note-only.sarif.json` | only the `hardcoded-password` rule | sample-target | 0 |
| `python-clean.sarif.json` | only the `hardcoded-password` rule | python-target | 0 |
| `pack-404.sarif.json` | an unknown registry pack (HTTP 404) | sample-target | 2 |
| `unreachable.sarif.json` | `p/default`, with the registry host unresolvable | sample-target | 2 |
| `invalid-rule.sarif.json` | a rule with an unparseable pattern | sample-target | 2 |
| `invalid-yaml.sarif.json` | a rules file that isn't valid YAML | sample-target | 7 |

## Scrubbing

Opengrep prefixes the IDs of rules loaded from a local file with that
file's absolute path, written with dots. Those prefixes are replaced with
`test.fixtures.opengrep-rules.` (or `tmp.` for throwaway rule files), and
absolute paths in messages with `<scratch>/rules.yaml`. Nothing else in
the real captures was changed.

## Hand-edited variants (labelled; derived from the captures above)

| File | Derived from | Edit |
| --- | --- | --- |
| `registry-500.sarif.json` | `pack-404.sarif.json` | HTTP status and body changed to 500 |
| `node-level-override.sarif.json` | `node.sarif.json` | the `hardcoded-password` result gets its own `level: error` (its rule's default is `note`); Opengrep itself doesn't emit per-result levels |
| `node-markup.sarif.json` | `node.sarif.json` | markup (`<script>…</script>&`) put into the taint finding's rule ID, message, file path, CWE tag and first flow location, to test HTML escaping |

# Snyk error fixtures (`test/fixtures/snyk`)

| File | Source |
| --- | --- |
| `code-error-auth.json` | real: `snyk code test --json` 1.1305.2 with an invalid `SNYK_TOKEN` printed this on **stderr** and exited 2 (`path` scrubbed) |
| `code-error-not-enabled.json` | hand-written in Snyk's documented `{ok:false, error, path}` error format; not a real capture |
| `code-error-other.json` | hand-written in the same format; not a real capture |
