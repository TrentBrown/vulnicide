# vulnicide

`vulnicide` (package `@trentbrown/vulnicide`) scans a project's code and
dependencies, saves JSON and HTML reports, and turns the findings into
prioritized, model-friendly **remediation packets**. An agent (the bundled
`remediate-vuln` skill) or a human can then work through the packets one at a
time and record each decision in an audit log.

- **Code** is analysed by [Opengrep](https://github.com/opengrep/opengrep)
  (LGPL-2.1) by default. It runs **entirely on your machine**: no source code is
  sent anywhere. Snyk Code, which uploads source to Snyk for analysis, is
  available with `--engine snyk`.
- **Dependencies** are checked by Snyk's own `snyk` CLI against Snyk's
  vulnerability database. It sends the dependency list, not your source.

It is an independent tool, not a Snyk or Opengrep product: it calls their CLIs.

## Prerequisites

- Node.js 22.12 or newer.
- For `code` scans (default engine): Opengrep 2.1.0 or newer on `PATH`:
  `curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/v2.1.0/install.sh | bash -s -- -v v2.1.0`
  (or `npm run setup:opengrep` from a checkout).
- For `deps` scans, and `code` scans with `--engine snyk`: Snyk's CLI and HTML
  reporter on `PATH`: `npm install -g snyk snyk-to-html`. From a checkout,
  `npm run setup:tools` installs these and Opengrep.
- Snyk authentication: `snyk auth` interactively, or `SNYK_TOKEN` in the
  environment for headless hosts.
- For `code` scans with `--engine snyk`, Snyk Code must be enabled for your
  Snyk organization.

See [docs/prerequisites.md](docs/prerequisites.md) for details and checks, and
[docs/test-usage.md](docs/test-usage.md) for how scans count against Snyk's
plan limits.

## Install

The package is not published to npm. Install it from git.

### Global install from git (no checkout)

```bash
npm install -g git+https://github.com/TrentBrown/vulnicide.git
vulnicide --version
```

To pin a version, add a tag or commit: `...vulnicide.git#<tag-or-sha>`. To
upgrade, run the same `npm install -g` command again.

### Development checkout

```bash
git clone https://github.com/TrentBrown/vulnicide.git ~/Code/tb/vulnicide
cd ~/Code/tb/vulnicide
npm install
npm link               # puts `vulnicide` on PATH from this checkout
npm run setup          # optional: global snyk/snyk-to-html, Opengrep + bundled skill
```

Without `npm link`, run `node ~/Code/tb/vulnicide/src/index.js ...` or
`npm run cli -- ...` inside the checkout.

### Bundled agent skill

`npm run setup:skills` (from a checkout) installs `skills/remediate-vuln` into
`${CODEX_HOME:-~/.codex}/skills/remediate-vuln`. It also installs into
`${AGENTS_HOME:-~/.agents}/skills/remediate-vuln` when that directory exists or
`AGENTS_HOME` is set. Restart the agent session if the skill does not appear.
After a global install, the same script lives at
`"$(npm root -g)/@trentbrown/vulnicide/scripts/install-skills.js"`.

### Fleet provisioning notes

A provisioned host needs:

1. Node.js 22.12 or newer, and npm.
2. `npm install -g git+https://github.com/TrentBrown/vulnicide.git#<tag-or-sha>`.
3. `npm install -g snyk snyk-to-html`, and Opengrep 2.1.0 or newer (the
   install command above, which puts `opengrep` in `~/.local/bin`).
4. `SNYK_TOKEN` in the environment of whatever runs scans. `snyk auth` needs a
   browser, so it is not suitable for unattended hosts.
5. `VULN_NO_OPEN=1` on headless hosts, so `browse`/`open` commands print the
   path instead of launching a browser or editor.
6. Optionally `node "$(npm root -g)/@trentbrown/vulnicide/scripts/install-skills.js"`
   for agent hosts.

## Usage

Every command scans the current directory unless you pass `--target <dir>`.

```bash
vulnicide policy init --target ../my-app     # write a starter .snyk policy
vulnicide deps build --target ../my-app      # snyk test  -> build/dependencies/
vulnicide deps explain --target ../my-app    # -> remediation-packets.{json,md}
vulnicide deps gate --json < request.json    # GateReeve gate scan: JSON in, findings JSON out
vulnicide code build --target ../my-app      # opengrep (local) -> build/code/
vulnicide code explain --target ../my-app    # -> remediation-packets.{json,md}
vulnicide audit open --target ../my-app      # create/open docs/vulnerability-remediation-log.md
vulnicide help -r                            # full command tree
```

| Command | What it does |
| --- | --- |
| `policy init [--force]` / `open` / `print` | Create the target's `.snyk` from [the generic template](assets/.snyk-template), open it, or print it |
| `deps build` / `rebuild` / `clean` / `browse` | Run `snyk test --json` in the target, write `build/dependencies/audit-dependencies.{json,html}` plus a minimal summary JSON |
| `deps explain` | Group findings by package@version into `D-###` packets with severity, direct/transitive status, Snyk upgrade advice and existing ignores |
| `deps gate --json [--timeout <seconds>]` | Scanning mode for GateReeve's dependency-scan gate: read a request on stdin, run one `snyk test` per target, write normalized findings JSON to stdout. Writes no files. See [Gate mode](#gate-mode) |
| `code build` / `rebuild` / `clean` / `browse` | Scan the target's source with Opengrep (default) or Snyk Code (`--engine snyk`). Write `build/code/audit-code.{json,html}` (SARIF and a report), a minimal summary JSON, and the outcome file `scan-result.json` |
| `code explain` | Turn each SARIF result into a `C-###` packet with the rule, location, data flow and classification |
| `audit path` / `open` | Print the target's remediation log path, or create it from [the template](assets/vulnerability-remediation-log-template.md) and open it |
| `summary build` / `browse` / `clean` | Build `vuln/dist/index.html` linking the HTML reports |
| `help [path...] [-r [depth]]` | Print the command tree from the root or the named command; `-r` recurses. `<command> help` and `<command> --help` do the same |

`deps build` needs a Node (`package.json`, with `node_modules` installed) or
Maven (`pom.xml`) project. `code build` works on any target.

`deps build` accepts `--severity-threshold <low|medium|high|critical>`;
`code build` accepts `--severity-threshold <low|medium|high>`. Both accept
`--debug`.

Each `deps build`, and each `code build --engine snyk`, runs one Snyk test.
See [docs/test-usage.md](docs/test-usage.md) before you schedule them. Opengrep
scans spend no Snyk quota.

### Code engines

| | Opengrep (default) | Snyk Code (`--engine snyk`) |
| --- | --- | --- |
| Where analysis runs | On this machine | Snyk's servers: **source files are uploaded** |
| Rules | `p/default` from the public rule registry, or your own (`opengrepConfig`) | Snyk's |
| Report | Self-contained HTML rendered by vulnicide | `snyk-to-html` |
| Needs | `opengrep` 2.1.0 or newer | `snyk`, `snyk-to-html`, a Snyk token, Snyk Code enabled |

Choose the engine with `--engine <opengrep|snyk>` on `code build` and
`code rebuild`, or set `codeEngine` in the project configuration. The flag wins
over the configuration, and the default is `opengrep`.

**Rules.** Opengrep downloads the `p/default` rule pack from the public rule
registry at scan time. Only the rules come down: the request names the pack,
and no code or file names are sent. To choose other packs, or your own rule
files and folders, set `opengrepConfig`. A list of local paths only gives a
fully offline scan:

```json
{ "codeEngine": "opengrep", "opengrepConfig": ["p/owasp-top-ten", "./security-rules/"] }
```

**Exclusions.** `.snyk` stays the single exclusion record for both engines.
For Opengrep, vulnicide passes each `exclude.global` and `exclude.code`
pattern as `--exclude`. Inline `nosemgrep` comments are ignored
(`--disable-nosem`), and so are `.semgrepignore` files and Opengrep's built-in
ignore list. If `.snyk` can't be parsed, or its `exclude.global`/`exclude.code`
isn't a list of patterns, the Opengrep scan ends as `error` rather than running
without the exclusions. See [docs/remediation.md](docs/remediation.md).

### Scan outcomes and exit codes

Every `code build` / `code rebuild` ends in exactly one outcome. It is written
to `build/code/scan-result.json` and also sets the exit code:

| Outcome | Exit | Meaning |
| --- | --- | --- |
| `clean` | 0 | The scan completed; nothing at or above the threshold |
| `findings` | 1 | The scan completed; findings at or above the threshold |
| `unavailable` | 2 | The scan couldn't run: `reason` is `not-installed` (including too old), `not-authenticated`, `not-entitled`, `rules-unavailable` or `network` |
| `error` | 3 | The engine ran but failed (bad rules, a crash, unreadable output), or the reports couldn't be written |

An unknown `--engine`, `codeEngine` or threshold is a usage error (exit 64),
and nothing is written. `audit-code.*` files are written only for `clean` and
`findings`. Outputs from an earlier run are removed first, so a failed scan
never leaves an old audit looking current.

`scan-result.json` (`schemaVersion` 1) has these fields: `engine`,
`engineVersion`, `outcome`, `reason`, `message` (it includes the engine's own
diagnostic on failure), `severityThreshold`, `counts` (`{ total, counted }`
for completed scans) and `startedAt`/`finishedAt`.

### Upgrading from 1.x

- **The default code engine is now Opengrep.** Install it (see
  Prerequisites), or keep Snyk Code with `--engine snyk` or
  `"codeEngine": "snyk"` in `.vulnrc.json`.
- **`code build` and `code rebuild` exit codes changed.** 1.x exited 0
  even when it found issues. 2.0.0 exits 1 for findings, 2 when the engine is
  unavailable and 3 on error (see above). Scripts that call these commands
  should check the exit code, or read `scan-result.json`.
- **`code explain` packets are `schemaVersion` 2.** They add `source.engine`,
  and `cwe`, `owasp` and `confidence` on each packet's rule. Classification
  now prefers the rule's CWE: for example, a Snyk command-injection finding
  (CWE-78) is now `input-validation`.

### Gate mode

`vulnicide deps gate --json` is the scanner side of GateReeve's dependency-scan
gate (contract `schemaVersion: 1`). GateReeve writes each side's `package.json`
and lockfile into scratch directories and calls it with a request on stdin:

```json
{"schemaVersion": 1, "includeDev": true,
 "policyPath": "/scratch/base.snyk", "annotatePolicyPath": "/scratch/head.snyk",
 "remoteRepoUrl": "https://github.com/owner/repo",
 "targets": [{"key": "package.json#base", "dir": "/scratch/base", "lockfile": "package-lock.json"}]}
```

For each target, in order, it runs
`snyk test --json [--dev] --file=<lockfile> [--policy-path=<policyPath>] [--remote-repo-url=<url>]`
in `dir`, and writes one response to stdout:

```json
{"schemaVersion": 1, "tool": {"name": "vulnicide", "version": "1.3.0"},
 "scanner": {"name": "snyk", "version": "1.1300.0"},
 "targets": [{"key": "package.json#base", "status": "ok", "unavailable": null,
   "testsConsumed": 1, "isPrivate": true,
   "findings": [{"vulnId": "SNYK-JS-LODASH-1040724", "package": "lodash", "version": "4.17.20",
     "severity": "high", "dev": false, "direct": true, "title": "Code Injection", "cvss": 7.2,
     "fixedIn": ["4.17.21"], "paths": [["app@1.0.0", "lodash@4.17.20"]],
     "upgradeAdvice": [{"dependency": "lodash@4.17.20", "upgradeTo": "lodash@4.18.1", "upgrades": ["lodash@4.17.20"]}],
     "branchIgnore": null}]}]}
```

- **Findings:** one per (vulnId, package, version), with every distinct path.
  License issues are left out. They are sorted by severity, then package,
  version and vulnId.
  - `direct` means some path reaches the package straight from the project.
  - `dev` means `includeDev` is true and every path starts at a dependency
    declared only in `devDependencies`.
  - `upgradeAdvice` uses the same shape as `deps explain` packets.
- **`branchIgnore`:** `{reason, expires, path}` from an unexpired ignore in the
  `annotatePolicyPath` policy (the branch's `.snyk`) that matches the finding.
  It is for display only. Only `policyPath` (the base `.snyk`) is passed to
  Snyk.
- **Unavailability is data.** When Snyk can't produce a result, the target's
  `status` is `unavailable` with a `reason`:
  - `not-installed` when `snyk` is missing;
  - `not-authenticated`;
  - `quota-exceeded` when the test limit is reached;
  - `network`, which includes the per-target timeout (600 s; `--timeout`
    overrides it);
  - `unsupported` when there is no supported project or lockfile, or the
    request's `schemaVersion` is unknown;
  - `scanner-error` for anything else, including a bad target `dir` or
    lockfile.

  The command still exits 0. `testsConsumed` is 1 when Snyk completed a test
  (exit 0 or 1), else 0.
- **Failure:** these exit 2 with nothing on stdout:
  - a request that isn't a JSON object with uniquely keyed `targets`;
  - a schemaVersion 1 request without a boolean `includeDev`, or with a
    `policyPath`, `annotatePolicyPath` or `remoteRepoUrl` that is missing or
    neither a string nor null;
  - a missing `--json`.
- **What it never does:** write files, need `node_modules`, pass `--debug`, or
  copy Snyk's error text, org, org ID or project path into its output.
  `unavailable.detail` is written by vulnicide: a fixed description, the exit
  code and any Snyk error code such as `SNYK-0005`. `SNYK_TOKEN` is read by
  `snyk` from the environment.

### Configuration

The target project can set `projectId`, `buildDir` (default `build`),
`vulnDir` (default `vuln`), `codeEngine` (default `opengrep`) and
`opengrepConfig` (default `["p/default"]`) in a `.vulnrc.json` file, or in a
`vuln` section of its `package.json`:

```json
{ "projectId": "my-project", "buildDir": "build", "vulnDir": "vuln", "codeEngine": "opengrep" }
```

Paths built from `buildDir`/`vulnDir` must stay inside the target directory.
The CLI refuses to create, write or delete anything outside the target,
including through a symlink, so `build`, `explain`, `summary` and `clean` never
touch another directory. Read-only inputs, such as a symlinked shared `.snyk`,
may live elsewhere.

The CLI reads one environment variable of its own: `VULN_NO_OPEN=1` suppresses
opening browsers and editors.

## Remediation process

[docs/remediation.md](docs/remediation.md) covers the packet workflow, `.snyk`
policy rules (dependency ignores compared with Code exclusions), the audit log,
and agent run modes. With the skill installed:

```text
Use $remediate-vuln in reviewed mode for packet C-001.
Use $remediate-vuln in batch mode for the next 10 code packets. Stop on suppression, major upgrades, failed verification, or ambiguous risk.
```

## Development

```bash
npm test               # offline smoke test
npm run test:install   # pack, install globally into a temp prefix, run the installed bins
bash test/install-check.sh git+https://github.com/TrentBrown/vulnicide.git#<sha>   # same, from the git URL
```

GitHub Actions (`.github/workflows/test.yml`) runs, on Node 22.12 and 24 for
every PR and every push to `main`:
- `npm test`;
- `npm run test:install`;
- `test/install-check.sh` against the repo's git URL at the exact commit.

The smoke test copies `test/fixtures/sample-target` (Node) and
`test/fixtures/python-target` into a temp directory. It runs `policy init`,
every command there:
- `deps` and `code`: build, explain, clean, rebuild, browse;
- `summary`: build, clean, rebuild, browse;
- `policy`: init, print, open;
- `audit`: path, open.

It also tests path containment (including symlink escapes), the help tree
and the skill installer. `test/gate.test.js` covers `deps gate`: arguments,
response shape, normalization, branch ignores, every unavailability reason,
request validation, no writes and no leaks. Its fixture variants (a dev-only
path, a license issue, a critical finding) are derived from the captured
`deps-node.json` at run time. `test/code-engine.test.js` covers both code
engines: engine selection, arguments, outcomes and exit codes, failure
classification, thresholds, reports and packets, for `build` and `rebuild`.

Stub `opengrep`, `snyk` and `snyk-to-html` binaries in `test/bin` replay
sanitized output captured from real runs, or fail the way Snyk does
(`VULN_STUB_MODE`), so the tests are offline, need no real scanner and spend no
Snyk quota.

The fixtures are **deliberately vulnerable** (lodash 4.17.20, minimist 1.2.0,
and command-injection/XSS sample code). The repo's own `.snyk` excludes `test/`
from Code scans. To dependency-scan this repo itself, run `snyk test` at the
root, or pass `--exclude=fixtures` with `--all-projects`.

`bash scripts/real-engine-check.sh` runs this checkout's CLI against a real
Opengrep (2.1.0 or newer on `PATH`, network for the `p/default` rule pack, no
stubs). It checks the findings outcome and the v2 packets, an unknown rule pack
(`unavailable`/`rules-unavailable`), and `.snyk` exclusions, and exits non-zero
if any expectation fails. Run it after changing the Opengrep integration or
raising the minimum version.

To refresh the Snyk fixtures, run the CLI against copies of the sample targets
with the real `snyk`. Copy the resulting `build/*/audit-*.json` over
`test/fixtures/snyk/`, and scrub `org` and `path`. The Opengrep fixtures come
from real Opengrep 2.1.0 runs with the local rules in
`test/fixtures/opengrep-rules/`. Their provenance, scrubbing and the few
labelled hand edits are listed in
[test/fixtures/opengrep/README.md](test/fixtures/opengrep/README.md).

## License

MIT. See [LICENSE](LICENSE).
