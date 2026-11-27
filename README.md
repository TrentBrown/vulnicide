# vulnicide

`vulnicide` (package `@trentbrown/vulnicide`) drives Snyk's own `snyk` CLI.
It scans a project's dependencies and code, saves JSON and HTML reports, and
turns the findings into prioritized, model-friendly **remediation packets**. An
agent (the bundled `remediate-vuln` skill) or a human can then work through the
packets one at a time and record each decision in an audit log.

It is an independent tool, not a Snyk product: `snyk` is Snyk's CLI and npm
package, and `vulnicide` calls it.

## Prerequisites

- Node.js 22.12 or newer.
- Snyk's CLI and HTML reporter on `PATH`:
  `npm install -g snyk snyk-to-html` (or `npm run setup:tools` from a checkout).
- Snyk authentication: `snyk auth` interactively, or `SNYK_TOKEN` in the
  environment for headless hosts.
- For `code` scans, Snyk Code must be enabled for your Snyk organization.

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
npm run setup          # optional: global snyk/snyk-to-html + bundled skill
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
3. `npm install -g snyk snyk-to-html`.
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
vulnicide code build --target ../my-app      # snyk code test -> build/code/
vulnicide code explain --target ../my-app    # -> remediation-packets.{json,md}
vulnicide audit open --target ../my-app      # create/open docs/vulnerability-remediation-log.md
vulnicide help -r                            # full command tree
```

| Command | What it does |
| --- | --- |
| `policy init [--force]` / `open` / `print` | Create the target's `.snyk` from [the generic template](assets/.snyk-template), open it, or print it |
| `deps build` / `rebuild` / `clean` / `browse` | Run `snyk test --json` in the target, write `build/dependencies/audit-dependencies.{json,html}` plus a minimal summary JSON |
| `deps explain` | Group findings by package@version into `D-###` packets with severity, direct/transitive status, Snyk upgrade advice and existing ignores |
| `code build` / `rebuild` / `clean` / `browse` | Run `snyk code test --json` (SARIF) in the target, for any language Snyk Code supports |
| `code explain` | Turn each SARIF result into a `C-###` packet with the rule, location, data flow and classification |
| `audit path` / `open` | Print the target's remediation log path, or create it from [the template](assets/vulnerability-remediation-log-template.md) and open it |
| `summary build` / `browse` / `clean` | Build `vuln/dist/index.html` linking the HTML reports |

`deps build` needs a Node (`package.json`, with `node_modules` installed) or
Maven (`pom.xml`) project. `code build` works on any target.

Both build commands accept `--severity-threshold <low|medium|high|critical>`
and `--debug`.

Each `build` runs one Snyk test. See [docs/test-usage.md](docs/test-usage.md)
before you schedule them.

### Configuration

The target project can set `projectId`, `buildDir` (default `build`) and
`vulnDir` (default `vuln`) in a `.vulnrc.json` file, or in a `vuln` section of
its `package.json`:

```json
{ "projectId": "my-project", "buildDir": "build", "vulnDir": "vuln" }
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

It also tests path containment (including symlink escapes) and the skill
installer. Stub
`snyk` and `snyk-to-html` binaries in `test/bin` replay sanitized output
captured from real Snyk runs, so the test is offline and spends no Snyk quota.

The fixtures are **deliberately vulnerable** (lodash 4.17.20, minimist 1.2.0,
and command-injection/XSS sample code). The repo's own `.snyk` excludes `test/`
from Code scans. To dependency-scan this repo itself, run `snyk test` at the
root, or pass `--exclude=fixtures` with `--all-projects`.

To refresh the fixtures, run the CLI against copies of the sample targets with
the real `snyk`. Copy the resulting `build/*/audit-*.json` over
`test/fixtures/snyk/`, and scrub `org` and `path`.

## License

MIT. See [LICENSE](LICENSE).
