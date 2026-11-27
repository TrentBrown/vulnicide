# CLAUDE.md

Guidance for agents working in this repository: the `vulnicide` CLI (package
`@trentbrown/vulnicide`), which drives Snyk's `snyk` CLI.

## Layout

- `src/index.js`: entry point (Commander). It registers command modules and
  adds the tree-style `help [path...] [-r [depth]]` from
  `src/utils/help-tree.js`.
- `src/commands/`: `dependencies.js` (`deps`), `code.js` (`code`), `policy.js`,
  `audit.js`, `summary.js`. `deps explain` and `code explain` build the
  remediation packets. `gate.js` is `deps gate --json`, GateReeve's
  dependency-scan gate scanner: JSON request on stdin, normalized findings on
  stdout, unavailability as data, no writes, no raw Snyk error text.
- `src/utils/`: `snyk.js` (spawns `snyk`/`snyk-to-html`; `spawnSnyk` never
  throws, for the gate), `upgrade-advice.js` (shared by explain and gate), `context.js`
  (`--target` resolution; `joinProjectPath` for anything written or deleted,
  symlink-checked; `readProjectPath` for read-only inputs), `config.js` (`.vulnrc.json` / package.json `vuln`),
  `browser.js` (opening, honouring `VULN_NO_OPEN`), `paths.js` (package-root
  paths, so assets and docs resolve under a global install).
- `assets/`: the `.snyk` template written by `policy init`, the remediation-log
  template, and the summary CSS.
- `skills/remediate-vuln/`: the agent skill. This repo is its source of truth.
  `scripts/install-skills.js` copies it into `~/.codex` and `~/.agents`.
- `docs/`: `remediation.md` (policy and workflow), `prerequisites.md`,
  `test-usage.md` (Snyk plan-limit accounting).
- `test/`: offline smoke and gate tests, stub Snyk binaries (with
  `VULN_STUB_MODE` failure modes), sample targets and captured Snyk JSON.

## Rules

- Don't name the package or any binary `snyk`, because it would shadow Snyk's
  CLI.
- Keep everything generic. No client names, hostnames, account IDs, org IDs or
  client-specific `.snyk` exclusions in the template, docs, examples or
  fixtures. Project-specific policy belongs in the target repo.
- `npm test` must stay offline and spend no Snyk quota. A command-behaviour
  change needs smoke-test coverage. Refresh fixtures from a real run (README →
  Development) and scrub `org`/`path`.
- The fixtures under `test/fixtures` are deliberately vulnerable. Don't
  "fix" them.
- User-facing hints say `vulnicide ...`, not `npm run cli -- ...`.
- The `deps gate` response is a versioned contract with GateReeve
  (`schemaVersion: 1`). Don't change its fields or meanings without a
  GateReeve contract amendment.
- Dependency majors (chalk 6, commander 15, js-yaml 5, open 11) are ESM-only.
  js-yaml 5 has no default export: use `import { load } from 'js-yaml'`.

## Run locally

```bash
npm install
node src/index.js help -r
VULN_NO_OPEN=1 node src/index.js deps build --target ../some-project
npm test
```
