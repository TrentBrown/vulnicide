# CLAUDE.md

Guidance for agents working in this repository: the `vulnicide` CLI (package
`@trentbrown/vulnicide`). It drives Opengrep (`opengrep`, the default local
code engine) and Snyk's `snyk` CLI (dependencies, and code with
`--engine snyk`).

## Layout

- `src/index.js`: entry point (Commander). It registers command modules and
  adds qp-cli-core's tree-style `help [path...] [-r]`.
- `src/commands/`: `dependencies.js` (`deps`), `code.js` (`code`), `policy.js`,
  `audit.js`, `summary.js`. `deps explain` and `code explain` build the
  remediation packets.
- `src/utils/`: `opengrep.js` (version gate, scan arguments, failure
  classification), `snyk.js` (spawns `snyk`/`snyk-to-html`; `runSnykCodeScan`
  classifies Snyk Code failures, while the deps runner is unchanged),
  `code-report.js` (self-contained Opengrep HTML), `process.js` (spawn and
  capture), `context.js`
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
- `test/`: offline smoke test, `code-engine.test.js` (both code engines),
  stub `opengrep`/`snyk`/`snyk-to-html` binaries, sample targets, captured
  Snyk JSON and Opengrep SARIF (`test/fixtures/opengrep/README.md` records
  their provenance and hand edits).

## Rules

- Don't name the package or any binary `snyk`, because it would shadow Snyk's
  CLI.
- Keep everything generic. No client names, hostnames, account IDs, org IDs or
  client-specific `.snyk` exclusions in the template, docs, examples or
  fixtures. Project-specific policy belongs in the target repo.
- `npm test` must stay offline, spend no Snyk quota and need no real
  `opengrep`. A command-behaviour change needs smoke-test coverage. Refresh
  fixtures from a real run (README → Development) and scrub `org`/`path`.
  Opengrep rule IDs from a local rules file embed that file's absolute path;
  scrub it.
- `code build`/`rebuild` end in one outcome (`build/code/scan-result.json`,
  exit 0 clean / 1 findings / 2 unavailable / 3 error; 64 for usage errors).
  Never write an engine error as `audit-code.json`.
- The fixtures under `test/fixtures` are deliberately vulnerable. Don't
  "fix" them.
- User-facing hints say `vulnicide ...`, not `npm run cli -- ...`.
- Dependency majors (chalk 6, commander 15, js-yaml 5, open 11) are ESM-only.
  js-yaml 5 has no default export: use `import { load } from 'js-yaml'`.

## Run locally

```bash
npm install
node src/index.js help -r
VULN_NO_OPEN=1 node src/index.js deps build --target ../some-project
npm test
```
