# Prerequisites

Check these before a scanning session, or when provisioning a new host.

1. **Node.js 22.12 or newer.**

   ```bash
   node --version
   ```

   Installing from git warns `EBADENGINE` because the `qp-cli-core` dependency
   pins an exact Node version. The warning is harmless: `vulnicide` is tested on
   Node 24.

2. **`vulnicide` itself** (see the [README](../README.md#install)):

   ```bash
   command -v vulnicide && vulnicide --version
   ```

3. **Opengrep 2.1.0 or newer** for `vulnicide code build`, the default code
   engine. Install the tested version with Opengrep's official installer. It
   puts the binary in `~/.opengrep/cli/` and links it from `~/.local/bin`:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/v2.1.0/install.sh | bash -s -- -v v2.1.0
   # or, from a vulnicide checkout: npm run setup:opengrep
   opengrep --version     # must print 2.1.0 or later
   ```

   With [cosign](https://github.com/sigstore/cosign) installed, the installer
   verifies the binary's signature (add `--verify-signatures` to require it).

   What leaves the machine during an Opengrep scan:

   - **No source code and no file names.** The analysis runs locally.
   - **No telemetry.** Opengrep 2.1.0 was checked: it has no metrics option and
     no code that sends usage data. vulnicide also sets `SEMGREP_SEND_METRICS=off`
     for every `opengrep` process, so a later version can't start sending
     usage data unnoticed.
   - **Rule downloads.** With the default rules, Opengrep fetches the rule
     pack with `GET https://semgrep.dev/c/p/default`. That request reveals
     the pack name, your IP address and a user agent, and nothing about your
     code. Registry rules are under the Semgrep Rules License, which permits
     internal use. To avoid the network entirely, list only local rule files
     or folders in `opengrepConfig`.

   vulnicide scans with `--x-ignore-semgrepignore-files`, so that `.snyk` alone
   (plus `.gitignore`) decides what is excluded. Opengrep marks that option
   **[INTERNAL]**: it prints a warning about it and may change it without
   notice. The 2.1.0 version floor and a smoke test guard it; check them when
   raising the minimum version. Opengrep still skips minified files (such as
   `*.min.js`) on its own.

4. **Snyk's CLI and HTML reporter**, installed globally so they are on `PATH`:

   ```bash
   npm install -g snyk snyk-to-html
   snyk --version
   command -v snyk-to-html
   ```

   These are needed for `vulnicide deps build`, and for `vulnicide code build`
   only with `--engine snyk`.

5. **Snyk authentication.** Use one of:

   ```bash
   snyk auth              # interactive; opens a browser
   export SNYK_TOKEN=...  # headless/CI; an API token or service-account token
   ```

   Check it with `snyk whoami --experimental`. Don't commit tokens or put them
   in `.vulnrc.json`.

6. **Snyk Code enabled** in the Snyk organization's settings if you
   use `vulnicide code build --engine snyk`. Otherwise the scan ends as
   `unavailable` with reason `not-entitled`. Snyk Code uploads the source
   files it analyses to Snyk.

7. **For dependency scans of Node projects**, install the target's dependencies
   first (`npm install` or `npm ci`). `vulnicide deps build` refuses a Node target
   without `node_modules`.

8. **Headless hosts:** set `VULN_NO_OPEN=1` so `browse`/`open` commands print
   paths instead of launching a browser or editor.

9. **Budget.** Each `deps build`, and each `code build --engine snyk`, is a
   Snyk test that counts against the plan's limits. See
   [test-usage.md](test-usage.md). Opengrep scans spend no Snyk quota.
