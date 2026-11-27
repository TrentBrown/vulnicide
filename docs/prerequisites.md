# Prerequisites

Check these before a scanning session, or when provisioning a new host.

1. **Node.js 22.12 or newer.**

   ```bash
   node --version
   ```

2. **`vulnicide` itself** (see the [README](../README.md#install)):

   ```bash
   command -v vulnicide && vulnicide --version
   ```

3. **Snyk's CLI and HTML reporter**, installed globally so they are on `PATH`:

   ```bash
   npm install -g snyk snyk-to-html
   snyk --version
   command -v snyk-to-html
   ```

4. **Snyk authentication.** Use one of:

   ```bash
   snyk auth              # interactive; opens a browser
   export SNYK_TOKEN=...  # headless/CI; an API token or service-account token
   ```

   Check it with `snyk whoami --experimental`. Don't commit tokens or put them
   in `.vulnrc.json`.

5. **Snyk Code enabled** in the Snyk organization's settings if you
   use `vulnicide code build`. Otherwise `snyk code test` fails with a "not enabled"
   error.

6. **For dependency scans of Node projects**, install the target's dependencies
   first (`npm install` or `npm ci`). `vulnicide deps build` refuses a Node target
   without `node_modules`.

7. **Headless hosts:** set `VULN_NO_OPEN=1` so `browse`/`open` commands print
   paths instead of launching a browser or editor.

8. **Budget.** Each `build` is a Snyk test that counts against the plan's
   limits. See [test-usage.md](test-usage.md).
