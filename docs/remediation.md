# Snyk Vulnerability Remediation Guide

This guide explains how to use the `.snyk` policy file to manage and remediate vulnerabilities in your project using Snyk. It covers both static code analysis and dependency scanning, and details how to record, ignore, or document vulnerabilities that cannot be fully remediated.

---

## Overview

Snyk scans for two types of vulnerabilities:
- **Code vulnerabilities** (static analysis of your application code)
- **Dependency vulnerabilities** (in libraries your application depends on)

Both scans use the same Snyk CLI tool, but with different command-line options.
Dependency ignores belong in the `.snyk` beside the relevant manifest. Snyk Code
file exclusions must be discoverable from its scan root; a nested application
policy must not be assumed to govern a repository-root GitHub Code project.
Align policy paths, revision, scan scope, severity and development-dependency
settings before expecting local and external reports to match.

When a repository nests its application under a subdirectory (for example
`app/` or `services/api/`), it often needs two policies: one `.snyk` beside each
manifest for dependency ignores, and one at the Code scan root for file
exclusions. Document that arrangement in the target repository, along with how
you checked that any externally imported (GitHub-integrated) projects use the
same scan root and policy.

---

## Differences in Exclusion Specifications

While the overall remediation process is similar for both code and dependency scans, the way you record and exclude un-remediated vulnerabilities in the `.snyk` policy file is different for each scan type:

- If you fully remediate a vulnerability (code or dependency), it will no longer appear in reports and no policy update is needed.
- If your remediation is not recognized by Snyk, or you accept the risk, you must update the policy file to exclude or ignore the vulnerability—but the method differs:
  - **Code scans**: You can exclude specific directories or files using the `exclude.code` section.
  - **Dependency scans**: You cannot exclude specific directories or files; there is no `exclude.dependencies` section. Instead, you use the `ignore` section to suppress specific dependency vulnerabilities.
- `exclude.global` applies to products supporting file exclusions, including
  Snyk Code. It does not exclude ordinary dependency projects or suppress their
  vulnerabilities. Use manifest selection for project scope and `ignore` for
  approved dependency-vulnerability exceptions.

---

## Excluding Files and Directories

- Use `exclude.global` only for products supporting file exclusions (e.g.,
  excluding `dist/` from Snyk Code); it does not exclude dependency projects.
- Use the `exclude.code` section to exclude directories from code scans only (e.g., `node_modules/`).
- There is **no** `exclude.dependencies` section; dependency scans do not support directory exclusions. For dependency vulnerabilities, use the `ignore` section to suppress specific issues.

> **Tip:** Code scans should only target your application source code. Exclude directories like `node_modules`, `bin`, `test`, etc., to speed up scans and avoid irrelevant results.

---

## Remediation Process

### Dependency Vulnerabilities

1. **Scan for vulnerabilities:**
   ```sh
   vulnicide deps build
   ```
   When scanning a project other than the current directory, pass the target
   project directory:
   ```sh
   vulnicide deps build --target ../my-app
   ```
2. **Remediate or accept risk:**
   - If you can fix the vulnerability, do so. It will disappear from reports.
   - If you cannot remediate, or accept the risk, add the vulnerability to the `ignore` section of `.snyk`.
3. **Document your decision:**
   - Add a `reason` property explaining why the risk is acceptable.
   - Follow the sample pattern below for comments and documentation.
4. **Re-scan:**
   - Run the scan again to ensure the vulnerability is ignored in the report.

#### Model-assisted dependency triage

Dependency scan JSON can be very large. Do not feed the full
`audit-dependencies.json` file to an AI model by default. Instead, generate
remediation packets:

```sh
vulnicide deps explain
```

When scanning another project from the CLI directory, pass the same target used
for the dependency scan:

```sh
vulnicide deps explain --target ../my-app
```

The command reads:

- `build/dependencies/audit-dependencies.json`
- `package.json`
- `.snyk`

It writes:

- `build/dependencies/remediation-packets.json`
- `build/dependencies/remediation-packets.md`

Each packet groups vulnerable dependency paths by package and version, then
records:

- the packet ID, such as `D-001-axios-0-21-4`
- severity and vulnerability counts
- Snyk vulnerability IDs, titles, CVEs/CWEs, fixed versions, and exploit notes
- example dependency paths
- whether the package is a direct dependency
- Snyk upgrade advice from `remediation.upgrade`
- existing `.snyk` ignore decisions, when present
- a short model prompt for the packet

Use the packet files as the working queue. For each packet:

1. Ask the model to evaluate one packet at a time using this guide.
2. Require a concrete recommendation before editing:
   - direct dependency upgrade
   - parent dependency upgrade
   - npm override or package-lock change
   - framework migration or deferral
   - documented `.snyk` ignore
3. Apply one small remediation.
4. Re-run `deps build` with the same `--target`.
5. Re-run `deps explain` and compare the new packet queue.

For accepted risk, the model may draft `.snyk` ignore text, but a human must
verify the rationale and the project-specific exploitability before committing.

### Code Vulnerabilities

1. **Scan for vulnerabilities:**
   ```sh
   vulnicide code build
   ```
   When scanning a project other than the current directory, pass the target
   project directory:
   ```sh
   vulnicide code build --target ../my-app
   ```
2. **Remediate or accept risk:**
   - If you fix the vulnerability and it no longer appears, you're done.
   - If you cannot remediate, or Snyk does not recognize your fix, continue below.
3. **Mitigate in code:**
   - Move or factor out the offending code into a `mitigated.js` file in the same directory as the original file. If `mitigated.js` exists, add to it.
4. **Exclude mitigated file:**
   - Add `mitigated.js` to the `exclude.code` section of `.snyk` if not already present.
5. **Document your decision:**
   - In the `.snyk` file, add a comment block explaining the vulnerability, your mitigation, and the reason for accepting the risk or why Snyk's detection is incorrect.
6. **Re-scan:**
   - Run the scan again to ensure the vulnerability is excluded from the report.

#### Model-assisted code triage

Code scan JSON is SARIF. It is more structured than the dependency audit JSON,
but still includes repeated rule documentation, fingerprints, and code-flow
metadata. Generate remediation packets before asking a model to evaluate code
findings:

```sh
vulnicide code explain
```

When scanning another project from the CLI directory, pass the same target used
for the code scan:

```sh
vulnicide code explain --target ../my-app
```

The command reads:

- `build/code/audit-code.json`
- `package.json`
- `.snyk`

It writes:

- `build/code/remediation-packets.json`
- `build/code/remediation-packets.md`

Each packet records:

- the packet ID, such as `C-001-javascript-xss-handlers-users-js-42`
- Snyk Code rule ID, title, level, priority score, and autofix flag
- primary file, line, and column
- the finding message and compact code-flow locations
- a short model prompt for the packet

The packet report also records existing `.snyk` code and global exclusions in
the summary metadata.

Use the packet files as the working queue. For each packet:

1. Ask the model to evaluate one packet at a time using this guide.
2. Require a concrete recommendation before editing:
   - direct code fix
   - validation or sanitization helper
   - refactor into a documented mitigation
   - `.snyk` code exclusion for accepted risk or false positive
3. Apply one small remediation.
4. Re-run `code build` with the same `--target`.
5. Re-run `code explain` and compare the new packet queue.

#### Remediation policy and guidance

Keep durable remediation policy in two places:

- `docs/remediation.md` in this repository for human-facing policy, review
  expectations, and examples.
- `skills/remediate-vuln/references/*.md` in this repository for agent
  execution rules that should steer model-assisted remediation.

Use `.snyk` comments only for packet-specific suppression or mitigation
rationale. Do not use `.snyk` as the source of broad remediation policy.

#### Remediation audit log

Keep the durable human-readable remediation audit trail in the target
repository at:

```text
docs/vulnerability-remediation-log.md
```

Use the CLI to find or open the file:

```sh
vulnicide audit path --target /path/to/project
vulnicide audit open --target /path/to/project
```

`audit path` prints the absolute target-project path without creating files.
`audit open` creates the file from a starter template when it is missing, then
opens it in the default OS application for Markdown files.

Update the audit log after each packet is resolved, suppressed, deferred, or
merged into another remediation. The entry should capture the packet ID, source
report, decision, changed files or policy entries, rationale, verification
commands and outcomes, and any follow-up condition. Generated files under
`build/` are working artifacts; they are not the durable decision record.

#### Agent run modes

Use an explicit run mode when asking an agent to use `$remediate-vuln`.

`reviewed` is the default mode. The agent processes one packet, updates
`docs/vulnerability-remediation-log.md`, reruns verification, reports the
result, and waits for human review before continuing.

`batch` mode is opt-in. The agent processes the packet queue in priority order,
updates the audit log after every packet, and continues until the requested
packet limit is reached or a blocker occurs. Use batch mode only when the owner
is comfortable reviewing a larger changeset after the run.

Example reviewed-mode prompt:

```text
Use $remediate-vuln in reviewed mode for packet C-001.
```

Example batch-mode prompt:

```text
Use $remediate-vuln in batch mode for the next 10 code packets. Stop on suppression, major upgrades, failed verification, or ambiguous risk.
```

Batch runs must stop for ambiguous exploitability or ownership, any
unauthorized suppression or accepted-risk decision, major dependency upgrades,
framework migrations, broad refactors, failed verification, unchanged packets
after a plausible fix, merge conflicts, unexplained lockfile changes, or missing
credentials/access.

When adding policy, distinguish universal guidance from project-specific
guidance. Universal rules belong in this repository. Project-specific rules
belong in the target repository (its `.snyk` comments and its
`docs/vulnerability-remediation-log.md`), not here.

For XSS remediation, preserve raw request and domain values for storage,
comparison, JSON responses, and non-HTML use. Escape untrusted text only when it
is going into an HTML context. If a handler composes trusted HTML, create
separate escaped display variables near that composition point and use those
escaped variables in the HTML string. Do not escape the full HTML string when it
contains trusted markup such as links or formatting tags.

---

## Sample `.snyk` Policy File

```yaml
version: v1.25.0

# File exclusions for supported products
exclude:
  # Global file exclusions (not ordinary dependency-project exclusions)
  global:
    - dist/**

  # Code scan exclusions
  code:
    # Standard code scan exclusions
    - node_modules/**
    - bin/**
    - test/**
    - tests/**
    - tools/**
    # Keep runtime code (for example data-access layers) scanned for
    # individual finding review; exclude only non-runtime content.
    - examples/**
    - assets/**

    # Application-specific code scan exclusions for mitigated issues

    # --------------------------------------------------------------------------------------------
    # id: javascript/HttpToHttps
    # cwe: CWE-319
    # level: warning
    # description:
    #     Cleartext Transmission of Sensitive Information
    # message:
    #     http.createServer uses HTTP which is an insecure protocol and should not be used
    #     in code due to cleartext transmission of information. Data in cleartext in a
    #     communication channel can be sniffed by unauthorized actors. Consider using the
    #     https module instead.
    # see:
    #     <functionName>()
    # reason:
    #     <Project-specific rationale, for example: TLS terminates at a load balancer in
    #     front of this server, so the server itself only listens on an internal network.>
    # --------------------------------------------------------------------------------------------
    - mitigated.js

    # --------------------------------------------------------------------------------------------
    # id: javascript/ServerLeak
    # cwe: CWE-200
    # level: warning
    # description:
    #     Information Exposure
    # message:
    #     An error object flows to send and is leaked to the attacker. This may disclose important
    #     information about the application to an attacker.
    # see:
    #     <functionName>()
    # reason:
    #     Mitigated by returning only generic error messages; the remaining flow sends a
    #     fixed, non-sensitive error code that Snyk cannot recognize as sanitized.
    # --------------------------------------------------------------------------------------------
    # id: javascript/Ssti
    # cwe: CWE-96
    # level: error
    # description:
    #     Improper Neutralization of Directives in Statically Saved Code
    # message:
    #     Unsanitized input from the HTTP request body flows into handlebars.compile,
    #     where it is used to construct a template that gets rendered. This may result in a
    #     Server-Side Template Injection vulnerability.
    # see:
    #     <functionName>()
    # reason:
    #     Mitigated by sanitizing the input before using it in the template.
    # --------------------------------------------------------------------------------------------
    - rest/mitigated.js

# Dependency scan ignores
ignore:
  # Placeholder: replace with a real Snyk ID and a rationale specific to your project.
  'SNYK-JS-EXAMPLE-1234567':
    - '*':
        reason: 'Accepting risk because <why it cannot affect this application> and because <why no compatible fix exists>.'
        expires: 2099-01-01T00:00:00.000Z
```

---

## Notes
- Always document your reasons for ignoring or excluding vulnerabilities.
- Keep your `.snyk` file under version control.
- Review and update your exclusions and ignores regularly as your codebase and dependencies evolve.
