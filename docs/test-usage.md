# Snyk test usage and plan limits

This note settles how `vulnicide` scans count against Snyk's Free plan limits. It
matters because a mandatory scan (for example a GateReeve gate) on a repository
with about 20 manifests could exhaust the monthly allowance quickly. Read
2026-11-25. Snyk's pages change, so recheck the links before relying on the
numbers.

## Short answer

| Question | Answer |
| --- | --- |
| Does `snyk test --all-projects` count as one test? | **No.** Each manifest in scope counts as its own Open Source test, so a repo with 20 manifests uses about 20 tests per run. |
| How is Snyk Code counted? | Per repository scanned, so one `snyk code test` of a repo is about 1 Code test. vulnicide's default code engine, Opengrep, runs locally and uses no Snyk tests. |
| Free plan limits | Code is 100 tests. Open Source is **400** on the docs' usage-settings page but **200** on the pricing page. Plan for 200 until your Usage page shows otherwise. |
| Are public repos exempt? | **Yes.** The limits apply to private repositories only. |
| What makes a CLI-scanned project public? | The documented route is `snyk monitor`, then set the project's **Git remote URL** to the public repo in the Snyk Web UI. No CLI flag is documented as marking a test public. |

## 1. Open Source: one test per manifest

Snyk's [What counts as a test?](https://docs.snyk.io/scan-with-snyk/scanning-overview/what-counts-as-a-test)
defines Open Source usage as "the number of manifest files where
vulnerabilities are identified by the application". It also says "each
manifest file in scope will generate a distinct test". It lists "CLI -
triggered by CLI commands" as a test trigger.

`--all-projects` auto-detects every manifest under the working directory
(`snyk test --help`), so one run produces one test per detected manifest, not
one per invocation. The first quoted sentence suggests that only manifests with
findings count, and the second suggests that every in-scope manifest counts.
The page doesn't settle which, so **budget for every manifest**. The page has
no separate rule for `snyk monitor`. Treat it as a CLI-triggered test too.

`vulnicide deps build` runs plain `snyk test` (no `--all-projects`) in the target
directory, which tests one manifest. A multi-manifest repository costs one test
per directory you build.

`vulnicide deps gate --json` (GateReeve's dependency-scan gate) runs one plain
`snyk test --file=<lockfile>` per request target, so it costs one test per
target. GateReeve sends at most two targets (base and head) for each manifest
the branch touched. It sends none when no manifest changed or when it reuses an
earlier result. Each target in the response
reports `testsConsumed`:
- 1 when Snyk completed a test (exit 0 or 1), even if its output was
  unusable;
- 0 when the test never ran, or Snyk refused it (auth, quota, network,
  timeout, unsupported).

It also passes through Snyk's `isPrivate`, which says whether Snyk treated the
project as private. Only private projects count against the plan limits. A quota refusal is reported as
`unavailable: quota-exceeded`, not as an error exit.

## 2. Snyk Code: one test per repository scanned

The same page defines Code usage as "the number of repositories scanned by the
customer". One `vulnicide code build --engine snyk` (`snyk code test`) of a
repository counts as one Code test however many files it contains. A plain
`vulnicide code build` uses Opengrep locally and counts against nothing.

## 3. Free plan limits

- [Usage settings](https://docs.snyk.io/snyk-platform-administration/groups-and-organizations/usage-settings):
  "For the Free plan, the limits are 400 tests for Open Source, 100 tests for
  Code, 300 tests for IaC, and 100 tests for Container." Usage is shown "over
  the current billing period".
- [Plans and pricing](https://snyk.io/plans/) FAQ: "Open Source, 200 tests;
  Code, 100 tests; IaC, 300 tests; Container, 100 tests". Its comparison table
  shows Code as "100 tests / month".
- [What counts as a test?](https://docs.snyk.io/scan-with-snyk/scanning-overview/what-counts-as-a-test):
  "Free Snyk Plan: test limits apply to all products including Snyk Container
  and Snyk IaC."

The two pages disagree on the Open Source number, and both describe a monthly
(billing period) allowance. The organization's **Usage** page in the Snyk Web
UI is authoritative for your account. These limits don't apply to
credit-based or Platform Subscription licenses.

## 4. Public repositories

- [What counts as a test?](https://docs.snyk.io/scan-with-snyk/scanning-overview/what-counts-as-a-test):
  "The applicable test limits apply to private repositories only."
- [Getting started with the Snyk CLI](https://docs.snyk.io/cli-ide-and-ci-cd-integrations/snyk-cli/getting-started-with-the-snyk-cli):
  "Test limits do not apply to public repositories." If a Free-plan user sees
  public-repo tests counted, the fix is "telling Snyk the public URL of the
  repository that is being scanned by the Snyk CLI". You do that by running
  `snyk monitor` and then entering the public URL "under **Git remote URL**" in
  the project's **Settings** in the Web UI.

What the CLI needs for Snyk to treat a repo as public:

1. A project in Snyk for the repo, created by `snyk monitor` (or by importing
   the repo through the GitHub integration).
2. That project's Git remote URL set to the **public** repository URL. Do this
   in the Web UI. `snyk test`/`snyk monitor` also accept
   `--remote-repo-url=<URL>` to "set or override the remote URL for the
   repository" (`snyk test --help`). The docs don't say whether that flag
   alone makes later tests count as public.
3. The repository must actually be public on GitHub. A private repo with a
   public-looking URL is still private.

Observed: the `snyk test --json` output of a local run includes
`"isPrivate": true` when no public remote is known (see
`test/fixtures/snyk/deps-node.json`). After setting up a public remote, check
that field and the Usage page counter.

## 5. What this means for a mandatory GateReeve scan

For a **private** repo with about 20 manifests on the Free plan:

| Scan | Cost per full run | Runs per month at 200 OS / 100 Code | At 400 OS |
| --- | --- | --- | --- |
| `snyk test --all-projects` | about 20 OS tests | about 10 (one every 3 days) | about 20 |
| `snyk code test` | 1 Code test | 100 (about 3 per day) | 100 |

All private repos in the organization share these allowances. A per-PR or
per-commit mandatory Open Source scan of every manifest is not sustainable on
the Free plan. Options:

- Scan only the manifests a change touches (`vulnicide deps build --target <dir>`
  or `snyk test --file=<manifest>`): 1 test each. GateReeve's gate does this
  through `vulnicide deps gate --json`, at 2 tests per touched manifest (base
  and head).
- Run the full `--all-projects` sweep on a schedule (for example weekly) rather
  than per change.
- Make the repo public and register its public remote (section 4): no limits.
- Use a paid plan.

**Verify empirically before committing to a cadence.** Note the Usage page
counters, run one `snyk test --all-projects` on the 20-manifest repo, and
compare. That also settles whether manifests without findings count.
