import { runProcess, stderrSummary } from './process.js';

export const OPENGREP_MIN_VERSION = '2.1.0';
// The tested version, via Opengrep's official installer (`npm run
// setup:opengrep` from a checkout runs the same command).
export const OPENGREP_INSTALL_COMMAND = 'curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/v2.1.0/install.sh | bash -s -- -v v2.1.0';

// Flags every scan uses:
// --sarif                         SARIF on stdout
// --dataflow-traces               data-flow steps (codeFlows) in the SARIF
// --disable-nosem                 inline `nosemgrep` comments never suppress;
//                                 .snyk is the one suppression record
// --x-ignore-semgrepignore-files  no built-in ignore list and no
//                                 .semgrepignore; .snyk (plus .gitignore)
//                                 decides exclusions. [INTERNAL] upstream:
//                                 guarded by the version floor and a test.
const SCAN_FLAGS = ['scan', '--sarif', '--dataflow-traces', '--disable-nosem', '--x-ignore-semgrepignore-files'];

// Opengrep 2.1.0 has no telemetry; this is the switch Semgrep-derived code
// reads, set so a later version can't start sending usage data unnoticed.
function opengrepEnv() {
    return { ...process.env, SEMGREP_SEND_METRICS: 'off' };
}

export function buildOpengrepArgs({ ruleConfigs, excludes }) {
    const args = [...SCAN_FLAGS];
    for (const config of ruleConfigs) args.push('--config', config);
    for (const pattern of excludes) args.push('--exclude', pattern);
    args.push('.');
    return args;
}

export function compareVersions(a, b) {
    const parse = (value) => String(value).split('-')[0].split('.').map((part) => Number.parseInt(part, 10) || 0);
    const [x, y] = [parse(a), parse(b)];
    for (let i = 0; i < Math.max(x.length, y.length); i++) {
        const diff = (x[i] || 0) - (y[i] || 0);
        if (diff !== 0) return Math.sign(diff);
    }
    return 0;
}

function notInstalled(message, engineVersion = null) {
    return {
        engine: 'opengrep',
        engineVersion,
        status: 'unavailable',
        reason: 'not-installed',
        message: `${message} Install Opengrep ${OPENGREP_MIN_VERSION} or later: ${OPENGREP_INSTALL_COMMAND}`,
        sarif: null
    };
}

// Run Opengrep over the target and return a normalized scan result:
// { engine, engineVersion, status: completed|unavailable|error, reason, message, sarif }
export async function runOpengrepScan({ cwd, ruleConfigs, excludes }) {
    const env = opengrepEnv();
    const probe = await runProcess('opengrep', ['--version'], { cwd, env });
    if (probe.notFound) {
        return notInstalled('Opengrep is not installed (no `opengrep` on PATH).');
    }
    const version = (probe.stdout.match(/\d+\.\d+\.\d+[^\s]*/) || [null])[0];
    if (probe.code !== 0 || !version) {
        return {
            engine: 'opengrep',
            engineVersion: null,
            status: 'error',
            reason: null,
            message: `Could not read the Opengrep version: ${stderrSummary(probe.stderr) || probe.stdout.trim() || `exit ${probe.code}`}`,
            sarif: null
        };
    }
    if (compareVersions(version, OPENGREP_MIN_VERSION) < 0) {
        return notInstalled(`Opengrep ${version} is older than the minimum ${OPENGREP_MIN_VERSION}.`, version);
    }

    const result = await runProcess('opengrep', buildOpengrepArgs({ ruleConfigs, excludes }), { cwd, env });
    if (result.notFound) return notInstalled('Opengrep disappeared from PATH during the scan.', version);
    return classifyOpengrepRun(result, version);
}

export function classifyOpengrepRun({ code, stdout, stderr }, engineVersion) {
    const base = { engine: 'opengrep', engineVersion };
    let sarif = null;
    try {
        sarif = JSON.parse(stdout);
    } catch {
        sarif = null;
    }
    const run = Array.isArray(sarif?.runs) ? sarif.runs[0] : null;
    if (!run || !Array.isArray(run.results)) {
        const detail = stderrSummary(stderr) || String(stdout).trim().slice(0, 300) || `exit ${code}`;
        return { ...base, status: 'error', reason: null, message: `Opengrep did not produce SARIF (exit ${code}): ${detail}`, sarif: null };
    }

    const notifications = (run.invocations || [])
        .flatMap((invocation) => invocation.toolExecutionNotifications || [])
        .filter((note) => note.level === 'error')
        .map((note) => note.message?.text || '')
        .filter(Boolean);

    // A rule-download failure still prints valid SARIF with zero results;
    // it must never read as a clean scan.
    const download = notifications.find((text) => /Failed to download config/i.test(text));
    if (download) {
        const httpError = /returned code \d{3}/i.test(download);
        return {
            ...base,
            status: 'unavailable',
            reason: httpError ? 'rules-unavailable' : 'network',
            message: `Opengrep could not fetch its rules: ${download}`,
            sarif: null
        };
    }

    if (code !== 0 && code !== 1) {
        const detail = notifications.join(' | ') || stderrSummary(stderr) || `exit ${code}`;
        return { ...base, status: 'error', reason: null, message: `Opengrep failed (exit ${code}): ${detail}`, sarif: null };
    }
    // Exit 0/1 with error notices (for example a target file that failed to
    // parse) is still a completed scan; keep the notices as warnings.
    const warnings = notifications.length ? ` Warnings: ${notifications.join(' | ')}` : '';
    return { ...base, status: 'completed', reason: null, message: `Opengrep scan completed.${warnings}`, sarif };
}
