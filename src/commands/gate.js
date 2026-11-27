// `vulnicide deps gate --json`: the scanner side of GateReeve's
// dependency-scan gate contract (schemaVersion 1).
//
// It reads one request on stdin, runs one `snyk test` per target, one at a
// time, and writes one normalized response on stdout. Snyk being unavailable is
// reported per target as data, with exit code 0. Only a request vulnicide can't
// answer at all exits nonzero (2), with nothing on stdout.
//
// It never writes anywhere: no reports, no build directory, nothing in the
// target directories. It never echoes Snyk's own error text, which can carry
// org names, org IDs and host paths. Each `unavailable.detail` is a fixed
// description plus the exit code and any Snyk error code.
import fs from 'fs';
import path from 'path';
import { load as loadYaml } from 'js-yaml';
import { spawnSnyk } from '../utils/snyk.js';
import { indexUpgradeRemediation, collectUpgradeAdvice } from '../utils/upgrade-advice.js';
import { packagePath } from '../utils/paths.js';

export const GATE_SCHEMA_VERSION = 1;
export const TOOL_NAME = 'vulnicide';
export const DEFAULT_GATE_TIMEOUT_SECONDS = 600;
const VERSION_PROBE_TIMEOUT_MS = 60_000;

const SUPPORTED_LOCKFILES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml']);
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

// Exit code for "vulnicide itself failed": no response was written.
const EXIT_FAILED = 2;

export class GateRequestError extends Error {}

export async function runGateCommand(options, io = defaultIo()) {
    if (!options.json) {
        io.stderr('vulnicide deps gate: --json is required (the request is read on stdin as JSON).\n');
        return EXIT_FAILED;
    }
    const timeoutSeconds = Number(options.timeout);
    if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0) {
        io.stderr('vulnicide deps gate: --timeout must be a positive number of seconds.\n');
        return EXIT_FAILED;
    }

    let request;
    try {
        request = parseGateRequest(await io.readStdin());
    } catch (error) {
        if (!(error instanceof GateRequestError)) throw error;
        io.stderr(`vulnicide deps gate: invalid request: ${error.message}\n`);
        return EXIT_FAILED;
    }

    const response = await runGate(request, { timeoutMs: timeoutSeconds * 1000, spawn: io.spawn });
    io.stdout(`${JSON.stringify(response)}\n`);
    return 0;
}

function defaultIo() {
    return {
        readStdin: async () => {
            process.stdin.setEncoding('utf8');
            let input = '';
            for await (const chunk of process.stdin) input += chunk;
            return input;
        },
        stdout: (text) => process.stdout.write(text),
        stderr: (text) => process.stderr.write(text),
        spawn: spawnSnyk
    };
}

// Parse and check the request (design choice 1). Throws GateRequestError for
// a request that can't be answered at all. Only the target keys are needed to
// answer a request with an unknown schemaVersion, so the other fields are
// checked only for schemaVersion 1.
export function parseGateRequest(text) {
    let request;
    try {
        request = JSON.parse(text);
    } catch {
        throw new GateRequestError('stdin is not valid JSON');
    }
    if (!isPlainObject(request)) throw new GateRequestError('the request must be a JSON object');
    if (!Array.isArray(request.targets)) throw new GateRequestError('"targets" must be an array');

    const keys = new Set();
    for (const [index, target] of request.targets.entries()) {
        if (!isPlainObject(target)) throw new GateRequestError(`targets[${index}] must be an object`);
        if (typeof target.key !== 'string' || target.key === '') {
            throw new GateRequestError(`targets[${index}].key must be a non-empty string`);
        }
        if (keys.has(target.key)) throw new GateRequestError(`targets[${index}].key duplicates an earlier key`);
        keys.add(target.key);
    }

    if (request.schemaVersion === GATE_SCHEMA_VERSION) {
        if (typeof request.includeDev !== 'boolean') throw new GateRequestError('"includeDev" must be a boolean');
        // A missing field is neither a string nor null, so it is malformed too:
        // scanning without a policy the caller meant to send would answer the
        // wrong question.
        for (const field of ['policyPath', 'annotatePolicyPath', 'remoteRepoUrl']) {
            const value = request[field];
            if (value !== null && typeof value !== 'string') {
                throw new GateRequestError(`"${field}" must be a string or null`);
            }
        }
    }
    return request;
}

export async function runGate(request, { timeoutMs = DEFAULT_GATE_TIMEOUT_SECONDS * 1000, spawn = spawnSnyk, now = new Date() } = {}) {
    const response = {
        schemaVersion: GATE_SCHEMA_VERSION,
        tool: { name: TOOL_NAME, version: toolVersion() },
        scanner: { name: 'snyk', version: null },
        targets: []
    };
    const unavailableAll = (reason, detail) => {
        response.targets = request.targets.map((target) => unavailableTarget(target.key, reason, detail));
        return response;
    };

    // Design choice 2: an unknown schemaVersion runs no scan.
    if (request.schemaVersion !== GATE_SCHEMA_VERSION) {
        return unavailableAll('unsupported', 'request schemaVersion is not supported; this vulnicide supports schemaVersion 1');
    }

    // Design choice 4: probe the scanner once, before any test.
    const probe = await spawn(['--version'], { timeoutMs: Math.min(timeoutMs, VERSION_PROBE_TIMEOUT_MS) });
    if (probe.spawnError) {
        return unavailableAll('not-installed', 'snyk could not be started; is the Snyk CLI installed and on PATH?');
    }
    response.scanner.version = parseScannerVersion(probe.stdout);

    // Design choice 3: the scan can't run under a policy that isn't there.
    const { policyPath, annotatePolicyPath, remoteRepoUrl } = request;
    for (const [field, value] of [['policyPath', policyPath], ['annotatePolicyPath', annotatePolicyPath]]) {
        if (value !== null && !isAbsoluteFile(value)) {
            return unavailableAll('scanner-error', `${field} is not an absolute path to an existing file`);
        }
    }
    const branchPolicy = annotatePolicyPath !== null ? readPolicy(annotatePolicyPath) : null;

    for (const target of request.targets) {
        response.targets.push(await scanTarget(target, {
            includeDev: request.includeDev,
            policyPath,
            remoteRepoUrl,
            branchPolicy,
            timeoutMs,
            spawn,
            now
        }));
    }
    return response;
}

async function scanTarget(target, options) {
    const invalid = checkTarget(target);
    if (invalid) return unavailableTarget(target.key, invalid.reason, invalid.detail);

    let packageJson;
    try {
        packageJson = JSON.parse(fs.readFileSync(path.join(target.dir, 'package.json'), 'utf-8'));
    } catch {
        return unavailableTarget(target.key, 'scanner-error', 'package.json in the target directory is not valid JSON');
    }

    const args = buildSnykArgs(target.lockfile, options);
    const result = await options.spawn(args, { cwd: target.dir, timeoutMs: options.timeoutMs });
    return interpretSnykResult(target.key, result, { ...options, packageJson });
}

// Design choice 3, per target. Returns null when the target can be scanned.
function checkTarget(target) {
    if (typeof target.dir !== 'string' || !path.isAbsolute(target.dir) || !isDirectory(target.dir)) {
        return { reason: 'scanner-error', detail: 'target dir is not an absolute path to an existing directory' };
    }
    const lockfile = target.lockfile;
    if (typeof lockfile !== 'string' || lockfile === '' || lockfile === '.' || lockfile === '..' ||
        lockfile !== path.basename(lockfile) || lockfile.includes('/') || lockfile.includes('\\')) {
        return { reason: 'scanner-error', detail: 'target lockfile must be a bare file name' };
    }
    if (!SUPPORTED_LOCKFILES.has(lockfile)) {
        return { reason: 'unsupported', detail: 'target lockfile type is not supported; use package-lock.json, npm-shrinkwrap.json, yarn.lock or pnpm-lock.yaml' };
    }
    if (!isFile(path.join(target.dir, 'package.json'))) {
        return { reason: 'scanner-error', detail: 'package.json is missing from the target directory' };
    }
    if (!isFile(path.join(target.dir, lockfile))) {
        return { reason: 'scanner-error', detail: 'the target lockfile is missing from the target directory' };
    }
    return null;
}

// AC1: exactly these arguments, never --debug (which can print credentials),
// --all-projects or --severity-threshold.
export function buildSnykArgs(lockfile, { includeDev, policyPath, remoteRepoUrl }) {
    const args = ['test', '--json'];
    if (includeDev) args.push('--dev');
    args.push(`--file=${lockfile}`);
    if (policyPath !== null && policyPath !== undefined) args.push(`--policy-path=${policyPath}`);
    if (remoteRepoUrl !== null && remoteRepoUrl !== undefined) args.push(`--remote-repo-url=${remoteRepoUrl}`);
    return args;
}

export function interpretSnykResult(key, result, { includeDev, packageJson, branchPolicy, timeoutMs, now }) {
    if (result.spawnError) {
        return unavailableTarget(key, 'not-installed', 'snyk could not be started; is the Snyk CLI installed and on PATH?');
    }
    if (result.timedOut) {
        return unavailableTarget(key, 'network', `snyk test timed out after ${Math.round(timeoutMs / 1000)} s`);
    }

    const parsed = parseJson(result.stdout);
    const tested = result.exitCode === 0 || result.exitCode === 1;

    // Design choice 7: a completed test may have counted against the quota
    // even when its output is unusable.
    if (tested) {
        if (!isPlainObject(parsed) || !Array.isArray(parsed.vulnerabilities)) {
            return {
                ...unavailableTarget(key, 'scanner-error', withCodes(`snyk test output was not a single-project JSON result (exit ${result.exitCode})`, [])),
                testsConsumed: 1
            };
        }
        return {
            key,
            status: 'ok',
            unavailable: null,
            testsConsumed: 1,
            isPrivate: typeof parsed.isPrivate === 'boolean' ? parsed.isPrivate : null,
            findings: normalizeFindings(parsed, { includeDev, packageJson, branchPolicy, now })
        };
    }

    const { reason, description } = classifySnykFailure(result.exitCode, parsed, result.stderr);
    const codes = snykErrorCodes(parsed, result.stderr);
    return unavailableTarget(key, reason, withCodes(`${description} (exit ${result.exitCode ?? 'none'})`, codes));
}

// Design choice 5. Snyk's messages are matched here and then discarded; they
// never reach the response.
export function classifySnykFailure(exitCode, parsed, stderr) {
    // Exit 3 is Snyk's own "no supported project" signal. It wins over text
    // matching, because the message can contain host paths with any word in them.
    if (exitCode === 3) return { reason: 'unsupported', description: 'snyk found no supported project to test' };
    const text = [...errorMessages(parsed), stderr || ''].join('\n');
    if (/test limit|limit of \d+|reached (your|the) (monthly |usage )?limit|usage limit|quota/i.test(text)) {
        return { reason: 'quota-exceeded', description: 'snyk reported that the test limit was reached' };
    }
    if (/authenticat|unauthori[sz]ed|not authori[sz]ed|snyk auth\b|(invalid|missing|expired) (api )?token|\b401\b|SNYK-0005/i.test(text)) {
        return { reason: 'not-authenticated', description: 'snyk reported an authentication error' };
    }
    if (/ENOTFOUND|ECONNREFUSED|ECONNRESET|ETIMEDOUT|EAI_AGAIN|EHOSTUNREACH|ENETUNREACH|socket hang up|getaddrinfo|network|connection (error|refused|reset|timed out)|(could not|unable to|failed to) connect|proxy/i.test(text)) {
        return { reason: 'network', description: 'snyk reported a network error' };
    }
    if (/could not detect supported target|no supported (target|project|files?)|unsupported|not supported/i.test(text)) {
        return { reason: 'unsupported', description: 'snyk found no supported project to test' };
    }
    return { reason: 'scanner-error', description: 'snyk test failed' };
}

function errorMessages(parsed) {
    if (!isPlainObject(parsed)) return [];
    const messages = [];
    for (const field of ['error', 'message']) {
        if (typeof parsed[field] === 'string') messages.push(parsed[field]);
    }
    if (typeof parsed.code === 'number' || typeof parsed.code === 'string') messages.push(String(parsed.code));
    for (const entry of Array.isArray(parsed.errors) ? parsed.errors : []) {
        if (!isPlainObject(entry)) continue;
        for (const field of ['code', 'title', 'detail', 'message']) {
            if (typeof entry[field] === 'string') messages.push(entry[field]);
        }
    }
    return messages;
}

// Snyk error catalog codes (such as SNYK-0005) identify an error class and
// carry no account data, so they are safe to pass through.
function snykErrorCodes(parsed, stderr) {
    const text = [...errorMessages(parsed), stderr || ''].join('\n');
    // Catalog codes look like SNYK-0005 or SNYK-OS-NODEJS-0001: letter
    // segments, then exactly four digits (vulnerability IDs have more).
    return [...new Set(text.match(/\bSNYK-(?:[A-Z]+-)*\d{4}\b/g) || [])].slice(0, 5);
}

function withCodes(detail, codes) {
    return codes.length ? `${detail}; snyk error code ${codes.join(', ')}` : detail;
}

// Design choices 9-11.
export function normalizeFindings(audit, { includeDev, packageJson, branchPolicy, now = new Date() }) {
    const upgradeIndex = indexUpgradeRemediation(audit.remediation?.upgrade || {});
    const devOnly = devOnlyDependencies(packageJson);
    const groups = new Map();

    for (const entry of audit.vulnerabilities) {
        if (!isPlainObject(entry) || entry.type === 'license') continue;
        const vulnId = entry.id;
        const pkg = entry.packageName || entry.name;
        const version = entry.version;
        if (typeof vulnId !== 'string' || typeof pkg !== 'string' || typeof version !== 'string') continue;

        const groupKey = JSON.stringify([vulnId, pkg, version]);
        let group = groups.get(groupKey);
        if (!group) {
            group = { vulnId, pkg, version, entries: [], paths: [], pathKeys: new Set() };
            groups.set(groupKey, group);
        }
        group.entries.push(entry);
        const from = Array.isArray(entry.from) ? entry.from.filter((step) => typeof step === 'string') : [];
        const pathKey = JSON.stringify(from);
        if (from.length && !group.pathKeys.has(pathKey)) {
            group.pathKeys.add(pathKey);
            group.paths.push(from);
        }
    }

    const findings = [...groups.values()].map((group) => {
        const first = group.entries[0];
        return {
            vulnId: group.vulnId,
            package: group.pkg,
            version: group.version,
            severity: first.severity ?? null,
            dev: includeDev && group.paths.length > 0 &&
                group.paths.every((from) => from.length > 1 && devOnly.has(packageNameOf(from[1]))),
            direct: group.paths.some((from) => from.length === 2),
            title: first.title ?? null,
            cvss: typeof first.cvssScore === 'number' ? first.cvssScore : null,
            fixedIn: unique(group.entries.flatMap((entry) => (Array.isArray(entry.fixedIn) ? entry.fixedIn : []))),
            paths: group.paths,
            upgradeAdvice: collectUpgradeAdvice([group.vulnId], upgradeIndex),
            branchIgnore: findBranchIgnore(branchPolicy, group.vulnId, group.paths, now)
        };
    });

    findings.sort((a, b) =>
        (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0) ||
        compare(a.package, b.package) ||
        compare(a.version, b.version) ||
        compare(a.vulnId, b.vulnId)
    );
    return findings;
}

function devOnlyDependencies(packageJson) {
    const dev = new Set(Object.keys(isPlainObject(packageJson?.devDependencies) ? packageJson.devDependencies : {}));
    for (const section of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
        for (const name of Object.keys(isPlainObject(packageJson?.[section]) ? packageJson[section] : {})) {
            dev.delete(name);
        }
    }
    return dev;
}

// "name@version" or "@scope/name@version" -> name.
export function packageNameOf(step) {
    const at = step.lastIndexOf('@');
    return at > 0 ? step.slice(0, at) : step;
}

function readPolicy(policyPath) {
    try {
        const policy = loadYaml(fs.readFileSync(policyPath, 'utf-8'));
        return isPlainObject(policy) ? policy : null;
    } catch {
        // Design choice 11: an unreadable head policy annotates nothing.
        return null;
    }
}

// Design choice 11: the first unexpired ignore rule in the head policy for
// this vulnId whose path matches one of the finding's paths. Display only.
export function findBranchIgnore(policy, vulnId, paths, now = new Date()) {
    const rules = policy?.ignore?.[vulnId];
    if (!Array.isArray(rules)) return null;
    for (const rule of rules) {
        if (!isPlainObject(rule)) continue;
        for (const [rulePath, settings] of Object.entries(rule)) {
            const details = isPlainObject(settings) ? settings : {};
            const expires = normalizeExpires(details.expires);
            // An expiry that isn't a valid date can't be shown to be in the
            // future, so the rule doesn't annotate.
            if (expires.invalid || (expires.time !== null && expires.time <= now.getTime())) continue;
            if (paths.some((from) => policyPathMatches(rulePath, from.slice(1)))) {
                return {
                    reason: typeof details.reason === 'string' ? details.reason : null,
                    expires: expires.value,
                    path: rulePath
                };
            }
        }
    }
    return null;
}

function normalizeExpires(expires) {
    if (expires === undefined || expires === null) return { value: null, time: null, invalid: false };
    const date = expires instanceof Date ? expires : new Date(String(expires));
    if (String(expires).trim() === '' || Number.isNaN(date.getTime())) return { value: null, time: null, invalid: true };
    return { value: date.toISOString(), time: date.getTime(), invalid: false };
}

// A rule path is `*` or ` > `-separated segments, each `*`, a name or
// name@version, matched against a prefix of the dependency path (project
// root removed). A trailing `*` matches whatever follows.
export function policyPathMatches(rulePath, steps) {
    const segments = String(rulePath).split('>').map((segment) => segment.trim()).filter(Boolean);
    if (segments.length === 0) return false;
    if (segments.length === 1 && segments[0] === '*') return true;
    for (const [index, segment] of segments.entries()) {
        if (segment === '*' && index === segments.length - 1) return steps.length >= index;
        const step = steps[index];
        if (step === undefined) return false;
        if (segment === '*') continue;
        if (segment !== step && segment !== packageNameOf(step)) return false;
    }
    return true;
}

function unavailableTarget(key, reason, detail) {
    return {
        key,
        status: 'unavailable',
        unavailable: { reason, detail },
        testsConsumed: 0,
        isPrivate: null,
        findings: []
    };
}

export function parseScannerVersion(output) {
    const match = /\b(\d+\.\d+\.\d+)\b/.exec(output || '');
    return match ? match[1] : null;
}

function toolVersion() {
    try {
        return JSON.parse(fs.readFileSync(packagePath('package.json'), 'utf-8')).version ?? null;
    } catch {
        return null;
    }
}

function parseJson(text) {
    try {
        return JSON.parse(text);
    } catch {
        return undefined;
    }
}

function isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isDirectory(candidate) {
    try {
        return fs.statSync(candidate).isDirectory();
    } catch {
        return false;
    }
}

function isFile(candidate) {
    try {
        return fs.statSync(candidate).isFile();
    } catch {
        return false;
    }
}

function isAbsoluteFile(candidate) {
    return path.isAbsolute(candidate) && isFile(candidate);
}

function unique(values) {
    return [...new Set(values.filter((value) => value !== undefined && value !== null && value !== ''))];
}

function compare(a, b) {
    return a < b ? -1 : a > b ? 1 : 0;
}
