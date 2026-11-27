// Offline tests for `vulnicide deps gate --json`, the scanner side of
// GateReeve's dependency-scan gate contract (schemaVersion 1).
//
// The stub `snyk` in test/bin replays the captured test/fixtures/snyk
// deps-node.json, or fails the way Snyk does (VULN_STUB_MODE). Variants of the
// captured fixture (a dev-only path, a license issue, a critical finding) are
// derived here at run time, so no hand-written Snyk JSON is checked in. No
// Snyk account, token, network or test quota is used.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');
const cli = path.join(repoRoot, 'src', 'index.js');
const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf-8'));
const capturedAudit = JSON.parse(fs.readFileSync(path.join(here, 'fixtures', 'snyk', 'deps-node.json'), 'utf-8'));

const FINDING_FIELDS = ['vulnId', 'package', 'version', 'severity', 'dev', 'direct', 'title', 'cvss', 'fixedIn', 'paths', 'upgradeAdvice', 'branchIgnore'];
const TARGET_FIELDS = ['key', 'status', 'unavailable', 'testsConsumed', 'isPrivate', 'findings'];
const PLANTED = ['planted-token-value', 'planted-org-name', '0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0', 'example-org', '/path/to/sample-target'];

let work;
let stubLog;
let emptyBin;
let base;
let head;
let policies;

function makeTarget(name, { packageJson, lockfile = 'package-lock.json' } = {}) {
    const dir = path.join(work, name);
    fs.mkdirSync(dir, { recursive: true });
    const samplePackage = JSON.parse(fs.readFileSync(path.join(here, 'fixtures', 'sample-target', 'package.json'), 'utf-8'));
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(packageJson || samplePackage, null, 2));
    if (lockfile) fs.copyFileSync(path.join(here, 'fixtures', 'sample-target', 'package-lock.json'), path.join(dir, lockfile));
    return dir;
}

function request(targets, overrides = {}) {
    return {
        schemaVersion: 1,
        includeDev: true,
        policyPath: null,
        annotatePolicyPath: null,
        remoteRepoUrl: null,
        targets,
        ...overrides
    };
}

function gate(input, { args = ['--json'], env = {}, pathDirs } = {}) {
    fs.rmSync(stubLog, { force: true });
    const result = spawnSync(process.execPath, [cli, 'deps', 'gate', ...args], {
        input: typeof input === 'string' ? input : JSON.stringify(input),
        encoding: 'utf-8',
        env: {
            ...process.env,
            PATH: pathDirs ?? `${path.join(here, 'bin')}${path.delimiter}${process.env.PATH}`,
            VULN_STUB_LOG: stubLog,
            SNYK_TOKEN: 'planted-token-value',
            VULN_STUB_MODE: '',
            VULN_STUB_DEPS_FIXTURE: '',
            ...env
        }
    });
    return {
        status: result.status,
        stdout: result.stdout,
        stderr: result.stderr,
        json: () => JSON.parse(result.stdout),
        calls: stubCalls()
    };
}

function ok(input, options) {
    const result = gate(input, options);
    assert.equal(result.status, 0, `gate exited ${result.status}:\n${result.stderr}`);
    assert.equal(result.stderr, '', 'a successful gate run writes nothing to stderr');
    assert.ok(result.stdout.endsWith('}\n'), 'one JSON document with a trailing newline');
    return { ...result, response: result.json() };
}

function stubCalls() {
    if (!fs.existsSync(stubLog)) return [];
    return fs.readFileSync(stubLog, 'utf-8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line));
}

function testCalls(calls) {
    return calls.filter((call) => call.args[0] === 'test');
}

function writeVariant(name, mutate) {
    const audit = structuredClone(capturedAudit);
    mutate(audit);
    const file = path.join(work, `${name}.json`);
    fs.writeFileSync(file, JSON.stringify(audit));
    return file;
}

function snapshot(dir) {
    const entries = [];
    const walk = (current) => {
        for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
            const full = path.join(current, entry.name);
            const relative = path.relative(dir, full);
            if (entry.isDirectory()) {
                entries.push(`${relative}/`);
                walk(full);
            } else {
                const stat = fs.statSync(full);
                const hash = crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex');
                entries.push(`${relative} ${stat.size} ${stat.mtimeMs} ${hash}`);
            }
        }
    };
    walk(dir);
    return entries;
}

before(() => {
    work = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnicide-gate-'));
    stubLog = path.join(work, 'snyk-calls.jsonl');
    emptyBin = path.join(work, 'empty-bin');
    fs.mkdirSync(emptyBin);
    base = makeTarget('base');
    head = makeTarget('head');
    policies = path.join(work, 'policies');
    fs.mkdirSync(policies);
    fs.writeFileSync(path.join(policies, 'base.snyk'), 'version: v1.25.0\nignore: {}\npatch: {}\n');
    const future = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();
    fs.writeFileSync(path.join(policies, 'head.snyk'), [
        'version: v1.25.0',
        'ignore:',
        '  SNYK-JS-LODASH-1040724:',
        "    - '*':",
        '        reason: Not reachable from request handlers',
        `        expires: ${future}`,
        '  SNYK-JS-LODASH-15869625:',
        "    - '*':",
        '        reason: Expired ignore',
        '        expires: 2020-01-01T00:00:00.000Z',
        '  SNYK-JS-MINIMIST-559764:',
        "    - 'lodash > *':",
        '        reason: Path does not match',
        '  SNYK-JS-MINIMIST-2429795:',
        "    - 'minimist@1.2.0':",
        '        reason: Only used by a build script',
        '  SNYK-JS-LODASH-15053838:',
        "    - '*':",
        '        reason: Unparseable expiry',
        '        expires: not-a-date',
        'patch: {}',
        ''
    ].join('\n'));
});

after(() => {
    fs.rmSync(work, { recursive: true, force: true });
});

test('R1: runs snyk test once per target, in order, with exactly the requested arguments', () => {
    const basePolicy = path.join(policies, 'base.snyk');
    const headPolicy = path.join(policies, 'head.snyk');
    const { calls } = ok(request([
        { key: 'package.json#base', dir: base, lockfile: 'package-lock.json' },
        { key: 'package.json#head', dir: head, lockfile: 'package-lock.json' }
    ], { policyPath: basePolicy, annotatePolicyPath: headPolicy, remoteRepoUrl: 'https://github.com/example/public-repo' }));

    assert.deepEqual(calls[0].args, ['--version'], 'snyk --version is probed first');
    assert.equal(calls.filter((call) => call.args[0] === '--version').length, 1, 'the version is probed once');
    const tests = testCalls(calls);
    assert.deepEqual(tests.map((call) => fs.realpathSync(call.cwd)), [fs.realpathSync(base), fs.realpathSync(head)]);
    for (const call of tests) {
        assert.deepEqual(call.args, [
            'test', '--json', '--dev', '--file=package-lock.json',
            `--policy-path=${basePolicy}`,
            '--remote-repo-url=https://github.com/example/public-repo'
        ]);
        assert.ok(!call.args.some((arg) => arg.includes('head.snyk')), 'the head policy is never passed to snyk');
    }

    // Every combination of the three optional flags, independently.
    const combos = [];
    for (const includeDev of [false, true]) {
        for (const policyPath of [null, basePolicy]) {
            for (const remoteRepoUrl of [null, 'https://github.com/example/public-repo', '']) {
                const [call] = testCalls(ok(request([{ key: 'k', dir: base, lockfile: 'package-lock.json' }], { includeDev, policyPath, remoteRepoUrl })).calls);
                const expected = ['test', '--json'];
                if (includeDev) expected.push('--dev');
                expected.push('--file=package-lock.json');
                if (policyPath !== null) expected.push(`--policy-path=${policyPath}`);
                if (remoteRepoUrl !== null) expected.push(`--remote-repo-url=${remoteRepoUrl}`);
                assert.deepEqual(call.args, expected, JSON.stringify({ includeDev, policyPath, remoteRepoUrl }));
                combos.push(call);
            }
        }
    }
    for (const call of [...tests, ...combos]) {
        for (const forbidden of ['--debug', '--all-projects', '--severity-threshold']) {
            assert.ok(!call.args.some((arg) => arg.startsWith(forbidden)), `${forbidden} is never passed`);
        }
    }
});

test('R2: the response has the contract shape, in request order, and exits 0', () => {
    const { response } = ok(request([
        { key: 'b', dir: base, lockfile: 'package-lock.json' },
        { key: 'a', dir: head, lockfile: 'package-lock.json' }
    ]));
    assert.deepEqual(Object.keys(response), ['schemaVersion', 'tool', 'scanner', 'targets']);
    assert.equal(response.schemaVersion, 1);
    assert.deepEqual(response.tool, { name: 'vulnicide', version: pkg.version });
    assert.deepEqual(response.scanner, { name: 'snyk', version: '1.1300.0' });
    assert.deepEqual(response.targets.map((target) => target.key), ['b', 'a']);
    for (const target of response.targets) {
        assert.deepEqual(Object.keys(target), TARGET_FIELDS);
        assert.equal(target.status, 'ok');
        assert.equal(target.unavailable, null);
        assert.equal(target.testsConsumed, 1);
        assert.equal(target.isPrivate, true);
    }

    const clean = ok(request([{ key: 'k', dir: base, lockfile: 'package-lock.json' }]), {
        env: { VULN_STUB_DEPS_FIXTURE: writeVariant('clean', (audit) => { audit.vulnerabilities = []; audit.ok = true; }), VULN_STUB_TEST_EXIT: '0' }
    }).response.targets[0];
    assert.equal(clean.status, 'ok');
    assert.equal(clean.testsConsumed, 1);
    assert.deepEqual(clean.findings, []);

    const noVersion = ok(request([{ key: 'k', dir: base, lockfile: 'package-lock.json' }]), { env: { VULN_STUB_NO_VERSION: '1' } }).response;
    assert.equal(noVersion.scanner.version, null, 'an unreadable snyk --version gives a null scanner version');
    assert.equal(noVersion.targets[0].status, 'ok');
});

test('R3: findings from the captured fixture are normalized, grouped and ordered', () => {
    const { response } = ok(request([{ key: 'k', dir: base, lockfile: 'package-lock.json' }]));
    const findings = response.targets[0].findings;
    for (const finding of findings) assert.deepEqual(Object.keys(finding), FINDING_FIELDS);
    assert.deepEqual(findings.map((finding) => [finding.severity, finding.package, finding.vulnId]), [
        ['high', 'lodash', 'SNYK-JS-LODASH-1040724'],
        ['high', 'lodash', 'SNYK-JS-LODASH-15869625'],
        ['medium', 'lodash', 'SNYK-JS-LODASH-1018905'],
        ['medium', 'lodash', 'SNYK-JS-LODASH-15053838'],
        ['medium', 'lodash', 'SNYK-JS-LODASH-15869619'],
        ['medium', 'minimist', 'SNYK-JS-MINIMIST-559764'],
        ['low', 'minimist', 'SNYK-JS-MINIMIST-2429795']
    ]);
    assert.deepEqual(findings[0], {
        vulnId: 'SNYK-JS-LODASH-1040724',
        package: 'lodash',
        version: '4.17.20',
        severity: 'high',
        dev: false,
        direct: true,
        title: 'Code Injection',
        cvss: 7.2,
        fixedIn: ['4.17.21'],
        paths: [['vuln-sample-target@1.0.0', 'lodash@4.17.20']],
        upgradeAdvice: [{
            dependency: 'lodash@4.17.20',
            upgradeTo: 'lodash@4.18.1',
            upgrades: capturedAudit.remediation.upgrade['lodash@4.17.20'].upgrades
        }],
        branchIgnore: null
    });
    assert.equal(findings.find((finding) => finding.package === 'minimist').upgradeAdvice[0].upgradeTo, 'minimist@1.2.6');
});

test('R3: grouping, dev/direct derivation, license exclusion and severity order on derived variants', () => {
    const lodash = capturedAudit.vulnerabilities.find((entry) => entry.id === 'SNYK-JS-LODASH-1040724');
    const minimist = capturedAudit.vulnerabilities.find((entry) => entry.id === 'SNYK-JS-MINIMIST-559764');
    const variant = writeVariant('variant', (audit) => {
        // A second path to the same lodash finding, through a dev-only tool,
        // plus an exact duplicate path: one finding, two distinct paths.
        audit.vulnerabilities.push({ ...lodash, from: ['vuln-sample-target@1.0.0', 'devtool@2.0.0', 'lodash@4.17.20'] });
        audit.vulnerabilities.push({ ...lodash });
        // A finding reachable only through dev-only dependencies.
        audit.vulnerabilities.push({ ...minimist, id: 'SNYK-JS-MINIMIST-0000001', severity: 'critical', from: ['vuln-sample-target@1.0.0', 'devtool@2.0.0', 'minimist@1.2.0'] });
        audit.vulnerabilities.push({ ...minimist, id: 'SNYK-JS-MINIMIST-0000001', severity: 'critical', from: ['vuln-sample-target@1.0.0', '@scope/devkit@1.0.0', 'x@1.0.0', 'minimist@1.2.0'] });
        // A license issue, which the gate ignores.
        audit.vulnerabilities.push({ ...minimist, id: 'snyk:lic:npm:minimist:GPL-3.0', type: 'license', severity: 'high' });
    });
    const packageJson = {
        name: 'vuln-sample-target',
        version: '1.0.0',
        dependencies: { lodash: '4.17.20', minimist: '1.2.0' },
        devDependencies: { devtool: '2.0.0', '@scope/devkit': '1.0.0', lodash: '4.17.20' }
    };
    const dir = makeTarget('variant-target', { packageJson });

    const findings = ok(request([{ key: 'k', dir, lockfile: 'package-lock.json' }]), { env: { VULN_STUB_DEPS_FIXTURE: variant } }).response.targets[0].findings;
    assert.ok(!findings.some((finding) => finding.vulnId.startsWith('snyk:lic:')), 'license issues are excluded');

    const critical = findings[0];
    assert.equal(critical.vulnId, 'SNYK-JS-MINIMIST-0000001', 'critical sorts first');
    assert.equal(critical.dev, true, 'every path starts at a dev-only dependency (including a scoped one)');
    assert.equal(critical.direct, false);
    assert.equal(critical.paths.length, 2);

    const lodashFinding = findings.find((finding) => finding.vulnId === 'SNYK-JS-LODASH-1040724');
    assert.deepEqual(lodashFinding.paths, [
        ['vuln-sample-target@1.0.0', 'lodash@4.17.20'],
        ['vuln-sample-target@1.0.0', 'devtool@2.0.0', 'lodash@4.17.20']
    ], 'one finding per (vulnId, package, version) with distinct paths in first-seen order');
    assert.equal(lodashFinding.direct, true);
    assert.equal(lodashFinding.dev, false, 'lodash is also a production dependency');
    assert.equal(findings.filter((finding) => finding.vulnId === 'SNYK-JS-LODASH-1040724').length, 1);

    const withoutDev = ok(request([{ key: 'k', dir, lockfile: 'package-lock.json' }], { includeDev: false }), { env: { VULN_STUB_DEPS_FIXTURE: variant } }).response.targets[0].findings;
    assert.ok(withoutDev.every((finding) => finding.dev === false), 'dev is false when includeDev is false');
});

test('R4: branchIgnore comes from the head policy only, for unexpired matching ignores', () => {
    const { response, calls } = ok(request([{ key: 'k', dir: base, lockfile: 'package-lock.json' }], {
        policyPath: path.join(policies, 'base.snyk'),
        annotatePolicyPath: path.join(policies, 'head.snyk')
    }));
    const byId = Object.fromEntries(response.targets[0].findings.map((finding) => [finding.vulnId, finding.branchIgnore]));
    assert.equal(byId['SNYK-JS-LODASH-1040724'].reason, 'Not reachable from request handlers');
    assert.equal(byId['SNYK-JS-LODASH-1040724'].path, '*');
    assert.match(byId['SNYK-JS-LODASH-1040724'].expires, /^\d{4}-\d\d-\d\dT/);
    assert.deepEqual(Object.keys(byId['SNYK-JS-LODASH-1040724']), ['reason', 'expires', 'path']);
    assert.equal(byId['SNYK-JS-LODASH-15869625'], null, 'an expired ignore does not annotate');
    assert.equal(byId['SNYK-JS-MINIMIST-559764'], null, 'a non-matching path does not annotate');
    assert.deepEqual(byId['SNYK-JS-MINIMIST-2429795'], { reason: 'Only used by a build script', expires: null, path: 'minimist@1.2.0' });
    assert.equal(byId['SNYK-JS-LODASH-1018905'], null, 'no ignore gives null');
    assert.equal(byId['SNYK-JS-LODASH-15053838'], null, 'an ignore with an invalid expiry does not annotate');
    assert.ok(testCalls(calls).every((call) => !call.args.join(' ').includes('head.snyk')));

    const broken = path.join(policies, 'broken.snyk');
    fs.writeFileSync(broken, 'ignore: [unclosed\n');
    const unparsed = ok(request([{ key: 'k', dir: base, lockfile: 'package-lock.json' }], { annotatePolicyPath: broken })).response;
    assert.ok(unparsed.targets[0].findings.every((finding) => finding.branchIgnore === null), 'an unparseable head policy annotates nothing');
});

test('R5: Snyk unavailability is reported per target as data, exiting 0', () => {
    const one = [{ key: 'k', dir: base, lockfile: 'package-lock.json' }];
    const cases = [
        ['auth', 'not-authenticated', 0, /SNYK-0005/],
        ['quota', 'quota-exceeded', 0],
        ['network', 'network', 0],
        ['no-project', 'unsupported', 0],
        ['error', 'scanner-error', 0],
        ['garbage', 'scanner-error', 1]
    ];
    for (const [mode, reason, testsConsumed, detailPattern] of cases) {
        const target = ok(request(one), { env: { VULN_STUB_MODE: mode } }).response.targets[0];
        assert.equal(target.status, 'unavailable', mode);
        assert.equal(target.unavailable.reason, reason, mode);
        assert.equal(typeof target.unavailable.detail, 'string', mode);
        assert.equal(target.testsConsumed, testsConsumed, `${mode} testsConsumed`);
        assert.equal(target.isPrivate, null, `${mode} isPrivate`);
        assert.deepEqual(target.findings, [], mode);
        if (detailPattern) assert.match(target.unavailable.detail, detailPattern, mode);
    }

    const exit3Text = ok(request(one), { env: { VULN_STUB_MODE: 'no-project-noisy' } }).response.targets[0];
    assert.equal(exit3Text.unavailable.reason, 'unsupported', 'exit 3 wins over words in the message');

    const timedOut = ok(request(one), { args: ['--json', '--timeout', '1'], env: { VULN_STUB_MODE: 'sleep' } }).response.targets[0];
    assert.equal(timedOut.unavailable.reason, 'network');
    assert.match(timedOut.unavailable.detail, /timed out/);
    assert.equal(timedOut.testsConsumed, 0);

    const missing = ok(request([...one, { key: 'k2', dir: head, lockfile: 'package-lock.json' }]), { pathDirs: emptyBin });
    assert.equal(missing.response.scanner.version, null);
    assert.deepEqual(missing.response.targets.map((target) => target.unavailable?.reason), ['not-installed', 'not-installed']);
    assert.equal(missing.calls.length, 0, 'no test is attempted without snyk');
});

test('R6: request validation', () => {
    const valid = [{ key: 'good', dir: base, lockfile: 'package-lock.json' }];

    const unknown = ok({ schemaVersion: 2, targets: [{ key: 'x' }, { key: 'y' }] });
    assert.equal(unknown.response.schemaVersion, 1);
    assert.deepEqual(unknown.response.targets.map((target) => [target.key, target.status, target.unavailable.reason]), [
        ['x', 'unavailable', 'unsupported'], ['y', 'unavailable', 'unsupported']
    ]);
    assert.equal(testCalls(unknown.calls).length, 0, 'no scan for an unknown schemaVersion');

    const noLock = makeTarget('no-lock', { lockfile: null });
    const yarn = makeTarget('yarn', { lockfile: 'yarn.lock' });
    const mixed = ok(request([
        { key: 'relative', dir: 'relative/dir', lockfile: 'package-lock.json' },
        { key: 'absent', dir: path.join(work, 'does-not-exist'), lockfile: 'package-lock.json' },
        { key: 'no-lockfile', dir: noLock, lockfile: 'package-lock.json' },
        { key: 'nested-lockfile', dir: base, lockfile: '../base/package-lock.json' },
        { key: 'gemfile', dir: base, lockfile: 'Gemfile.lock' },
        { key: 'yarn', dir: yarn, lockfile: 'yarn.lock' },
        ...valid
    ])).response;
    assert.deepEqual(mixed.targets.map((target) => [target.key, target.status, target.unavailable?.reason ?? null]), [
        ['relative', 'unavailable', 'scanner-error'],
        ['absent', 'unavailable', 'scanner-error'],
        ['no-lockfile', 'unavailable', 'scanner-error'],
        ['nested-lockfile', 'unavailable', 'scanner-error'],
        ['gemfile', 'unavailable', 'unsupported'],
        ['yarn', 'ok', null],
        ['good', 'ok', null]
    ]);
    for (const target of mixed.targets.filter((entry) => entry.status === 'unavailable')) {
        assert.ok(!target.unavailable.detail.includes(work), 'details do not echo host paths');
    }

    const missingPolicy = ok(request(valid, { policyPath: path.join(work, 'missing.snyk') }));
    assert.deepEqual(missingPolicy.response.targets.map((target) => target.unavailable?.reason), ['scanner-error']);
    assert.equal(testCalls(missingPolicy.calls).length, 0);
    const relativePolicy = ok(request(valid, { annotatePolicyPath: 'head.snyk' }));
    assert.equal(relativePolicy.response.targets[0].unavailable.reason, 'scanner-error');

    const malformed = [
        'not json',
        '[]',
        JSON.stringify({ schemaVersion: 1, includeDev: true }),
        JSON.stringify(request([{ key: 'a', dir: base, lockfile: 'package-lock.json' }, { key: 'a', dir: head, lockfile: 'package-lock.json' }])),
        JSON.stringify(request([{ key: '', dir: base, lockfile: 'package-lock.json' }])),
        JSON.stringify(request(['not-an-object'])),
        JSON.stringify(request(valid, { includeDev: 'yes' })),
        JSON.stringify(request(valid, { policyPath: 7 })),
        ...['policyPath', 'annotatePolicyPath', 'remoteRepoUrl', 'includeDev'].map((field) => {
            const missing = request(valid);
            delete missing[field];
            return JSON.stringify(missing);
        })
    ];
    for (const input of malformed) {
        const result = gate(input);
        assert.equal(result.status, 2, `malformed request ${input} exits 2`);
        assert.equal(result.stdout, '', `malformed request ${input} writes nothing to stdout`);
        assert.match(result.stderr, /invalid request/);
        assert.equal(result.calls.length, 0);
    }

    const withoutJson = gate(request(valid), { args: [] });
    assert.equal(withoutJson.status, 2);
    assert.equal(withoutJson.stdout, '');
    assert.match(withoutJson.stderr, /--json is required/);
});

test('R7: the gate writes nothing into targets and needs no node_modules', () => {
    const dirs = [base, head];
    for (const dir of dirs) assert.ok(!fs.existsSync(path.join(dir, 'node_modules')));
    const before = dirs.map(snapshot);
    const policyBefore = snapshot(policies);
    ok(request(dirs.map((dir, index) => ({ key: `k${index}`, dir, lockfile: 'package-lock.json' })), {
        policyPath: path.join(policies, 'base.snyk'),
        annotatePolicyPath: path.join(policies, 'head.snyk')
    }));
    ok(request([{ key: 'k', dir: base, lockfile: 'package-lock.json' }]), { env: { VULN_STUB_MODE: 'auth' } });
    assert.deepEqual(dirs.map(snapshot), before);
    assert.deepEqual(snapshot(policies), policyBefore);
});

test('R8: no token, org name, org ID or raw Snyk text reaches stdout or stderr', () => {
    const one = [{ key: 'k', dir: base, lockfile: 'package-lock.json' }];
    for (const mode of ['leak', 'auth', 'quota', 'network', 'no-project', 'error', 'garbage', '']) {
        const result = gate(request(one), { env: { VULN_STUB_MODE: mode } });
        assert.equal(result.status, 0, mode);
        for (const secret of PLANTED) {
            assert.ok(!result.stdout.includes(secret), `${mode}: stdout leaks ${secret}`);
            assert.ok(!result.stderr.includes(secret), `${mode}: stderr leaks ${secret}`);
        }
        for (const raw of ['Authentication failed', 'monthly limit', 'getaddrinfo', 'Could not detect', 'Unexpected failure', 'not json from']) {
            assert.ok(!result.stdout.includes(raw), `${mode}: raw Snyk text "${raw}" in stdout`);
        }
        const response = result.json();
        assert.ok(!('org' in response) && !('path' in response));
        assert.ok(response.targets.every((target) => !('org' in target) && !('path' in target)));
    }
});
