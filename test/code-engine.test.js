// Offline tests for the code-scanning engines (Opengrep by default, Snyk
// Code optional). Stub `opengrep`, `snyk` and `snyk-to-html` binaries
// (test/bin) replay output captured from real runs, so no network, Snyk
// account or real scanner is needed. See test/fixtures/opengrep/README.md.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
    browseCode,
    classifyByCwe,
    classifyCodePacket,
    ruleMetadata,
    CWE_CLASSES,
    OUTCOME_EXIT_CODES
} from '../src/commands/code.js';
import { getCommandContext } from '../src/utils/context.js';
import { OPENGREP_INSTALL_COMMAND } from '../src/utils/opengrep.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');
const cli = path.join(repoRoot, 'src', 'index.js');
const stubBin = path.join(here, 'bin');
const ogFixtures = path.join(here, 'fixtures', 'opengrep');
const snykFixtures = path.join(here, 'fixtures', 'snyk');
const COMMANDS = ['build', 'rebuild'];
const ENGINES = ['opengrep', 'snyk'];
const OUTCOME_FIELDS = ['schemaVersion', 'engine', 'engineVersion', 'outcome', 'reason', 'message', 'severityThreshold', 'counts', 'startedAt', 'finishedAt'];
const CODE_OUTPUTS = ['audit-code.json', 'audit-code.html', 'audit-code-minimal.json'];

// Schema-1 Snyk packets recorded from the unmodified CLI (main at 759c655)
// for the captured Snyk fixtures, before `code explain` changed.
const SNYK_SCHEMA1 = {
    'sample-target': [
        ['C-001-javascript-commandinjection-src-server-js-10', 'javascript/CommandInjection', 'autofix-candidate', 625],
        ['C-002-javascript-xss-src-server-js-11', 'javascript/XSS', 'output-sanitization', 625],
        ['C-003-javascript-httptohttps-src-server-js-6', 'javascript/HttpToHttps', 'autofix-candidate', 375],
        ['C-004-javascript-noratelimitingforexpensiveweboperation-src-se', 'javascript/NoRateLimitingForExpensiveWebOperation', 'autofix-candidate', 375]
    ],
    'python-target': [
        ['C-001-python-commandinjection-app-py-11', 'python/CommandInjection', 'autofix-candidate', 650],
        ['C-002-python-xss-app-py-11', 'python/XSS', 'output-sanitization', 650]
    ]
};
// Amendment A1: CWE-78 Snyk rules move to input-validation; the rest keep
// their schema-1 class.
const SNYK_V2_CLASSES = {
    'javascript/CommandInjection': 'input-validation',
    'javascript/XSS': 'output-sanitization',
    'javascript/HttpToHttps': 'autofix-candidate',
    'javascript/NoRateLimitingForExpensiveWebOperation': 'autofix-candidate',
    'python/CommandInjection': 'input-validation',
    'python/XSS': 'output-sanitization'
};

let work;
let counter = 0;
let binsWithout = {};

before(() => {
    work = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnicide-engine-'));
    // PATH variants missing one engine. `node` is linked in because the
    // stubs start with `#!/usr/bin/env node`.
    for (const missing of ['opengrep', 'snyk']) {
        const dir = path.join(work, `bin-without-${missing}`);
        fs.mkdirSync(dir);
        fs.symlinkSync(process.execPath, path.join(dir, 'node'));
        for (const tool of ['opengrep', 'snyk', 'snyk-to-html']) {
            if (tool !== missing) fs.symlinkSync(path.join(stubBin, tool), path.join(dir, tool));
        }
        binsWithout[missing] = dir;
    }
});

after(() => {
    fs.rmSync(work, { recursive: true, force: true });
});

// A fresh copy of a sample target, with node_modules so nothing complains.
function target(name = 'sample-target') {
    const dir = path.join(work, `${name}-${++counter}`);
    fs.cpSync(path.join(here, 'fixtures', name), dir, { recursive: true });
    return dir;
}

function run(args, { env = {}, pathOverride } = {}) {
    const log = path.join(work, `calls-${++counter}.jsonl`);
    const result = spawnSync(process.execPath, [cli, ...args], {
        encoding: 'utf-8',
        env: {
            ...process.env,
            PATH: pathOverride ?? `${stubBin}${path.delimiter}${process.env.PATH}`,
            VULN_NO_OPEN: '1',
            VULN_STUB_LOG: log,
            FORCE_COLOR: '0',
            NO_COLOR: '1',
            ...env
        }
    });
    const calls = fs.existsSync(log)
        ? fs.readFileSync(log, 'utf-8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line))
        : [];
    return { status: result.status, output: `${result.stdout}${result.stderr}`, calls };
}

function code(command, dir, extra = [], options = {}) {
    return run(['code', command, ...extra, '--target', dir], options);
}

function codeDir(dir) {
    return path.join(dir, 'build', 'code');
}

function readOutcome(dir) {
    return JSON.parse(fs.readFileSync(path.join(codeDir(dir), 'scan-result.json'), 'utf-8'));
}

function scanCalls(calls, tool) {
    return calls.filter((call) => call.tool === tool && call.args[0] !== '--version');
}

function writeJson(file, value) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(value, null, 2));
}

function sarifFixture(name) {
    return JSON.parse(fs.readFileSync(path.join(ogFixtures, name), 'utf-8'));
}

function snykZeroResultSarif() {
    const sarif = JSON.parse(fs.readFileSync(path.join(snykFixtures, 'code-node.sarif.json'), 'utf-8'));
    sarif.runs[0].results = [];
    return JSON.stringify(sarif);
}

// --- AC1 / R1: engine selection ------------------------------------------

for (const command of COMMANDS) {
    test(`R1 ${command}: default engine is Opengrep`, () => {
        const dir = target();
        const result = code(command, dir);
        assert.equal(result.status, 1, result.output);
        assert.equal(scanCalls(result.calls, 'opengrep').length, 1);
        assert.equal(scanCalls(result.calls, 'snyk').length, 0);
        assert.equal(readOutcome(dir).engine, 'opengrep');
    });

    test(`R1 ${command}: codeEngine in .vulnrc.json selects Snyk`, () => {
        const dir = target();
        writeJson(path.join(dir, '.vulnrc.json'), { codeEngine: 'snyk' });
        const result = code(command, dir);
        assert.equal(result.status, 1, result.output);
        assert.equal(scanCalls(result.calls, 'snyk').length, 1);
        assert.equal(scanCalls(result.calls, 'opengrep').length, 0);
        assert.equal(readOutcome(dir).engine, 'snyk');
    });

    test(`R1 ${command}: codeEngine under package.json vuln selects Snyk`, () => {
        const dir = target();
        const pkgPath = path.join(dir, 'package.json');
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        writeJson(pkgPath, { ...pkg, vuln: { codeEngine: 'snyk' } });
        const result = code(command, dir);
        assert.equal(scanCalls(result.calls, 'snyk').length, 1, result.output);
        assert.equal(readOutcome(dir).engine, 'snyk');
    });

    test(`R1 ${command}: --engine overrides codeEngine`, () => {
        const dir = target();
        writeJson(path.join(dir, '.vulnrc.json'), { codeEngine: 'snyk' });
        const result = code(command, dir, ['--engine', 'opengrep']);
        assert.equal(scanCalls(result.calls, 'opengrep').length, 1, result.output);
        assert.equal(scanCalls(result.calls, 'snyk').length, 0);
        assert.equal(readOutcome(dir).engine, 'opengrep');
    });

    for (const via of ['flag', 'config']) {
        test(`R1 ${command}: an unknown engine via ${via} is a usage error that touches nothing`, () => {
            const dir = target();
            fs.mkdirSync(codeDir(dir), { recursive: true });
            fs.writeFileSync(path.join(codeDir(dir), 'audit-code.json'), 'previous audit');
            fs.writeFileSync(path.join(codeDir(dir), 'keep.txt'), 'keep');
            const extra = via === 'flag' ? ['--engine', 'semgrep'] : [];
            if (via === 'config') writeJson(path.join(dir, '.vulnrc.json'), { codeEngine: 'semgrep' });
            const result = code(command, dir, extra);
            assert.equal(result.status, 64, result.output);
            assert.match(result.output, /opengrep/);
            assert.match(result.output, /snyk/);
            assert.deepEqual(result.calls, []);
            assert.ok(!fs.existsSync(path.join(codeDir(dir), 'scan-result.json')));
            assert.equal(fs.readFileSync(path.join(codeDir(dir), 'audit-code.json'), 'utf-8'), 'previous audit');
            assert.equal(fs.readFileSync(path.join(codeDir(dir), 'keep.txt'), 'utf-8'), 'keep');
        });
    }
}

// --- AC2 / R2, R3: invocation and version gate ----------------------------

for (const command of COMMANDS) {
    test(`R2 ${command}: Opengrep gets the fixed flags, default rules, .snyk excludes and metrics off`, () => {
        const dir = target();
        fs.writeFileSync(path.join(dir, '.snyk'), [
            'version: v1.25.0',
            'exclude:',
            '  global:',
            '    - build/**',
            '  code:',
            '    - test/**',
            "    - '**/vendor/**'",
            ''
        ].join('\n'));
        const result = code(command, dir);
        const opengrep = result.calls.filter((call) => call.tool === 'opengrep');
        assert.equal(opengrep.length, 2, result.output);
        assert.deepEqual(opengrep[0].args, ['--version']);
        for (const call of opengrep) assert.equal(call.metrics, 'off');
        const scan = opengrep[1];
        assert.equal(fs.realpathSync(scan.cwd), fs.realpathSync(dir));
        assert.deepEqual(scan.args, [
            'scan', '--sarif', '--dataflow-traces', '--disable-nosem', '--x-ignore-semgrepignore-files',
            '--config', 'p/default',
            '--exclude', 'build/**', '--exclude', 'test/**', '--exclude', '**/vendor/**',
            '.'
        ]);
        assert.ok(!result.calls.some((call) => call.tool === 'snyk' || call.tool === 'snyk-to-html'));
    });

    test(`R2 ${command}: opengrepConfig replaces the default rule sources`, () => {
        const dir = target();
        writeJson(path.join(dir, '.vulnrc.json'), { opengrepConfig: ['p/owasp-top-ten', './security-rules/'] });
        const scan = scanCalls(code(command, dir).calls, 'opengrep')[0];
        const configs = scan.args.flatMap((arg, i) => (scan.args[i - 1] === '--config' ? [arg] : []));
        assert.deepEqual(configs, ['p/owasp-top-ten', './security-rules/']);
    });

    test(`R2 ${command}: Snyk gets code test --json with threshold and policy path`, () => {
        const dir = target();
        const result = code(command, dir, ['--engine', 'snyk']);
        const scan = scanCalls(result.calls, 'snyk')[0];
        assert.deepEqual(scan.args, ['code', 'test', '--json', '--severity-threshold=low', `--policy-path=${path.join(dir, '.snyk')}`]);
        assert.ok(!result.calls.some((call) => call.tool === 'opengrep'));
    });

    test(`R3 ${command}: an Opengrep older than 2.1.0 is unavailable/not-installed without scanning`, () => {
        const dir = target();
        const result = code(command, dir, [], { env: { VULN_STUB_OPENGREP_VERSION: '2.0.0' } });
        assert.equal(result.status, 2, result.output);
        assert.equal(scanCalls(result.calls, 'opengrep').length, 0);
        const outcome = readOutcome(dir);
        assert.equal(outcome.outcome, 'unavailable');
        assert.equal(outcome.reason, 'not-installed');
        assert.equal(outcome.engineVersion, '2.0.0');
        assert.ok(outcome.message.includes(OPENGREP_INSTALL_COMMAND), outcome.message);
    });

    test(`R3 ${command}: a missing Opengrep is unavailable/not-installed with the install command`, () => {
        const dir = target();
        const result = code(command, dir, [], { pathOverride: binsWithout.opengrep });
        assert.equal(result.status, 2, result.output);
        const outcome = readOutcome(dir);
        assert.equal(outcome.reason, 'not-installed');
        assert.equal(outcome.engineVersion, null);
        assert.ok(outcome.message.includes(OPENGREP_INSTALL_COMMAND), outcome.message);
    });

    test(`R3 ${command}: Opengrep 2.1.0 proceeds to scan`, () => {
        const dir = target();
        const result = code(command, dir, [], { env: { VULN_STUB_OPENGREP_VERSION: '2.1.0' } });
        assert.equal(scanCalls(result.calls, 'opengrep').length, 1, result.output);
    });
}

// --- AC3 / R4: outcome file and exit codes ---------------------------------

const OUTCOME_CASES = {
    opengrep: {
        clean: { make: () => target('python-target'), env: { VULN_STUB_OPENGREP_FIXTURE: 'python-clean.sarif.json' }, version: '2.1.0', counts: { total: 0, counted: 0 } },
        findings: { make: () => target(), env: {}, version: '2.1.0', counts: { total: 3, counted: 3 } },
        unavailable: { make: () => target(), pathOverride: () => binsWithout.opengrep, version: null, reason: 'not-installed', counts: null },
        error: { make: () => target(), env: { VULN_STUB_OPENGREP_FIXTURE: 'invalid-rule.sarif.json' }, version: '2.1.0', counts: null }
    },
    snyk: {
        clean: { make: () => target(), env: { VULN_STUB_SNYK_CODE_RAW: snykZeroResultSarif(), VULN_STUB_SNYK_CODE_EXIT: '1' }, version: '1.1305.2', counts: { total: 0, counted: 0 } },
        findings: { make: () => target(), env: {}, version: '1.1305.2', counts: { total: 4, counted: 4 } },
        unavailable: { make: () => target(), pathOverride: () => binsWithout.snyk, version: null, reason: 'not-installed', counts: null },
        error: { make: () => target(), env: { VULN_STUB_SNYK_CODE_FIXTURE: 'code-error-other.json', VULN_STUB_SNYK_CODE_EXIT: '2', VULN_STUB_SNYK_CODE_STREAM: 'stderr' }, version: null, counts: null }
    }
};

for (const command of COMMANDS) {
    for (const engine of ENGINES) {
        for (const [outcomeName, spec] of Object.entries(OUTCOME_CASES[engine])) {
            test(`R4 ${command} ${engine}: ${outcomeName} writes the outcome file and exits ${OUTCOME_EXIT_CODES[outcomeName]}`, () => {
                const dir = spec.make();
                const result = code(command, dir, ['--engine', engine], { env: spec.env || {}, pathOverride: spec.pathOverride?.() });
                assert.equal(result.status, OUTCOME_EXIT_CODES[outcomeName], result.output);
                const outcome = readOutcome(dir);
                assert.deepEqual(Object.keys(outcome).sort(), [...OUTCOME_FIELDS].sort());
                assert.equal(outcome.schemaVersion, 1);
                assert.equal(outcome.engine, engine);
                assert.equal(outcome.engineVersion, spec.version);
                assert.equal(outcome.outcome, outcomeName);
                assert.equal(outcome.reason, spec.reason ?? null);
                assert.equal(typeof outcome.message, 'string');
                assert.ok(outcome.message.length > 0);
                assert.equal(outcome.severityThreshold, 'low');
                assert.deepEqual(outcome.counts, spec.counts);
                const started = Date.parse(outcome.startedAt);
                const finished = Date.parse(outcome.finishedAt);
                assert.ok(Number.isFinite(started) && Number.isFinite(finished) && started <= finished);
            });
        }

        test(`R4 ${command} ${engine}: a build directory symlinked out of the target is refused before scanning`, () => {
            const dir = target();
            const outside = path.join(work, `outside-${++counter}`);
            fs.mkdirSync(outside);
            fs.symlinkSync(outside, path.join(dir, 'linked-out'), 'dir');
            writeJson(path.join(dir, '.vulnrc.json'), { buildDir: 'linked-out' });
            const result = code(command, dir, ['--engine', engine]);
            assert.notEqual(result.status, 0);
            assert.match(result.output, /Refusing path outside the target directory/);
            assert.equal(scanCalls(result.calls, engine).length, 0);
            assert.deepEqual(fs.readdirSync(outside), []);
        });
    }
}

// --- AC3 / R5: no stale or error audits -------------------------------------

function assertNoCodeOutputs(dir) {
    for (const file of CODE_OUTPUTS) {
        assert.ok(!fs.existsSync(path.join(codeDir(dir), file)), `${file} survived a failed run`);
    }
}

const ERROR_ENV = {
    opengrep: { VULN_STUB_OPENGREP_FIXTURE: 'invalid-yaml.sarif.json' },
    snyk: { VULN_STUB_SNYK_CODE_FIXTURE: 'code-error-other.json', VULN_STUB_SNYK_CODE_EXIT: '2', VULN_STUB_SNYK_CODE_STREAM: 'stderr' }
};

for (const command of COMMANDS) {
    for (const engine of ENGINES) {
        test(`R5 ${command} ${engine}: findings then error leaves no code outputs`, () => {
            const dir = target();
            assert.equal(code('build', dir, ['--engine', engine]).status, 1);
            for (const file of CODE_OUTPUTS) assert.ok(fs.existsSync(path.join(codeDir(dir), file)));
            const result = code(command, dir, ['--engine', engine], { env: ERROR_ENV[engine] });
            assert.equal(result.status, 3, result.output);
            assertNoCodeOutputs(dir);
            assert.equal(readOutcome(dir).outcome, 'error');
        });

        test(`R5 ${command} ${engine}: findings then unavailable leaves no code outputs`, () => {
            const dir = target();
            assert.equal(code('build', dir, ['--engine', engine]).status, 1);
            const result = code(command, dir, ['--engine', engine], { pathOverride: binsWithout[engine] });
            assert.equal(result.status, 2, result.output);
            assertNoCodeOutputs(dir);
            assert.equal(readOutcome(dir).outcome, 'unavailable');
        });
    }

    test(`R5 ${command} snyk: Snyk error JSON on stdout is never saved as the audit`, () => {
        const dir = target();
        const result = code(command, dir, ['--engine', 'snyk'], {
            env: { VULN_STUB_SNYK_CODE_FIXTURE: 'code-error-other.json', VULN_STUB_SNYK_CODE_EXIT: '2' }
        });
        assert.equal(result.status, 3, result.output);
        assert.ok(['error', 'unavailable'].includes(readOutcome(dir).outcome));
        assertNoCodeOutputs(dir);
    });

    test(`R5 ${command} snyk: a failing snyk-to-html turns the run into an error without outputs`, () => {
        const dir = target();
        const result = code(command, dir, ['--engine', 'snyk'], { env: { VULN_STUB_SNYK_TO_HTML_FAIL: '1' } });
        assert.equal(result.status, 3, result.output);
        const outcome = readOutcome(dir);
        assert.equal(outcome.outcome, 'error');
        assert.match(outcome.message, /snyk-to-html/);
        assert.equal(outcome.counts, null);
        assertNoCodeOutputs(dir);
    });
}

const MALFORMED_POLICIES = {
    'unparseable YAML': 'version: v1.25.0\nexclude:\n  code: [unterminated\n',
    'exclude.code as a mapping': 'version: v1.25.0\nexclude:\n  code:\n    src: true\n',
    'exclude.global as a scalar': 'version: v1.25.0\nexclude:\n  global: dist/**\n'
};

for (const command of COMMANDS) {
    for (const [name, policy] of Object.entries(MALFORMED_POLICIES)) {
        test(`R2/R4 ${command}: a .snyk with ${name} is an error, never a scan without its exclusions`, () => {
            const dir = target();
            assert.equal(code('build', dir).status, 1);
            fs.writeFileSync(path.join(dir, '.snyk'), policy);
            const result = code(command, dir);
            assert.equal(result.status, 3, result.output);
            assert.equal(result.calls.filter((call) => call.tool === 'opengrep').length, 0, 'no scan without the policy');
            const outcome = readOutcome(dir);
            assert.equal(outcome.outcome, 'error');
            assert.match(outcome.message, /\.snyk/);
            assertNoCodeOutputs(dir);
        });
    }

    test(`R5 ${command}: packets from an earlier run are removed with its audit`, () => {
        const dir = target();
        assert.equal(code('build', dir).status, 1);
        assert.equal(run(['code', 'explain', '--target', dir]).status, 0);
        assert.ok(fs.existsSync(path.join(codeDir(dir), 'remediation-packets.json')));
        assert.equal(code(command, dir, [], { env: ERROR_ENV.opengrep }).status, 3);
        for (const file of ['remediation-packets.json', 'remediation-packets.md']) {
            assert.ok(!fs.existsSync(path.join(codeDir(dir), file)), `${file} survived a failed run`);
        }
    });
}

// --- AC4 / R6: failure classification ---------------------------------------

const FAILURE_ROWS = [
    { engine: 'opengrep', name: 'registry 404', env: { VULN_STUB_OPENGREP_FIXTURE: 'pack-404.sarif.json' }, outcome: 'unavailable', reason: 'rules-unavailable', text: 'returned code 404' },
    { engine: 'opengrep', name: 'registry 500', env: { VULN_STUB_OPENGREP_FIXTURE: 'registry-500.sarif.json' }, outcome: 'unavailable', reason: 'rules-unavailable', text: 'returned code 500' },
    { engine: 'opengrep', name: 'registry unreachable', env: { VULN_STUB_OPENGREP_FIXTURE: 'unreachable.sarif.json' }, outcome: 'unavailable', reason: 'network', text: 'name resolution failed' },
    { engine: 'opengrep', name: 'invalid rule (exit 2)', env: { VULN_STUB_OPENGREP_FIXTURE: 'invalid-rule.sarif.json' }, outcome: 'error', reason: null, text: 'Rule parse error' },
    { engine: 'opengrep', name: 'invalid rules YAML (exit 7)', env: { VULN_STUB_OPENGREP_FIXTURE: 'invalid-yaml.sarif.json' }, outcome: 'error', reason: null, text: 'Invalid YAML' },
    { engine: 'opengrep', name: 'output that is not SARIF', env: { VULN_STUB_OPENGREP_RAW: 'Segmentation fault in rule engine', VULN_STUB_OPENGREP_EXIT: '139' }, outcome: 'error', reason: null, text: 'Segmentation fault in rule engine' },
    { engine: 'opengrep', name: 'missing binary', pathOverride: () => binsWithout.opengrep, outcome: 'unavailable', reason: 'not-installed', text: 'not installed' },
    { engine: 'snyk', name: 'missing binary', pathOverride: () => binsWithout.snyk, outcome: 'unavailable', reason: 'not-installed', text: 'not installed' },
    { engine: 'snyk', name: 'authentication error (real capture)', env: { VULN_STUB_SNYK_CODE_FIXTURE: 'code-error-auth.json', VULN_STUB_SNYK_CODE_EXIT: '2', VULN_STUB_SNYK_CODE_STREAM: 'stderr' }, outcome: 'unavailable', reason: 'not-authenticated', text: 'snyk auth' },
    { engine: 'snyk', name: 'Snyk Code not enabled', env: { VULN_STUB_SNYK_CODE_FIXTURE: 'code-error-not-enabled.json', VULN_STUB_SNYK_CODE_EXIT: '2', VULN_STUB_SNYK_CODE_STREAM: 'stderr' }, outcome: 'unavailable', reason: 'not-entitled', text: 'not enabled' },
    { engine: 'snyk', name: 'other error', env: { VULN_STUB_SNYK_CODE_FIXTURE: 'code-error-other.json', VULN_STUB_SNYK_CODE_EXIT: '2', VULN_STUB_SNYK_CODE_STREAM: 'stderr' }, outcome: 'error', reason: null, text: 'unknown error occurred' }
];

for (const command of COMMANDS) {
    for (const row of FAILURE_ROWS) {
        test(`R6 ${command} ${row.engine}: ${row.name} → ${row.outcome}${row.reason ? `/${row.reason}` : ''}`, () => {
            const dir = target();
            const result = code(command, dir, ['--engine', row.engine], { env: row.env || {}, pathOverride: row.pathOverride?.() });
            assert.equal(result.status, OUTCOME_EXIT_CODES[row.outcome], result.output);
            const outcome = readOutcome(dir);
            assert.equal(outcome.outcome, row.outcome);
            assert.equal(outcome.reason, row.reason);
            assert.notEqual(outcome.outcome, 'clean');
            assert.ok(outcome.message.includes(row.text), `message should keep "${row.text}": ${outcome.message}`);
        });
    }
}

// --- AC5 / R7: severity threshold -------------------------------------------

function thresholdRun(command, fixture, threshold, dirMaker = target) {
    const dir = dirMaker();
    const result = code(command, dir, ['--severity-threshold', threshold], { env: { VULN_STUB_OPENGREP_FIXTURE: fixture } });
    return { dir, result, outcome: readOutcome(dir) };
}

for (const command of COMMANDS) {
    test(`R7 ${command}: low/medium/high count error, warning and note levels`, () => {
        const expected = { low: 3, medium: 2, high: 1 };
        for (const [threshold, counted] of Object.entries(expected)) {
            const { outcome } = thresholdRun(command, 'node.sarif.json', threshold);
            assert.deepEqual(outcome.counts, { total: 3, counted }, threshold);
            assert.equal(outcome.outcome, 'findings');
            assert.equal(outcome.severityThreshold, threshold);
        }
    });

    test(`R7 ${command}: a result's own level overrides its rule's default`, () => {
        // The hardcoded-password result says error; its rule says note.
        assert.equal(thresholdRun(command, 'node-level-override.sarif.json', 'high').outcome.counts.counted, 2);
        assert.equal(thresholdRun(command, 'node-level-override.sarif.json', 'medium').outcome.counts.counted, 3);
    });

    test(`R7 ${command}: an all-note scan is clean at medium and findings at low`, () => {
        const medium = thresholdRun(command, 'node-note-only.sarif.json', 'medium');
        assert.equal(medium.result.status, 0, medium.result.output);
        assert.equal(medium.outcome.outcome, 'clean');
        assert.equal(thresholdRun(command, 'node-note-only.sarif.json', 'low').outcome.outcome, 'findings');
    });

    test(`R7 ${command}: the report lists only counted results and the audit stays unfiltered`, () => {
        const { dir } = thresholdRun(command, 'node.sarif.json', 'high');
        const html = fs.readFileSync(path.join(codeDir(dir), 'audit-code.html'), 'utf-8');
        assert.match(html, /fixture\.js\.command-injection-taint/);
        assert.doesNotMatch(html, /fixture\.js\.reflected-html/);
        assert.doesNotMatch(html, /fixture\.js\.hardcoded-password/);
        const audit = JSON.parse(fs.readFileSync(path.join(codeDir(dir), 'audit-code.json'), 'utf-8'));
        assert.deepEqual(audit, sarifFixture('node.sarif.json'));
    });

    test(`R7 ${command}: Snyk receives the threshold and its result count decides the outcome`, () => {
        const dir = target();
        const forwarded = code(command, dir, ['--engine', 'snyk', '--severity-threshold', 'high']);
        assert.ok(scanCalls(forwarded.calls, 'snyk')[0].args.includes('--severity-threshold=high'));
        const zero = code(command, target(), ['--engine', 'snyk'], { env: { VULN_STUB_SNYK_CODE_RAW: snykZeroResultSarif(), VULN_STUB_SNYK_CODE_EXIT: '1' } });
        assert.equal(zero.status, 0, zero.output);
        const withResults = target();
        const findings = code(command, withResults, ['--engine', 'snyk'], { env: { VULN_STUB_SNYK_CODE_EXIT: '1' } });
        assert.equal(findings.status, 1);
        assert.deepEqual(readOutcome(withResults).counts, { total: 4, counted: 4 });
    });
}

// --- AC6 / R8: reports -------------------------------------------------------

function assertSelfContained(html) {
    assert.doesNotMatch(html, /<link/i);
    assert.doesNotMatch(html, /<(img|iframe|object|embed)\b/i);
    assert.doesNotMatch(html, /\ssrc\s*=/i);
    for (const match of html.matchAll(/\shref\s*=\s*"([^"]*)"/gi)) assert.ok(match[1].startsWith('#'), match[0]);
    assert.doesNotMatch(html, /@import/i);
    assert.doesNotMatch(html, /url\(/i);
    assert.doesNotMatch(html, /<script/i);
}

for (const command of COMMANDS) {
    test(`R8 ${command}: the Opengrep report groups findings by level with rule, location, CWE and flow`, () => {
        const dir = target();
        const result = code(command, dir);
        assert.equal(result.status, 1, result.output);
        assert.ok(!result.calls.some((call) => call.tool === 'snyk-to-html'));
        const html = fs.readFileSync(path.join(codeDir(dir), 'audit-code.html'), 'utf-8');
        const order = ['level-error', 'level-warning', 'level-note'].map((id) => html.indexOf(`id="${id}"`));
        assert.ok(order.every((index) => index > 0), 'every level present');
        assert.ok(order[0] < order[1] && order[1] < order[2], 'error, then warning, then note');
        for (const [rule, location, cwe] of [
            ['fixture.js.command-injection-taint', 'src/server.js:10', 'CWE-78'],
            ['fixture.js.reflected-html', 'src/server.js:11', 'CWE-79'],
            ['fixture.js.hardcoded-password', 'src/server.js:16', 'CWE-798']
        ]) {
            assert.ok(html.includes(rule), rule);
            assert.ok(html.includes(location), location);
            assert.ok(html.includes(cwe), cwe);
        }
        assert.ok(html.includes('Source: &#39;req.url&#39;'), 'data-flow source step');
        assert.ok(html.includes('src/server.js:7'), 'data-flow location');
        assert.match(html, /Opengrep 2\.1\.0/);
        assert.match(html, /Severity threshold: low/);
        assertSelfContained(html);
    });

    test(`R8 ${command}: markup in every rendered field is escaped`, () => {
        const dir = target();
        code(command, dir, [], { env: { VULN_STUB_OPENGREP_FIXTURE: 'node-markup.sarif.json' } });
        const html = fs.readFileSync(path.join(codeDir(dir), 'audit-code.html'), 'utf-8');
        const escaped = '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;';
        for (const field of [
            `fixture.js.command-injection-taint${escaped}`,
            `Message ${escaped}`,
            `src/${escaped}.js:10`,
            `CWE-78: ${escaped}`,
            `src/flow${escaped}.js:7`
        ]) {
            assert.ok(html.includes(field), `escaped field missing: ${field}`);
        }
        assertSelfContained(html);
    });

    test(`R8 ${command}: a clean Opengrep run still writes a report saying so`, () => {
        const dir = target('python-target');
        const result = code(command, dir, [], { env: { VULN_STUB_OPENGREP_FIXTURE: 'python-clean.sarif.json' } });
        assert.equal(result.status, 0, result.output);
        const html = fs.readFileSync(path.join(codeDir(dir), 'audit-code.html'), 'utf-8');
        assert.match(html, /No findings met the severity threshold/);
        assertSelfContained(html);
    });

    test(`R8 ${command}: Snyk reports still come from snyk-to-html`, () => {
        const dir = target();
        const result = code(command, dir, ['--engine', 'snyk']);
        assert.equal(result.calls.filter((call) => call.tool === 'snyk-to-html').length, 1, result.output);
        assert.match(fs.readFileSync(path.join(codeDir(dir), 'audit-code.html'), 'utf-8'), /stub report/);
    });

    for (const engine of ENGINES) {
        test(`R8 ${command} ${engine}: code browse names the report`, () => {
            const dir = target();
            code(command, dir, ['--engine', engine]);
            const report = path.join(codeDir(dir), 'audit-code.html');
            const browse = run(['code', 'browse', '--target', dir]);
            assert.ok(browse.output.includes(`VULN_NO_OPEN is set; not opening file://${report}`), browse.output);
        });
    }
}

for (const command of COMMANDS) test(`R8 ${command}: code browse hands the report URL to the opener`, async () => {
    for (const engine of ENGINES) {
        const dir = target();
        code(command, dir, ['--engine', engine]);
        const opened = [];
        const context = getCommandContext({ opts: () => ({ target: dir }) });
        await browseCode(context, async (url) => { opened.push(url); });
        assert.deepEqual(opened, [`file://${path.join(codeDir(dir), 'audit-code.html')}`]);
    }
});

for (const command of COMMANDS) test(`R8 ${command}: the summary page labels the code report with its engine`, () => {
    for (const [engine, label] of [['opengrep', 'Opengrep'], ['snyk', 'Snyk Code']]) {
        const dir = target();
        code(command, dir, ['--engine', engine]);
        assert.equal(run(['summary', 'build', '--target', dir]).status, 0);
        const html = fs.readFileSync(path.join(dir, 'vuln', 'dist', 'index.html'), 'utf-8');
        assert.ok(html.includes(`audit-code.html (${label})`), `${engine}: ${html}`);
    }
});

// --- AC7 / R9: packets --------------------------------------------------------

function explain(dir) {
    const result = run(['code', 'explain', '--target', dir]);
    assert.equal(result.status, 0, result.output);
    return {
        json: JSON.parse(fs.readFileSync(path.join(codeDir(dir), 'remediation-packets.json'), 'utf-8')),
        markdown: fs.readFileSync(path.join(codeDir(dir), 'remediation-packets.md'), 'utf-8')
    };
}

function packetHeadings(markdown) {
    return [...new Set(markdown.split('\n').filter((line) => /^#{1,2} /.test(line)).map((line) => line.replace(/^## C-\d{3}-.*/, '## <packet>')))];
}

test('R9: Opengrep packets carry engine, CWE, OWASP, confidence and CWE classes', () => {
    const dir = target();
    code('build', dir);
    const { json, markdown } = explain(dir);
    assert.equal(json.schemaVersion, 2);
    assert.equal(json.source.engine, 'opengrep');
    const byRule = Object.fromEntries(json.packets.map((packet) => [packet.rule.id.replace(/^test\.fixtures\.opengrep-rules\./, ''), packet]));
    assert.deepEqual(byRule['fixture.js.command-injection-taint'].rule.cwe, ['CWE-78']);
    assert.deepEqual(byRule['fixture.js.command-injection-taint'].rule.owasp, ['A03:2021 - Injection']);
    assert.equal(byRule['fixture.js.command-injection-taint'].rule.confidence, 'high');
    assert.equal(byRule['fixture.js.command-injection-taint'].classification, 'input-validation');
    assert.equal(byRule['fixture.js.reflected-html'].classification, 'output-sanitization');
    assert.equal(byRule['fixture.js.hardcoded-password'].classification, 'secret-remediation');
    for (const packet of json.packets) {
        assert.match(packet.id, /^C-\d{3}-[a-z0-9-]+$/);
        assert.equal(packet.priority.priorityScore, null);
        assert.equal(packet.priority.isAutofixable, false);
        assert.match(packet.modelPrompt, /Evaluate Opengrep finding/);
    }
    // Ordered by level (error, warning, note), then file and line.
    assert.deepEqual(json.packets.map((packet) => packet.rule.level), ['error', 'warning', 'note']);
    assert.deepEqual(json.packets.map((packet) => packet.id.slice(0, 5)), ['C-001', 'C-002', 'C-003']);
    assert.deepEqual(packetHeadings(markdown), ['# Code Remediation Packets', '## Summary', '## <packet>']);
});

for (const name of ['sample-target', 'python-target']) {
    test(`R9: Snyk packets for ${name} keep schema-1 IDs, order and scores; classes follow amendment A1`, () => {
        const dir = target(name);
        code('build', dir, ['--engine', 'snyk']);
        const { json, markdown } = explain(dir);
        assert.equal(json.schemaVersion, 2);
        assert.equal(json.source.engine, 'snyk');
        assert.deepEqual(json.packets.map((packet) => [packet.id, packet.rule.id, packet.priority.priorityScore]),
            SNYK_SCHEMA1[name].map(([id, rule, , score]) => [id, rule, score]));
        for (const packet of json.packets) {
            assert.equal(packet.classification, SNYK_V2_CLASSES[packet.rule.id], packet.rule.id);
            assert.match(packet.modelPrompt, /Evaluate Snyk Code finding/);
        }
        const injection = json.packets.find((packet) => /CommandInjection/.test(packet.rule.id));
        assert.deepEqual(injection.rule.cwe, ['CWE-78']);
        assert.deepEqual(packetHeadings(markdown), ['# Code Remediation Packets', '## Summary', '## <packet>']);
    });
}

test('R9: every listed CWE maps to its class, from Opengrep tags and Snyk properties', () => {
    for (const { cwes, classification } of CWE_CLASSES) {
        for (const cwe of cwes) {
            const tagRule = { properties: { tags: [`${cwe}: Example weakness`, 'HIGH CONFIDENCE'] } };
            const propertyRule = { properties: { cwe: [cwe] } };
            for (const rule of [tagRule, propertyRule]) {
                assert.deepEqual(ruleMetadata(rule).cwe, [cwe]);
                assert.equal(classifyCodePacket({ ruleId: 'x' }, rule, { file: 'src/a.js' }), classification, cwe);
            }
        }
    }
});

test('R9: classification precedence: test files first, then CWE (first row wins), then rule names', () => {
    const injection = { properties: { tags: ['CWE-78: OS Command Injection'] } };
    assert.equal(classifyCodePacket({ ruleId: 'x' }, injection, { file: 'test/app.test.js' }), 'test-code-triage');
    assert.equal(classifyByCwe(['CWE-89', 'CWE-79']), 'output-sanitization');
    assert.equal(classifyCodePacket({ ruleId: 'x' }, { properties: { tags: ['CWE-79: XSS', 'CWE-89: SQLi'] } }, { file: 'src/a.js' }), 'output-sanitization');
    assert.equal(classifyCodePacket({ ruleId: 'javascript/HardcodedSecret' }, { properties: { tags: ['CWE-1004: other'] } }, { file: 'src/a.js' }), 'secret-remediation');
    assert.equal(classifyCodePacket({ ruleId: 'javascript/Other', properties: { isAutofixable: true } }, {}, { file: 'src/a.js' }), 'autofix-candidate');
    assert.equal(classifyCodePacket({ ruleId: 'javascript/Other' }, {}, { file: 'src/a.js' }), 'manual-code-triage');
});
