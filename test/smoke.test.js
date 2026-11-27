// Offline smoke test for the vulnicide CLI.
//
// Copies the sample targets into a temp directory and runs the real CLI
// against them. Stub `snyk` and `snyk-to-html` binaries (test/bin) come first
// on PATH and replay captured Snyk output, so no Snyk account, token or
// test quota is used.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..');
const cli = path.join(repoRoot, 'src', 'index.js');
const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf-8'));

let work;
let nodeTarget;
let pythonTarget;
let stubLog;

function vuln(...args) {
    return vulnExpect(0, ...args);
}

// `code build`/`rebuild` exit 1 when the scan finds issues (2.0.0 outcome codes).
function vulnExpect(expectedStatus, ...args) {
    const result = spawnSync(process.execPath, [cli, ...args], {
        encoding: 'utf-8',
        env: {
            ...process.env,
            PATH: `${path.join(here, 'bin')}${path.delimiter}${process.env.PATH}`,
            VULN_NO_OPEN: '1',
            VULN_STUB_LOG: stubLog,
            FORCE_COLOR: '0',
            NO_COLOR: '1'
        }
    });
    const output = `${result.stdout}${result.stderr}`;
    assert.equal(result.status, expectedStatus, `vulnicide ${args.join(' ')} exited ${result.status}:\n${output}`);
    return output;
}

function readJson(...parts) {
    return JSON.parse(fs.readFileSync(path.join(...parts), 'utf-8'));
}

function stubCalls() {
    if (!fs.existsSync(stubLog)) return [];
    return fs.readFileSync(stubLog, 'utf-8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line));
}

before(() => {
    work = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnicide-smoke-'));
    nodeTarget = path.join(work, 'sample-target');
    pythonTarget = path.join(work, 'python-target');
    stubLog = path.join(work, 'snyk-calls.jsonl');
    fs.cpSync(path.join(here, 'fixtures', 'sample-target'), nodeTarget, { recursive: true });
    fs.cpSync(path.join(here, 'fixtures', 'python-target'), pythonTarget, { recursive: true });
    // deps build refuses a Node target without node_modules.
    fs.mkdirSync(path.join(nodeTarget, 'node_modules'));
});

after(() => {
    fs.rmSync(work, { recursive: true, force: true });
});

test('--version reports the package version', () => {
    assert.equal(vuln('--version').trim(), pkg.version);
});

test('help -r lists every command group', () => {
    const output = vuln('help', '-r');
    for (const name of ['deps', 'code', 'policy', 'audit', 'summary', 'explain', 'init']) {
        assert.match(output, new RegExp(`\\b${name}\\b`), `help tree is missing ${name}`);
    }
});

test('policy init writes a generic .snyk from the template', () => {
    const output = vuln('policy', 'init', '--target', nodeTarget);
    assert.match(output, /Created \.snyk policy file/);
    const policy = fs.readFileSync(path.join(nodeTarget, '.snyk'), 'utf-8');
    assert.match(policy, /^version: v1\./m);
    assert.match(policy, /- node_modules\/\*\*/);

    // A second run without --force must not overwrite.
    fs.appendFileSync(path.join(nodeTarget, '.snyk'), '# local edit\n');
    assert.match(vuln('policy', 'init', '--target', nodeTarget), /already exists/);
    assert.match(fs.readFileSync(path.join(nodeTarget, '.snyk'), 'utf-8'), /# local edit/);
});

test('deps build writes JSON, HTML and minimal reports', () => {
    const output = vuln('deps', 'build', '--target', nodeTarget);
    assert.match(output, /Issues above severity threshold "low" were found/);

    const dir = path.join(nodeTarget, 'build', 'dependencies');
    for (const file of ['audit-dependencies.json', 'audit-dependencies.html', 'audit-dependencies-minimal.json']) {
        assert.ok(fs.existsSync(path.join(dir, file)), `missing ${file}`);
    }
    assert.equal(readJson(dir, 'audit-dependencies-minimal.json').vulnerabilities, 7);

    const call = stubCalls().find((entry) => entry.args[0] === 'test');
    assert.ok(call, 'snyk test was not invoked');
    assert.equal(fs.realpathSync(call.cwd), fs.realpathSync(nodeTarget));
    assert.ok(call.args.includes('--json'));
    assert.ok(call.args.includes(`--policy-path=${path.join(nodeTarget, '.snyk')}`));
    assert.ok(call.args.includes('--severity-threshold=low'));
});

test('deps explain builds prioritized dependency packets', () => {
    vuln('deps', 'explain', '--target', nodeTarget);
    const dir = path.join(nodeTarget, 'build', 'dependencies');
    const report = readJson(dir, 'remediation-packets.json');

    assert.equal(report.schemaVersion, 1);
    assert.deepEqual(report.packets.map((packet) => packet.package.name).sort(), ['lodash', 'minimist']);
    for (const packet of report.packets) {
        assert.match(packet.id, /^D-\d{3}-/);
        assert.equal(packet.classification, 'direct-upgrade-candidate');
        assert.ok(packet.package.directDependency, `${packet.package.name} should be direct`);
        assert.ok(packet.modelPrompt.includes(path.join(repoRoot, 'docs', 'remediation.md')));
    }
    // Highest severity first: lodash (high) before minimist (medium).
    assert.deepEqual(report.packets.map((packet) => packet.priority.highestSeverity), ['high', 'medium']);
    assert.match(fs.readFileSync(path.join(dir, 'remediation-packets.md'), 'utf-8'), /# Dependency Remediation Packets/);
});

test('code build and explain work for a Node target with Snyk Code', () => {
    vulnExpect(1, 'code', 'build', '--engine', 'snyk', '--target', nodeTarget);
    const dir = path.join(nodeTarget, 'build', 'code');
    assert.ok(fs.existsSync(path.join(dir, 'audit-code.html')));

    const call = stubCalls().find((entry) => entry.args[0] === 'code' && fs.realpathSync(entry.cwd) === fs.realpathSync(nodeTarget));
    assert.ok(call, 'snyk code test was not invoked for the Node target');
    assert.ok(call.args.includes(`--policy-path=${path.join(nodeTarget, '.snyk')}`));

    vuln('code', 'explain', '--target', nodeTarget);
    const report = readJson(dir, 'remediation-packets.json');
    const rules = report.packets.map((packet) => packet.rule.id);
    assert.ok(rules.includes('javascript/CommandInjection'));
    for (const packet of report.packets) {
        assert.match(packet.id, /^C-\d{3}-/);
        assert.equal(packet.finding.primaryLocation.file, 'src/server.js');
    }
    // Errors sort before warnings.
    assert.equal(report.packets[0].rule.level, 'error');
});

test('code build and explain work for a non-Node target with Snyk Code', () => {
    const output = vulnExpect(1, 'code', 'build', '--engine', 'snyk', '--target', pythonTarget);
    assert.doesNotMatch(output, /No Node\.js project/);
    vuln('code', 'explain', '--target', pythonTarget);
    const report = readJson(pythonTarget, 'build', 'code', 'remediation-packets.json');
    assert.deepEqual(report.packets.map((packet) => packet.rule.id).sort(), ['python/CommandInjection', 'python/XSS']);
    assert.equal(report.packets[0].finding.primaryLocation.file, 'app.py');
});

test('audit open creates the remediation log from the template', () => {
    const logPath = path.join(nodeTarget, 'docs', 'vulnerability-remediation-log.md');
    assert.equal(vuln('audit', 'path', '--target', nodeTarget).trim(), logPath);
    assert.ok(!fs.existsSync(logPath), 'audit path must not create the log');

    const output = vuln('audit', 'open', '--target', nodeTarget);
    assert.match(output, /Created /);
    assert.match(output, /VULN_NO_OPEN is set/);
    const template = fs.readFileSync(path.join(repoRoot, 'assets', 'vulnerability-remediation-log-template.md'), 'utf-8');
    assert.equal(fs.readFileSync(logPath, 'utf-8'), template);

    // An existing log is left alone.
    fs.appendFileSync(logPath, '\nlocal entry\n');
    assert.doesNotMatch(vuln('audit', 'open', '--target', nodeTarget), /Created /);
    assert.match(fs.readFileSync(logPath, 'utf-8'), /local entry/);
});

test('policy print shows the target policy', () => {
    assert.match(vuln('policy', 'print', '--target', nodeTarget), /^version: v1\./m);
});

test('summary build links the HTML reports and escapes project metadata', () => {
    fs.writeFileSync(path.join(nodeTarget, '.vulnrc.json'), JSON.stringify({
        projectName: '<script>alert(1)</script>',
        projectId: '../escape'
    }));
    try {
        vuln('summary', 'build', '--target', nodeTarget);
        const dist = path.join(nodeTarget, 'vuln', 'dist');
        const html = fs.readFileSync(path.join(dist, 'index.html'), 'utf-8');
        assert.doesNotMatch(html, /<script>/);
        assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
        assert.match(html, /audit-dependencies\.html/);
        assert.match(html, /audit-code\.html/);
        assert.ok(fs.existsSync(path.join(dist, 'index.css')));
        // projectId is reduced to one safe filename segment inside dist.
        assert.ok(fs.readdirSync(dist).some((file) => file.startsWith('..-escape-')));
        assert.ok(!fs.existsSync(path.join(nodeTarget, 'vuln', 'escape-audit-code.html')));

        vuln('summary', 'clean', '--target', nodeTarget);
        assert.ok(!fs.existsSync(dist));
    } finally {
        fs.rmSync(path.join(nodeTarget, '.vulnrc.json'), { force: true });
    }
});

test('clean refuses a configured build directory outside the target', () => {
    const outside = path.join(work, 'outside-build');
    fs.mkdirSync(path.join(outside, 'dependencies'), { recursive: true });
    fs.writeFileSync(path.join(nodeTarget, '.vulnrc.json'), JSON.stringify({ buildDir: '../outside-build' }));
    try {
        const result = spawnSync(process.execPath, [cli, 'deps', 'clean', '--target', nodeTarget], {
            encoding: 'utf-8',
            env: { ...process.env, VULN_NO_OPEN: '1', NO_COLOR: '1' }
        });
        assert.notEqual(result.status, 0);
        assert.match(`${result.stdout}${result.stderr}`, /Refusing path outside the target directory/);
        assert.ok(fs.existsSync(path.join(outside, 'dependencies')), 'outside directory must survive');
    } finally {
        fs.rmSync(path.join(nodeTarget, '.vulnrc.json'), { force: true });
    }
});

test('deps clean and code clean remove only their report directories', () => {
    vuln('deps', 'clean', '--target', nodeTarget);
    assert.ok(!fs.existsSync(path.join(nodeTarget, 'build', 'dependencies')));
    assert.ok(fs.existsSync(path.join(nodeTarget, 'build', 'code')));
    vuln('code', 'clean', '--target', nodeTarget);
    assert.ok(!fs.existsSync(path.join(nodeTarget, 'build', 'code')));
    assert.ok(fs.existsSync(path.join(nodeTarget, 'src', 'server.js')));
});

test('setup:skills installs the bundled skill into CODEX_HOME and AGENTS_HOME', () => {
    const codexHome = path.join(work, 'codex-home');
    const agentsHome = path.join(work, 'agents-home');
    const stale = path.join(codexHome, 'skills', 'remediate-vuln');
    fs.mkdirSync(stale, { recursive: true });
    fs.writeFileSync(path.join(stale, 'stale.md'), 'old');
    fs.mkdirSync(path.join(codexHome, 'skills', 'other-skill'), { recursive: true });

    const result = spawnSync(process.execPath, [path.join(repoRoot, 'scripts', 'install-skills.js')], {
        encoding: 'utf-8',
        env: { ...process.env, CODEX_HOME: codexHome, AGENTS_HOME: agentsHome }
    });
    assert.equal(result.status, 0, result.stderr);
    const source = fs.readFileSync(path.join(repoRoot, 'skills', 'remediate-vuln', 'SKILL.md'), 'utf-8');
    for (const home of [codexHome, agentsHome]) {
        assert.equal(fs.readFileSync(path.join(home, 'skills', 'remediate-vuln', 'SKILL.md'), 'utf-8'), source);
    }
    assert.ok(!fs.existsSync(path.join(stale, 'stale.md')), 'installer replaces the old skill copy');
    assert.ok(fs.existsSync(path.join(codexHome, 'skills', 'other-skill')), 'other skills are untouched');
    assert.match(source, /TrentBrown\/vulnicide/);
});

test('clean refuses a build directory that is a symlink out of the target', () => {
    const outside = path.join(work, 'outside-symlink-build');
    fs.mkdirSync(path.join(outside, 'dependencies'), { recursive: true });
    fs.writeFileSync(path.join(outside, 'dependencies', 'keep.txt'), 'keep');
    fs.symlinkSync(outside, path.join(nodeTarget, 'linked-build'), 'dir');
    fs.writeFileSync(path.join(nodeTarget, '.vulnrc.json'), JSON.stringify({ buildDir: 'linked-build' }));
    try {
        const result = spawnSync(process.execPath, [cli, 'deps', 'clean', '--target', nodeTarget], {
            encoding: 'utf-8',
            env: { ...process.env, VULN_NO_OPEN: '1', NO_COLOR: '1' }
        });
        assert.notEqual(result.status, 0);
        assert.match(`${result.stdout}${result.stderr}`, /Refusing path outside the target directory/);
        assert.ok(fs.existsSync(path.join(outside, 'dependencies', 'keep.txt')), 'symlink target must survive');
    } finally {
        fs.rmSync(path.join(nodeTarget, '.vulnrc.json'), { force: true });
        fs.rmSync(path.join(nodeTarget, 'linked-build'), { force: true });
    }
});

test('a build directory whose name merely starts with ".." stays allowed', () => {
    fs.writeFileSync(path.join(nodeTarget, '.vulnrc.json'), JSON.stringify({ buildDir: '..build' }));
    try {
        vulnExpect(1, 'code', 'build', '--target', nodeTarget);
        assert.ok(fs.existsSync(path.join(nodeTarget, '..build', 'code', 'audit-code.json')));
        vuln('code', 'clean', '--target', nodeTarget);
        assert.ok(!fs.existsSync(path.join(nodeTarget, '..build', 'code')));
    } finally {
        fs.rmSync(path.join(nodeTarget, '.vulnrc.json'), { force: true });
        fs.rmSync(path.join(nodeTarget, '..build'), { recursive: true, force: true });
    }
});

test('rebuild, browse and policy open run without launching anything', () => {
    assert.match(vuln('deps', 'rebuild', '--target', nodeTarget), /Cleaned dependencies audit report[\s\S]*\.\.\.done/);
    assert.match(vulnExpect(1, 'code', 'rebuild', '--target', nodeTarget), /Cleaned code audit report[\s\S]*\.\.\.done/);
    assert.match(vuln('summary', 'rebuild', '--target', nodeTarget), /Cleaned summary report[\s\S]*Built summary report/);

    const reports = {
        deps: path.join(nodeTarget, 'build', 'dependencies', 'audit-dependencies.html'),
        code: path.join(nodeTarget, 'build', 'code', 'audit-code.html'),
        summary: path.join(nodeTarget, 'vuln', 'dist', 'index.html')
    };
    for (const [command, report] of Object.entries(reports)) {
        const output = vuln(command, 'browse', '--target', nodeTarget);
        assert.ok(output.includes(`VULN_NO_OPEN is set; not opening file://${report}`), `${command} browse: ${output}`);
    }
    assert.match(vuln('policy', 'open', '--target', nodeTarget), /VULN_NO_OPEN is set; not opening .*\.snyk/);

    // browse before build explains instead of failing.
    assert.match(vuln('deps', 'browse', '--target', pythonTarget), /No dependencies audit page found/);
});

test('read paths may follow a symlinked .snyk outside the target', () => {
    const shared = path.join(work, 'shared.snyk');
    fs.writeFileSync(shared, 'version: v1.25.0\n# shared policy\n');
    const linked = path.join(pythonTarget, '.snyk');
    fs.symlinkSync(shared, linked);
    try {
        assert.match(vuln('policy', 'print', '--target', pythonTarget), /# shared policy/);
        assert.match(vuln('policy', 'init', '--target', pythonTarget), /already exists/);
        assert.equal(fs.readFileSync(shared, 'utf-8'), 'version: v1.25.0\n# shared policy\n');
    } finally {
        fs.rmSync(linked, { force: true });
    }
});

test('build refuses to write through a build directory symlinked out of the target', () => {
    const outside = path.join(work, 'outside-write-build');
    fs.mkdirSync(outside, { recursive: true });
    fs.symlinkSync(outside, path.join(nodeTarget, 'linked-out'), 'dir');
    fs.writeFileSync(path.join(nodeTarget, '.vulnrc.json'), JSON.stringify({ buildDir: 'linked-out', vulnDir: 'linked-out' }));
    try {
        for (const args of [['deps', 'build'], ['code', 'build'], ['summary', 'build']]) {
            const result = spawnSync(process.execPath, [cli, ...args, '--target', nodeTarget], {
                encoding: 'utf-8',
                env: {
                    ...process.env,
                    PATH: `${path.join(here, 'bin')}${path.delimiter}${process.env.PATH}`,
                    VULN_NO_OPEN: '1',
                    NO_COLOR: '1'
                }
            });
            assert.notEqual(result.status, 0, `${args.join(' ')} should refuse`);
            assert.match(`${result.stdout}${result.stderr}`, /Refusing path outside the target directory/);
        }
        assert.deepEqual(fs.readdirSync(outside), [], 'nothing may be written outside the target');
    } finally {
        fs.rmSync(path.join(nodeTarget, '.vulnrc.json'), { force: true });
        fs.rmSync(path.join(nodeTarget, 'linked-out'), { force: true });
    }
});

test('policy init and audit open refuse a dangling symlink pointing outside the target', () => {
    const target = path.join(work, 'dangling-target');
    fs.mkdirSync(path.join(target, 'docs'), { recursive: true });
    const outsidePolicy = path.join(work, 'dangling-outside', '.snyk');
    const outsideLog = path.join(work, 'dangling-outside', 'log.md');
    fs.symlinkSync(outsidePolicy, path.join(target, '.snyk'));
    fs.symlinkSync(outsideLog, path.join(target, 'docs', 'vulnerability-remediation-log.md'));
    for (const args of [['policy', 'init'], ['audit', 'open']]) {
        const result = spawnSync(process.execPath, [cli, ...args, '--target', target], {
            encoding: 'utf-8',
            env: { ...process.env, VULN_NO_OPEN: '1', NO_COLOR: '1' }
        });
        assert.notEqual(result.status, 0, `${args.join(' ')} should refuse`);
        assert.match(`${result.stdout}${result.stderr}`, /Refusing path outside the target directory/);
    }
    assert.ok(!fs.existsSync(path.join(work, 'dangling-outside')), 'nothing may be created outside the target');
});

test('a dangling link inside a symlinked directory cannot write outside the target', () => {
    const parent = path.join(work, 'nested-parent');
    const target = path.join(parent, 'target');
    fs.mkdirSync(target, { recursive: true });
    fs.symlinkSync('.', path.join(target, 'docs'));
    fs.symlinkSync('../evil.md', path.join(target, 'vulnerability-remediation-log.md'));
    const result = spawnSync(process.execPath, [cli, 'audit', 'open', '--target', target], {
        encoding: 'utf-8',
        env: { ...process.env, VULN_NO_OPEN: '1', NO_COLOR: '1' }
    });
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}${result.stderr}`, /Refusing path outside the target directory/);
    assert.ok(!fs.existsSync(path.join(parent, 'evil.md')), 'nothing may be created in the parent directory');
});
