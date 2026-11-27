import { spawn } from 'child_process';
import chalk from 'chalk';
import { runProcess, stderrSummary } from './process.js';

export async function runSnykTest(options = {}) {
    const args = ['test', '--json'];

    if (options.severityThreshold) {
        args.push(`--severity-threshold=${options.severityThreshold}`);
    }

    if (options.policyPath) {
        args.push(`--policy-path=${options.policyPath}`);
    }

    if (options.file) {
        args.push(`--file=${options.file}`);
    }

    if (options.debug) {
        args.push('--debug');
    }

    return runSnykCommand(args, options);
}

export function buildSnykCodeArgs(options = {}) {
    const args = ['code', 'test', '--json'];
    if (options.severityThreshold) args.push(`--severity-threshold=${options.severityThreshold}`);
    if (options.policyPath) args.push(`--policy-path=${options.policyPath}`);
    if (options.debug) args.push('--debug');
    return args;
}

// Run Snyk Code and return a normalized scan result:
// { engine, engineVersion, status: completed|unavailable|error, reason, message, sarif }
// Unlike the dependency runner, the exit code and Snyk's error JSON are
// checked, so an error is never mistaken for an audit.
export async function runSnykCodeScan(options = {}) {
    const result = await runProcess('snyk', buildSnykCodeArgs(options), {
        cwd: options.cwd || process.cwd(),
        env: { ...process.env, FORCE_COLOR: '1' }
    });
    if (result.notFound) {
        return {
            engine: 'snyk',
            engineVersion: null,
            status: 'unavailable',
            reason: 'not-installed',
            message: 'Snyk is not installed (no `snyk` on PATH). Install it with: npm install -g snyk',
            sarif: null
        };
    }
    return classifySnykCodeRun(result);
}

export function classifySnykCodeRun({ code, stdout, stderr }) {
    const parse = (text) => {
        try {
            return JSON.parse(text);
        } catch {
            return null;
        }
    };
    const out = parse(stdout);
    const err = parse(stderr);

    if ((code === 0 || code === 1) && Array.isArray(out?.runs)) {
        const driver = out.runs[0]?.tool?.driver || {};
        return {
            engine: 'snyk',
            engineVersion: driver.semanticVersion || driver.version || null,
            status: 'completed',
            reason: null,
            message: 'Snyk Code scan completed.',
            sarif: out
        };
    }

    // Snyk prints `{ ok: false, error, ... }`, on stderr in current releases
    // (stdout in some older ones).
    const errorObject = [out, err].find((value) => value && value.ok === false && value.error);
    const detail = errorObject
        ? String(errorObject.error)
        : (stderrSummary(stderr) || String(stdout).trim().slice(0, 300) || `exit ${code}`);
    const reason = classifySnykError(detail, errorObject);
    if (reason) {
        return { engine: 'snyk', engineVersion: null, status: 'unavailable', reason, message: `Snyk Code is unavailable: ${detail}`, sarif: null };
    }
    return { engine: 'snyk', engineVersion: null, status: 'error', reason: null, message: `Snyk Code failed (exit ${code}): ${detail}`, sarif: null };
}

function classifySnykError(detail, errorObject) {
    const text = `${detail} ${errorObject?.code ?? ''}`;
    if (/snyk auth|authenticat|unauthori[sz]ed|SNYK-0005|\b401\b/i.test(text)) return 'not-authenticated';
    if (/not enabled|not supported for (?:this )?org|enable .*Snyk Code|limit|quota|\b403\b|\b429\b/i.test(text)) return 'not-entitled';
    return null;
}

export async function generateHtmlReport(jsonPath, htmlPath, options = {}) {
    return new Promise((resolve, reject) => {
        const child = spawn('snyk-to-html', ['--input', jsonPath, '--output', htmlPath], {
            cwd: options.cwd || process.cwd()
        });

        let stderr = '';

        child.stderr.on('data', (data) => {
            stderr += data.toString();
        });

        child.on('close', (code) => {
            if (code !== 0) {
                reject(new Error(`snyk-to-html failed with code ${code}: ${stderr}`));
            } else {
                resolve();
            }
        });

        child.on('error', (error) => {
            reject(error);
        });
    });
}

// Run `snyk` and report what happened without throwing: the gate mode turns
// every outcome, including a missing binary or a timeout, into data.
// Resolves { exitCode, stdout, stderr, spawnError, timedOut }. Colour is
// switched off so JSON output and error messages stay plain.
export function spawnSnyk(args, { cwd, timeoutMs } = {}) {
    return new Promise((resolve) => {
        let child;
        try {
            child = spawn('snyk', args, {
                cwd: cwd || process.cwd(),
                env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '0' },
                stdio: ['ignore', 'pipe', 'pipe']
            });
        } catch (error) {
            resolve({ exitCode: null, stdout: '', stderr: '', spawnError: error, timedOut: false });
            return;
        }

        let stdout = '';
        let stderr = '';
        let timedOut = false;
        let settled = false;
        let killTimer = null;
        const finish = (result) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            clearTimeout(killTimer);
            resolve(result);
        };
        const timer = timeoutMs > 0
            ? setTimeout(() => {
                timedOut = true;
                child.kill('SIGTERM');
                killTimer = setTimeout(() => child.kill('SIGKILL'), 2000);
            }, timeoutMs)
            : null;

        child.stdout.on('data', (data) => { stdout += data.toString(); });
        child.stderr.on('data', (data) => { stderr += data.toString(); });
        child.on('error', (error) => {
            finish({ exitCode: null, stdout, stderr, spawnError: error, timedOut });
        });
        child.on('close', (code) => {
            finish({ exitCode: code, stdout, stderr, spawnError: null, timedOut });
        });
    });
}

async function runSnykCommand(args, options = {}) {
    return new Promise((resolve, reject) => {
        const child = spawn('snyk', args, {
            cwd: options.cwd || process.cwd(),
            env: { ...process.env, FORCE_COLOR: '1' }
        });

        let stdout = '';
        let stderr = '';

        child.stdout.on('data', (data) => {
            stdout += data.toString();
        });

        child.stderr.on('data', (data) => {
            stderr += data.toString();
        });

        child.on('close', (code) => {
            // Snyk returns non-zero exit code when vulnerabilities are found
            // We still want to process the results
            try {
                const result = JSON.parse(stdout);
                resolve({
                    success: code === 0,
                    data: result,
                    exitCode: code
                });
            } catch (error) {
                reject(new Error(`Failed to parse Snyk output: ${error.message}\nStderr: ${stderr}`));
            }
        });

        child.on('error', (error) => {
            reject(error);
        });
    });
}
