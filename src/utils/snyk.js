import { spawn } from 'child_process';
import chalk from 'chalk';

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

export async function runSnykCodeTest(options = {}) {
    const args = ['code', 'test', '--json'];

    if (options.severityThreshold) {
        args.push(`--severity-threshold=${options.severityThreshold}`);
    }

    if (options.policyPath) {
        args.push(`--policy-path=${options.policyPath}`);
    }

    if (options.debug) {
        args.push('--debug');
    }

    return runSnykCommand(args, options);
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
