import { spawn } from 'child_process';

// Run a command to completion and capture its output. Never rejects: a
// missing binary is reported as `notFound`, any other spawn failure as
// `spawnError`, so callers can classify every case.
export function runProcess(command, args, options = {}) {
    return new Promise((resolve) => {
        let child;
        try {
            child = spawn(command, args, {
                cwd: options.cwd || process.cwd(),
                env: options.env || process.env
            });
        } catch (error) {
            resolve({ code: null, stdout: '', stderr: '', notFound: error.code === 'ENOENT', spawnError: error });
            return;
        }

        let stdout = '';
        let stderr = '';
        let settled = false;
        const finish = (result) => {
            if (settled) return;
            settled = true;
            resolve(result);
        };

        child.stdout.on('data', (data) => { stdout += data.toString(); });
        child.stderr.on('data', (data) => { stderr += data.toString(); });
        child.on('error', (error) => {
            finish({ code: null, stdout, stderr, notFound: error.code === 'ENOENT', spawnError: error });
        });
        child.on('close', (code) => {
            finish({ code, stdout, stderr, notFound: false, spawnError: null });
        });
    });
}

// Last meaningful lines of an engine's stderr, for outcome messages.
export function stderrSummary(stderr, maxLines = 5) {
    return String(stderr || '')
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
        .filter((line) => !/options starting with '--x-'/.test(line))
        .slice(-maxLines)
        .join(' | ');
}
