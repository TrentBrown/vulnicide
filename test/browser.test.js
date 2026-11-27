// Unit test for the browser opener's failure reporting.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openInBrowser } from '../src/utils/browser.js';

test('openInBrowser sets a failing exit code when both launch attempts fail', async () => {
    const saved = { exitCode: process.exitCode, noOpen: process.env.VULN_NO_OPEN, error: console.error, log: console.log };
    delete process.env.VULN_NO_OPEN;
    const calls = [];
    console.error = () => {};
    console.log = () => {};
    try {
        process.exitCode = undefined;
        await openInBrowser('file:///nowhere.html', 'No Such Browser', async (...args) => {
            calls.push(args);
            throw new Error('cannot launch');
        });
        assert.equal(calls.length, 2, 'tries the named browser, then the default opener');
        assert.equal(process.exitCode, 1);

        process.exitCode = undefined;
        await openInBrowser('file:///ok.html', 'No Such Browser', async () => {});
        assert.equal(process.exitCode, undefined, 'success leaves the exit code alone');
    } finally {
        process.exitCode = saved.exitCode;
        console.error = saved.error;
        console.log = saved.log;
        if (saved.noOpen !== undefined) process.env.VULN_NO_OPEN = saved.noOpen;
    }
});
