import open from 'open';
import chalk from 'chalk';

// Set VULN_NO_OPEN=1 to skip launching browsers/editors (CI, tests, headless hosts).
export function openingDisabled() {
    return Boolean(process.env.VULN_NO_OPEN);
}

export async function openPath(target, options = {}) {
    if (openingDisabled()) {
        console.log(chalk.gray(`VULN_NO_OPEN is set; not opening ${target}`));
        return;
    }
    await open(target, options);
}

// `opener` is injectable for tests; production callers use the `open` package.
export async function openInBrowser(url, browserName = 'Google Chrome', opener = open) {
    if (openingDisabled()) {
        console.log(chalk.gray(`VULN_NO_OPEN is set; not opening ${url}`));
        return;
    }
    console.log(chalk.blue(`Opening ${url} in ${browserName}`));
    try {
        await opener(url, { app: { name: browserName } });
    } catch (error) {
        console.error(chalk.red(`Failed to open browser: ${error.message}`));
        // Try without specifying browser as fallback
        try {
            await opener(url);
        } catch (fallbackError) {
            console.error(chalk.red(`Failed to open URL: ${fallbackError.message}`));
            process.exitCode = 1;
        }
    }
}
