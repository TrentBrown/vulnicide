import chalk from 'chalk';
import fs from 'fs/promises';
import { createWriteStream } from 'fs';
import path from 'path';
import {
    loadProjectConfig,
    getVulnDirPath,
    getDistDirPath,
    getBuildDirPath,
    getProjectId
} from '../utils/config.js';
import {
    ensureDirectory,
    cleanDirectory,
    directoryExists,
    fileExists,
    copyFile
} from '../utils/files.js';
import { openInBrowser } from '../utils/browser.js';
import { getCommandContext } from '../utils/context.js';
import { packagePath } from '../utils/paths.js';

export function summaryCommands(program) {
    const summary = program.command('summary')
        .description('Manage vulnerability summary reports');

    summary.command('build')
        .description('Build vulnerability summary report')
        .action(async (_options, command) => {
            await buildSummary(getCommandContext(command));
        });

    summary.command('browse')
        .description('Open the local summary page in browser')
        .action(async (_options, command) => {
            await browseSummary(getCommandContext(command));
        });

    summary.command('clean')
        .description('Clean summary report files')
        .action(async (_options, command) => {
            await cleanSummary(getCommandContext(command));
        });

    summary.command('rebuild')
        .description('Clean and rebuild summary report')
        .action(async (_options, command) => {
            const context = getCommandContext(command);
            await cleanSummary(context);
            await buildSummary(context);
        });
}

async function buildSummary(context) {
    console.log(`Building vulnerability summary report for ${context.targetDir}...`);

    const config = await loadProjectConfig(context);
    const vulnDir = context.readProjectPath(getVulnDirPath(config));
    const distDir = context.joinProjectPath(getDistDirPath(config));
    const buildDir = context.readProjectPath(getBuildDirPath(config));

    await ensureDirectory(distDir);

    // Copy CSS file if it exists in the package
    const packageCssPath = packagePath('assets', 'index.css');
    const localCssPath = path.join(vulnDir, 'index.css');
    const distCssPath = context.joinProjectPath(getDistDirPath(config), 'index.css');

    // Try package CSS first, then local CSS
    if (await fileExists(packageCssPath)) {
        await copyFile(packageCssPath, distCssPath);
    } else if (await fileExists(localCssPath)) {
        await copyFile(localCssPath, distCssPath);
    } else {
        // Create a default CSS file
        await createDefaultCss(distCssPath);
    }

    // Create index.html
    const indexPath = context.joinProjectPath(getDistDirPath(config), 'index.html');
    const writeStream = createWriteStream(indexPath);

    // Write HTML header
    await writeToStream(writeStream, `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Vulnerability Summary</title>
    <link rel="stylesheet" type="text/css" href="index.css">
</head>
<body>
    <div class="container">
        <div class="title">Vulnerability Summary</div>
`);

    // Add project info
    const projectName = config.projectName || path.basename(context.targetDir);
    await writeToStream(writeStream, `        <div style="application">
            <div style="application-name">${escapeHtml(projectName)}</div>
            <div style="reports">
`);

    // Copy and link audit reports
    const reports = [];

    // Check for dependency reports
    const depsDir = path.join(buildDir, 'dependencies');
    if (await directoryExists(depsDir)) {
        const files = await fs.readdir(depsDir);
        for (const file of files) {
            if (file.endsWith('.html')) {
                const srcPath = path.join(depsDir, file);
                const dstFile = `${getProjectId(config, context)}-${file}`;
                const dstPath = context.joinProjectPath(getDistDirPath(config), dstFile);
                await copyFile(srcPath, dstPath);
                reports.push({ name: file, path: dstFile });
            }
        }
    }

    // Check for code reports
    const codeDir = path.join(buildDir, 'code');
    if (await directoryExists(codeDir)) {
        const files = await fs.readdir(codeDir);
        for (const file of files) {
            if (file.endsWith('.html')) {
                const srcPath = path.join(codeDir, file);
                const dstFile = `${getProjectId(config, context)}-${file}`;
                const dstPath = context.joinProjectPath(getDistDirPath(config), dstFile);
                await copyFile(srcPath, dstPath);
                reports.push({ name: file, path: dstFile });
            }
        }
    }

    // Write report links
    for (const report of reports) {
        await writeToStream(writeStream, `                <a href="./${escapeHtml(encodeURIComponent(report.path))}" target="_blank">${escapeHtml(report.name)}</a>\n`);
    }

    // Close HTML
    await writeToStream(writeStream, `            </div>
        </div>
    </div>
</body>
</html>`);

    writeStream.end();

    console.log('Built summary report');
    if (reports.length === 0) {
        console.log(chalk.yellow('No vulnerability reports found. Run "vulnicide deps build" or "vulnicide code build" first.'));
    }
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

async function writeToStream(stream, content) {
    return new Promise((resolve, reject) => {
        stream.write(content, (error) => {
            if (error) reject(error);
            else resolve();
        });
    });
}

async function createDefaultCss(cssPath) {
    const defaultCss = `body {
    font-family: 'Arial', sans-serif;
    margin: 0;
    padding: 0;
    background: #f4f4f4;
    color: #333;
}

.container {
    max-width: 800px;
    margin: auto;
    padding: 20px;
}

.title {
    font-size: 24px;
    font-weight: bold;
    padding-bottom: 20px;
}

div[style="application"] {
    background: white;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

div[style="application-name"] {
    font-size: 18px;
    font-weight: bold;
    margin-bottom: 15px;
}

div[style="reports"] {
    padding-left: 20px;
}

a {
    display: block;
    color: #007bff;
    text-decoration: none;
    padding: 5px 0;
    transition: color 0.3s;
}

a:hover {
    color: #0056b3;
    text-decoration: underline;
}`;

    await fs.writeFile(cssPath, defaultCss);
}

async function browseSummary(context) {
    const config = await loadProjectConfig(context);
    const distDir = context.readProjectPath(getDistDirPath(config));
    const indexPath = path.join(distDir, 'index.html');

    if (!await fileExists(indexPath)) {
        console.log(chalk.yellow('No summary report found. Run "vulnicide summary build" first.'));
        return;
    }

    const absoluteIndexPath = path.resolve(indexPath);
    const url = `file://${absoluteIndexPath}`;
    await openInBrowser(url);
}

async function cleanSummary(context) {
    const config = await loadProjectConfig(context);
    const distDir = context.joinProjectPath(getDistDirPath(config));

    await cleanDirectory(distDir);
    console.log('Cleaned summary report');
}
