import chalk from 'chalk';
import fs from 'fs/promises';
import path from 'path';
import { fileExists, ensureDirectory } from '../utils/files.js';
import { getCommandContext } from '../utils/context.js';
import { openPath, openingDisabled } from '../utils/browser.js';
import { packagePath } from '../utils/paths.js';

const AUDIT_LOG_PATH = path.join('docs', 'vulnerability-remediation-log.md');

export function auditCommands(program) {
    const audit = program.command('audit')
        .description('Manage the vulnerability remediation audit log');

    audit.command('path')
        .description('Print the vulnerability remediation audit log path')
        .action(async (_options, command) => {
            await printAuditLogPath(getCommandContext(command));
        });

    audit.command('open')
        .description('Open the vulnerability remediation audit log')
        .action(async (_options, command) => {
            await openAuditLog(getCommandContext(command));
        });
}

async function printAuditLogPath(context) {
    console.log(getAuditLogPath(context));
}

async function openAuditLog(context) {
    const auditLogPath = getAuditLogPath(context);

    try {
        if (!await fileExists(auditLogPath)) {
            await createAuditLog(auditLogPath);
            console.log(chalk.green(`Created ${auditLogPath}`));
        }

        await openPath(auditLogPath);
        if (!openingDisabled()) {
            console.log(chalk.green(`Opened ${auditLogPath}`));
        }
    } catch (error) {
        console.error(chalk.red(`Error opening vulnerability remediation audit log: ${error.message}`));
        process.exit(1);
    }
}

async function createAuditLog(auditLogPath) {
    const templatePath = packagePath('assets', 'vulnerability-remediation-log-template.md');
    const templateContent = await fs.readFile(templatePath, 'utf-8');

    await ensureDirectory(path.dirname(auditLogPath));
    await fs.writeFile(auditLogPath, templateContent, 'utf-8');
}

function getAuditLogPath(context) {
    return context.joinProjectPath(AUDIT_LOG_PATH);
}
