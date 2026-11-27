import chalk from 'chalk';
import fs from 'fs/promises';
import { fileExists } from '../utils/files.js';
import { getCommandContext } from '../utils/context.js';
import { openPath, openingDisabled } from '../utils/browser.js';
import { packagePath } from '../utils/paths.js';

export function policyCommand(program) {
    const policy = program.command('policy')
        .description('Manage Snyk security policies');

    // Init subcommand
    policy.command('init')
        .description('Initialize Snyk policy file (.snyk) for the project')
        .option('--force', 'Overwrite existing .snyk file if it exists')
        .action(async (options, command) => {
            await initSnykPolicy(options, getCommandContext(command));
        });

    // Open subcommand
    policy.command('open')
        .description('Open the .snyk policy file in the default editor')
        .action(async (_options, command) => {
            await openSnykPolicy(getCommandContext(command));
        });

    // Print subcommand
    policy.command('print')
        .description('Print the contents of the .snyk policy file')
        .action(async (_options, command) => {
            await printSnykPolicy(getCommandContext(command));
        });
}

async function initSnykPolicy(options, context) {
    // Check if .snyk already exists (it may be a symlink to a shared policy).
    if (await fileExists(context.readProjectPath('.snyk')) && !options.force) {
        console.log(chalk.yellow('.snyk file already exists. Use --force to overwrite.'));
        return;
    }

    // Writing is only allowed inside the target, never through a symlink.
    const snykFilePath = context.joinProjectPath('.snyk');

    try {
        // Path to the template file
        const templatePath = packagePath('assets', '.snyk-template');

        // Read the template file
        const templateContent = await fs.readFile(templatePath, 'utf-8');

        // Process the template to handle the example entries
        // Keep the comments but comment out the actual exclusion lines for mitigated.js examples
        let processedContent = templateContent
            .replace(/^(\s*)(- mitigated\.js)$/m, '$1# $2')
            .replace(/^(\s*)(- rest\/mitigated\.js)$/m, '$1# $2');

        // Write the processed content to .snyk file
        await fs.writeFile(snykFilePath, processedContent, 'utf-8');

        console.log(chalk.green('✓ Created .snyk policy file from template'));
        console.log(chalk.gray('You can customize this file to:'));
        console.log(chalk.gray('  - Exclude additional directories from code scanning'));
        console.log(chalk.gray('  - Ignore specific vulnerabilities with reasons'));
        console.log(chalk.gray('  - Configure scanning behavior'));
        console.log(chalk.gray('\nNote: Example mitigated.js entries are commented out.'));
        console.log(chalk.gray('Uncomment them when you create actual mitigation files.'));

    } catch (error) {
        console.error(chalk.red(`Error creating .snyk file: ${error.message}`));
        process.exit(1);
    }
}

async function openSnykPolicy(context) {
    const snykFilePath = context.readProjectPath('.snyk');

    // Check if .snyk exists
    if (!await fileExists(snykFilePath)) {
        console.log(chalk.yellow('.snyk file does not exist. Run "vulnicide policy init" to create one.'));
        return;
    }

    try {
        await openPath(snykFilePath);
        if (!openingDisabled()) {
            console.log(chalk.green('✓ Opened .snyk policy file'));
        }
    } catch (error) {
        console.error(chalk.red(`Error opening .snyk file: ${error.message}`));
        process.exit(1);
    }
}

async function printSnykPolicy(context) {
    const snykFilePath = context.readProjectPath('.snyk');

    // Check if .snyk exists
    if (!await fileExists(snykFilePath)) {
        console.log(chalk.yellow('.snyk file does not exist. Run "vulnicide policy init" to create one.'));
        return;
    }

    try {
        // Read and print the file contents
        const content = await fs.readFile(snykFilePath, 'utf-8');
        console.log(content);
    } catch (error) {
        console.error(chalk.red(`Error reading .snyk file: ${error.message}`));
        process.exit(1);
    }
}
