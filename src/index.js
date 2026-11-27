#!/usr/bin/env node

import { readFileSync } from 'fs';
import { Command } from 'commander';
import chalk from 'chalk';
import { summaryCommands } from './commands/summary.js';
import { dependenciesCommands } from './commands/dependencies.js';
import { codeCommands } from './commands/code.js';
import { policyCommand } from './commands/policy.js';
import { auditCommands } from './commands/audit.js';
import { addTargetOption } from './utils/context.js';
import { addTreeCommand } from './utils/help-tree.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf-8'));

async function main() {
    const program = new Command();

    program
        .name('vulnicide')
        .description('Snyk-driven vulnerability scanning and remediation packets')
        .version(pkg.version);
    addTargetOption(program);

    // Register command modules
    summaryCommands(program);
    dependenciesCommands(program);
    codeCommands(program);
    policyCommand(program);
    auditCommands(program);

    // Tree-style `help [commandPath...] [-r [depth]]`, `<command> help` and `--help`
    addTreeCommand(program);

    // Add detailed help
    program.on('--help', () => {
        console.log('');
        console.log('Examples:');
        console.log('  vulnicide policy init --target ../app          Initialize .snyk policy file');
        console.log('  vulnicide deps build --target ../app           Scan dependencies for vulnerabilities');
        console.log('  vulnicide deps explain --target ../app         Build dependency remediation packets');
        console.log('  vulnicide deps gate --json < request.json      GateReeve gate scan: JSON request in, findings JSON out');
        console.log('  vulnicide code build --target ../app           Scan code for security issues');
        console.log('  vulnicide code explain --target ../app         Build code remediation packets');
        console.log('  vulnicide audit open --target ../app           Create/open the remediation audit log');
        console.log('  vulnicide summary build --target ../app        Generate summary report');
        console.log('  vulnicide help -r                              Show all commands in tree format');
        console.log('');
        console.log('Prerequisites:');
        console.log('  • Snyk CLI: npm install -g snyk');
        console.log('  • Snyk-to-HTML: npm install -g snyk-to-html');
    });

    try {
        await program.parseAsync(process.argv);
    } catch (error) {
        console.error(chalk.red('Error:'), error.message);
        process.exit(1);
    }

    // Show help if no command provided
    if (!process.argv.slice(2).length) {
        program.outputHelp();
    }
}

main();
