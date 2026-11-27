// Tree-style help for the vulnicide CLI.
//
//   vulnicide help [commandPath...] [-r [depth]]
//   vulnicide <command...> help [-r [depth]]
//   vulnicide [<command...>] --help [-r [depth]]
//
// Each form prints the command, its options and arguments, and its
// subcommands. Without -r, only the immediate subcommands are listed, with
// options shown for leaf subcommands. With -r, the whole tree below the
// command is printed, limited to `depth` levels when a depth is given.
import chalk from 'chalk';

const INDENT = '    ';

export function addTreeCommand(program) {
    program.helpCommand(false);
    program
        .command('help [commandPath...]')
        .description('Display command tree with all subcommands and options')
        .option('-r, --recurse [depth]', 'Show recursive tree, optionally limited to N levels')
        .action((commandPath, options) => {
            const target = findCommandByPath(program, commandPath);
            if (!target) {
                reportUnknownPath(commandPath, 'help');
                process.exit(1);
            }
            const footer = commandPath.length ? helpFooter(commandPath, { includeFlag: false }) : [];
            console.log(renderHelp(target, parseDepth(options.recurse), footer));
        });

    // `vulnicide --help [path...] [-r [depth]]`: Commander calls this for the
    // root --help, so the path and depth are read from argv.
    program.configureHelp({
        formatHelp: () => {
            const afterHelp = argsAfterHelpFlag(process.argv.slice(2));
            const commandPath = afterHelp.filter((arg, index) => !arg.startsWith('-') && !isDepthValue(afterHelp, index));
            const target = findCommandByPath(program, commandPath);
            if (!target) {
                reportUnknownPath(commandPath, '--help');
                process.exit(1);
            }
            return renderHelp(target, depthFromArgv(afterHelp), []);
        }
    });

    for (const command of program.commands) {
        if (command.name() !== 'help') addCommandHelp(command);
    }
}

// Give a command (and, recursively, its subcommands) a hidden `help`
// subcommand and a `--help` that both print its tree.
function addCommandHelp(command) {
    const show = (depth) => {
        console.log(renderHelp(command, depth, helpFooter(commandPath(command), { includeFlag: true })));
    };

    command.helpCommand(false);
    command
        .command('help', { hidden: true })
        .description('Show help for this command')
        .option('-r, --recurse [depth]', 'Show recursive tree, optionally limited to N levels')
        .action((options) => show(parseDepth(options.recurse)));
    command.configureHelp({
        formatHelp: () => {
            show(depthFromArgv(process.argv.slice(2)));
            return '';
        }
    });

    for (const sub of command.commands) {
        if (sub.name() !== 'help') addCommandHelp(sub);
    }
}

function renderHelp(command, depth, footer) {
    const lines = treeLines(command, 0, depth);
    if (footer.length) lines.push('', 'Help options for this command:', ...footer);
    lines.push(
        '',
        'Legend:',
        `${chalk.cyan('■')} Command with subcommands`,
        `${chalk.green('■')} Command without subcommands`,
        `${chalk.yellow('■')} Options and arguments`,
        `${chalk.magenta('■')} Default values`
    );
    return lines.join('\n');
}

function helpFooter(pathParts, { includeFlag }) {
    const joined = pathParts.join(' ');
    const lines = [`  ${chalk.gray(`help ${joined}`)}`, `  ${chalk.gray(`${joined} help`)}`];
    if (includeFlag) lines.push(`  ${chalk.gray(`${joined} --help`)}`);
    return lines;
}

// depth: null for the default view (immediate subcommands only), otherwise
// the number of levels to recurse (Infinity for all).
function treeLines(command, level, depth) {
    const indent = INDENT.repeat(level);
    const lines = [];
    const displayName = level === 0 && command.parent ? commandPath(command).join(' ') : command.name();
    lines.push(`${indent}${commandLabel(command, displayName)} ${command.description()}`);
    lines.push(...detailLines(command, indent));

    const children = visibleSubcommands(command);
    if (depth === null) {
        for (const child of children) {
            lines.push(`${indent}${INDENT}${commandLabel(child, child.name())} ${child.description()}`);
            if (isLeaf(child)) lines.push(...detailLines(child, `${indent}${INDENT}`));
        }
    } else if (level < depth) {
        for (const child of children) lines.push(...treeLines(child, level + 1, depth));
    }
    return lines;
}

function commandLabel(command, name) {
    const color = isLeaf(command) ? chalk.green : chalk.cyan;
    const aliases = command.aliases();
    return color(aliases.length ? `${name} (${aliases.join(', ')})` : name);
}

// Option and argument lines for a command, indented one level below it.
function detailLines(command, indent) {
    const lines = [];
    for (const option of command.options) {
        const extra = [];
        if (option.envVar) extra.push(`env: ${chalk.magenta(option.envVar)}`);
        if (option.defaultValue !== undefined) extra.push(`default: ${chalk.magenta(option.defaultValue)}`);
        if (option.mandatory) extra.push(chalk.white('required'));
        const description = option.description ? ` ${option.description}` : '';
        lines.push(`${indent}${INDENT}${chalk.yellow(option.flags)}${description}${extra.length ? ` (${extra.join(', ')})` : ''}`);
        if (Array.isArray(option.argChoices) && option.argChoices.length) {
            lines.push(`${indent}${INDENT}${INDENT}choices: ${chalk.magenta(option.argChoices.join(' | '))}`);
        }
    }
    for (const argument of command.registeredArguments) {
        const description = argument.description ? ` ${argument.description}` : '';
        const defaultValue = argument.defaultValue !== undefined ? ` (${chalk.magenta(argument.defaultValue)})` : '';
        lines.push(`${indent}${INDENT}${chalk.yellow(`<${argument.name()}>`)}${description}${defaultValue}`);
    }
    return lines;
}

// Every subcommand except the per-command `help` ones. The root keeps its
// `help` command so the tree shows how to ask for help.
function visibleSubcommands(command) {
    return command.commands.filter((child) => !(child.name() === 'help' && command.parent));
}

function isLeaf(command) {
    return command.commands.every((child) => child.name() === 'help');
}

function commandPath(command) {
    const parts = [];
    for (let current = command; current?.parent; current = current.parent) parts.unshift(current.name());
    return parts;
}

function findCommandByPath(root, pathParts) {
    let current = root;
    for (const part of pathParts) {
        current = current.commands.find((command) => command.name() === part || command.aliases().includes(part));
        if (!current) return null;
    }
    return current;
}

function reportUnknownPath(pathParts, helpWord) {
    console.error(chalk.red(`Command path '${pathParts.join(' ')}' not found.`));
    if (pathParts.length > 1) {
        console.error(`Try '${helpWord} ${pathParts.slice(0, -1).join(' ')}' to see available subcommands.`);
    } else {
        console.error(`Try '${helpWord}' to see all available commands.`);
    }
}

// Commander gives `-r` as true (no depth) or the depth string.
function parseDepth(recurse) {
    if (recurse === undefined || recurse === false) return null;
    if (recurse === true) return Infinity;
    return /^\d+$/.test(String(recurse)) ? Number(recurse) : Infinity;
}

function depthFromArgv(args) {
    const index = args.findIndex((arg) => arg === '-r' || arg === '--recurse');
    if (index === -1) return null;
    const next = args[index + 1];
    return next !== undefined && /^\d+$/.test(next) ? Number(next) : Infinity;
}

function isDepthValue(args, index) {
    return index > 0 && (args[index - 1] === '-r' || args[index - 1] === '--recurse') && /^\d+$/.test(args[index]);
}

function argsAfterHelpFlag(args) {
    const index = args.findIndex((arg) => arg === '--help' || arg === '-h');
    return index === -1 ? [] : args.slice(index + 1);
}
