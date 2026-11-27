import chalk from 'chalk';
import fs from 'fs/promises';
import {
    loadProjectConfig,
    getBuildDirPath,
    hasNodeProject,
    hasMavenProject
} from '../utils/config.js';
import {
    ensureDirectory,
    cleanDirectory,
    directoryExists,
    fileExists,
    joinPath
} from '../utils/files.js';
import { openInBrowser } from '../utils/browser.js';
import { runSnykTest, generateHtmlReport } from '../utils/snyk.js';
import { getCommandContext } from '../utils/context.js';
import { REMEDIATION_GUIDE } from '../utils/paths.js';
import { runGateCommand, DEFAULT_GATE_TIMEOUT_SECONDS } from './gate.js';
import { indexUpgradeRemediation, collectUpgradeAdvice } from '../utils/upgrade-advice.js';
import path from 'path';
import { load as loadYaml } from 'js-yaml';

const SEVERITY_ORDER = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1
};

export function dependenciesCommands(program) {
    const deps = program.command('deps')
        .description('Manage dependency vulnerability scanning');

    deps.command('build')
        .description('Build an audit of security issues in project dependencies')
        .option('--debug', 'Run in debug mode')
        .option('--severity-threshold <threshold>', 'Report only vulnerabilities at the specified level or higher', 'low')
        .action(async (options, command) => {
            await buildDependencies(options, getCommandContext(command));
        });

    deps.command('browse')
        .description('Open the local dependencies audit page in browser')
        .action(async (_options, command) => {
            await browseDependencies(getCommandContext(command));
        });

    deps.command('clean')
        .description('Clean the local dependencies audit files')
        .action(async (_options, command) => {
            await cleanDependencies(getCommandContext(command));
        });

    deps.command('explain')
        .description('Build model-friendly remediation packets from the dependencies audit JSON')
        .action(async (_options, command) => {
            await explainDependencies(getCommandContext(command));
        });

    deps.command('gate')
        .description('GateReeve scanning mode: read a JSON request on stdin, write normalized findings JSON to stdout')
        .option('--json', 'Required: read the request on stdin and write the response as JSON')
        .option('--timeout <seconds>', 'Per-target snyk test timeout in seconds', String(DEFAULT_GATE_TIMEOUT_SECONDS))
        .action(async (options) => {
            process.exitCode = await runGateCommand(options);
        });

    deps.command('rebuild')
        .description('Clean and rebuild dependencies audit')
        .option('--debug', 'Run in debug mode')
        .option('--severity-threshold <threshold>', 'Report only vulnerabilities at the specified level or higher', 'low')
        .action(async (options, command) => {
            const context = getCommandContext(command);
            await cleanDependencies(context);
            await buildDependencies(options, context);
        });
}

async function buildDependencies(options, context) {
    const isNodeProject = await hasNodeProject(context);
    const isMavenProject = await hasMavenProject(context);

    if (!isNodeProject && !isMavenProject) {
        console.log(chalk.yellow(`No Node.js or Maven project found in target directory: ${context.targetDir}`));
        return;
    }

    console.log(`Building dependencies audit report for ${context.targetDir}...`);

    // Check for node_modules if Node project
    if (isNodeProject) {
        const nodeModulesExists = await directoryExists(context.readProjectPath('node_modules'));
        if (!nodeModulesExists) {
            console.log(chalk.red('No node_modules folder found. Run "npm install" and run this command again.'));
            return;
        }
    }

    const config = await loadProjectConfig(context);
    const buildDir = getBuildDirPath(config);
    const dependenciesBuildDir = context.joinProjectPath(buildDir, 'dependencies');

    await ensureDirectory(dependenciesBuildDir);

    const jsonFilePath = context.joinProjectPath(buildDir, 'dependencies', 'audit-dependencies.json');
    const htmlFilePath = context.joinProjectPath(buildDir, 'dependencies', 'audit-dependencies.html');

    const snykOptions = {
        severityThreshold: options.severityThreshold || 'low',
        policyPath: context.readProjectPath('.snyk'),
        cwd: context.targetDir,
        debug: options.debug
    };

    // Add file option for Maven projects
    if (isMavenProject && !isNodeProject) {
        snykOptions.file = context.readProjectPath('pom.xml');
    }

    try {
        const result = await runSnykTest(snykOptions);

        // Write JSON results
        await fs.writeFile(jsonFilePath, JSON.stringify(result.data, null, 2));

        // Generate HTML report
        await generateHtmlReport(jsonFilePath, htmlFilePath, { cwd: context.targetDir });

        console.log('...done');

        if (result.success) {
            console.log(chalk.green(`No issues were found above severity threshold "${snykOptions.severityThreshold}"`));
        } else {
            console.log(chalk.red(`Issues above severity threshold "${snykOptions.severityThreshold}" were found. Run "vulnicide deps browse${context.targetOption}" to see them.`));
        }

        // Create minimal JSON file
        await createMinimalJsonDependencies(jsonFilePath, context.joinProjectPath(buildDir, 'dependencies', 'audit-dependencies-minimal.json'));

    } catch (error) {
        console.error(chalk.red(`Error running vulnerability scan: ${error.message}`));
        process.exit(1);
    }
}

async function browseDependencies(context) {
    const config = await loadProjectConfig(context);
    const buildDir = getBuildDirPath(config);
    const htmlFilePath = context.readProjectPath(buildDir, 'dependencies', 'audit-dependencies.html');
    const absoluteHtmlFilePath = path.resolve(htmlFilePath);
    if (!await fileExists(absoluteHtmlFilePath)) {
        console.log(chalk.yellow(`No dependencies audit page found at ${absoluteHtmlFilePath}.`));
        console.log(chalk.gray(`Run "vulnicide deps build${context.targetOption}" first, or pass the same --target used for the build.`));
        return;
    }
    const url = `file://${absoluteHtmlFilePath}`;
    await openInBrowser(url);
}

async function cleanDependencies(context) {
    const config = await loadProjectConfig(context);
    const buildDir = getBuildDirPath(config);
    const dependenciesBuildDir = context.joinProjectPath(buildDir, 'dependencies');

    await cleanDirectory(dependenciesBuildDir);
    console.log('Cleaned dependencies audit report');
}

async function explainDependencies(context) {
    const config = await loadProjectConfig(context);
    const buildDir = getBuildDirPath(config);
    const dependenciesBuildDir = context.joinProjectPath(buildDir, 'dependencies');
    const auditJsonPath = joinPath(dependenciesBuildDir, 'audit-dependencies.json');

    if (!await fileExists(auditJsonPath)) {
        console.log(chalk.yellow(`No dependencies audit JSON found at ${auditJsonPath}.`));
        console.log(chalk.gray(`Run "vulnicide deps build${context.targetOption}" first.`));
        return;
    }

    const [audit, packageJson, snykPolicy] = await Promise.all([
        readJson(auditJsonPath),
        readOptionalJson(context.readProjectPath('package.json')),
        readSnykPolicy(context.readProjectPath('.snyk'))
    ]);

    const packets = buildRemediationPackets(audit, packageJson, snykPolicy, context, auditJsonPath);
    const packetsJsonPath = context.joinProjectPath(buildDir, 'dependencies', 'remediation-packets.json');
    const packetsMarkdownPath = context.joinProjectPath(buildDir, 'dependencies', 'remediation-packets.md');

    await fs.writeFile(packetsJsonPath, JSON.stringify(packets, null, 2));
    await fs.writeFile(packetsMarkdownPath, renderRemediationPacketsMarkdown(packets));

    console.log(chalk.green(`Built ${packets.packets.length} remediation packets.`));
    console.log(`JSON: ${packetsJsonPath}`);
    console.log(`Markdown: ${packetsMarkdownPath}`);
}

function buildRemediationPackets(audit, packageJson, snykPolicy, context, auditJsonPath) {
    const vulnerabilities = Array.isArray(audit.vulnerabilities) ? audit.vulnerabilities : [];
    const directDependencies = collectDirectDependencies(packageJson);
    const policyIgnores = collectPolicyIgnores(snykPolicy);
    const upgradeRemediationByVuln = indexUpgradeRemediation(audit.remediation?.upgrade || {});
    const unresolvedIds = new Set((audit.remediation?.unresolved || []).map((vulnerability) => vulnerability.id));
    const groups = groupVulnerabilities(vulnerabilities);

    const packets = [...groups.entries()].map(([groupKey, group]) => {
        const highestSeverity = getHighestSeverity(group.vulnerabilities);
        const vulnerabilityIds = unique(group.vulnerabilities.map((vulnerability) => vulnerability.id));
        const fixedIn = unique(group.vulnerabilities.flatMap((vulnerability) => vulnerability.fixedIn || []));
        const dependencyPaths = unique(group.vulnerabilities.map((vulnerability) => (vulnerability.from || []).join(' > '))).slice(0, 8);
        const upgradeAdvice = collectUpgradeAdvice(vulnerabilityIds, upgradeRemediationByVuln);
        const ignored = vulnerabilityIds
            .filter((id) => policyIgnores.has(id))
            .map((id) => ({ id, ...policyIgnores.get(id) }));
        const directDependency = directDependencies.get(group.packageName);
        const packageManagers = unique(group.vulnerabilities.map((vulnerability) => vulnerability.packageManager).filter(Boolean));
        const exploitMaturity = unique(group.vulnerabilities.map((vulnerability) => vulnerability.exploit).filter(Boolean));

        return {
            id: null,
            package: {
                name: group.packageName,
                version: group.version,
                key: groupKey,
                directDependency: directDependency || null
            },
            priority: {
                highestSeverity,
                severityRank: SEVERITY_ORDER[highestSeverity] || 0,
                vulnerabilityCount: group.vulnerabilities.length,
                uniqueVulnerabilityCount: vulnerabilityIds.length,
                hasCritical: group.vulnerabilities.some((vulnerability) => vulnerability.severity === 'critical'),
                hasHigh: group.vulnerabilities.some((vulnerability) => vulnerability.severity === 'high')
            },
            classification: classifyPacket({
                group,
                directDependency,
                upgradeAdvice,
                unresolvedIds,
                vulnerabilityIds
            }),
            vulnerabilities: vulnerabilityIds.map((id) => summarizeVulnerability(id, group.vulnerabilities)),
            remediation: {
                snykUpgradeAdvice: upgradeAdvice,
                fixedIn,
                ignored,
                unresolved: vulnerabilityIds.filter((id) => unresolvedIds.has(id))
            },
            evidence: {
                packageManagers,
                exploitMaturity,
                dependencyPaths
            },
            modelPrompt: [
                `Use ${REMEDIATION_GUIDE}.`,
                `Evaluate ${group.packageName}@${group.version}.`,
                'Decide whether to remediate by direct upgrade, parent dependency upgrade, npm override, framework migration, or documented .snyk ignore.',
                'Propose a small, verifiable next step before editing.'
            ].join(' ')
        };
    });

    packets.sort((a, b) =>
        b.priority.severityRank - a.priority.severityRank ||
        b.priority.uniqueVulnerabilityCount - a.priority.uniqueVulnerabilityCount ||
        a.package.name.localeCompare(b.package.name)
    );
    packets.forEach((packet, index) => {
        packet.id = packetId(index + 1, packet.package.name, packet.package.version);
    });

    return {
        schemaVersion: 1,
        generatedAt: new Date().toISOString(),
        targetDir: context.targetDir,
        source: {
            auditJson: auditJsonPath,
            projectName: audit.projectName || packageJson?.name || path.basename(context.targetDir),
            packageManager: audit.packageManager || null,
            dependencyCount: audit.dependencyCount || 0,
            vulnerablePaths: vulnerabilities.length,
            uniqueCount: audit.uniqueCount || packets.length,
            summary: audit.summary || null
        },
        packets
    };
}

function collectDirectDependencies(packageJson) {
    const sections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
    const dependencies = new Map();
    if (!packageJson) return dependencies;

    for (const section of sections) {
        for (const [name, range] of Object.entries(packageJson[section] || {})) {
            dependencies.set(name, { section, range });
        }
    }

    return dependencies;
}

function collectPolicyIgnores(snykPolicy) {
    const ignores = new Map();
    for (const [id, entries] of Object.entries(snykPolicy?.ignore || {})) {
        const reasons = [];
        for (const entry of entries || []) {
            for (const value of Object.values(entry || {})) {
                if (value?.reason) {
                    reasons.push(value.reason);
                }
            }
        }
        ignores.set(id, { reasons });
    }
    return ignores;
}

function groupVulnerabilities(vulnerabilities) {
    const groups = new Map();
    for (const vulnerability of vulnerabilities) {
        const packageName = vulnerability.packageName || vulnerability.name || 'unknown';
        const version = vulnerability.version || 'unknown';
        const key = `${packageName}@${version}`;
        if (!groups.has(key)) {
            groups.set(key, { packageName, version, vulnerabilities: [] });
        }
        groups.get(key).vulnerabilities.push(vulnerability);
    }
    return groups;
}

function classifyPacket({ group, directDependency, upgradeAdvice, unresolvedIds, vulnerabilityIds }) {
    const packageName = group.packageName;
    const paths = group.vulnerabilities.flatMap((vulnerability) => vulnerability.from || []);

    if (isFrameworkPackage(packageName) || paths.some(isFrameworkPackage)) {
        return 'framework-or-major-migration';
    }
    if (directDependency && upgradeAdvice.length > 0) {
        return 'direct-upgrade-candidate';
    }
    if (upgradeAdvice.length > 0) {
        return 'transitive-upgrade-candidate';
    }
    if (vulnerabilityIds.some((id) => unresolvedIds.has(id))) {
        return directDependency ? 'direct-manual-triage' : 'transitive-manual-triage';
    }
    return directDependency ? 'direct-investigate' : 'transitive-investigate';
}

function summarizeVulnerability(id, vulnerabilities) {
    const matching = vulnerabilities.filter((vulnerability) => vulnerability.id === id);
    const first = matching[0];
    return {
        id,
        title: first.title,
        severity: first.severity,
        cvssScore: first.cvssScore || null,
        identifiers: first.identifiers || {},
        fixedIn: first.fixedIn || [],
        exploit: first.exploit || null,
        publicationTime: first.publicationTime || null,
        pathCount: matching.length
    };
}

function renderRemediationPacketsMarkdown(packets) {
    const lines = [
        '# Dependency Remediation Packets',
        '',
        `- **Generated:** ${packets.generatedAt}`,
        `- **Target:** ${packets.targetDir}`,
        `- **Project:** ${packets.source.projectName}`,
        `- **Package manager:** ${packets.source.packageManager || 'unknown'}`,
        `- **Vulnerable paths:** ${packets.source.vulnerablePaths}`,
        `- **Unique Snyk count:** ${packets.source.uniqueCount}`,
        `- **Packets:** ${packets.packets.length}`,
        ''
    ];

    for (const packet of packets.packets) {
        lines.push(`## ${packet.id} - ${packet.package.key}`);
        lines.push('');
        lines.push(`- **Classification:** ${packet.classification}`);
        lines.push(`- **Priority:** ${packet.priority.highestSeverity}; ${packet.priority.uniqueVulnerabilityCount} unique vulnerabilities across ${packet.priority.vulnerabilityCount} paths`);
        lines.push(`- **Direct dependency:** ${packet.package.directDependency ? `${packet.package.directDependency.section} ${packet.package.directDependency.range}` : 'no'}`);
        lines.push(`- **Fixed in:** ${packet.remediation.fixedIn.length ? packet.remediation.fixedIn.join(', ') : 'not listed'}`);
        lines.push(`- **Snyk upgrade advice:** ${packet.remediation.snykUpgradeAdvice.length ? packet.remediation.snykUpgradeAdvice.map((entry) => `${entry.dependency} -> ${entry.upgradeTo}`).join('; ') : 'none'}`);
        lines.push(`- **Already ignored:** ${packet.remediation.ignored.length ? packet.remediation.ignored.map((entry) => entry.id).join(', ') : 'no'}`);
        lines.push('');
        lines.push('**Vulnerabilities**');
        for (const vulnerability of packet.vulnerabilities) {
            lines.push(`- ${vulnerability.id} (${vulnerability.severity}) - ${vulnerability.title}`);
        }
        lines.push('');
        lines.push('**Example dependency paths**');
        for (const dependencyPath of packet.evidence.dependencyPaths.slice(0, 4)) {
            lines.push(`- ${dependencyPath}`);
        }
        lines.push('');
        lines.push('**Model prompt**');
        lines.push('');
        lines.push('```text');
        lines.push(packet.modelPrompt);
        lines.push('```');
        lines.push('');
    }

    return `${lines.join('\n')}\n`;
}

function getHighestSeverity(vulnerabilities) {
    return vulnerabilities
        .map((vulnerability) => vulnerability.severity || 'low')
        .sort((a, b) => (SEVERITY_ORDER[b] || 0) - (SEVERITY_ORDER[a] || 0))[0] || 'low';
}

function packetId(index, packageName, version) {
    const slug = `${packageName}-${version}`
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '')
        .slice(0, 48);
    return `D-${String(index).padStart(3, '0')}-${slug}`;
}

function unique(values) {
    return [...new Set(values.filter((value) => value !== undefined && value !== null && value !== ''))];
}

function isFrameworkPackage(name) {
    return /^(nuxt|vue|vue-|@nuxt|@vue|bootstrap-vue|bootstrap-vue-3)/.test(name);
}

async function readJson(filePath) {
    return JSON.parse(await fs.readFile(filePath, 'utf-8'));
}

async function readOptionalJson(filePath) {
    if (!await fileExists(filePath)) return null;
    return readJson(filePath);
}

async function readSnykPolicy(filePath) {
    if (!await fileExists(filePath)) return {};
    try {
        return loadYaml(await fs.readFile(filePath, 'utf-8')) || {};
    } catch (error) {
        console.log(chalk.yellow(`Warning: Could not parse .snyk policy file: ${error.message}`));
        return {};
    }
}

async function createMinimalJsonDependencies(inputPath, outputPath) {
    try {
        const content = await fs.readFile(inputPath, 'utf-8');
        const data = JSON.parse(content);

        const minimal = {
            ok: data.ok || false,
            vulnerabilities: data.uniqueCount || 0,
            dependencies: data.dependencyCount || 0,
            summary: data.summary || {}
        };

        await fs.writeFile(outputPath, JSON.stringify(minimal, null, 2));
    } catch (error) {
        console.error(chalk.yellow(`Warning: Could not create minimal JSON: ${error.message}`));
    }
}
