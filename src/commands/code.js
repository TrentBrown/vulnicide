import chalk from 'chalk';
import fs from 'fs/promises';
import {
    loadProjectConfig,
    getBuildDirPath
} from '../utils/config.js';
import {
    ensureDirectory,
    cleanDirectory,
    fileExists,
    joinPath
} from '../utils/files.js';
import { openInBrowser } from '../utils/browser.js';
import { runSnykCodeTest, generateHtmlReport } from '../utils/snyk.js';
import { getCommandContext } from '../utils/context.js';
import { REMEDIATION_GUIDE } from '../utils/paths.js';
import path from 'path';
import { load as loadYaml } from 'js-yaml';

const LEVEL_ORDER = {
    error: 3,
    warning: 2,
    note: 1,
    none: 0
};

export function codeCommands(program) {
    const code = program.command('code')
        .description('Manage code vulnerability scanning');

    code.command('build')
        .description('Build a code security audit report')
        .option('--debug', 'Run in debug mode')
        .option('--severity-threshold <threshold>', 'Report only vulnerabilities at the specified level or higher', 'low')
        .action(async (options, command) => {
            await buildCode(options, getCommandContext(command));
        });

    code.command('browse')
        .description('Open the local code audit page in browser')
        .action(async (_options, command) => {
            await browseCode(getCommandContext(command));
        });

    code.command('clean')
        .description('Clean the local code audit files')
        .action(async (_options, command) => {
            await cleanCode(getCommandContext(command));
        });

    code.command('explain')
        .description('Build model-friendly remediation packets from the code audit JSON')
        .action(async (_options, command) => {
            await explainCode(getCommandContext(command));
        });

    code.command('rebuild')
        .description('Clean and rebuild code audit')
        .option('--debug', 'Run in debug mode')
        .option('--severity-threshold <threshold>', 'Report only vulnerabilities at the specified level or higher', 'low')
        .action(async (options, command) => {
            const context = getCommandContext(command);
            await cleanCode(context);
            await buildCode(options, context);
        });
}

async function buildCode(options, context) {
    console.log(`Building code audit report for ${context.targetDir}...`);

    const config = await loadProjectConfig(context);
    const buildDir = getBuildDirPath(config);
    const codeBuildDir = context.joinProjectPath(buildDir, 'code');

    await ensureDirectory(codeBuildDir);

    const jsonFilePath = context.joinProjectPath(buildDir, 'code', 'audit-code.json');
    const htmlFilePath = context.joinProjectPath(buildDir, 'code', 'audit-code.html');

    const snykOptions = {
        severityThreshold: options.severityThreshold || 'low',
        policyPath: context.readProjectPath('.snyk'),
        cwd: context.targetDir,
        debug: options.debug
    };

    try {
        const result = await runSnykCodeTest(snykOptions);

        // Write JSON results
        await fs.writeFile(jsonFilePath, JSON.stringify(result.data, null, 2));

        // Generate HTML report
        await generateHtmlReport(jsonFilePath, htmlFilePath, { cwd: context.targetDir });

        console.log('...done');

        if (result.success) {
            console.log(chalk.green(`No issues were found above severity threshold "${snykOptions.severityThreshold}"`));
        } else {
            console.log(chalk.red(`Issues above severity threshold "${snykOptions.severityThreshold}" were found. Run "vulnicide code browse${context.targetOption}" to see them.`));
        }

        // Create minimal JSON file
        await createMinimalJsonCode(jsonFilePath, context.joinProjectPath(buildDir, 'code', 'audit-code-minimal.json'));

    } catch (error) {
        console.error(chalk.red(`Error running code scan: ${error.message}`));
        process.exit(1);
    }
}

async function browseCode(context) {
    const config = await loadProjectConfig(context);
    const buildDir = getBuildDirPath(config);
    const htmlFilePath = context.readProjectPath(buildDir, 'code', 'audit-code.html');
    const absoluteHtmlFilePath = path.resolve(htmlFilePath);
    if (!await fileExists(absoluteHtmlFilePath)) {
        console.log(chalk.yellow(`No code audit page found at ${absoluteHtmlFilePath}.`));
        console.log(chalk.gray(`Run "vulnicide code build${context.targetOption}" first, or pass the same --target used for the build.`));
        return;
    }
    const url = `file://${absoluteHtmlFilePath}`;
    await openInBrowser(url);
}

async function cleanCode(context) {
    const config = await loadProjectConfig(context);
    const buildDir = getBuildDirPath(config);
    const codeBuildDir = context.joinProjectPath(buildDir, 'code');

    await cleanDirectory(codeBuildDir);
    console.log('Cleaned code audit report');
}

async function explainCode(context) {
    const config = await loadProjectConfig(context);
    const buildDir = getBuildDirPath(config);
    const codeBuildDir = context.joinProjectPath(buildDir, 'code');
    const auditJsonPath = joinPath(codeBuildDir, 'audit-code.json');

    if (!await fileExists(auditJsonPath)) {
        console.log(chalk.yellow(`No code audit JSON found at ${auditJsonPath}.`));
        console.log(chalk.gray(`Run "vulnicide code build${context.targetOption}" first.`));
        return;
    }

    const [audit, packageJson, snykPolicy] = await Promise.all([
        readJson(auditJsonPath),
        readOptionalJson(context.readProjectPath('package.json')),
        readSnykPolicy(context.readProjectPath('.snyk'))
    ]);

    const packets = buildCodeRemediationPackets(audit, packageJson, snykPolicy, context, auditJsonPath);
    const packetsJsonPath = context.joinProjectPath(buildDir, 'code', 'remediation-packets.json');
    const packetsMarkdownPath = context.joinProjectPath(buildDir, 'code', 'remediation-packets.md');

    await fs.writeFile(packetsJsonPath, JSON.stringify(packets, null, 2));
    await fs.writeFile(packetsMarkdownPath, renderCodeRemediationPacketsMarkdown(packets));

    console.log(chalk.green(`Built ${packets.packets.length} code remediation packets.`));
    console.log(`JSON: ${packetsJsonPath}`);
    console.log(`Markdown: ${packetsMarkdownPath}`);
}

function buildCodeRemediationPackets(audit, packageJson, snykPolicy, context, auditJsonPath) {
    const run = audit.runs?.[0] || {};
    const rules = run.tool?.driver?.rules || [];
    const results = run.results || [];
    const excludedPaths = collectCodeExcludes(snykPolicy);

    const packets = results.map((result, index) => {
        const rule = getRuleForResult(result, rules);
        const primaryLocation = summarizeLocation(result.locations?.[0]);
        const codeFlow = summarizeCodeFlow(result.codeFlows);
        const level = result.level || rule?.defaultConfiguration?.level || 'none';
        const ruleId = result.ruleId || rule?.id || 'unknown';
        const title = getRuleTitle(rule, ruleId);

        return {
            id: null,
            rule: {
                id: ruleId,
                name: rule?.name || null,
                title,
                level,
                helpUri: rule?.helpUri || null,
                helpSummary: summarizeRuleHelp(rule)
            },
            priority: {
                level,
                levelRank: LEVEL_ORDER[level] || 0,
                priorityScore: result.properties?.priorityScore || null,
                priorityScoreFactors: result.properties?.priorityScoreFactors || [],
                isAutofixable: result.properties?.isAutofixable || false
            },
            classification: classifyCodePacket(result, rule, primaryLocation),
            finding: {
                message: result.message?.text || result.message?.markdown || '',
                arguments: result.message?.arguments || [],
                primaryLocation,
                codeFlow,
                fingerprints: result.fingerprints || {}
            },
            modelPrompt: [
                `Use ${REMEDIATION_GUIDE}.`,
                `Evaluate Snyk Code finding ${ruleId} in ${formatLocation(primaryLocation)}.`,
                'Decide whether to remediate with a code change, refactor into a documented mitigation, update code exclusions for accepted risk or false positive, or defer with rationale.',
                'Propose a small, verifiable next step before editing.'
            ].join(' '),
            _sortIndex: index
        };
    });

    packets.sort((a, b) =>
        b.priority.levelRank - a.priority.levelRank ||
        (b.priority.priorityScore || 0) - (a.priority.priorityScore || 0) ||
        (a.finding.primaryLocation.file || '').localeCompare(b.finding.primaryLocation.file || '') ||
        (a.finding.primaryLocation.startLine || 0) - (b.finding.primaryLocation.startLine || 0) ||
        a._sortIndex - b._sortIndex
    );
    packets.forEach((packet, index) => {
        packet.id = codePacketId(index + 1, packet.rule.id, packet.finding.primaryLocation);
        delete packet._sortIndex;
    });

    return {
        schemaVersion: 1,
        generatedAt: new Date().toISOString(),
        targetDir: context.targetDir,
        source: {
            auditJson: auditJsonPath,
            projectName: packageJson?.name || path.basename(context.targetDir),
            tool: run.tool?.driver?.name || 'SnykCode',
            toolVersion: run.tool?.driver?.semanticVersion || run.tool?.driver?.version || null,
            issueCount: results.length,
            fileCount: countUniqueFiles(results),
            ruleSummary: countBy(results, (result) => result.ruleId || 'unknown'),
            levelSummary: countBy(results, (result) => result.level || 'none'),
            fileSummary: countBy(results, (result) => summarizeLocation(result.locations?.[0]).file || 'unknown'),
            policy: {
                excludedPaths
            }
        },
        packets
    };
}

function getRuleForResult(result, rules) {
    if (Number.isInteger(result.ruleIndex) && rules[result.ruleIndex]) {
        return rules[result.ruleIndex];
    }
    return rules.find((rule) => rule.id === result.ruleId) || null;
}

function getRuleTitle(rule, fallback) {
    return rule?.shortDescription?.text || rule?.fullDescription?.text || rule?.name || fallback;
}

function summarizeRuleHelp(rule) {
    const markdown = rule?.help?.markdown || rule?.help?.text || '';
    if (!markdown) return null;

    const summary = markdown
        .replace(/```[\s\S]*?```/g, '')
        .replace(/^#+\s*/gm, '')
        .replace(/\n{2,}/g, '\n')
        .trim()
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
        .slice(0, 6)
        .join(' ');

    return summary.length > 1200 ? `${summary.slice(0, 1197)}...` : summary;
}

function summarizeLocation(location) {
    const physicalLocation = location?.physicalLocation || {};
    const region = physicalLocation.region || {};
    return {
        file: physicalLocation.artifactLocation?.uri || null,
        uriBaseId: physicalLocation.artifactLocation?.uriBaseId || null,
        startLine: region.startLine || null,
        endLine: region.endLine || region.startLine || null,
        startColumn: region.startColumn || null,
        endColumn: region.endColumn || null
    };
}

function summarizeCodeFlow(codeFlows) {
    const locations = [];
    for (const codeFlow of codeFlows || []) {
        for (const threadFlow of codeFlow.threadFlows || []) {
            for (const threadLocation of threadFlow.locations || []) {
                locations.push(summarizeLocation(threadLocation.location));
            }
        }
    }
    return locations.filter((location) => location.file).slice(0, 12);
}

function classifyCodePacket(result, rule, primaryLocation) {
    const ruleId = result.ruleId || rule?.id || '';
    const file = primaryLocation.file || '';

    if (file.includes('/test/') || file.startsWith('test/') || /\.test\./.test(file)) {
        return 'test-code-triage';
    }
    if (/Hardcoded.*Secret|Hardcoded.*Password|NoHardcodedPasswords/i.test(ruleId)) {
        return 'secret-remediation';
    }
    if (/XSS|Sanitization|Ssti|Template/i.test(ruleId)) {
        return 'output-sanitization';
    }
    if (/HTTPSourceWithUncheckedType|Type Validation/i.test(ruleId)) {
        return 'input-validation';
    }
    if (result.properties?.isAutofixable) {
        return 'autofix-candidate';
    }
    return 'manual-code-triage';
}

function collectCodeExcludes(snykPolicy) {
    return {
        global: snykPolicy?.exclude?.global || [],
        code: snykPolicy?.exclude?.code || []
    };
}

function renderCodeRemediationPacketsMarkdown(packets) {
    const lines = [
        '# Code Remediation Packets',
        '',
        `- **Generated:** ${packets.generatedAt}`,
        `- **Target:** ${packets.targetDir}`,
        `- **Project:** ${packets.source.projectName}`,
        `- **Tool:** ${packets.source.tool}${packets.source.toolVersion ? ` ${packets.source.toolVersion}` : ''}`,
        `- **Issues:** ${packets.source.issueCount}`,
        `- **Files:** ${packets.source.fileCount}`,
        `- **Packets:** ${packets.packets.length}`,
        ''
    ];

    lines.push('## Summary');
    lines.push('');
    lines.push('**Levels**');
    for (const [level, count] of sortCounts(packets.source.levelSummary)) {
        lines.push(`- ${level}: ${count}`);
    }
    lines.push('');
    lines.push('**Rules**');
    for (const [ruleId, count] of sortCounts(packets.source.ruleSummary)) {
        lines.push(`- ${ruleId}: ${count}`);
    }
    lines.push('');
    lines.push('**Files**');
    for (const [file, count] of sortCounts(packets.source.fileSummary)) {
        lines.push(`- ${file}: ${count}`);
    }
    lines.push('');
    if (packets.source.policy.excludedPaths.global.length || packets.source.policy.excludedPaths.code.length) {
        lines.push('**Existing exclusions**');
        for (const pattern of packets.source.policy.excludedPaths.global) {
            lines.push(`- global: ${pattern}`);
        }
        for (const pattern of packets.source.policy.excludedPaths.code) {
            lines.push(`- code: ${pattern}`);
        }
        lines.push('');
    }

    for (const packet of packets.packets) {
        lines.push(`## ${packet.id} - ${packet.rule.id}`);
        lines.push('');
        lines.push(`- **Classification:** ${packet.classification}`);
        lines.push(`- **Level:** ${packet.priority.level}`);
        lines.push(`- **Priority score:** ${packet.priority.priorityScore ?? 'not listed'}`);
        lines.push(`- **Autofixable:** ${packet.priority.isAutofixable ? 'yes' : 'no'}`);
        lines.push(`- **Location:** ${formatLocation(packet.finding.primaryLocation)}`);
        lines.push(`- **Title:** ${packet.rule.title}`);
        lines.push('');
        lines.push('**Message**');
        lines.push('');
        lines.push(packet.finding.message || 'No message listed.');
        lines.push('');
        if (packet.finding.codeFlow.length) {
            lines.push('**Code flow**');
            for (const location of packet.finding.codeFlow.slice(0, 8)) {
                lines.push(`- ${formatLocation(location)}`);
            }
            lines.push('');
        }
        if (packet.rule.helpSummary) {
            lines.push('**Rule summary**');
            lines.push('');
            lines.push(packet.rule.helpSummary);
            lines.push('');
        }
        lines.push('**Model prompt**');
        lines.push('');
        lines.push('```text');
        lines.push(packet.modelPrompt);
        lines.push('```');
        lines.push('');
    }

    return `${lines.join('\n')}\n`;
}

function formatLocation(location) {
    if (!location?.file) return 'unknown location';
    if (!location.startLine) return location.file;
    const column = location.startColumn ? `:${location.startColumn}` : '';
    return `${location.file}:${location.startLine}${column}`;
}

function countUniqueFiles(results) {
    return new Set(results.map((result) => summarizeLocation(result.locations?.[0]).file).filter(Boolean)).size;
}

function countBy(values, getKey) {
    return values.reduce((counts, value) => {
        const key = getKey(value);
        counts[key] = (counts[key] || 0) + 1;
        return counts;
    }, {});
}

function sortCounts(counts) {
    return Object.entries(counts || {}).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

function codePacketId(index, ruleId, location) {
    const locationSlug = `${location.file || 'unknown'}-${location.startLine || ''}`;
    const slug = `${ruleId}-${locationSlug}`
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '')
        .slice(0, 56);
    return `C-${String(index).padStart(3, '0')}-${slug}`;
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

async function createMinimalJsonCode(inputPath, outputPath) {
    try {
        const content = await fs.readFile(inputPath, 'utf-8');
        const data = JSON.parse(content);

        const minimal = {
            ok: data.runs?.[0]?.results?.length === 0 || false,
            issues: data.runs?.[0]?.results?.length || 0,
            files: new Set(data.runs?.[0]?.results?.map(r => r.locations?.[0]?.physicalLocation?.artifactLocation?.uri) || []).size
        };

        await fs.writeFile(outputPath, JSON.stringify(minimal, null, 2));
    } catch (error) {
        console.error(chalk.yellow(`Warning: Could not create minimal JSON: ${error.message}`));
    }
}
