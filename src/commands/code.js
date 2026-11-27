import chalk from 'chalk';
import fs from 'fs/promises';
import {
    loadProjectConfig,
    getBuildDirPath,
    getCodeEngine,
    getOpengrepConfig,
    UsageError
} from '../utils/config.js';
import {
    ensureDirectory,
    cleanDirectory,
    fileExists,
    joinPath
} from '../utils/files.js';
import { openInBrowser } from '../utils/browser.js';
import { runSnykCodeScan, generateHtmlReport } from '../utils/snyk.js';
import { runOpengrepScan } from '../utils/opengrep.js';
import { renderOpengrepReport, resultLevel } from '../utils/code-report.js';
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

export const SCAN_RESULT_SCHEMA_VERSION = 1;
export const OUTCOME_EXIT_CODES = { clean: 0, findings: 1, unavailable: 2, error: 3 };
// Usage errors (an unknown engine or threshold) get their own exit code so
// they can't be mistaken for an outcome.
export const USAGE_EXIT_CODE = 64;

const SEVERITY_THRESHOLDS = ['low', 'medium', 'high'];
// Lowest SARIF level counted at each threshold.
const THRESHOLD_MIN_RANK = { low: 0, medium: LEVEL_ORDER.warning, high: LEVEL_ORDER.error };
const ENGINE_LABELS = { opengrep: 'Opengrep', snyk: 'Snyk Code' };
const CODE_OUTPUT_FILES = ['audit-code.json', 'audit-code.html', 'audit-code-minimal.json'];

export function codeCommands(program) {
    const code = program.command('code')
        .description('Manage code vulnerability scanning (Opengrep by default, or Snyk Code)');

    code.command('build')
        .description('Build a code security audit report')
        .option('--engine <engine>', 'Code analysis engine: opengrep (default, runs locally) or snyk (uploads code to Snyk)')
        .option('--debug', 'Run in debug mode')
        .option('--severity-threshold <threshold>', 'Report only vulnerabilities at the specified level or higher (low, medium, high)', 'low')
        .action(async (options, command) => {
            await runCodeCommand(options, getCommandContext(command), { clean: false });
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
        .option('--engine <engine>', 'Code analysis engine: opengrep (default, runs locally) or snyk (uploads code to Snyk)')
        .option('--debug', 'Run in debug mode')
        .option('--severity-threshold <threshold>', 'Report only vulnerabilities at the specified level or higher (low, medium, high)', 'low')
        .action(async (options, command) => {
            await runCodeCommand(options, getCommandContext(command), { clean: true });
        });
}

async function runCodeCommand(options, context, { clean }) {
    let plan;
    try {
        // Validate everything the user chose before touching build/code/.
        plan = await planCodeBuild(options, context);
    } catch (error) {
        if (error instanceof UsageError) {
            console.error(chalk.red(error.message));
            process.exitCode = USAGE_EXIT_CODE;
            return;
        }
        throw error;
    }
    if (clean) await cleanCode(context);
    const outcome = await buildCode(plan, context);
    process.exitCode = OUTCOME_EXIT_CODES[outcome.outcome];
}

async function planCodeBuild(options, context) {
    const config = await loadProjectConfig(context);
    const engine = getCodeEngine(config, options.engine);
    const severityThreshold = options.severityThreshold || 'low';
    if (!SEVERITY_THRESHOLDS.includes(severityThreshold)) {
        throw new UsageError(`Unknown severity threshold "${severityThreshold}". Use one of: ${SEVERITY_THRESHOLDS.join(', ')}.`);
    }
    return {
        config,
        engine,
        severityThreshold,
        ruleConfigs: engine === 'opengrep' ? getOpengrepConfig(config) : null,
        debug: Boolean(options.debug)
    };
}

// Count the results at or above the threshold. Snyk has already applied the
// threshold itself, so every result in its SARIF counts.
export function countedResults(sarif, engine, severityThreshold) {
    const run = sarif?.runs?.[0] || {};
    const results = run.results || [];
    if (engine !== 'opengrep') return results;
    const rules = run.tool?.driver?.rules || [];
    const minRank = THRESHOLD_MIN_RANK[severityThreshold] ?? 0;
    return results.filter((result) => {
        const rule = getRuleForResult(result, rules);
        return (LEVEL_ORDER[resultLevel(result, rule)] ?? 0) >= minRank;
    });
}

// .snyk exclusions for an Opengrep scan. A policy that can't be read or
// parsed, or whose exclude lists aren't lists of strings, is an error: it
// must never silently scan files the project meant to exclude.
// Returns { excludes } or { error }.
export async function readCodeExcludes(policyPath) {
    // Only a .snyk that doesn't exist at all means "no exclusions". An entry
    // that exists but can't be read (for example a symlink to a shared
    // policy whose target is missing) is an error.
    try {
        await fs.lstat(policyPath);
    } catch (error) {
        if (error.code === 'ENOENT') return { excludes: [] };
        return { error: `The .snyk policy could not be read, so its code exclusions can't be applied: ${error.message}` };
    }
    let policy;
    try {
        policy = loadYaml(await fs.readFile(policyPath, 'utf-8')) ?? {};
    } catch (error) {
        return { error: `The .snyk policy could not be read, so its code exclusions can't be applied: ${error.message}` };
    }
    if (typeof policy !== 'object' || Array.isArray(policy)) {
        return { error: 'The .snyk policy is not a YAML mapping, so its code exclusions can\'t be applied.' };
    }
    const exclude = policy.exclude ?? {};
    if (typeof exclude !== 'object' || Array.isArray(exclude)) {
        return { error: 'The .snyk policy\'s exclude section must be a mapping with global and/or code lists.' };
    }
    const excludes = [];
    for (const section of ['global', 'code']) {
        const list = exclude[section];
        if (list === undefined || list === null) continue;
        if (!Array.isArray(list) || !list.every((pattern) => typeof pattern === 'string' && pattern.trim())) {
            return { error: `The .snyk policy's exclude.${section} must be a list of path patterns (strings).` };
        }
        excludes.push(...list);
    }
    return { excludes };
}

async function runOpengrepWithPolicy(plan, context) {
    const policy = await readCodeExcludes(context.readProjectPath('.snyk'));
    if (policy.error) {
        return { engine: 'opengrep', engineVersion: null, status: 'error', reason: null, message: policy.error, sarif: null };
    }
    return runOpengrepScan({ cwd: context.targetDir, ruleConfigs: plan.ruleConfigs, excludes: policy.excludes });
}

async function buildCode(plan, context) {
    const startedAt = new Date().toISOString();
    const { engine, severityThreshold } = plan;
    const buildDir = getBuildDirPath(plan.config);
    // joinProjectPath refuses a build directory outside the target (also
    // through a symlink) before anything is scanned or written.
    const codeBuildDir = context.joinProjectPath(buildDir, 'code');
    const outputPaths = Object.fromEntries(CODE_OUTPUT_FILES.map((file) => [file, context.joinProjectPath(buildDir, 'code', file)]));
    const scanResultPath = context.joinProjectPath(buildDir, 'code', 'scan-result.json');

    await ensureDirectory(codeBuildDir);
    // Remove the previous run's outputs (and packets built from them) first,
    // so a failed scan can never leave an older audit looking current.
    await removeFiles([
        ...Object.values(outputPaths),
        scanResultPath,
        context.joinProjectPath(buildDir, 'code', 'remediation-packets.json'),
        context.joinProjectPath(buildDir, 'code', 'remediation-packets.md')
    ]);

    console.log(`Building code audit report for ${context.targetDir} with ${ENGINE_LABELS[engine]}...`);

    const scan = engine === 'opengrep'
        ? await runOpengrepWithPolicy(plan, context)
        : await runSnykCodeScan({
            cwd: context.targetDir,
            severityThreshold,
            policyPath: context.readProjectPath('.snyk'),
            debug: plan.debug
        });

    let outcome;
    let message = scan.message;
    let counts = null;
    if (scan.status === 'completed') {
        const counted = countedResults(scan.sarif, engine, severityThreshold);
        counts = { total: (scan.sarif.runs?.[0]?.results || []).length, counted: counted.length };
        outcome = counted.length > 0 ? 'findings' : 'clean';
        try {
            await writeCodeOutputs({ scan, counted, engine, severityThreshold, outputPaths, context });
            message = outcome === 'clean'
                ? `No issues were found at or above severity threshold "${severityThreshold}".`
                : `${counted.length} issue(s) at or above severity threshold "${severityThreshold}" were found. Run "vulnicide code browse${context.targetOption}" to see them.`;
            if (scan.message && scan.message !== 'Opengrep scan completed.' && scan.message !== 'Snyk Code scan completed.') {
                message += ` ${scan.message}`;
            }
        } catch (error) {
            await removeFiles(Object.values(outputPaths));
            outcome = 'error';
            counts = null;
            message = `The scan completed but its reports could not be written: ${error.message}`;
        }
    } else {
        outcome = scan.status;
    }

    const scanResult = {
        schemaVersion: SCAN_RESULT_SCHEMA_VERSION,
        engine,
        engineVersion: scan.engineVersion ?? null,
        outcome,
        reason: outcome === 'unavailable' ? scan.reason : null,
        message,
        severityThreshold,
        counts,
        startedAt,
        finishedAt: new Date().toISOString()
    };
    await fs.writeFile(scanResultPath, `${JSON.stringify(scanResult, null, 2)}\n`);

    const color = { clean: chalk.green, findings: chalk.red, unavailable: chalk.yellow, error: chalk.red }[outcome];
    console.log('...done');
    console.log(color(`[${outcome}${scanResult.reason ? `: ${scanResult.reason}` : ''}] ${message}`));
    return scanResult;
}

async function writeCodeOutputs({ scan, counted, engine, severityThreshold, outputPaths, context }) {
    const jsonFilePath = outputPaths['audit-code.json'];
    const htmlFilePath = outputPaths['audit-code.html'];
    // The full SARIF, unfiltered, so `code explain` sees every result.
    await fs.writeFile(jsonFilePath, JSON.stringify(scan.sarif, null, 2));
    if (engine === 'opengrep') {
        await fs.writeFile(htmlFilePath, renderOpengrepReport({
            sarif: scan.sarif,
            counted,
            engineVersion: scan.engineVersion,
            severityThreshold,
            generatedAt: new Date().toISOString()
        }));
    } else {
        await generateHtmlReport(jsonFilePath, htmlFilePath, { cwd: context.targetDir });
    }
    await fs.writeFile(outputPaths['audit-code-minimal.json'], JSON.stringify({
        ok: counted.length === 0,
        issues: counted.length,
        files: new Set(counted.map((result) => result.locations?.[0]?.physicalLocation?.artifactLocation?.uri).filter(Boolean)).size
    }, null, 2));
}

async function removeFiles(paths) {
    for (const filePath of paths) {
        await fs.rm(filePath, { force: true });
    }
}

// `opener` is injectable for tests; the CLI uses openInBrowser.
export async function browseCode(context, opener = openInBrowser) {
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
    await opener(url);
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

    const [audit, packageJson, snykPolicy, scanResult] = await Promise.all([
        readJson(auditJsonPath),
        readOptionalJson(context.readProjectPath('package.json')),
        readSnykPolicy(context.readProjectPath('.snyk')),
        readOptionalJson(joinPath(codeBuildDir, 'scan-result.json'))
    ]);

    const engine = detectEngine(audit, scanResult);
    const packets = buildCodeRemediationPackets(audit, packageJson, snykPolicy, context, auditJsonPath, engine);
    const packetsJsonPath = context.joinProjectPath(buildDir, 'code', 'remediation-packets.json');
    const packetsMarkdownPath = context.joinProjectPath(buildDir, 'code', 'remediation-packets.md');

    await fs.writeFile(packetsJsonPath, JSON.stringify(packets, null, 2));
    await fs.writeFile(packetsMarkdownPath, renderCodeRemediationPacketsMarkdown(packets));

    console.log(chalk.green(`Built ${packets.packets.length} code remediation packets.`));
    console.log(`JSON: ${packetsJsonPath}`);
    console.log(`Markdown: ${packetsMarkdownPath}`);
}

// The engine that produced the audit: the outcome file when it names one,
// otherwise the SARIF tool name.
export function detectEngine(audit, scanResult) {
    if (scanResult && ENGINE_LABELS[scanResult.engine]) return scanResult.engine;
    const name = audit?.runs?.[0]?.tool?.driver?.name || '';
    if (/opengrep/i.test(name)) return 'opengrep';
    if (/snyk/i.test(name)) return 'snyk';
    return 'unknown';
}

export const PACKET_SCHEMA_VERSION = 2;

function buildCodeRemediationPackets(audit, packageJson, snykPolicy, context, auditJsonPath, engine) {
    const engineLabel = ENGINE_LABELS[engine] || 'code scanner';
    const run = audit.runs?.[0] || {};
    const rules = run.tool?.driver?.rules || [];
    const results = run.results || [];
    const excludedPaths = collectCodeExcludes(snykPolicy);

    const packets = results.map((result, index) => {
        const rule = getRuleForResult(result, rules);
        const primaryLocation = summarizeLocation(result.locations?.[0]);
        const codeFlow = summarizeCodeFlow(result.codeFlows);
        const level = resultLevel(result, rule);
        const ruleId = result.ruleId || rule?.id || 'unknown';
        const title = getRuleTitle(rule, ruleId);
        const metadata = ruleMetadata(rule);

        return {
            id: null,
            rule: {
                id: ruleId,
                name: rule?.name || null,
                title,
                level,
                cwe: metadata.cwe,
                owasp: metadata.owasp,
                confidence: metadata.confidence,
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
            classification: classifyCodePacket(result, rule, primaryLocation, metadata.cwe),
            finding: {
                message: result.message?.text || result.message?.markdown || '',
                arguments: result.message?.arguments || [],
                primaryLocation,
                codeFlow,
                fingerprints: result.fingerprints || {}
            },
            modelPrompt: [
                `Use ${REMEDIATION_GUIDE}.`,
                `Evaluate ${engineLabel} finding ${ruleId} in ${formatLocation(primaryLocation)}.`,
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
        schemaVersion: PACKET_SCHEMA_VERSION,
        generatedAt: new Date().toISOString(),
        targetDir: context.targetDir,
        source: {
            engine,
            auditJson: auditJsonPath,
            projectName: packageJson?.name || path.basename(context.targetDir),
            tool: run.tool?.driver?.name || engineLabel,
            toolVersion: run.tool?.driver?.semanticVersion || run.tool?.driver?.version || null,
            issueCount: results.length,
            fileCount: countUniqueFiles(results),
            ruleSummary: countBy(results, (result) => result.ruleId || 'unknown'),
            levelSummary: countBy(results, (result) => resultLevel(result, getRuleForResult(result, rules))),
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

// CWE → packet class. When a rule's CWEs match more than one row, the
// first matching row wins.
export const CWE_CLASSES = [
    { cwes: ['CWE-798', 'CWE-259', 'CWE-321'], classification: 'secret-remediation' },
    { cwes: ['CWE-79', 'CWE-80', 'CWE-1336'], classification: 'output-sanitization' },
    { cwes: ['CWE-20', 'CWE-22', 'CWE-77', 'CWE-78', 'CWE-89', 'CWE-94', 'CWE-943'], classification: 'input-validation' }
];

export function classifyByCwe(cwes) {
    const ids = new Set(cwes || []);
    return CWE_CLASSES.find((row) => row.cwes.some((cwe) => ids.has(cwe)))?.classification || null;
}

// CWE IDs, OWASP categories and confidence from a SARIF rule. Opengrep
// carries them as tags ("CWE-78: ...", "OWASP-A03:2021 - Injection",
// "HIGH CONFIDENCE"); Snyk carries CWE IDs in properties.cwe.
export function ruleMetadata(rule) {
    const tags = Array.isArray(rule?.properties?.tags) ? rule.properties.tags : [];
    const cwe = [];
    for (const value of [...tags, ...(Array.isArray(rule?.properties?.cwe) ? rule.properties.cwe : [])]) {
        const match = /^\s*(CWE-\d+)\b/i.exec(String(value));
        if (match && !cwe.includes(match[1].toUpperCase())) cwe.push(match[1].toUpperCase());
    }
    const owasp = tags
        .map((tag) => /^OWASP-(.+)$/i.exec(String(tag)))
        .filter(Boolean)
        .map((match) => match[1].trim());
    const confidenceTag = tags.map((tag) => /^(HIGH|MEDIUM|LOW) CONFIDENCE$/i.exec(String(tag))).find(Boolean);
    return { cwe, owasp, confidence: confidenceTag ? confidenceTag[1].toLowerCase() : null };
}

export function classifyCodePacket(result, rule, primaryLocation, cwes = ruleMetadata(rule).cwe) {
    const ruleId = result.ruleId || rule?.id || '';
    const file = primaryLocation.file || '';

    if (file.includes('/test/') || file.startsWith('test/') || /\.test\./.test(file)) {
        return 'test-code-triage';
    }
    const byCwe = classifyByCwe(cwes);
    if (byCwe) return byCwe;
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
    const list = (value) => (Array.isArray(value) ? value.filter((pattern) => typeof pattern === 'string') : []);
    return {
        global: list(snykPolicy?.exclude?.global),
        code: list(snykPolicy?.exclude?.code)
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
