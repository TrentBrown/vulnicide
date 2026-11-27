import fs from 'fs/promises';
import path from 'path';
import { fileExists } from './files.js';

export async function loadProjectConfig(context = {}) {
    const targetDir = context.targetDir || process.cwd();
    const configPath = path.resolve(targetDir, '.vulnrc.json');
    if (await fileExists(configPath)) {
        const content = await fs.readFile(configPath, 'utf-8');
        return JSON.parse(content);
    }

    // Check package.json for vuln configuration
    const packageJsonPath = path.resolve(targetDir, 'package.json');
    if (await fileExists(packageJsonPath)) {
        const content = await fs.readFile(packageJsonPath, 'utf-8');
        const pkg = JSON.parse(content);
        if (pkg.vuln) {
            return pkg.vuln;
        }
    }

    return {};
}

export function getProjectId(config, context = {}) {
    // Used as a filename prefix, so keep it to a single safe path segment.
    const id = String(config.projectId || path.basename(context.targetDir || process.cwd()));
    return id.replace(/[^A-Za-z0-9._-]/g, '-');
}

export const CODE_ENGINES = ['opengrep', 'snyk'];
export const DEFAULT_CODE_ENGINE = 'opengrep';
export const DEFAULT_OPENGREP_CONFIG = ['p/default'];

export class UsageError extends Error {}

// Engine precedence: --engine flag, then project config `codeEngine`, then
// the built-in default. An unknown name is a usage error.
export function getCodeEngine(config, flagValue) {
    const fromFlag = flagValue !== undefined && flagValue !== null;
    const engine = fromFlag ? flagValue : (config.codeEngine ?? DEFAULT_CODE_ENGINE);
    if (!CODE_ENGINES.includes(engine)) {
        const source = fromFlag ? '--engine' : 'codeEngine in the project config';
        throw new UsageError(`Unknown code engine "${engine}" (from ${source}). Use one of: ${CODE_ENGINES.join(', ')}.`);
    }
    return engine;
}

// Opengrep rule sources: registry packs (p/<name>) and/or local rule files
// or folders. A project list replaces the default entirely.
export function getOpengrepConfig(config) {
    const list = config.opengrepConfig;
    if (list === undefined || list === null) return [...DEFAULT_OPENGREP_CONFIG];
    if (!Array.isArray(list) || list.length === 0 || !list.every((entry) => typeof entry === 'string' && entry.trim())) {
        throw new UsageError('opengrepConfig in the project config must be a non-empty list of rule sources, e.g. ["p/default", "./security-rules/"].');
    }
    return list;
}

export function getBuildDirPath(config) {
    return config.buildDir || 'build';
}

export function getVulnDirPath(config) {
    return config.vulnDir || 'vuln';
}

export function getDistDirPath(config) {
    const vulnDir = getVulnDirPath(config);
    return path.join(vulnDir, 'dist');
}

export async function hasNodeProject(context = {}) {
    const targetDir = context.targetDir || process.cwd();
    return await fileExists(path.resolve(targetDir, 'package.json'));
}

export async function hasMavenProject(context = {}) {
    const targetDir = context.targetDir || process.cwd();
    return await fileExists(path.resolve(targetDir, 'pom.xml'));
}
