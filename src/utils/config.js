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
