import fs from 'fs/promises';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const packageDir = path.resolve(__dirname, '..');
const skillName = 'remediate-vuln';
const sourceDir = path.join(packageDir, 'skills', skillName);

async function main() {
    await ensureSkillSource();

    const targets = await getInstallTargets();
    const installed = [];

    for (const target of targets) {
        await installSkill(target);
        installed.push(target);
    }

    console.log(`Installed ${skillName} skill:`);
    for (const target of installed) {
        console.log(`- ${path.join(target, 'SKILL.md')}`);
    }
    console.log('');
    console.log('Restart your agent session if the skill is not immediately visible.');
    console.log(`Fallback prompt: Use $${skillName} at ${sourceDir} to remediate one Snyk explain packet.`);
}

async function ensureSkillSource() {
    const skillFile = path.join(sourceDir, 'SKILL.md');
    try {
        await fs.access(skillFile);
    } catch {
        throw new Error(`Skill source not found at ${skillFile}`);
    }
}

async function getInstallTargets() {
    const home = os.homedir();
    const codexHome = process.env.CODEX_HOME || path.join(home, '.codex');
    const agentsHome = process.env.AGENTS_HOME || path.join(home, '.agents');
    const targets = [path.join(codexHome, 'skills', skillName)];

    if (process.env.AGENTS_HOME || await directoryExists(agentsHome)) {
        targets.push(path.join(agentsHome, 'skills', skillName));
    }

    return unique(targets);
}

async function installSkill(targetDir) {
    await fs.mkdir(path.dirname(targetDir), { recursive: true });
    await fs.rm(targetDir, { recursive: true, force: true });
    await fs.cp(sourceDir, targetDir, { recursive: true });
}

async function directoryExists(dir) {
    try {
        const stat = await fs.stat(dir);
        return stat.isDirectory();
    } catch {
        return false;
    }
}

function unique(values) {
    return [...new Set(values)];
}

main().catch((error) => {
    console.error(`Failed to install ${skillName} skill: ${error.message}`);
    process.exit(1);
});
