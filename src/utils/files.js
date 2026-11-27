import fs from 'fs/promises';
import path from 'path';

export async function fileExists(filePath) {
    try {
        await fs.access(filePath);
        return true;
    } catch {
        return false;
    }
}

export async function directoryExists(dirPath) {
    try {
        const stat = await fs.stat(dirPath);
        return stat.isDirectory();
    } catch {
        return false;
    }
}

export async function ensureDirectory(dirPath) {
    try {
        await fs.mkdir(dirPath, { recursive: true });
    } catch (error) {
        if (error.code !== 'EEXIST') {
            throw error;
        }
    }
}

export async function cleanDirectory(dirPath) {
    try {
        await fs.rm(dirPath, { recursive: true, force: true });
    } catch (error) {
        // Ignore errors if directory doesn't exist
        if (error.code !== 'ENOENT') {
            throw error;
        }
    }
}

export async function copyFile(source, destination) {
    await fs.copyFile(source, destination);
}

export function resolvePath(...parts) {
    return path.resolve(...parts);
}

export function joinPath(...parts) {
    return path.join(...parts);
}