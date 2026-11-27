import path from 'path';
import { fileURLToPath } from 'url';

// Root of the installed vulnicide package (works for a git checkout and a global install).
export const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

export function packagePath(...parts) {
    return path.join(PACKAGE_ROOT, ...parts);
}

export const REMEDIATION_GUIDE = packagePath('docs', 'remediation.md');
