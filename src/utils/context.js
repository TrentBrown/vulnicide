import fs from 'fs';
import path from 'path';

export function addTargetOption(command) {
    command.option('--target <path>', 'Project directory to scan');
}

export function getCommandContext(command) {
    const options = command.optsWithGlobals ? command.optsWithGlobals() : command.opts();
    const target = options.target || process.cwd();
    const targetDir = path.resolve(target);

    return {
        target,
        targetDir,
        targetOption: options.target ? ` --target ${target}` : '',
        // For anything the CLI creates, writes or deletes: refuse a path that
        // leaves the target lexically or through a symlink.
        joinProjectPath: (...parts) => projectPath(targetDir, path.join(targetDir, ...parts), parts, { followSymlinks: true }),
        // For read-only inputs (.snyk, package.json, node_modules, reports):
        // lexical containment only, so a symlinked shared .snyk still works.
        readProjectPath: (...parts) => projectPath(targetDir, path.join(targetDir, ...parts), parts)
    };
}

// Every path the CLI reads, writes or deletes is derived from the target
// directory, partly from target-controlled config (.vulnrc.json
// buildDir/vulnDir). Refuse anything that lexically leaves the target. Paths
// the CLI writes or deletes are also checked after resolving symlinks, so
// build/explain/summary/clean never touch an unrelated directory; reads may
// still follow a symlinked .snyk or node_modules.
function projectPath(targetDir, candidate, parts, { followSymlinks = false } = {}) {
    const root = followSymlinks ? realpathOfExisting(targetDir) : targetDir;
    const resolved = followSymlinks ? realpathOfExisting(path.resolve(candidate)) : path.resolve(candidate);
    if (!isInside(root, resolved)) {
        throw new Error(`Refusing path outside the target directory: ${path.join(...parts)} (target: ${targetDir})`);
    }
    return candidate;
}

function isInside(root, candidate) {
    const relative = path.relative(root, candidate);
    return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

// Resolve symlinks in the longest existing prefix of an absolute path, then
// re-append the parts that do not exist yet. A dangling symlink is followed to
// its (missing) destination, so writing through it is judged by where the
// write would land.
function realpathOfExisting(absolutePath, depth = 0) {
    if (depth > 40) throw new Error(`Too many symbolic links resolving ${absolutePath}`);
    const missing = [];
    let current = absolutePath;
    for (;;) {
        try {
            return path.join(fs.realpathSync(current), ...missing);
        } catch (error) {
            if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error;
            const link = danglingLinkTarget(current);
            if (link !== null) {
                // A relative link resolves against the link's real parent
                // directory, which may itself sit behind symlinks.
                const parent = realpathOfExisting(path.dirname(current), depth + 1);
                return path.join(realpathOfExisting(path.resolve(parent, link), depth + 1), ...missing);
            }
            const parent = path.dirname(current);
            if (parent === current) return absolutePath;
            missing.unshift(path.basename(current));
            current = parent;
        }
    }
}

function danglingLinkTarget(linkPath) {
    try {
        if (!fs.lstatSync(linkPath).isSymbolicLink()) return null;
        return fs.readlinkSync(linkPath);
    } catch {
        return null;
    }
}
