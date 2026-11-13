import { realpathSync, statSync, readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { resolve, sep, isAbsolute, basename, join, relative } from "node:path";

// Optional bind mounts of dedicated host folders, each at /workspace/<folder name>, read-write or read-only. /workspace itself stays
// the devicedock-workspace Docker volume (the bridge service writes AGENTS.md and CLAUDE.md there).
// This relaxes "nothing from the host is mounted", so every folder is validated hard:
//   - it must be a dedicated directory strictly inside the home folder (Docker only shares that by default),
//   - never the home folder itself, "/", any ancestor of home, or the DeviceDock project or anything above it,
//   - inside the DeviceDock project only a separate git checkout, never .runtime (bridge token), .git or node_modules,
//   - never inside or containing a credential/config directory, and never holding credential files at its top level.
// An agent in autonomous mode can modify everything inside a read-write folder, including any .git/config and hooks.
// See SECURITY.md: do not run git inside it on the host, fetch from it into another clone instead.

/** Directories under $HOME that hold credentials or app state; the mount must be neither inside nor above them. */
export const SENSITIVE_HOME_DIRS = [
  ".ssh", ".aws", ".gnupg", ".config", ".kube", ".docker", ".azure", ".npm", ".netrc",
  ".claude", ".codex", ".colima", ".lima", "Library", ".local", ".cache", ".password-store",
];
/** Files whose presence at the top of the folder means it is not a plain project folder. */
export const SENSITIVE_TOP_LEVEL = [".ssh", ".aws", ".gnupg", ".netrc", ".env", "id_rsa", "id_ed25519", ".npmrc", "credentials.json"];

/** Parts of the DeviceDock project that must never be reachable from the sandbox. */
export const PROJECT_PRIVATE = [".runtime", ".git", "node_modules"];

export type FsProbe = {
  real(p: string): string;
  isDir(p: string): boolean;
  list(p: string): string[];
};
export const nodeFs: FsProbe = {
  // .native returns the on-disk spelling, so another letter case cannot slip past the checks on macOS.
  real: (p) => realpathSync.native(p),
  isDir: (p) => {
    try { return statSync(p).isDirectory(); } catch { return false; }
  },
  list: (p) => readdirSync(p),
};

const inside = (child: string, parent: string) => child === parent || child.startsWith(parent + sep);

/** Returns the resolved folder, or throws an Error explaining exactly why it is refused. */
export function validateWorkspacePath(
  input: string,
  opts: { home?: string; projectRoot: string; fs?: FsProbe; contents?: boolean },
): string {
  // The sandbox can change what a mounted folder contains, so the content checks run only when a folder is added
  // (contents !== false); otherwise an agent could block the next start by creating a .env file.
  const contents = opts.contents !== false;
  const fs = opts.fs ?? nodeFs;
  const home = fs.real(opts.home ?? homedir());
  if (!input || !isAbsolute(input)) throw new Error("The workspace folder must be an absolute path");
  if (!fs.isDir(input)) throw new Error(`${input} is not an existing directory`);
  const dir = fs.real(resolve(input)); // follows symlinks, so a link cannot smuggle in another place
  const project = fs.real(opts.projectRoot);

  if (dir === sep) throw new Error('Refusing "/" as the workspace');
  if (dir === home || inside(home, dir)) throw new Error("Refusing your home folder (or a folder above it): use a dedicated subfolder");
  if (!inside(dir, home)) throw new Error(`The workspace must be inside your home folder (${home}); Docker only shares that`);
  if (inside(project, dir))
    throw new Error("Refusing the DeviceDock project folder (it holds the bridge token) or a folder above it");
  if (inside(dir, project)) {
    const parts = dir.slice(project.length + 1).split(sep);
    if (parts.some((p) => PROJECT_PRIVATE.includes(p)))
      throw new Error(`Refusing ${dir}: ${PROJECT_PRIVATE.join(", ")} of the DeviceDock project are never shared`);
    if (contents && !fs.list(dir).includes(".git"))
      throw new Error(`Refusing ${dir}: inside the DeviceDock project only a separate git checkout can be mounted`);
  }
  for (const s of SENSITIVE_HOME_DIRS) {
    const sensitive = `${home}${sep}${s}`;
    if (inside(dir, sensitive)) throw new Error(`Refusing ${dir}: inside ~/${s}, which holds credentials or app state`);
  }
  const top = new Set(contents ? fs.list(dir) : []);
  const found = SENSITIVE_TOP_LEVEL.filter((n) => top.has(n));
  if (found.length) throw new Error(`Refusing ${dir}: it contains ${found.join(", ")}, which looks like credentials, not a project folder`);
  return dir;
}

/** Where a validated folder appears in the sandbox: /workspace/<folder name>. */
export function mountTarget(dir: string): string {
  const name = basename(dir);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name))
    throw new Error(`Cannot mount ${dir}: the folder name may only contain letters, digits, ".", "_" and "-"`);
  if (/[,"\n]/.test(dir)) throw new Error(`Cannot mount ${dir}: the path contains a comma, quote or line break`);
  if (["AGENTS.md", "CLAUDE.md"].includes(name)) throw new Error(`Cannot mount a folder named ${name}`);
  return `/workspace/${name}`;
}

/** Names that suggest credentials anywhere below a mounted folder. */
function sensitiveName(name: string) {
  return (
    SENSITIVE_TOP_LEVEL.includes(name) ||
    [".git-credentials", ".pypirc", "id_ecdsa", "id_dsa"].includes(name) ||
    (name.startsWith(".env.") && ![".example", ".sample", ".template", ".dist"].some((t) => name.endsWith(t))) ||
    [".pem", ".key", ".p12", ".pfx"].some((ext) => name.endsWith(ext))
  );
}
/** True when a git config holds a password or token inside a URL (https://user:secret@host/...). */
export const urlWithCredentials = (config: string) => /:\/\/[^/\s@]*:[^/\s@]*@/.test(config);

/**
 * Paths below `dir` that look like credentials, relative to it. The sandbox can read (and, with internet access,
 * send away) everything in a mounted folder, so these are shown to the user before a folder is added. The walk is
 * bounded and never follows symlinks; it is a hint, not a guarantee.
 */
export function findSensitive(dir: string): string[] {
  const maxDepth = 6, maxEntries = 50_000, skip = ["node_modules", "target", "build"];
  const found: string[] = [];
  const stack: [string, number][] = [[dir, 0]];
  let seen = 0;
  while (stack.length) {
    const [current, depth] = stack.pop()!;
    let entries;
    try { entries = readdirSync(current, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      if (++seen > maxEntries) return found;
      const path = join(current, entry.name), shown = relative(dir, path);
      if (sensitiveName(entry.name)) found.push(shown);
      else if (entry.isDirectory() && entry.name === ".git") {
        let config = "";
        try { config = readFileSync(join(path, "config"), "utf8"); } catch { /* no config: nothing to report */ }
        if (urlWithCredentials(config)) found.push(`${join(shown, "config")} (a password or token in a remote URL)`);
      } else if (entry.isDirectory() && depth < maxDepth && !skip.includes(entry.name)) stack.push([path, depth + 1]);
    }
  }
  return found.sort();
}

/** One configured folder. Read-only folders cannot be changed from the sandbox at all. */
export type Mount = { path: string; readOnly: boolean };
/** A validated mount: host folder, container path, mode. */
export type Bind = { dir: string; target: string; readOnly: boolean };

/** Reads the stored list: every entry is { "path": ..., "readOnly": true|false }. */
export function parseMounts(value: unknown): Mount[] {
  if (!Array.isArray(value)) throw new Error("expected a list of folders");
  return value.map((entry): Mount => {
    if (!entry || typeof entry !== "object" || typeof entry.path !== "string")
      throw new Error("every entry needs a path");
    // A missing or malformed flag must not quietly turn a read-only folder into a writable one.
    if (typeof entry.readOnly !== "boolean") throw new Error(`readOnly of ${entry.path} must be true or false`);
    return { path: entry.path, readOnly: entry.readOnly };
  });
}

/** The `docker run --mount` value for a validated mount. */
export const bindArg = (b: Bind) => `type=bind,src=${b.dir},dst=${b.target}${b.readOnly ? ",readonly" : ""}`;

/**
 * Validates every configured folder (without the content checks). A folder inside another mounted folder is
 * refused: the sandbox could replace it with a symlink and have a different host folder mounted on the next start.
 */
export function resolveMounts(mounts: Mount[], opts: { home?: string; projectRoot: string; fs?: FsProbe }): Bind[] {
  const binds: Bind[] = [];
  for (const mount of mounts) {
    const dir = validateWorkspacePath(mount.path, { ...opts, contents: false });
    const target = mountTarget(dir);
    const same = binds.find((b) => b.target === target);
    if (same && same.dir !== dir) throw new Error(`${dir} and ${same.dir} would both be mounted at ${target}`);
    if (same) continue;
    const nested = binds.find((b) => inside(dir, b.dir) || inside(b.dir, dir));
    if (nested) throw new Error(`${dir} and ${nested.dir} cannot both be mounted: one is inside the other`);
    binds.push({ dir, target, readOnly: mount.readOnly });
  }
  return binds;
}
