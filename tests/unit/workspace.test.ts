import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bindArg, findSensitive, mountTarget, parseMounts, resolveMounts, urlWithCredentials, validateWorkspacePath, type FsProbe } from "../../apps/server/workspace.ts";

const home = "/Users/me";
const projectRoot = "/Users/me/work/devicedock";
const fakeFs = (dirs: Record<string, string[]>): FsProbe => ({
  real: (p) => p,
  isDir: (p) => p in dirs,
  list: (p) => dirs[p] ?? [],
});
const fs = fakeFs({
  [home]: [],
  [projectRoot]: [".git", ".runtime", "apps"],
  "/Users/me/work/devicedock/contiki-ng": [".git", "Makefile.include"],
  "/Users/me/work/devicedock/apps": ["server"],
  "/Users/me/work/devicedock/.runtime": [],
  "/Users/me/work/devicedock/node_modules/pkg": [".git"],
  "/Users/me/work": [],
  "/Users/me/src/contiki-ng": [".git"],
  "/Users/me/src/secrets": [".env"],
  "/Users/me/.ssh": [],
  "/Users/me/src/bad,name": [],
  "/Users/me/src/contiki-ng/examples": [],
  "/Users/me/src/other": [".git"],
  "/opt/x": [],
});
const opts = { home, projectRoot, fs };
const rw = (...paths: string[]) => paths.map((path) => ({ path, readOnly: false }));
const args = (mounts: { path: string; readOnly: boolean }[], o = opts) => resolveMounts(mounts, o).map(bindArg);

test("a dedicated folder in the home folder is accepted", () => {
  assert.equal(validateWorkspacePath("/Users/me/src/contiki-ng", opts), "/Users/me/src/contiki-ng");
});
test("a separate git checkout inside the project is accepted", () => {
  assert.equal(validateWorkspacePath(`${projectRoot}/contiki-ng`, opts), `${projectRoot}/contiki-ng`);
});
test("the project, its own folders and its private parts are refused", () => {
  assert.throws(() => validateWorkspacePath(projectRoot, opts), /DeviceDock project folder/);
  assert.throws(() => validateWorkspacePath("/Users/me/work", opts), /DeviceDock project folder/);
  assert.throws(() => validateWorkspacePath(`${projectRoot}/apps`, opts), /separate git checkout/);
  assert.throws(() => validateWorkspacePath(`${projectRoot}/.runtime`, opts), /never shared/);
  assert.throws(() => validateWorkspacePath(`${projectRoot}/node_modules/pkg`, opts), /never shared/);
});
test("home, outside home, credential folders and credential files are refused", () => {
  assert.throws(() => validateWorkspacePath(home, opts), /home folder/);
  assert.throws(() => validateWorkspacePath("/opt/x", opts), /inside your home folder/);
  assert.throws(() => validateWorkspacePath("/Users/me/.ssh", opts), /credentials/);
  assert.throws(() => validateWorkspacePath("/Users/me/src/secrets", opts), /\.env/);
  assert.throws(() => validateWorkspacePath("contiki-ng", opts), /absolute/);
});
test("folders are mounted below /workspace under their own name", () => {
  assert.equal(mountTarget("/Users/me/src/contiki-ng"), "/workspace/contiki-ng");
  assert.throws(() => mountTarget("/Users/me/src/bad,name"), /folder name/);
  assert.deepEqual(args(rw("/Users/me/src/contiki-ng", "/Users/me/src/contiki-ng")), [
    "type=bind,src=/Users/me/src/contiki-ng,dst=/workspace/contiki-ng",
  ]);
  assert.deepEqual(args([]), []);
});
test("a folder inside another mounted folder is refused, in either order", () => {
  const outer = "/Users/me/src/contiki-ng", inner = "/Users/me/src/contiki-ng/examples";
  assert.throws(() => args(rw(outer, inner)), /one is inside the other/);
  assert.throws(() => args(rw(inner, outer)), /one is inside the other/);
  assert.equal(args(rw(outer, "/Users/me/src/other")).length, 2);
});
test("content checks apply when a folder is added, not on later starts", () => {
  const changed = fakeFs({ [home]: [], [projectRoot]: [".git"], "/Users/me/src/p": [".env"], [`${projectRoot}/co`]: [] });
  const o = { home, projectRoot, fs: changed };
  assert.throws(() => validateWorkspacePath("/Users/me/src/p", o), /\.env/);
  assert.throws(() => validateWorkspacePath(`${projectRoot}/co`, o), /separate git checkout/);
  assert.equal(args(rw("/Users/me/src/p", `${projectRoot}/co`), o).length, 2);
});
test("two folders with the same name cannot both be mounted", () => {
  assert.throws(() => args(rw("/Users/me/src/contiki-ng", `${projectRoot}/contiki-ng`)), /both be mounted/);
});
test("read-only folders are mounted with the readonly option", () => {
  const mounts = [{ path: "/Users/me/src/contiki-ng", readOnly: true }, { path: "/Users/me/src/other", readOnly: false }];
  assert.deepEqual(args(mounts), [
    "type=bind,src=/Users/me/src/contiki-ng,dst=/workspace/contiki-ng,readonly",
    "type=bind,src=/Users/me/src/other,dst=/workspace/other",
  ]);
  assert.deepEqual(parseMounts(JSON.parse(JSON.stringify(mounts))), mounts);
});
test("the stored list is read strictly: a malformed entry never becomes a writable mount", () => {
  assert.throws(() => parseMounts([{ path: "/a", readOnly: "true" }]), /true or false/);
  assert.throws(() => parseMounts([{ path: "/a" }]), /true or false/);
  assert.throws(() => parseMounts([{ readOnly: true }]), /needs a path/);
  assert.throws(() => parseMounts(["/a"]), /needs a path/);
  assert.throws(() => parseMounts([null]), /needs a path/);
  assert.throws(() => parseMounts({}), /list/);
});
test("nested files that look like credentials are found", () => {
  const dir = mkdtempSync(join(tmpdir(), "devicedock-sensitive-"));
  try {
    for (const sub of ["conf/deep", ".git", "node_modules/pkg", "docs"]) mkdirSync(join(dir, sub), { recursive: true });
    const files: [string, string][] = [
      ["conf/deep/.env.production", ""], ["conf/.env.example", ""], ["conf/server.key", ""], ["docs/readme.md", ""],
      ["node_modules/pkg/.env", ""], [".git/config", '[remote "origin"]\n\turl = https://me:s3cret@example.com/repo.git\n'],
    ];
    for (const [file, text] of files) writeFileSync(join(dir, file), text);
    assert.deepEqual(findSensitive(dir), [
      ".git/config (a password or token in a remote URL)", "conf/deep/.env.production", "conf/server.key",
    ]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  assert.equal(urlWithCredentials("url = https://example.com/repo.git\nurl = git@github.com:a/b.git"), false);
});
