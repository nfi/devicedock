import {
  startSandbox,
  docker,
  container,
  verifyManaged,
  sandboxExists,
  readMounts,
  writeMounts,
  takenTargets,
  takenMessage,
} from "../apps/server/sandbox.ts";
import { findSensitive, mountTarget, resolveMounts, validateWorkspacePath, type Mount } from "../apps/server/workspace.ts";
import { resolve, basename } from "node:path";
import { createInterface } from "node:readline";

const runningWarning =
  "The sandbox is running. Changing mounts recreates its container:\nagent sessions, terminals and builds running in it end now. Volumes and logins are kept.";
const mode = (readOnly: boolean) => (readOnly ? "read-only" : "read-write");

/** Whether the managed container runs; null when there is no container. Throws when Docker is not reachable. */
async function containerRunning(): Promise<boolean | null> {
  if (!(await sandboxExists())) return null;
  await verifyManaged();
  return (await docker(["inspect", "--format", "{{.State.Running}}", container])) === "true";
}
/** Shows what the change means and asks before going on. No warnings, no question. */
async function confirm(warnings: string[]) {
  if (!warnings.length) return;
  for (const warning of warnings) console.log(warning);
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise<string>((done) => {
    rl.question("Continue? [y/N] ", done);
    rl.once("close", () => done(""));
  });
  rl.close();
  if (answer.trim() !== "y") throw Error("nothing changed");
}

// Saves the new list and applies it. If the sandbox cannot be recreated with it, the old list is put back.
async function changeMounts(previous: Mount[], next: Mount[]) {
  await writeMounts(next);
  try {
    await applyMounts();
  } catch (e) {
    await writeMounts(previous);
    const restored = await startSandbox().then(
      () => "the sandbox is running with the previous mounts",
      () => "the sandbox could not be restarted",
    );
    throw Error(`${(e as Error).message}\nThe mount list was left unchanged; ${restored}.`);
  }
}
// Mounts are fixed at container creation: remove the container so the next start creates it with the new list.
async function applyMounts() {
  let running: boolean | null;
  try {
    running = await containerRunning();
  } catch {
    return console.log("Docker is not reachable: takes effect the next time the sandbox is started.");
  }
  if (running === null) return console.log("Takes effect when the sandbox is started.");
  await docker(["rm", "-f", container]);
  if (running) await startSandbox();
  console.log(running ? "Sandbox recreated with the new mounts (volumes kept)." : "Takes effect when the sandbox is started.");
}
const op = process.argv[2];
try {
  if (op === "start") {
    await startSandbox();
    console.log("Sandbox started.");
  } else if (op === "stop") {
    await verifyManaged();
    await docker(["stop", container]);
    console.log("Sandbox stopped; workspace and credentials preserved.");
  } else if (op === "clean") {
    await verifyManaged();
    await docker(["rm", "-f", container]);
    console.log(
      "Container removed. Volumes preserved. See README for explicit data removal.",
    );
  } else if (op === "mounts") {
    const mounts = await readMounts();
    for (const m of mounts) console.log(`${m.path}  ->  ${mountTarget(m.path)}  (${mode(m.readOnly)})`);
    if (!mounts.length) console.log("No host folders are mounted.");
  } else if (op === "mount") {
    const readOnly = process.argv[3] === "--ro";
    const arg = process.argv[readOnly ? 4 : 3];
    if (!arg || process.argv.length > (readOnly ? 5 : 4)) throw Error("Use mount [--ro] <folder>");
    const dir = validateWorkspacePath(resolve(arg), { projectRoot: process.cwd() });
    const target = mountTarget(dir);
    const previous = await readMounts();
    const existing = previous.find((m) => m.path === dir);
    if (existing?.readOnly === readOnly) {
      console.log(`${dir} is already mounted ${mode(readOnly)} at ${target}. Nothing changed.`);
    } else {
      // Mounting a folder again changes its mode.
      const mounts = [...previous.filter((m) => m.path !== dir), { path: dir, readOnly }];
      resolveMounts(mounts, { projectRoot: process.cwd() });
      const running = await containerRunning().catch(() => undefined);
      const warnings: string[] = [];
      if (existing?.readOnly)
        warnings.push(`${dir} is mounted read-only now. Read-write lets the sandbox change everything in it.`);
      if (!existing) {
        // Without Docker this is checked when the sandbox is next created.
        const taken = await takenTargets([target]).catch(() => []);
        if (taken.length) throw Error(takenMessage(taken));
        const sensitive = findSensitive(dir);
        const more = sensitive.length > 15 ? `\n  ... and ${sensitive.length - 15} more` : "";
        if (sensitive.length)
          warnings.push(
            `These look like credentials. The sandbox has internet access and will be able to read them:\n  ${sensitive.slice(0, 15).join("\n  ")}${more}`,
          );
      }
      if (running) warnings.push(runningWarning);
      await confirm(warnings);
      console.log(`${dir} will be mounted ${mode(readOnly)} at ${target}.`);
      await changeMounts(previous, mounts);
    }
  } else if (op === "unmount") {
    const arg = process.argv[3];
    if (!arg) throw Error("Use unmount <folder>");
    const mounts = await readMounts();
    const kept = mounts.filter((m) => m.path !== resolve(arg) && basename(m.path) !== arg);
    if (kept.length === mounts.length) throw Error(`${arg} is not mounted`);
    if (await containerRunning().catch(() => false)) await confirm([runningWarning]);
    console.log(`${arg} will no longer be mounted. The folder on the host is untouched.`);
    await changeMounts(mounts, kept);
  } else throw Error("Use start, stop, clean, mounts, mount [--ro] <folder>, or unmount <folder>");
} catch (e) {
  console.error((e as Error).message);
  process.exitCode = 1;
}
