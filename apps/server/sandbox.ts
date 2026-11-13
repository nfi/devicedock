import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { bindArg, parseMounts, resolveMounts, type Bind, type Mount } from "./workspace.ts";
const exec = promisify(execFile);
const mountsFile = ".runtime/mounts.json";
/** Host folders the user chose to mount into the sandbox (see workspace.ts). */
export async function readMounts(): Promise<Mount[]> {
  try {
    return parseMounts(JSON.parse(await readFile(mountsFile, "utf8")));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw Error(`${mountsFile} is unreadable: ${(e as Error).message}`);
  }
}
export async function writeMounts(mounts: Mount[]) {
  await mkdir(".runtime", { recursive: true, mode: 0o700 });
  await writeFile(mountsFile, JSON.stringify(mounts.map(({ path, readOnly }) => ({ path, readOnly })), null, 2) + "\n", { mode: 0o600 });
}
/** Bind mounts of the existing container as "<destination> rw|ro", sorted. */
async function currentBinds() {
  const out = await docker([
    "inspect",
    "--format",
    '{{range .Mounts}}{{if eq .Type "bind"}}{{.Destination}} {{if .RW}}rw{{else}}ro{{end}}{{"\n"}}{{end}}{{end}}',
    container,
  ]);
  return out.split("\n").map((l) => l.trim()).filter(Boolean).sort();
}
/**
 * Mount points that already hold something in the workspace volume. The sandbox can write there, so a symlink could
 * send a mount somewhere else in the container and existing files would be hidden. The empty folder Docker leaves
 * behind from an earlier mount is fine. Looked at from a throwaway container: the sandbox may not exist.
 */
export async function takenTargets(targets: string[]): Promise<string[]> {
  if (!targets.length) return [];
  const check = 'for p; do if [ -L "$p" ] || { [ -e "$p" ] && { [ ! -d "$p" ] || [ -n "$(ls -A "$p")" ]; }; }; then echo "$p"; fi; done';
  const out = await docker([
    "run", "--rm", "--network", "none", "--user", "1000:1000", "--cap-drop=ALL", "--security-opt=no-new-privileges",
    "--read-only", "--mount", "type=volume,src=devicedock-workspace,dst=/workspace", "--entrypoint", "sh",
    "devicedock-sandbox:local", "-c", check, "sh", ...targets,
  ]);
  return out.split("\n").map((l) => l.trim()).filter(Boolean);
}
export const takenMessage = (taken: string[]) =>
  `${taken.join(", ")} already exists in the sandbox's workspace volume. Rename or remove it there (./devicedock.sh, then sh), or unmount the folder.`;
export const container = "devicedock-sandbox";
export const bridgePort = 47832;
export async function docker(args: string[]) {
  return (
    await exec("docker", args, { timeout: 120000, maxBuffer: 1024 * 1024 })
  ).stdout.trim();
}
export async function health() {
  const result: {
    docker: boolean;
    container: boolean;
    agent: boolean;
    error?: string;
  } = { docker: false, container: false, agent: false };
  try {
    await exec("docker", ["info", "--format", "{{.ServerVersion}}"], {
      timeout: 5000,
    });
    result.docker = true;
    result.container =
      (await docker([
        "inspect",
        "--format",
        "{{.State.Running}}",
        container,
      ])) === "true";
    if (result.container) {
      await docker(["exec", container, "codex", "--version"]);
      result.agent = true;
    }
  } catch (e) {
    result.error = (e as Error).message.slice(0, 350);
  }
  return result;
}
export async function getBridgeToken() {
  return (await readFile(".runtime/bridge-token", "utf8")).trim();
}
export async function verifyManaged() {
  const label = await docker([
    "inspect",
    "--format",
    '{{index .Config.Labels "devicedock.managed"}}',
    container,
  ]);
  if (label !== "true")
    throw Error(
      "A container with this name already exists and is not managed by DeviceDock",
    );
}
export async function sandboxExists(run: typeof docker = docker) {
  const names = await run([
    "container", "ls", "--all",
    "--filter", `name=^/${container}$`,
    "--format", "{{.Names}}",
  ]);
  return names.split("\n").some(name => name.trim() === container);
}
export async function startSandbox() {
  await mkdir(".runtime", { recursive: true, mode: 0o700 });
  let token: string;
  try {
    token = await getBridgeToken();
  } catch {
    token = randomBytes(32).toString("hex");
    await writeFile(".runtime/bridge-token", token, { mode: 0o600 });
  }
  // Validated on every start: a folder may have changed since it was added.
  let binds: Bind[];
  try {
    binds = resolveMounts(await readMounts(), { projectRoot: process.cwd() });
  } catch (e) {
    throw Error(`${(e as Error).message}\nFix the folder, or remove it with ./devicedock.sh unmount <name>.`);
  }
  const wanted = binds.map((b) => `${b.target} ${b.readOnly ? "ro" : "rw"}`).sort();
  let exists = await sandboxExists();
  let recreate = false;
  if (exists) {
    await verifyManaged();
    // Mounts are fixed when a container is created, so a changed list or mode needs a new container (volumes are kept).
    recreate = (await currentBinds()).join("\n") !== wanted.join("\n");
  }
  if (!exists || recreate) {
    // Checked before the old container is removed: a refusal must leave a running sandbox alone.
    await docker(["volume", "create", "devicedock-workspace"]);
    await docker(["volume", "create", "devicedock-home"]);
    const taken = await takenTargets(binds.map((b) => b.target));
    if (taken.length) throw Error(takenMessage(taken));
  }
  if (recreate) {
    console.log("Mounted folders changed: recreating the sandbox container (volumes are kept).");
    await docker(["rm", "-f", container]);
    exists = false;
  }
  if (exists) {
    await docker(["start", container]);
  } else {
    await docker([
      "run",
      "-d",
      "--name",
      container,
      "--label",
      "devicedock.managed=true",
      "--user",
      "1000:1000",
      "--cap-drop=ALL",
      "--security-opt=no-new-privileges",
      "--cpus=2",
      "--memory=2g",
      "--pids-limit=256",
      "--read-only",
      "--tmpfs",
      "/tmp:rw,nosuid,nodev,size=256m",
      "--mount",
      "type=volume,src=devicedock-workspace,dst=/workspace",
      "--mount",
      "type=volume,src=devicedock-home,dst=/home/node",
      ...binds.flatMap((b) => ["--mount", bindArg(b)]),
      "-p",
      `127.0.0.1:${bridgePort}:47832`,
      "devicedock-sandbox:local",
    ]);
  }
  // Send the token over stdin, never in command arguments or Docker environment metadata.
  await new Promise<void>((resolve, reject) => {
    const p = spawn(
      "docker",
      [
        "exec",
        "-i",
        container,
        "sh",
        "-c",
        "umask 077; cat > /home/node/.bridge-token",
      ],
      { stdio: ["pipe", "ignore", "pipe"] },
    );
    p.on("error", reject);
    p.on("exit", (code) =>
      code === 0
        ? resolve()
        : reject(Error("Could not provision bridge token")),
    );
    p.stdin.end(token);
  });
}
