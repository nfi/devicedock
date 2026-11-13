//! Port of apps/server/sandbox.ts: the hardened sandbox container and the health probe.
use crate::workspace::{self, Bind, Mount};
use rand::RngCore;
use serde_json::{json, Value};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

pub const CONTAINER: &str = "devicedock-sandbox";
pub const BRIDGE_PORT: u16 = 47832;
pub const IMAGE: &str = "devicedock-sandbox:local";

pub fn random_hex() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

pub async fn docker_timeout(args: &[&str], secs: u64) -> Result<String, String> {
    let out = Command::new("docker").args(args).stdin(Stdio::null()).kill_on_drop(true).output();
    let out = tokio::time::timeout(Duration::from_secs(secs), out)
        .await
        .map_err(|_| format!("docker {} timed out", args.first().unwrap_or(&"")))?
        .map_err(|e| format!("docker: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("Command failed: docker {}\n{}", args.join(" "), err.trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
pub async fn docker(args: &[&str]) -> Result<String, String> {
    docker_timeout(args, 120).await
}

pub async fn health() -> Value {
    let (mut docker_ok, mut container, mut agent) = (false, false, false);
    let mut error = None;
    let r: Result<(), String> = async {
        docker_timeout(&["info", "--format", "{{.ServerVersion}}"], 5).await?;
        docker_ok = true;
        container = docker(&["inspect", "--format", "{{.State.Running}}", CONTAINER]).await? == "true";
        if container {
            docker(&["exec", CONTAINER, "codex", "--version"]).await?;
            agent = true;
        }
        Ok(())
    }
    .await;
    if let Err(e) = r {
        error = Some(e.chars().take(350).collect::<String>());
    }
    let mut v = json!({"docker": docker_ok, "container": container, "agent": agent});
    if let Some(e) = error {
        v["error"] = json!(e);
    }
    v
}

pub fn bridge_token() -> std::io::Result<String> {
    Ok(std::fs::read_to_string(".runtime/bridge-token")?.trim().to_string())
}

pub async fn verify_managed() -> Result<(), String> {
    let label = docker(&["inspect", "--format", "{{index .Config.Labels \"devicedock.managed\"}}", CONTAINER]).await?;
    if label != "true" {
        return Err("A container with this name already exists and is not managed by DeviceDock".into());
    }
    Ok(())
}

async fn sandbox_exists() -> Result<bool, String> {
    let filter = format!("name=^/{CONTAINER}$");
    let names = docker(&["container", "ls", "--all", "--filter", &filter, "--format", "{{.Names}}"]).await?;
    Ok(names.lines().any(|n| n.trim() == CONTAINER))
}

pub fn ensure_runtime_dir() -> std::io::Result<()> {
    std::fs::create_dir_all(".runtime")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(".runtime", std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Writes a secret file readable only by the user (mode 0600).
pub fn write_secret(path: &str, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?.write_all(content.as_bytes())
}

const MOUNTS_FILE: &str = ".runtime/mounts.json";

/// Host folders the user chose to mount into the sandbox (see workspace.rs). Same file as the Node backend.
pub fn read_mounts() -> Result<Vec<Mount>, String> {
    let unreadable = |e: String| format!("{MOUNTS_FILE} is unreadable: {e}");
    match std::fs::read_to_string(MOUNTS_FILE) {
        Ok(text) => {
            let value: Value = serde_json::from_str(&text).map_err(|e| unreadable(e.to_string()))?;
            workspace::parse_mounts(&value).map_err(unreadable)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(unreadable(e.to_string())),
    }
}
fn write_mounts(mounts: &[Mount]) -> Result<(), String> {
    ensure_runtime_dir().map_err(|e| e.to_string())?;
    let text = serde_json::to_string_pretty(&workspace::serialize_mounts(mounts)).map_err(|e| e.to_string())? + "\n";
    write_secret(MOUNTS_FILE, &text).map_err(|e| e.to_string())
}
fn with_roots<T>(check: impl FnOnce(&workspace::Roots) -> Result<T, String>) -> Result<T, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    let project = std::env::current_dir().map_err(|e| e.to_string())?;
    check(&workspace::Roots { home: Path::new(&home), project_root: &project, fs: &workspace::RealFs })
}
fn resolve_mounts(mounts: &[Mount]) -> Result<Vec<Bind>, String> {
    with_roots(|roots| workspace::resolve_mounts(mounts, roots))
}
fn mode(read_only: bool) -> &'static str {
    if read_only {
        "read-only"
    } else {
        "read-write"
    }
}
/// Bind mounts of the existing container as "<destination> rw|ro", sorted.
async fn current_binds() -> Result<Vec<String>, String> {
    let format = r#"{{range .Mounts}}{{if eq .Type "bind"}}{{.Destination}} {{if .RW}}rw{{else}}ro{{end}}{{"\n"}}{{end}}{{end}}"#;
    let out = docker(&["inspect", "--format", format, CONTAINER]).await?;
    let mut binds: Vec<String> = out.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
    binds.sort_unstable();
    Ok(binds)
}

pub fn list_mounts() -> Result<(), String> {
    let mounts = read_mounts()?;
    for m in &mounts {
        println!("{}  ->  {}  ({})", m.path, workspace::mount_target(Path::new(&m.path))?, mode(m.read_only));
    }
    if mounts.is_empty() {
        println!("No host folders are mounted.");
    }
    Ok(())
}

const RUNNING_WARNING: &str = "The sandbox is running. Changing mounts recreates its container:\n\
    agent sessions, terminals and builds running in it end now. Volumes and logins are kept.";

/// Whether the managed container runs; None when there is no container. An error means Docker is not reachable.
async fn container_running() -> Result<Option<bool>, String> {
    if !sandbox_exists().await? {
        return Ok(None);
    }
    verify_managed().await?;
    Ok(Some(docker(&["inspect", "--format", "{{.State.Running}}", CONTAINER]).await? == "true"))
}

/// Shows what the change means and asks before going on. No warnings, no question.
fn confirm(warnings: &[String]) -> Result<(), String> {
    use std::io::Write;
    if warnings.is_empty() {
        return Ok(());
    }
    for warning in warnings {
        println!("{warning}");
    }
    print!("Continue? [y/N] ");
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer).map_err(|e| e.to_string())?;
    if answer.trim() == "y" {
        Ok(())
    } else {
        Err("nothing changed".into())
    }
}

/// Mount points that already hold something in the workspace volume. The sandbox can write there, so a symlink
/// could send a mount somewhere else in the container and existing files would be hidden. The empty folder Docker
/// leaves behind from an earlier mount is fine. Looked at from a throwaway container: the sandbox may not exist.
async fn taken_targets(targets: &[&str]) -> Result<Vec<String>, String> {
    const CHECK: &str = r#"for p; do if [ -L "$p" ] || { [ -e "$p" ] && { [ ! -d "$p" ] || [ -n "$(ls -A "$p")" ]; }; }; then echo "$p"; fi; done"#;
    if targets.is_empty() {
        return Ok(vec![]);
    }
    let mut args = vec![
        "run", "--rm", "--network", "none", "--user", "1000:1000", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--read-only", "--mount", "type=volume,src=devicedock-workspace,dst=/workspace", "--entrypoint", "sh", IMAGE,
        "-c", CHECK, "sh",
    ];
    args.extend(targets);
    Ok(docker(&args).await?.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect())
}
fn taken_message(taken: &[String]) -> String {
    format!(
        "{} already exists in the sandbox's workspace volume. Rename or remove it there (./devicedock.sh, then sh), \
         or unmount the folder.",
        taken.join(", ")
    )
}

pub async fn add_mount(arg: &str, read_only: bool) -> Result<(), String> {
    let given = std::path::absolute(arg).map_err(|e| e.to_string())?;
    let dir = with_roots(|roots| workspace::validate_workspace_path(&given.to_string_lossy(), roots, true))?;
    let target = workspace::mount_target(&dir)?;
    let path = dir.to_string_lossy().into_owned();
    let previous = read_mounts()?;
    let existing = previous.iter().find(|m| m.path == path);
    if existing.is_some_and(|m| m.read_only == read_only) {
        println!("{path} is already mounted {} at {target}. Nothing changed.", mode(read_only));
        return Ok(());
    }
    // Mounting a folder again changes its mode.
    let mut mounts: Vec<Mount> = previous.iter().filter(|m| m.path != path).cloned().collect();
    mounts.push(Mount { path: path.clone(), read_only });
    resolve_mounts(&mounts)?;

    let state = container_running().await;
    let mut warnings = vec![];
    if existing.is_some_and(|m| m.read_only) {
        warnings.push(format!("{path} is mounted read-only now. Read-write lets the sandbox change everything in it."));
    }
    if existing.is_none() {
        // Without Docker this is checked when the sandbox is next created.
        if let Ok(taken) = taken_targets(&[target.as_str()]).await {
            if !taken.is_empty() {
                return Err(taken_message(&taken));
            }
        }
        let sensitive = workspace::find_sensitive(&dir);
        if !sensitive.is_empty() {
            let shown: Vec<&str> = sensitive.iter().take(15).map(String::as_str).collect();
            let more = if sensitive.len() > shown.len() { format!("\n  ... and {} more", sensitive.len() - shown.len()) } else { String::new() };
            warnings.push(format!(
                "These look like credentials. The sandbox has internet access and will be able to read them:\n  {}{more}",
                shown.join("\n  ")
            ));
        }
    }
    if matches!(state, Ok(Some(true))) {
        warnings.push(RUNNING_WARNING.into());
    }
    confirm(&warnings)?;
    println!("{path} will be mounted {} at {target}.", mode(read_only));
    change_mounts(&previous, &mounts).await
}

/// Saves the new list and applies it. If the sandbox cannot be recreated with it, the old list is put back.
async fn change_mounts(previous: &[Mount], next: &[Mount]) -> Result<(), String> {
    write_mounts(next)?;
    if let Err(e) = apply_mounts().await {
        write_mounts(previous)?;
        let restored = match Box::pin(start_sandbox()).await {
            Ok(()) => "the sandbox is running with the previous mounts",
            Err(_) => "the sandbox could not be restarted",
        };
        return Err(format!("{e}\nThe mount list was left unchanged; {restored}."));
    }
    Ok(())
}

pub async fn remove_mount(arg: &str) -> Result<(), String> {
    let given = std::path::absolute(arg).map_err(|e| e.to_string())?;
    let mounts = read_mounts()?;
    let named = |m: &Mount| Path::new(&m.path).file_name().is_some_and(|n| n == arg);
    let kept: Vec<Mount> = mounts.iter().filter(|m| Path::new(&m.path) != given && !named(m)).cloned().collect();
    if kept.len() == mounts.len() {
        return Err(format!("{arg} is not mounted"));
    }
    if matches!(container_running().await, Ok(Some(true))) {
        confirm(&[RUNNING_WARNING.into()])?;
    }
    println!("{arg} will no longer be mounted. The folder on the host is untouched.");
    change_mounts(&mounts, &kept).await
}

/// Mounts are fixed at container creation: remove the container so the next start creates it with the new list.
async fn apply_mounts() -> Result<(), String> {
    let running = match container_running().await {
        Ok(Some(running)) => running,
        Ok(None) => {
            println!("Takes effect when the sandbox is started.");
            return Ok(());
        }
        Err(_) => {
            println!("Docker is not reachable: takes effect the next time the sandbox is started.");
            return Ok(());
        }
    };
    docker(&["rm", "-f", CONTAINER]).await?;
    if running {
        start_sandbox().await?;
        println!("Sandbox recreated with the new mounts (volumes kept).");
    } else {
        println!("Takes effect when the sandbox is started.");
    }
    Ok(())
}

pub async fn start_sandbox() -> Result<(), String> {
    ensure_runtime_dir().map_err(|e| e.to_string())?;
    let token = match bridge_token() {
        Ok(t) if !t.is_empty() => t,
        _ => {
            let t = random_hex();
            write_secret(".runtime/bridge-token", &t).map_err(|e| e.to_string())?;
            t
        }
    };
    // Validated on every start: a folder may have changed since it was added.
    let mounts = resolve_mounts(&read_mounts()?)
        .map_err(|e| format!("{e}\nFix the folder, or remove it with ./devicedock.sh unmount <name>."))?;
    let mut exists = sandbox_exists().await?;
    let mut recreate = false;
    if exists {
        verify_managed().await?;
        // Mounts are fixed when a container is created, so a changed list or mode needs a new container (volumes are kept).
        let mut wanted: Vec<String> =
            mounts.iter().map(|b| format!("{} {}", b.target, if b.read_only { "ro" } else { "rw" })).collect();
        wanted.sort_unstable();
        recreate = current_binds().await? != wanted;
    }
    if !exists || recreate {
        // Checked before the old container is removed: a refusal must leave a running sandbox alone.
        docker(&["volume", "create", "devicedock-workspace"]).await?;
        docker(&["volume", "create", "devicedock-home"]).await?;
        let taken = taken_targets(&mounts.iter().map(|b| b.target.as_str()).collect::<Vec<_>>()).await?;
        if !taken.is_empty() {
            return Err(taken_message(&taken));
        }
    }
    if recreate {
        println!("Mounted folders changed: recreating the sandbox container (volumes are kept).");
        docker(&["rm", "-f", CONTAINER]).await?;
        exists = false;
    }
    if exists {
        docker(&["start", CONTAINER]).await?;
    } else {
        let publish = format!("127.0.0.1:{BRIDGE_PORT}:47832");
        let binds: Vec<String> = mounts.iter().map(Bind::arg).collect();
        let mut args = vec![
            "run", "-d", "--name", CONTAINER, "--label", "devicedock.managed=true", "--user", "1000:1000",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--cpus=2", "--memory=2g", "--pids-limit=256",
            "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
            "--mount", "type=volume,src=devicedock-workspace,dst=/workspace",
            "--mount", "type=volume,src=devicedock-home,dst=/home/node",
        ];
        for bind in &binds {
            args.extend(["--mount", bind.as_str()]);
        }
        args.extend(["-p", &publish, IMAGE]);
        docker(&args).await?;
    }
    // Send the token over stdin, never in command arguments or Docker environment metadata.
    let mut p = Command::new("docker")
        .args(["exec", "-i", CONTAINER, "sh", "-c", "umask 077; cat > /home/node/.bridge-token"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut stdin = p.stdin.take().unwrap();
    stdin.write_all(token.as_bytes()).await.map_err(|e| e.to_string())?;
    drop(stdin);
    let status = p.wait().await.map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("Could not provision bridge token".into());
    }
    Ok(())
}

pub async fn stop_sandbox() -> Result<(), String> {
    verify_managed().await?;
    docker(&["stop", CONTAINER]).await.map(|_| ())
}

pub async fn clean_sandbox() -> Result<(), String> {
    verify_managed().await?;
    docker(&["rm", "-f", CONTAINER]).await.map(|_| ())
}
