//! Port of apps/server/workspace.ts: validation of host folders the user chose to mount into the sandbox.
//!
//! Each folder is bind-mounted at /workspace/<folder name>, read-write or read-only; /workspace itself stays the devicedock-workspace Docker
//! volume (the bridge service writes AGENTS.md and CLAUDE.md there). This relaxes "nothing from the host is
//! mounted", so every folder is validated hard:
//!   - it must be a dedicated directory strictly inside the home folder (Docker only shares that by default),
//!   - never the home folder itself, "/", any ancestor of home, or the DeviceDock project or anything above it,
//!   - inside the DeviceDock project only a separate git checkout, never .runtime (bridge token), .git or node_modules,
//!   - never inside or containing a credential/config directory, and never holding credential files at its top level.
//!
//! An agent in autonomous mode can modify everything inside a read-write folder, including any .git/config and hooks.
//! See SECURITY.md: do not run git inside it on the host, fetch from it into another clone instead.
use serde_json::{json, Value};
use std::path::{Component, Path, PathBuf};

/// Directories under $HOME that hold credentials or app state; a mount must be neither inside nor above them.
pub const SENSITIVE_HOME_DIRS: &[&str] = &[
    ".ssh", ".aws", ".gnupg", ".config", ".kube", ".docker", ".azure", ".npm", ".netrc", ".claude", ".codex",
    ".colima", ".lima", "Library", ".local", ".cache", ".password-store",
];
/// Files whose presence at the top of the folder means it is not a plain project folder.
pub const SENSITIVE_TOP_LEVEL: &[&str] =
    &[".ssh", ".aws", ".gnupg", ".netrc", ".env", "id_rsa", "id_ed25519", ".npmrc", "credentials.json"];
/// Parts of the DeviceDock project that must never be reachable from the sandbox.
pub const PROJECT_PRIVATE: &[&str] = &[".runtime", ".git", "node_modules"];

pub trait FsProbe {
    fn real(&self, p: &Path) -> Result<PathBuf, String>;
    fn is_dir(&self, p: &Path) -> bool;
    fn list(&self, p: &Path) -> Vec<String>;
}
pub struct RealFs;
impl FsProbe for RealFs {
    fn real(&self, p: &Path) -> Result<PathBuf, String> {
        std::fs::canonicalize(p).map_err(|e| format!("{}: {e}", p.display()))
    }
    fn is_dir(&self, p: &Path) -> bool {
        p.is_dir()
    }
    fn list(&self, p: &Path) -> Vec<String> {
        std::fs::read_dir(p)
            .map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
            .unwrap_or_default()
    }
}

pub struct Roots<'a> {
    pub home: &'a Path,
    pub project_root: &'a Path,
    pub fs: &'a dyn FsProbe,
}

/// Returns the resolved folder, or an error explaining exactly why it is refused.
///
/// The sandbox can change what a mounted folder contains, so the content checks run only when a folder is added
/// (`check_contents`); otherwise an agent could block the next start by creating a .env file.
pub fn validate_workspace_path(input: &str, roots: &Roots, check_contents: bool) -> Result<PathBuf, String> {
    let fs = roots.fs;
    let home = fs.real(roots.home)?;
    let given = Path::new(input);
    if input.is_empty() || !given.is_absolute() {
        return Err("The workspace folder must be an absolute path".into());
    }
    if !fs.is_dir(given) {
        return Err(format!("{input} is not an existing directory"));
    }
    let dir = fs.real(given)?; // follows symlinks, so a link cannot smuggle in another place
    let project = fs.real(roots.project_root)?;
    let shown = dir.display();

    if dir.parent().is_none() {
        return Err("Refusing \"/\" as the workspace".into());
    }
    if home.starts_with(&dir) {
        return Err("Refusing your home folder (or a folder above it): use a dedicated subfolder".into());
    }
    if !dir.starts_with(&home) {
        return Err(format!("The workspace must be inside your home folder ({}); Docker only shares that", home.display()));
    }
    if project.starts_with(&dir) {
        return Err("Refusing the DeviceDock project folder (it holds the bridge token) or a folder above it".into());
    }
    if let Ok(rel) = dir.strip_prefix(&project) {
        let private = rel.components().any(|c| match c {
            Component::Normal(n) => PROJECT_PRIVATE.iter().any(|p| n == std::ffi::OsStr::new(p)),
            _ => false,
        });
        if private {
            return Err(format!("Refusing {shown}: {} of the DeviceDock project are never shared", PROJECT_PRIVATE.join(", ")));
        }
        if check_contents && !fs.list(&dir).iter().any(|n| n == ".git") {
            return Err(format!("Refusing {shown}: inside the DeviceDock project only a separate git checkout can be mounted"));
        }
    }
    for s in SENSITIVE_HOME_DIRS {
        if dir.starts_with(home.join(s)) {
            return Err(format!("Refusing {shown}: inside ~/{s}, which holds credentials or app state"));
        }
    }
    let top = if check_contents { fs.list(&dir) } else { vec![] };
    let found: Vec<&str> = SENSITIVE_TOP_LEVEL.iter().copied().filter(|n| top.iter().any(|t| t == n)).collect();
    if !found.is_empty() {
        return Err(format!("Refusing {shown}: it contains {}, which looks like credentials, not a project folder", found.join(", ")));
    }
    Ok(dir)
}

/// Where a validated folder appears in the sandbox: /workspace/<folder name>.
pub fn mount_target(dir: &Path) -> Result<String, String> {
    let shown = dir.display();
    let path = dir.to_str().ok_or_else(|| format!("Cannot mount {shown}: the path is not valid UTF-8"))?;
    let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let ok_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) || !name.chars().all(ok_char) {
        return Err(format!("Cannot mount {shown}: the folder name may only contain letters, digits, \".\", \"_\" and \"-\""));
    }
    if path.contains([',', '"', '\n']) {
        return Err(format!("Cannot mount {shown}: the path contains a comma, quote or line break"));
    }
    if name == "AGENTS.md" || name == "CLAUDE.md" {
        return Err(format!("Cannot mount a folder named {name}"));
    }
    Ok(format!("/workspace/{name}"))
}

/// Names that suggest credentials anywhere below a mounted folder.
fn sensitive_name(name: &str) -> bool {
    const EXACT: &[&str] = &[".git-credentials", ".pypirc", "id_ecdsa", "id_dsa"];
    const TEMPLATES: &[&str] = &[".example", ".sample", ".template", ".dist"];
    SENSITIVE_TOP_LEVEL.contains(&name)
        || EXACT.contains(&name)
        || (name.starts_with(".env.") && !TEMPLATES.iter().any(|t| name.ends_with(t)))
        || [".pem", ".key", ".p12", ".pfx"].iter().any(|ext| name.ends_with(ext))
}
/// True when a git config holds a password or token inside a URL (https://user:secret@host/...).
fn url_with_credentials(config: &str) -> bool {
    config.lines().any(|line| {
        line.split_once("://").is_some_and(|(_, rest)| {
            let authority = rest.split(['/', ' ', '\t']).next().unwrap_or("");
            authority.split_once('@').is_some_and(|(user, _)| user.contains(':'))
        })
    })
}

/// Paths below `dir` that look like credentials, relative to it. The sandbox can read (and, with internet access,
/// send away) everything in a mounted folder, so these are shown to the user before a folder is added. The walk is
/// bounded and never follows symlinks; it is a hint, not a guarantee.
pub fn find_sensitive(dir: &Path) -> Vec<String> {
    const MAX_DEPTH: usize = 6;
    const MAX_ENTRIES: usize = 50_000;
    const SKIP: &[&str] = &["node_modules", "target", "build"];
    let mut found = vec![];
    let mut seen = 0;
    let mut stack = vec![(dir.to_path_buf(), 0)];
    while let Some((current, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else { continue };
        for entry in entries.flatten() {
            seen += 1;
            if seen > MAX_ENTRIES {
                return found;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            let shown = || path.strip_prefix(dir).unwrap_or(&path).to_string_lossy().into_owned();
            let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
            if sensitive_name(&name) {
                found.push(shown());
            } else if is_dir && name == ".git" {
                if std::fs::read_to_string(path.join("config")).is_ok_and(|c| url_with_credentials(&c)) {
                    found.push(format!("{} (a password or token in a remote URL)", Path::new(&shown()).join("config").display()));
                }
            } else if is_dir && depth < MAX_DEPTH && !SKIP.contains(&name.as_str()) {
                stack.push((path, depth + 1));
            }
        }
    }
    found.sort();
    found
}

/// One configured folder. Read-only folders cannot be changed from the sandbox at all.
#[derive(Clone, Debug, PartialEq)]
pub struct Mount {
    pub path: String,
    pub read_only: bool,
}
/// A validated mount: host folder, container path, mode.
#[derive(Debug, PartialEq)]
pub struct Bind {
    pub dir: String,
    pub target: String,
    pub read_only: bool,
}
impl Bind {
    /// The `docker run --mount` value.
    pub fn arg(&self) -> String {
        format!("type=bind,src={},dst={}{}", self.dir, self.target, if self.read_only { ",readonly" } else { "" })
    }
}

/// Reads the stored list: every entry is {"path": ..., "readOnly": true|false}.
pub fn parse_mounts(value: &Value) -> Result<Vec<Mount>, String> {
    let list = value.as_array().ok_or("expected a list of folders")?;
    list.iter()
        .map(|entry| {
            let path = entry.get("path").and_then(Value::as_str).ok_or("every entry needs a path")?;
            // A missing or malformed flag must not quietly turn a read-only folder into a writable one.
            let read_only =
                entry.get("readOnly").and_then(Value::as_bool).ok_or_else(|| format!("readOnly of {path} must be true or false"))?;
            Ok(Mount { path: path.into(), read_only })
        })
        .collect()
}
pub fn serialize_mounts(mounts: &[Mount]) -> Value {
    mounts.iter().map(|m| json!({"path": m.path, "readOnly": m.read_only})).collect()
}

/// Validates every configured folder (without the content checks). A folder inside another mounted folder is
/// refused: the sandbox could replace it with a symlink and have a different host folder mounted on the next start.
pub fn resolve_mounts(mounts: &[Mount], roots: &Roots) -> Result<Vec<Bind>, String> {
    let mut out: Vec<Bind> = vec![];
    for mount in mounts {
        let path = validate_workspace_path(&mount.path, roots, false)?;
        let target = mount_target(&path)?;
        let dir = path.to_string_lossy().into_owned();
        match out.iter().find(|b| b.target == target) {
            Some(same) if same.dir != dir => {
                return Err(format!("{dir} and {} would both be mounted at {target}", same.dir))
            }
            Some(_) => continue,
            None => {}
        }
        if let Some(nested) = out.iter().find(|b| path.starts_with(&b.dir) || Path::new(&b.dir).starts_with(&path)) {
            return Err(format!("{dir} and {} cannot both be mounted: one is inside the other", nested.dir));
        }
        out.push(Bind { dir, target, read_only: mount.read_only });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct FakeFs(HashMap<&'static str, Vec<&'static str>>);
    impl FsProbe for FakeFs {
        fn real(&self, p: &Path) -> Result<PathBuf, String> {
            Ok(p.to_path_buf())
        }
        fn is_dir(&self, p: &Path) -> bool {
            self.0.contains_key(p.to_str().unwrap())
        }
        fn list(&self, p: &Path) -> Vec<String> {
            self.0.get(p.to_str().unwrap()).map(|v| v.iter().map(|s| s.to_string()).collect()).unwrap_or_default()
        }
    }
    const HOME: &str = "/Users/me";
    const PROJECT: &str = "/Users/me/work/devicedock";
    fn fake() -> FakeFs {
        FakeFs(HashMap::from([
            (HOME, vec![]),
            (PROJECT, vec![".git", ".runtime", "apps"]),
            ("/Users/me/work/devicedock/contiki-ng", vec![".git", "Makefile.include"]),
            ("/Users/me/work/devicedock/apps", vec!["server"]),
            ("/Users/me/work/devicedock/.runtime", vec![]),
            ("/Users/me/work/devicedock/node_modules/pkg", vec![".git"]),
            ("/Users/me/work", vec![]),
            ("/Users/me/src/contiki-ng", vec![".git"]),
            ("/Users/me/src/secrets", vec![".env"]),
            ("/Users/me/.ssh", vec![]),
            ("/opt/x", vec![]),
            ("/Users/me/src/contiki-ng/examples", vec![]),
            ("/Users/me/src/other", vec![".git"]),
            ("/Users/me/work/devicedock/co", vec![]),
        ]))
    }
    fn check(input: &str) -> Result<PathBuf, String> {
        let fs = fake();
        validate_workspace_path(input, &Roots { home: Path::new(HOME), project_root: Path::new(PROJECT), fs: &fs }, true)
    }
    fn rw(paths: &[&str]) -> Vec<Mount> {
        paths.iter().map(|p| Mount { path: p.to_string(), read_only: false }).collect()
    }
    fn refused(input: &str, why: &str) {
        let e = check(input).unwrap_err();
        assert!(e.contains(why), "{input}: {e}");
    }

    #[test]
    fn accepts_dedicated_folders_and_checkouts_inside_the_project() {
        assert_eq!(check("/Users/me/src/contiki-ng").unwrap(), Path::new("/Users/me/src/contiki-ng"));
        assert_eq!(check("/Users/me/work/devicedock/contiki-ng").unwrap(), Path::new("/Users/me/work/devicedock/contiki-ng"));
    }
    #[test]
    fn refuses_the_project_its_own_folders_and_its_private_parts() {
        refused(PROJECT, "DeviceDock project folder");
        refused("/Users/me/work", "DeviceDock project folder");
        refused("/Users/me/work/devicedock/apps", "separate git checkout");
        refused("/Users/me/work/devicedock/.runtime", "never shared");
        refused("/Users/me/work/devicedock/node_modules/pkg", "never shared");
    }
    #[test]
    fn refuses_home_outside_home_and_credentials() {
        refused(HOME, "home folder");
        refused("/opt/x", "inside your home folder");
        refused("/Users/me/.ssh", "credentials");
        refused("/Users/me/src/secrets", ".env");
        refused("contiki-ng", "absolute");
        refused("/Users/me/src/missing", "not an existing directory");
    }
    #[test]
    fn mounts_folders_below_workspace_under_their_own_name() {
        assert_eq!(mount_target(Path::new("/Users/me/src/contiki-ng")).unwrap(), "/workspace/contiki-ng");
        assert!(mount_target(Path::new("/Users/me/src/bad,name")).is_err());
        assert!(mount_target(Path::new("/Users/me/a,b/ok")).is_err());
        let fs = fake();
        let roots = Roots { home: Path::new(HOME), project_root: Path::new(PROJECT), fs: &fs };
        assert_eq!(
            resolve_mounts(&rw(&["/Users/me/src/contiki-ng", "/Users/me/src/contiki-ng"]), &roots).unwrap(),
            vec![Bind { dir: "/Users/me/src/contiki-ng".into(), target: "/workspace/contiki-ng".into(), read_only: false }]
        );
        let clash = rw(&["/Users/me/src/contiki-ng", "/Users/me/work/devicedock/contiki-ng"]);
        assert!(resolve_mounts(&clash, &roots).unwrap_err().contains("both be mounted"));
        assert!(resolve_mounts(&[], &roots).unwrap().is_empty());
    }
    #[test]
    fn refuses_a_folder_inside_another_mounted_folder_in_either_order() {
        let fs = fake();
        let roots = Roots { home: Path::new(HOME), project_root: Path::new(PROJECT), fs: &fs };
        let (outer, inner) = ("/Users/me/src/contiki-ng", "/Users/me/src/contiki-ng/examples");
        assert!(resolve_mounts(&rw(&[outer, inner]), &roots).unwrap_err().contains("one is inside the other"));
        assert!(resolve_mounts(&rw(&[inner, outer]), &roots).unwrap_err().contains("one is inside the other"));
        assert_eq!(resolve_mounts(&rw(&[outer, "/Users/me/src/other"]), &roots).unwrap().len(), 2);
    }
    #[test]
    fn content_checks_apply_when_a_folder_is_added_not_on_later_starts() {
        refused("/Users/me/src/secrets", ".env");
        refused("/Users/me/work/devicedock/co", "separate git checkout");
        let fs = fake();
        let roots = Roots { home: Path::new(HOME), project_root: Path::new(PROJECT), fs: &fs };
        let later = rw(&["/Users/me/src/secrets", "/Users/me/work/devicedock/co"]);
        assert_eq!(resolve_mounts(&later, &roots).unwrap().len(), 2);
    }
    #[test]
    fn read_only_folders_are_mounted_readonly() {
        let fs = fake();
        let roots = Roots { home: Path::new(HOME), project_root: Path::new(PROJECT), fs: &fs };
        let mounts = vec![
            Mount { path: "/Users/me/src/contiki-ng".into(), read_only: true },
            Mount { path: "/Users/me/src/other".into(), read_only: false },
        ];
        let args: Vec<String> = resolve_mounts(&mounts, &roots).unwrap().iter().map(Bind::arg).collect();
        assert_eq!(
            args,
            ["type=bind,src=/Users/me/src/contiki-ng,dst=/workspace/contiki-ng,readonly", "type=bind,src=/Users/me/src/other,dst=/workspace/other"]
        );
        let stored = serialize_mounts(&mounts);
        let expected = json!([{"path": "/Users/me/src/contiki-ng", "readOnly": true}, {"path": "/Users/me/src/other", "readOnly": false}]);
        assert_eq!(stored, expected);
        assert_eq!(parse_mounts(&stored).unwrap(), mounts);
    }
    #[test]
    fn finds_nested_files_that_look_like_credentials() {
        let dir = std::env::temp_dir().join(format!("devicedock-sensitive-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for sub in ["conf/deep", ".git", "node_modules/pkg", "docs"] {
            std::fs::create_dir_all(dir.join(sub)).unwrap();
        }
        for (file, text) in [
            ("conf/deep/.env.production", ""),
            ("conf/.env.example", ""),
            ("conf/server.key", ""),
            ("docs/readme.md", ""),
            ("node_modules/pkg/.env", ""),
            (".git/config", "[remote \"origin\"]\n\turl = https://me:s3cret@example.com/repo.git\n"),
        ] {
            std::fs::write(dir.join(file), text).unwrap();
        }
        let found = find_sensitive(&dir);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(found, [".git/config (a password or token in a remote URL)", "conf/deep/.env.production", "conf/server.key"]);
        assert!(!url_with_credentials("url = https://example.com/repo.git\nurl = git@github.com:a/b.git"));
    }
    #[test]
    fn the_stored_list_is_read_strictly() {
        assert!(parse_mounts(&json!(["/a"])).is_err());
        assert!(parse_mounts(&json!([{"path": "/a"}])).unwrap_err().contains("true or false"));
        assert!(parse_mounts(&json!([{"path": "/a", "readOnly": "true"}])).unwrap_err().contains("true or false"));
        assert!(parse_mounts(&json!([{"readOnly": true}])).is_err());
        assert!(parse_mounts(&json!([null])).is_err());
        assert!(parse_mounts(&json!({})).is_err());
    }
}
