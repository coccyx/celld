// Copyright 2026 Deno Land Inc. Apache-2.0 license.

//! Host-issued, single-use execution grants. Neither Worker options nor image
//! metadata can broaden a profile. Writable bind mounts outlive the container;
//! their quota, restore and publication protocol belong to the issuing host.
// Host cgroups and grant files must refer to the engine's real namespace, not
// celld's injected durable-node filesystem. O_NOFOLLOW, ownership and fsync are
// part of this external host interface, as with the daemon's Unix socket.
#![allow(clippy::disallowed_methods)]

use anyhow::{anyhow, Context};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub grants: PathBuf,
    pub profiles: BTreeMap<String, Profile>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub classes: Vec<String>,
    pub image: String,
    pub runtime: String,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_root: PathBuf,
    pub memory_bytes: u64,
    pub cpu_millis: u64,
    pub pids: u64,
    pub max_deadline_ms: u64,
    pub commands: BTreeMap<String, Vec<String>>,
    pub env: Vec<String>,
    pub working_dir: PathBuf,
    pub mounts: BTreeMap<String, MountPolicy>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountPolicy {
    pub target: PathBuf,
    pub root: PathBuf,
    pub writable: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub version: u32,
    pub scope: String,
    pub profile: String,
    pub command: String,
    pub expires_at_ms: u64,
    pub deadline_ms: u64,
    pub cgroup: PathBuf,
    pub mounts: BTreeMap<String, Mount>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    pub source: PathBuf,
    pub readonly: bool,
}
pub struct Execution {
    pub token: String,
    pub profile: Profile,
    pub grant: Grant,
    revoked: PathBuf,
    // Pin every mount directory for the complete operation. The daemon sees
    // the same host namespace; the trusted issuer owns their parent directories.
    _directories: Vec<File>,
}
fn now_ms() -> u64 {
    crate::asyncrt::wall_ms().max(0) as u64
}

pub fn token_valid(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn clean(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}
fn directory(path: &Path) -> anyhow::Result<File> {
    anyhow::ensure!(
        clean(path) && fs::canonicalize(path)? == path,
        "execution directory is not canonical"
    );
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?)
}
fn protected(path: &Path) -> anyhow::Result<File> {
    let parent = directory(
        path.parent()
            .ok_or_else(|| anyhow!("execution configuration parent"))?,
    )?;
    let meta = parent.metadata()?;
    anyhow::ensure!(
        meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "execution configuration directory must be host-owned"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    anyhow::ensure!(
        meta.is_file()
            && meta.uid() == 0
            && meta.mode() & 0o022 == 0
            && meta.nlink() == 1
            && meta.len() <= 65536,
        "execution configuration must be a bounded host-owned regular file"
    );
    Ok(file)
}
fn read<T: serde::de::DeserializeOwned>(file: File) -> anyhow::Result<T> {
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 65536, "execution configuration too large");
    Ok(serde_json::from_slice(&bytes)?)
}
pub fn configuration() -> anyhow::Result<Option<Configuration>> {
    let Some(path) = std::env::var_os("CELLD_CONTAINER_EXECUTION_PROFILES") else {
        return Ok(None);
    };
    let config: Configuration = read(protected(Path::new(&path))?)?;
    let meta = directory(&config.grants)?.metadata()?;
    anyhow::ensure!(
        meta.uid() == 0 && meta.mode() & 0o077 == 0,
        "execution grant directory must be private and host-owned"
    );
    Ok(Some(config))
}
pub fn required(class: &str) -> anyhow::Result<bool> {
    Ok(configuration()?.is_some_and(|c| {
        c.profiles
            .values()
            .any(|p| p.classes.iter().any(|n| n == class))
    }))
}
pub fn revoke(scope: &str, token: &str) -> anyhow::Result<()> {
    anyhow::ensure!(token_valid(token), "invalid execution token");
    let config =
        configuration()?.ok_or_else(|| anyhow!("host execution profiles are not configured"))?;
    let source = config.grants.join(format!("{token}.json"));
    let claimed = config.grants.join(format!("{token}.claimed"));
    let file = protected(if source.exists() { &source } else { &claimed })?;
    let grant: Grant = read(file)?;
    anyhow::ensure!(
        grant.scope == scope,
        "execution grant belongs to another scope"
    );
    let path = config.grants.join(format!("{token}.revoked"));
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(file) => file.sync_all()?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    File::open(config.grants)?.sync_all()?;
    Ok(())
}

impl Execution {
    pub fn claim(scope: &str, class: &str, token: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(token_valid(token), "invalid execution token");
        let config = configuration()?
            .ok_or_else(|| anyhow!("host execution profiles are not configured"))?;
        let source = config.grants.join(format!("{token}.json"));
        let file = protected(&source)?;
        let grant: Grant = read(file)?;
        anyhow::ensure!(
            grant.version == 1 && grant.scope == scope,
            "execution grant belongs to another scope"
        );
        let profile = config
            .profiles
            .get(&grant.profile)
            .filter(|p| p.classes.iter().any(|c| c == class))
            .ok_or_else(|| anyhow!("execution profile does not authorize this class"))?
            .clone();
        validate(&profile, &grant)?;
        let mut directories = vec![directory(&grant.cgroup)?];
        for (name, mount) in &grant.mounts {
            let policy = profile
                .mounts
                .get(name)
                .ok_or_else(|| anyhow!("unknown execution mount"))?;
            anyhow::ensure!(
                mount.source.starts_with(&policy.root)
                    && mount.source != policy.root
                    && (mount.readonly || policy.writable),
                "execution mount exceeds host policy"
            );
            directories.push(directory(&mount.source)?);
        }
        anyhow::ensure!(
            grant.mounts.len() == profile.mounts.len(),
            "execution mounts are incomplete"
        );
        // link is atomic and refuses an existing claim. Keep the tombstone until
        // operator cleanup; deleting a grant never authorizes replay.
        let claimed = config.grants.join(format!("{token}.claimed"));
        fs::hard_link(&source, &claimed).context("execution grant already claimed")?;
        fs::remove_file(source)?;
        File::open(&config.grants)?.sync_all()?;
        let execution = Self {
            token: token.to_owned(),
            profile,
            grant,
            revoked: config.grants.join(format!("{token}.revoked")),
            _directories: directories,
        };
        execution.check_live()?;
        Ok(execution)
    }
    pub fn check_live(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.revoked.exists(), "execution grant revoked");
        anyhow::ensure!(
            now_ms() < self.grant.expires_at_ms,
            "execution grant expired"
        );
        // A frozen ancestor is a permanent fence against delayed daemon starts.
        // The issuer keeps it until removal is confirmed and never reuses it.
        for path in self
            .grant
            .cgroup
            .ancestors()
            .take_while(|p| p.starts_with("/sys/fs/cgroup"))
        {
            let freeze = path.join("cgroup.freeze");
            if freeze.exists() {
                anyhow::ensure!(
                    fs::read_to_string(freeze)?.trim() == "0",
                    "execution cgroup has been fenced"
                );
            }
        }
        anyhow::ensure!(
            fs::read_to_string(self.grant.cgroup.join("memory.max"))?.trim()
                == self.profile.memory_bytes.to_string()
                && fs::read_to_string(self.grant.cgroup.join("memory.swap.max"))?.trim() == "0"
                && fs::read_to_string(self.grant.cgroup.join("pids.max"))?.trim()
                    == self.profile.pids.to_string()
                && fs::read_to_string(self.grant.cgroup.join("cpu.max"))?.trim()
                    == format!("{} 100000", self.profile.cpu_millis * 100),
            "execution cgroup does not enforce the host profile"
        );
        Ok(())
    }
    pub fn fence(&self) -> anyhow::Result<()> {
        fs::write(self.grant.cgroup.join("cgroup.freeze"), "1")?;
        fs::write(self.grant.cgroup.join("cgroup.kill"), "1")?;
        Ok(())
    }
    pub fn body(&self) -> Value {
        let mounts: Vec<Value> = self.grant.mounts.iter().map(|(name, mount)| {
            json!({"Type":"bind", "Source":mount.source, "Target":self.profile.mounts[name].target,
                "ReadOnly":mount.readonly,"BindOptions":{"Propagation":"rprivate"}})
        }).collect();
        json!({
            "Image":self.profile.image,"Entrypoint":self.profile.commands[&self.grant.command],"Cmd":[],
            "User":format!("{}:{}",self.profile.uid,self.profile.gid),"WorkingDir":self.profile.working_dir,
            "Env":self.profile.env,"AttachStdout":true,"AttachStderr":true,
            "HostConfig":{
                "Runtime":self.profile.runtime,"NetworkMode":"none","ReadonlyRootfs":true,
                "CapDrop":["ALL"],"SecurityOpt":["no-new-privileges"],"Privileged":false,
                "PidsLimit":self.profile.pids,"NanoCpus":self.profile.cpu_millis * 1_000_000,
                "Memory":self.profile.memory_bytes,"MemorySwap":self.profile.memory_bytes,
                "CgroupParent":format!("/{}",self.grant.cgroup.strip_prefix("/sys/fs/cgroup").unwrap().display()),
                "Mounts":mounts,"Init":true,"RestartPolicy":{"Name":"no"},
                "LogConfig":{"Type":"json-file","Config":{"max-size":"4m","max-file":"1"}},
                "Ulimits":[{"Name":"nofile","Soft":4096,"Hard":4096}],"ShmSize":16777216
            }
        })
    }
}
fn validate(profile: &Profile, grant: &Grant) -> anyhow::Result<()> {
    anyhow::ensure!(
        profile
            .image
            .strip_prefix("sha256:")
            .is_some_and(token_valid),
        "execution image must be an immutable engine ID"
    );
    anyhow::ensure!(
        !profile.runtime.is_empty() && profile.uid >= 1000 && profile.gid >= 1000,
        "execution profile requires a runtime and non-root identity"
    );
    anyhow::ensure!(
        profile.cpu_millis > 0
            && profile.cpu_millis <= 64000
            && profile.memory_bytes >= 16 * 1024 * 1024
            && profile.pids > 0
            && profile.pids <= 65536,
        "execution profile must have bounded resources"
    );
    anyhow::ensure!(
        grant.deadline_ms > 0
            && grant.deadline_ms <= profile.max_deadline_ms
            && profile.max_deadline_ms <= 3_600_000
            && grant.expires_at_ms > now_ms()
            && grant.expires_at_ms <= now_ms().saturating_add(profile.max_deadline_ms + 60000),
        "execution deadline exceeds profile"
    );
    anyhow::ensure!(
        clean(&profile.cgroup_root)
            && profile.cgroup_root.starts_with("/sys/fs/cgroup")
            && profile.cgroup_root != Path::new("/sys/fs/cgroup")
            && grant.cgroup.starts_with(&profile.cgroup_root)
            && grant.cgroup != profile.cgroup_root
            && clean(&grant.cgroup),
        "execution cgroup exceeds host policy"
    );
    anyhow::ensure!(
        profile
            .commands
            .get(&grant.command)
            .is_some_and(|v| !v.is_empty() && v[0].starts_with('/')),
        "execution command is not approved"
    );
    anyhow::ensure!(
        clean(&profile.working_dir),
        "execution working directory must be absolute"
    );
    anyhow::ensure!(
        grant.mounts.len() == profile.mounts.len(),
        "execution mounts are incomplete"
    );
    for (name, mount) in &grant.mounts {
        let policy = profile
            .mounts
            .get(name)
            .ok_or_else(|| anyhow!("unknown execution mount"))?;
        anyhow::ensure!(
            clean(&mount.source)
                && mount.source.starts_with(&policy.root)
                && mount.source != policy.root
                && (mount.readonly || policy.writable),
            "execution mount exceeds host policy"
        );
    }
    let mut targets = std::collections::BTreeSet::new();
    for mount in profile.mounts.values() {
        anyhow::ensure!(
            clean(&mount.root)
                && mount.root != Path::new("/")
                && clean(&mount.target)
                && mount.target != Path::new("/")
                && !mount.target.starts_with("/proc")
                && !mount.target.starts_with("/sys")
                && !mount.target.starts_with("/dev")
                && targets.insert(&mount.target),
            "unsafe execution mount policy"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Profile, Grant) {
        let profile = serde_json::from_value(json!({
            "classes":["Fixture"],"image":format!("sha256:{}","a".repeat(64)),"runtime":"runsc",
            "uid":1000,"gid":1000,"cgroup_root":"/sys/fs/cgroup/execution",
            "memory_bytes":1073741824u64,"cpu_millis":1000,"pids":96,"max_deadline_ms":60000,
            "commands":{"tool":["/bin/sh","-c","true"]},"env":["HOME=/scratch"],"working_dir":"/workspace",
            "mounts":{"workspace":{"root":"/volumes","target":"/workspace","writable":true},
                "input":{"root":"/inputs","target":"/input","writable":false}}
        })).unwrap();
        let grant = serde_json::from_value(json!({"version":1,"scope":"Fixture:object","profile":"test","command":"tool",
            "expires_at_ms":now_ms()+30000,"deadline_ms":15000,"cgroup":"/sys/fs/cgroup/execution/task/guest",
            "mounts":{"workspace":{"source":"/volumes/object/workspace","readonly":false},
                "input":{"source":"/inputs/task","readonly":true}}
        })).unwrap();
        (profile, grant)
    }
    #[test]
    fn fixed_policy_overrides_image_defaults() {
        let (profile, grant) = fixture();
        validate(&profile, &grant).unwrap();
        let run = Execution {
            token: "b".repeat(64),
            profile,
            grant,
            revoked: PathBuf::new(),
            _directories: Vec::new(),
        };
        let body = run.body();
        assert_eq!(body["HostConfig"]["NetworkMode"], "none");
        assert_eq!(body["HostConfig"]["ReadonlyRootfs"], true);
        assert_eq!(body["HostConfig"]["Privileged"], false);
        assert_eq!(
            body["HostConfig"]["SecurityOpt"],
            json!(["no-new-privileges"])
        );
        assert_eq!(body["HostConfig"]["CapDrop"], json!(["ALL"]));
        assert_eq!(body["HostConfig"]["CgroupParent"], "/execution/task/guest");
        assert_eq!(body["User"], "1000:1000");
        assert_eq!(body["HostConfig"]["RestartPolicy"]["Name"], "no");
        assert_eq!(
            body["HostConfig"]["Memory"],
            body["HostConfig"]["MemorySwap"]
        );
    }
    #[test]
    fn no_arbitrary_mount_or_write_upgrade() {
        let (profile, mut grant) = fixture();
        grant.mounts.get_mut("input").unwrap().readonly = false;
        assert!(validate(&profile, &grant).is_err());
        grant.mounts.get_mut("input").unwrap().readonly = true;
        grant.mounts.get_mut("input").unwrap().source = "/etc".into();
        assert!(validate(&profile, &grant).is_err());
        grant.mounts.get_mut("input").unwrap().source = "/inputs/../etc".into();
        assert!(validate(&profile, &grant).is_err());
    }
    #[test]
    fn refuses_missing_mounts_and_unapproved_commands() {
        let (profile, mut grant) = fixture();
        grant.command = "arbitrary".into();
        assert!(validate(&profile, &grant).is_err());
        grant.command = "tool".into();
        grant.mounts.remove("input");
        assert!(validate(&profile, &grant).is_err());
    }
    #[test]
    fn requires_immutable_image_and_non_root_identity() {
        let (mut profile, grant) = fixture();
        profile.image = "node:latest".into();
        assert!(validate(&profile, &grant).is_err());
        profile.image = format!("sha256:{}", "a".repeat(64));
        profile.uid = 0;
        assert!(validate(&profile, &grant).is_err());
    }
    #[test]
    fn deadline_and_cgroup_cannot_escape_host_allocation() {
        let (profile, mut grant) = fixture();
        grant.deadline_ms = 60001;
        assert!(validate(&profile, &grant).is_err());
        grant.deadline_ms = 1000;
        grant.expires_at_ms = 0;
        assert!(validate(&profile, &grant).is_err());
        grant.expires_at_ms = now_ms() + 5000;
        grant.cgroup = "/sys/fs/cgroup/other/task".into();
        assert!(validate(&profile, &grant).is_err());
    }
    #[test]
    fn mount_policy_cannot_replace_kernel_filesystems() {
        let (mut profile, grant) = fixture();
        profile.mounts.get_mut("workspace").unwrap().target = "/proc".into();
        assert!(validate(&profile, &grant).is_err());
    }
    #[test]
    fn tokens_are_capabilities_not_paths() {
        assert!(token_valid(&"a".repeat(64)));
        for value in [
            "../../etc/passwd".to_owned(),
            "a".repeat(63),
            "A".repeat(64),
            format!("{}?x", "a".repeat(64)),
        ] {
            assert!(!token_valid(&value));
        }
    }
}
