// Copyright 2026 Deno Land Inc. Apache-2.0 license.

//! Containers attached to Durable Objects: the engine side of
//! `ctx.container`.
//!
//! A cell of a class named in the deployment's `containers` config owns at
//! most one container, named after the cell, on the node that owns the
//! cell. The Durable Object supervises it through the ops in
//! `js/container.rs`; this module performs the effects against the
//! container engine, which is the Docker Engine API on a unix socket
//! (Podman serves the same API).
//!
//! The container is bound to the cell's ownership on this node, not to its
//! residency: an idle eviction leaves it running under an inactivity timer
//! and the next activation of the same cell reconnects to it by name, which
//! is what Cloudflare does and what the `@cloudflare/containers` class's
//! `sleepAfter` alarm relies on. Every other stop destroys it. The
//! container's disk is ephemeral on Cloudflare too, so a takeover that
//! starts fresh is conformant.
//!
//! Images travel through the bucket. `celld deploy` saves the image the
//! config names as a tar at `deploy/images/<id>.tar`, and a node loads it
//! into its engine the first time a cell of that class starts, so a node
//! never talks to a registry.

pub mod execution;

use crate::asyncrt;
use crate::docker::{frame_header, Docker, Stream};
use anyhow::{anyhow, Context};
use bytes::Bytes;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};

/// One `containers[]` entry of a deployment, as the node sees it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContainerSpec {
    pub class_name: String,
    /// The image reference the engine starts, `celld-image:<content key>`,
    /// so two deployments of one image share one tar and one load.
    pub image: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_instances: Option<u64>,
    /// The OCI runtime this class runs under, such as `runsc` (gVisor) for
    /// untrusted code. Overrides the node's `CELLD_CONTAINER_RUNTIME` for
    /// this class; `None` takes the node default. A node whose daemon does
    /// not have the runtime fails every start of the class, so the class
    /// runs only where its isolation is available. celld extends the
    /// Cloudflare config here, which has no per-class runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
}

/// The reference every engine holds an image under, from its content key.
/// The key hashes the layer digests and the image config, so an engine
/// that rebuilds identical content under a new id still resolves it.
pub fn image_reference(key: &str) -> String {
    format!("celld-image:{key}")
}

/// The bucket key of one saved image, from its reference.
pub fn image_key(image: &str) -> String {
    format!(
        "deploy/images/{}.tar",
        image.trim_start_matches("celld-image:")
    )
}

/// The resources an instance type reserves. Cloudflare's published table;
/// a name outside it is refused at deploy.
pub fn instance_resources(instance_type: &str) -> Option<(f64, u64)> {
    let gib = 1024 * 1024 * 1024;
    Some(match instance_type {
        "lite" | "dev" => (1.0 / 16.0, 256 * 1024 * 1024),
        "basic" => (0.25, gib),
        "standard-1" | "standard" => (0.5, 4 * gib),
        "standard-2" => (1.0, 6 * gib),
        "standard-3" => (2.0, 8 * gib),
        "standard-4" => (4.0, 12 * gib),
        _ => return None,
    })
}

/// The instance type of a class that declares none, as on Cloudflare.
const DEFAULT_INSTANCE_TYPE: &str = "dev";

/// The resolvers a container gets when it runs under a non-default runtime
/// and the operator set none. gVisor's network stack does not reach
/// Docker's embedded resolver at `127.0.0.11`, so a container under it
/// cannot resolve a hostname though it reaches the Internet by address; a
/// public resolver, which the fence permits, restores name resolution.
/// `CELLD_CONTAINER_DNS` overrides this.
const DEFAULT_CONTAINER_DNS: &[&str] = &["1.1.1.1", "1.0.0.1"];

/// The memory a container of this instance type reserves on the node. A
/// class that declares none gets the default type, as `create_and_start`
/// does. An unknown name is refused at deploy, so a running container
/// always maps; this returns 0 for a name that somehow does not, which
/// undercounts rather than blocks a sample.
pub fn instance_memory_bytes(instance_type: Option<&str>) -> u64 {
    instance_resources(instance_type.unwrap_or(DEFAULT_INSTANCE_TYPE))
        .map(|(_, memory)| memory)
        .unwrap_or(0)
}

/// The memory this node commits to its running containers, for the node's
/// capacity accounting. Zero when no engine has connected. See
/// `celld_logic::pressure::Load::container_reserved_bytes` for why the node
/// counts the cap rather than the container's live usage.
pub fn reserved_memory_bytes() -> u64 {
    engine_if_ready().map_or(0, |engine| engine.reserved_memory_bytes())
}

/// This node's running containers per class, published in the node lease so
/// peers can sum a class's instances across the fleet for `max_instances`.
/// Empty when no engine has connected.
pub fn running_instances_by_class() -> std::collections::BTreeMap<String, u64> {
    engine_if_ready().map_or_else(Default::default, |engine| {
        engine.running_instances_by_class()
    })
}
/// Processes one container can hold. Cloudflare publishes no number; this
/// is room for a build tool's process tree and far short of a fork bomb.
const PIDS_LIMIT: u64 = 1024;
/// The host interfaces of the two bridges, named so the fence can address
/// them; Docker's default `br-<id>` changes with every recreation.
const OPEN_BRIDGE: &str = "celld0";
const INTERNAL_BRIDGE: &str = "celld1";
const BRIDGE_NAME_OPTION: &str = "com.docker.network.bridge.name";
/// The fence, installed on the node from a one-shot privileged container of
/// the `celld-fence` image: a container may reach the Internet and nothing
/// of the node's own. Hooks before Docker's own chains (priority filter -
/// 10) so a verdict here is final. Input: no new connection from a bridge
/// to the node itself, which is where the internal listener and the public
/// listener bind; replies to connections the node opened still pass.
/// Forward: nothing to the private ranges, where the fleet, the VPC, and
/// the metadata service live. Rules on the host side of the bridge cover
/// every runtime, gVisor included, and no process inside a container can
/// see them, let alone remove them.
const FENCE_RULES: &str = r#"table inet celld
delete table inet celld
table inet celld {
  chain input {
    type filter hook input priority -10; policy accept;
    iifname { "celld0", "celld1" } ct state established,related accept
    iifname { "celld0", "celld1" } reject
  }
  chain forward {
    type filter hook forward priority -10; policy accept;
    iifname { "celld0", "celld1" } ip daddr { 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 } reject
    iifname { "celld0", "celld1" } ip6 daddr { fe80::/10, fc00::/7 } reject
  }
}
"#;

/// Docker's bridge option that forbids traffic between two containers on
/// the same bridge. The node still reaches every container, because it
/// speaks from the host side of the bridge.
const ICC_OPTION: &str = "com.docker.network.bridge.enable_icc";

/// How a cell stop treats its container.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Release {
    /// An idle eviction: keep the container under its inactivity timer.
    Keep,
    /// Ownership leaves this node, or the cell is reset: destroy it.
    Destroy,
}

/// The default inactivity window after an idle eviction when the object
/// never set one. The `@cloudflare/containers` alarm wakes the object well
/// inside this to enforce `sleepAfter`, so this is the backstop for an
/// object that never wakes, not the policy.
const DEFAULT_INACTIVITY: Duration = Duration::from_secs(10 * 60);

/// Environment every container sees. The values mirror workerd's local
/// engine: applications read the names, never the values.
const DEFAULT_ENV: &[&str] = &[
    "CLOUDFLARE_COUNTRY_A2=XX",
    "CLOUDFLARE_DEPLOYMENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "CLOUDFLARE_LOCATION=loc01",
    "CLOUDFLARE_REGION=REGN",
    "CLOUDFLARE_APPLICATION_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
];

pub struct StartParams {
    pub entrypoint: Option<Vec<String>>,
    pub env: Vec<(String, String)>,
    pub enable_internet: bool,
    pub labels: Vec<(String, String)>,
}

#[derive(Default)]
struct CellState {
    running: bool,
    starting: bool,
    stopping: bool,
    retired: bool,
    /// Immutable engine ID, retained until removal is confirmed.
    container_id: Option<String>,
    /// A create may have reached the daemon without returning its ID.
    creating: bool,
    execution: Option<Arc<execution::Execution>>,
    idle_epoch: u64,
    /// Where the node dials the container: the bridge address on Linux,
    /// the published loopback ports elsewhere.
    address: Address,
    inactivity: Option<Duration>,
    /// Cancel the idle timer, but never interrupt cleanup after it starts.
    sweeper: Option<tokio::sync::oneshot::Sender<()>>,
    /// Bumped per start so a wait from a previous run cannot report for
    /// this one.
    run: u64,
}

#[derive(Clone, Debug, Default)]
enum Address {
    #[default]
    None,
    Ip(String),
    Published(HashMap<u16, u16>),
}

pub struct CellContainer {
    scope: String,
    name: String,
    spec: Arc<ContainerSpec>,
    state: Mutex<CellState>,
    /// Serialize lifecycle effects, including attachment and exec setup.
    lifecycle: tokio::sync::Mutex<()>,
    /// Processes `exec()` started in this container. An object drops one
    /// after `output()`; the rest go with the container.
    processes: Mutex<Vec<u64>>,
    /// The exit of the current run, `None` while it runs. `Some(Err)` is
    /// an engine failure the wait could not attribute to the process.
    /// Written with `send_replace`: a plain `send` discards the value
    /// while nobody subscribes, and `monitor()` usually subscribes late.
    exit: watch::Sender<Option<(u64, Result<i64, String>)>>,
}

impl CellContainer {
    pub fn running(&self) -> bool {
        self.state.lock().unwrap().running
    }

    /// `host:port` for `getTcpPort(port)`.
    pub fn address(&self, port: u16) -> Result<String, String> {
        let state = self.state.lock().unwrap();
        if !state.running {
            return Err("the container is not running".to_string());
        }
        match &state.address {
            Address::Ip(ip) => Ok(format!("{ip}:{port}")),
            Address::Published(ports) => ports
                .get(&port)
                .map(|host| format!("127.0.0.1:{host}"))
                .ok_or_else(|| {
                    format!(
                        "The container is not listening on port {port}: on this platform a port \
                         must be declared with EXPOSE in the image"
                    )
                }),
            Address::None => Err(format!("The container is not listening on port {port}")),
        }
    }

    pub fn set_inactivity(&self, duration: Duration) {
        self.state.lock().unwrap().inactivity = Some(duration);
    }

    /// Open the next run, synchronously, before the start is even queued.
    /// The object's `start()` returns at once and its `monitor()` follows
    /// immediately, so the run they both mean must exist before either
    /// effect runs, or the monitor would find the previous run's exit and
    /// report the new container dead on arrival.
    pub fn begin_run(&self) -> anyhow::Result<u64> {
        let mut state = self.state.lock().unwrap();
        anyhow::ensure!(
            !state.running && !state.starting && !state.stopping && !state.retired,
            "the container is running, stopping, or no longer attached"
        );
        state.run += 1;
        state.running = true;
        state.starting = true;
        state.execution = None;
        state.address = Address::None;
        state.idle_epoch += 1;
        state.sweeper = None;
        let run = state.run;
        self.exit.send_replace(None);
        Ok(run)
    }

    /// Capture the target before asynchronous work can be reordered. Even a
    /// confirmed process exit must not permit a new start during removal.
    pub fn request_destroy(&self) -> u64 {
        let mut state = self.state.lock().unwrap();
        state.stopping = true;
        state.run
    }

    /// The run `monitor()` waits on: the newest one.
    pub fn current_run(&self) -> u64 {
        self.state.lock().unwrap().run
    }
}

pub struct ContainerEngine {
    /// See `Config::runtime`.
    runtime: Option<String>,
    /// See `Config::dns`.
    dns: Vec<String>,
    /// The absolute path of the container resolv.conf this engine wrote and
    /// bind-mounts; `None` when it could not be written.
    resolv_conf: Option<PathBuf>,
    docker: Docker,
    node: String,
    bucket: Option<crate::bucket::Bucket>,
    /// Per-image load lock, so two cells of one class starting together
    /// load the tar once.
    images: Mutex<HashMap<String, Arc<tokio::sync::Mutex<bool>>>>,
    cells: Mutex<HashMap<String, Arc<CellContainer>>>,
    networks: tokio::sync::Mutex<Option<(String, String)>>,
    /// Whether this process has installed the fence on the node's bridges.
    fenced: tokio::sync::Mutex<bool>,
}

/// What the runtime told this module about the node: set once at start.
struct Config {
    node: String,
    bucket: Option<crate::bucket::Bucket>,
    /// `CELLD_CONTAINER_RUNTIME`: the OCI runtime every container starts
    /// under, such as `runsc` (gVisor) or `kata` (a VM). `None` is the
    /// daemon's default, which is `runc` unless the operator changed it. A
    /// class can override it, see `ContainerSpec::runtime`.
    runtime: Option<String>,
    /// `CELLD_CONTAINER_DNS`: the resolvers a container gets, overriding
    /// `DEFAULT_CONTAINER_DNS`. Empty takes the default when a runtime is in
    /// use and the daemon's otherwise.
    dns: Vec<String>,
    /// The node's state directory. celld writes the container resolv.conf
    /// here and bind-mounts it, so the path must be the same on the host as
    /// celld sees it; a self-hosted node runs celld as a host process, and
    /// the lab mounts the directory one-to-one.
    data_dir: PathBuf,
}

static CONFIG: RwLock<Option<Config>> = RwLock::new(None);
/// The deployment's container classes. Replaced on every generation swap;
/// a running container keeps the spec it started with.
static SPECS: RwLock<Vec<Arc<ContainerSpec>>> = RwLock::new(Vec::new());
/// The deployment's `celld-fence` image; see `Manifest::fence_image`.
static FENCE_IMAGE: RwLock<Option<String>> = RwLock::new(None);
/// The engine, connected on first use. A node whose deployment declares no
/// container class never opens the socket.
static ENGINE: tokio::sync::OnceCell<Arc<ContainerEngine>> = tokio::sync::OnceCell::const_new();

pub fn configure(node: String, bucket: Option<crate::bucket::Bucket>, data_dir: PathBuf) {
    let runtime = std::env::var("CELLD_CONTAINER_RUNTIME")
        .ok()
        .filter(|runtime| !runtime.is_empty());
    let dns = std::env::var("CELLD_CONTAINER_DNS")
        .unwrap_or_default()
        .split(',')
        .map(|resolver| resolver.trim().to_string())
        .filter(|resolver| !resolver.is_empty())
        .collect();
    *CONFIG.write().unwrap() = Some(Config {
        node,
        bucket,
        runtime,
        dns,
        data_dir,
    });
}

pub fn install_specs(specs: Vec<ContainerSpec>, fence_image: Option<String>) {
    *SPECS.write().unwrap() = specs.into_iter().map(Arc::new).collect();
    *FENCE_IMAGE.write().unwrap() = fence_image;
}

pub fn spec(class: &str) -> Option<Arc<ContainerSpec>> {
    SPECS
        .read()
        .unwrap()
        .iter()
        .find(|spec| spec.class_name == class)
        .cloned()
}

/// The engine, connecting on the first call. A failure is returned rather
/// than cached, so a daemon that comes up later is found by the next call.
pub async fn engine() -> anyhow::Result<Arc<ContainerEngine>> {
    ENGINE
        .get_or_try_init(|| async {
            let (node, bucket, runtime, dns, data_dir) = {
                let config = CONFIG.read().unwrap();
                let config = config.as_ref().ok_or_else(|| {
                    anyhow!("the container engine is not configured on this node")
                })?;
                (
                    config.node.clone(),
                    config.bucket.clone(),
                    config.runtime.clone(),
                    config.dns.clone(),
                    config.data_dir.clone(),
                )
            };
            let docker = Docker::discover().ok_or_else(|| {
                anyhow!(
                    "no container engine: set DOCKER_HOST to a unix socket, or run a Docker or \
                     Podman daemon on this node"
                )
            })?;
            Ok(Arc::new(
                ContainerEngine::connect(docker, node, bucket, runtime, dns, data_dir).await?,
            ))
        })
        .await
        .cloned()
}

/// The engine only if a previous call connected it.
pub fn engine_if_ready() -> Option<Arc<ContainerEngine>> {
    ENGINE.get().cloned()
}

/// Destroy every container of this node at process exit. A preserve
/// shutdown (`celld dev` on Ctrl-C) keeps its cells resident and stops
/// none of them, and a handoff cut by the deadline leaves cells behind
/// too; without this their containers ran on until the next start of the
/// same node reaped them, invisible to the object that owned them.
pub async fn shutdown() {
    let Some(engine) = engine_if_ready() else {
        return;
    };
    if let Err(error) = engine.reap().await {
        tracing::warn!(
            event = "container_shutdown_reap_failed",
            error = %format!("{error:#}"),
            "containers of this node may still be running"
        );
    }
}

/// Connect and load every image of the installed specs, ahead of the
/// first cell that needs one. Failures are logged: a node without an
/// engine still serves every other class, and the container class fails
/// at its first `start()` with the same message.
pub async fn prewarm() {
    let engine = match engine().await {
        Ok(engine) => engine,
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "containers are unavailable on this node");
            return;
        }
    };
    let needs_bridge = SPECS
        .read()
        .unwrap()
        .iter()
        .any(|spec| !execution::required(&spec.class_name).unwrap_or(false));
    if needs_bridge {
        if let Err(error) = engine.ensure_fence().await {
            tracing::warn!(
                error = %format!("{error:#}"),
                "the container bridges are not fenced; no container starts on this node"
            );
        }
    }
    let specs = SPECS.read().unwrap().clone();
    for spec in specs {
        if let Err(error) = engine.ensure_image(&spec.image).await {
            tracing::warn!(
                class = %spec.class_name,
                image = %spec.image,
                error = %format!("{error:#}"),
                "container image is unavailable"
            );
        }
    }
}

impl ContainerEngine {
    /// Connect to the engine and reap every container a previous process
    /// of this node left behind. A restarted node cannot know which of its
    /// containers still belong to cells it will own again, and a container
    /// whose object has lost track of it is a leak, so a restart starts
    /// clean. The next `start()` of each object creates a fresh one.
    pub async fn connect(
        docker: Docker,
        node: String,
        bucket: Option<crate::bucket::Bucket>,
        runtime: Option<String>,
        dns: Vec<String>,
        data_dir: PathBuf,
    ) -> anyhow::Result<Self> {
        // Write the resolv.conf once, to bind into every container that runs
        // under a non-default runtime. gVisor cannot reach Docker's embedded
        // resolver, so a bind-mounted file with a public resolver, which the
        // fence permits, is the only resolv.conf the container can use.
        let resolvers: Vec<String> = if dns.is_empty() {
            DEFAULT_CONTAINER_DNS
                .iter()
                .map(|r| r.to_string())
                .collect()
        } else {
            dns.clone()
        };
        let resolv_conf = {
            let path = data_dir.join("container-resolv.conf");
            let body: String = resolvers
                .iter()
                .map(|resolver| format!("nameserver {resolver}\n"))
                .collect();
            let fs = asyncrt::fs();
            match fs
                .create_dir_all(&data_dir)
                .and_then(|()| fs.write(&path, body.as_bytes()))
            {
                Ok(()) => Some(path),
                Err(error) => {
                    tracing::warn!(event = "container_resolv_write_failed", %error);
                    None
                }
            }
        };
        let engine = Self {
            docker,
            node,
            bucket,
            runtime,
            dns,
            resolv_conf,
            images: Mutex::new(HashMap::new()),
            cells: Mutex::new(HashMap::new()),
            networks: tokio::sync::Mutex::new(None),
            fenced: tokio::sync::Mutex::new(false),
        };
        engine.reap().await?;
        Ok(engine)
    }

    pub fn socket(&self) -> &std::path::Path {
        self.docker.socket()
    }

    async fn reap(&self) -> anyhow::Result<()> {
        let filters = json!({ "label": [format!("celld.node={}", self.node)] }).to_string();
        let reply = self
            .docker
            .expect(
                "GET",
                &format!(
                    "/containers/json?all=true&filters={}",
                    percent_encoding::utf8_percent_encode(
                        &filters,
                        percent_encoding::NON_ALPHANUMERIC
                    )
                ),
                None,
                "list containers",
            )
            .await?;
        let list = reply.json()?;
        let list = list
            .as_array()
            .ok_or_else(|| anyhow!("list containers answered without an array"))?;
        let mut failures = Vec::new();
        for entry in list {
            let Some(id) = entry.get("Id").and_then(Value::as_str) else {
                failures.push("list containers answered without a container id".to_string());
                continue;
            };
            if let Err(error) = self.remove_container(id).await {
                // Try every container even if one cannot be removed. On
                // startup the error refuses the engine; on shutdown the
                // caller reports that containers may still be running.
                failures.push(format!("{id}: {error:#}"));
            }
        }
        if !failures.is_empty() {
            return Err(anyhow!("reap containers failed: {}", failures.join("; ")));
        }
        Ok(())
    }

    /// Removal is idempotent, but a failed request is not evidence that
    /// the container is gone. In particular, a lost daemon connection must
    /// leave the handle available for a later cleanup attempt.
    async fn remove_container(&self, id: &str) -> anyhow::Result<()> {
        let reply = self
            .docker
            .call("DELETE", &format!("/containers/{id}?force=true"), None)
            .await
            .context("remove container")?;
        if !reply.status.is_success() && reply.status.as_u16() != 404 {
            return Err(anyhow!(
                "remove container failed with [{}] {}",
                reply.status.as_u16(),
                reply.message()
            ));
        }
        Ok(())
    }

    /// Make the class's image present in the engine, loading it from the
    /// bucket when it is not. Idempotent and serialized per image.
    pub async fn ensure_image(&self, image: &str) -> anyhow::Result<()> {
        let lock = self
            .images
            .lock()
            .unwrap()
            .entry(image.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(false)))
            .clone();
        let mut loaded = lock.lock().await;
        if *loaded {
            return Ok(());
        }
        let reply = self
            .docker
            .call("GET", &format!("/images/{image}/json"), None)
            .await?;
        if reply.status.is_success() {
            tracing::info!(image, "container image present in the engine");
            *loaded = true;
            return Ok(());
        }
        let bucket = self
            .bucket
            .as_ref()
            .ok_or_else(|| anyhow!("image {image} is not present in the container engine"))?;
        let key = image_key(image);
        let (tar, _) = bucket.get(&key).await?.ok_or_else(|| {
            anyhow!("image {image} is not in the bucket at {key}; run `celld deploy`")
        })?;
        let bytes = tar.len();
        let reply = self
            .docker
            .post_octets("/images/load?quiet=true", tar, "load image")
            .await?;
        tracing::info!(
            image,
            bytes,
            answer = %String::from_utf8_lossy(&reply.body).trim_end(),
            "container image loaded from the bucket"
        );
        *loaded = true;
        Ok(())
    }

    /// The two bridges every container joins: one with egress, one
    /// without. Docker implements an internal network by omitting the
    /// masquerade rule and the default route; the node still reaches the
    /// bridge address, which is all ingress needs.
    async fn networks(&self) -> anyhow::Result<(String, String)> {
        let mut guard = self.networks.lock().await;
        if let Some(names) = guard.as_ref() {
            return Ok(names.clone());
        }
        for (name, internal) in [("celld", false), ("celld-internal", true)] {
            // A bridge keeps the options it was created with, so one from
            // before containers were isolated from each other is replaced.
            // The replacement fails while a container is attached, which a
            // node start after its reap never has; a failure keeps the old
            // bridge and says so rather than refusing every container.
            let current = self
                .docker
                .call("GET", &format!("/networks/{name}"), None)
                .await?;
            if current.status.is_success() {
                let bridge = if internal {
                    INTERNAL_BRIDGE
                } else {
                    OPEN_BRIDGE
                };
                let current_options = current
                    .json()
                    .ok()
                    .and_then(|network| network.get("Options").cloned())
                    .unwrap_or(Value::Null);
                let option = |key: &str| current_options.get(key).and_then(Value::as_str);
                if option(ICC_OPTION) == Some("false") && option(BRIDGE_NAME_OPTION) == Some(bridge)
                {
                    continue;
                }
                let removed = self
                    .docker
                    .call("DELETE", &format!("/networks/{name}"), None)
                    .await?;
                if !removed.status.is_success() {
                    tracing::warn!(
                        network = name,
                        error = %removed.message(),
                        "the container bridge predates container isolation and is in use; \
                         containers on it can reach each other until the node restarts idle"
                    );
                    continue;
                }
            }
            let reply = self
                .docker
                .call(
                    "POST",
                    "/networks/create",
                    Some(json!({
                        "Name": name,
                        "Driver": "bridge",
                        "Internal": internal,
                        "Options": {
                            ICC_OPTION: "false",
                            BRIDGE_NAME_OPTION: if internal { INTERNAL_BRIDGE } else { OPEN_BRIDGE },
                        },
                    })),
                )
                .await?;
            // 409: it exists, which is the steady state.
            if !reply.status.is_success() && reply.status.as_u16() != 409 {
                return Err(anyhow!(
                    "create network {name} failed with [{}] {}",
                    reply.status.as_u16(),
                    reply.message()
                ));
            }
        }
        let names = ("celld".to_string(), "celld-internal".to_string());
        *guard = Some(names.clone());
        Ok(names)
    }

    /// Install the fence on the node's bridges, once per process. Every
    /// container start waits on this and fails when it fails: a node that
    /// cannot fence its bridges runs no container, because an unfenced
    /// container can reach the node's internal listener and the cloud's
    /// metadata service. The rules live in the kernel and outlive this
    /// process; a restart re-applies them, which is idempotent.
    pub async fn ensure_fence(&self) -> anyhow::Result<()> {
        let mut fenced = self.fenced.lock().await;
        if *fenced {
            return Ok(());
        }
        let image = FENCE_IMAGE.read().unwrap().clone().ok_or_else(|| {
            anyhow!(
                "this deployment has no fence image; deploy it again with this celld, which \
                 saves the celld-fence image beside the container images"
            )
        })?;
        self.ensure_image(&image).await?;
        self.networks().await?;
        let body = json!({
            "Image": image,
            "Env": [format!("CELLD_NFT={FENCE_RULES}")],
            "Cmd": ["sh", "-c", "printf '%s' \"$CELLD_NFT\" | nft -f -"],
            "Labels": { "celld.node": self.node, "celld.fence": "1" },
            "HostConfig": { "NetworkMode": "host", "CapAdd": ["NET_ADMIN"] },
        });
        let created = self
            .docker
            .expect(
                "POST",
                "/containers/create",
                Some(body),
                "create fence container",
            )
            .await?
            .json()?;
        let id = created
            .get("Id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("create fence container answered without an id"))?
            .to_string();
        let outcome = async {
            self.docker
                .expect(
                    "POST",
                    &format!("/containers/{id}/start"),
                    None,
                    "start fence container",
                )
                .await?;
            let waited = self
                .docker
                .expect(
                    "POST",
                    &format!("/containers/{id}/wait"),
                    None,
                    "wait fence container",
                )
                .await?
                .json()?;
            let code = waited
                .get("StatusCode")
                .and_then(Value::as_i64)
                .unwrap_or(-1);
            if code != 0 {
                let logs = self.logs(&id).await.unwrap_or_default();
                return Err(anyhow!(
                    "the fence container exited with {code}: {}",
                    logs.trim()
                ));
            }
            Ok(())
        }
        .await;
        let _ = self
            .docker
            .call("DELETE", &format!("/containers/{id}?force=true"), None)
            .await;
        outcome.context("fence the container bridges")?;
        tracing::info!(
            event = "container_bridges_fenced",
            bridges = format!("{OPEN_BRIDGE},{INTERNAL_BRIDGE}"),
            "containers can reach the Internet and nothing of the node's own"
        );
        *fenced = true;
        Ok(())
    }

    /// Both output streams of a stopped container, for an error message.
    async fn logs(&self, id: &str) -> anyhow::Result<String> {
        let reply = self
            .docker
            .expect(
                "GET",
                &format!("/containers/{id}/logs?stdout=true&stderr=true"),
                None,
                "container logs",
            )
            .await?;
        let mut text = Vec::new();
        let mut rest: &[u8] = &reply.body;
        while rest.len() >= 8 {
            let (_, length) = frame_header(rest[..8].try_into().unwrap());
            let end = (8 + length).min(rest.len());
            text.extend_from_slice(&rest[8..end]);
            rest = &rest[end..];
        }
        Ok(String::from_utf8_lossy(&text).into_owned())
    }

    /// The cell's container handle, adopting a container a previous
    /// activation on this node left running. Called at cell start for a
    /// class with a spec; the object's `running` reads the answer.
    pub async fn attach(&self, scope: &str, class: &str) -> anyhow::Result<Arc<CellContainer>> {
        let spec = spec(class).ok_or_else(|| anyhow!("class {class} has no container"))?;
        loop {
            let cell = {
                let mut cells = self.cells.lock().unwrap();
                let cell = cells.entry(scope.to_string()).or_insert_with(|| {
                    Arc::new(CellContainer {
                        scope: scope.to_string(),
                        name: container_name(&self.node, scope),
                        spec: spec.clone(),
                        state: Mutex::new(CellState::default()),
                        lifecycle: tokio::sync::Mutex::new(()),
                        processes: Mutex::new(Vec::new()),
                        exit: watch::channel(None).0,
                    })
                });
                cell.clone()
            };
            let lifecycle = cell.lifecycle.lock().await;
            {
                let mut state = cell.state.lock().unwrap();
                if state.retired {
                    continue;
                }
                // Once cleanup acquired the lifecycle lock, let it finish. Never
                // cancel a sweeper halfway through a daemon mutation.
                state.idle_epoch += 1;
                state.sweeper = None;
                if state.run != 0 {
                    drop(state);
                    drop(lifecycle);
                    return Ok(cell);
                }
            }
            // Only an uninitialized handle discovers by name. Every subsequent
            // operation uses the immutable ID returned by this validated inspect.
            let info = self.inspect_owned(&cell, None).await?;
            let mut state = cell.state.lock().unwrap();
            if let Some(info) = info {
                let id = engine_container_id(&info)?;
                state.container_id = Some(id.clone());
                state.running = info
                    .pointer("/State/Running")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| anyhow!("inspect container answered without running state"))?;
                if state.running {
                    state.run += 1;
                    state.address = address_of(&info);
                    cell.exit.send_replace(None);
                    self.watch_exit(&cell, state.run, id).detach();
                }
            }
            drop(state);
            drop(lifecycle);
            return Ok(cell);
        }
    }

    /// The cell's handle, if the cell started on this node.
    pub fn cell(&self, scope: &str) -> Option<Arc<CellContainer>> {
        self.cells.lock().unwrap().get(scope).cloned()
    }

    /// The memory the node's running containers reserve, summed over their
    /// instance-type caps. A cell whose container is not running reserves
    /// nothing: a stopped container holds no memory, and an idle eviction
    /// stops it before the sample would count it.
    pub fn reserved_memory_bytes(&self) -> u64 {
        self.cells
            .lock()
            .unwrap()
            .values()
            .filter(|cell| cell.running())
            .map(|cell| {
                cell.state.lock().unwrap().execution.as_ref().map_or_else(
                    || instance_memory_bytes(cell.spec.instance_type.as_deref()),
                    |e| e.profile.memory_bytes,
                )
            })
            .sum()
    }

    /// This node's running containers per class.
    fn running_instances_by_class(&self) -> std::collections::BTreeMap<String, u64> {
        let mut counts = std::collections::BTreeMap::new();
        for cell in self.cells.lock().unwrap().values() {
            if cell.running() {
                *counts.entry(cell.spec.class_name.clone()).or_insert(0) += 1;
            }
        }
        counts
    }

    /// Refuse a start that would put the class over its fleet-wide
    /// `max_instances`. The fleet count is this node's own running
    /// containers of the class, read live, plus every peer's count from the
    /// shared capacity sample; `begin_run` already marked the starting cell
    /// running, so the live count includes it. A class with no
    /// `max_instances`, or a node with no bucket to read the sample from as
    /// under `celld dev`, has no fleet ceiling. See
    /// [`crate::ownership_store::fleet_class_instances`] for the staleness
    /// the sample admits.
    async fn enforce_instance_ceiling(&self, cell: &CellContainer) -> anyhow::Result<()> {
        let Some(max) = cell.spec.max_instances else {
            return Ok(());
        };
        let class = &cell.spec.class_name;
        let here = self
            .cells
            .lock()
            .unwrap()
            .values()
            .filter(|other| other.running() && other.spec.class_name == *class)
            .count() as u64;
        let elsewhere = match &self.bucket {
            Some(bucket) => {
                crate::ownership_store::fleet_class_instances(bucket, class, &self.node).await
            }
            None => 0,
        };
        anyhow::ensure!(
            here + elsewhere <= max,
            "container class {class} is at its max_instances limit of {max}: \
             {here} on this node and {elsewhere} on other nodes",
        );
        Ok(())
    }

    async fn inspect_owned(
        &self,
        cell: &CellContainer,
        run: Option<u64>,
    ) -> anyhow::Result<Option<Value>> {
        let reply = self
            .docker
            .call("GET", &format!("/containers/{}/json", cell.name), None)
            .await?;
        if reply.status.as_u16() == 404 {
            return Ok(None);
        }
        if !reply.status.is_success() {
            return Err(anyhow!(
                "inspect container failed with [{}] {}",
                reply.status.as_u16(),
                reply.message()
            ));
        }
        let info = reply.json()?;
        engine_container_id(&info)?;
        let labels = &info["Config"]["Labels"];
        anyhow::ensure!(
            labels["celld.node"].as_str() == Some(&self.node)
                && labels["celld.cell"].as_str() == Some(&cell.scope),
            "container name belongs to another owner"
        );
        if let Some(run) = run {
            anyhow::ensure!(
                labels["celld.run"].as_str() == Some(&run.to_string()),
                "container name belongs to another run"
            );
        }
        Ok(Some(info))
    }

    /// Start the cell's container for the run `begin_run` opened. The
    /// object's `start()` returns before this completes, as on Cloudflare;
    /// a failure surfaces through `monitor()`.
    pub async fn start(
        &self,
        cell: &Arc<CellContainer>,
        run: u64,
        params: StartParams,
    ) -> anyhow::Result<()> {
        let _lifecycle = cell.lifecycle.lock().await;
        {
            let state = cell.state.lock().unwrap();
            if state.run != run || !state.starting || state.stopping || state.retired {
                return Ok(());
            }
        }
        let started = self.create_and_start(cell, run, params).await;
        let address = match started {
            Ok(address) => address,
            Err(error) => {
                // `start()` is fire-and-forget for the object, and its
                // `monitor()` sees this error only if it was already
                // waiting; say it here too, or a start that fails fast
                // leaves no trace anywhere.
                tracing::warn!(
                    event = "container_start_failed",
                    cell = %cell.scope,
                    error = %format!("{error:#}"),
                    "the container did not start"
                );
                let mut state = cell.state.lock().unwrap();
                state.starting = false;
                // An ambiguous create/start can leave a live guest. Retain
                // its identity (or pending create) until destroy reconciles it.
                state.running = state.container_id.is_some() || state.creating;
                cell.exit
                    .send_replace(Some((run, Err(format!("{error:#}")))));
                return Err(error);
            }
        };
        {
            let mut state = cell.state.lock().unwrap();
            state.starting = false;
            state.running = true;
            state.address = address;
        }
        let id = cell
            .state
            .lock()
            .unwrap()
            .container_id
            .clone()
            .expect("started container has an ID");
        self.watch_exit(cell, run, id).detach();
        Ok(())
    }

    /// Wait for the container's root process to end and publish the exit
    /// for `run`; a later run's start has already replaced the state.
    fn watch_exit(
        &self,
        cell: &Arc<CellContainer>,
        run: u64,
        id: String,
    ) -> asyncrt::TaskHandle<()> {
        let docker = self.docker.clone();
        let cell_ = cell.clone();
        asyncrt::spawn(async move {
            let result = docker
                .call("POST", &format!("/containers/{id}/wait"), None)
                .await
                .and_then(|reply| {
                    if !reply.status.is_success() {
                        return Err(anyhow!(
                            "wait failed with [{}] {}",
                            reply.status.as_u16(),
                            reply.message()
                        ));
                    }
                    let body = reply.json()?;
                    // Docker can report a wait failure in a successful
                    // HTTP response. StatusCode alone is not an exit in
                    // that case.
                    if let Some(error) = body.get("Error").filter(|value| !value.is_null()) {
                        return Err(anyhow!("wait failed: {error}"));
                    }
                    body.get("StatusCode")
                        .and_then(Value::as_i64)
                        .ok_or_else(|| anyhow!("wait answered without a status code"))
                })
                .map_err(|error| format!("{error:#}"));
            let mut state = cell_.state.lock().unwrap();
            if state.run != run || state.container_id.as_deref() != Some(&id) {
                return;
            }
            if result.is_ok() {
                state.running = false;
                state.address = Address::None;
            }
            cell_.exit.send_replace(Some((run, result)));
        })
    }

    async fn create_and_start(
        &self,
        cell: &CellContainer,
        run: u64,
        params: StartParams,
    ) -> anyhow::Result<Address> {
        let execution = cell.state.lock().unwrap().execution.clone();
        anyhow::ensure!(
            execution.is_some() || !execution::required(&cell.spec.class_name)?,
            "this class requires a host execution grant"
        );
        if execution.is_none() {
            self.ensure_fence().await?;
        }
        self.enforce_instance_ceiling(cell).await?;
        self.ensure_image(&cell.spec.image).await?;
        let (open, internal) = if execution.is_some() {
            (String::new(), String::new())
        } else {
            self.networks().await?
        };
        let previous = cell.state.lock().unwrap().container_id.clone();
        if let Some(id) = previous {
            self.remove_container(&id).await?;
            cell.state.lock().unwrap().container_id = None;
            for id in cell.processes.lock().unwrap().drain(..) {
                drop_process(id);
            }
        }
        let mut env: Vec<String> = DEFAULT_ENV.iter().map(|entry| entry.to_string()).collect();
        env.push(format!("CLOUDFLARE_DURABLE_OBJECT_ID={}", cell.scope));
        env.extend(
            params
                .env
                .iter()
                .map(|(name, value)| format!("{name}={value}")),
        );
        let mut labels = serde_json::Map::new();
        labels.insert("celld.node".into(), json!(self.node));
        labels.insert("celld.cell".into(), json!(cell.scope));
        labels.insert("celld.class".into(), json!(cell.spec.class_name));
        labels.insert("celld.run".into(), json!(run.to_string()));
        for (name, value) in &params.labels {
            labels.insert(format!("celld.user.{name}"), json!(value));
        }
        // Off Linux the node reaches a container only through published
        // ports, and Docker publishes nothing on an internal network, so
        // `enableInternet: false` would make the container unreachable.
        // Development there keeps egress; the compat page says so.
        let offline = !params.enable_internet && cfg!(target_os = "linux");
        if !params.enable_internet && !offline {
            tracing::warn!(
                cell = %cell.scope,
                "enableInternet: false is not enforced on this platform; the container keeps egress"
            );
        }
        // A container is a tenant's process tree, not the operator's: no
        // capability, no privilege gain through setuid binaries, the
        // daemon's seccomp profile, and a process ceiling. What a class
        // legitimately needs beyond this is a config question for later,
        // not a default. The kernel boundary itself is the runtime's.
        let mut host_config = json!({
            "NetworkMode": if offline { &internal } else { &open },
            "PublishAllPorts": !cfg!(target_os = "linux"),
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "PidsLimit": PIDS_LIMIT,
            // An init as PID 1 reaps orphaned children. Without it a process
            // whose parent exits becomes a zombie the container holds until
            // it stops, and enough of them exhaust the PID ceiling; a fleet
            // fork bomb left exactly these behind.
            "Init": true,
        });
        // A class can name its own runtime, else the node default. A class
        // that needs isolation names `runsc`, and the node's daemon must
        // have it or the start fails, so the class runs only where its
        // isolation is real.
        let runtime = cell
            .spec
            .runtime
            .as_deref()
            .or(self.runtime.as_deref())
            .filter(|runtime| !runtime.is_empty());
        if let Some(runtime) = runtime {
            host_config["Runtime"] = json!(runtime);
        }
        // A container under a non-default runtime gets an explicit resolver
        // through a bind-mounted resolv.conf: gVisor cannot reach Docker's
        // embedded resolver at `127.0.0.11`, and on a user bridge Docker
        // keeps that address in resolv.conf whatever `--dns` says, so the
        // file itself must name a reachable resolver. An operator who set
        // `CELLD_CONTAINER_DNS` gets it for every container.
        let wants_resolver = runtime.is_some() || !self.dns.is_empty();
        if wants_resolver {
            if let Some(resolv) = &self.resolv_conf {
                let bind = format!("{}:/etc/resolv.conf:ro", resolv.display());
                host_config["Binds"] = json!([bind]);
            }
        }
        // Every container has a limit: a class without an instance type
        // gets Cloudflare's default type rather than the node.
        let instance_type = cell
            .spec
            .instance_type
            .as_deref()
            .unwrap_or(DEFAULT_INSTANCE_TYPE);
        let (vcpu, memory) =
            instance_resources(instance_type).expect("the deploy refused this instance type");
        host_config["NanoCpus"] = json!((vcpu * 1e9) as u64);
        host_config["Memory"] = json!(memory);
        host_config["MemorySwap"] = json!(memory);
        let mut body = json!({
            "Image": cell.spec.image,
            "Env": env,
            "Labels": labels,
            "HostConfig": host_config,
        });
        if let Some(entrypoint) = params.entrypoint {
            body["Cmd"] = json!(entrypoint);
        }
        if let Some(execution) = &execution {
            execution.check_live()?;
            // Load through celld's existing bucket/image integration, then insist
            // on the immutable image authorized by the host profile.
            let image = self
                .docker
                .expect(
                    "GET",
                    &format!("/images/{}/json", cell.spec.image),
                    None,
                    "inspect approved image",
                )
                .await?
                .json()?;
            anyhow::ensure!(
                image["Id"] == execution.profile.image,
                "class image does not match the host profile"
            );
            let labels = body["Labels"].clone();
            body = execution.body();
            body["Labels"] = labels;
            body["Labels"]["celld.execution"] = json!(execution.token);
            execution.check_live()?;
        }
        // A lost create reply is ambiguous. Keep the pending identity so a
        // later destroy can reconcile it by name, owner and run label.
        cell.state.lock().unwrap().creating = true;
        let reply = self
            .docker
            .call(
                "POST",
                &format!("/containers/create?name={}", cell.name),
                Some(body),
            )
            .await?;
        // Definite client refusals did not create this run. In particular a
        // 409 is not authority to delete whichever container now owns a name.
        if reply.status.is_client_error() {
            cell.state.lock().unwrap().creating = false;
        }
        if reply.status.as_u16() == 404 {
            return Err(anyhow!("No such image available named {}", cell.spec.image));
        }
        if !reply.status.is_success() {
            return Err(anyhow!(
                "Create container failed with [{}] {}",
                reply.status.as_u16(),
                reply.message()
            ));
        }
        let id = engine_container_id(&reply.json()?)?;
        {
            let mut state = cell.state.lock().unwrap();
            state.container_id = Some(id.clone());
            state.creating = false;
        }
        if let Some(execution) = &execution {
            execution.check_live()?;
        }
        self.docker
            .expect(
                "POST",
                &format!("/containers/{id}/start"),
                None,
                "start container",
            )
            .await?;
        let info = self
            .docker
            .expect(
                "GET",
                &format!("/containers/{id}/json"),
                None,
                "inspect container",
            )
            .await?
            .json()?;
        anyhow::ensure!(
            engine_container_id(&info)? == id,
            "inspect answered for another container"
        );
        Ok(address_of(&info))
    }

    /// Wait for the current run to end. `Ok(code)` is the root process's
    /// exit code; a destroyed container reports 137.
    pub async fn monitor(&self, cell: &Arc<CellContainer>, run: u64) -> Result<i64, String> {
        let mut receiver = cell.exit.subscribe();
        loop {
            if let Some((ended, result)) = receiver.borrow_and_update().clone() {
                if ended == run {
                    return result;
                }
            }
            if cell.current_run() != run {
                return Err("the monitored container run was superseded".into());
            }
            if receiver.changed().await.is_err() {
                return Err("the container engine went away".to_string());
            }
        }
    }

    #[cfg(test)]
    pub async fn destroy(&self, cell: &Arc<CellContainer>) -> anyhow::Result<()> {
        let run = cell.request_destroy();
        self.destroy_run(cell, run).await
    }

    pub async fn destroy_run(&self, cell: &Arc<CellContainer>, run: u64) -> anyhow::Result<()> {
        let _lifecycle = cell.lifecycle.lock().await;
        self.destroy_locked(cell, run, false).await
    }

    async fn destroy_locked(
        &self,
        cell: &CellContainer,
        run: u64,
        retire: bool,
    ) -> anyhow::Result<()> {
        {
            let mut state = cell.state.lock().unwrap();
            if state.run != run || state.retired {
                return Ok(());
            }
            state.stopping = true;
        }
        let execution = {
            let state = cell.state.lock().unwrap();
            state
                .execution
                .clone()
                .filter(|_| state.container_id.is_some() || state.creating)
        };
        if let Some(execution) = execution {
            execution.fence()?;
        }
        let creating = cell.state.lock().unwrap().creating;
        if creating {
            let info = self.inspect_owned(cell, Some(run)).await?;
            let id = info.as_ref().map(engine_container_id).transpose()?;
            let mut state = cell.state.lock().unwrap();
            state.container_id = id;
            state.creating = false;
        }
        let id = cell.state.lock().unwrap().container_id.clone();
        // Kill first so the wait task reports 137 before the removal makes
        // the name disappear under it. The process may already have exited
        // or been removed, so a failed kill can still be followed by a
        // successful force-remove. Only confirmed removal (including 404)
        // lets this call acknowledge destruction.
        if let Some(id) = id {
            let _ = self
                .docker
                .call(
                    "POST",
                    &format!("/containers/{id}/kill?signal=SIGKILL"),
                    None,
                )
                .await;
            self.remove_container(&id).await?;
        }
        let mut state = cell.state.lock().unwrap();
        state.running = false;
        state.starting = false;
        state.stopping = false;
        state.container_id = None;
        state.retired = retire;
        state.address = Address::None;
        // A removed run has a terminal result even if its delayed Docker wait
        // answers 404. Preserve a process exit already observed for this run.
        cell.exit.send_if_modified(|exit| {
            if matches!(exit, Some((ended, Ok(_))) if *ended == run) {
                return false;
            }
            *exit = Some((run, Ok(137)));
            true
        });
        Ok(())
    }

    /// Execute a host-approved command and remove its process tree before
    /// returning output. Mount contents are retained for the host's checkpoint.
    pub async fn run_execution(
        &self,
        cell: &Arc<CellContainer>,
        run: u64,
        token: &str,
    ) -> anyhow::Result<Value> {
        let execution = match execution::Execution::claim(&cell.scope, &cell.spec.class_name, token)
        {
            Ok(execution) => Arc::new(execution),
            Err(error) => {
                let mut state = cell.state.lock().unwrap();
                if state.run == run {
                    state.running = state.container_id.is_some() || state.creating;
                    state.starting = false;
                    cell.exit
                        .send_replace(Some((run, Err(format!("{error:#}")))));
                }
                return Err(error);
            }
        };
        {
            let mut state = cell.state.lock().unwrap();
            anyhow::ensure!(
                state.run == run && !state.retired,
                "execution was superseded"
            );
            state.execution = Some(execution.clone());
        }
        let deadline = Duration::from_millis(execution.grant.deadline_ms);
        let outcome = asyncrt::timeout(deadline, async {
            self.start(
                cell,
                run,
                StartParams {
                    entrypoint: None,
                    env: Vec::new(),
                    enable_internet: false,
                    labels: Vec::new(),
                },
            )
            .await?;
            self.monitor(cell, run).await.map_err(anyhow::Error::msg)
        })
        .await;
        // Keep a persistent kernel fence even if a daemon reply is lost or a
        // start request completes after our own deadline. The host owns its removal.
        execution.fence()?;
        let _lifecycle = cell.lifecycle.lock().await;
        let id = {
            let state = cell.state.lock().unwrap();
            anyhow::ensure!(state.run == run, "execution was superseded");
            state.container_id.clone()
        };
        let output = if let Some(id) = &id {
            self.execution_output(id).await
        } else {
            Ok((String::new(), String::new()))
        };
        self.destroy_locked(cell, run, false).await?;
        let (stdout, stderr) = output?;
        let code = match outcome {
            Ok(Ok(code)) => code,
            Ok(Err(error)) => return Err(error),
            Err(_) => 124,
        };
        Ok(
            json!({"exitCode":code,"stdout":stdout,"stderr":stderr,"stopped":true,"execution":token}),
        )
    }

    pub async fn stop_execution(
        &self,
        cell: &Arc<CellContainer>,
        token: &str,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(execution::token_valid(token), "invalid execution token");
        let cgroup = execution::revoke(&cell.scope, &cell.spec.class_name, token)?;
        let run = {
            let mut state = cell.state.lock().unwrap();
            if state.execution.as_ref().is_some_and(|e| e.token == token) {
                state.stopping = true;
                Some(state.run)
            } else {
                None
            }
        };
        let _lifecycle = cell.lifecycle.lock().await;
        if let Some(run) = run {
            self.destroy_locked(cell, run, false).await
        } else {
            self.remove_recovered_execution(cell, token, &cgroup).await
        }
    }

    // Process/node identity changes after a restart. The protected host grant
    // authorizes cleanup of this exact execution across those identities, not
    // a mutable name or another execution now occupying the cell's slot.
    async fn remove_recovered_execution(
        &self,
        cell: &CellContainer,
        token: &str,
        cgroup: &std::path::Path,
    ) -> anyhow::Result<()> {
        let filters = json!({"label":[format!("celld.execution={token}"), format!("celld.cell={}", cell.scope)]}).to_string();
        let list = self
            .docker
            .expect(
                "GET",
                &format!(
                    "/containers/json?all=true&filters={}",
                    percent_encoding::utf8_percent_encode(
                        &filters,
                        percent_encoding::NON_ALPHANUMERIC
                    )
                ),
                None,
                "list issued execution",
            )
            .await?
            .json()?;
        let list = list
            .as_array()
            .ok_or_else(|| anyhow!("execution list answered without an array"))?;
        let expected_group = format!("/{}", cgroup.strip_prefix("/sys/fs/cgroup")?.display());
        for entry in list {
            let id = engine_container_id(entry)?;
            let reply = self
                .docker
                .call("GET", &format!("/containers/{id}/json"), None)
                .await?;
            if reply.status.as_u16() == 404 {
                continue;
            }
            anyhow::ensure!(
                reply.status.is_success(),
                "inspect recovered execution failed"
            );
            let info = reply.json()?;
            let labels = &info["Config"]["Labels"];
            anyhow::ensure!(
                engine_container_id(&info)? == id
                    && labels["celld.execution"].as_str() == Some(token)
                    && labels["celld.cell"].as_str() == Some(&cell.scope)
                    && labels["celld.class"].as_str() == Some(&cell.spec.class_name)
                    && info["HostConfig"]["CgroupParent"].as_str() == Some(&expected_group),
                "recovered container does not match the issued execution"
            );
            let (run, attached) = {
                let state = cell.state.lock().unwrap();
                (state.run, state.container_id.as_deref() == Some(&id))
            };
            if attached {
                self.destroy_locked(cell, run, false).await?;
            } else {
                self.remove_container(&id).await?;
            }
        }
        Ok(())
    }

    async fn execution_output(&self, id: &str) -> anyhow::Result<(String, String)> {
        let reply = self
            .docker
            .expect(
                "GET",
                &format!("/containers/{id}/logs?stdout=true&stderr=true"),
                None,
                "execution logs",
            )
            .await?;
        anyhow::ensure!(
            reply.body.len() <= 5 * 1024 * 1024,
            "execution output exceeds limit"
        );
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let mut rest: &[u8] = &reply.body;
        while !rest.is_empty() {
            anyhow::ensure!(rest.len() >= 8, "truncated execution output");
            let (stream, length) = frame_header(rest[..8].try_into().unwrap());
            anyhow::ensure!(
                length <= rest.len() - 8 && [1, 2].contains(&stream),
                "invalid execution output"
            );
            let target = if stream == 1 {
                &mut stdout
            } else {
                &mut stderr
            };
            target.extend_from_slice(&rest[8..8 + length]);
            rest = &rest[8 + length..];
        }
        Ok((String::from_utf8(stdout)?, String::from_utf8(stderr)?))
    }

    pub async fn signal(
        &self,
        cell: &Arc<CellContainer>,
        run: u64,
        signal: u32,
    ) -> anyhow::Result<()> {
        let _lifecycle = cell.lifecycle.lock().await;
        let id = self.running_id(cell, run)?;
        self.docker
            .expect(
                "POST",
                &format!("/containers/{id}/kill?signal={signal}"),
                None,
                "signal container",
            )
            .await?;
        Ok(())
    }

    /// The cell left this node's runtime. An idle eviction keeps the
    /// container for its inactivity window; anything else destroys it, and
    /// the stop waits for that: a drain ends the process right after its
    /// last stop, and a destroy left to a detached task did not always get
    /// its two daemon calls in before the exit.
    pub async fn release(self: &Arc<Self>, scope: &str, release: Release) {
        let Some(cell) = self.cell(scope) else {
            return;
        };
        match release {
            Release::Keep => {
                let mut state = cell.state.lock().unwrap();
                state.idle_epoch += 1;
                let epoch = state.idle_epoch;
                let window = state.inactivity.unwrap_or(DEFAULT_INACTIVITY);
                let engine = self.clone();
                let cell_ = cell.clone();
                let (cancel, cancelled) = tokio::sync::oneshot::channel();
                asyncrt::spawn(async move {
                    asyncrt::select! {
                        _ = asyncrt::sleep(window) => {},
                        _ = cancelled => return,
                    }
                    engine.forget_idle(&cell_, Some(epoch)).await;
                })
                .detach();
                state.sweeper = Some(cancel);
            }
            Release::Destroy => self.forget(&cell).await,
        }
    }

    async fn forget(&self, cell: &Arc<CellContainer>) {
        self.forget_idle(cell, None).await;
    }

    async fn forget_idle(&self, cell: &Arc<CellContainer>, idle_epoch: Option<u64>) {
        // An ownership release fences starts before waiting for another
        // lifecycle operation. An idle timer instead validates its epoch
        // under the lock, so it cannot fence a returning activation.
        let requested_run = idle_epoch.is_none().then(|| cell.request_destroy());
        let _lifecycle = cell.lifecycle.lock().await;
        let run = {
            let mut state = cell.state.lock().unwrap();
            if state.retired
                || idle_epoch.is_some_and(|epoch| epoch != state.idle_epoch)
                || requested_run.is_some_and(|run| run != state.run)
            {
                return;
            }
            state.stopping = true;
            state.run
        };
        if let Err(error) = self.destroy_locked(cell, run, true).await {
            tracing::warn!(
                event = "container_destroy_failed",
                cell = %cell.scope,
                error = %format!("{error:#}"),
                "retaining the container handle for a later cleanup attempt"
            );
            return;
        }
        for id in cell.processes.lock().unwrap().drain(..) {
            drop_process(id);
        }
        let mut cells = self.cells.lock().unwrap();
        if cells
            .get(&cell.scope)
            .is_some_and(|current| Arc::ptr_eq(current, cell))
        {
            cells.remove(&cell.scope);
        }
    }

    pub async fn exec(
        &self,
        cell: &Arc<CellContainer>,
        run: u64,
        params: ExecParams,
    ) -> anyhow::Result<Arc<ExecProcess>> {
        let _lifecycle = cell.lifecycle.lock().await;
        let container_id = self.running_id(cell, run)?;
        anyhow::ensure!(
            cell.state.lock().unwrap().execution.is_none(),
            "host-issued executions cannot accept additional execs"
        );
        let mut body = json!({
            "AttachStdin": true,
            "AttachStdout": true,
            "AttachStderr": true,
            "Tty": false,
            "Cmd": params.cmd,
        });
        if !params.env.is_empty() {
            body["Env"] = json!(params
                .env
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>());
        }
        if let Some(cwd) = &params.cwd {
            body["WorkingDir"] = json!(cwd);
        }
        if let Some(user) = &params.user {
            body["User"] = json!(user);
        }
        let created = self
            .docker
            .expect(
                "POST",
                &format!("/containers/{container_id}/exec"),
                Some(body),
                "create exec",
            )
            .await?
            .json()?;
        let exec_id = created
            .get("Id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("exec create answered without an id"))?
            .to_string();
        let stream = self
            .docker
            .hijack(
                &format!("/exec/{exec_id}/start"),
                json!({ "Detach": false, "Tty": false }),
            )
            .await?;
        // Docker reports `Running: false` with no pid before it has spawned
        // the process, and a finished exec keeps its pid, so a pid of zero
        // is the one answer that means "not yet": retry it briefly, as
        // workerd does. Breaking on `Running: false` here lost the pid of a
        // short command whenever the inspect landed in that window.
        let mut pid = 0;
        for _ in 0..20 {
            let info = self
                .docker
                .expect(
                    "GET",
                    &format!("/exec/{exec_id}/json"),
                    None,
                    "inspect exec",
                )
                .await?
                .json()?;
            pid = info.get("Pid").and_then(Value::as_i64).unwrap_or(0);
            if pid != 0 {
                break;
            }
            asyncrt::sleep(Duration::from_millis(50)).await;
        }
        let (read, write) = tokio::io::split(stream);
        let (stdout_tx, stdout_rx) = mpsc::channel(16);
        let (stderr_tx, stderr_rx) = mpsc::channel(16);
        let combined = params.combined;
        let ended = watch::channel(false).0;
        let ended_ = ended.clone();
        asyncrt::spawn(async move {
            demux(read, stdout_tx, stderr_tx, combined).await;
            ended_.send_replace(true);
        })
        .detach();
        let process = Arc::new(ExecProcess {
            id: next_exec_id(),
            exec_id,
            container: container_id,
            pid,
            docker: self.docker.clone(),
            stdin: tokio::sync::Mutex::new(Some(write)),
            stdout: tokio::sync::Mutex::new(stdout_rx),
            stderr: tokio::sync::Mutex::new(stderr_rx),
            ended,
            exit_code: tokio::sync::Mutex::new(None),
        });
        processes()
            .lock()
            .unwrap()
            .insert(process.id, process.clone());
        cell.processes.lock().unwrap().push(process.id);
        Ok(process)
    }

    fn running_id(&self, cell: &CellContainer, run: u64) -> anyhow::Result<String> {
        let state = cell.state.lock().unwrap();
        anyhow::ensure!(
            state.run == run
                && state.running
                && !state.starting
                && !state.stopping
                && !state.retired,
            "the requested container run is not available"
        );
        state
            .container_id
            .clone()
            .ok_or_else(|| anyhow!("the container has no confirmed engine ID"))
    }
}

/// Full IDs cannot be reinterpreted as a mutable name or ambiguous prefix.
fn engine_container_id(info: &Value) -> anyhow::Result<String> {
    let id = info
        .get("Id")
        .and_then(Value::as_str)
        .filter(|id| id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| anyhow!("container response has no full engine ID"))?;
    Ok(id.to_string())
}

#[cfg(all(test, not(celld_internal_tests)))]
mod lifecycle_tests;

pub struct ExecParams {
    pub cmd: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<String>,
    pub user: Option<String>,
    /// stderr folded into stdout.
    pub combined: bool,
}

type WriteHalf = tokio::io::WriteHalf<Box<dyn Stream>>;

pub struct ExecProcess {
    pub id: u64,
    exec_id: String,
    container: String,
    pub pid: i64,
    docker: Docker,
    stdin: tokio::sync::Mutex<Option<WriteHalf>>,
    stdout: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    stderr: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    /// True once the hijacked stream reached EOF, which the daemon sends
    /// when the process exits.
    ended: watch::Sender<bool>,
    exit_code: tokio::sync::Mutex<Option<i64>>,
}

fn processes() -> &'static Mutex<HashMap<u64, Arc<ExecProcess>>> {
    static PROCESSES: OnceLock<Mutex<HashMap<u64, Arc<ExecProcess>>>> = OnceLock::new();
    PROCESSES.get_or_init(Default::default)
}

fn next_exec_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

pub fn process(id: u64) -> Option<Arc<ExecProcess>> {
    processes().lock().unwrap().get(&id).cloned()
}

pub fn drop_process(id: u64) {
    processes().lock().unwrap().remove(&id);
}

impl ExecProcess {
    /// One chunk of stdout (`1`) or stderr (`2`); empty at end of stream.
    pub async fn read(&self, which: u8) -> Bytes {
        let mut receiver = match which {
            1 => self.stdout.lock().await,
            _ => self.stderr.lock().await,
        };
        receiver.recv().await.unwrap_or_default()
    }

    pub async fn write(&self, bytes: &[u8]) -> Result<(), String> {
        let mut guard = self.stdin.lock().await;
        let stdin = guard.as_mut().ok_or("stdin is closed")?;
        stdin
            .write_all(bytes)
            .await
            .map_err(|error| format!("stdin write failed: {error}"))?;
        stdin
            .flush()
            .await
            .map_err(|error| format!("stdin flush failed: {error}"))
    }

    /// End stdin. Half-closing the hijacked connection is how the daemon
    /// learns the process's stdin reached EOF.
    pub async fn close_stdin(&self) {
        if let Some(mut stdin) = self.stdin.lock().await.take() {
            let _ = stdin.shutdown().await;
        }
    }

    pub async fn wait(&self) -> anyhow::Result<i64> {
        let mut exit = self.exit_code.lock().await;
        if let Some(code) = *exit {
            return Ok(code);
        }
        let mut ended = self.ended.subscribe();
        while !*ended.borrow_and_update() {
            if ended.changed().await.is_err() {
                break;
            }
        }
        // The stream closes when the process exits, but the daemon records
        // the exit code a moment later.
        let mut code = None;
        for _ in 0..40 {
            let info = self
                .docker
                .expect(
                    "GET",
                    &format!("/exec/{}/json", self.exec_id),
                    None,
                    "inspect exec",
                )
                .await?
                .json()?;
            if !info
                .get("Running")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                code = info.get("ExitCode").and_then(Value::as_i64);
                break;
            }
            asyncrt::sleep(Duration::from_millis(50)).await;
        }
        let code = code.ok_or_else(|| anyhow!("the process did not report an exit code"))?;
        *exit = Some(code);
        Ok(code)
    }

    /// The Engine API has no exec kill, so the signal is delivered by a
    /// second exec of `kill`, as workerd does.
    pub async fn kill(&self, signal: u32) -> anyhow::Result<()> {
        let body = json!({
            "AttachStdin": false, "AttachStdout": false, "AttachStderr": false,
            "Cmd": ["kill", format!("-{signal}"), self.pid.to_string()],
        });
        let created = self
            .docker
            .expect(
                "POST",
                &format!("/containers/{}/exec", self.container),
                Some(body),
                "create exec",
            )
            .await?
            .json()?;
        let id = created
            .get("Id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("exec create answered without an id"))?;
        self.docker
            .expect(
                "POST",
                &format!("/exec/{id}/start"),
                Some(json!({ "Detach": true })),
                "start exec",
            )
            .await?;
        Ok(())
    }
}

/// Split Docker's multiplexed stream into stdout and stderr chunks until
/// the daemon closes it.
async fn demux(
    mut read: tokio::io::ReadHalf<Box<dyn Stream>>,
    stdout: mpsc::Sender<Bytes>,
    stderr: mpsc::Sender<Bytes>,
    combined: bool,
) {
    let mut header = [0u8; 8];
    loop {
        if read.read_exact(&mut header).await.is_err() {
            return;
        }
        let (stream, length) = frame_header(&header);
        let mut payload = vec![0u8; length];
        if read.read_exact(&mut payload).await.is_err() {
            return;
        }
        let target = if stream == 2 && !combined {
            &stderr
        } else {
            &stdout
        };
        if target.send(Bytes::from(payload)).await.is_err() {
            // The reader went away; keep draining so the process is not
            // blocked on a full pipe.
            continue;
        }
    }
}

fn address_of(info: &Value) -> Address {
    if cfg!(target_os = "linux") {
        let ip = info
            .pointer("/NetworkSettings/Networks")
            .and_then(Value::as_object)
            .and_then(|networks| networks.values().next())
            .and_then(|network| network.get("IPAddress"))
            .and_then(Value::as_str)
            .filter(|ip| !ip.is_empty());
        return ip.map_or(Address::None, |ip| Address::Ip(ip.to_string()));
    }
    let mut ports = HashMap::new();
    if let Some(map) = info
        .pointer("/NetworkSettings/Ports")
        .and_then(Value::as_object)
    {
        for (key, bindings) in map {
            let Some(port) = key
                .strip_suffix("/tcp")
                .and_then(|port| port.parse::<u16>().ok())
            else {
                continue;
            };
            let host = bindings
                .as_array()
                .into_iter()
                .flatten()
                .find_map(|binding| binding.get("HostPort")?.as_str()?.parse::<u16>().ok());
            if let Some(host) = host {
                ports.insert(port, host);
            }
        }
    }
    Address::Published(ports)
}

/// A Docker name from a node and a cell scope: the scope's characters are
/// not all legal, so the name is a hash and the scope rides in a label.
/// The node is part of it because two nodes can share one engine in a
/// development or test setup, and a name from the scope alone let one
/// node adopt, or reap, the other's container for the same object.
fn container_name(node: &str, scope: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(format!("{node}\n{scope}").as_bytes());
    format!("celld-{:x}", digest)[..30].to_string()
}
