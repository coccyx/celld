// Copyright 2026 Deno Land Inc. Apache-2.0 license.

//! Exercise the real Docker HTTP client against a scripted local daemon.
//! No Docker installation, credentials, or private test corpus is required.

#![allow(clippy::disallowed_methods)] // The fixture uses real local I/O and bounded waits.

use super::*;
use tokio::net::UnixListener;
use tokio::sync::oneshot;

const TEST_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NEXT_ID: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn recovered_info() -> Value {
    json!({"Id":TEST_ID,"Config":{"Labels":{
        "celld.node":"previous-process", "celld.cell":"test-scope", "celld.class":"Test",
        "celld.execution":"c".repeat(64)}},"HostConfig":{"CgroupParent":"/issued/task/guest"}})
}
fn recovery_replies(info: Value) -> Vec<Reply> {
    vec![
        Reply {
            method: "GET",
            path: "/containers/json?".into(),
            status: 200,
            body: json!([{"Id":TEST_ID}]),
            gate: None,
        },
        Reply {
            method: "GET",
            path: format!("/containers/{TEST_ID}/json"),
            status: 200,
            body: info,
            gate: None,
        },
    ]
}

#[tokio::test]
async fn issued_execution_recovery_removes_previous_process_container_by_exact_id() {
    let mut replies = recovery_replies(recovered_info());
    replies.push(remove(&format!("/containers/{TEST_ID}?force=true"), 204));
    let (engine, cell, daemon) = fixture(replies);
    // A new node has no in-memory association with the old execution. Its
    // current run must not be changed by cleanup of the separately issued run.
    cell.state.lock().unwrap().container_id = Some(NEXT_ID.into());
    engine
        .remove_recovered_execution(
            &cell,
            &"c".repeat(64),
            std::path::Path::new("/sys/fs/cgroup/issued/task/guest"),
        )
        .await
        .unwrap();
    assert_eq!(
        cell.state.lock().unwrap().container_id.as_deref(),
        Some(NEXT_ID)
    );
    let path = daemon.requests.lock().unwrap()[0].1.clone();
    let filter = path.split("&filters=").nth(1).unwrap();
    let decoded = percent_encoding::percent_decode_str(filter)
        .decode_utf8()
        .unwrap();
    let value: Value = serde_json::from_str(&decoded).unwrap();
    assert_eq!(
        value,
        json!({"label":[format!("celld.execution={}","c".repeat(64)),"celld.cell=test-scope"]})
    );
    daemon.finish().await;
}

#[tokio::test]
async fn issued_execution_recovery_revalidates_every_identity_before_removal() {
    for pointer in [
        "/Id",
        "/Config/Labels/celld.execution",
        "/Config/Labels/celld.cell",
        "/Config/Labels/celld.class",
        "/HostConfig/CgroupParent",
    ] {
        let mut info = recovered_info();
        *info.pointer_mut(pointer).unwrap() = json!(NEXT_ID);
        let (engine, cell, daemon) = fixture(recovery_replies(info));
        assert!(engine
            .remove_recovered_execution(
                &cell,
                &"c".repeat(64),
                std::path::Path::new("/sys/fs/cgroup/issued/task/guest")
            )
            .await
            .is_err());
        daemon.finish().await;
    }
}

#[tokio::test]
async fn issued_execution_recovery_does_not_acknowledge_engine_failure() {
    for stage in 0..3 {
        let mut replies = recovery_replies(recovered_info());
        replies.push(remove(&format!("/containers/{TEST_ID}?force=true"), 204));
        replies[stage].status = 500;
        replies.truncate(stage + 1);
        let (engine, cell, daemon) = fixture(replies);
        cell.state.lock().unwrap().container_id = None;
        assert!(engine
            .remove_recovered_execution(
                &cell,
                &"c".repeat(64),
                std::path::Path::new("/sys/fs/cgroup/issued/task/guest")
            )
            .await
            .is_err());
        daemon.finish().await;
    }
}

#[tokio::test]
async fn issued_execution_recovery_clears_an_adopted_handle_after_confirmed_removal() {
    let mut replies = recovery_replies(recovered_info());
    replies.push(kill(409));
    replies.push(remove(&format!("/containers/{TEST_ID}?force=true"), 204));
    let (engine, cell, daemon) = fixture(replies);
    engine
        .remove_recovered_execution(
            &cell,
            &"c".repeat(64),
            std::path::Path::new("/sys/fs/cgroup/issued/task/guest"),
        )
        .await
        .unwrap();
    assert!(!cell.running());
    assert!(cell.state.lock().unwrap().container_id.is_none());
    daemon.finish().await;
}

struct Reply {
    method: &'static str,
    path: String,
    status: u16,
    body: Value,
    gate: Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>,
}

fn kill(status: u16) -> Reply {
    Reply {
        method: "POST",
        path: format!("/containers/{TEST_ID}/kill?signal=SIGKILL"),
        status,
        body: json!({ "message": "kill response" }),
        gate: None,
    }
}

fn remove(id: &str, status: u16) -> Reply {
    Reply {
        method: "DELETE",
        path: id.into(),
        status,
        body: json!({ "message": "removal response" }),
        gate: None,
    }
}

fn wait(status: u16, body: Value) -> Reply {
    Reply {
        method: "POST",
        path: format!("/containers/{TEST_ID}/wait"),
        status,
        body,
        gate: None,
    }
}

struct Daemon {
    _dir: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
    requests: Arc<Mutex<Vec<(String, String, Value)>>>,
}

impl Daemon {
    async fn finish(self) {
        tokio::time::timeout(Duration::from_secs(3), self.task)
            .await
            .expect("daemon did not receive all expected calls")
            .expect("unexpected daemon request");
    }
}

fn fixture(replies: Vec<Reply>) -> (ContainerEngine, Arc<CellContainer>, Daemon) {
    // asyncrt retains one process-wide host handle. Keep that runtime alive
    // across tests instead of capturing a per-test runtime that is dropped.
    static HOST: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let host = HOST.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    });
    asyncrt::set_host_handle(host.handle().clone());
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("engine.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = requests.clone();
    let task = tokio::spawn(async move {
        let mut responses = Vec::new();
        for reply in replies {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                headers.push(stream.read_u8().await.unwrap());
                assert!(headers.len() < 16 * 1024, "unbounded request headers");
            }
            let headers = String::from_utf8(headers).unwrap();
            let mut line = headers.lines().next().unwrap().split_whitespace();
            let method = line.next().unwrap();
            let path = line.next().unwrap();
            assert_eq!(method, reply.method);
            if reply.path.ends_with('?') {
                assert!(path.starts_with(&reply.path), "unexpected path {path}");
            } else {
                assert_eq!(path, reply.path);
            }
            let length = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                .map_or(0, |(_, value)| value.trim().parse::<usize>().unwrap());
            assert!(length < 65536);
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await.unwrap();
            let body = if body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&body).unwrap()
            };
            observed
                .lock()
                .unwrap()
                .push((method.into(), path.into(), body));
            responses.push(tokio::spawn(async move {
                if let Some((entered, resume)) = reply.gate {
                    entered.send(()).unwrap();
                    resume.await.unwrap();
                }
                if reply.status == 101 {
                stream.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n").await.unwrap();
                return;
            }
            // A disconnected request models an ambiguous engine failure:
                // the caller cannot know whether the operation took effect.
                if reply.status == 0 {
                    return;
                }
                let body = if reply.status == 204 {
                    String::new()
                } else {
                    reply.body.to_string()
                };
                let response = format!(
                    "HTTP/1.1 {} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    reply.status,
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }));
        }
        for response in responses {
            response.await.unwrap();
        }
    });
    let cell = Arc::new(CellContainer {
        scope: "test-scope".into(),
        name: "test-container".into(),
        spec: Arc::new(ContainerSpec {
            class_name: "Test".into(),
            image: "test-image".into(),
            instance_type: None,
            max_instances: None,
            runtime: None,
        }),
        state: Mutex::new(CellState {
            running: true,
            run: 1,
            container_id: Some(TEST_ID.into()),
            address: Address::Ip("192.0.2.1".into()),
            ..CellState::default()
        }),
        lifecycle: tokio::sync::Mutex::new(()),
        processes: Mutex::new(Vec::new()),
        exit: watch::channel(None).0,
    });
    let engine = ContainerEngine {
        runtime: None,
        dns: Vec::new(),
        resolv_conf: None,
        docker: Docker::new(socket),
        node: "test-node".into(),
        bucket: None,
        images: Mutex::new(HashMap::new()),
        cells: Mutex::new(HashMap::from([(cell.scope.clone(), cell.clone())])),
        networks: tokio::sync::Mutex::new(None),
        fenced: tokio::sync::Mutex::new(false),
    };
    (
        engine,
        cell,
        Daemon {
            _dir: dir,
            task,
            requests,
        },
    )
}

#[tokio::test]
async fn destroy_reports_engine_errors_and_preserves_retry_state() {
    for status in [500, 409, 0] {
        let (engine, cell, daemon) = fixture(vec![
            kill(500),
            remove(&format!("/containers/{TEST_ID}?force=true"), status),
        ]);
        let error = engine.destroy(&cell).await.unwrap_err();
        assert!(format!("{error:#}").contains("remove container"));
        assert!(
            cell.running(),
            "unknown state must not permit another start"
        );
        assert_eq!(cell.address(8080).unwrap(), "192.0.2.1:8080");
        daemon.finish().await;
    }
}

#[tokio::test]
async fn destroy_accepts_confirmed_removal_after_a_failed_kill() {
    for kill_status in [409, 404, 500, 0] {
        let (engine, cell, daemon) = fixture(vec![
            kill(kill_status),
            remove(&format!("/containers/{TEST_ID}?force=true"), 204),
        ]);
        engine.destroy(&cell).await.unwrap();
        assert!(!cell.running());
        assert!(cell.address(8080).is_err());
        daemon.finish().await;
    }
}

#[tokio::test]
async fn destroy_is_idempotent_when_the_container_is_already_absent() {
    let (engine, cell, daemon) = fixture(vec![
        kill(404),
        remove(&format!("/containers/{TEST_ID}?force=true"), 404),
    ]);
    engine.destroy(&cell).await.unwrap();
    assert!(!cell.running());
    daemon.finish().await;
}

#[tokio::test]
async fn failed_forget_retains_the_handle_until_cleanup_succeeds() {
    let (engine, cell, daemon) = fixture(vec![
        kill(500),
        remove(&format!("/containers/{TEST_ID}?force=true"), 500),
        kill(204),
        remove(&format!("/containers/{TEST_ID}?force=true"), 204),
    ]);
    cell.processes.lock().unwrap().push(u64::MAX);
    engine.forget(&cell).await;
    assert!(Arc::ptr_eq(&engine.cell(&cell.scope).unwrap(), &cell));
    assert!(cell.running());
    assert_eq!(*cell.processes.lock().unwrap(), vec![u64::MAX]);

    engine.forget(&cell).await;
    assert!(engine.cell(&cell.scope).is_none());
    assert!(!cell.running());
    assert!(cell.processes.lock().unwrap().is_empty());
    daemon.finish().await;
}

#[tokio::test]
async fn reap_attempts_every_container_and_reports_failures() {
    let (engine, _, daemon) = fixture(vec![
        Reply {
            method: "GET",
            path: "/containers/json?".into(),
            status: 200,
            body: json!([{ "Id": "a" }, { "Id": "b" }, { "Id": "c" }]),
            gate: None,
        },
        remove("/containers/a?force=true", 500),
        remove("/containers/b?force=true", 204),
        remove("/containers/c?force=true", 404),
    ]);
    let error = engine.reap().await.unwrap_err();
    assert!(format!("{error:#}").contains("a: remove container failed with [500]"));
    daemon.finish().await;
}

#[tokio::test]
async fn reap_rejects_malformed_inventory() {
    for body in [json!({}), json!([{}])] {
        let (engine, _, daemon) = fixture(vec![Reply {
            method: "GET",
            path: "/containers/json?".into(),
            status: 200,
            body,
            gate: None,
        }]);
        assert!(engine.reap().await.is_err());
        daemon.finish().await;
    }
}

async fn observed_exit(engine: &ContainerEngine, cell: &Arc<CellContainer>) -> Result<i64, String> {
    let mut exit = cell.exit.subscribe();
    engine.watch_exit(cell, 1, TEST_ID.into());
    tokio::time::timeout(Duration::from_secs(3), exit.changed())
        .await
        .expect("wait result was not published")
        .unwrap();
    let (run, result) = exit.borrow().clone().unwrap();
    assert_eq!(run, 1);
    result
}

#[tokio::test]
async fn failed_wait_is_not_a_confirmed_process_exit() {
    for reply in [
        wait(500, json!({ "message": "daemon failure" })),
        wait(0, Value::Null),
        wait(200, json!({})),
        wait(
            200,
            json!({ "StatusCode": 0, "Error": { "Message": "wait failed" } }),
        ),
    ] {
        let (engine, cell, daemon) = fixture(vec![reply]);
        assert!(observed_exit(&engine, &cell).await.is_err());
        assert!(
            cell.running(),
            "an unobserved exit must retain running state"
        );
        daemon.finish().await;
    }
}

#[tokio::test]
async fn successful_wait_publishes_the_exit_code_and_stopped_state() {
    for code in [0, 137] {
        let (engine, cell, daemon) = fixture(vec![wait(
            200,
            json!({ "StatusCode": code, "Error": null }),
        )]);
        assert_eq!(observed_exit(&engine, &cell).await.unwrap(), code);
        assert!(!cell.running());
        assert!(cell.address(8080).is_err());
        daemon.finish().await;
    }
}

fn reply(method: &'static str, path: impl Into<String>, status: u16, body: Value) -> Reply {
    Reply {
        method,
        path: path.into(),
        status,
        body,
        gate: None,
    }
}

fn paused(mut reply: Reply) -> (Reply, oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (entered, received) = oneshot::channel();
    let (resume, resumed) = oneshot::channel();
    reply.gate = Some((entered, resumed));
    (reply, received, resume)
}

async fn entered(received: oneshot::Receiver<()>) {
    tokio::time::timeout(Duration::from_secs(3), received)
        .await
        .unwrap()
        .unwrap();
}

fn prepare_start(engine: &ContainerEngine, cell: &CellContainer) -> u64 {
    // These unrelated integrations have their own real-engine qualification.
    *engine.fenced.try_lock().unwrap() = true;
    *engine.networks.try_lock().unwrap() = Some(("celld".into(), "celld-internal".into()));
    engine.images.lock().unwrap().insert(
        cell.spec.image.clone(),
        Arc::new(tokio::sync::Mutex::new(true)),
    );
    {
        let mut state = cell.state.lock().unwrap();
        state.running = false;
        state.container_id = None;
    }
    cell.begin_run().unwrap()
}

fn params() -> StartParams {
    StartParams {
        entrypoint: None,
        env: Vec::new(),
        enable_internet: false,
        labels: Vec::new(),
    }
}

fn owned_info(run: u64) -> Value {
    json!({ "Id": TEST_ID, "State": { "Running": true },
        "Config": { "Labels": { "celld.node": "test-node", "celld.cell": "test-scope", "celld.run": run.to_string() } },
        "NetworkSettings": { "Networks": { "test": { "IPAddress": "192.0.2.1" } } } })
}

#[tokio::test]
async fn late_wait_cannot_overwrite_a_newer_run_result() {
    let (old, received, resume) = paused(wait(200, json!({"StatusCode":137})));
    let (engine, cell, daemon) = fixture(vec![
        old,
        reply(
            "POST",
            format!("/containers/{NEXT_ID}/wait"),
            200,
            json!({"StatusCode":23}),
        ),
    ]);
    let old_wait = engine.watch_exit(&cell, 1, TEST_ID.into());
    entered(received).await;
    cell.state.lock().unwrap().running = false;
    let run = cell.begin_run().unwrap();
    {
        let mut state = cell.state.lock().unwrap();
        state.starting = false;
        state.container_id = Some(NEXT_ID.into());
    }
    engine.watch_exit(&cell, run, NEXT_ID.into()).await.unwrap();
    assert_eq!(engine.monitor(&cell, run).await.unwrap(), 23);
    resume.send(()).unwrap();
    old_wait.await.unwrap();
    assert_eq!(engine.monitor(&cell, run).await.unwrap(), 23);
    assert!(engine
        .monitor(&cell, 1)
        .await
        .unwrap_err()
        .contains("superseded"));
    daemon.finish().await;
}

#[tokio::test]
async fn delayed_wait_after_removal_cannot_erase_confirmed_shutdown() {
    let (old, received, resume) = paused(wait(404, json!({"message":"removed"})));
    let (engine, cell, daemon) = fixture(vec![
        old,
        kill(204),
        remove(&format!("/containers/{TEST_ID}?force=true"), 204),
    ]);
    let old_wait = engine.watch_exit(&cell, 1, TEST_ID.into());
    entered(received).await;
    engine.destroy(&cell).await.unwrap();
    resume.send(()).unwrap();
    old_wait.await.unwrap();
    assert_eq!(engine.monitor(&cell, 1).await.unwrap(), 137);
    assert!(!cell.running());
    daemon.finish().await;
}

#[tokio::test]
async fn destroy_before_start_dispatch_prevents_guest_creation() {
    let (engine, cell, daemon) = fixture(vec![]);
    let run = prepare_start(&engine, &cell);
    assert!(
        cell.begin_run().is_err(),
        "a queued start already owns the run"
    );
    let stopped = cell.request_destroy();
    engine.destroy_run(&cell, stopped).await.unwrap();
    engine.start(&cell, run, params()).await.unwrap();
    assert!(!cell.running());
    assert!(daemon.requests.lock().unwrap().is_empty());
    assert_eq!(engine.monitor(&cell, run).await.unwrap(), 137);
    daemon.finish().await;
}

#[tokio::test]
async fn destroy_waits_for_inflight_create_and_removes_its_exact_id() {
    let (create, received, resume) = paused(reply(
        "POST",
        "/containers/create?name=test-container",
        201,
        json!({"Id":TEST_ID}),
    ));
    // The wait task and kill may be scheduled in either order. Wait stays
    // separate here: queue destruction while create is blocked, then have
    // the start fail ambiguously, retaining its ID for the queued cleanup.
    let (engine, cell, daemon) = fixture(vec![
        create,
        reply(
            "POST",
            format!("/containers/{TEST_ID}/start"),
            0,
            Value::Null,
        ),
        kill(204),
        remove(&format!("/containers/{TEST_ID}?force=true"), 204),
    ]);
    let run = prepare_start(&engine, &cell);
    let start = engine.start(&cell, run, params());
    tokio::pin!(start);
    asyncrt::select! { result = &mut start => panic!("start completed before create release: {result:?}"), _ = entered(received) => {} }
    let stop_run = cell.request_destroy();
    let stop = engine.destroy_run(&cell, stop_run);
    tokio::pin!(stop);
    assert!(tokio::time::timeout(Duration::from_millis(30), &mut stop)
        .await
        .is_err());
    assert_eq!(daemon.requests.lock().unwrap().len(), 1);
    assert!(cell.begin_run().is_err());
    resume.send(()).unwrap();
    assert!(start.await.is_err());
    stop.await.unwrap();
    assert!(!cell.running());
    assert!(cell.state.lock().unwrap().container_id.is_none());
    assert_eq!(
        daemon.requests.lock().unwrap()[0].2["Labels"]["celld.run"],
        run.to_string()
    );
    daemon.finish().await;
}

#[tokio::test]
async fn failed_removal_blocks_new_runs_even_after_process_exit() {
    let (engine, cell, daemon) = fixture(vec![
        kill(204),
        remove(&format!("/containers/{TEST_ID}?force=true"), 500),
        kill(404),
        remove(&format!("/containers/{TEST_ID}?force=true"), 204),
    ]);
    cell.state.lock().unwrap().running = false; // A successful wait raced removal.
    assert!(engine.destroy(&cell).await.is_err());
    assert!(cell.begin_run().is_err());
    assert_eq!(
        cell.state.lock().unwrap().container_id.as_deref(),
        Some(TEST_ID)
    );
    engine.destroy(&cell).await.unwrap();
    assert!(cell.begin_run().is_ok());
    daemon.finish().await;
}

#[tokio::test]
async fn stale_stop_signal_exec_and_idle_cleanup_cannot_touch_a_new_run() {
    let (engine, cell, daemon) = fixture(vec![]);
    cell.state.lock().unwrap().running = false;
    let run = cell.begin_run().unwrap();
    {
        let mut state = cell.state.lock().unwrap();
        state.starting = false;
        state.container_id = Some(NEXT_ID.into());
    }
    engine.destroy_run(&cell, 1).await.unwrap();
    assert!(engine.signal(&cell, 1, 9).await.is_err());
    assert!(engine
        .exec(
            &cell,
            1,
            ExecParams {
                cmd: vec!["true".into()],
                env: vec![],
                cwd: None,
                user: None,
                combined: false
            }
        )
        .await
        .is_err());
    engine.forget_idle(&cell, Some(0)).await;
    assert!(cell.running());
    assert_eq!(cell.current_run(), run);
    assert!(engine.cell(&cell.scope).is_some());
    assert!(daemon.requests.lock().unwrap().is_empty());
    daemon.finish().await;
}

#[tokio::test]
async fn ambiguous_create_is_reconciled_by_owner_and_run_before_removal() {
    let (engine, cell, daemon) = fixture(vec![
        reply(
            "POST",
            "/containers/create?name=test-container",
            0,
            Value::Null,
        ),
        reply("GET", "/containers/test-container/json", 200, owned_info(2)),
        kill(204),
        remove(&format!("/containers/{TEST_ID}?force=true"), 204),
    ]);
    let run = prepare_start(&engine, &cell);
    assert_eq!(run, 2);
    assert!(engine.start(&cell, run, params()).await.is_err());
    assert!(cell.running());
    assert!(cell.begin_run().is_err());
    engine.destroy(&cell).await.unwrap();
    assert!(!cell.running());
    daemon.finish().await;
}

#[tokio::test]
async fn ambiguous_create_cannot_remove_a_reused_name() {
    for wrong_owner in [false, true] {
        let mut info = owned_info(99);
        if wrong_owner {
            info["Config"]["Labels"]["celld.node"] = json!("another-node");
        }
        let (engine, cell, daemon) = fixture(vec![reply(
            "GET",
            "/containers/test-container/json",
            200,
            info,
        )]);
        {
            let mut state = cell.state.lock().unwrap();
            state.container_id = None;
            state.creating = true;
        }
        assert!(engine.destroy(&cell).await.is_err());
        assert!(cell.running());
        assert!(cell.begin_run().is_err());
        assert_eq!(daemon.requests.lock().unwrap().len(), 1);
        daemon.finish().await;
    }
}

#[tokio::test]
async fn name_conflict_is_not_permission_to_delete_another_instance() {
    let (engine, cell, daemon) = fixture(vec![reply(
        "POST",
        "/containers/create?name=test-container",
        409,
        json!({"message":"name in use"}),
    )]);
    let run = prepare_start(&engine, &cell);
    assert!(engine.start(&cell, run, params()).await.is_err());
    assert!(!cell.running());
    engine.destroy(&cell).await.unwrap();
    assert_eq!(daemon.requests.lock().unwrap().len(), 1);
    daemon.finish().await;
}

#[tokio::test]
async fn forgotten_handles_cannot_restart_or_remove_replacement_handles() {
    let (engine, cell, daemon) = fixture(vec![
        kill(204),
        remove(&format!("/containers/{TEST_ID}?force=true"), 204),
    ]);
    engine.forget(&cell).await;
    assert!(cell.begin_run().is_err());
    assert!(engine.cell(&cell.scope).is_none());
    engine.start(&cell, 1, params()).await.unwrap();
    assert!(!cell.running());
    daemon.finish().await;
}

#[test]
fn container_identity_requires_full_engine_ids() {
    for id in [
        "test-container",
        "",
        "abc",
        "../../other",
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    ] {
        assert!(engine_container_id(&json!({"Id":id})).is_err());
    }
    assert_eq!(
        engine_container_id(&json!({"Id":TEST_ID})).unwrap(),
        TEST_ID
    );
}

#[tokio::test]
async fn successful_start_wait_and_inspect_use_the_returned_id() {
    let (wait_reply, received, resume) = paused(wait(200, json!({"StatusCode":0})));
    let (engine, cell, daemon) = fixture(vec![
        reply(
            "POST",
            "/containers/create?name=test-container",
            201,
            json!({"Id":TEST_ID}),
        ),
        reply(
            "POST",
            format!("/containers/{TEST_ID}/start"),
            204,
            Value::Null,
        ),
        reply(
            "GET",
            format!("/containers/{TEST_ID}/json"),
            200,
            owned_info(2),
        ),
        wait_reply,
    ]);
    let run = prepare_start(&engine, &cell);
    engine.start(&cell, run, params()).await.unwrap();
    entered(received).await;
    assert!(cell.running());
    assert_eq!(cell.address(8080).unwrap(), "192.0.2.1:8080");
    resume.send(()).unwrap();
    assert_eq!(engine.monitor(&cell, run).await.unwrap(), 0);
    daemon.finish().await;
}

#[tokio::test]
async fn exec_handle_keeps_its_container_id_after_a_new_run_reuses_the_name() {
    let (engine, cell, daemon) = fixture(vec![
        reply(
            "POST",
            format!("/containers/{TEST_ID}/exec"),
            201,
            json!({"Id":"old-exec"}),
        ),
        reply("POST", "/exec/old-exec/start", 101, Value::Null),
        reply(
            "GET",
            "/exec/old-exec/json",
            200,
            json!({"Pid":123,"Running":true}),
        ),
        // A stale process must target the old immutable container, even when
        // its PID also exists in the replacement's namespace.
        reply(
            "POST",
            format!("/containers/{TEST_ID}/exec"),
            404,
            json!({"message":"old instance removed"}),
        ),
    ]);
    let process = engine
        .exec(
            &cell,
            1,
            ExecParams {
                cmd: vec!["sleep".into(), "10".into()],
                env: vec![],
                cwd: None,
                user: None,
                combined: false,
            },
        )
        .await
        .unwrap();
    cell.state.lock().unwrap().running = false;
    cell.begin_run().unwrap();
    cell.state.lock().unwrap().container_id = Some(NEXT_ID.into());
    assert!(process.kill(9).await.is_err());
    assert_eq!(
        daemon.requests.lock().unwrap()[3].2["Cmd"],
        json!(["kill", "-9", "123"])
    );
    drop_process(process.id);
    daemon.finish().await;
}

#[tokio::test]
async fn returning_activation_invalidates_idle_timer_without_reinspect() {
    let (engine, cell, daemon) = fixture(vec![]);
    install_specs(vec![(*cell.spec).clone()], None);
    let engine = Arc::new(engine);
    cell.set_inactivity(Duration::from_millis(30));
    engine.release(&cell.scope, Release::Keep).await;
    let attached = engine.attach(&cell.scope, "Test").await.unwrap();
    assert!(Arc::ptr_eq(&cell, &attached));
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(cell.running());
    assert!(engine.cell(&cell.scope).is_some());
    assert!(daemon.requests.lock().unwrap().is_empty());
    daemon.finish().await;
}

#[tokio::test]
async fn returning_activation_waits_for_cleanup_already_in_progress() {
    let (kill_reply, received, resume) = paused(kill(204));
    let name = container_name("test-node", "test-scope");
    let (engine, cell, daemon) = fixture(vec![
        kill_reply,
        remove(&format!("/containers/{TEST_ID}?force=true"), 204),
        reply("GET", format!("/containers/{name}/json"), 404, Value::Null),
    ]);
    install_specs(vec![(*cell.spec).clone()], None);
    let engine = Arc::new(engine);
    cell.set_inactivity(Duration::from_millis(1));
    engine.release(&cell.scope, Release::Keep).await;
    entered(received).await;
    let attach = engine.attach(&cell.scope, "Test");
    tokio::pin!(attach);
    assert!(tokio::time::timeout(Duration::from_millis(30), &mut attach)
        .await
        .is_err());
    assert_eq!(daemon.requests.lock().unwrap().len(), 1);
    resume.send(()).unwrap();
    let replacement = attach.await.unwrap();
    assert!(!Arc::ptr_eq(&cell, &replacement));
    assert!(cell.begin_run().is_err());
    assert!(!replacement.running());
    daemon.finish().await;
}

#[tokio::test]
async fn ownership_release_fences_starts_before_waiting_for_lifecycle_lock() {
    let (engine, cell, daemon) = fixture(vec![
        kill(204),
        remove(&format!("/containers/{TEST_ID}?force=true"), 204),
    ]);
    let lock = cell.lifecycle.lock().await;
    let forget = engine.forget(&cell);
    tokio::pin!(forget);
    assert!(tokio::time::timeout(Duration::from_millis(30), &mut forget)
        .await
        .is_err());
    cell.state.lock().unwrap().running = false; // A wait callback can report exit while removal waits.
    assert!(cell.begin_run().is_err());
    drop(lock);
    forget.await;
    assert!(cell.state.lock().unwrap().retired);
    assert!(engine.cell(&cell.scope).is_none());
    daemon.finish().await;
}
