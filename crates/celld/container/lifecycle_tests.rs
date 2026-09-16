// Copyright 2026 Deno Land Inc. Apache-2.0 license.

//! Exercise the real Docker HTTP client against a scripted local daemon.
//! No Docker installation, credentials, or private test corpus is required.

#![allow(clippy::disallowed_methods)] // The fixture uses real local I/O and bounded waits.

use super::*;
use tokio::net::UnixListener;

struct Reply {
    method: &'static str,
    path: &'static str,
    status: u16,
    body: Value,
}

fn kill(status: u16) -> Reply {
    Reply {
        method: "POST",
        path: "/containers/test-container/kill?signal=SIGKILL",
        status,
        body: json!({ "message": "kill response" }),
    }
}

fn remove(id: &'static str, status: u16) -> Reply {
    Reply {
        method: "DELETE",
        path: id,
        status,
        body: json!({ "message": "removal response" }),
    }
}

fn wait(status: u16, body: Value) -> Reply {
    Reply {
        method: "POST",
        path: "/containers/test-container/wait",
        status,
        body,
    }
}

struct Daemon {
    _dir: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
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
    let task = tokio::spawn(async move {
        for reply in replies {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                headers.push(stream.read_u8().await.unwrap());
                assert!(headers.len() < 16 * 1024, "unbounded request headers");
            }
            let headers = String::from_utf8(headers).unwrap();
            let mut line = headers.lines().next().unwrap().split_whitespace();
            assert_eq!(line.next(), Some(reply.method));
            let path = line.next().unwrap();
            if reply.path.ends_with('?') {
                assert!(path.starts_with(reply.path), "unexpected path {path}");
            } else {
                assert_eq!(path, reply.path);
            }
            // A disconnected request models an ambiguous engine failure:
            // the caller cannot know whether the operation took effect.
            if reply.status == 0 {
                continue;
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
            address: Address::Ip("192.0.2.1".into()),
            ..CellState::default()
        }),
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
    (engine, cell, Daemon { _dir: dir, task })
}

#[tokio::test]
async fn destroy_reports_engine_errors_and_preserves_retry_state() {
    for status in [500, 409, 0] {
        let (engine, cell, daemon) = fixture(vec![
            kill(500),
            remove("/containers/test-container?force=true", status),
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
            remove("/containers/test-container?force=true", 204),
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
        remove("/containers/test-container?force=true", 404),
    ]);
    engine.destroy(&cell).await.unwrap();
    assert!(!cell.running());
    daemon.finish().await;
}

#[tokio::test]
async fn failed_forget_retains_the_handle_until_cleanup_succeeds() {
    let (engine, cell, daemon) = fixture(vec![
        kill(500),
        remove("/containers/test-container?force=true", 500),
        kill(204),
        remove("/containers/test-container?force=true", 204),
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
            path: "/containers/json?",
            status: 200,
            body: json!([{ "Id": "a" }, { "Id": "b" }, { "Id": "c" }]),
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
            path: "/containers/json?",
            status: 200,
            body,
        }]);
        assert!(engine.reap().await.is_err());
        daemon.finish().await;
    }
}

async fn observed_exit(engine: &ContainerEngine, cell: &Arc<CellContainer>) -> Result<i64, String> {
    let mut exit = cell.exit.subscribe();
    engine.watch_exit(cell, 1);
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
