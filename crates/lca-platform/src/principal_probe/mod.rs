//! LCA-01M experimental principal isolation.
//!
//! This module is compiled only as a Windows unit test. The agent binary does not
//! contain it. `apply_ntfs` does not call it. No user account is created, no production
//! ACL is edited, and no shell tool is registered.
//!
//! A restricted token is still this user. The tests measure what that token can open.
//! They do not promote the result into a production sandbox.

#![allow(unsafe_code)]

mod broker;
mod lifecycle;
mod research;
mod winutil;
mod worker;

use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};

use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;

use broker::{Broker, EXPECTED_LABELS};
use lifecycle::trace_for_launch;
use winutil::{
    current_pid, fields, open_code, pipe_name, prepare, secret_bytes, spawn_reaching, start_servers,
};

#[test]
fn principal_probe_child() {
    if std::env::var_os("LCA_01M_ROLE").is_none() {
        return;
    }
    let code = worker::run();
    std::process::exit(code);
}

#[test]
fn experiment_restricted_worker_reaches_user_code_and_cannot_open_secrets() {
    let prepared = prepare("access").expect("stage");
    let before = secret_bytes(&prepared.stage);
    let child = spawn_reaching(
        &prepared.stage,
        prepared.token.raw(),
        prepared.job.raw(),
        "access",
        "",
        "worker-access",
        &prepared.evidence_hex,
        None,
    )
    .unwrap_or_else(|error| {
        panic!(
            "worker did not reach user code: {error}; {}",
            prepared.stage.preflight
        )
    });
    let (exit_code, report) = child.wait_report(20_000);
    let map = fields(&report);
    observe(
        "access.txt",
        &format!(
            "attempt={} pid={} assign={} in_job={} exit={exit_code:#x}\njob {}\ntoken {}\npreflight {}\n{report}",
            child.attempt,
            child.pid,
            child.assign_error,
            child.in_job,
            prepared.job.report,
            prepared.token.facts,
            prepared.stage.preflight
        ),
    );
    assert_eq!(child.assign_error, 0, "{report}");
    assert_eq!(child.in_job, 1, "{report}");
    assert!(report.contains("reached=1"), "{report}");
    assert_eq!(map["token_type"], "1", "{report}");
    assert_ne!(map["integrity"], "4096", "{report}");
    let privileges: u32 = map["privileges"].parse().unwrap_or(u32::MAX);
    assert!(privileges <= 2, "{report}");
    let restricted: u32 = map["restricted"].parse().unwrap_or(0);
    assert!(restricted >= 1, "{report}");
    assert_eq!(map["allowed_read"], "0", "{report}");
    assert_ne!(map["denied_read"], "0", "{report}");
    assert_ne!(map["denied_write"], "0", "{report}");
    assert_ne!(map["store_read"], "0", "{report}");
    assert_ne!(map["evidence_read"], "0", "{report}");
    assert_ne!(map["outside_read"], "0", "{report}");
    assert_ne!(map["outside_write"], "0", "{report}");
    assert_ne!(map["hardlink"], "0", "{report}");
    assert!(!prepared.stage.link.exists(), "hardlink was created");
    assert_eq!(map["drop_write"], "0", "{report}");
    assert_eq!(map["granted_read"], "0", "{report}");
    assert_ne!(map["granted_write"], "0", "{report}");
    assert_eq!(
        map["granted_hex"],
        broker::hex(b"fixture-bytes"),
        "{report}"
    );
    assert_ne!(map["foreign_read"], "0", "{report}");
    assert!(map["dpapi"] == "ok" || map["dpapi"] == "fail", "{report}");
    assert!(map.contains_key("own_pipe"), "{report}");
    assert_eq!(secret_bytes(&prepared.stage), before);
    assert_eq!(open_code(&prepared.stage.denied, FILE_GENERIC_READ), 0);
    let trace = trace_for_launch(true).expect("lifecycle");
    assert_eq!(trace.last().copied(), Some(lifecycle::Phase::Terminated));
    assert_ne!(exit_code, 259, "worker still active\n{report}");
}

#[test]
fn experiment_broker_authenticates_the_pipe_peer() {
    let prepared = prepare("ipc").expect("stage");
    let before = secret_bytes(&prepared.stage);
    let worker_id = "worker-ipc";
    let fixture = std::fs::read(&prepared.stage.allowed).expect("fixture");
    let broker = Arc::new(Mutex::new(Broker::new(worker_id, fixture)));
    let bound = Arc::new(AtomicU32::new(0));
    let name = pipe_name();
    let servers = start_servers(
        &name,
        Arc::clone(&broker),
        prepared.user_sid.clone(),
        Arc::clone(&bound),
    )
    .expect("pipe");
    let child = spawn_reaching(
        &prepared.stage,
        prepared.token.raw(),
        prepared.job.raw(),
        "ipc",
        &name,
        worker_id,
        &prepared.evidence_hex,
        Some(&bound),
    )
    .unwrap_or_else(|error| {
        panic!(
            "ipc worker did not start: {error}; {}",
            prepared.stage.preflight
        )
    });
    let parent = current_pid();
    let attacker_id = worker_id.to_owned();
    let attacker_pipe = name.clone();
    let attacker = std::thread::spawn(move || {
        let message = broker::request("attacker-1", "ping", "", &attacker_id, broker::now_ms());
        winutil::client_exchange(&attacker_pipe, &[message])
    });
    let (exit_code, report) = child.wait_report(20_000);
    let attacker_result = attacker.join().expect("attacker");
    servers.finish();
    let audit = broker.lock().expect("broker").audit().to_vec();
    observe(
        "ipc.txt",
        &format!(
            "attempt={} pid={} parent={parent} exit={exit_code:#x}\n{report}\naudit:\n{}",
            child.attempt,
            child.pid,
            audit.join("\n")
        ),
    );
    let map = fields(&report);
    assert!(report.contains("reached=1"), "{report}");
    assert_eq!(
        map.get("decisions").map(String::as_str),
        Some(EXPECTED_LABELS),
        "{report}\n{audit:?}"
    );
    assert_eq!(
        map.get("read_payload").map(String::as_str),
        Some(broker::hex(b"fixture-bytes").as_str()),
        "{report}"
    );
    assert!(!map["read_payload"].contains('\\'));
    assert_ne!(map["store_read"], "0", "{report}");
    assert_ne!(map["evidence_read"], "0", "{report}");
    let worker_lines: Vec<_> = audit
        .iter()
        .filter(|line| line.starts_with(&format!("pid={} ", child.pid)))
        .cloned()
        .collect();
    let worker_labels: Vec<_> = worker_lines.iter().map(|line| audit_label(line)).collect();
    assert_eq!(worker_labels.join(","), EXPECTED_LABELS, "{worker_lines:?}");
    assert!(
        audit.iter().any(|line| {
            line.starts_with(&format!("pid={parent} ")) && line.contains("error=identity")
        }),
        "attacker was not denied\n{audit:?}\nattacker={attacker_result:?}"
    );
    assert_eq!(secret_bytes(&prepared.stage), before);
    let _ = child_running_trace(true);
}

#[test]
fn experiment_job_kills_the_worker_and_blocks_a_child_process() {
    let prepared = prepare("job").expect("stage");
    let before = secret_bytes(&prepared.stage);
    assert!(
        prepared.job.report.starts_with("limits=0"),
        "{}",
        prepared.job.report
    );
    let child = spawn_reaching(
        &prepared.stage,
        prepared.token.raw(),
        prepared.job.raw(),
        "wait",
        "",
        "worker-wait",
        &prepared.evidence_hex,
        None,
    )
    .unwrap_or_else(|error| panic!("wait worker did not start: {error}"));
    assert_eq!(child.in_job, 1, "job assignment");
    drop(prepared.job);
    let exit_code = child.wait_exit(8_000);
    let report = child.read_report();
    observe(
        "job-kill.txt",
        &format!("exit={exit_code:#x} in_job={} {report}", child.in_job),
    );
    assert_ne!(
        exit_code, 259,
        "job close left the worker running\n{report}"
    );
    assert!(!report.contains("wait_returned=1"), "{report}");
    assert_eq!(secret_bytes(&prepared.stage), before);
    drop(child);

    let job = winutil::Job::create().expect("second job");
    let spawner = spawn_reaching(
        &prepared.stage,
        prepared.token.raw(),
        job.raw(),
        "spawn",
        "",
        "worker-spawn",
        &prepared.evidence_hex,
        None,
    )
    .unwrap_or_else(|error| panic!("spawn worker did not start: {error}"));
    let (spawn_exit, spawn_report) = spawner.wait_report(20_000);
    let spawn_map = fields(&spawn_report);
    observe(
        "job-spawn.txt",
        &format!("exit={spawn_exit:#x} job {}\n{spawn_report}", job.report),
    );
    assert_ne!(spawn_map["spawn"], "0", "{spawn_report}");
    assert_ne!(spawn_map["denied_write"], "0", "{spawn_report}");
    assert_eq!(secret_bytes(&prepared.stage), before);
    assert!(trace_for_launch(false).is_ok());
}

fn audit_label(line: &str) -> String {
    let decision = field_after(line, "decision=");
    let error = field_after(line, "error=");
    if error.is_empty() {
        decision
    } else {
        format!("{decision}:{error}")
    }
}

fn field_after(line: &str, key: &str) -> String {
    line.split_whitespace()
        .find_map(|token| token.strip_prefix(key))
        .unwrap_or("")
        .to_owned()
}

fn observe(name: &str, text: &str) {
    let dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"))
        .join("lca-01m");
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(dir.join(name), text);
}

fn child_running_trace(reached: bool) -> bool {
    trace_for_launch(reached).is_ok()
}
