//! LCA-01N experimental cross-identity worker.
//!
//! Compiled only as a Windows unit test. The model cannot call it. No account is
//! created, no production ACL is edited, and `apply_ntfs` does not call it.
//!
//! A different SID string is not a boundary. Mode B runs only when the user has
//! already supplied a local account name and a Credential Manager secret. Otherwise
//! the integration is inconclusive and must not be reported as a pass.

mod broker;
mod contract;
mod host;
mod launch;

pub(super) fn worker_main() -> i32 {
    launch::worker_main()
}

use contract::{Finding, Gate};

#[test]
fn same_sid_is_not_a_separate_principal() {
    let broker =
        contract::sample_principal("S-1-5-21-1-2-3-1000", contract::Verification::AccessChecked);
    let worker =
        contract::sample_principal("S-1-5-21-1-2-3-1000", contract::Verification::AccessChecked);
    let findings = contract::evaluate(&broker, &worker, &contract::denied_evidence());
    assert_eq!(contract::finding(&findings, "INV-01"), Finding::Violated);
    assert_eq!(
        contract::decide_gate(false, &findings),
        Gate::NotEstablished
    );
}

#[test]
fn a_distinct_sid_without_an_access_check_is_not_isolation() {
    let broker =
        contract::sample_principal("S-1-5-21-1-2-3-1000", contract::Verification::TokenObserved);
    let mut worker =
        contract::sample_principal("S-1-5-21-9-8-7-1001", contract::Verification::SidOnly);
    let mut evidence = contract::unknown_evidence();
    evidence.boundary_claimed = true;
    let findings = contract::evaluate(&broker, &worker, &evidence);
    assert_eq!(
        contract::finding(&findings, "INV-01"),
        Finding::Inconclusive
    );
    assert_eq!(contract::finding(&findings, "INV-11"), Finding::Violated);
    assert_eq!(
        contract::decide_gate(false, &findings),
        Gate::NotEstablished
    );
    worker.verification = contract::Verification::AccessChecked;
    evidence.boundary_claimed = false;
    evidence.store_readable = Some(false);
    evidence.store_writable = Some(false);
    evidence.evidence_readable = Some(false);
    evidence.evidence_writable = Some(false);
    evidence.restoration_readable = Some(false);
    evidence.restoration_writable = Some(false);
    evidence.host_readable = Some(false);
    evidence.host_writable = Some(false);
    let checked = contract::evaluate(&broker, &worker, &evidence);
    assert_eq!(contract::finding(&checked, "INV-11"), Finding::Holds);
    assert_eq!(contract::decide_gate(false, &checked), Gate::NotEstablished);
}

#[test]
fn privileged_groups_and_privileges_fail_closed() {
    let broker =
        contract::sample_principal("S-1-5-21-1-2-3-1000", contract::Verification::TokenObserved);
    let mut worker =
        contract::sample_principal("S-1-5-21-9-8-7-1001", contract::Verification::TokenObserved);
    worker.enabled_groups.push(contract::sid("S-1-5-32-544"));
    let findings = contract::evaluate(&broker, &worker, &contract::unknown_evidence());
    assert_eq!(contract::finding(&findings, "INV-02"), Finding::Violated);
    worker.enabled_groups.clear();
    worker.privileges.push(contract::TokenPrivilege {
        name: "SeDebugPrivilege".to_owned(),
        enabled: false,
    });
    let privileges = contract::evaluate(&broker, &worker, &contract::unknown_evidence());
    assert_eq!(contract::finding(&privileges, "INV-03"), Finding::Violated);
    worker.privileges.clear();
    worker.integrity = contract::Integrity::High;
    let high = contract::evaluate(&broker, &worker, &contract::unknown_evidence());
    assert_eq!(contract::finding(&high, "INV-02"), Finding::Violated);
}

#[test]
fn the_worker_cannot_mint_a_grant_or_authorize_a_path() {
    let mut broker = broker::Broker::new("S-1-5-21-1-2-3-1000", b"fixture-bytes".to_vec());
    let session = broker
        .open_session(broker::peer(), "session-a")
        .expect("session");
    let now = 1_700_000_000_000;
    let minted = broker.decide(
        &broker::request(&session, "req-approve", "approve", "", now, now + 1_000),
        &broker::peer(),
        now,
    );
    assert_eq!(broker::label(&minted), "deny:capability");
    assert!(broker.grant("fixture-001").is_some());
    assert!(broker.grant("worker-made").is_none());
    let path = broker.decide(
        &broker::request(
            &session,
            "req-path",
            "read_fixture",
            "C:/secret",
            now,
            now + 1_000,
        ),
        &broker::peer(),
        now,
    );
    assert_eq!(broker::label(&path), "deny:resource");
    let claimed = broker.decide(
        &format!(
            "{{\"protocol_version\":2,\"session_id\":\"{session}\",\"request_id\":\"req-claim\",\"capability\":\"ping\",\"resource_id\":\"\",\"issued_at\":{now},\"expires_at\":{},\"policy_version\":1,\"user_sid\":\"S-1-5-21-9-8-7-1001\"}}",
            now + 1_000
        ),
        &broker::peer(),
        now,
    );
    assert_eq!(broker::label(&claimed), "deny:schema");
}

#[test]
fn replay_sessions_and_restarts_are_rejected() {
    let mut broker = broker::Broker::new("S-1-5-21-1-2-3-1000", b"fixture-bytes".to_vec());
    let session = broker
        .open_session(broker::peer(), "session-a")
        .expect("session");
    let now = 1_700_000_000_000;
    let peer = broker::peer();
    let first = broker.decide(
        &broker::request(&session, "req-ping", "ping", "", now, now + 1_000),
        &peer,
        now,
    );
    assert_eq!(broker::label(&first), "allow");
    let replay = broker.decide(
        &broker::request(&session, "req-ping", "ping", "", now, now + 1_000),
        &peer,
        now,
    );
    assert_eq!(broker::label(&replay), "deny:replay");
    let expired = broker.decide(
        &broker::request(&session, "req-old", "ping", "", now - 60_000, now - 1),
        &peer,
        now,
    );
    assert_eq!(broker::label(&expired), "deny:lifetime");
    let foreign = broker.decide(
        &broker::request("session-other", "req-foreign", "ping", "", now, now + 1_000),
        &peer,
        now,
    );
    assert_eq!(broker::label(&foreign), "deny:session");
    broker.close_session(&session);
    let closed = broker.decide(
        &broker::request(&session, "req-closed", "ping", "", now, now + 1_000),
        &peer,
        now,
    );
    assert_eq!(broker::label(&closed), "deny:session");
    let mut restarted = broker::peer();
    restarted.logon_low = peer.logon_low.wrapping_add(1);
    let next = broker
        .open_session(restarted.clone(), "session-b")
        .expect("restart");
    assert_ne!(next, session);
    let old = broker.decide(
        &broker::request(&session, "req-stale-session", "ping", "", now, now + 1_000),
        &restarted,
        now,
    );
    assert_eq!(broker::label(&old), "deny:session");
    assert!(broker.open_session(peer, "session-a").is_err());
}

#[test]
fn identity_is_not_taken_from_a_well_formed_message() {
    let mut broker = broker::Broker::new("S-1-5-21-1-2-3-1000", b"fixture-bytes".to_vec());
    let now = 1_700_000_000_000;
    let text = broker::request("session-a", "req-ping", "ping", "", now, now + 1_000);
    let mut liar = broker::peer();
    liar.user_sid = "S-1-5-21-9-8-7-1001".to_owned();
    liar.impersonation_sid = liar.user_sid.clone();
    let denied = broker.decide(&text, &liar, now);
    assert_eq!(broker::label(&denied), "deny:session");
    let session = broker
        .open_session(broker::peer(), "session-a")
        .expect("open");
    let mut wrong_luid = broker::peer();
    wrong_luid.logon_low = 99;
    let luid = broker.decide(
        &broker::request(&session, "req-luid", "ping", "", now, now + 1_000),
        &wrong_luid,
        now,
    );
    assert_eq!(broker::label(&luid), "deny:identity");
    let mut wrong_pipe = broker::peer();
    wrong_pipe.pipe_instance = 2;
    let pipe = broker.decide(
        &broker::request(&session, "req-pipe", "ping", "", now, now + 1_000),
        &wrong_pipe,
        now,
    );
    assert_eq!(broker::label(&pipe), "deny:identity");
    let mut wrong_pid = broker::peer();
    wrong_pid.pid = 8;
    let pid = broker.decide(
        &broker::request(&session, "req-pid", "ping", "", now, now + 1_000),
        &wrong_pid,
        now,
    );
    assert_eq!(broker::label(&pid), "deny:identity");
    let mut impersonation = broker::peer();
    impersonation.impersonation_sid = "S-1-5-21-4-4-4-4".to_owned();
    let impersonated = broker.decide(
        &broker::request(&session, "req-imp", "ping", "", now, now + 1_000),
        &impersonation,
        now,
    );
    assert_eq!(broker::label(&impersonated), "deny:identity");
    for (index, capability) in [
        "execute",
        "shell",
        "write_file",
        "apply_patch",
        "restore",
        "approve",
        "change_policy",
        "open_path",
    ]
    .into_iter()
    .enumerate()
    {
        let response = broker.decide(
            &broker::request(
                &session,
                &format!("req-cap-{index}"),
                capability,
                "",
                now,
                now + 1_000,
            ),
            &broker::peer(),
            now,
        );
        assert_eq!(broker::label(&response), "deny:capability", "{capability}");
    }
}

#[test]
fn launch_contract_rejects_a_message_chosen_executable_and_implicit_handles() {
    let allowed = std::path::Path::new(r"C:\lca-stage\worker.exe");
    let spec = contract::LaunchSpec {
        account: "lca-worker".to_owned(),
        executable: allowed.to_path_buf(),
        working_directory: std::path::PathBuf::from(r"C:\lca-stage\drop"),
        handles: vec![contract::HandleGrant {
            use_kind: contract::HandleUse::FixtureRead,
            access: 0x1,
        }],
        inherit_unlisted: false,
        endpoint: r"\\.\pipe\lca-01n-test".to_owned(),
        timeout_ms: 5_000,
    };
    assert!(contract::validate_launch(&spec, allowed).is_ok());
    let mut command = spec.clone();
    command.executable = std::path::PathBuf::from(r"C:\Windows\System32\cmd.exe");
    assert_eq!(
        contract::validate_launch(&command, allowed),
        Err(contract::LaunchFault::Executable)
    );
    let mut inherit = spec.clone();
    inherit.inherit_unlisted = true;
    assert_eq!(
        contract::validate_launch(&inherit, allowed),
        Err(contract::LaunchFault::Handle)
    );
    let mut writable = spec.clone();
    writable.handles[0].access = 0x2;
    assert_eq!(
        contract::validate_launch(&writable, allowed),
        Err(contract::LaunchFault::Handle)
    );
    let mut path_end = spec.clone();
    path_end.endpoint = r"\\.\pipe\C:\secret".to_owned();
    assert_eq!(
        contract::validate_launch(&path_end, allowed),
        Err(contract::LaunchFault::Endpoint)
    );
    let line = contract::worker_command_line(allowed);
    let text = String::from_utf16_lossy(&line);
    assert!(text.contains("cross_identity_child"));
    assert!(!text.to_ascii_lowercase().contains("password"));
    let err = contract::worker_environment(&[("LCA_PASSWORD", "super-secret-value")]);
    assert!(err.is_err());
    let env = contract::worker_environment(&[("LCA_01N_ROLE", "worker")]).expect("env");
    let env_text = String::from_utf16_lossy(&env);
    assert!(env_text.contains("LCA_01N_ROLE"));
    assert!(!env_text.contains("super-secret-value"));
}

#[test]
fn reports_do_not_contain_a_password() {
    let _ = contract::Verification::Unverified;
    let _ = contract::Verification::Rejected;
    let _ = contract::HandleUse::StandardNull;
    let _ = contract::HandleUse::ReportWrite;
    let secret = contract::Password::from_units("super-secret-value".encode_utf16().collect());
    assert_eq!(format!("{secret:?}"), "redacted");
    let failure = contract::OsFailure {
        step: "logon",
        code: 1326,
    };
    let text = failure.public_text();
    assert!(!text.contains("super-secret-value"));
    assert!(!text.to_ascii_lowercase().contains("password"));
    drop(secret);
}

#[test]
fn restart_requires_a_new_session_and_abort_must_contain_the_worker() {
    assert!(contract::restarted_session("a", "b", (1, 0), (2, 0)));
    assert!(!contract::restarted_session("a", "a", (1, 0), (2, 0)));
    assert!(!contract::restarted_session("a", "b", (1, 0), (1, 0)));
    assert!(!contract::restarted_session("a", "b", (0, 0), (1, 0)));
    assert!(contract::abort_contains(true, 0));
    assert!(!contract::abort_contains(false, 0));
    assert!(!contract::abort_contains(true, 1));
    assert!(contract::hardlink_is_violation(true, true));
    assert!(!contract::hardlink_is_violation(false, true));
    assert!(!contract::hardlink_is_violation(true, false));
}

#[test]
fn current_process_token_is_read_from_windows() {
    let snapshot = host::current_principal().expect("token");
    let text = snapshot.public_summary();
    observe("principal.txt", &text);
    assert!(snapshot.user_sid.as_str().starts_with("S-1-"));
    assert_eq!(snapshot.token_type, contract::TokenKind::Primary);
    assert!(snapshot.verification.token_proven());
    assert!(snapshot.authentication_id.nonzero());
    assert!(!snapshot.token_source.name.is_empty());
    assert!(!text.contains("password"));
}

#[test]
fn access_check_uses_the_token_and_not_a_sid_string() {
    let report = host::access_check_probe().expect("access");
    observe("access-check.txt", &report);
    assert!(report.contains("foreign_denied=1"), "{report}");
    assert!(report.contains("self_allowed=1"), "{report}");
    assert!(report.contains("owner_match=1"), "{report}");
    assert!(!report.contains("password"));
}

#[test]
fn pipe_identity_is_the_connected_client() {
    let report = host::same_user_pipe_probe().expect("pipe");
    observe("pipe.txt", &report);
    assert!(report.contains("observed_sid_match=1"), "{report}");
    assert!(report.contains("message_sid_used=0"), "{report}");
    assert!(report.contains("decision=deny:session"), "{report}");
    assert!(!report.contains("password"));
}

#[test]
fn same_user_can_still_hardlink_a_file_it_owns() {
    let report = host::same_user_hardlink_probe().expect("link");
    observe("same-user-hardlink.txt", &report);
    assert!(report.contains("same_user_hardlink="), "{report}");
    assert!(report.contains("cross_identity=0"), "{report}");
}

#[test]
fn missing_principal_is_inconclusive_and_does_not_validate_the_boundary() {
    let outcome = launch::run_mode_b();
    observe("mode-b.txt", &outcome.report);
    assert!(!outcome.report.contains("password"));
    assert!(!outcome.report.to_ascii_lowercase().contains("super-secret"));
    match outcome.gate {
        Gate::Validated => {
            assert!(outcome.worker_started);
            assert!(outcome.report.contains("gate=A"));
            assert!(outcome.report.contains("store_read_denied=1"));
            assert!(outcome.report.contains("broker_authenticated=1"));
        }
        Gate::Partial => {
            panic!(
                "partial measurement must still fail closed\n{}",
                outcome.report
            );
        }
        Gate::NotEstablished => {
            assert!(!outcome.worker_started);
            assert!(outcome.report.contains("INCONCLUSIVE"));
            assert!(outcome.report.contains("gate=C"));
            assert!(!outcome.report.contains("gate=A"));
        }
    }
}

fn observe(name: &str, text: &str) {
    let dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target"))
        .join("lca-01n");
    let _ = std::fs::create_dir_all(&dir);
    let _ = std::fs::write(dir.join(name), text);
}
