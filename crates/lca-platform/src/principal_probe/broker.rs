//! Experimental capability broker.
//!
//! A well-formed request is not a grant. The caller must already have matched the
//! process the broker started: pid, user SID, and a restricted token. `worker_id` is
//! checked against the id the broker assigned. It is not an identity by itself.
//! `resource_id` is a registry key. It is never opened as a path.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy)]
pub(super) struct Peer {
    pub pid: u32,
    pub bound_pid: u32,
    pub same_user: bool,
    pub restricted_sids: u32,
    pub impersonation_rejects: bool,
}

#[derive(Debug, Default)]
struct Budget {
    count: u32,
    ids: BTreeSet<String>,
}

pub(super) struct Broker {
    worker_id: String,
    grants: BTreeMap<String, Vec<u8>>,
    peers: BTreeMap<u32, Budget>,
    audit: Vec<String>,
    max_messages: u32,
    max_bytes: usize,
    max_age_ms: u64,
}

impl Broker {
    pub(super) fn new(worker_id: impl Into<String>, fixture: Vec<u8>) -> Self {
        let mut grants = BTreeMap::new();
        grants.insert("fixture-001".to_owned(), fixture);
        Self {
            worker_id: worker_id.into(),
            grants,
            peers: BTreeMap::new(),
            audit: Vec::new(),
            max_messages: 8,
            max_bytes: 1024,
            max_age_ms: 30_000,
        }
    }

    pub(super) fn audit(&self) -> &[String] {
        &self.audit
    }

    pub(super) fn decide(&mut self, raw: &str, peer: &Peer, now_ms: u64) -> String {
        let judgment = self.judge(raw, peer, now_ms);
        self.audit.push(format!(
            "pid={} id={} capability={} decision={} error={}",
            peer.pid, judgment.id, judgment.capability, judgment.decision, judgment.error
        ));
        response(
            &judgment.id,
            judgment.decision,
            judgment.error,
            &judgment.payload,
        )
    }

    fn judge(&mut self, raw: &str, peer: &Peer, now_ms: u64) -> Judgment {
        if raw.len() > self.max_bytes || !ascii_json(raw) {
            return Judgment::deny("-", "-", "size");
        }
        let parsed = match parse_request(raw) {
            Ok(parsed) => parsed,
            Err(error) => return Judgment::deny("-", "-", error),
        };
        if parsed.version != 1 {
            return Judgment::deny(&parsed.id, &parsed.capability, "version");
        }
        if !authenticated(peer) || parsed.worker_id != self.worker_id {
            return Judgment::deny(&parsed.id, &parsed.capability, "identity");
        }
        let budget = self.peers.entry(peer.pid).or_default();
        budget.count += 1;
        if budget.count > self.max_messages {
            return Judgment::deny(&parsed.id, &parsed.capability, "rate");
        }
        let skew = now_ms.abs_diff(parsed.issued_unix_ms);
        if parsed.issued_unix_ms > now_ms.saturating_add(5_000) || skew > self.max_age_ms {
            return Judgment::deny(&parsed.id, &parsed.capability, "lifetime");
        }
        if !budget.ids.insert(parsed.id.clone()) {
            return Judgment::deny(&parsed.id, &parsed.capability, "replay");
        }
        match parsed.capability.as_str() {
            "ping" => self.finish_ping(&parsed),
            "worker_info" => self.finish_info(&parsed, peer),
            "read_fixture" => self.finish_read(&parsed),
            _ => Judgment::deny(&parsed.id, &parsed.capability, "capability"),
        }
    }

    fn finish_ping(&self, parsed: &Request) -> Judgment {
        if !parsed.resource_id.is_empty() {
            return Judgment::deny(&parsed.id, &parsed.capability, "resource");
        }
        Judgment::allow(&parsed.id, &parsed.capability, "pong")
    }

    fn finish_info(&self, parsed: &Request, peer: &Peer) -> Judgment {
        if !parsed.resource_id.is_empty() {
            return Judgment::deny(&parsed.id, &parsed.capability, "resource");
        }
        Judgment::allow(
            &parsed.id,
            &parsed.capability,
            &format!("pid={};restricted={}", peer.pid, peer.restricted_sids),
        )
    }

    fn finish_read(&self, parsed: &Request) -> Judgment {
        if path_shaped(&parsed.resource_id) {
            return Judgment::deny(&parsed.id, &parsed.capability, "resource");
        }
        match self.grants.get(&parsed.resource_id) {
            Some(bytes) => Judgment::allow(&parsed.id, &parsed.capability, &hex(bytes)),
            None => Judgment::deny(&parsed.id, &parsed.capability, "resource"),
        }
    }
}

struct Judgment {
    id: String,
    capability: String,
    decision: &'static str,
    error: &'static str,
    payload: String,
}

impl Judgment {
    fn deny(id: &str, capability: &str, error: &'static str) -> Self {
        Self {
            id: id.to_owned(),
            capability: capability.to_owned(),
            decision: "deny",
            error,
            payload: String::new(),
        }
    }

    fn allow(id: &str, capability: &str, payload: &str) -> Self {
        Self {
            id: id.to_owned(),
            capability: capability.to_owned(),
            decision: "allow",
            error: "",
            payload: payload.to_owned(),
        }
    }
}

struct Request {
    version: u64,
    id: String,
    capability: String,
    resource_id: String,
    worker_id: String,
    issued_unix_ms: u64,
}

fn authenticated(peer: &Peer) -> bool {
    peer.pid == peer.bound_pid
        && peer.pid != 0
        && peer.same_user
        && peer.restricted_sids > 0
        && !peer.impersonation_rejects
}

fn path_shaped(resource: &str) -> bool {
    resource.is_empty()
        || resource
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'\\' | b':' | b'.'))
}

fn ascii_json(raw: &str) -> bool {
    raw.bytes().all(|byte| (0x20..0x7f).contains(&byte))
}

fn parse_request(raw: &str) -> Result<Request, &'static str> {
    if !raw.starts_with('{') || !raw.ends_with('}') {
        return Err("schema");
    }
    for key in [
        "protocol_version",
        "request_id",
        "capability",
        "resource_id",
        "worker_id",
        "issued_unix_ms",
    ] {
        if raw.matches(&format!("\"{key}\"")).count() != 1 {
            return Err("schema");
        }
    }
    let version = json_number(raw, "protocol_version").ok_or("schema")?;
    let issued = json_number(raw, "issued_unix_ms").ok_or("schema")?;
    let id = json_string(raw, "request_id").ok_or("schema")?;
    let capability = json_string(raw, "capability").ok_or("schema")?;
    let resource = json_string(raw, "resource_id").ok_or("schema")?;
    let worker = json_string(raw, "worker_id").ok_or("schema")?;
    if !ident(id, 64) || !ident(capability, 64) || !ident(worker, 64) {
        return Err("schema");
    }
    if resource.len() > 64 {
        return Err("schema");
    }
    Ok(Request {
        version,
        id: id.to_owned(),
        capability: capability.to_owned(),
        resource_id: resource.to_owned(),
        worker_id: worker.to_owned(),
        issued_unix_ms: issued,
    })
}

fn ident(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn json_string<'a>(raw: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!("\"{key}\"");
    let start = raw.find(&marker)? + marker.len();
    let after = raw[start..].trim_start().strip_prefix(':')?.trim_start();
    let value = after.strip_prefix('"')?;
    let end = value.find('"')?;
    let text = &value[..end];
    if text.bytes().any(|byte| byte == b'\\' || byte < 0x20) {
        return None;
    }
    Some(text)
}

fn json_number(raw: &str, key: &str) -> Option<u64> {
    let marker = format!("\"{key}\"");
    let start = raw.find(&marker)? + marker.len();
    let after = raw[start..].trim_start().strip_prefix(':')?.trim_start();
    let digits: String = after.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

fn response(id: &str, decision: &str, error: &str, payload: &str) -> String {
    format!(
        "{{\"protocol_version\":1,\"request_id\":\"{id}\",\"decision\":\"{decision}\",\"error\":\"{error}\",\"payload\":\"{payload}\"}}"
    )
}

pub(super) fn decision_label(response_text: &str) -> String {
    let decision = json_string(response_text, "decision").unwrap_or("bad");
    let error = json_string(response_text, "error").unwrap_or("");
    if error.is_empty() {
        decision.to_owned()
    } else {
        format!("{decision}:{error}")
    }
}

pub(super) fn payload_of(response_text: &str) -> String {
    json_string(response_text, "payload")
        .unwrap_or("")
        .to_owned()
}

pub(super) fn request(
    id: &str,
    capability: &str,
    resource: &str,
    worker_id: &str,
    issued_unix_ms: u64,
) -> String {
    format!(
        "{{\"protocol_version\":1,\"request_id\":\"{id}\",\"capability\":\"{capability}\",\"resource_id\":\"{resource}\",\"worker_id\":\"{worker_id}\",\"issued_unix_ms\":{issued_unix_ms}}}"
    )
}

pub(super) fn scripted_requests(worker_id: &str, now_ms: u64) -> Vec<String> {
    vec![
        request("req-ping", "ping", "", worker_id, now_ms),
        request("req-info", "worker_info", "", worker_id, now_ms),
        request("req-read", "read_fixture", "fixture-001", worker_id, now_ms),
        request(
            "req-missing",
            "read_fixture",
            "fixture-missing",
            worker_id,
            now_ms,
        ),
        request("req-ping", "ping", "", worker_id, now_ms),
        request("req-write", "write_file", "", worker_id, now_ms),
        request("req-spoof", "ping", "", "not-the-worker", now_ms),
        request("req-path", "read_fixture", "C:/secret", worker_id, now_ms),
        request("req-stale", "ping", "", worker_id, 1),
        request("req-extra", "ping", "", worker_id, now_ms),
        "A".repeat(1200),
    ]
}

pub(super) const EXPECTED_LABELS: &str = "allow,allow,allow,deny:resource,deny:replay,deny:capability,deny:identity,deny:resource,deny:lifetime,deny:rate,deny:size";

pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(0))
        .unwrap_or(0)
}

pub(super) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    out
}

pub(super) fn good_peer(pid: u32) -> Peer {
    Peer {
        pid,
        bound_pid: pid,
        same_user: true,
        restricted_sids: 2,
        impersonation_rejects: false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Broker, EXPECTED_LABELS, decision_label, good_peer, payload_of, request, scripted_requests,
    };

    const NOW: u64 = 1_700_000_000_000;
    const FIXTURE: &[u8] = b"fixture-bytes";

    fn labels_for(peer: super::Peer, messages: &[String]) -> Vec<String> {
        let mut broker = Broker::new("worker-1", FIXTURE.to_vec());
        messages
            .iter()
            .map(|message| decision_label(&broker.decide(message, &peer, NOW)))
            .collect()
    }

    #[test]
    fn scripted_contract_matches_the_worker_sequence() {
        let labels = labels_for(good_peer(42), &scripted_requests("worker-1", NOW));
        assert_eq!(labels.join(","), EXPECTED_LABELS);
        let mut broker = Broker::new("worker-1", FIXTURE.to_vec());
        let read = broker.decide(
            &request("req-read", "read_fixture", "fixture-001", "worker-1", NOW),
            &good_peer(42),
            NOW,
        );
        let payload = payload_of(&read);
        assert_eq!(payload, super::hex(FIXTURE));
        assert!(!payload.contains('\\'));
        assert!(!payload.contains("fixture-bytes"));
        assert!(!read.contains("Public"));
    }

    #[test]
    fn identity_lifetime_and_foreign_capabilities_are_denied() {
        let mut broker = Broker::new("worker-1", FIXTURE.to_vec());
        let mut other = good_peer(7);
        other.bound_pid = 42;
        let spoof = broker.decide(&request("req-a", "ping", "", "worker-1", NOW), &other, NOW);
        assert_eq!(decision_label(&spoof), "deny:identity");
        let mut unrestricted = good_peer(42);
        unrestricted.restricted_sids = 0;
        let open = broker.decide(
            &request("req-b", "ping", "", "worker-1", NOW),
            &unrestricted,
            NOW,
        );
        assert_eq!(decision_label(&open), "deny:identity");
        let stale = broker.decide(
            &request("req-c", "ping", "", "worker-1", NOW - 60_000),
            &good_peer(42),
            NOW,
        );
        assert_eq!(decision_label(&stale), "deny:lifetime");
        for (index, capability) in ["write_file", "execute", "apply_patch", "shell"]
            .into_iter()
            .enumerate()
        {
            let response = broker.decide(
                &request(&format!("req-cap-{index}"), capability, "", "worker-1", NOW),
                &good_peer(42),
                NOW,
            );
            assert_eq!(decision_label(&response), "deny:capability", "{capability}");
        }
        let future = broker.decide(
            &request("req-e", "ping", "", "worker-1", NOW + 60_000),
            &good_peer(42),
            NOW,
        );
        assert_eq!(decision_label(&future), "deny:lifetime");
        let version = broker.decide(
            &request("req-f", "ping", "", "worker-1", NOW)
                .replace("\"protocol_version\":1", "\"protocol_version\":2"),
            &good_peer(42),
            NOW,
        );
        assert_eq!(decision_label(&version), "deny:version");
    }
}
