//! Protocol 2 capability broker.
//!
//! A well-formed message is not a grant. The user SID, logon session, pid, and
//! pipe instance come from [`ObservedPeer`], which the pipe server fills from
//! Windows. Fields inside the JSON body are not an identity.
//!
//! Replay state lives in this process. Closing the broker drops it. A new broker
//! has no sessions, so an old session id is denied before a replay id could match.
//! That is the persistence limit: do not store sessions without the replay set.

use std::collections::{BTreeMap, BTreeSet};

pub(super) const PROTOCOL_VERSION: u64 = 2;
pub(super) const POLICY_VERSION: u64 = 1;

const MAX_BYTES: usize = 1024;
const MAX_MESSAGES: u32 = 8;
const MAX_TTL_MS: u64 = 30_000;
const MAX_SKEW_MS: u64 = 5_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ObservedPeer {
    pub pid: u32,
    pub user_sid: String,
    pub logon_low: u32,
    pub logon_high: i32,
    pub pipe_instance: u64,
    pub impersonation_sid: String,
    pub impersonation_ok: bool,
}

struct Session {
    user_sid: String,
    logon_low: u32,
    logon_high: i32,
    pid: u32,
    pipe_instance: u64,
    alive: bool,
    count: u32,
    ids: BTreeSet<String>,
}

pub(super) struct Broker {
    broker_sid: String,
    grants: BTreeMap<String, Vec<u8>>,
    sessions: BTreeMap<String, Session>,
    audit: Vec<String>,
}

impl Broker {
    pub(super) fn new(broker_sid: impl Into<String>, fixture: Vec<u8>) -> Self {
        let mut grants = BTreeMap::new();
        grants.insert("fixture-001".to_owned(), fixture);
        Self {
            broker_sid: broker_sid.into(),
            grants,
            sessions: BTreeMap::new(),
            audit: Vec::new(),
        }
    }

    pub(super) fn grant(&self, resource: &str) -> Option<&[u8]> {
        self.grants.get(resource).map(Vec::as_slice)
    }

    pub(super) fn audit(&self) -> &[String] {
        &self.audit
    }

    /// Binds a session to a peer the broker already observed. The session id is
    /// chosen by the broker. The same user as the broker is refused.
    pub(super) fn open_session(
        &mut self,
        peer: ObservedPeer,
        session_id: &str,
    ) -> Result<String, &'static str> {
        if !session_ok(session_id) || self.sessions.contains_key(session_id) {
            return Err("session");
        }
        if peer.user_sid == self.broker_sid || peer.user_sid.is_empty() || peer.pid == 0 {
            return Err("identity");
        }
        if !peer.impersonation_ok || peer.impersonation_sid != peer.user_sid {
            return Err("identity");
        }
        self.sessions.insert(
            session_id.to_owned(),
            Session {
                user_sid: peer.user_sid,
                logon_low: peer.logon_low,
                logon_high: peer.logon_high,
                pid: peer.pid,
                pipe_instance: peer.pipe_instance,
                alive: true,
                count: 0,
                ids: BTreeSet::new(),
            },
        );
        Ok(session_id.to_owned())
    }

    pub(super) fn close_session(&mut self, session_id: &str) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.alive = false;
        }
    }

    pub(super) fn decide(&mut self, raw: &str, peer: &ObservedPeer, now_ms: u64) -> String {
        let judgment = self.judge(raw, peer, now_ms);
        self.audit.push(format!(
            "pid={} request={} capability={} decision={} error={}",
            peer.pid, judgment.id, judgment.capability, judgment.decision, judgment.error
        ));
        response(
            &judgment.id,
            judgment.decision,
            judgment.error,
            &judgment.payload,
        )
    }

    fn judge(&mut self, raw: &str, peer: &ObservedPeer, now_ms: u64) -> Judgment {
        if raw.len() > MAX_BYTES || !ascii_json(raw) || smuggles_identity(raw) {
            return Judgment::deny("-", "-", "schema");
        }
        let parsed = match parse_request(raw) {
            Ok(parsed) => parsed,
            Err(error) => return Judgment::deny("-", "-", error),
        };
        if parsed.version != PROTOCOL_VERSION {
            return Judgment::deny(&parsed.id, &parsed.capability, "version");
        }
        if parsed.policy != POLICY_VERSION {
            return Judgment::deny(&parsed.id, &parsed.capability, "policy");
        }
        let Some(session) = self.sessions.get(&parsed.session_id) else {
            return Judgment::deny(&parsed.id, &parsed.capability, "session");
        };
        if !session.alive || session.user_sid == self.broker_sid {
            return Judgment::deny(&parsed.id, &parsed.capability, "session");
        }
        if !peer_matches(session, peer) {
            return Judgment::deny(&parsed.id, &parsed.capability, "identity");
        }
        let ttl = parsed.expires_at.saturating_sub(parsed.issued_at);
        let expired = parsed.expires_at < now_ms
            || parsed.issued_at > now_ms.saturating_add(MAX_SKEW_MS)
            || ttl == 0
            || ttl > MAX_TTL_MS;
        if expired {
            return Judgment::deny(&parsed.id, &parsed.capability, "lifetime");
        }
        let session = self.sessions.get_mut(&parsed.session_id).expect("session");
        session.count += 1;
        if session.count > MAX_MESSAGES {
            return Judgment::deny(&parsed.id, &parsed.capability, "rate");
        }
        if !session.ids.insert(parsed.id.clone()) {
            return Judgment::deny(&parsed.id, &parsed.capability, "replay");
        }
        if !allowed_capability(&parsed.capability) {
            return Judgment::deny(&parsed.id, &parsed.capability, "capability");
        }
        match parsed.capability.as_str() {
            "ping" | "worker_info" => {
                if parsed.resource_id.is_empty() {
                    Judgment::allow(&parsed.id, &parsed.capability, "ok")
                } else {
                    Judgment::deny(&parsed.id, &parsed.capability, "resource")
                }
            }
            "read_fixture" => {
                if path_shaped(&parsed.resource_id) {
                    return Judgment::deny(&parsed.id, &parsed.capability, "resource");
                }
                match self.grants.get(&parsed.resource_id) {
                    Some(bytes) => Judgment::allow(&parsed.id, &parsed.capability, &hex(bytes)),
                    None => Judgment::deny(&parsed.id, &parsed.capability, "resource"),
                }
            }
            _ => Judgment::deny(&parsed.id, &parsed.capability, "capability"),
        }
    }
}

fn peer_matches(session: &Session, peer: &ObservedPeer) -> bool {
    peer.impersonation_ok
        && peer.pid == session.pid
        && peer.user_sid == session.user_sid
        && peer.impersonation_sid == session.user_sid
        && peer.logon_low == session.logon_low
        && peer.logon_high == session.logon_high
        && peer.pipe_instance == session.pipe_instance
        && peer.pid != 0
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
    session_id: String,
    id: String,
    capability: String,
    resource_id: String,
    issued_at: u64,
    expires_at: u64,
    policy: u64,
}

fn allowed_capability(name: &str) -> bool {
    matches!(name, "ping" | "worker_info" | "read_fixture")
}

fn smuggles_identity(raw: &str) -> bool {
    raw.contains("\"user_sid\"")
        || raw.contains("\"logon_sid\"")
        || raw.contains("\"password\"")
        || raw.contains("\"token\"")
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

fn session_ok(value: &str) -> bool {
    ident(value, 64)
}

fn parse_request(raw: &str) -> Result<Request, &'static str> {
    if !raw.starts_with('{') || !raw.ends_with('}') {
        return Err("schema");
    }
    for key in [
        "protocol_version",
        "session_id",
        "request_id",
        "capability",
        "resource_id",
        "issued_at",
        "expires_at",
        "policy_version",
    ] {
        if raw.matches(&format!("\"{key}\"")).count() != 1 {
            return Err("schema");
        }
    }
    let version = json_number(raw, "protocol_version").ok_or("schema")?;
    let issued = json_number(raw, "issued_at").ok_or("schema")?;
    let expires = json_number(raw, "expires_at").ok_or("schema")?;
    let policy = json_number(raw, "policy_version").ok_or("schema")?;
    let session = json_string(raw, "session_id").ok_or("schema")?;
    let id = json_string(raw, "request_id").ok_or("schema")?;
    let capability = json_string(raw, "capability").ok_or("schema")?;
    let resource = json_string(raw, "resource_id").ok_or("schema")?;
    if !ident(session, 64) || !ident(id, 64) || !ident(capability, 64) {
        return Err("schema");
    }
    if resource.len() > 64 {
        return Err("schema");
    }
    Ok(Request {
        version,
        session_id: session.to_owned(),
        id: id.to_owned(),
        capability: capability.to_owned(),
        resource_id: resource.to_owned(),
        issued_at: issued,
        expires_at: expires,
        policy,
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
        "{{\"protocol_version\":2,\"request_id\":\"{id}\",\"decision\":\"{decision}\",\"error\":\"{error}\",\"payload\":\"{payload}\"}}"
    )
}

pub(super) fn label(response_text: &str) -> String {
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
    session: &str,
    id: &str,
    capability: &str,
    resource: &str,
    issued_at: u64,
    expires_at: u64,
) -> String {
    format!(
        "{{\"protocol_version\":2,\"session_id\":\"{session}\",\"request_id\":\"{id}\",\"capability\":\"{capability}\",\"resource_id\":\"{resource}\",\"issued_at\":{issued_at},\"expires_at\":{expires_at},\"policy_version\":1}}"
    )
}

pub(super) fn peer() -> ObservedPeer {
    ObservedPeer {
        pid: 42,
        user_sid: "S-1-5-21-9-8-7-1001".to_owned(),
        logon_low: 7,
        logon_high: 0,
        pipe_instance: 1,
        impersonation_sid: "S-1-5-21-9-8-7-1001".to_owned(),
        impersonation_ok: true,
    }
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

#[cfg(test)]
mod tests {
    use super::{Broker, hex, label, payload_of, peer, request};

    const NOW: u64 = 1_700_000_000_000;

    #[test]
    fn a_registered_fixture_is_hex_and_a_foreign_id_is_denied() {
        let mut broker = Broker::new("S-1-5-21-1-2-3-1000", b"fixture-bytes".to_vec());
        let session = broker.open_session(peer(), "session-a").expect("session");
        let read = broker.decide(
            &request(
                &session,
                "req-read",
                "read_fixture",
                "fixture-001",
                NOW,
                NOW + 1_000,
            ),
            &peer(),
            NOW,
        );
        assert_eq!(label(&read), "allow");
        assert_eq!(payload_of(&read), hex(b"fixture-bytes"));
        assert!(!payload_of(&read).contains('\\'));
        let missing = broker.decide(
            &request(
                &session,
                "req-miss",
                "read_fixture",
                "fixture-002",
                NOW,
                NOW + 1_000,
            ),
            &peer(),
            NOW,
        );
        assert_eq!(label(&missing), "deny:resource");
    }

    #[test]
    fn the_broker_refuses_its_own_sid_as_a_worker_session() {
        let mut broker = Broker::new("S-1-5-21-9-8-7-1001", b"fixture-bytes".to_vec());
        let error = broker.open_session(peer(), "session-a");
        assert_eq!(error, Err("identity"));
    }
}
