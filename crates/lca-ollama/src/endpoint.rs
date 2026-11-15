use lca_model_runtime::{MAX_TIMEOUT, RuntimeError};
use url::{Host, Url};

const MAX_ENDPOINT_LEN: usize = 2048;

/// Normalized loopback origin.
#[derive(Debug)]
pub(crate) struct LoopbackEndpoint {
    pub(crate) origin: String,
}

/// Accepts an HTTP or HTTPS loopback origin and rejects everything else.
///
/// Credentials, paths, queries, and non-loopback hosts fail before a connection is opened.
/// The error text never includes a username or password.
pub(crate) fn check_loopback_endpoint(value: &str) -> Result<LoopbackEndpoint, RuntimeError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(RuntimeError::invalid(
            "model runtime endpoint must not be empty",
        ));
    }
    if trimmed.len() > MAX_ENDPOINT_LEN {
        return Err(RuntimeError::invalid("model runtime endpoint is too long"));
    }

    let url = Url::parse(trimmed).map_err(|_| {
        RuntimeError::invalid("model runtime endpoint must be an http or https URL")
    })?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(RuntimeError::invalid(
            "model runtime endpoint scheme must be http or https",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(RuntimeError::invalid(
            "model runtime endpoint must not contain embedded credentials",
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| RuntimeError::invalid("model runtime endpoint must include a host"))?;
    if url.path() != "/" && !url.path().is_empty() {
        return Err(RuntimeError::invalid(
            "model runtime endpoint path must be empty",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(RuntimeError::invalid(
            "model runtime endpoint must not include a query or fragment",
        ));
    }
    if !host_is_loopback(&url) {
        return Err(RuntimeError::invalid(format!(
            "model runtime accepts only loopback endpoints (host {host})"
        )));
    }

    let origin = match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    };
    Ok(LoopbackEndpoint { origin })
}

pub(crate) fn check_timeouts(
    connect_timeout: std::time::Duration,
    request_timeout: std::time::Duration,
) -> Result<(), RuntimeError> {
    for (label, timeout) in [
        ("connect timeout", connect_timeout),
        ("request timeout", request_timeout),
    ] {
        if timeout.is_zero() || timeout > MAX_TIMEOUT {
            return Err(RuntimeError::invalid(format!(
                "{label} must be from 1ms through 3600s"
            )));
        }
    }
    Ok(())
}

fn host_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn loopback_origins_are_normalized() {
        let endpoint = check_loopback_endpoint("http://127.0.0.1:11434/").expect("ipv4");
        assert_eq!(endpoint.origin, "http://127.0.0.1:11434");

        let localhost = check_loopback_endpoint("http://localhost:11434").expect("name");
        assert_eq!(localhost.origin, "http://localhost:11434");

        let ipv6 = check_loopback_endpoint("http://[::1]:11434").expect("ipv6");
        assert!(ipv6.origin.contains("::1"), "{}", ipv6.origin);
    }

    #[test]
    fn remote_hosts_credentials_and_zero_timeouts_are_rejected() {
        let remote = check_loopback_endpoint("http://192.0.2.10:11434").expect_err("remote");
        assert_eq!(remote.kind(), "invalid_request");
        assert!(remote.to_string().contains("loopback"), "{remote}");

        let secret = check_loopback_endpoint("http://user:super-secret-password@127.0.0.1:11434")
            .expect_err("credentials");
        assert!(!secret.to_string().contains("super-secret-password"));
        assert!(secret.to_string().contains("credentials"), "{secret}");

        let path = check_loopback_endpoint("http://127.0.0.1:11434/v1").expect_err("path");
        assert!(path.to_string().contains("path"), "{path}");

        let timeout = check_timeouts(Duration::ZERO, Duration::from_secs(1)).expect_err("zero");
        assert_eq!(timeout.kind(), "invalid_request");
        assert!(check_timeouts(Duration::from_secs(1), Duration::from_secs(1)).is_ok());
    }
}
