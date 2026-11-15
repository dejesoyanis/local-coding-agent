use std::io::Read;
use std::time::Duration;

use serde::de::DeserializeOwned;
use url::Url;

use crate::dto::{TagsResponse, VersionResponse, model_is_present};
use crate::error::{OllamaAvailability, OllamaError};

const MAX_ENDPOINT_LEN: usize = 2048;
const MAX_MODEL_LEN: usize = 256;
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

/// Checks whether a local Ollama server is reachable and advertises a model.
pub trait OllamaClient {
    /// Performs the check. Implementations must not panic when the server is offline.
    fn check_model(&self, model: &str) -> OllamaAvailability;
}

/// Blocking HTTP client for Ollama's native API (`/api/version` and `/api/tags`).
pub struct HttpOllamaClient {
    endpoint: String,
    agent: ureq::Agent,
    max_body_bytes: u64,
}

impl std::fmt::Debug for HttpOllamaClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpOllamaClient")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl HttpOllamaClient {
    /// Builds a client for `endpoint` with the given connect and read timeout.
    ///
    /// Construction validates the URL and does not open a connection.
    pub fn new(endpoint: &str, timeout: Duration) -> Result<Self, OllamaError> {
        Self::build(endpoint, timeout, MAX_RESPONSE_BYTES)
    }

    fn build(endpoint: &str, timeout: Duration, max_body_bytes: u64) -> Result<Self, OllamaError> {
        if timeout.is_zero() {
            return Err(OllamaError::InvalidTimeout);
        }
        let endpoint = normalize_endpoint(endpoint)?;
        let agent = ureq::AgentBuilder::new()
            .timeout(timeout)
            .timeout_connect(timeout)
            .timeout_read(timeout)
            .timeout_write(timeout)
            .redirects(0)
            .build();
        Ok(Self {
            endpoint,
            agent,
            max_body_bytes,
        })
    }

    /// Normalized origin this client will call.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn check_model_inner(&self, model: &str) -> OllamaAvailability {
        if !valid_model_name(model) {
            return OllamaAvailability::Unavailable {
                message: "model name is invalid".to_owned(),
            };
        }

        let version = match self.get_json::<VersionResponse>("/api/version") {
            Ok(response) => response.version,
            Err(message) => return OllamaAvailability::Unavailable { message },
        };
        match self.get_json::<TagsResponse>("/api/tags") {
            Ok(response) if model_is_present(model, &response.models) => {
                OllamaAvailability::Ready { version }
            }
            Ok(_) => OllamaAvailability::ModelMissing { version },
            Err(message) => OllamaAvailability::Unavailable { message },
        }
    }

    fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let url = format!("{}{path}", self.endpoint);
        let response = match self
            .agent
            .get(&url)
            .set("Accept", "application/json")
            .set("User-Agent", "lca/0.1")
            .call()
        {
            Ok(response) => response,
            Err(ureq::Error::Status(code, response)) => {
                let _ = self.read_body(response);
                return Err(format!("HTTP {code} from {url}"));
            }
            Err(ureq::Error::Transport(error)) => {
                return Err(format!("request to {url} failed: {error}"));
            }
        };

        let body = self.read_body(response)?;
        serde_json::from_str(&body).map_err(|_| format!("invalid JSON from {url}"))
    }

    fn read_body(&self, response: ureq::Response) -> Result<String, String> {
        let mut reader = response.into_reader().take(self.max_body_bytes + 1);
        let mut body = Vec::new();
        reader
            .read_to_end(&mut body)
            .map_err(|error| format!("failed to read response body: {error}"))?;
        if body.len() as u64 > self.max_body_bytes {
            return Err(format!(
                "response body exceeds {} bytes",
                self.max_body_bytes
            ));
        }
        String::from_utf8(body).map_err(|_| "response body was not valid UTF-8".to_owned())
    }
}

impl OllamaClient for HttpOllamaClient {
    fn check_model(&self, model: &str) -> OllamaAvailability {
        let availability = self.check_model_inner(model);
        tracing::debug!(
            endpoint = %self.endpoint,
            state = availability.as_str(),
            "checked Ollama"
        );
        availability
    }
}

fn valid_model_name(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= MAX_MODEL_LEN
        && !model
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
}

fn normalize_endpoint(value: &str) -> Result<String, OllamaError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(OllamaError::EmptyEndpoint);
    }
    if trimmed.len() > MAX_ENDPOINT_LEN {
        return Err(OllamaError::EndpointTooLong);
    }

    let url = Url::parse(trimmed).map_err(|_| OllamaError::InvalidUrl)?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(OllamaError::InvalidScheme);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(OllamaError::EndpointCredentials);
    }
    let host = url.host_str().ok_or(OllamaError::MissingHost)?;
    if url.path() != "/" && !url.path().is_empty() {
        return Err(OllamaError::UnexpectedPath);
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(OllamaError::UnexpectedQuery);
    }

    let origin = match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    };
    Ok(origin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Instant;

    fn client(endpoint: &str) -> HttpOllamaClient {
        HttpOllamaClient::new(endpoint, Duration::from_secs(2)).expect("client")
    }

    fn serve(responses: Vec<(u16, String)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        thread::spawn(move || {
            for (status, body) in responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut buffer = [0_u8; 4096];
                let _ = stream.read(&mut buffer);
                let reason = if status == 200 { "OK" } else { "Error" };
                let header = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes());
                let _ = stream.write_all(body.as_bytes());
            }
        });
        format!("http://{address}")
    }

    #[test]
    fn construction_validates_without_connecting() {
        let client = HttpOllamaClient::new("http://127.0.0.1:11434/", Duration::from_secs(5))
            .expect("normalized");
        assert_eq!(client.endpoint(), "http://127.0.0.1:11434");

        let ipv6 =
            HttpOllamaClient::new("http://[::1]:11434", Duration::from_secs(1)).expect("ipv6");
        assert_eq!(ipv6.endpoint(), "http://[::1]:11434");

        assert_eq!(
            HttpOllamaClient::new("ftp://127.0.0.1:11434", Duration::from_secs(1))
                .expect_err("scheme"),
            OllamaError::InvalidScheme
        );
        assert_eq!(
            HttpOllamaClient::new("http://127.0.0.1:11434/v1", Duration::from_secs(1))
                .expect_err("path"),
            OllamaError::UnexpectedPath
        );
        assert_eq!(
            HttpOllamaClient::new(
                "http://user:super-secret-password@127.0.0.1:11434",
                Duration::from_secs(1)
            )
            .expect_err("credentials"),
            OllamaError::EndpointCredentials
        );
        assert!(
            !OllamaError::EndpointCredentials
                .to_string()
                .contains("super-secret-password")
        );
        assert_eq!(
            HttpOllamaClient::new("http://127.0.0.1:11434", Duration::ZERO).expect_err("timeout"),
            OllamaError::InvalidTimeout
        );
    }

    #[test]
    fn ready_and_missing_models_come_from_the_native_api() {
        let ready_endpoint = serve(vec![
            (200, r#"{"version":"0.13.5"}"#.to_owned()),
            (
                200,
                r#"{"models":[{"name":"lca-30b-agent:latest","size":1}]}"#.to_owned(),
            ),
        ]);
        let ready = client(&ready_endpoint).check_model("lca-30b-agent");
        assert_eq!(
            ready,
            OllamaAvailability::Ready {
                version: "0.13.5".to_owned()
            }
        );

        let missing_endpoint = serve(vec![
            (200, r#"{"version":"0.13.5"}"#.to_owned()),
            (200, r#"{"models":[{"name":"other:latest"}]}"#.to_owned()),
        ]);
        let missing = client(&missing_endpoint).check_model("lca-30b-agent");
        assert_eq!(
            missing,
            OllamaAvailability::ModelMissing {
                version: "0.13.5".to_owned()
            }
        );
    }

    #[test]
    fn bad_responses_are_unavailable_and_do_not_include_the_body() {
        let invalid = serve(vec![(200, "not-json".to_owned())]);
        let status = client(&invalid).check_model("lca-30b-agent");
        let OllamaAvailability::Unavailable { message } = status else {
            panic!("expected unavailable");
        };
        assert!(message.contains("invalid JSON"), "{message}");
        assert!(!message.contains("not-json"), "{message}");

        let failure = serve(vec![(500, "secret-body".to_owned())]);
        let status = client(&failure).check_model("lca-30b-agent");
        let OllamaAvailability::Unavailable { message } = status else {
            panic!("expected unavailable");
        };
        assert!(message.contains("HTTP 500"), "{message}");
        assert!(!message.contains("secret-body"), "{message}");
    }

    #[test]
    fn connection_refused_is_unavailable() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("address").port();
        drop(listener);

        let client =
            HttpOllamaClient::new(&format!("http://127.0.0.1:{port}"), Duration::from_secs(1))
                .expect("client");
        let status = client.check_model("lca-30b-agent");
        assert!(
            matches!(status, OllamaAvailability::Unavailable { .. }),
            "{status:?}"
        );
    }

    #[test]
    fn stalled_server_hits_the_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                thread::sleep(Duration::from_secs(5));
                drop(stream);
            }
        });

        let client =
            HttpOllamaClient::new(&format!("http://{address}"), Duration::from_millis(300))
                .expect("client");
        let started = Instant::now();
        let status = client.check_model("lca-30b-agent");
        let elapsed = started.elapsed();
        let OllamaAvailability::Unavailable { message } = status else {
            panic!("expected unavailable");
        };
        // The stub holds the socket for 5s. Returning sooner shows the client timeout
        // fired. Windows formats that failure in the local language (os error 10060).
        assert!(
            (Duration::from_millis(150)..Duration::from_secs(2)).contains(&elapsed),
            "{elapsed:?} {message}"
        );
    }

    #[test]
    fn oversized_bodies_are_rejected_without_being_returned() {
        let endpoint = serve(vec![(200, "a".repeat(64))]);
        let client =
            HttpOllamaClient::build(&endpoint, Duration::from_secs(2), 16).expect("client");
        let status = client.check_model("lca-30b-agent");
        let OllamaAvailability::Unavailable { message } = status else {
            panic!("expected unavailable");
        };
        assert!(message.contains("exceeds 16 bytes"), "{message}");
        assert!(!message.contains(&"a".repeat(16)), "{message}");
    }

    #[test]
    fn invalid_model_names_do_not_contact_the_server() {
        let client = client("http://127.0.0.1:9");
        let status = client.check_model(" ");
        assert_eq!(
            status,
            OllamaAvailability::Unavailable {
                message: "model name is invalid".to_owned()
            }
        );
    }
}
