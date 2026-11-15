//! Optional live call. `cargo test` does not run it.
//!
//! ```text
//! $env:LCA_OLLAMA_SMOKE = "1"
//! cargo test -p lca-ollama --test smoke -- --ignored --nocapture
//! ```
//!
//! A missing daemon or missing weights fails only this ignored test.

use std::time::Duration;

use lca_model_runtime::{GenerationOptions, GenerationRequest, Message, ModelRuntime};
use lca_ollama::{OllamaModelRuntime, OllamaRuntimeConfig};

#[tokio::test]
#[ignore = "talks to a local Ollama daemon; set LCA_OLLAMA_SMOKE=1"]
async fn live_ollama_smoke() {
    if std::env::var("LCA_OLLAMA_SMOKE").ok().as_deref() != Some("1") {
        eprintln!("skipping live smoke: LCA_OLLAMA_SMOKE is not 1");
        return;
    }
    let model = std::env::var("LCA_OLLAMA_MODEL").unwrap_or_else(|_| "lca-30b-agent".to_owned());
    let endpoint = std::env::var("LCA_OLLAMA_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:11434".to_owned());
    let runtime = OllamaModelRuntime::connect(OllamaRuntimeConfig::new(
        endpoint,
        Duration::from_secs(5),
        Duration::from_secs(120),
    ))
    .expect("runtime");
    let request = GenerationRequest::try_new(
        model,
        vec![Message::user("Reply with the single word pong.")],
        GenerationOptions {
            max_tokens: Some(32),
            timeout: Some(Duration::from_secs(120)),
            ..GenerationOptions::default()
        },
    )
    .expect("request");
    let response = runtime.generate(request).await.expect("generate");
    assert!(!response.text().trim().is_empty());
}
