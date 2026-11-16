mod common;

use std::time::{Duration, Instant};

use futures_util::StreamExt;
use lca_model_runtime::contract::{
    self, CUT_TEXT, HANG_TEXT, MODEL_CUT, MODEL_HANG, MODEL_MISSING, MODEL_OK, MODEL_STREAM,
    OK_INPUT_TOKENS, OK_OUTPUT_TOKENS, OK_TEXT, STREAM_PARTS,
};
use lca_model_runtime::{
    GenerationEvent, GenerationOptions, GenerationRequest, Message, ModelRuntime,
};
use lca_ollama::{MAX_STREAM_FRAME_BYTES, OllamaModelRuntime, OllamaRuntimeConfig};

use common::{Reply, json_body, spawn};

fn connect_at(endpoint: &str, connect: Duration, request: Duration) -> OllamaModelRuntime {
    OllamaModelRuntime::connect(OllamaRuntimeConfig::new(endpoint, connect, request))
        .expect("runtime")
}

fn user_request(model: &str, timeout: Duration) -> GenerationRequest {
    GenerationRequest::try_new(
        model,
        vec![Message::user("ping")],
        GenerationOptions {
            timeout: Some(timeout),
            ..GenerationOptions::default()
        },
    )
    .expect("request")
}

fn contract_reply(request: String) -> Reply {
    let model = request
        .split("\"model\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or("");
    match model {
        MODEL_OK => json_body(
            200,
            &format!(
                "{{\"model\":\"{MODEL_OK}\",\"message\":{{\"role\":\"assistant\",\"content\":\"{OK_TEXT}\"}},\"done\":true,\"done_reason\":\"stop\",\"prompt_eval_count\":{OK_INPUT_TOKENS},\"eval_count\":{OK_OUTPUT_TOKENS}}}"
            ),
        ),
        MODEL_MISSING => json_body(
            404,
            &format!("{{\"error\":\"model '{MODEL_MISSING}' not found\"}}"),
        ),
        MODEL_STREAM => json_body(
            200,
            &format!(
                "{{\"model\":\"{MODEL_STREAM}\",\"message\":{{\"role\":\"assistant\",\"content\":\"{}\"}},\"done\":false}}\n{{\"model\":\"{MODEL_STREAM}\",\"message\":{{\"role\":\"assistant\",\"content\":\"{}\"}},\"done\":false}}\n{{\"model\":\"{MODEL_STREAM}\",\"message\":{{\"role\":\"assistant\",\"content\":\"\"}},\"done\":true,\"done_reason\":\"stop\"}}\n",
                STREAM_PARTS[0], STREAM_PARTS[1]
            ),
        ),
        MODEL_CUT => json_body(
            200,
            &format!(
                "{{\"model\":\"{MODEL_CUT}\",\"message\":{{\"role\":\"assistant\",\"content\":\"{CUT_TEXT}\"}},\"done\":false}}\n"
            ),
        ),
        MODEL_HANG => {
            let line = format!(
                "{{\"model\":\"{MODEL_HANG}\",\"message\":{{\"role\":\"assistant\",\"content\":\"{HANG_TEXT}\"}},\"done\":false}}\n"
            );
            Reply::Chunked {
                parts: vec![line.into_bytes()],
                hold: true,
            }
        }
        _ => json_body(500, "{\"error\":\"unexpected model\"}"),
    }
}

#[tokio::test]
async fn ollama_adapter_satisfies_the_runtime_contract() {
    let mock = spawn(contract_reply).await;
    let runtime = connect_at(
        mock.endpoint(),
        Duration::from_secs(2),
        Duration::from_secs(2),
    );
    let result = tokio::time::timeout(Duration::from_secs(5), contract::exercise(&runtime)).await;
    assert!(result.is_ok(), "contract exercise timed out");
}

#[tokio::test]
async fn http_status_codes_map_to_runtime_errors_without_retry() {
    let cases = [
        (400, "{\"error\":\"bad options\"}", "invalid_request"),
        (
            404,
            "{\"error\":\"model 'm' not found\"}",
            "model_not_found",
        ),
        (500, "super-secret-password", "backend_failure"),
    ];
    for (status, body, kind) in cases {
        let body = body.to_owned();
        let mock = spawn(move |_| json_body(status, &body)).await;
        let runtime = connect_at(
            mock.endpoint(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let error = runtime
            .generate(user_request("m", Duration::from_secs(1)))
            .await
            .expect_err("status");
        assert_eq!(error.kind(), kind, "{error}");
        assert!(
            !error.to_string().contains("super-secret-password"),
            "{error}"
        );
        assert_eq!(mock.hits(), 1, "generation was retried");
    }
}

#[tokio::test]
async fn a_rejected_json_format_is_not_retried() {
    let mock = spawn(|request| {
        assert!(
            request.contains("\"format\":\"json\""),
            "JSON output was not requested"
        );
        json_body(
            400,
            "{\"error\":\"json format is not supported for this model\"}",
        )
    })
    .await;
    let runtime = connect_at(
        mock.endpoint(),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    let request = GenerationRequest::try_new(
        "lca-30b-agent",
        vec![Message::user("ping")],
        GenerationOptions {
            timeout: Some(Duration::from_secs(1)),
            response_format: lca_model_runtime::ResponseFormat::Json,
            ..GenerationOptions::default()
        },
    )
    .expect("request");
    let error = runtime.generate(request).await.expect_err("rejected");
    assert_eq!(error.kind(), "invalid_request", "{error}");
    assert!(
        error.to_string().contains("json format is not supported"),
        "{error}"
    );
    assert!(!error.to_string().contains("native"), "{error}");
    assert_eq!(mock.hits(), 1, "JSON format rejection was retried");
}

#[tokio::test]
async fn connection_reset_is_a_connection_error() {
    // This host drops SYNs to closed ports instead of sending RST, so a closed port
    // surfaces as a connect timeout. An accepted socket closed with linger 0 is a
    // connection failure the adapter must not report as success or as a timeout.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("address").port();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        socket2::SockRef::from(&stream)
            .set_linger(Some(Duration::ZERO))
            .expect("linger");
        drop(stream);
        std::thread::sleep(Duration::from_millis(300));
    });
    let runtime = connect_at(
        &format!("http://127.0.0.1:{port}"),
        Duration::from_secs(2),
        Duration::from_secs(2),
    );
    let started = Instant::now();
    let error = runtime
        .generate(user_request("m", Duration::from_secs(2)))
        .await
        .expect_err("reset");
    assert_eq!(
        error.kind(),
        "connection",
        "{} after {:?}",
        lca_model_runtime::report(&error),
        started.elapsed()
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    server.join().expect("server");
}

#[tokio::test]
async fn a_closed_port_does_not_complete() {
    // Windows on this machine blackholes SYNs to a closed port (connect timeout).
    // Other stacks answer with connection refused. Either result is a failure.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("address").port();
    drop(listener);
    let runtime = connect_at(
        &format!("http://127.0.0.1:{port}"),
        Duration::from_millis(400),
        Duration::from_millis(400),
    );
    let started = Instant::now();
    let error = runtime
        .generate(user_request("m", Duration::from_millis(400)))
        .await
        .expect_err("closed");
    assert!(
        error.kind() == "connection" || error.kind() == "timeout",
        "{}",
        lca_model_runtime::report(&error)
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn a_stalled_server_is_a_request_timeout() {
    let mock = spawn(|_| Reply::Stall).await;
    let runtime = connect_at(
        mock.endpoint(),
        Duration::from_millis(200),
        Duration::from_millis(300),
    );
    let started = Instant::now();
    let error = runtime
        .generate(user_request("m", Duration::from_millis(300)))
        .await
        .expect_err("timeout");
    assert_eq!(error.kind(), "timeout", "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let mock =
        spawn(|_| Reply::Redirect("http://127.0.0.1:9/super-secret-password".to_owned())).await;
    let runtime = connect_at(
        mock.endpoint(),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    let error = runtime
        .generate(user_request("m", Duration::from_secs(1)))
        .await
        .expect_err("redirect");
    let rendered = error.to_string();
    assert!(!rendered.contains("super-secret-password"), "{rendered}");
    assert!(
        rendered.contains("redirect") || rendered.contains("302"),
        "{rendered}"
    );
    assert_eq!(mock.hits(), 1);
}

#[tokio::test]
async fn empty_and_invalid_success_bodies_are_protocol_errors() {
    for body in ["", "{"] {
        let empty = body.is_empty();
        let body = body.to_owned();
        let mock = spawn(move |_| json_body(200, &body)).await;
        let runtime = connect_at(
            mock.endpoint(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let error = runtime
            .generate(user_request("m", Duration::from_secs(1)))
            .await
            .expect_err("body");
        assert_eq!(error.kind(), "protocol_violation", "{error}");
        let code = if empty {
            "protocol_violation"
        } else {
            "invalid_http_json"
        };
        assert_eq!(error.code(), code, "{error}");
        assert!(!error.to_string().contains("assistant content"), "{error}");
        assert!(!error.to_string().contains('{'), "{error}");
    }
}

#[tokio::test]
async fn an_early_close_is_not_a_successful_completion() {
    let mock = spawn(|_| Reply::Close).await;
    let runtime = connect_at(
        mock.endpoint(),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    let error = runtime
        .generate(user_request("m", Duration::from_secs(1)))
        .await
        .expect_err("close");
    assert_ne!(error.kind(), "invalid_request", "{error}");
    assert!(
        matches!(
            error.kind(),
            "connection" | "protocol_violation" | "stream_interrupted"
        ),
        "{error}"
    );
}

async fn collect(
    runtime: &OllamaModelRuntime,
    model: &str,
) -> Vec<Result<GenerationEvent, lca_model_runtime::RuntimeError>> {
    let mut stream = runtime
        .generate_stream(user_request(model, Duration::from_secs(2)))
        .await
        .expect("stream");
    let mut events = Vec::new();
    while let Some(event) = stream.next().await {
        let stop = event.is_err();
        events.push(event);
        if stop {
            break;
        }
    }
    events
}

#[tokio::test]
async fn ndjson_frames_can_share_a_chunk_or_be_split() {
    let shared = concat!(
        "{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"Hello\"},\"done\":false}\n",
        "{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\" world\"},\"done\":true,\"done_reason\":\"stop\"}\n",
    );
    let mock = spawn(move |_| json_body(200, shared)).await;
    let runtime = connect_at(
        mock.endpoint(),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    let events = collect(&runtime, "m").await;
    assert_eq!(events.len(), 3, "{events:?}");
    assert!(matches!(&events[0], Ok(GenerationEvent::TextDelta(text)) if text == "Hello"));
    assert!(matches!(&events[1], Ok(GenerationEvent::TextDelta(text)) if text == " world"));
    assert!(matches!(events[2], Ok(GenerationEvent::Completed(_))));

    let full = "{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"Hello\"},\"done\":true,\"done_reason\":\"stop\"}\n";
    let split = full.len() / 2;
    let left = full.as_bytes()[..split].to_vec();
    let right = full.as_bytes()[split..].to_vec();
    let mock = spawn(move |_| Reply::Chunked {
        parts: vec![left.clone(), right.clone()],
        hold: false,
    })
    .await;
    let runtime = connect_at(
        mock.endpoint(),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    let events = collect(&runtime, "m").await;
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Ok(GenerationEvent::TextDelta(text)) if text == "Hello")),
        "{events:?}"
    );
    assert!(
        matches!(events.last(), Some(Ok(GenerationEvent::Completed(_)))),
        "{events:?}"
    );
}

#[tokio::test]
async fn a_stream_without_done_or_with_a_partial_frame_does_not_complete() {
    let mock = spawn(|_| {
        json_body(
            200,
            "{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"partial\"},\"done\":false}\n",
        )
    })
    .await;
    let runtime = connect_at(
        mock.endpoint(),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    let events = collect(&runtime, "m").await;
    assert!(matches!(&events[0], Ok(GenerationEvent::TextDelta(text)) if text == "partial"));
    assert_eq!(
        events[1].as_ref().expect_err("cut").kind(),
        "stream_interrupted"
    );
    assert!(
        events
            .iter()
            .all(|event| !matches!(event, Ok(GenerationEvent::Completed(_))))
    );

    let mock = spawn(|_| json_body(200, "{\"message\":{\"content\":\"Hi\"")).await;
    let runtime = connect_at(
        mock.endpoint(),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    let events = collect(&runtime, "m").await;
    assert_eq!(
        events
            .last()
            .and_then(|event| event.as_ref().err())
            .map(|error| error.kind()),
        Some("protocol_violation"),
        "{events:?}"
    );
}

#[tokio::test]
async fn an_oversized_frame_is_rejected() {
    let body = "x".repeat(MAX_STREAM_FRAME_BYTES + 1);
    let mock = spawn(move |_| json_body(200, &body)).await;
    let runtime = connect_at(
        mock.endpoint(),
        Duration::from_secs(2),
        Duration::from_secs(2),
    );
    let events = collect(&runtime, "m").await;
    assert_eq!(
        events[0].as_ref().expect_err("frame").kind(),
        "protocol_violation",
        "{events:?}"
    );
}

#[tokio::test]
async fn dropping_a_stream_releases_the_connection() {
    let line = b"{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"partial\"},\"done\":false}\n".to_vec();
    let mock = spawn(move |_| Reply::Chunked {
        parts: vec![line.clone()],
        hold: true,
    })
    .await;
    let runtime = connect_at(
        mock.endpoint(),
        Duration::from_secs(2),
        Duration::from_secs(2),
    );
    let mut stream = runtime
        .generate_stream(user_request("m", Duration::from_secs(2)))
        .await
        .expect("stream");
    let first = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("first event timed out")
        .expect("empty");
    assert!(
        matches!(first, Ok(GenerationEvent::TextDelta(_))),
        "{first:?}"
    );
    let started = Instant::now();
    drop(stream);
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[tokio::test]
async fn capabilities_use_show_and_do_not_invent_tools() {
    let mock = spawn(|_| {
        json_body(
            200,
            r#"{"capabilities":["completion","vision"],"details":{"family":"qwen","parameter_size":"30B"},"model_info":{"qwen2.context_length":32768}}"#,
        )
    })
    .await;
    let runtime = connect_at(
        mock.endpoint(),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    let report = runtime
        .capabilities("lca-agent")
        .await
        .expect("capabilities");
    assert_eq!(report.model(), "lca-agent");
    assert_eq!(
        report.chat(),
        lca_model_runtime::CapabilityStatus::Confirmed
    );
    assert_eq!(
        report.tools(),
        lca_model_runtime::CapabilityStatus::NotReported
    );
    assert_eq!(
        report.json_mode(),
        lca_model_runtime::CapabilityStatus::Unknown
    );
    assert_eq!(report.context_length(), Some(32_768));
    assert_eq!(report.unrecognized(), &["vision".to_owned()]);

    let missing = spawn(|_| json_body(404, r#"{"error":"model 'missing' not found"}"#)).await;
    let runtime = connect_at(
        missing.endpoint(),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    let error = runtime.capabilities("missing").await.expect_err("missing");
    assert_eq!(error.kind(), "model_not_found", "{error}");
}

#[tokio::test]
async fn an_invalid_request_does_not_open_a_connection() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("address").port();
    drop(listener);
    let runtime = connect_at(
        &format!("http://127.0.0.1:{port}"),
        Duration::from_secs(1),
        Duration::from_secs(1),
    );
    let error = runtime
        .generate(contract::invalid_request())
        .await
        .expect_err("invalid");
    assert_eq!(error.kind(), "invalid_request", "{error}");
}
