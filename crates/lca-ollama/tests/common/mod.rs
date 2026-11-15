//! In-process HTTP stub for runtime tests. It does not start Ollama.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub struct Mock {
    endpoint: String,
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Mock {
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub enum Reply {
    Bytes {
        status: u16,
        content_type: &'static str,
        body: Vec<u8>,
    },
    Chunked {
        parts: Vec<Vec<u8>>,
        hold: bool,
    },
    Redirect(String),
    Close,
    Stall,
}

pub async fn spawn(handler: impl Fn(String) -> Reply + Send + Sync + 'static) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = Arc::clone(&hits);
    let handler = Arc::new(handler);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let handler = Arc::clone(&handler);
            let hits_task = Arc::clone(&hits_task);
            tokio::spawn(async move {
                if let Some(request) = read_request(&mut socket).await {
                    hits_task.fetch_add(1, Ordering::SeqCst);
                    let reply = handler(request);
                    let _ = apply(&mut socket, reply).await;
                }
            });
        }
    });
    Mock {
        endpoint: format!("http://{address}"),
        hits,
        task,
    }
}

async fn read_request(socket: &mut TcpStream) -> Option<String> {
    let _ = socket.set_nodelay(true);
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 4096];
    let header_end = loop {
        if buffer.len() > 2_000_000 {
            return None;
        }
        let count = match tokio::time::timeout(Duration::from_secs(2), socket.read(&mut temp)).await
        {
            Ok(Ok(count)) => count,
            _ => return None,
        };
        if count == 0 {
            return None;
        }
        buffer.extend_from_slice(&temp[..count]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
    };
    let headers = String::from_utf8_lossy(&buffer[..header_end]);
    let length = content_length(&headers).unwrap_or(0);
    while buffer.len() < header_end + 4 + length {
        let count = match tokio::time::timeout(Duration::from_secs(2), socket.read(&mut temp)).await
        {
            Ok(Ok(count)) => count,
            _ => break,
        };
        if count == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..count]);
    }
    let end = (header_end + 4 + length).min(buffer.len());
    Some(String::from_utf8_lossy(&buffer[..end]).into_owned())
}

fn content_length(headers: &str) -> Option<usize> {
    for line in headers.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            return value.trim().parse().ok();
        }
    }
    None
}

async fn apply(socket: &mut TcpStream, reply: Reply) -> std::io::Result<()> {
    match reply {
        Reply::Bytes {
            status,
            content_type,
            body,
        } => {
            let reason = reason(status);
            let header = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(header.as_bytes()).await?;
            socket.write_all(&body).await?;
            socket.flush().await
        }
        Reply::Chunked { parts, hold } => {
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await?;
            for part in parts {
                let size = format!("{:x}\r\n", part.len());
                socket.write_all(size.as_bytes()).await?;
                socket.write_all(&part).await?;
                socket.write_all(b"\r\n").await?;
                socket.flush().await?;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            if hold {
                let mut sink = [0_u8; 32];
                let _ = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut sink)).await;
                return Ok(());
            }
            socket.write_all(b"0\r\n\r\n").await?;
            socket.flush().await
        }
        Reply::Redirect(location) => {
            let header = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            socket.write_all(header.as_bytes()).await?;
            socket.flush().await
        }
        Reply::Close => Ok(()),
        Reply::Stall => {
            tokio::time::sleep(Duration::from_secs(3)).await;
            Ok(())
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Error",
    }
}

pub fn json_body(status: u16, body: &str) -> Reply {
    Reply::Bytes {
        status,
        content_type: "application/json",
        body: body.as_bytes().to_vec(),
    }
}
