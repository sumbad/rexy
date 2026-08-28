use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// PAC script that routes only the intercepted host through the local MITM proxy and lets
/// everything else (messenger, WebRTC/STUN, long-poll, CDN) go DIRECT. Without this, the
/// browser sends *all* traffic through the proxy, whose CONNECT passthrough for
/// non-intercepted hosts breaks the calls signaling/media.
pub fn content(host: &str, proxy_port: u16) -> String {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let host_cond = format!("host === \"{host}\" || host.endsWith(\".{host}\")");

    r#"function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (__HOST_COND__) {
    return "PROXY 127.0.0.1:__PORT__";
  }
  return "DIRECT";
}
"#
    .replace("__HOST_COND__", &host_cond)
    .replace("__PORT__", &proxy_port.to_string())
}

/// Minimal one-shot HTTP server serving the PAC script. Chromium fetches the PAC script URL
/// directly (before applying the PAC), so a plain 127.0.0.1 listener is sufficient.
pub async fn serve(listener: TcpListener, content: String) {
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            continue;
        };

        let content = content.clone();
        tokio::spawn(handle(socket, content));
    }
}

async fn handle(mut socket: TcpStream, content: String) {
    // Consume the request until the end of the headers so the response is not interleaved
    // with a still-in-flight request. The PAC fetch is a tiny GET, so a single small buffer
    // covers it, but loop until we see the header terminator just in case.
    let mut buf = [0u8; 1024];
    let mut seen = 0usize;
    loop {
        match socket.read(&mut buf[seen..]).await {
            Ok(0) => break,
            Ok(n) => {
                seen += n;
                if buf[..seen].windows(4).any(|w| w == b"\r\n\r\n") || seen == buf.len() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{}",
        content.len(),
        content
    );

    let _ = socket.write_all(response.as_bytes()).await;
    let _ = socket.shutdown().await;
}
