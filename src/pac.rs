use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// PAC script that routes only the intercepted host through the local MITM proxy and lets
/// everything else (messenger, WebRTC/STUN, long-poll, CDN) go DIRECT. Without this, the
/// browser sends *all* traffic through the proxy, whose CONNECT passthrough for
/// non-intercepted hosts breaks the calls signaling/media.
pub fn content(hosts: &[String], proxy_port: u16) -> String {
    let conditions: Vec<String> = hosts
        .iter()
        .map(|host| {
            let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
            format!("host === \"{host}\" || host.endsWith(\".{host}\")")
        })
        .collect();

    let host_cond = if conditions.is_empty() {
        "false".to_string()
    } else {
        conditions.join("\n    || ")
    };

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pac_contains_all_hosts() {
        let pac = content(&["a.example.com".into(), "b.example.com".into()], 8888);

        assert!(pac.contains("host === \"a.example.com\" || host.endsWith(\".a.example.com\")"));
        assert!(pac.contains("host === \"b.example.com\" || host.endsWith(\".b.example.com\")"));
        assert!(pac.contains("PROXY 127.0.0.1:8888"));
    }

    #[test]
    fn pac_empty_hosts_routes_direct() {
        let pac = content(&[], 8888);

        assert!(pac.contains("if (false)"));
        assert!(pac.contains("PROXY 127.0.0.1:8888"));
    }
}
