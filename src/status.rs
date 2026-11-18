//! Live status of rule decisions: an event log shared with the proxy handler
//! and a tiny HTTP server exposing it — an HTML page (SSE) for humans, a JSON
//! feed for harness scripts. This is the "the rule did not match, silently"
//! antidote: every intercepted connection and request shows up with the
//! decision the proxy made and the reason.

use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

/// How many events the ring buffer keeps for `/events` and SSE snapshots.
const BUFFER_CAPACITY: usize = 500;

/// What the proxy decided about one intercepted unit (a TLS connection or an
/// HTTP request). Serialized into the JSON feed; field names are the contract
/// for harness scripts.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Decision {
    /// Rule matched: the request goes to this target.
    Matched { rule_index: usize, target: String },
    /// No rule matched; the reason says why.
    Missed { reason: String },
    /// CONNECT tunnel passed through without decryption (a rule opted the
    /// host out of interception).
    #[allow(dead_code)]
    Tunnel,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Event {
    pub id: u64,
    /// Epoch milliseconds.
    pub ts: u64,
    /// `connect` or `request`. Responses never emit a separate event — they
    /// fill the `status`/`duration_ms` fields of the matching request event
    /// in place and re-notify its id.
    pub kind: &'static str,
    pub host: String,
    /// Request path (empty for connects).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    /// Filled by the matching `response` event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Request → response round-trip, milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

impl Event {
    fn new(kind: &'static str, host: String, path: String, method: String) -> Self {
        Self {
            id: 0,
            ts: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            kind,
            host,
            path,
            method,
            decision: None,
            status: None,
            duration_ms: None,
        }
    }
}

/// Shared event log: ring buffer for late subscribers plus a broadcast channel
/// for live SSE updates.
#[derive(Debug)]
pub struct EventLog {
    buffer: Mutex<VecDeque<Arc<RwLock<Event>>>>,
    sender: broadcast::Sender<u64>,
    next_id: AtomicU64,
}

impl Default for EventLog {
    fn default() -> Self {
        let (sender, _) = broadcast::channel(256);

        Self {
            buffer: Mutex::new(VecDeque::with_capacity(BUFFER_CAPACITY)),
            sender,
            next_id: AtomicU64::new(1),
        }
    }
}

impl EventLog {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn push(&self, mut event: Event) -> Arc<RwLock<Event>> {
        event.id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let shared = Arc::new(RwLock::new(event));

        {
            let mut buffer = self.buffer.lock().expect("event buffer lock");
            buffer.push_front(Arc::clone(&shared));
            while buffer.len() > BUFFER_CAPACITY {
                buffer.pop_back();
            }
        }

        // Live subscribers get the id; they read the event from `/events`
        // semantics by asking the log — keeps the channel payload tiny.
        let _ = self.sender.send(shared.read().expect("event lock").id);

        shared
    }

    /// Record a TLS CONNECT decision; returns the event id.
    pub fn record_connect(&self, host: &str, decision: Decision) -> u64 {
        let mut event = Event::new("connect", host.to_string(), String::new(), String::new());
        event.decision = Some(decision);
        self.push(event).read().expect("event lock").id
    }

    /// Record an HTTP request with its rule decision; returns the event id.
    pub fn record_request(&self, method: &str, host: &str, path: &str, decision: Decision) -> u64 {
        let mut event = Event::new(
            "request",
            host.to_string(),
            path.to_string(),
            method.to_string(),
        );
        event.decision = Some(decision);
        self.push(event).read().expect("event lock").id
    }

    /// Fill in the outcome of the request with the given id.
    pub fn record_response(&self, id: u64, status: u16, duration_ms: u64) {
        {
            let buffer = self.buffer.lock().expect("event buffer lock");
            if let Some(event) = buffer
                .iter()
                .find(|event| event.read().expect("event lock").id == id)
            {
                let mut guard = event.write().expect("event lock");
                guard.status = Some(status);
                guard.duration_ms = Some(duration_ms);
            }
        }

        // Live subscribers re-render the updated row.
        let _ = self.sender.send(id);
    }

    /// The event with this id, newest-first lookup.
    pub fn get(&self, id: u64) -> Option<Event> {
        let buffer = self.buffer.lock().expect("event buffer lock");

        buffer
            .iter()
            .find(|event| event.read().expect("event lock").id == id)
            .map(|event| event.read().expect("event lock").clone())
    }

    /// Newest-first snapshot for `/events` and the SSE hello.
    pub fn snapshot(&self) -> Vec<Event> {
        let buffer = self.buffer.lock().expect("event buffer lock");

        buffer
            .iter()
            .map(|event| event.read().expect("event lock").clone())
            .collect()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<u64> {
        self.sender.subscribe()
    }
}

/// Epoch milliseconds, the timestamp unit of the status feed.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn json_of(events: &[Event]) -> String {
    serde_json::to_string(events).unwrap_or_else(|_| "[]".into())
}

/// Minimal HTML page: a table of events, live via EventSource. Inline styles,
/// no build step — this is a status page, not a product.
fn html_page() -> &'static str {
    r##"<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>rexy — rules status</title>
<style>
  body { font: 13px/1.4 ui-monospace, Menlo, monospace; margin: 16px; background: #111; color: #ddd; }
  h1 { font-size: 15px; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: 3px 8px; border-bottom: 1px solid #333; vertical-align: top; }
  th { color: #888; }
  .miss { color: #ff7b72; }
  .match { color: #7ee787; }
  .tunnel { color: #d2a8ff; }
  time { color: #666; }
</style>
</head>
<body>
<h1>rexy — rule decisions <time id="updated"></time></h1>
<table id="log">
  <thead>
    <tr><th>id</th><th>kind</th><th>method</th><th>host</th><th>path</th><th>decision</th><th>status</th><th>ms</th></tr>
  </thead>
  <tbody></tbody>
</table>
<script>
const tbody = document.querySelector("#log tbody");
const rows = new Map();

function decisionText(e) {
  if (!e.decision) return "";
  if (e.decision.type === "matched") return `rule #${e.decision.rule_index + 1} → ${e.decision.target}`;
  if (e.decision.type === "tunnel") return "CONNECT tunnel (no decrypt)";
  return `miss: ${e.decision.reason}`;
}
function classOf(e) {
  if (!e.decision) return "";
  return e.decision.type === "matched" ? "match" : e.decision.type === "tunnel" ? "tunnel" : "miss";
}
function render(e) {
  let tr = rows.get(e.id);
  if (!tr) {
    tr = document.createElement("tr");
    tr.innerHTML = "<td></td><td></td><td></td><td></td><td></td><td></td><td></td><td></td>";
    rows.set(e.id, tr);
    tbody.appendChild(tr);
  }
  const cells = tr.children;
  cells[0].textContent = e.id;
  cells[1].textContent = e.kind;
  cells[2].textContent = e.method;
  cells[3].textContent = e.host;
  cells[4].textContent = e.path;
  const dec = cells[5];
  dec.textContent = decisionText(e);
  dec.className = classOf(e);
  cells[6].textContent = e.status ?? "";
  cells[7].textContent = e.duration_ms ?? "";
  document.getElementById("updated").textContent = new Date(e.ts).toISOString();
}
function loadAll() {
  fetch("/events").then(r => r.json()).then(events => {
    tbody.textContent = "";
    rows.clear();
    [...events].reverse().forEach(render);
  });
}
loadAll();
new EventSource("/stream").onmessage = m => render(JSON.parse(m.data));
</script>
</body>
</html>
"##
}

/// Serve the status endpoints on `listener` until the process exits:
/// `GET /` — HTML page, `GET /events` — JSON snapshot, `GET /stream` — SSE.
pub async fn serve(listener: TcpListener, log: Arc<EventLog>) {
    let port = listener.local_addr().map(|addr| addr.port()).unwrap_or(0);

    loop {
        let Ok((socket, _)) = listener.accept().await else {
            continue;
        };

        let log = Arc::clone(&log);
        tokio::spawn(async move {
            if let Err(err) = handle(socket, log, port).await {
                tracing::debug!(?err, "status server connection ended");
            }
        });
    }
}

/// The `Host` header value of a raw request, if present.
fn request_host_header(request: &str) -> Option<&str> {
    request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("host").then(|| value.trim())
    })
}

/// Whether the `Host` header names this server itself. The header is parsed
/// as host:port: clients legitimately omit the port (curl on the default
/// port 80 sends `Host: localhost`), send an empty one (`localhost:`, the
/// RFC 3986 default-port form), append trailing root dots (`localhost.`) and
/// use any case (`LocalHost`) — all of those must pass. Anything else (a
/// rebinding host resolved to 127.0.0.1, bracketed or bare IPv6 — matching
/// is IPv4-name based — or an out-of-range port) is refused.
fn is_local_host(host_header: &str, bound_port: u16) -> bool {
    let host_header = host_header.trim_end_matches('.');

    // Split off the port at the last colon; a tail that is not purely
    // numeric (an unbracketed IPv6 literal, for instance) means no port.
    let (host, port) = match host_header.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => match port.parse::<u16>()
        {
            Ok(port) => (host, Some(port)),
            // An empty port is the default port (RFC 3986) — the bound one
            // here; a number outside u16 is not a port at all.
            Err(_) if port.is_empty() => (host, None),
            Err(_) => return false,
        },
        _ => (host_header, None),
    };

    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let port = port.unwrap_or(bound_port);

    (host == "127.0.0.1" || host == "localhost") && port == bound_port
}

async fn handle(mut socket: TcpStream, log: Arc<EventLog>, bound_port: u16) -> std::io::Result<()> {
    let mut buf = [0u8; 2048];
    let mut seen = 0usize;

    loop {
        let n = socket.read(&mut buf[seen..]).await?;
        if n == 0 {
            return Ok(());
        }
        seen += n;
        if buf[..seen].windows(4).any(|w| w == b"\r\n\r\n") || seen == buf.len() {
            break;
        }
    }

    let request = String::from_utf8_lossy(&buf[..seen]);

    // DNS rebinding guard: the status server is a localhost diagnostic that
    // exposes the rule decisions, so only the local names it is bound to may
    // address it. A page from any other origin (its host resolved to
    // 127.0.0.1 by a rebinding attack) is refused before any body is sent.
    if !request_host_header(&request).is_some_and(|host| is_local_host(host, bound_port)) {
        socket
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
        return Ok(());
    }

    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_string();

    match path.as_str() {
        "/" => {
            let body = html_page();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await?;
        }
        "/events" => {
            let body = json_of(&log.snapshot());
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await?;
        }
        "/stream" => {
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n",
                )
                .await?;

            // Subscribe BEFORE the snapshot: an event recorded between the
            // snapshot and a later subscribe would be in neither — the
            // broadcast channel only delivers ids published after
            // subscribing. A double delivery (queue + snapshot) is fine:
            // the client page keys its rows by event id.
            let mut receiver = log.subscribe();
            let mut last_sent_id = 0u64;

            // Hello: the full snapshot, newest first, then live updates.
            for event in log.snapshot() {
                let line = format!(
                    "data: {}\n\n",
                    serde_json::to_string(&event).unwrap_or_default()
                );
                socket.write_all(line.as_bytes()).await?;
                last_sent_id = event.id;
            }
            let _ = socket.flush().await;

            loop {
                match receiver.recv().await {
                    Ok(id) => {
                        if let Some(event) = log.get(id) {
                            let line = format!(
                                "data: {}\n\n",
                                serde_json::to_string(&event).unwrap_or_default()
                            );
                            if socket.write_all(line.as_bytes()).await.is_err() {
                                break;
                            }
                            let _ = socket.flush().await;
                            last_sent_id = last_sent_id.max(id);
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Missed notifications. The ids the receiver still
                        // retains are drained here (try_recv consumes them,
                        // so recv() would never re-deliver them) and re-sent
                        // below, after the older catch-up ids — the retained
                        // ones are the newest, so the client still sees ids
                        // in ascending order.
                        //
                        // The ring loop is bounded by the newest retained id:
                        // an event recorded after the drain is newer still and
                        // reaches this client through recv() in order —
                        // sending it from the snapshot here would break the
                        // ordering and duplicate it later. In-place response
                        // updates re-notify an old id on purpose; the client
                        // page keys its rows by id, so a repeated id is at
                        // worst an idempotent re-render.
                        let mut retained = Vec::new();
                        loop {
                            match receiver.try_recv() {
                                Ok(id) => retained.push(id),
                                Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
                                Err(_) => break,
                            }
                        }
                        retained.sort_unstable();
                        retained.dedup();
                        let retained_max = retained.last().copied().unwrap_or(last_sent_id);
                        let retained_set: std::collections::HashSet<u64> =
                            retained.iter().copied().collect();

                        // Older missed events from the ring (ids are
                        // monotonic). Events already evicted from the ring are
                        // gone for good — the newest ones still arrive.
                        for event in log.snapshot().into_iter().rev() {
                            if event.id <= last_sent_id
                                || event.id > retained_max
                                || retained_set.contains(&event.id)
                            {
                                continue;
                            }
                            let line = format!(
                                "data: {}\n\n",
                                serde_json::to_string(&event).unwrap_or_default()
                            );
                            if socket.write_all(line.as_bytes()).await.is_err() {
                                return Ok(());
                            }
                            last_sent_id = last_sent_id.max(event.id);
                        }

                        for id in retained {
                            if let Some(event) = log.get(id) {
                                let line = format!(
                                    "data: {}\n\n",
                                    serde_json::to_string(&event).unwrap_or_default()
                                );
                                if socket.write_all(line.as_bytes()).await.is_err() {
                                    return Ok(());
                                }
                                last_sent_id = last_sent_id.max(id);
                            }
                        }
                        let _ = socket.flush().await;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
        _ => {
            let response =
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_get_ids_and_snapshot_is_newest_first() {
        let log = EventLog::new();

        let first = log.record_request(
            "GET",
            "a.example.com",
            "/x",
            Decision::Missed {
                reason: "host not configured".into(),
            },
        );
        let second = log.record_request(
            "GET",
            "b.example.com",
            "/y",
            Decision::Matched {
                rule_index: 0,
                target: "http://127.0.0.1:1".into(),
            },
        );

        assert_eq!(first + 1, second);

        let snapshot = log.snapshot();
        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].host, "b.example.com");
        assert_eq!(snapshot[1].host, "a.example.com");
    }

    #[test]
    fn buffer_is_capped() {
        let log = EventLog::new();

        for i in 0..(BUFFER_CAPACITY + 50) {
            log.record_request(
                "GET",
                &format!("host-{i}.example.com"),
                "/",
                Decision::Missed {
                    reason: "host not configured".into(),
                },
            );
        }

        assert_eq!(log.snapshot().len(), BUFFER_CAPACITY);
        assert_eq!(
            log.snapshot()[0].host,
            format!("host-{}.example.com", BUFFER_CAPACITY + 49)
        );
    }

    #[test]
    fn response_updates_request_in_place() {
        let log = EventLog::new();

        let id = log.record_request(
            "GET",
            "a.example.com",
            "/x",
            Decision::Matched {
                rule_index: 2,
                target: "http://127.0.0.1:1".into(),
            },
        );

        log.record_response(id, 200, 42);

        let snapshot = log.snapshot();
        assert_eq!(snapshot[0].status, Some(200));
        assert_eq!(snapshot[0].duration_ms, Some(42));
        assert!(matches!(
            snapshot[0].decision,
            Some(Decision::Matched { .. })
        ));
    }

    #[tokio::test]
    async fn server_answers_events_and_unknown_paths() {
        let log = EventLog::new();
        log.record_request(
            "GET",
            "a.example.com",
            "/x",
            Decision::Missed {
                reason: "host not configured".into(),
            },
        );

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::clone(&log)));

        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(
                format!(
                    "GET /events HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                    addr.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).await.unwrap();

        assert!(response.contains("200 OK"));
        assert!(response.contains("a.example.com"));
        assert!(response.contains("host not configured"));

        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(
                format!(
                    "GET /nope HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                    addr.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).await.unwrap();

        assert!(response.contains("404"));
    }

    #[tokio::test]
    async fn foreign_host_header_is_rejected() {
        let log = EventLog::new();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::clone(&log)));

        // A rebinding-style request: the page origin claims a different host.
        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(b"GET /events HTTP/1.1\r\nHost: evil.example.com\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).await.unwrap();

        assert!(response.contains("403"), "{response}");
        assert!(!response.contains("a.example.com"), "{response}");

        // No Host header at all is equally refused.
        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(b"GET /events HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).await.unwrap();

        assert!(response.contains("403"), "{response}");
    }

    #[test]
    fn is_local_host_accepts_client_host_variations() {
        // The port may be omitted (curl sends `Host: localhost` on the
        // default port 80); an omitted port counts as the bound one.
        assert!(is_local_host("localhost", 80));
        assert!(is_local_host("localhost", 8125));
        assert!(is_local_host("127.0.0.1", 8125));
        assert!(is_local_host("LOCALHOST", 8125));

        // Case-insensitive, trailing root dots on the host or after the
        // port, an explicit correct port, and an empty port (the RFC 3986
        // default-port form) all pass.
        assert!(is_local_host("LocalHost:8125", 8125));
        assert!(is_local_host("localhost.:8125", 8125));
        assert!(is_local_host("localhost:8125.", 8125));
        assert!(is_local_host("127.0.0.1:8125", 8125));
        assert!(is_local_host("localhost:", 8125));

        // Anything else is refused: other hosts, wrong ports, bracketed or
        // bare IPv6 literals (matching is IPv4-name based), out-of-range
        // port numbers.
        assert!(!is_local_host("evil.example.com:8125", 8125));
        assert!(!is_local_host("127.0.0.1:9999", 8125));
        assert!(!is_local_host("localhost:80", 8125));
        assert!(!is_local_host("localhost.:8125", 9999));
        assert!(!is_local_host("[::1]:8125", 8125));
        assert!(!is_local_host("::1", 8125));
        assert!(!is_local_host("localhost:65536", 8125));
    }

    #[tokio::test]
    async fn host_header_without_port_is_accepted() {
        let log = EventLog::new();

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::clone(&log)));

        // curl on the default port sends `Host: localhost` with no port at
        // all — the bound port is implied and the request must pass.
        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(b"GET /events HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).await.unwrap();

        assert!(response.contains("200 OK"), "{response}");
    }

    #[tokio::test]
    async fn stream_sends_hello_snapshot_with_data_prefix() {
        let log = EventLog::new();
        log.record_request(
            "GET",
            "a.example.com",
            "/x",
            Decision::Missed {
                reason: "host not configured".into(),
            },
        );

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::clone(&log)));

        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(
                format!(
                    "GET /stream HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                    addr.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        // The hello (headers + snapshot lines) must arrive promptly; the
        // stream itself stays open (SSE), so read until the data lines show
        // up instead of read_to_string.
        let read = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let marker = b"data: {";
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = socket.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf
                    .windows(marker.len())
                    .any(|window| window == marker.as_slice())
                {
                    break;
                }
            }
            buf
        })
        .await
        .expect("hello snapshot must arrive within the timeout");

        let hello = String::from_utf8_lossy(&read);
        assert!(hello.contains("200 OK"), "{hello}");
        assert!(hello.contains("data: {"), "{hello}");
        assert!(hello.contains("a.example.com"), "{hello}");
    }

    #[tokio::test]
    async fn lagged_stream_catches_up_in_order_without_duplicates() {
        let log = EventLog::new();
        log.record_request(
            "GET",
            "a.example.com",
            "/x",
            Decision::Missed {
                reason: "host not configured".into(),
            },
        );

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, Arc::clone(&log)));

        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(
                format!(
                    "GET /stream HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                    addr.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        // Read the hello (headers + the id 1 snapshot line).
        let hello = read_until_marker(&mut socket, b"data: {").await;
        assert!(hello.contains("a.example.com"), "{hello}");

        // A burst of events while this test task holds the only thread: the
        // stream handler cannot poll its receiver, the broadcast queue
        // (capacity 256) overflows and the handler must take the Lagged
        // catch-up path.
        for i in 0..320 {
            log.record_request(
                "GET",
                &format!("host-{i}.example.com"),
                "/",
                Decision::Missed {
                    reason: "burst".into(),
                },
            );
        }

        // Read until the last event id shows up.
        let tail = read_until_marker(&mut socket, br#""id":321,"#).await;
        let raw = format!("{hello}{tail}");

        let ids: Vec<u64> = raw
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .map(|json| {
                serde_json::from_str::<serde_json::Value>(json)
                    .expect("every data line is a JSON event")["id"]
                    .as_u64()
                    .expect("event id is a number")
            })
            .collect();

        // Hello id 1 first, the burst last: strictly increasing means no
        // duplicates and no gaps — the lagged events all arrived exactly
        // once.
        assert_eq!(ids.len(), 321, "ids: {ids:?}");
        assert_eq!(ids.first(), Some(&1), "ids: {ids:?}");
        assert_eq!(ids.last(), Some(&321), "ids: {ids:?}");
        assert!(
            ids.windows(2).all(|pair| pair[0] < pair[1]),
            "ids must be strictly increasing: {ids:?}"
        );
    }

    /// Read from the socket until `marker` shows up (or the stream ends),
    /// bounded by a timeout — the SSE connection never closes on its own.
    async fn read_until_marker(socket: &mut TcpStream, marker: &[u8]) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let n = socket.read(&mut chunk).await.expect("socket read");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(marker.len()).any(|w| w == marker) {
                    break;
                }
            }
        })
        .await
        .expect("expected data must arrive within the timeout");

        String::from_utf8_lossy(&buf).into_owned()
    }
}
