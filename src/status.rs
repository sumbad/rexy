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
    /// `connect`, `request` or `response`.
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
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            continue;
        };

        let log = Arc::clone(&log);
        tokio::spawn(async move {
            if let Err(err) = handle(socket, log).await {
                tracing::debug!(?err, "status server connection ended");
            }
        });
    }
}

async fn handle(mut socket: TcpStream, log: Arc<EventLog>) -> std::io::Result<()> {
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

            // Hello: the full snapshot, newest first, then live updates.
            for event in log.snapshot() {
                let line = format!(
                    "data: {}\n\n",
                    serde_json::to_string(&event).unwrap_or_default()
                );
                socket.write_all(line.as_bytes()).await?;
            }
            let _ = socket.flush().await;

            let mut receiver = log.subscribe();
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
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
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
            .write_all(b"GET /events HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).await.unwrap();

        assert!(response.contains("200 OK"));
        assert!(response.contains("a.example.com"));
        assert!(response.contains("host not configured"));

        let mut socket = TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(b"GET /nope HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).await.unwrap();

        assert!(response.contains("404"));
    }
}
