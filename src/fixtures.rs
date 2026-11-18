//! Record and replay of intercepted exchanges as HAR files — offline smoke
//! runs without the prod network.
//!
//! Format: HAR 1.2, one file per session. Only the fields rexy needs are
//! emitted; readers of the file (Chrome DevTools, mitmproxy) tolerate the
//! subset. Bodies are stored base64-encoded, so binary responses survive.
//!
//! Boundaries (documented in the README): responses are buffered before
//! recording, so streaming answers (SSE/long-poll) are not suitable for
//! recording; replay matches by method + URL (exact first, then URL without
//! the query) and returns the recorded status/headers/body as-is.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

// ---------- HAR subset ----------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HarHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HarContent {
    pub size: usize,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    pub text: String,
    pub encoding: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HarResponse {
    pub status: u16,
    #[serde(rename = "statusText")]
    pub status_text: String,
    #[serde(rename = "httpVersion")]
    pub http_version: String,
    pub headers: Vec<HarHeader>,
    pub content: HarContent,
    pub headers_size: i64,
    pub body_size: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HarRequest {
    pub method: String,
    pub url: String,
    #[serde(rename = "httpVersion")]
    pub http_version: String,
    pub headers: Vec<HarHeader>,
    #[serde(rename = "queryString")]
    pub query_string: Vec<HarHeader>,
    pub cookies: Vec<HarHeader>,
    #[serde(rename = "headersSize")]
    pub headers_size: i64,
    #[serde(rename = "bodySize")]
    pub body_size: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HarEntry {
    #[serde(rename = "startedDateTime")]
    pub started_date_time: String,
    pub time: i64,
    pub request: HarRequest,
    pub response: HarResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HarLog {
    pub version: String,
    pub creator: HarCreator,
    pub entries: Vec<HarEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HarCreator {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Har {
    pub log: HarLog,
}

impl Har {
    fn empty() -> Self {
        Self {
            log: HarLog {
                version: "1.2".into(),
                creator: HarCreator {
                    name: "rexy".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                },
                entries: Vec::new(),
            },
        }
    }

    pub fn from_str(raw: &str) -> Result<Self, String> {
        let har: Har = serde_json::from_str(raw).map_err(|err| format!("not a HAR file: {err}"))?;

        if har.log.version != "1.2" {
            return Err(format!("unsupported HAR version: {}", har.log.version));
        }

        Ok(har)
    }

    fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".into())
    }
}

// ---------- recording ----------

/// Accumulates entries during `--record <dir>` and rewrites the HAR file on
/// every completed exchange — a hard kill loses at most the exchange in
/// flight.
pub struct Recorder {
    path: PathBuf,
    har: Mutex<Har>,
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder")
            .field("path", &self.path)
            .finish()
    }
}

impl Recorder {
    pub fn start(dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(dir)
            .map_err(|err| format!("failed to create record dir {}: {err}", dir.display()))?;

        Ok(Self {
            path: dir.join("rexy-session.har"),
            har: Mutex::new(Har::empty()),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        method: &str,
        url: &str,
        request_headers: Vec<HarHeader>,
        response_status: u16,
        response_headers: Vec<HarHeader>,
        body: &[u8],
        duration_ms: i64,
    ) {
        use base64::Engine;

        let started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64 - duration_ms)
            .unwrap_or(0);

        let entry = HarEntry {
            started_date_time: iso8601_millis(started),
            time: duration_ms,
            request: HarRequest {
                method: method.to_string(),
                url: url.to_string(),
                http_version: "HTTP/1.1".into(),
                headers: request_headers,
                query_string: Vec::new(),
                cookies: Vec::new(),
                headers_size: -1,
                body_size: -1,
            },
            response: HarResponse {
                status: response_status,
                status_text: String::new(),
                http_version: "HTTP/1.1".into(),
                headers: response_headers,
                content: HarContent {
                    size: body.len(),
                    mime_type: String::new(),
                    text: base64::engine::general_purpose::STANDARD.encode(body),
                    encoding: Some("base64".into()),
                },
                headers_size: -1,
                body_size: body.len() as i64,
            },
        };

        let mut har = self.har.lock().expect("recorder lock");
        har.log.entries.push(entry);

        if let Err(err) = std::fs::write(&self.path, har.to_json()) {
            tracing::warn!(%err, path = %self.path.display(), "failed to write HAR file");
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// RFC 3339 timestamp from epoch milliseconds (no external time crates: HAR
/// readers accept ISO 8601 with any offset, UTC is used).
fn iso8601_millis(epoch_ms: i64) -> String {
    let secs = epoch_ms.div_euclid(1000);
    let millis = epoch_ms.rem_euclid(1000);

    // Civil-from-days algorithm (Howard Hinnant), valid for the whole range.
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (h, m, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{d:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

// ---------- replay ----------

/// Answers requests from a recorded HAR session: match by method + URL
/// (exact first, then URL without the query), so cache-busting query params
/// do not break the replay. Unmatched requests fall through to the usual
/// rules.
pub struct Replayer {
    entries: Mutex<HashMap<(String, String), HarResponse>>,
    no_query: Mutex<HashMap<(String, String), HarResponse>>,
}

impl std::fmt::Debug for Replayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Replayer").finish()
    }
}

impl Replayer {
    pub fn open(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|err| format!("failed to read HAR file {}: {err}", path.display()))?;
        let har = Har::from_str(&raw)?;

        let mut exact = HashMap::new();
        let mut no_query = HashMap::new();

        for entry in har.log.entries {
            let key = (
                entry.request.method.to_ascii_uppercase(),
                entry.request.url.clone(),
            );
            no_query
                .entry((key.0.clone(), strip_query(&key.1)))
                .or_insert(entry.response.clone());
            exact.insert(key, entry.response);
        }

        Ok(Self {
            entries: Mutex::new(exact),
            no_query: Mutex::new(no_query),
        })
    }

    pub fn lookup(&self, method: &str, url: &str) -> Option<HarResponse> {
        let entries = self.entries.lock().expect("replayer lock");
        if let Some(response) = entries.get(&(method.to_ascii_uppercase(), url.to_string())) {
            return Some(response.clone());
        }
        drop(entries);

        let no_query = self.no_query.lock().expect("replayer lock");
        no_query
            .get(&(method.to_ascii_uppercase(), strip_query(url)))
            .cloned()
    }
}

fn strip_query(url: &str) -> String {
    match url.find('?') {
        Some(pos) => url[..pos].to_string(),
        None => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_body() -> &'static [u8] {
        b"console.log(1)"
    }

    fn write_session(path: &Path) {
        let recorder = Recorder::start(path).unwrap();
        recorder.record(
            "GET",
            "https://a.example.com/api/x?v=1",
            vec![HarHeader {
                name: "host".into(),
                value: "a.example.com".into(),
            }],
            200,
            vec![HarHeader {
                name: "content-type".into(),
                value: "text/javascript".into(),
            }],
            sample_body(),
            12,
        );
    }

    #[test]
    fn recorded_session_is_har_and_replays_by_url() {
        let dir = std::env::temp_dir().join(format!("rexy-har-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        write_session(&dir);

        let har_path = dir.join("rexy-session.har");
        let raw = std::fs::read_to_string(&har_path).unwrap();
        // HAR 1.2 marker and base64 body survive the round trip.
        assert!(raw.contains(r#""version": "1.2""#));
        assert!(raw.contains("Y29uc29sZS5sb2coMSk=")); // base64(sample_body())

        let replayer = Replayer::open(&har_path).unwrap();

        // Exact URL hit.
        let hit = replayer
            .lookup("GET", "https://a.example.com/api/x?v=1")
            .expect("exact URL must hit");
        assert_eq!(hit.status, 200);

        // Same URL with a different query still hits (cache-buster tolerance).
        let hit = replayer
            .lookup("GET", "https://a.example.com/api/x?v=999")
            .expect("query-free URL must hit");
        assert_eq!(hit.status, 200);
        assert_eq!(hit.content.text, "Y29uc29sZS5sb2coMSk=");

        // Different URL or method misses.
        assert!(
            replayer
                .lookup("GET", "https://a.example.com/other")
                .is_none()
        );
        assert!(
            replayer
                .lookup("POST", "https://a.example.com/api/x?v=1")
                .is_none()
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn replay_rejects_non_har_files() {
        let path = std::env::temp_dir().join(format!("rexy-har-bad-{}.json", std::process::id()));
        std::fs::write(&path, "not json").unwrap();

        assert!(Replayer::open(&path).is_err());

        std::fs::write(
            &path,
            r#"{"log":{"version":"9.9","creator":{"name":"x","version":"1"},"entries":[]}}"#,
        )
        .unwrap();
        assert!(Replayer::open(&path).is_err());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn iso_timestamps_are_utc_rfc3339() {
        assert_eq!(iso8601_millis(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            iso8601_millis(1_700_000_000_123),
            "2023-11-14T22:13:20.123Z"
        );
    }
}
