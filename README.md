# rexy

`rexy` launches a browser through a local man-in-the-middle (MITM) proxy. The proxy
intercepts traffic to one live site (e.g. `example.com`) and serves requests under a
chosen path prefix from your local dev server — everything else reaches the live site
untouched. No `/etc/hosts`, no DNS tricks, no self-signed certificates on your dev
server.

You give `rexy` three things: the domain of a live site, a path prefix, and your dev
server URL. It starts the local proxy, generates a PAC file that routes only that domain
through it, and launches Chrome (or Chromium, or any browser executable). Then you just
browse the site as usual — the matching pages are transparently served from your local
build.

![How rexy works](docs/rexy-flow.svg)

## How it works

1. `./generate_ca.sh` generates a local certificate authority (one-time setup) in
   `ca/` — `rexy.cer` (the certificate) and `rexy.key` (its private key).
2. `rexy trust` installs that CA into your OS trust store, so the browser accepts the
   certificates the proxy issues on the fly.
3. On `rexy run`, the tool:
   - starts a [hudsucker](https://crates.io/crates/hudsucker) MITM proxy on
     `127.0.0.1` (a free port by default),
   - serves a PAC script that routes **only** the intercepted host (and its
     subdomains) through the proxy — everything else goes `DIRECT`, so messengers,
     WebRTC/STUN, long-poll and CDNs are unaffected,
   - launches the browser with `--proxy-pac-url=...` and `--disable-quic`,
   - rewrites matching requests: `https://<host><path>*` → `<target>` (matching uses the `host` header, falling back to the request URI authority so HTTP/2 requests, which have no `host` header, are matched too).
4. TLS interception is restricted to the intercepted host only.

Ctrl+C stops the browser and the proxy.

## Requirements

- OpenSSL (for `generate_ca.sh`)
- A browser: Chrome / Chromium / any Chromium-based executable, or Firefox
  (Firefox CA installation needs NSS `certutil` on PATH)

Supported platforms: **macOS**, **Windows**, **Linux**.

## Install

### Quick Install (recommended)

You can install `rexy` with a single command using the installer script.

**Linux / macOS:**
```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/sumbad/rexy/releases/latest/download/rexy-installer.sh | sh
```

**Windows:**
```bash
powershell -ExecutionPolicy Bypass -c "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; irm https://github.com/sumbad/rexy/releases/latest/download/rexy-installer.ps1 | iex"
```

### Manual Installation

Alternatively, you can install `rexy` by downloading a pre-compiled binary from the [**Releases page**](https://github.com/sumbad/rexy/releases).

1.  Download the appropriate archive for your system.
2.  Unpack the archive.
3.  Move the `kley` binary to a directory in your system's `PATH` (e.g., `/usr/local/bin` on macOS/Linux).

### Install via npm (Node.js)
If you have Node.js installed, you can install `rexy` directly from npm:

```bash
npm install -g rexy-cli
```

### Install via Cargo (crates.io)
If you have Rust and Cargo installed, you can install `rexy` directly from crates.io:

```bash
cargo install --locked rexy
```

Or build from source:

```sh
cargo install --path .
```

## Setup

```sh
# 1. Generate the local CA (one-time; creates ca/rexy.cer and ca/rexy.key)
./generate_ca.sh

# 2. Install the CA into the OS trust store
rexy trust
```

- **macOS** — installs into the login keychain via `security` (`trustRoot`, SSL policy)
- **Windows** — installs into the current-user `Root` store via `certutil`
- **Linux** — copies the certificate to
  `/usr/local/share/ca-certificates/local-dev-proxy.crt` and runs
  `update-ca-certificates` (via `pkexec`)

`rexy trust` is idempotent: re-running it after regenerating the CA replaces the old certificate. `rexy clean` removes the CA from the trust store.

### Firefox

Firefox does not read the OS trust store — it has its own NSS store:

```sh
rexy trust --firefox    # install the CA into every Firefox profile (needs certutil)
rexy clean --firefox    # remove it again
```

When rexy launches Firefox itself (`--browser firefox`), it imports the CA into the throwaway
session profile automatically (via the same `certutil`); without `certutil` on PATH rexy logs a
warning and the profile stays untrusted. Note for Windows: the required `certutil` is the one
from [NSS tools](https://wiki.mozilla.org/NSS) — the built-in Windows `certutil.exe` (System32)
will not work.

## Usage

Single rule via flags:

```
rexy run --host <host> --path <path> --target <url> -- <browser args>
```

Example serves an url from a local Vite dev server:

```sh
rexy run \
  --browser chrome \
  --host example.com \
  --path /app/ \
  --target http://127.0.0.1:5173 \
  -- --new-window https://example.com/app/foo
```

If the target server sends a restrictive `Content-Security-Policy` that breaks the proxied page (e.g. `frame-ancestors` blocks embedding it in a parent shell), override the header for responses served from the target:

```sh
rexy run \
  --browser chrome \
  --host example.com \
  --path / \
  --target https://dev.example.internal \
  --csp-override "frame-ancestors *" \
  -- --new-window https://app.example.com/
```

`--csp-override off` removes the header entirely. Only responses actually redirected to `--target` are affected; production passthrough traffic and `Content-Security-Policy-Report-Only` are never modified.

### Running an Electron app as the browser

`--browser` accepts any executable, including an Electron app — the typical superapp workflow is
to run the local shell through rexy instead of a plain browser:

```sh
rexy run   --browser /path/to/my-electron-app   --file rules.toml   -- --user-data-dir=/tmp/rexy-electron-profile --remote-debugging-port=9222      /path/to/my-electron-app --some-app-flag
```

- Everything after `--` is passed to the launched executable **as is** — rexy does not interpret
  it. That passthrough is what lets you give the Electron app its own arguments (app path,
  app flags, profile).
- The proxy settings (PAC URL and `--disable-quic`) are added by rexy itself; the app does not
  need to know about the proxy. The PAC-based routing works for Electron exactly like for
  Chrome, because Electron is Chromium.
- The CDP (remote debugging) port is an Electron/Chromium argument passed after `--`
  (`--remote-debugging-port=9222`), not a rexy option — rexy never talks to it itself, tools
  like `dev-workspace` connect to `127.0.0.1:9222` directly.
- A separate `--user-data-dir` is recommended: Chrome ≥136 does not enable remote debugging on
  the default profile, and an isolated profile keeps the session independent of your daily
  browser.

### Multiple rules via a config file

Pass `--file`/`-f` with a TOML file to intercept several hosts with one browser:

```toml
# rules.toml
[[rules]]
host = "app.example.com"
path = "/"
target = "https://dev-app.example.internal"
csp_override = "frame-ancestors *"   # optional; "off" removes the header
embed = true                         # optional; shed iframe blockers on target responses

[[rules]]
host = "pinned.example.com"
target = "http://127.0.0.1:3000"
intercept = false                    # optional; CONNECT-tunnel without decryption

[[rules]]
host = "static.example.com"
path = "/assets/"
target = "file:/Users/me/build/static"   # optional; Map Local
```

```sh
rexy run -f rules.toml
```

- `--file` cannot be combined with `--host`, `--path`, `--target` or `--csp-override` — those configure a single rule.
- `--browser`, `--proxy-port` and browser arguments after `--` stay on the command line.
- The first matching rule wins (host + path prefix).
- `host` may contain ASCII letters, digits, dots, dashes and underscores (punycode `xn--` labels
  are fine — underscores are common in internal DNS); IPv6 literals are not supported. Matching
  is exact-host (normalized: lowercased, port stripped), no subdomains.
- `intercept = false` tunnels the host as a CONNECT passthrough: rexy never decrypts or rewrites
  it — the escape hatch for pinned clients and MITM-unfriendly WAFs. `rexy rules check` skips
  such rules too, and they never trigger the shadowing warning.
- `embed = true` removes `X-Frame-Options` and the `Cross-Origin-Opener-Policy` /
  `Cross-Origin-Embedder-Policy` / `Cross-Origin-Resource-Policy` headers from responses served
  from that rule's target — for embedding the local page in an iframe of a parent shell
  (the typical iframe scenario is `embed = true` plus `csp_override = "off"`). Passthrough
  traffic is never modified. Defaults to `false`; single-rule CLI mode has no flag for it.
- Rule values support environment variable interpolation: `${VAR}`, `${VAR:-default}`, `$$` for
  a literal `$`. A bare `$VAR` is *not* interpolated, but a literal `${...}` in a value is —
  escape it with `$$` if you need it verbatim. An unset variable without a default is a load
  error naming the variable, the rule and the field.
- Rules are hot-reloaded: edits to the `--file` apply within a second, without restarting the
  proxy or the browser (`--no-hot-reload` disables the watcher). Limitation: adding or removing
  a host additionally needs the browser to re-read the PAC file — restart the browser session
  (or the browser) for new hosts; edits to `path`/`target`/`csp_override`/`embed` of hosts the
  browser already routes through the proxy apply immediately.
- If an earlier rule shadows a later one (same host, its path prefix covers the later rule's
  path — including duplicates), the load logs a warning naming both rules: the later rule can
  never fire for those paths. The warning goes to stderr and never fails the load — reorder the
  rules so the more specific path comes first.
- An empty `rules` list is allowed: rexy logs a warning and runs without redirects.

### Map Local: serve local files instead of a dev server

A rule with a `file:` target serves static files from a directory by the requested path — local
assets on top of prod without running a dev server. `csp_override` applies to these responses too:

```toml
[[rules]]
host = "app.example.com"
path = "/static/"
target = "file:/Users/me/build/static"
csp_override = "off"
```

- The full request path is appended to the target directory; the rule prefix is not stripped.
  For this example, `/static/app.js` resolves to `/Users/me/build/static/static/app.js`.
- Content-Type is derived from the file extension (html, js, css, json, images, fonts, wasm, …); unknown extensions are served as `application/octet-stream`.
- Missing files and directories answer `404` — no directory listing. `..` segments and symlink escapes are rejected with `403`. The query string is not part of the lookup.
- `GET` and `HEAD` are served; other methods answer `405`.
- Works in `--file` configs and with the single-rule `--target file:<dir>`.
- Out of scope by design: caching, directory listing, server-side includes.

### Checking rules offline

`rexy rules check` evaluates URLs against a rules file with the same matcher the proxy uses
(first-match-wins, host + path prefix, scheme optional) — a config sanity check for CI and
agent scripts, no proxy or browser required:

```sh
rexy rules check -f rules.toml https://app.example.com/api/v1/get
rexy rules check -f rules.toml --json https://app.example.com/api/v1/get app.example.com/
```

- Unmatched URLs are a normal result (exit code stays `0`); an invalid URL or a broken config
  file is an error.
- `--json` emits one JSON object per URL. Field names are the contract for scripts: `url`,
  `matched`, `rule_index` (0-based), `rule_host`, `rule_path`, `target`, `csp_override`
  (`"off"` or the policy string).
- Passthrough rules (`intercept = false`) never match — exactly like the proxy's request
  matching. Config warnings (shadowed rules) go to **stderr**, so the JSON on stdout stays
  machine-readable.

### Commands

| Command                  | Description                                                       |
| ------------------------ | ----------------------------------------------------------------- |
| `rexy run`               | Launch the browser through the local proxy                        |
| `rexy trust`             | Install the Rexy Local CA into the OS trust store                 |
| `rexy trust --firefox`   | Install the CA into Firefox profiles (NSS, via `certutil`)        |
| `rexy clean`             | Remove the Rexy Local CA from the OS trust store                  |
| `rexy clean --firefox`   | Remove the CA from Firefox profiles                               |
| `rexy rules check`       | Print which rule would match each URL (offline, same matcher)     |

### `run` options

| Option                     | Default    | Description                                                        |
| -------------------------- | ---------- | ------------------------------------------------------------------ |
| `--browser <name or path>` | `chrome`   | `chrome`, `chromium`, `firefox`, or a path to a browser executable |
| `--file <path>` (`-f`)     | —          | TOML file with `[[rules]]`; excludes `--host/--path/--target/--csp-override` |
| `--host <host>`            | —          | Production hostname to intercept (hostname only, no path/scheme)   |
| `--path <prefix>`          | `/`        | Production path prefix to redirect (must start with `/`)           |
| `--target <url>`           | —          | Local development server (`http://` or `https://`) or `file:<dir>` for [Map Local](#map-local-serve-local-files-instead-of-a-dev-server) |
| `--proxy-port <port>`      | `0`        | Local proxy port; `0` picks a free port                            |
| `--csp-override <policy\|off>` | —      | Replace all `Content-Security-Policy` headers of responses served from `--target` (`off` removes them); passthrough traffic is untouched |
| `--record <dir>`           | —          | Write intercepted exchanges into `<dir>/rexy-session.har` (HAR 1.2) |
| `--replay <file>`          | —          | Answer requests from a recorded HAR session; unmatched follow the rules |
| `--no-hot-reload`          | —          | Disable the rules file hot-reload watcher; rule edits need a restart |
| `-- <args>`                | —          | Extra arguments passed to the browser                              |

### Rules status page

While running, rexy serves a live status page — `http://127.0.0.1:8125/` by default (env
`REXY_STATUS_PORT`, `0` picks a free port, `off` disables the page). It shows the fate of every
intercepted connection and request: which rule matched (rule number → target), a replayed
fixture (`(replay)`), or why not (host not configured, no rule for the path), plus the response
status and round-trip duration. The "the rule did not match, silently" class of problems becomes
visible at a glance.

- `GET /` — HTML page with live updates (Server-Sent Events).
- `GET /events` — JSON array of the last 500 events, newest first — the feed for harness scripts.
- `GET /stream` — SSE stream of new and updated events.

If the port is busy, rexy logs a warning and runs without the page — the proxy itself is
unaffected. The server only answers requests whose `Host` is the local address it is bound to
(otherwise a DNS-rebinding page could read the feed).
### Record and replay (offline smoke runs)

`--record <dir>` writes every intercepted exchange into `<dir>/rexy-session.har` (HAR 1.2 — the
file opens in Chrome DevTools or mitmproxy); `--replay <file>` answers requests from a recorded
session without touching the network. The two flags are mutually exclusive.

```sh
# run the smoke once, against prod/local targets, recording everything
rexy run --record /tmp/smoke-1 -f rules.toml --browser chromium

# later: the same smoke fully offline — responses come from the fixtures
rexy run --replay /tmp/smoke-1/rexy-session.har -f rules.toml --browser chromium
```

- Replay matches by method + URL: the exact URL first, then the URL without the query string —
  cache-busting parameters do not break the replay. Unmatched requests follow the usual rules
  (redirect targets or passthrough).
- Bodies are stored base64-encoded, so binary responses survive; recorded response headers —
  cookies included — are replayed as-is, and rule edits (`csp_override`, `embed`) are **not**
  applied to replayed responses: the recording is served exactly as captured.
- Recording buffers response bodies — the whole session (bodies included) stays in memory while
  rexy runs, so streaming responses (SSE, long-poll) are not suitable for recording.
- The HAR file is flushed continuously while the session is small and every 25th exchange after
  that; Ctrl+C always writes the complete session, a hard kill can lose the last few exchanges.
- Recording covers every request that reaches the proxy on intercepted hosts — redirected to a
  target, served from a `file:` target, or passing through within those hosts. Traffic rexy never
  sees (PAC `DIRECT`) is not recorded, so offline replay works for the intercepted hosts, not for
  the whole browser session.

### Logging

Logging is controlled by `RUST_LOG` (via `tracing-subscriber`), e.g.:

```sh
RUST_LOG=debug rexy run ...
```

### Environment variables

| Variable       | Default | Description                                                                                       |
| -------------- | ------- | ------------------------------------------------------------------------------------------------- |
| `RUST_LOG`     | —       | `tracing` log filter (see [Logging](#logging))                                                      |
| `REXY_STATUS_PORT` | `8125`  | Port of the live [rules status page](#rules-status-page); `0` picks a free port, `off` disables the page entirely. If the port is busy, rexy runs without the page. |
| `REXY_PAC_ALL` | unset   | When `1`, the PAC routes **every** host through the proxy (not just intercepted ones). Diagnostic escape hatch: it defeats the `DIRECT` optimization so traffic the browser would otherwise keep on a direct connection (e.g. HTTP/2 long-polls) becomes interceptable. WebRTC/media may break while it is on; rexy logs a warning at startup. |

## Security notes

- `ca/rexy.key` is the private key of your local CA. It never leaves your machine and must **never** be committed.
- The CA is scoped to this machine's development use. Regenerate it if it may have leaked, then re-run `rexy trust`.
- Only traffic to the hosts you explicitly configure (via `--host` or rules in `--file`) is intercepted and decrypted.
- `--record` writes the HAR file in **plaintext**: it contains request and response headers —
  cookies and `Authorization` included — plus response bodies. Keep the record directory private
  and delete it after the smoke run (rexy logs a reminder at startup).

## License

Licensed under the [MIT License](LICENSE).
