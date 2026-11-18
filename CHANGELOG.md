# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **Live rules status page**: while running, rexy serves `http://127.0.0.1:8125/` (env `REXY_STATUS_PORT`, `0` = free port, `off` = disable the page) with the fate of every intercepted connection and request — matched rule → target or miss with the reason (host not configured, no rule for the path), response status and duration. HTML page with SSE for humans, `GET /events` JSON feed (last 500 events) for harness scripts.
- **Record and replay (`--record <dir>` / `--replay <file>`)**: intercepted exchanges are written to a HAR 1.2 file; a replay answers requests from the recording without the network — offline smoke runs. Matching is by method + URL (exact, then query-free), unmatched requests follow the usual rules; bodies are base64-encoded, headers replayed as-is.
- **`REXY_PAC_ALL=1` env for `rexy run`**: routes *every* host through the proxy instead of only the intercepted ones (PAC returns `PROXY` unconditionally). Diagnostic-only escape hatch — it defeats the `DIRECT` optimization so traffic the browser would otherwise keep on a direct connection becomes interceptable (e.g. HTTP/2 long-polls). WebRTC/media may break while it is on.
- **`rexy rules check`**: offline rule evaluation from CI and agent scripts — the same matcher the proxy uses, human-readable text or `--json` (one object per URL; field names are the contract). Unmatched URLs are a normal result; an invalid URL or config file is an error. Config warnings go to stderr, so the JSON on stdout stays machine-readable.
- **Shadowed-rule warning**: an earlier rule that makes a later one unreachable (same host, path prefix covers it — duplicates included) logs a warning naming both rules on every config load. Passthrough rules (`intercept = false`) never shadow anything.
- **Environment interpolation in rule values**: `${VAR}` and `${VAR:-default}` (bash `:-` semantics), `$$` for a literal `$`; a bare `$VAR` is not interpolated (see Changed). An unset variable without a default is a load error naming the variable, the rule and the field.
- **`intercept = false` per rule**: CONNECT-tunnel the host without decryption — the escape hatch for pinned clients and MITM-unfriendly WAFs. The proxy never rewrites such a host; `rules check` treats it the same way.
- **`embed = true` per rule**: sheds `X-Frame-Options` / COOP / COEP / CORP on responses served from that rule's target — for embedding the local page in an iframe of a parent shell (the typical scenario is `embed = true` plus `csp_override = "off"`).
- **Map Local (`target = "file:<dir>"`)**: serve static files from a directory by the requested path — local assets on top of prod without a dev server. Content-Type by file extension, `..` segments and symlink escapes rejected with `403`, `GET`/`HEAD` only, `csp_override` applies.
- **Firefox support**: `rexy trust --firefox` / `rexy clean --firefox` manage the CA in Firefox's NSS profiles (via `certutil`); `--browser firefox` launches a throwaway proxy profile with the CA imported automatically (warns with an install hint when `certutil` is missing — on Windows that is the NSS `certutil.exe`; the built-in Windows certutil will not work).
- **Rules hot-reload**: the rules file is watched and edits apply within a second without restarting the proxy or the browser; the PAC is regenerated when the host list changes. `--no-hot-reload` disables the watcher. Adding or removing a host additionally needs the browser to re-read the PAC (restart the session); `path`/`target`/`csp_override`/`embed` edits of already-proxied hosts apply immediately.
- **HTTP/2 end-to-end**: the upstream connection negotiates h2 via ALPN, so prod pages living on h2 (multiplexing, long-poll) work through the proxy. HTTP/3/QUIC stays off — the browser is launched with `--disable-quic`.

### Changed

- **Literal `${...}` in rule values is now interpolated** (see Added): an unset variable without a default is a load error; escape literal dollars with `$$`.
- **The status server and the rules hot-reload watcher are enabled by default**: `REXY_STATUS_PORT=off` disables the status page, `--no-hot-reload` disables the watcher.

### Fixed

- **Rule matching missed HTTP/2 requests**: rules matched on the `host` header only, which HTTP/2 requests don't carry (they use the `:authority` pseudo-header). Such requests were never redirected and silently went to prod. Matching now falls back to the request URI host when the `host` header is absent.
- **Windows: the Firefox CA import resolved `certutil` to the built-in Windows certutil.exe**: System32 is always on PATH and CreateProcess prefers it for the bare `certutil` name even when the NSS tools come later, so `clean --firefox` printed a false success and `trust --firefox` failed cryptically. The NSS `certutil.exe` is now looked up only outside the Windows system directories and invoked by its resolved absolute path; without the NSS tools rexy reports the install hint.
- **Underscore hosts were rejected by the config validation** introduced in this release: hosts like `my_host.internal` (common in internal DNS) used to load and match; an underscore is inert in the generated PAC script and is allowed again. IPv6 literals stay unsupported and the error text says so.
- **The status page refused legitimate `Host` headers**: `LocalHost:8125`, trailing root dots (`localhost.`, `localhost:8125.`), an empty port (`localhost:`) and the port-less `Host: localhost` (curl on the default port) got 403. The check now parses host:port case-insensitively and treats an omitted or empty port as the bound one; bracketed/bare IPv6 and out-of-range ports are still refused.
- **The SSE stream could duplicate or lose events after a broadcast lag**: the lagged catch-up now drains the notifications the subscriber still retains and re-sends them after the older ring events, bounded so events recorded during the catch-up arrive once through the live channel — no losses and no duplicates for new events; ids ascend except when a burst races the catch-up (the client page keys its rows by id, so ordering hiccups still render correctly; in-place response updates re-notify an id on purpose).
- **A session killed mid-flush left `rexy-session.har.<pid>.tmp` orphans** in the record directory; the next `--record` session cleans them up.
- **The throwaway Firefox profile directory had a pid-only predictable name** while certutil writes `cert9.db` into it; it is now created exclusively under a pid+nanosecond name, and a pre-planted path is never reused.

## [0.2.0] - 2026-09-03

### Added

- **`--file` option for `rexy run`**: TOML rules file for multi-host redirects — several `host/path/target` rules with per-rule `csp_override` in one browser session. Excludes `--host/--path/--target/--csp-override`; an empty rules list logs a warning and runs without redirects.

### Fixed

- **CSP override was never applied**: request→response correlation state leaked through per-request handler clones (hudsucker reuses the CONNECT-phase instance as the clone source), so the override header silently stayed the target's original one. Correlation now uses overwrite semantics; a regression test emulates the clone chain.
- **Upstream TLS now trusts the OS certificate store** instead of only the bundled webpki roots — `https://` targets with internal or mkcert CAs no longer fail with `invalid peer certificate: UnknownIssuer`. Hostname validation is unchanged: the target hostname must match the certificate SANs.

## [0.1.0] - 2026-09-02

### Added

- **`rexy run` command**: Launches a Chromium-based browser through a local MITM proxy.
- **Selective PAC routing**: A PAC script routes only the intercepted host and its subdomains through the proxy; all other traffic stays `DIRECT`, so WebRTC calls, CDNs and messengers are unaffected.
- **Browser resolution**: `--browser` accepts `chrome`, `chromium`, or a custom executable path.
- **`rexy trust` / `rexy clean` commands**: Install/remove the Rexy Local CA in the OS trust store on macOS, Windows, and Linux.
- **`generate_ca.sh` script**: One-time local CA generation (EC P-256).
- **`--csp-override` option for `rexy run`**: Replaces all `Content-Security-Policy` headers of responses served from `--target` with the given policy (`off` removes the header entirely).
