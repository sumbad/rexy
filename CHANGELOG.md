# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-09-02

### Added

- **`rexy run` command**: Launches a Chromium-based browser through a local MITM proxy.
- **Selective PAC routing**: A PAC script routes only the intercepted host and its subdomains through the proxy; all other traffic stays `DIRECT`, so WebRTC calls, CDNs and messengers are unaffected.
- **Browser resolution**: `--browser` accepts `chrome`, `chromium`, or a custom executable path.
- **`rexy trust` / `rexy clean` commands**: Install/remove the Rexy Local CA in the OS trust store on macOS, Windows, and Linux.
- **`generate_ca.sh` script**: One-time local CA generation (EC P-256).
- **`--csp-override` option for `rexy run`**: Replaces all `Content-Security-Policy` headers of responses served from `--target` with the given policy (`off` removes the header entirely).
