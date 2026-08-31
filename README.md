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
   - rewrites matching requests: `https://<host><path>*` → `<target>`.
4. TLS interception is restricted to the intercepted host only.

Ctrl+C stops the browser and the proxy.

## Requirements

- OpenSSL (for `generate_ca.sh`)
- A Chromium-based browser (Chrome / Chromium / any executable path)

Supported platforms: **macOS**, **Windows**, **Linux**.

## Install

Once the first version is released, install from [GitHub Releases](https://github.com/sumbad/rexy/releases):

```sh
# Cargo (crates.io)
cargo install --locked rexy

# npm
npm install -g rexy

# Shell (macOS / Linux)
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/sumbad/rexy/releases/latest/download/rexy-installer.sh | sh

# PowerShell (Windows)
irm https://github.com/sumbad/rexy/releases/latest/download/rexy-installer.ps1 | iex
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

`rexy trust` is idempotent: re-running it after regenerating the CA replaces the old
certificate. `rexy clean` removes the CA from the trust store.

## Usage

```
rexy run --host <host> --path <path> --target <url> -- <browser args>
```

Example — serve the production mini-app from a local Vite dev server:

```sh
rexy run \
  --browser chrome \
  --host superapp.example.com \
  --path /mini-app/ \
  --target http://127.0.0.1:5173 \
  -- --new-window https://superapp.example.com/mini-app/foo
```

### Commands

| Command       | Description                                        |
| ------------- | -------------------------------------------------- |
| `rexy run`    | Launch the browser through the local proxy         |
| `rexy trust`  | Install the Rexy Local CA into the OS trust store  |
| `rexy clean`  | Remove the Rexy Local CA from the OS trust store   |

### `run` options

| Option                     | Default    | Description                                                        |
| -------------------------- | ---------- | ------------------------------------------------------------------ |
| `--browser <name or path>` | `chrome`   | `chrome`, `chromium`, or a path to a browser executable            |
| `--host <host>`            | —          | Production hostname to intercept (hostname only, no path/scheme)   |
| `--path <prefix>`          | `/`        | Production path prefix to redirect (must start with `/`)           |
| `--target <url>`           | —          | Local development server (`http://` or `https://`)                 |
| `--proxy-port <port>`      | `0`        | Local proxy port; `0` picks a free port                            |
| `-- <args>`                | —          | Extra arguments passed to the browser                              |

### Logging

Logging is controlled by `RUST_LOG` (via `tracing-subscriber`), e.g.:

```sh
RUST_LOG=debug rexy run ...
```

## Security notes

- `ca/rexy.key` is the private key of your local CA. It never leaves your machine and
  must **never** be committed — the repo's `.gitignore` already excludes `ca/`.
- The CA is scoped to this machine's development use. Regenerate it if it may have
  leaked, then re-run `rexy trust`.
- Only traffic to the `--host` you explicitly pass is intercepted and decrypted.

## License

Licensed under the [MIT License](LICENSE).
