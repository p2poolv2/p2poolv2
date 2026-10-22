# p2poolv2_web

An interactive dashboard for a P2Poolv2 node, written in Rust with
[Leptos](https://leptos.dev) (client-side rendering) and compiled to
WebAssembly. There is no hand-written JavaScript; the only JavaScript is the
loader `wasm-bindgen` generates, and the only CSS is `style.css`.

It shows live pool, local and network hashrate, the share chain height, a
zoomable hashrate chart, recent shares (live over `/ws`), found blocks, share
details and a miner lookup.

## Why Leptos

Leptos CSR has fine-grained signals, so a live share arriving over the
WebSocket updates one table row instead of re-rendering the page, and SVG
charts are plain `view!` markup. It builds with `trunk` to a single static
bundle (~800 kB wasm) that any web server can host. Dioxus web would also
work; Leptos was chosen for the smaller runtime and the mature trunk path.

## Data

Everything comes from the node's JSON API. Numbers are computed in the node,
not the browser:

| Endpoint | Used for |
|---|---|
| `/hashrate?window=` | KPIs and chart, from the node's once-a-minute hashrate history (the same one `/dashboard` draws): pool from share chain work, local from accepted stratum difficulty, network from template difficulty |
| `/chain_info` | share chain height |
| `/shares?num=`, `/ws` (topic `shares`) | recent shares, then live updates |
| `/found_blocks` | found blocks |
| `/share?hash=` | share detail |
| `/miner?address=` | miner lookup |

## Build

```bash
rustup target add wasm32-unknown-unknown
cargo install trunk --locked
cd p2poolv2_web
trunk build --release
```

The assets land in `p2poolv2_web/dist`, built to be served from `/`.

## Serve from the node

Point the node's `web_root` at the built directory and restart it:

```toml
[api]
web_root = "/path/to/p2poolv2_web/dist"
```

The app is then at `http://<api hostname>:<api port>/`; the node serves the
folder for every path its API does not use. With `public_dashboard = true`
the app and the share chain routes it reads open without a login. Otherwise
the API calls need the credentials from `auth_user` and `auth_token`. Enter them under **Settings**; the user and API URL are
remembered in local storage, the password only for the browser tab.

## Serve it elsewhere

Any static file server works. Build for its path, for example
`trunk build --release --public-url /p2pool/`, and set the node's API URL in
Settings or with `?api=https://node.example:46884` in the page URL. The node
must then allow the page's origin: set `cors_allowed = true` under `[api]`.

## Develop

`trunk serve --config Trunk.dev.toml` serves on http://127.0.0.1:8080/ and
proxies the API paths to a node on `127.0.0.1:46884`, so no CORS setup is
needed. Unit tests for the formatting, chart geometry and API parsing run
natively with `cargo test -p p2poolv2_web`.
