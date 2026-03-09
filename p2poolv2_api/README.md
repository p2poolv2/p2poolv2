# p2poolv2_api

HTTP API server for P2Pool v2. Built with [Axum](https://docs.rs/axum)
and exposes pool state over a REST-like JSON interface.

## Starting the server

The API server is started automatically by the main `p2poolv2` node
process. It binds to the hostname and port specified in the `[api]`
section of the configuration file.

## Authentication

All REST endpoints are protected by optional HTTP Basic authentication.
When `auth_user` and `auth_token` are set in the `[api]` config
section, every request must include a valid `Authorization: Basic
<base64(user:password)>` header. If no credentials are configured,
all endpoints are accessible without authentication.

The WebSocket endpoint (`/ws`) uses a query parameter for
authentication instead of the `Authorization` header. Pass
`?token=<base64(user:password)>` when connecting. Make sure the token
value is URL-encoded (percent-encoded) so that characters like `+`,
`/`, and `=` are transmitted correctly. If no credentials are
configured on the server, the token parameter is not required.

Use the `p2poolv2_cli gen-auth` command to generate a salted HMAC
token suitable for the config file.

## Endpoints

- [GET /dashboard](#get-dashboard) -- Monitoring dashboard (no auth required)
- [GET /health](#get-health) -- Liveness check
- [GET /metrics](#get-metrics) -- Pool metrics in Prometheus format
- [GET /chain_info](#get-chain_info) -- Share chain state
- [GET /shares](#get-shares) -- Confirmed shares by height range
- [GET /candidates](#get-candidates) -- Candidate shares by height range
- [GET /share](#get-share) -- Look up a share by hash or height
- [GET /peers](#get-peers) -- Connected peers
- [GET /pplns_shares](#get-pplns_shares) -- PPLNS accounting data
- [WebSocket /ws](#websocket-ws) -- Real-time event subscriptions

### GET /dashboard

Serves a static monitoring dashboard page built with Pico CSS and
Alpine.js. The page prompts for username/password and authenticates
against the API using HTTP Basic auth. On successful login it displays
chain state information from `/chain_info`. This route is served
without auth middleware since the page handles authentication
client-side.

### GET /health

Returns `"OK"`. Useful for liveness checks.

### GET /metrics

Returns pool metrics in Prometheus/Grafana exposition format. Includes
the current coinbase reward distribution when a job is active.

### GET /chain_info

Returns information about the current share chain state.

**Response fields:**

| Field                      | Type            | Description                                 |
|----------------------------|-----------------|---------------------------------------------|
| `genesis_blockhash`        | `string\|null`  | Blockhash of the genesis share              |
| `chain_tip_height`         | `number\|null`  | Height of the confirmed chain tip           |
| `total_work`               | `string`        | Total accumulated work (hex)                |
| `chain_tip_blockhash`      | `string\|null`  | Blockhash of the confirmed chain tip        |
| `top_candidate_height`     | `number\|null`  | Height of the highest candidate share       |
| `top_candidate_blockhash`  | `string\|null`  | Blockhash of the highest candidate share    |

### GET /shares

Returns confirmed shares and their uncles blockhashes for a height range.

**Query parameters:**

| Parameter | Type     | Default    | Description                                       |
|-----------|----------|------------|---------------------------------------------------|
| `to`      | `number` | chain tip  | Height to query up to (inclusive)                  |
| `num`     | `number` | 10         | Number of shares going back from `to` (max 1000)  |

**Response fields:**

| Field         | Type     | Description                  |
|---------------|----------|------------------------------|
| `from_height` | `number` | Start of the returned range  |
| `to_height`   | `number` | End of the returned range    |
| `shares`      | `array`  | List of share objects        |

Each share object contains: `blockhash`, `prev_blockhash`, `height`,
`miner_pubkey`, `timestamp`, `bits`, and an `uncles` array of uncle
objects (each with `blockhash`, `prev_blockhash`, `miner_pubkey`,
`timestamp`, `height`).

### GET /candidates

Returns candidate (unconfirmed) shares and their uncle blockhashes for
a height range. Same query parameters and response shape as `/shares`,
but operates on the candidate chain.

### GET /share

Look up a single share by blockhash or by height.

**Query parameters (exactly one required):**

| Parameter | Type      | Description                                      |
|-----------|-----------|--------------------------------------------------|
| `hash`    | `string`  | Full blockhash of the share                      |
| `height`  | `number`  | Height to look up (returns all shares at height) |
| `full`    | `boolean` | Include full transaction list (default false)     |

**Response:** JSON array of share detail objects. Each object includes:

| Field                       | Type            | Description                               |
|-----------------------------|-----------------|-------------------------------------------|
| `blockhash`                 | `string`        | Share blockhash                           |
| `height`                    | `number\|null`  | Share height                              |
| `status`                    | `string`        | Validation status of the share            |
| `parent`                    | `string`        | Parent share blockhash                    |
| `uncles`                    | `array`         | Uncle blockhashes                         |
| `miner_pubkey`              | `string`        | Miner public key                          |
| `merkle_root`               | `string`        | Share merkle root                         |
| `bits`                      | `string`        | Compact target (hex)                      |
| `time`                      | `string`        | Human-readable timestamp                  |
| `bitcoin_header`            | `object`        | Embedded Bitcoin block header             |
| `bitcoin_transaction_count` | `number`        | Number of Bitcoin transactions            |
| `transactions`              | `array\|null`   | Transaction IDs (only when `full=true`)   |

### GET /peers

Returns the list of currently connected peers.

**Response:** JSON array of objects with a `peer_id` string field.

### GET /pplns_shares

Returns PPLNS (Pay Per Last N Shares) accounting data with optional
time filtering.

**Query parameters:**

| Parameter    | Type     | Default       | Description                                  |
|--------------|----------|---------------|----------------------------------------------|
| `limit`      | `number` | 100           | Max shares to return (1-1000)                |
| `start_time` | `string` | epoch (0)     | RFC 3339 timestamp for range start           |
| `end_time`   | `string` | current time  | RFC 3339 timestamp for range end             |

### WebSocket /ws

Real-time push notifications for share chain events, new shares, and
peer connectivity changes. Clients subscribe to topics and receive
JSON messages as events occur.

**Authentication:** When auth is configured, pass credentials as a
query parameter: `ws://host:port/ws?token=<base64(user:password)>`.
Returns HTTP 401 if credentials are missing or invalid.

**Subscription protocol:**

Clients send JSON messages to subscribe or unsubscribe from topics:

```json
{"action": "subscribe", "topic": "shares"}
{"action": "subscribe", "topic": "peers"}
{"action": "unsubscribe", "topic": "shares"}
```

**Available topics:**

| Topic    | Description                                      |
|----------|--------------------------------------------------|
| `shares` | New confirmed shares (includes uncle blockhashes)|
| `peers`  | Peer connection and disconnection events         |

Chain state information is available via the `/chain_info` REST
endpoint. Clients can derive chain tip updates from share events.

**Server-to-client messages:**

Events are delivered as JSON with `topic` and `data` fields:

```json
{"topic": "Share", "data": {"blockhash": "00000...", "prev_blockhash": "00000...", "height": 42, "miner_pubkey": "02aa...", "timestamp": 1700000000, "bits": "1d00ffff", "uncles": [<json uncle info>]}}
{"topic": "Peer", "data": {"peer_id": "12D3KooW...", "status": "Connected"}}
```

Note: Share events in the WebSocket stream carry uncle blockhashes
(strings), not full uncle objects. Use previously received Uncle
events to look up full details for each blockhash. The REST
`/shares` and `/candidates` endpoints return full uncle objects.

**Example with websocat (no auth):**

```sh
# Connect and subscribe to shares
websocat ws://127.0.0.1:46884/ws
> {"action": "subscribe", "topic": "shares"}
< {"topic":"Share","data":{"blockhash":"00000...","height":42,...}}
```

**Example with websocat (with auth):**

```sh
# Encode credentials as base64
TOKEN=$(echo -n "admin:mypassword" | base64)

# Connect with token
websocat "ws://127.0.0.1:46884/ws?token=${TOKEN}"
> {"action": "subscribe", "topic": "peers"}
< {"topic":"Peer","data":{"peer_id":"12D3KooW...","status":"Connected"}}
```

**Example subscribing to multiple topics:**

```sh
websocat ws://127.0.0.1:46884/ws
> {"action": "subscribe", "topic": "shares"}
> {"action": "subscribe", "topic": "peers"}
```

## Error responses

All endpoints return errors as JSON with an `error` field:

```json
{"error": "description of the problem"}
```

HTTP status codes used:

- `400` -- Bad request (invalid parameters)
- `404` -- Resource not found
- `401` -- Unauthorized (missing or invalid credentials)
- `500` -- Internal server error

## CLI access

The `p2poolv2_cli` crate provides convenience command-line access to
these API endpoints. It reads the same config file as the node to
determine the API address and credentials.

Available CLI commands:

| Command        | API Endpoint    | Description                              |
|----------------|-----------------|------------------------------------------|
| `info`         | `/chain_info`   | Display chain state information          |
| `shares`       | `/shares`       | List confirmed shares in a height range  |
| `candidates`   | `/candidates`   | List candidate shares in a height range  |
| `share`        | `/share`        | Look up a share by hash or height        |
| `pplns-shares` | `/pplns_shares` | Get PPLNS accounting shares              |
| `peers-info`   | `/peers`        | Show connected peers                     |
| `gen-auth`     | (local)         | Generate API auth credentials            |

Example usage:

```sh
p2poolv2_cli --config config.toml info
p2poolv2_cli --config config.toml shares --num 20
p2poolv2_cli --config config.toml share --height 42
```
