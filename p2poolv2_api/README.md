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
- [GET /found_blocks](#get-found_blocks) -- Bitcoin blocks found by the pool
- [GET /share_headers](#get-share_headers) -- Raw share headers by height range
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
| `num`     | `number` | 10         | Number of shares going back from `to` (max 100)   |

**Response fields:**

| Field         | Type     | Description                  |
|---------------|----------|------------------------------|
| `from_height` | `number` | Start of the returned range  |
| `to_height`   | `number` | End of the returned range    |
| `shares`      | `array`  | List of share objects        |

Each share object contains: `blockhash`, `prev_blockhash`, `height`,
`miner_address`, `timestamp`, `bits`, and an `uncles` array of uncle
objects (each with `blockhash`, `prev_blockhash`, `miner_address`,
`timestamp`, `height`).

### GET /candidates

Returns candidate (unconfirmed) shares and their uncle blockhashes for
a height range. Same query parameters and response shape as `/shares`,
but operates on the candidate chain.

### GET /found_blocks

Returns the most recent bitcoin blocks found by the pool, highest
bitcoin height first. A block is recorded when the share carrying it
is confirmed and is never removed, so the list can include blocks
since orphaned on the bitcoin chain.

**Query parameters:**

| Parameter | Type     | Default | Description                                   |
|-----------|----------|---------|-----------------------------------------------|
| `num`     | `number` | 10      | Number of most recent found blocks (max 100)  |

**Response fields:**

| Field          | Type     | Description                                        |
|----------------|----------|----------------------------------------------------|
| `network`      | `string` | Bitcoin chain name as bitcoind spells it           |
| `total`        | `number` | Total number of bitcoin blocks found by the pool, counted up to 1000 |
| `total_capped` | `bool`   | True when more than 1000 blocks exist, so `total` is a lower bound |
| `found_blocks` | `array`  | List of found block objects                        |

Each found block object contains: `bitcoin_height`,
`bitcoin_blockhash`, `share_blockhash`, `bitcoin_time` (bitcoin header
time, unix seconds) and `miner_bitcoin_address`.

### GET /share

Look up a single share by blockhash or by height.

**Query parameters (exactly one required):**

| Parameter | Type      | Description                                      |
|-----------|-----------|--------------------------------------------------|
| `hash`    | `string`  | Full blockhash of the share                      |
| `height`  | `number`  | Height to look up (returns all shares at height) |
| `full`    | `boolean` | Include full transaction list (default false)     |

**Response:** JSON array of share detail objects. Each object includes:

| Field                            | Type           | Description                                                        |
|----------------------------------|----------------|--------------------------------------------------------------------|
| `blockhash`                      | `string`       | Share blockhash                                                    |
| `height`                         | `number\|null` | Share height                                                       |
| `validation_status`              | `string`       | `Pending`, `HeaderValid`, `Invalid`, `BlockValid` or `Unknown`     |
| `chain`                          | `string`       | `None`, `Candidate`, `Confirmed` or `Unknown`                      |
| `parent`                         | `string`       | Parent share blockhash                                             |
| `uncles`                         | `array`        | Uncle blockhashes                                                  |
| `miner_bitcoin_address`          | `string`       | Bitcoin address receiving the miner's PPLNS payout                 |
| `miner_address`                  | `string`       | Share chain address owning the share coinbase output               |
| `share_witness_root`             | `string`       | Share witness root committed in the coinbase proof                 |
| `bits`                           | `string`       | Compact share target (hex)                                         |
| `time`                           | `number`       | Share time, unix seconds                                           |
| `bitcoin_header`                 | `object`       | Embedded bitcoin block header (see below)                          |
| `template_merkle_branches_count` | `number`       | Depth of the template merkle branch path                           |
| `transactions`                   | `array`        | Transaction IDs; only present when `full=true` and not pruned      |
| `pruned`                         | `boolean`      | Only present, as `true`, when `full=true` and the body was pruned  |

`bitcoin_header` contains `block_hash`, `version`, `prev_blockhash`,
`merkle_root`, `time` (unix seconds), `bits` (hex) and `nonce`.

### GET /share_headers

Returns raw share headers for a confirmed height range, ordered
ascending by height. Unlike `/shares`, this returns the raw
`ShareHeader` structure and can optionally include share block
transactions.

**Query parameters:**

| Parameter                  | Type      | Default    | Description                                           |
|----------------------------|-----------|------------|-------------------------------------------------------|
| `to`                       | `number`  | chain tip  | Height to query up to (inclusive)                      |
| `num`                      | `number`  | 10         | Number of headers going back from `to` (max 100)      |
| `share_block_transactions` | `boolean` | false      | Include share block transactions in the response       |

**Response fields:**

| Field         | Type     | Description                           |
|---------------|----------|---------------------------------------|
| `from_height` | `number` | Start of the returned range           |
| `to_height`   | `number` | End of the returned range             |
| `headers`     | `array`  | List of share header entry objects    |

Each header entry contains the flattened `ShareHeader` fields and an
optional `transactions` array (present only when
`share_block_transactions=true`).

### GET /peers

Returns the list of currently connected peers.

**Response:** JSON array of objects with a `peer_id` string field.

### GET /pplns_shares

Returns PPLNS (Pay Per Last N Shares) accounting data with optional
time filtering.

**Query parameters:**

| Parameter    | Type     | Default       | Description                                  |
|--------------|----------|---------------|----------------------------------------------|
| `limit`      | `number` | 100           | Max shares to return (1-100)                 |
| `start_time` | `number` | epoch (0)     | Unix seconds for range start                 |
| `end_time`   | `number` | current time  | Unix seconds for range end                   |

Example: `/pplns_shares?start_time=1760730000&end_time=1760730600&limit=10`

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
{"topic": "Share", "data": {"blockhash": "00000...", "prev_blockhash": "00000...", "height": 42, "miner_address": "02aa...", "timestamp": 1700000000, "bits": "1d00ffff", "uncles": [<json uncle info>]}}
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

| Command         | API Endpoint      | Description                                     |
|-----------------|-------------------|-------------------------------------------------|
| `info`          | `/chain_info`     | Display chain state information                 |
| `shares`        | `/share_headers`  | Dump share headers (optionally with transactions)|
| `candidates`    | `/candidates`     | List candidate shares in a height range         |
| `share`         | `/share`          | Look up a share by hash or height               |
| `pplns-shares`  | `/pplns_shares`   | Get PPLNS accounting shares                     |
| `peers-info`    | `/peers`          | Show connected peers                            |
| `gen-auth`      | (local)           | Generate API auth credentials                   |

Example usage:

```sh
p2poolv2_cli --config config.toml info
p2poolv2_cli --config config.toml shares --num 20
p2poolv2_cli --config config.toml shares --num 5 --share-block-transactions
p2poolv2_cli --config config.toml share --height 42
```
