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
- [GET /share_headers](#get-share_headers) -- Raw share headers by height range
- [GET /miner](#get-miner) -- One miner's shares and weight in the PPLNS window
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
| `miner_address`             | `string`        | Miner bitcoin address                     |
| `merkle_root`               | `string`        | Share merkle root                         |
| `bits`                      | `string`        | Compact target (hex)                      |
| `time`                      | `string`        | Human-readable timestamp                  |
| `bitcoin_header`            | `object`        | Embedded Bitcoin block header             |
| `template_merkle_branches_count` | `number`   | Depth of the template merkle branch path  |
| `transactions`              | `array\|null`   | Transaction IDs (only when `full=true`)   |

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

### GET /miner

Returns one miner's shares and weight in the share chain PPLNS window, so
a share chain explorer or miner software can show a miner's standing
without indexing the chain itself.

The window is the one the next share this node mines would pay: anchored
on the share it mines on, minus the shares not yet mature for payout, then
`PPLNS_WINDOW_SHARES` shares (see
`docs/architecture/payout-distribution.md`). It is walked and weighted by
the same `PplnsWindow` code that builds and validates coinbases, so the
numbers are the payout's own.

**Query parameters:**

| Parameter | Type     | Default | Description                                         |
|-----------|----------|---------|-----------------------------------------------------|
| `address` | `string` | --      | Payout address or share chain address (required)    |
| `limit`   | `number` | 100     | Max shares listed, newest first (1-100)             |

`address` is either of the two addresses a share header carries; neither
is derived from the other:

- **Payout address** (`miner_bitcoin_address`), which receives the
  coinbase payout. On Bitcoin Cash a CashAddr for the node's network, with
  or without its `bitcoincash:`, `bchtest:` or `bchreg:` prefix. On Bitcoin
  a Bitcoin address for the node's network.
- **Share chain address** (`miner_address`), which owns the share. On
  Bitcoin Cash `p2pool:`, `tp2pool:` or `rp2pool:`; on Bitcoin the bech32m
  `p2pool1`, `tp2pool1`, `sp2pool1` or `rp2pool1` form. Its shares' weight
  is paid to the payout address each share names, shown per share.

An address with nothing in the window gets zero counts and an empty
`shares` list, not an error.

**Response fields:**

| Field             | Type     | Description                                                       |
|-------------------|----------|-------------------------------------------------------------------|
| `address`         | `string` | The queried address as this node spells it (CashAddr with prefix) |
| `address_type`    | `string` | `payout` or `share`                                               |
| `anchor`          | `string` | Share the window is anchored on (the share this node mines on)    |
| `anchor_height`   | `number` | Height of the anchor                                              |
| `window`          | `object` | `newest_height`, `oldest_height`, `share_count` and `weight` of the whole window |
| `share_count`     | `number` | Window shares this address mined                                  |
| `uncle_count`     | `number` | Uncles this address mined that window shares include              |
| `weight`          | `string` | This address's summed weight                                      |
| `share_fraction`  | `number` | `share_count` / `window.share_count`: its share of the window     |
| `payout_fraction` | `number` | `weight` / `window.weight`: its fraction of the next block's PPLNS payout |
| `shares`          | `array`  | Shares and uncles it earns weight from, newest first, at most `limit` |

Each `shares` entry has `blockhash`, `height` (an uncle is credited at the
height of the share that includes it), `nephew` (that share's blockhash, or
`null` for a window share), `difficulty`, `weight` and `payout_address`.

Weights are difficulty weights in the payout's scaled units: a share earns
10 times its difficulty plus 1 times the difficulty of each uncle it
includes, an uncle 9 times its own. Weights and difficulties are decimal
strings because a window's total exceeds what a JSON number carries
exactly in most clients.

`payout_fraction` is a fraction of the PPLNS payout, which is the coinbase
less the donation and fee set in the header of the share that finds the
block. It is an estimate: the window moves with every share.

**Example** (Bitcoin Cash chipnet, payout address without its prefix):

```sh
curl -u user:password 'http://127.0.0.1:46884/miner?address=qze95tc2dqrnltvxfa5yhunwx5952f34fv28vandn2&limit=2'
```

```json
{
  "address": "bchtest:qze95tc2dqrnltvxfa5yhunwx5952f34fv28vandn2",
  "address_type": "payout",
  "anchor": "0000000e5c...a41f",
  "anchor_height": 1250,
  "window": {
    "newest_height": 1250,
    "oldest_height": 0,
    "share_count": 1251,
    "weight": "62750000"
  },
  "share_count": 312,
  "uncle_count": 4,
  "weight": "15780000",
  "share_fraction": 0.24940047961630696,
  "payout_fraction": 0.25147410358565736,
  "shares": [
    {
      "blockhash": "0000003b71...9c20",
      "height": 1249,
      "nephew": null,
      "difficulty": "5000",
      "weight": "50000",
      "payout_address": "bchtest:qze95tc2dqrnltvxfa5yhunwx5952f34fv28vandn2"
    },
    {
      "blockhash": "00000019d4...07be",
      "height": 1247,
      "nephew": "000000a2f8...5d13",
      "difficulty": "5000",
      "weight": "45000",
      "payout_address": "bchtest:qze95tc2dqrnltvxfa5yhunwx5952f34fv28vandn2"
    }
  ]
}
```

The second entry is an uncle the miner found, included by the share at
height 1247. The chain here is younger than the maturity depth
(`COINBASE_MATURITY`, 6,048 shares), so nothing is skipped and the window
starts at the anchor; on an older chain `window.newest_height` sits that
many shares below `anchor_height`.

Querying a share chain address, for example
`?address=tp2pool:qq3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyga4duy5w2`, returns the
same shape with `"address_type": "share"`, and each share's
`payout_address` is whatever payout address that share named.

**Errors:**

- `400` -- `address` missing, malformed or for another network, or
  `limit` out of range:
  `{"error": "Invalid address 'bitcoincash:qq...': not a share address (...) nor a payout address (...)"}`
- `404` -- the node does not pay from the share chain PPLNS window
  (Hydrapool mode), or it has no share chain yet.
- `503` -- the node's PPLNS window is not loaded yet, or the anchor is
  deeper than its window cache reaches.

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
- `503` -- Not ready yet (for example the PPLNS window is still loading)

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
