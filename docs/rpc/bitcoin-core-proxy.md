# Bitcoin Core JSON-RPC Proxy

P2Poolv2 can expose a second HTTP listener that forwards a subset of Bitcoin Core
RPC methods to the upstream `bitcoind` node.  This lets mining-management
software that speaks the Bitcoin Core wire format point at p2poolv2 instead of
`bitcoind` directly, without requiring direct access to the node.

## Enabling the proxy

Add a `[bitcoin_rpc_api]` section to your config:

```toml
[bitcoin_rpc_api]
enabled = true
host = "127.0.0.1"
port = 18332
rpcuser = "p2pool"
rpcpassword = "p2pool"
```

The proxy binds to `host:port` and forwards requests to the `[bitcoinrpc]`
upstream defined elsewhere in the same config file. The gateway is disabled by
default, `host` defaults to `127.0.0.1`, and `port` must be set explicitly when
the gateway is enabled.

### Required `bitcoin.conf` settings

```
rpcallowip=127.0.0.1
rpcbind=127.0.0.1
rpcuser=p2pool
rpcpassword=p2pool
```

## Authentication

HTTP Basic Auth is required whenever the gateway is enabled. Set both `rpcuser`
and `rpcpassword` in `[bitcoin_rpc_api]`; startup rejects missing or incomplete
credentials.

The proxy uses constant-time comparison (SHA-256 hash then `ct_eq`) to prevent
timing attacks on the credential check.  A failed authentication returns
`HTTP 401` with `WWW-Authenticate: Basic realm="jsonrpc"`.

## Wire format

The proxy follows Bitcoin Core's legacy and JSON-RPC 2.0 wire formats. A
request is JSON-RPC 2.0 only when it contains `"jsonrpc":"2.0"`; all other
requests use the legacy format.

- Legacy responses contain `result`, `error`, and `id`.
- JSON-RPC 2.0 responses contain `jsonrpc`, `id`, and exactly one of `result`
  or `error`.
- JSON-RPC 2.0 requests without `id` are executed as notifications and omitted
  from the response. Notification-only requests return HTTP 204.
- Both single calls and batch requests are accepted. Empty batches are
  rejected.

### Single request

```
POST / HTTP/1.1
Authorization: Basic <base64(user:pass)>
Content-Type: application/json

{"jsonrpc":"1.1","id":1,"method":"getblockcount","params":[]}
```

Response:

```json
{"result":840000,"error":null,"id":1}
```

### Batch request

```json
[
  {"jsonrpc":"1.1","id":1,"method":"getblockcount","params":[]},
  {"jsonrpc":"1.1","id":2,"method":"getbestblockhash","params":[]}
]
```

Response (same order as the request):

```json
[
  {"result":840000,"error":null,"id":1},
  {"result":"000000000000000000024bead8df69990852c202","error":null,"id":2}
]
```

The maximum number of calls in a single batch is controlled by
`max_batch_size` (default: 20).  Exceeding it returns a single error response
with code `-32600`.

## Parameters

Bitcoin Core accepts positional parameters, named parameters, and the named
`args` parameter. The proxy forwards the parameter array or object unchanged,
so Bitcoin Core remains the source of truth for each method's parameter schema.

Example with named params:

```json
{"method":"getblock","params":{"blockhash":"00000000...","verbosity":1},"id":1}
```

## Supported methods

| Method | Description |
|---|---|
| `getblockchaininfo` | General blockchain state |
| `getbestblockhash` | Hash of the best (tip) block |
| `getblock` | Block data by hash; `verbosity` 0/1/2 |
| `getblockcount` | Current block height |
| `getblockfilter` | BIP 157 compact block filter |
| `getblockhash` | Block hash at a given height |
| `getblockheader` | Block header by hash |
| `getmempoolentry` | Single mempool entry by txid |
| `getnetworkinfo` | Node network information |
| `getrawmempool` | All txids (or verbose map) in the mempool |
| `getrawtransaction` | Raw transaction hex or decoded object |
| `gettxout` | UTXO information |
| `estimatesmartfee` | Fee estimate for target confirmation count |
| `sendrawtransaction` | Broadcast a raw transaction |
| `testmempoolaccept` | Dry-run transaction acceptance check |
| `decoderawtransaction` | Decode a raw transaction hex string |

Any other method returns a JSON-RPC error with code `-32601` (method not found).

## Method examples

### `getblock`

```json
{"method":"getblock","params":["000000000000000000024bead8df69990852c202",1],"id":1}
```

### `estimatesmartfee`

```json
{"method":"estimatesmartfee","params":[6,"ECONOMICAL"],"id":1}
```

Response:

```json
{"result":{"feerate":0.00012345,"errors":null,"blocks":6},"error":null,"id":1}
```

### `sendrawtransaction`

```json
{"method":"sendrawtransaction","params":["02000000..."],"id":1}
```

### `testmempoolaccept`

```json
{"method":"testmempoolaccept","params":[["02000000..."]],"id":1}
```

## Error codes

The proxy uses standard JSON-RPC 2.0 error codes for protocol errors, and
passes Bitcoin Core error codes through verbatim for upstream failures.

| Code | Meaning |
|---|---|
| `-32700` | Parse error (malformed JSON) |
| `-32600` | Invalid request (batch too large, wrong type, etc.) |
| `-32601` | Method not found |
| `-32602` | Invalid params |
| `-32603` | Internal error |
| `-5`, `-8`, … | Bitcoin Core domain errors — passed through unchanged |

## Forward compatibility

The router is structured to allow `/wallet/{name}` sub-paths for per-wallet
RPCs in a future release without breaking the existing `/` endpoint.
