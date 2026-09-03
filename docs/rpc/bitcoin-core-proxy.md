# Bitcoin Core JSON-RPC gateway

P2Poolv2 can expose an authenticated HTTP gateway to the `bitcoind` configured
in `[bitcoinrpc]`. The gateway does not answer from the P2Poolv2 share chain and
is not a P2Poolv2-native Bitcoin chain backend. It forwards an allowlisted set
of calls to that upstream Bitcoin Core node and returns the upstream results.

This is not an Electrum server, an Esplora API, or an NBXplorer API. It exposes
only `POST /`, has no wallet endpoint, and is not a drop-in replacement for
those protocols or for Bitcoin Core's complete RPC interface.

## Configuration

Configure the upstream node and gateway separately:

```toml
[bitcoinrpc]
url = "http://127.0.0.1:38332"
username = "upstream-user"
password = "replace-with-upstream-password"

[bitcoin_rpc_api]
enabled = true
host = "127.0.0.1"
port = 18332
rpcuser = "gateway-user"
rpcpassword = "replace-with-gateway-password"
max_batch_size = 20
```

The `[bitcoinrpc]` credentials authenticate P2Poolv2 to the upstream
`bitcoind`. P2Poolv2 requires the configured username and password and does not
read Bitcoin Core's cookie file. The `[bitcoin_rpc_api]` credentials are a
separate pair that clients use to authenticate to this gateway.

The gateway is disabled by default. When enabled, `port`, `rpcuser`, and
`rpcpassword` are required and must be non-empty. `host` defaults to
`127.0.0.1`, and `max_batch_size` defaults to 20 and must be greater than zero.
Configuration is rejected at startup if these requirements are not met.

The listener participates in normal P2Poolv2 shutdown: the node signals the
gateway, and the HTTP server stops gracefully.

## Upstream Bitcoin Core

The `bitcoind` daemon enables its JSON-RPC server by default, so it normally
does not need `server=1`. The option is relevant when using the `bitcoin-qt`
GUI, whose JSON-RPC server is disabled by default.

For a same-host setup, Bitcoin Core's default loopback RPC binding is enough;
`rpcbind` and `rpcallowip` are not normally needed. If P2Poolv2 runs on another
host or container, configure those options for only the required private
address or network.

The upstream node needs credentials matching `[bitcoinrpc]`. It also needs the
indexes required by the calls clients will make:

```ini
rpcuser=upstream-user
rpcpassword=replace-with-upstream-password
txindex=1
blockfilterindex=1
```

`txindex=1` is needed for arbitrary historical `getrawtransaction` lookups by
transaction ID alone. A transaction in the mempool, or a transaction queried
with the hash of an available containing block, does not require the full
transaction index. `blockfilterindex=1` is needed for `getblockfilter`; wait for
the index to synchronize before relying on it.

## Security

Every gateway request requires HTTP Basic Auth. Missing or invalid credentials
return HTTP 401 with `WWW-Authenticate: Basic realm="jsonrpc"`.

The gateway serves plain HTTP and does not terminate TLS. Basic Auth encodes
credentials but does not encrypt them, so anyone able to observe the traffic
can recover them. Keep the default loopback binding when possible. Do not
expose the listener directly to the public Internet; use a trusted private
network or a TLS-protected tunnel or reverse proxy when remote access is
required.

The gateway credentials protect access only to the gateway. The upstream
credentials remain in `[bitcoinrpc]` and are used for the gateway's calls to
Bitcoin Core.

## Supported v1 methods

Gateway v1 exposes exactly these 16 methods:

| Method | Forwarded operation |
|---|---|
| `getbestblockhash` | Return the best block hash |
| `getblock` | Return block data by hash |
| `getblockchaininfo` | Return blockchain state |
| `getblockcount` | Return the current block height |
| `getblockfilter` | Return a BIP 157 compact block filter |
| `getblockhash` | Return the block hash at a height |
| `getblockheader` | Return a block header by hash |
| `getmempoolentry` | Return one mempool entry |
| `getnetworkinfo` | Return node network information |
| `getrawmempool` | Return mempool transaction IDs or details |
| `getrawtransaction` | Return raw or decoded transaction data |
| `gettxout` | Return information about an unspent output |
| `estimatesmartfee` | Estimate a fee rate for a confirmation target |
| `sendrawtransaction` | Submit a raw transaction |
| `testmempoolaccept` | Test transaction acceptance without submission |
| `decoderawtransaction` | Decode raw transaction hex |

Every other method, including wallet RPCs, returns code `-32601` (method not
found). The allowlist is a security and scope boundary, not evidence that a
downstream application is compatible.

## Request and response formats

The gateway accepts Bitcoin Core's legacy JSON-RPC envelope and JSON-RPC 2.0.
A request is treated as 2.0 only when it contains exactly
`"jsonrpc":"2.0"`; every other request uses the legacy response envelope.
The gateway sends each allowed call upstream using its internal legacy client
and reconstructs the client-facing response with the original request ID.

### Legacy example

```sh
curl --user gateway-user:replace-with-gateway-password \
  --data-binary '{"method":"getblockcount","params":[],"id":"height"}' \
  --header 'content-type: application/json' \
  http://127.0.0.1:18332/
```

```json
{"result":840000,"error":null,"id":"height"}
```

Legacy responses always contain `result`, `error`, and `id`. A legacy request
without `id` is not a notification; it receives a response with `"id":null`.

### JSON-RPC 2.0 example

```sh
curl --user gateway-user:replace-with-gateway-password \
  --data-binary '{"jsonrpc":"2.0","method":"getblockhash","params":{"height":0},"id":1}' \
  --header 'content-type: application/json' \
  http://127.0.0.1:18332/
```

```json
{"jsonrpc":"2.0","result":"network-specific-genesis-hash","id":1}
```

A JSON-RPC 2.0 response contains `jsonrpc`, `id`, and exactly one of `result`
or `error`.

## Parameters

Both positional arrays and named objects are accepted and forwarded unchanged
as the upstream call's `params` value. These equivalent requests show both
forms:

```json
{"method":"getblockhash","params":[0],"id":1}
```

```json
{"method":"getblockhash","params":{"height":0},"id":1}
```

`params` may also be omitted or set to `null`. Any other JSON type is rejected
with code `-32602`. Bitcoin Core remains the source of truth for each method's
parameter names, positions, defaults, and validation.

## Batches and notifications

A top-level JSON array is a batch. Calls are sent to the upstream node one at a
time in request order, and non-notification responses are returned in that
same order. A one-call batch still produces an array response. Duplicate IDs
are preserved; the gateway does not deduplicate them.

```json
[
  {"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1},
  {"jsonrpc":"2.0","method":"getbestblockhash","params":[]}
]
```

The second item is a JSON-RPC 2.0 notification because it omits `id`. It is
executed but omitted from the response:

```json
[
  {"jsonrpc":"2.0","result":840000,"id":1}
]
```

A single notification or notification-only batch returns HTTP 204 with an
empty body. A JSON-RPC 2.0 request with `"id":null` is not treated as a
notification. Empty batches return `-32600`. Batches larger than
`max_batch_size` return one `-32600` response without executing any item.

Malformed JSON returns `-32700`; invalid request shapes return `-32600`; and
upstream Bitcoin Core error codes and messages are preserved. Other fields in
an upstream error object are not preserved. Upstream HTTP, transport, or
response-decoding failures become `-32603`. JSON protocol errors use HTTP 200,
which differs from Bitcoin Core's legacy HTTP error status behavior.

## Downstream compatibility

Status means:

- **Tested**: an end-to-end test passed against the named release or commit.
- **Partially tested**: only a documented subset passed against the named
  release or commit.
- **Not tested**: no end-to-end result is recorded; no compatibility claim is
  made.

The repository contains no successful end-to-end run against an exact version
or commit of any target below. Mock-backed coverage and method overlap do not
establish compatibility.

| Software | Status | Version or commit | Scope and limitations |
|---|---|---|---|
| Bitcoin Core | Not tested | None recorded | An ignored live-regtest comparison exists, but no successful run or Bitcoin Core version is recorded. |
| LND | Not tested | None | No LND release or commit has been tested. LND normally also connects directly to Bitcoin Core's raw-block and raw-transaction ZMQ endpoints; setting `bitcoind.rpcpolling=true` selects its RPC polling mode instead. Neither mode has been validated with this gateway. |
| CLN | Not tested | None | No Core Lightning release or commit has been tested. Its default `bcli` Bitcoin backend has not been validated against this allowlist. |
| CoinSwap | Not tested | None | No CoinSwap implementation, release, or commit has been selected or tested. |
| Ark | Not tested | None | No Ark implementation, release, or commit has been selected or tested. |

## Official references

- [Bitcoin Core 31.0 JSON-RPC interface](https://github.com/bitcoin/bitcoin/blob/v31.0/doc/JSON-RPC-interface.md)
- [Bitcoin Core 31.0 `bitcoind` server default](https://github.com/bitcoin/bitcoin/blob/v31.0/src/bitcoind.cpp)
- [Bitcoin Core 31.0 `getrawtransaction`](https://bitcoincore.org/en/doc/31.0.0/rpc/rawtransactions/getrawtransaction/)
- [Bitcoin Core 31.0 `getblockfilter`](https://bitcoincore.org/en/doc/31.0.0/rpc/blockchain/getblockfilter/)
- [LND installation and `bitcoind` backend](https://github.com/lightningnetwork/lnd/blob/master/docs/INSTALL.md)
- [LND sample configuration for ZMQ and RPC polling](https://github.com/lightningnetwork/lnd/blob/master/sample-lnd.conf)
- [Core Lightning Bitcoin Core backend](https://docs.corelightning.org/docs/bitcoin-core)
- [Core Lightning Bitcoin backend plugin interface](https://docs.corelightning.org/docs/bitcoin-backend)
