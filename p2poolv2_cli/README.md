# P2Pool v2 CLI

Command-line utility for querying a running P2Pool v2 node. All commands
output JSON and require a config file pointing at the node's API.

## Prerequisites

- A running P2Poolv2 node
- A config file with the API section (`hostname`, `port`, and optional auth
  credentials)

## Running

```sh
p2poolv2_cli --config /path/to/config.toml <command>
```

You can also use environment variable to provide the config:

```sh
P2POOL_CONFIG=/path/to/config.toml p2poolv2_cli <command>
```

## Commands

### info

Display chain state (tip height, total work, candidate info, share count).

```sh
p2poolv2_cli info
```

### shares

Display confirmed shares for a height range.

```sh
p2poolv2_cli shares                 # last 10 shares up to chain tip
p2poolv2_cli shares --num 20        # last 20 shares
p2poolv2_cli shares --to 500 --num 5  # 5 shares ending at height 500
```

### candidates

Display candidate shares for a height range.

```sh
p2poolv2_cli candidates             # last 10 candidates
p2poolv2_cli candidates --num 20    # last 20 candidates
p2poolv2_cli candidates --to 500 --num 5
```

### share

Look up a single share by blockhash or height.

```sh
p2poolv2_cli share --hash <blockhash>
p2poolv2_cli share --height 42
p2poolv2_cli share --height 42 --full   # include transaction list
```

### pplns-shares

Query PPLNS shares with optional time filtering.

```sh
p2poolv2_cli pplns-shares --limit 50
p2poolv2_cli pplns-shares --limit 100 --start-time 1700000000 --end-time 1700100000
```

### peers-info

List connected peers.

```sh
p2poolv2_cli peers-info
```

### gen-auth

Generate API authentication credentials. Does not require a running
node or config file.

```sh
p2poolv2_cli gen-auth myuser           # auto-generate password
p2poolv2_cli gen-auth myuser mypass    # use provided password
```

## Formatting output with jq

All commands output JSON. Use `jq` to extract fields or build tables.

### Shares as a tab-separated table

```sh
p2poolv2_cli shares --num 5 \
| jq -r '.shares[] | [.height, .blockhash[:8], .miner_pubkey[:8], .difficulty] | @tsv'
```

### Shares table with column headers

```sh
p2poolv2_cli shares --num 5 \
  | jq -r '["Height","Hash","Miner","Difficulty"], (.shares[] | [.height, .blockhash[:8], .miner_pubkey[:8], .difficulty]) | @tsv' \
  | column -t
```

### List uncle blockhashes for a share

```sh
p2poolv2_cli share --height 42 \
  | jq -r '.[0].uncles[]'
```

### Filter shares by miner pubkey

```sh
p2poolv2_cli shares --num 100 \
  | jq '.shares[] | select(.miner_pubkey | startswith("02aabb"))'
```

### Candidate heights only

```sh
p2poolv2_cli candidates --num 20 \
  | jq -r '.shares[].height'
```

### Peer IDs as a plain list

```sh
p2poolv2_cli peers-info \
  | jq -r '.[].peer_id'
```
