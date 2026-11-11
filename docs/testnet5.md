# Running P2Poolv2 on testnet5 (rehearsal)

Testnet5 is specified in [BIP 95](https://github.com/bitcoin/bips/blob/master/bip-0095.md).
It follows mainnet consensus, with two differences:

- there is no minimum difficulty exception;
- BIP 54 (consensus cleanup) is enforced from block 1.
- the minimum difficulty is about 1,000,000.

As of November 2026 testnet5 is still being bootstrapped by a public ckpool
at `lapis.erisian.com.au`. A rehearsal chain is live now, and the final genesis
block will replace it. The share chain genesis in
`p2poolv2_lib/src/shares/genesis/testnet5.dat` anchors on the rehearsal
genesis (`00000000000027fb...42d7`). It gets replaced once the BIP 95
genesis is mined.

## Running Bitcoin Core

No released Bitcoin Core supports testnet5 yet. The reference
implementation is Bitcoin Core PR #35861 (branch
`fjahr/2026-07-t5-draft`). That branch still has a placeholder
genesis, so for the rehearsal chain, we patched `CTestNet5Params` in
`src/kernel/chainparams.cpp` with the values from `curl -s
https://lapis.erisian.com.au/chain.json | jq .genesis`:

| field                 | rehearsal value                                                                      |
|-----------------------|--------------------------------------------------------------------------------------|
| `consensus.powLimit`  | `0000000000007fff800000000000000000000000000000000000000000000000`                   |
| genesis message       | `2026-11-09 975209 000000000000000000016bd0ac174bb6916cc35f96a9927fcc13914beabf888b` |
| genesis output script | `CScript() << OP_RETURN << "8120f26a0014f839"_hex`                                   |
| nTime, nNonce         | `1794253005`, `0x0f270180`                                                           |
| nBits, nVersion       | `0x1a7fff80`, `0x24e3a000`                                                           |
| genesis hash          | `00000000000027fb17bedec4b497ca06af49783d3618ecb6ed98e357db6c42d7`                   |
| merkle root           | `0c24fb78382cfdd3fd8da4c9d687a60ae230cab45bfc12201bef01b4c216f02b`                   |

Build with ZMQ (P2Poolv2 subscribes to `zmqpubhashblock`):

```sh
cmake -B build-t5 -DWITH_ZMQ=ON -DENABLE_IPC=OFF -DBUILD_GUI=OFF
cmake --build build-t5 -j$(nproc)
```

Run it with its own datadir and peer with the bootstrap pool's node:

```sh
build-t5/bin/bitcoind -testnet5 -datadir=$HOME/.bitcoin-t5 -server -daemon \
  -addnode=lapis.erisian.com.au:18353 \
  -zmqpubhashblock=tcp://127.0.0.1:28335 \
  -rpcuser=p2pool -rpcpassword=p2pool
```

Testnet5 ports: P2P 18353, RPC 18352. Check the node:

```sh
bitcoin-cli -testnet5 getblockhash 0      # 00000000000027fb...
bitcoin-cli -testnet5 getblocktemplate '{"rules":["segwit","consensuscleanup"]}'
```

If P2P sync fails, the bootstrap blocks can be imported from chain.json:

```sh
curl -s https://lapis.erisian.com.au/chain.json | jq -r '.blocks[].block' |
  while read block; do bitcoin-cli -testnet5 submitblock "$block"; done
```

## P2Poolv2

Start from `config.sample.toml` and set at least:

```toml
[network]
# Testnet5 nodes listen on 56886; the built-in DNS seed
# seed.testnet5.p2poolv2.org returns nodes on that port.
listen_address = "/ip4/0.0.0.0/tcp/56886"
dial_peers = []
# Set false only on the first node of a new share chain.
dns_seed = true

[stratum]
network = "testnet5"
zmqpubhashblock = "tcp://127.0.0.1:28335"
bootstrap_address = "tb1..."
miner_address = "tp2pool1..."
# The first node of a new share chain has nothing to sync from.
wait_for_chain_sync = false

[bitcoinrpc]
url = "http://127.0.0.1:18352"
```

Then run `p2poolv2 --config <file>` and point miners at the stratum port.

## When the BIP 95 genesis is mined

1. Rebuild Bitcoin Core from a branch with the final params, or repeat the
   patch above with the final chain.json values. Start over with a fresh
   datadir.
2. Replace `testnet5.dat` with the new genesis block
   (`jq -r '.blocks[0].block' chain.json | xxd -r -p`). Update the hash in
   `test_testnet5_genesis_block_hash` and the genesis share timestamp.
