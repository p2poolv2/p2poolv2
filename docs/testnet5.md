# Running P2Poolv2 on testnet5

Testnet5 is specified in [BIP 95](https://github.com/bitcoin/bips/blob/master/bip-0095.md).
It follows mainnet consensus, with two differences:

- there is no minimum difficulty exception;
- BIP 54 (consensus cleanup) is enforced from block 1.
- the minimum difficulty is about 1,000,000.

The BIP 95 genesis block was mined on 2026-11-14 by a public ckpool at
`lapis.erisian.com.au`, which keeps bootstrapping the chain. This is the
final testnet5 chain; the earlier rehearsal chain (genesis
`00000000000027fb...42d7`) is abandoned. The share chain genesis in
`p2poolv2_lib/src/shares/genesis/testnet5.dat` anchors on testnet5 block 35
(`00000000000002bd0196f81f7b58c99cb72b2e4b4720bb24dc98c2a47ae3b3b8`).

## Running Bitcoin Core

No released Bitcoin Core supports testnet5 yet. Build bitcoind from the
reference implementation, Bitcoin Core PR #35861 (branch
`fjahr/2026-07-t5-draft`):

```sh
git clone --branch 2026-07-t5-draft https://github.com/fjahr/bitcoin.git
cd bitcoin
```

The PR still has a placeholder genesis, so patch `CTestNet5Params` in
`src/kernel/chainparams.cpp` with the values from `curl -s
https://lapis.erisian.com.au/chain.json | jq .genesis`:

| field                 | value                                                                                |
|-----------------------|--------------------------------------------------------------------------------------|
| `consensus.powLimit`  | `0000000000000fffff0000000000000000000000000000000000000000000000`                   |
| genesis message       | `2026-11-14 975744 0000000000000000000123e2681e2f82acdcb9430a15eec24cc85b400691d479` |
| genesis output script | `CScript() << OP_RETURN << "95ebf76a02000000"_hex`                                   |
| nTime, nNonce         | `1794632593`, `0x653d9131`                                                           |
| nBits, nVersion       | `0x1a0fffff`, `0x2230c000`                                                           |
| genesis hash          | `00000000000008c1637e7d3252dc1c333d4546fd6fff6a474b200d674a91d497`                   |
| merkle root           | `8c5899b65c5b0834adb17af314e22a9bf067e7ed8144c37967b5ec56b5a6e28d`                   |

If you built a node for the rehearsal chain, start over with a fresh
datadir.

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
bitcoin-cli -testnet5 getblockhash 0      # 00000000000008c1...
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
