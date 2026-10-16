# BCH P2Pool Job Declaration

This is the BCH direct PPLNS contract carried by the published SV2 Mining
and Job Declaration messages. A generic client that expects one custodial
pool payout needs BCH P2Pool support. Independent client interoperability
has not been verified.

An extended mining channel negotiates `REQUIRES_WORK_SELECTION` (bit 1).
A separate Job Declaration connection selects Full-Template with
`DECLARE_TX_DATA` (bit 0), or Coinbase-Only with that bit clear.
Job Declaration setup success flags are zero in both modes.

Allocation returns required payout scripts with zero values as a
CompactSize-prefixed transaction-output vector. The actual payments come
from the PPLNS window anchored by the token: use the same difficulty weights,
donation/fee cuts, rounding and script ordering as peer payout validation.
`PreparedNotifyParams::declared_outputs` and `build_pplns_outputs` implement
that calculation. The declarator needs the local share-chain snapshot.

The opaque token also exposes the public commitment terms. Its version-1
layout is: version byte, 32 random bytes, previous share hash, CompactSize
uncle count and hashes, compact share bits, share time, optional donation
address, donation basis points, optional fee address, fee basis points.
Integers use Bitcoin consensus little endian. Optional addresses use the
share-header address encoding. `ShareCommitment::from_mining_job_token`
decodes these terms; parsing alone does not authenticate a token. The pool
accepts only a token present in its registry, for 120 seconds after allocation,
and consumes it once when a mining connection requests installation.
Full-Template success rotates the random bytes without changing the terms.

The miner supplies its payout address, BCH share owner and selected template
revenue when constructing the share commitment. The BCH descriptor binds the
raw scriptSig prefix and auxiliary root/tree-size/nonce. The prefix begins
with the canonical height push and leaves room for the channel's complete
12-byte extranonce within the 100-byte scriptSig limit. Coinbase version is
2, sequence is `0xfffffffe`, and locktime is `height - 1`. Output order is
the exact PPLNS outputs, one zero-value aux commitment, canonical padding,
then the share commitment. Arbitrary extra outputs and output reordering
are rejected. Existing legacy jobs retain their original encoding.

Full-Template clients declare the serialized coinbase prefix and suffix
around that extranonce, reveal all non-coinbase transactions, then present
the returned token in `SetCustomMiningJob`. The server orders transactions
by BCH CTOR, verifies the matching Merkle path and coinbase declaration,
and asks the local BCHN node to validate a block proposal without PoW.
Only a null proposal result permits installation. A successful response
contains the installed channel job id; shares can be submitted immediately.
The pool can broadcast a complete found block in this mode.

Coinbase-Only clients do not declare or reveal their transaction list.
They present the allocated token with their coinbase and private Merkle
path directly. The pool verifies visible coinbase/header rules, exact
payments and share PoW. It cannot validate hidden transactions, CTOR, actual
fees or total hidden block size. The declarator must validate and broadcast
the complete block; the pool never broadcasts an incomplete substitute.
This mode retains the protocol's withholding and hidden-invalid-work risk.

Once a job is active, its target and credited difficulty remain fixed.
Vardiff and `UpdateChannel` change later jobs. Device maximum targets apply
when each job is assigned; zero maximum targets are rejected.

Limits: 64 outstanding tokens and 64 MiB of declared transaction state per
registry, eight pending declarations per connection, 25 Merkle siblings,
SV2's 65,535-byte coinbase-output field and 16 MiB frame limit. All revealed
transactions currently arrive in one response; larger declarations require
transaction-cache negotiation before increasing those limits. The shared
[auxiliary work verifier](bch-auxpow.md) checks inclusion through the full
coinbase and parent header. Token-specific covenant rules remain unfinished;
choosing an aux root does not prove those assets or authorize their issuance.

Protocol references: [SV2 Mining Protocol](https://stratumprotocol.org/specification/05-mining-protocol/)
and [SV2 Job Declaration Protocol](https://stratumprotocol.org/specification/06-job-declaration-protocol/).

## Two-node BCHN regtest check

The ignored `bchn_declared_jobs_reach_both_real_nodes` test uses two disposable,
connected BCHN nodes. It verifies Full-Template proposal validation and pool
submission, then a private transaction absent from both mempools, Coinbase-Only
header submission and client block broadcast. Both nodes must accept each
block, both emitted coinbase proofs must match, and BCHN must reject an extra
satoshi of coinbase value. Mining handlers run directly inside the test;
this does not exercise an independent client or the encrypted network exchange.

Use fresh data directories, outside the repository. The first node needs this
`bitcoin.conf`:

```ini
regtest=1
server=1
discover=0
dnsseed=0
listenonion=0
rpcuser=p2pool-jd-test
rpcpassword=local-regtest-only
rpcallowip=127.0.0.1
[regtest]
rpcbind=127.0.0.1
rpcport=19453
bind=127.0.0.1
port=19454
```

The second uses the same settings with RPC port 19455 and P2P port 19456;
add `connect=127.0.0.1:19454` under `[regtest]` and `disablewallet=1` before
that section. The fixed credentials are solely for these loopback test nodes.
Start both nodes, create/load a wallet named `jd-regtest` on the first, and
mine at least 101 blocks to an address from that wallet. For example, in
PowerShell with `$bchnBin` pointing to BCHN's `bin` directory and `$clientData`
and `$poolData` pointing to the fresh directories:

```powershell
Start-Process "$bchnBin/bitcoind.exe" -ArgumentList "`"-datadir=$clientData`"" -WindowStyle Hidden
Start-Process "$bchnBin/bitcoind.exe" -ArgumentList "`"-datadir=$poolData`"" -WindowStyle Hidden
# Wait until both RPC endpoints respond, then initialize the disposable wallet.
& "$bchnBin/bitcoin-cli.exe" "-datadir=$clientData" createwallet jd-regtest
$testAddress = & "$bchnBin/bitcoin-cli.exe" "-datadir=$clientData" -rpcwallet=jd-regtest getnewaddress
& "$bchnBin/bitcoin-cli.exe" "-datadir=$clientData" generatetoaddress 101 $testAddress
$env:BCHN_JD_CLIENT_RPC = 'http://127.0.0.1:19453'
$env:BCHN_JD_POOL_RPC = 'http://127.0.0.1:19455'
cargo nextest run -p p2poolv2_lib --run-ignored ignored-only -E 'test(bchn_declared_jobs_reach_both_real_nodes)' --nocapture
# Stop only these two disposable nodes when finished.
& "$bchnBin/bitcoin-cli.exe" "-datadir=$clientData" stop
& "$bchnBin/bitcoin-cli.exe" "-datadir=$poolData" stop
```

The test verifies loopback endpoints and `chain = regtest` before spending.
It requires an otherwise empty mempool and enough mature wallet balance for
two 1-BCH payments; do not run it concurrently against the same pair. Windows
build prerequisites are the same as the workspace's other native Rust tests.

Repeated with BCHN 29.2.0 on 2026-10-15 (one test passed, 0.158 seconds):

| Mode | Height | Block hash | Coinbase value (sat) |
|---|---|---|---|
| Full-Template | 205 | `3e137beafcec73ffceb86ecf6937fd37c4e554b92f871a348d7c5ff90f200850` | 2500000219 |
| Coinbase-Only | 206 | `4b67278077005751d6e25cbb058fc8e635d6761506c58757d2e2c8c554dbfe23` | 2500000219 |

Each block included 219 satoshis in transaction fees. The Coinbase-Only
transaction was signed with the disposable wallet but withheld from both
mempools until its complete block was broadcast.
