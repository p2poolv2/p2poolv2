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
coinbase and parent header. An experimental SAFA covenant now verifies that
proof and its own issuance rules in a real regtest spend. Other assets need
their own covenant adapters; choosing an aux root alone cannot authorize
their issuance.

Protocol references: [SV2 Mining Protocol](https://stratumprotocol.org/specification/05-mining-protocol/)
and [SV2 Job Declaration Protocol](https://stratumprotocol.org/specification/06-job-declaration-protocol/).

## Encrypted network regression

`encrypted_bch_job_declaration_modes_install_mine_and_emit` runs the real
listener with a configured authority and three loopback TCP connections.
The reference SV2 codec pins that authority for the mining connection and
the separate Full-Template and Coinbase-Only declarators. It transfers their
tokens to the mining connection, installs jobs, mines headers and checks both
emitted coinbase proofs. Reusing a consumed token must fail.

The clients send adjacent setup/allocation frames in one write and split
other writes after the first byte. A 5,000-byte declaration field forces
payload decoding across the listener's 4,096-byte reads; TCP decides the
actual segmentation. The test also checks Full-Template proposal/submission
calls, Coinbase-Only transaction privacy and connection cleanup. Simulation
builds retain their existing block-submission suppression.

```sh
cargo nextest run -p p2poolv2_lib -E 'test(encrypted_bch_job_declaration_modes_install_mine_and_emit)'
```

BCHN responses are mocked in this test. The test below combines encrypted
network exchange with real BCHN nodes. Neither test establishes independent
client or ASIC compatibility.

Validated locally on Windows on 2026-10-16: the focused exchange passed,
followed by 1,719 default workspace tests (two skipped) and 1,727 all-features
tests (one skipped). Clippy passed for all targets with default and all
features and warnings denied. Formatting and `git diff --check` passed.

## Two-node BCHN regtest check

The ignored `bchn_declared_jobs_reach_both_real_nodes_over_noise` test uses two
disposable, connected BCHN nodes and the actual SV2 TCP listener. A client
using SRI's initiator pins the test authority key on three authenticated Noise
connections: Mining, Full-Template JD and Coinbase-Only JD. It allocates tokens,
declares and reveals Full-Template transactions, installs both jobs and submits
their shares over these sockets. It verifies Full-Template proposal validation
and pool submission, then a private transaction absent from both mempools, Coinbase-Only
header submission and client block broadcast. Both nodes must accept each
block, both emitted coinbase proofs must match, and BCHN must reject an extra
satoshi of coinbase value. This repository's client uses the published SRI
transport and messages; independent declarator or ASIC firmware interoperability
still requires separate validation.

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
cargo nextest run -p p2poolv2_lib --run-ignored ignored-only -E 'test(bchn_declared_jobs_reach_both_real_nodes_over_noise)' --nocapture
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

Repeated on 2026-10-17 using the authenticated network test and real SAFA work:

| Mode | Height | Block hash | Coinbase value (sat) |
|---|---|---|---|
| Full-Template | 173 | `44ccdc671714314018c0840339f46f057ac0cab71cff32e5330a2d6955f30975` | 2500000219 |
| Coinbase-Only | 174 | `523418daf87a30df4f57d5d67cdd41d3cb17e8deeb24008cea80b46bfe392a7f` | 2500000219 |

The test passed in 6.459 seconds. These proofs then authorized a real token
withdrawal. BCHN rejected that identical signed transaction one block before
its 74-block relative age matured, then accepted it after one more block.
The withdrawal, public vectors and reproduction commands are in
[the SAFA evidence record](../tools/safa-auxpow/README.md#regtest-evidence-and-reproduction).

## Encrypted BCHN and SAFA check (2026-10-17)

The earlier 205/206 run used direct mining handlers. The current opt-in test
also completed the full encrypted network exchange against two fresh BCHN
29.2.0 nodes. Full-Template allocation, transaction delivery, token rotation,
installation and submission all crossed authenticated TCP connections.
Coinbase-Only kept its raw transaction on the client and used client broadcast
after the pool accepted the header and emitted its proof. Both nodes accepted
these blocks carrying actual experimental SAFA work:

| Mode | Height | Block hash | Coinbase value (sat) |
|---|---|---|---|
| Full-Template | 249 | `291220623fcad14e4eda3d6388d12376014700abdb4171049a0ede9064a7ff45` | 2500000219 |
| Coinbase-Only | 250 | `6ed5e6f5841ab37c8f32c1b821bee134463c51635ebe70b177aab66b179dc820` | 2500000219 |

The private proof authorized withdrawal
`9cea5236f7032f80635253e3529e3373c1f5aed68367e5173518c48c5eab8287`
in block `5edef1a9f5669fdb44a34a919fec69a541944b833a7b5ed42550d00a413c7887`
at height 252. Both nodes validated the continuation with 419,999,000 tokens
and the 1,000-token recipient reward. Its 1,266-byte scriptSig includes the
839-byte redeem script; the transaction paid 5,000 satoshis in fees using a
sponsor input.
BCHN rejected an altered coinbase Merkle sibling. Both private and Full-Template
proofs also verified against the actual withdrawal and genesis outputs in
the standard BCH 2026 VM; the Full-Template scriptSig used 1,298 bytes.

At tip 250, BCHN rejected that same signed transaction with `non-BIP68-final`:
the baton required 74 blocks. After mining block 251, the identical bytes
passed the mempool check and the withdrawal confirmed at 252. The harness
retains both results, separating VM sequence checks from actual chain maturity.

Reproduce the token preparation and withdrawal using
[the SAFA harness](../tools/safa-auxpow/README.md#regtest-evidence-and-reproduction)
around this opt-in test. An initial synthetic-work run also passed at heights
102 and 103. The disposable nodes were stopped after validation, with their
public proof and transaction evidence retained locally. Independent clients,
ASIC firmware, chipnet issuance and the final SAFA economic policy remain open.

The combined branch passed 1,719 default workspace tests (two skipped), 1,727
all-features tests (one skipped), and all-target Clippy with default and all
features and warnings denied. Formatting and whitespace checks passed.
