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

Limits: 64 outstanding tokens and 64 MiB of declared transaction state per
registry, eight pending declarations per connection, 25 Merkle siblings,
SV2's 65,535-byte coinbase-output field and 16 MiB frame limit. All revealed
transactions currently arrive in one response; larger declarations require
transaction-cache negotiation before increasing those limits. Auxiliary
token/covenant inclusion proofs remain unfinished; choosing an aux root
does not prove those assets or their rules.

Protocol references: [SV2 Mining Protocol](https://stratumprotocol.org/specification/05-mining-protocol/)
and [SV2 Job Declaration Protocol](https://stratumprotocol.org/specification/06-job-declaration-protocol/).
