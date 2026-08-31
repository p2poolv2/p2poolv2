# Share Chain Address Format

This document specifies the P2Poolv2 share chain address: its encoding,
the rules a parser must enforce, test vectors, and how a miner supplies
one to a pool.

## Why a separate address type

A share block header carries two addresses, on two different chains,
for two different purposes:

| Field | Type | Chain | Role |
|---|---|---|---|
| `miner_bitcoin_address` | `bitcoin::Address` | bitcoin | receives the PPLNS payout from a found block's coinbase |
| `miner_address` | `p2poolv2_address::Address` | share chain | owns the share coinbase output |

These were one field until the two-address split. Separating them
matters because the two identities have different requirements. A
bitcoin payout address is *receive-only*: miners routinely point it at
an exchange deposit address or a watch-only descriptor, and nothing
ever needs to spend from it on the miner's behalf. Share ownership
needs a *spend-capable* identity, because shares are meant to be traded
for bitcoin UTXOs and the share chain runs real script validation
(`bitcoinconsensus::verify` in `validate_scripts_for_tx`,
`shares/validation/mod.rs:653`) with prevout, maturity and double-spend
checks.

`miner_address` is never derived from `miner_bitcoin_address`. Deriving
would assign shares to receive-only addresses that can never sign a
share chain spend, would require witness material miners often cannot
export, and would force one key across two chains with no domain
separation. The single exception is genesis
(`shares/share_block/mod.rs:396-406`), where the source is a NUMS key
nobody can spend on either chain.

## Encoding

bech32m (BIP350) over a witness version followed by a 32 byte taproot
output key, under a P2Poolv2 specific human readable part.

| Network | HRP | Constant |
|---|---|---|
| Mainnet | `p2pool` | `HRP_MAINNET` |
| Testnet4 | `tp2pool` | `HRP_TESTNET4` |
| Signet | `sp2pool` | `HRP_SIGNET` |
| Regtest | `rp2pool` | `HRP_REGTEST` |

Testnet3 has no HRP. `Network::Testnet` yields
`AddressError::UnsupportedNetwork`, matching `genesis_data()`, which
already returns an error for it.

The data part is the witness version as a single bech32 field element,
followed by the 32 byte output key regrouped from 8-bit to 5-bit
groups. Because only version 1 is accepted, this is byte for byte what
BIP350 prescribes for a segwit v1 address.

### The HRP is the only separator

A share address and a bitcoin taproot address differ *only* in their
human readable part. That is sufficient for safety, because the bech32m
checksum covers the HRP: neither string can be reinterpreted as the
other without failing its checksum, and `bitcoin::Address::from_str`
rejects a share address because `p2pool` is not a `KnownHrp`.

**The corollary matters for anything downstream.** A raw segwit parser
that does not restrict the HRP will decode a share address quite
happily -- `bech32::segwit::decode` included, because `validate_segwit`
deliberately does not restrict the HRP. Any code deciding whether a
string is a bitcoin address must check the HRP, not merely that the
string parses as segwit.

### Witness version 1 only

Every other witness version is rejected outright rather than supported
and deprecated. Version 0 (P2WPKH and P2WSH) included.

- The share chain already verifies taproot in full, so restricting to
  v0 would have put the address type *below* what the chain enforces.
- Trading a share for a bitcoin UTXO is a cross chain atomic swap.
  Taproot on both sides allows adaptor signatures: an ordinary key path
  spend on each chain, no HTLC script, no preimage published. Witness
  v0 would force HTLC scripts, hence P2WSH, hence 32 byte programs
  anyway, so it does not even avoid the wider format.
- One output type keeps one swap protocol. Supporting both would split
  the share chain into shares that trade via adaptor signatures and
  shares that need HTLCs, and every downstream tool would carry both
  paths forever.
- Script paths arrive later with no format change, because taproot
  commits the merkle root inside the output key.

Wider support can be soft forked in later: the witness version travels
in the encoding, so accepting a new one is a format extension. It
remains a consensus change, because `miner_address` is committed in
`ShareHeader`.

The encoded key is the taproot *output* key, matching BIP086 and
matching what lands in the `scriptPubKey`. Whether that key commits a
script tree is invisible in the address and is not restricted.

## Parsing rules

A conforming parser must reject all of the following. Each maps to a
variant of `AddressError` in `p2poolv2_address/src/lib.rs:98`.

| Input | Error |
|---|---|
| BIP173 bech32 checksum instead of bech32m | `Encoding` |
| Mixed case | `Encoding` |
| HRP not one of the four | `UnknownPrefix` |
| Empty data part, so no witness version | `MissingWitnessVersion` |
| First data symbol decodes above 16 | `InvalidWitnessVersion` |
| A real witness version other than 1 | `UnsupportedWitnessVersion` |
| Program not 32 bytes | `InvalidOutputKeyLength` |
| 32 bytes that are not a valid x-only curve point | `InvalidOutputKey` |
| Non-zero trailing padding bits | `Padding` |
| Right format, wrong network | `NetworkMismatch` (via `require_network`) |

All-uppercase is valid and parses to the same address, per BIP173.
Mixed case is not: it defeats the checksum, which is why the stratum
password parser slices the address out of the *original* string rather
than a lowercased copy.

Rejecting a non-curve-point is not pedantry. Those 32 bytes would
encode an output nobody can ever spend, so a share paid to it would be
permanently lost.

## Test vectors

Verified against an independent bech32m implementation, not against the
Rust code, so they check the spec rather than themselves.

### Output key used directly, no tweak

Output key `ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d`
(the x-coordinate of the genesis NUMS pubkey
`02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d`):

```
Mainnet   p2pool1p43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5ksxgg7wd
Testnet4  tp2pool1p43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5kst4gevn
Signet    sp2pool1p43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5ks0hep27
Regtest   rp2pool1p43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5ksqy32kj
```

### BIP086 key path only tweak applied

The same NUMS pubkey with the BIP086 tweak (empty merkle root), giving
output key `66db9f0ac8ca0a00603027b3a445da6ee2df6c0e04f8dc6f996db4e59d0e45bf`.
These are the addresses genesis actually uses:

```
Mainnet   p2pool1pvmde7zkgeg9qqcpsy7e6g3w6dm3d7mqwqnudcmuedk6wt8gwgklsuackff
Testnet4  tp2pool1pvmde7zkgeg9qqcpsy7e6g3w6dm3d7mqwqnudcmuedk6wt8gwgkls3qc3th
Signet    sp2pool1pvmde7zkgeg9qqcpsy7e6g3w6dm3d7mqwqnudcmuedk6wt8gwgkls4zffd6
Regtest   rp2pool1pvmde7zkgeg9qqcpsy7e6g3w6dm3d7mqwqnudcmuedk6wt8gwgkls63pz3k
```

Note that the two sets differ for the same input pubkey. That is the
point of the tweak, and it is why an implementation must be explicit
about whether it is handed an internal key or an output key.

### Must be rejected

```
sp2pool1q43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5kssufyhq   witness version 0
sp2pool1z43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5ks82qwy4   witness version 2
sp2pool1343yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5ksnrrrlj   first symbol is not a version
sp2pool1pyhy6a                                                        no witness version
sp2pool1px6e0gj7q7xurl08cwnpmeve6w6zf4tw6kz9fv3                       20 byte program
sp2pool1plllllllllllllllllllllllllllllllllllllllllllllllllllskmdz0g   not a curve point
sp2pool1p43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5ks6tfd0u   bech32, not bech32m
p2p1p43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5ks3cfkdm       unknown prefix
```

The bech32 and bech32m entries carry the *same* payload and differ only
in checksum, which is the pair worth testing first in a new
implementation.

Bitcoin addresses must also be rejected, including
`tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqhqjek6`
(taproot), `tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx` (v0) and
`1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` (legacy).

## Where the address appears in consensus

- `ShareHeader.miner_address` (`shares/share_block/mod.rs:72`),
  consensus encoded as a length-prefixed ASCII bech32m string
  immediately after `miner_bitcoin_address` (`:228`, decoded at `:271`).
- The share coinbase pays it: `build_sharechain_coinbase_transaction`
  (`shares/transactions/coinbase.rs:41`) puts
  `miner_address.script_pubkey()` in output 0, valued at one share.
- Validation enforces it: `validate_share_coinbase`
  (`shares/validation/mod.rs:813`) rejects a share whose coinbase output
  0 does not pay the header's `miner_address`.
- `ShareCommitment::hash()` (`shares/share_commitment.rs:207`)
  deliberately does **not** hash `miner_address` directly. It binds
  `merkle_root`, and the share coinbase paying the address is what the
  root commits to. Binding the root rather than the payee covers the
  whole transaction set rather than just the coinbase.

## Obtaining an address

**Get the key from a wallet, not from P2Poolv2.** The recommended source
is a Bitcoin Core wallet, which gives you a taproot key it will custody,
back up and can later sign with.

Ask the wallet for a taproot address, then read its details:

```sh
bitcoin-cli -signet getnewaddress "p2pool share owner" bech32m
bitcoin-cli -signet getaddressinfo <that address>
```

The field you want is **`witness_program`**: the 32 byte taproot output
key, hex. That is exactly the payload a share address encodes, so
re-encoding those bytes as bech32m under the `sp2pool` HRP gives the
share address for that wallet key. No tweak is applied at this step,
because the wallet already applied it -- `witness_program` is the
already-tweaked output key that lands in the `scriptPubKey`.

Do not look for a `pubkey` field. Bitcoin Core omits it for taproot
addresses; the internal key appears only inside the `desc` descriptor,
as `tr([origin]<internal key>)`. Using that internal key means applying
the BIP086 tweak yourself, which `witness_program` avoids entirely.

Check `"ismine": true` and `"solvable": true` in the same output. Those
are what tell you the wallet can sign for the key. Do not rely on
`iswatchonly`: Bitcoin Core deprecated it and it now always reports
false.

A worked example, confirmed against Bitcoin Core 30.2 on signet:

```
address           tb1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqq0gh57d
witness_program   a3ea4c1c5f042ae7fbd086bc7f30e2a08c8b6753c4631db7d4b1fcb3ab941900
share address     sp2pool1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqqd9033x
```

Both addresses produce the identical `scriptPubKey`
`5120a3ea4c1c5f042ae7fbd086bc7f30e2a08c8b6753c4631db7d4b1fcb3ab941900`,
which is the check to make when implementing this: the share address and
the wallet's own taproot address must yield the same script.

Note that the taproot address is not itself accepted. `tb1p...` and
`sp2pool1p...` carry the same 32 bytes, but the HRP is part of the
checksum, so the strings are not interchangeable and both parsers reject
the other's form. That is the whole point of the separate type.

**There is no P2Poolv2 tool that performs the bech32m re-encoding
today.** The format is fully specified above, including verified test
vectors, so external tooling can implement it. Until such a tool exists,
the working route for a pool is the operator setting `[stratum]
miner_address` once, so no miner needs to supply an address at all; see
"Supplying an address" below.

A future encoder should take a **public key or output key, never a
private key and never a bitcoin address**. Public key input keeps every
private key outside this project, and is a weak spend-capability signal
in its own right: you cannot produce the pubkey behind someone else's
exchange deposit address, which is the same argument that ruled out
deriving `miner_address` from `miner_bitcoin_address`.

### No P2Poolv2 crate generates private keys

This is a standing constraint, not an oversight. Tools that generate
private keys eventually ship a flaw in doing so: `bx seed` in
libbitcoin-explorer shipped a time-seeded Mersenne Twister and drained
real wallets (Milk Sad, CVE-2023-39910). The hazard is structural rather
than hypothetical here, because this repo already contains deliberately
deterministic RNG paths for simulation, so a key generator would sit one
bad import away from that failure mode.

Beyond entropy, a printed private key is non-revocable and leaks through
shell history, scrollback, tmux buffers, journald and support
screenshots, with no backup, encryption-at-rest or recovery story. A
taproot output key derived from such a key is equally a valid bitcoin
address, so any miner who funds it puts real BTC behind it.

The node only ever needs the *address* to build the share coinbase
output, so the constraint costs nothing operationally. `rand` is used
only for session nonces, compact block salt, API auth material and
simulation jitter.

## Supplying an address

The share address comes from the operator's config or from the miner,
and the operator wins.

### From the miner: the stratum password

Set the stratum password to `p2p=<address>`. It combines with the
existing difficulty hints as a delimiter-separated list, in any order:

```
p2p=sp2pool1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ss5najrp,d=1000
```

Accepted delimiters are comma, space, tab and semicolon. The key `p2p=`
is matched case-insensitively; the address value keeps the case it was
given, so an all-uppercase address works and a mixed-case one is
rejected by the checksum.

The stratum **username** remains the bitcoin payout address, exactly as
before. These are two different addresses on two different chains, and
swapping them is rejected rather than silently accepted.

Note that `p2p=<address>` is 71 characters. Some miner firmware caps the
password field, and a truncated address fails its checksum rather than
silently redirecting shares elsewhere -- which is exactly what the
checksum is for. An operator whose fleet cannot carry 71 characters
should use the config route instead.

### From the operator: `[stratum] miner_address`

```toml
[stratum]
miner_address = "sp2pool1pvmde7zkgeg9qqcpsy7e6g3w6dm3d7mqwqnudcmuedk6wt8gwgkls4zffd6"
```

When set, this address owns **every** share the pool mines, and no miner
needs to change anything. Bitcoin PPLNS payouts still go per miner from
the stratum username, so the operator accumulates the tradable shares
while miners keep their bitcoin payouts. That is a real operating model,
not merely a convenience for fleets that cannot carry a long password.

The address is network-checked at config parse time, so a wrong-network
or malformed value fails at startup with
`Invalid share chain address: <reason>` rather than at authorize.

Setting `miner_address` together with `mode = "hydrapool"` is rejected
at startup with `miner_address cannot be set when mode is hydrapool,
which has no share chain`. Hydrapool builds no share commitment, so the
field could never be used and its presence is a misconfiguration worth
failing on.

### Resolution table

Implemented in `resolve_share_address`
(`stratum/message_handlers/authorize_response.rs:57`).

| `[stratum] miner_address` | `p2p=` in password | Outcome |
|---|---|---|
| set | absent | use the config address |
| set | identical address | use the config address |
| set | different address | reject: conflict |
| set | unparseable | reject |
| unset | valid, matching network | use the miner's address |
| unset | valid, wrong network | reject |
| unset | unparseable | reject |
| unset | absent | reject |
| any | any | Hydrapool mode needs none, and ignores one that is sent |

Two rules drive that table: never silently derive an address, and never
silently substitute one for another. `set + unparseable` rejects rather
than quietly falling back to the config address, because the miner asked
for something specific and the node cannot verify it matches.

Rejection sends a stratum error (`UnauthorizedWorker`, code 24) naming
the actual cause. A second failure on the same connection disconnects
instead. Returning an error immediately on the first attempt would close
the socket without writing anything, leaving the miner with an
unexplained disconnect and nothing to diagnose.

Nothing is adopted on rejection: the session's miner address, username,
bitcoin address and user id all stay unset.

## What you can do with a share today

A miner can **own** a share: the share coinbase pays one share unit to
their taproot output key, and `merkle_root` commits to that coinbase.

A miner cannot yet **spend or trade** one through this node. There is no
transaction construction, no submission path and no CLI command for it.
`handle_stratum_share.rs:51` assembles every share with an empty
non-coinbase transaction list and carries a TODO for the rest.

The validator side is already built: non-coinbase share transactions are
fully verified when they arrive, including taproot script validation via
`bitcoinconsensus`. What is missing is the wallet side that constructs
and signs them.

The practical consequence for miners: use a key your wallet manages and
can export later, not a throwaway. Shares accrue to that key now and
become spendable when the wallet side ships.

## Registration

The HRPs are not yet registered in SLIP-173. Registration is intended,
so that wallet software can recognise the prefix rather than guess.
