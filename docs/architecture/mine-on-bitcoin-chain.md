**The architecture files are LLM generated. The goal is make it easier
for new comers to the code base and other LLMs to quickly understand
the design and remain consistent with the design choices.**

# Mine on the Current Bitcoin Chain

How P2Poolv2 pays shares only for work on the bitcoin chain the paying
block extends, give or take one block. Work on a fabricated bitcoin
block is never paid, work on a hostile fork of bitcoin is paid for at
most the fork's first two blocks, and work on a block that lost an
orphan race is still paid. Tracks issue #652.

## Summary

Every share names the bitcoin block it builds on, its
`bitcoin_header.prev_blockhash`. This document calls that block the
share's **bitcoin prev**. Without a rule on it, a miner could name a
bitcoin prev that does not exist, or one on a hostile fork, and still
collect PPLNS weight. During a fork war, the hostile fork's miners would
then be paid by both chains for the same proof of work.

The design has three parts:

- **A payout rule.** A share's coinbase pays a window share only if that
  share's bitcoin prev is on the bitcoin chain the paying share builds
  on, or one block off it. Every node rebuilds every coinbase, so this is
  a share validity rule.
- **Carried bitcoin headers.** Share messages carry the bitcoin headers a
  receiver needs to place each share's bitcoin prev, outside the share's
  hash. Each node checks them itself.
- **Acceptance needs a known bitcoin prev.** A node accepts a share only
  once it knows the header of the share's bitcoin prev. Fork choice and
  the job builder are otherwise unchanged.

A TLA+ model checks the design (see Formal model).

## Definitions

- **Share chain names** start with `share_`, bitcoin chain names with
  `btc_`.
- `btc_prev(S)`: the bitcoin prev of share `S`, i.e.
  `S.bitcoin_header.prev_blockhash`.
- `share_parent(S)`, `share_uncles(S)`: the share chain parent and uncles
  of `S`.
- `btc_parent(B)`: the parent of bitcoin block `B`.
- **Known header**: a bitcoin header in the node's header store, either
  reported by the local bitcoind or carried with a share and checked (see
  "Checking a header").
- **Paying chain of `S`**: the bitcoin chain ending at `btc_prev(S)`, the
  chain `S`'s coinbase extends if `S` meets bitcoin difficulty.
- **Eligible for `S`**: a bitcoin block `B` is eligible for `S` when `B`
  is on the paying chain of `S`, or `btc_parent(B)` is. A share is
  eligible for `S` when its bitcoin prev is.

## Rules

| Rule | Kind | Why |
|---|---|---|
| A window share is paid only if it is eligible for the paying share | payout validity | the payout rule |
| An uncle is paid only if it is eligible; a nephew gets no bonus for an ineligible uncle | payout validity | uncles cannot launder ineligible work |
| An ineligible share keeps its window slot and is paid zero | payout validity | the window's end stays fixed by the chain |
| A share whose window holds shares but none eligible is `Invalid` | validity | see "When nothing in the window is eligible" |
| A share is accepted only once the header of its bitcoin prev is known | acceptance | every node places every accepted share the same way |
| Carried headers must link to a known header, meet the exact required `bits`, and be at most 2 hours ahead of the local clock | acceptance | each known header cost a full block of real proof of work |
| An honest job builder stops when nothing in its window is eligible | job builder | the share chain it extends is controlled by an attacker |

## Goal and non-goals

**Goal:** a share is paid only for work that could have extended the
paying block's bitcoin chain, give or take one block:

- work on a fabricated bitcoin prev is never paid,
- work on a block that lost an orphan race is paid, and
- work on a hostile fork is paid for at most the fork's first two
  blocks. Work that extends the fork further is never paid by blocks on
  the main chain.

**Non-goals:**

- **Block withholding.** A miner can always discard a share that meets
  bitcoin difficulty. No pool can detect this.
- **Invalid templates.** A miner can mine on a valid bitcoin prev with
  invalid transactions. Detecting this needs the full bitcoin block. The
  effect equals block withholding.
- **Deliberately stale bitcoin prevs.** A miner can choose an old block
  on the paying chain, or a block one off it. That work cannot win a
  block, but it costs the same and does the same damage as withholding.
  This includes a fork miner who keeps mining on the fork's first block
  to stay eligible: that work extends neither chain.
- **Header-only blocks one off the paying chain.** Work on a header with
  no published body is paid if the header is one off the paying chain.
  Publishing such a header costs a full block of proof of work and
  forfeits its reward.

## The payout rule

### Definition

When a node builds or checks the coinbase of share `S`, it computes the
PPLNS window anchored on `share_parent(S)` as today, then pays each window
share `W` only if `W` is eligible for `S`:

- `btc_prev(W)` is on the paying chain of `S` (an ancestor of, or equal
  to, `btc_prev(S)`), or
- `btc_parent(btc_prev(W))` is.

Uncles in the window follow the same rule, and so does the nephew's bonus
for each uncle (see "PPLNS accounting").

### It is measured from the paying share

Eligibility is relative to `btc_prev(S)`, the chain `S`'s coinbase would
extend, never to the checking node's own bitcoind tip. So it depends on
headers alone, and every node that knows the same headers rebuilds the
same coinbase. Measured against each node's own tip, nodes would
disagree on which coinbases are valid.

### What it pays

| `btc_prev(W)` relative to the paying chain | Paid? | Examples |
|---|---|---|
| on it | yes | ordinary shares; deliberately old prevs (a non-goal) |
| one block off it | yes | a block that lost an orphan race; a fork's first block; a header-only block |
| two or more blocks off it | no | a fork's second and later blocks; the second block of a two-block orphan race |
| unknown | never in a window | shares with an unknown bitcoin prev are not accepted |

**Orphans.** Bitcoin blocks `T` and `O` race at the same height and `T`
wins. A share mined on `O` is one block off every later paying chain,
since `btc_parent(O)` is on it, so it is paid for as long as it stays in
the window.

**A hostile fork.** A fork leaves the main chain at block `P` with
blocks `F1, F2, ...`:

- shares on `P` are on the main chain and paid; fork miners producing
  `F1` mine exactly these,
- shares on `F1` are one block off and paid; these produce `F2`,
- shares on `F2` and later are two or more blocks off, and never paid by
  blocks on the main chain.

So a fork costs the main chain at most about two block intervals of the
fork's hashrate each time a fork starts. The same proof of work cannot
both extend the fork past `F2` and earn on the main chain.

**Templates that lag.** A node's template can lag the share chain by a
block: its miners extend a share on block `N` while their own template
still builds on `N`'s parent. `N` is one block off that template's paying
chain, so the shares on `N` are still paid. A template two blocks behind
would leave the newest shares unpaid by its coinbase.

### Why it is a validity rule

Every share's coinbase is rebuilt and compared exactly:
`validate_bitcoin_payout` builds the expected outputs from the PPLNS
window and rebuilds the coinbase, and any mismatch is a `Consensus`
failure. Who gets paid is already part of validity, so the payout rule
changes validity. A rule applied only by honest job builders would not
work, since validators would have to accept coinbases built either way.

## Bitcoin headers

### Why every node must know the same headers

To check `S`'s coinbase, a node must place every bitcoin prev in the
window, about 14 days of them, relative to `btc_prev(S)`, including
blocks that lost orphan races.

The local bitcoind cannot supply that consistently. Bitcoin Core
announces a block only if it made that block its tip, and it does not
fetch an equal-work sibling it receives as a compact block
(`net_processing.cpp`, `// We know something better`). So some nodes'
bitcoinds never learn about an orphan. A node that could not place a
share on it would rebuild a different coinbase and mark `S` `Invalid`
while others accept it.

So shares carry the headers. Knowing more headers never makes anything
eligible beyond one block off the paying chain: a hostile fork's headers
being known everywhere only lets every node agree that its second and
later blocks are two or more blocks off.

### Checking a header

A node checks every carried header itself, with no RPC:

- it links to a known header (its `prev_blockhash`),
- its hash meets its `bits`,
- its `bits` is **exactly** the target the difficulty rules require.
  Within a 2,016-block period that is the parent's `bits`. At a retarget
  boundary it is computed from the period's first and last headers, with
  rust-bitcoin's `CompactTarget::from_next_work_required`. On testnet4,
  the min-difficulty rule and the BIP94 timewarp rule apply as well; they
  have to be implemented on top of rust-bitcoin, which has the parameters
  but not the logic, and
- its timestamp is no more than 2 hours ahead of the local clock. The
  required `bits` depends on timestamps at a retarget boundary, and on
  testnet4 at every block, so without this limit a fake branch could set
  timestamps to make its `bits` easier.

A header that passes cost a full block of real bitcoin proof of work at
the correct difficulty. It does not prove that a valid body exists, and
it does not need to: the payout rule bounds how far off the paying chain
paid work can be.

### What a share carries

For share `S`, the **required headers** are the bitcoin headers on the
path from `btc_prev(S)` back to, but not including, the fork point of
`btc_prev(S)` and `btc_prev(share_parent(S))`.

- Usually `btc_prev(S) == btc_prev(share_parent(S))`, and nothing is
  required.
- In the first share after a new bitcoin block, one header is required.
- After a bitcoin reorg, the headers back to the fork point are required.

The first share of every `ShareHeaderBatch` also carries the path from
`btc_prev(S)` back to the first header on the sender's bitcoind active
chain. The receiver may never have seen that share's parent, so it cannot
rely on knowing the parent's bitcoin prev. The first header on the
sender's active chain is old main chain history, which the receiver's
bitcoind has. This is also how a syncing node learns the headers of
orphans from weeks ago.

### Where they travel

Alongside the share header in P2P messages, as the coinbase merkle branch
already does:

- `ShareHeaderBatch` gets a list of bitcoin headers, deduplicated the way
  `branches` already are. A batch of 2,000 shares spans about 33 bitcoin
  blocks, so about 2.6 KB.
- Share block messages and announcements carry the required headers of
  that share.

They are **not** part of the share's hash:

- `btc_prev(S)` is already bound by the share's proof of work.
- A block hash fixes the header it names, and each header's
  `prev_blockhash` fixes the one before it, so the required headers are
  fully determined by data the share already commits to.
- A sender can only leave headers out or add wrong ones. A missing header
  leaves `btc_prev(S)` unknown, so the share is not accepted until a copy
  with the headers arrives. A wrong header fails the check.
- One proof of work is still one share hash, whatever headers travel
  with it.

### The header store

The node keeps full headers with their heights and parents. Acceptance
and payout checks read only this store. It is fed by:

- **zmq `sequence` events** from the local bitcoind. A block connect
  (`C`) adds the block; a disconnect (`D`) does not remove it.
  `sequence` numbers every message, so a gap shows one was missed.
- **The `getchaintips` RPC**, at startup and after a gap in sequence
  numbers or a zmq reconnect. Walk each listed branch back with
  `getblockheader` until reaching a header already in the store.
- **Carried headers** that pass the check.

**Retention.** Payout checks place bitcoin prevs about 14 days back from
the paying share, and nodes validate shares up to `PRUNE_DEPTH` (about 28
days) deep. So the store keeps headers for at least the window plus
`PRUNE_DEPTH` plus one retarget period: roughly six weeks, about 6,000
headers.

**Eligible set.** Eligibility for `S` changes only when `btc_prev(S)`
changes, about every 10 minutes. Compute the set of eligible bitcoin
blocks once per paying bitcoin prev, by walking the paying chain back over
the window's span and adding each block's known children, and reuse it
for every share on that bitcoin prev.

## Accepting a share

The same steps apply to a share header in a `ShareHeaderBatch` and to an
unsolicited share block. None of them waits on bitcoind.

1. **Parent or uncle unknown.** If the share's parent or an uncle is
   unknown even as a header, drop the share. Recovery is the existing
   missing-parent handling: an unknown parent makes the node ask the
   sender for headers (`request_headers_for_missing_blocks`), and the
   reply now also carries the bitcoin headers.
2. **Check the carried headers.** Skip headers already known, check
   oldest first and stop at the first failure, and skip header hashes
   that failed recently (a bounded cache). Headers that pass go into the
   header store.
3. **Bitcoin prev known.** If the header of `btc_prev(S)` is now known,
   carry on as today: store the share header, fetch and validate the body
   (including the payout rule), and organise it.
4. **Otherwise drop it.** It is not stored, validated or relayed, and it
   gets no verdict. Its hash goes into a bounded, expiring cache of
   dropped shares, so a child naming it is dropped without asking for it
   again. In a `ShareHeaderBatch`, the rest of the batch depends on it,
   so the batch stops there.

**Why acceptance needs a known bitcoin prev.** Without it, an attacker
could mine a share on a real orphan and send it with headers to some
nodes and without to others. Nodes would then place it differently in
later windows and disagree on later coinbases. Requiring the header at
acceptance means every accepted share's bitcoin prev is in every
accepting node's header store. Shares on a fabricated bitcoin prev never
get a header, so they are never accepted.

**An honest share is almost never dropped.** Its parent was accepted
first, so its carried headers link onto a bitcoin prev the node knows.
What remains is a relay that leaves headers out, and a local clock more
than 2 hours behind. Either way the share comes back when a descendant
names it as parent and the missing-parent handling fetches it again.

Initial block download cannot cause drops: the node does not start until
bitcoind has finished it (`wait_for_bitcoin_node_synced` in
`p2poolv2_node/src/preflight.rs`).

**Example.** Shares `A -> B -> C -> D`. B is the first share after a new
bitcoin block `N`, so B carries `N`'s header. C also builds on `N`, so C
carries none.

1. A arrives and is accepted.
2. B is lost or late.
3. C arrives. Its parent B is unknown, so C is dropped (step 1), and the
   node asks the sender for headers. The reply carries B and C, with
   `N`'s header on B. B and C are accepted, and their bodies are fetched.
4. If that request fails, D arrives, its parent C is unknown, and the same
   recovery runs for B, C and D.

## Fork choice and the job builder

Fork choice, the candidate and confirmed chains, the mining base search
and uncle selection are unchanged. Every node accepts every valid share
whose bitcoin prev it knows, so nodes hold the same shares. Honest miners
may build on a hostile fork's shares; their coinbases just do not pay
them.

The job builder builds coinbases with the payout rule, so it needs the
template's bitcoin prev when it computes the PPLNS distribution. A new
template already triggers a new job, so a new bitcoin prev already
produces a new coinbase.

If nothing in its window is eligible, the job builder stops the node (see
"When nothing in the window is eligible").

## PPLNS accounting

### The window

- The window is the last `PPLNS_WINDOW_SHARES` (120,960) shares, counted
  back from the anchor, the paying share's parent. Each share is weighted
  by its difficulty and uses one slot (`accumulate_candidate_difficulty`,
  `accumulate_confirmed_difficulty`).
- Uncles use no slots. An uncle's miner gets 9/10 of the uncle's
  difficulty, and the nephew's miner a 1/10 bonus (`add_entry_difficulty`).
- The cache holds the window plus a 1% buffer (`cache_capacity`, about
  122,000 entries). An anchor too deep for the buffer gives
  `InsufficientEntries`, and the share is dropped as `Unresolvable`.
- The same `get_distribution_from_start_hash` builds jobs (`payout.rs`)
  and checks payouts (`validate_bitcoin_payout`).

With the payout rule, whether an entry is paid depends on the paying
share's bitcoin prev as well as the anchor. All the shares mined on one
bitcoin block, about 60, see the same eligible set.

### Ineligible shares keep their window slots

An ineligible share counts towards the 120,960 like any other, and its
weight is zero.

**Expected payouts are unchanged.** Let the window hold `N` shares, a
fraction `u` of them ineligible, and let each eligible share find a block
with probability `p`, for a reward `R`.

- An eligible share stays in the window for the next `N` shares. About
  `(1 - u) * N` of them are eligible and can find blocks, so about
  `(1 - u) * N * p` blocks are found while it is in the window.
- Each of those blocks splits `R` among about `(1 - u) * N` eligible
  shares.
- So an eligible share expects `(1 - u) * N * p * R / ((1 - u) * N) =
  p * R`, the fair value.

**Variance rises by a factor of `1 / (1 - u)`.** Fewer blocks are found
while a share is in the window, and each pays it a larger slice. This
matters only while ineligible shares make up a large part of the chain
honest miners extend, for example during a fork war.

**Why ineligible shares do not skip their slots.** The window would then
reach back until it had counted 120,960 eligible shares:

- its end would depend on the paying share's bitcoin prev and on how many
  ineligible shares there are, not on the chain alone,
- the cache would need about `120,960 / (1 - u)` entries. The 1% buffer
  covers only `u` up to 1%, so a fork miner with 2% of share hashrate
  would make every payout check `Unresolvable` and stall the network, and
  growing the cache instead means memory that grows with the attacker's
  share rate, and
- expected payouts would be the same `p * R`; only variance would be
  lower.

### Uncles

- An ineligible uncle gets no uncle weight, and the nephew gets no bonus
  for it, so honest nephews gain nothing by including fork shares.
- An eligible uncle under an ineligible nephew gets its uncle weight. The
  bonus belongs to the nephew, which is not paid, so it is not paid.
- Uncles still use no window slots.

### When nothing in the window is eligible

**Building a job: the node stops**, as it does today for an empty
window. The job builder's window is the share chain this node's miners
extend, measured from its own template. If none of it is eligible, an
attacker controls the share chain, and the node should stop rather than
mine.

**Checking a share: it is `Invalid`.** A checking node must not stop,
because anyone can make such a share for one share's proof of work:

- mine a share whose bitcoin prev is a main chain block from more than 14
  days ago; its header is public and passes every check,
- its paying chain ends at that old block, and every bitcoin prev in its
  window is a later main chain block, so none is on or one block off
  that chain, and the whole window is ineligible.

Marking it `Invalid` is deterministic, and no honest share has an empty
eligible set: an honest share's paying chain ends at its node's current
template, which its window's recent shares are on or next to. A window
with no shares at all, at the start of the share chain, is not this
case.

A share whose bitcoin prev is old but still inside the window is valid.
Its coinbase pays only the window shares eligible for that old chain, and
every node rebuilds the same coinbase. It is a deliberately stale share
(a non-goal), and it affects only its own coinbase.

### Implementation

- **Cache entries.** `ConfirmedEntry` and `UncleEntry` gain the share's
  bitcoin prev, stored as an index into the header store rather than 32
  bytes. Entries built from candidate headers need it too.
- **Eligible set.** Computed once per paying bitcoin prev (see "The header
  store"). Each window entry then costs one lookup, on top of the walk
  the window already does.
- **API.** `get_distribution_from_start_hash` and
  `fill_distribution_from_shares` take the paying share's bitcoin prev:
  the share's own when checking, the template's previous block when
  building a job.
- **Activation.** Shares below the activation height keep the old rule,
  so the payout code needs to know which rule applies to each paying
  share.
- **If payout checks become slow:** keep per-address sums grouped by
  bitcoin prev, since a window has only about 2,000 distinct ones, so a
  distribution is a sum over the eligible groups.

Hydrapool's time-window PPLNS mode does not use this window and is not
affected.

## What the design costs

- **A validity change**, needing a coordinated upgrade (see Deployment).
- **Hostile forks are paid for about two block intervals** of their
  hashrate each time a fork starts.
- **Header-only work one off the paying chain is paid**, at the cost of a
  full block of proof of work.
- **Two-block orphan races.** Shares on the second block of the losing
  branch are not paid. Such races are rare.
- **Higher payout variance during a fork war**, by `1 / (1 - u)` while a
  fraction `u` of the chain is ineligible. Expected payouts are
  unchanged.
- **More work per payout check**: an eligibility lookup per window entry,
  from a set computed once per paying bitcoin prev.
- **Difficulty code.** Exact `bits` needs the retarget calculation, and on
  testnet4 the min-difficulty and BIP94 rules, written in the node.
- **Signet is weakly protected.** A signet block's validity comes from a
  signature in its body, and its header proof of work is nearly free, so
  a fake signet branch costs almost nothing. The payout rule still limits
  paid work to one block off the paying chain.

## Denial of service

### What an attack costs

- **Share proof of work.** Every share must meet the minimum share
  difficulty (`MAX_POOL_TARGET` = `0x1b384bd7`, about difficulty 1,165,
  roughly 5e12 hashes) and pass the coinbase proof. One proof of work
  gives exactly one share hash. A 100 TH/s machine makes about 20 shares
  a second.
- **Size.** A share block is at most 200 kB (`BLOCK_TXS_SIZE_LIMIT`), and
  its body must match its header.
- **Rate limits.** Unsolicited share blocks pass the per-peer rate limiter
  (`max_requests_per_second`, 100 in the sample configs). Up to 50
  inbound peers are allowed, and peer identities are free, so the rate
  limiter bounds one connection, not an attacker.
- **No other penalty.** The only sanction is disconnecting a peer.

### A gap that exists today

`BlockReceiver` buffers a share whose parent or uncles are not ready in
`pending`, a `HashMap` with no capacity limit and no expiry
(`block_receiver.rs`). A share naming a random parent hash passes every
check at receipt and then waits forever. One 100 TH/s machine can grow
that map by about 4 MB a second, on every node it connects to. This is
independent of issue #652 and should be fixed on its own.

### Changes

| Change | Required | Stops |
|---|---|---|
| 1. Drop a share whose parent or uncle header is unknown, instead of buffering it (recovery is the existing missing-parent header request) | yes, independent of #652 | fabricated-parent floods (today's gap) |
| 2. Cap the parent-wait buffer, evicting the longest-waiting entry, and drop entries whose parent fell below `current_prune_height()` | yes, independent of #652 | memory exhaustion from withheld bodies |
| 3. Drop shares whose bitcoin prev is unknown, with a bounded, expiring cache of dropped hashes | yes, for #652 | memory cost of fabricated-prev shares, and repeat fetches of them |
| 4. Cap carried headers per share and per batch in the decoder (about 100), check them locally, stop at the first failure, cache failed hashes | yes, for #652 | message size and header-check load: a fabricated header costs one local check, no RPC |
| 5. Disconnect a peer whose share still has an unknown bitcoin prev after its carried headers are checked | optional | bandwidth from one connection |

Per-peer quotas on the buffers are not needed: with free peer identities,
an attacker spreads its entries across connections, and a global cap
gives the same memory bound more simply.

With changes 1 to 4, the memory an attacker can occupy is bounded by the
parent-wait cap and the cache of dropped share hashes, and a fabricated
header costs one local check. Ineligible shares are not a memory cost of
their own: they are ordinary accepted shares, each paid for with share
proof of work.

## Deployment

The payout rule changes share validity: a node with the rule and one
without rebuild different coinbases for any share whose window holds an
ineligible share. Share messages also gain carried headers.

- Activate it at a fixed share chain height, or with the planned chain
  reset, behind a protocol version bump. Shares below the activation
  height keep the old payout rule.
- New nodes should not exchange shares with old ones.

## Alternatives considered

- **Accept only shares whose bitcoin prev is within `K` blocks of the
  local active chain.** It would let a hostile fork's miners be paid for
  its first `K` blocks of work while they attack the main chain. And
  since it depends on each node's active chain, a bitcoin reorg makes
  nodes disagree for good on which shares they hold.
- **The payout rule with bitcoind's headers only.** Nodes would disagree
  on coinbases whenever some bitcoinds never saw an orphan. The only
  consistent version pays work on the paying chain alone, which stops
  paying orphans.
- **Ineligible shares skip their window slots.** See "Why ineligible
  shares do not skip their slots".
- **Validity rules on bitcoin chainwork and fork depth along the share
  chain.** A header-only block passes them, they do not stop the second
  and later blocks of a fork from being paid, and they need the same
  header knowledge as the payout rule.
- **Passing each carried header to bitcoind (`submitheader`) before
  accepting the share.** An RPC round trip per new header, and a way for
  attackers to load bitcoind. The local check is enough.
- **Checking only that a header's hash meets its own `bits`**, or `bits`
  within 4x at a retarget boundary. A fake branch could use easy `bits`,
  at a quarter of a block per header or less.

## Open items

- **Checking a share with nothing eligible.** The decision was to stop
  the node. That is kept for the job builder, but a checking node marks
  the share `Invalid` instead, since an old bitcoin prev produces such a
  share for one share's proof of work. To confirm.
- **Pending-buffer gap.** Changes 1 and 2 under "Denial of service" fix
  an existing unbounded buffer and are independent of this design. They
  should be tracked as their own issue.
- **Found-block records.** `bitcoin_height` and `bitcoin_header.bits` of
  a share's own bitcoin header are not checked. A share can claim easy
  `bits` and show up as a found block in the found-block records and the
  effort metrics. Record a found block only if the local bitcoind
  accepted it.

## Formal model

The TLA+ spec is in `spec/BitcoinChainSync/`:

- `BitcoinChainSync.tla`: about 360 lines.
- `BitcoinChainSync.cfg`: two honest nodes.
- `BitcoinChainSyncAttacker.cfg`: adds an attacker that mines shares on
  any bitcoin prev (fabricated, old, header-only or on a hostile fork),
  with any parent and uncle, and publishes blocks honest bitcoinds do not
  accept.

The model covers:

- a bitcoin block tree in which some blocks are never accepted by honest
  bitcoinds; they stand for header-only blocks and hostile forks,
- each node's bitcoind behaving like Bitcoin Core: its tip moves only to
  a block with more work, and headers arrive from the bitcoin network only
  sometimes,
- acceptance: a share is accepted once its parent and uncles are, and its
  bitcoin prev's header is known using its carried headers, which come
  from any honest node that accepted the share or from the attacker that
  mined it; a share that cannot be accepted yet can be later,
- the job builder unchanged: the highest accepted share as parent,
  accepted shares as uncles, with the uncle position rules from
  `validate_uncle_positions`, and stopping when nothing in its window is
  eligible,
- the payout rule: a window of `PplnsWindow` shares from the parent in
  which ineligible shares keep their slots, uncles paid only if eligible,
  and a share with nothing eligible rejected, and
- shares that meet bitcoin difficulty becoming bitcoin blocks.

Payouts are modelled as the set of shares paid, not amounts.

Two switches reproduce the failures the design avoids:

- `CarryHeaders = FALSE`: shares carry no bitcoin headers.
- `PayoutRule = FALSE`: coinbases pay the whole window.

It checks:

- `PoolBlocksPayOnlyWorkNearTheirChain`: a pool block on the main chain,
  found by an honest miner or by an accepted attacker share, never pays
  work on a fabricated bitcoin prev or more than one block into a branch
  honest bitcoinds do not accept.
- `StoreHoldsValidHistory`: every accepted share's parent and uncles are
  accepted, its bitcoin prev's header is known, and its window has
  something eligible.
- `AcceptAgreement`: once settled, honest nodes hold the same shares.
- `HonestWorkPaidWhenSettled`: once settled, a share mined on the common
  tip would pay every honest share in its window, including uncles and
  shares mined on orphans.

Settled means every bitcoind is on the same tip and no node can accept
any more shares.

It assumes every bitcoin block and share has equal work. It does not
model header proof of work and timestamps (every existing header is
valid), payout amounts and variance, the PPLNS cache buffer, notify
timing, or hashrate. With 4 or 5 bitcoin blocks, a two-block orphan race
cannot occur, so honest work is always within one block of the common
chain.

Results, with 2 honest nodes and a window of 3 shares:

| Config | Bounds | Result |
|---|---|---|
| Honest only, `CarryHeaders = FALSE` | 4 blocks, 4 shares | fails `AcceptAgreement` at depth 8: nodes hold different shares when an orphan's header reaches only some bitcoinds |
| Honest only | 4 blocks, 4 shares | pass, exhaustive, 1.3M distinct states |
| With attacker, `PayoutRule = FALSE` | 4 blocks, 4 shares | fails `PoolBlocksPayOnlyWorkNearTheirChain` at depth 8: an honest block pays a share two blocks into a hostile fork |
| With attacker | 4 blocks, 3 shares | pass, exhaustive, 5.3M distinct states |
| With attacker | 4 blocks, 4 shares | no violation in 44.4M distinct states (15 minute limit) |
| With attacker | 5 blocks, 5 shares | no violation in 22.1M states (simulation, 5 minutes) |

Run with a heap cap, for example:

```
java -Xmx4g -cp tla2tools.jar tlc2.TLC BitcoinChainSync.tla \
  -config BitcoinChainSyncAttacker.cfg -workers 8
```
