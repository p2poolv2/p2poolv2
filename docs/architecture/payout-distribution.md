**The architecture files are LLM generated. The goal is make it easier
for new comers to the code base and other LLMs to quickly understand
the design and remain consistent with the design choices.**

# Payout Distribution

How a share that finds a bitcoin block splits the reward, in share chain
(P2Poolv2) mode. Hydrapool (`accounting/payout/simple_pplns/`) is out of
scope.

## Rules

`N` = `COINBASE_MATURITY` (6,048), `W` = `PPLNS_WINDOW_SHARES` (120,960),
`K` = `BCH_PPLNS_WINDOW_BLOCKS` (3), `p` = paying share height, `D` = the
difficulty of the paying share's own bitcoin header (`bitcoin_header.bits`,
through `bitcoin_block_difficulty`).

1. **Outputs:** donation cut, then fee cut, then the remainder split over
   the window by weighted difficulty.
2. **Anchor:** the window is walked from the paying share's
   `prev_share_blockhash`, never from a node's tip.
3. **Maturity:** a share at height `h` is paid only if `h < N` or
   `p - h >= N`. The walk skips
   `min(N - 1, p.saturating_sub(N))` shares from the anchor, then takes the
   window.
4. **Window:** on Bitcoin, `W` shares. On Bitcoin Cash, the shares up to and
   including the first one that brings the window's work to `K * D`, at most
   `W` shares. A share's work is its difficulty plus its uncles'. If
   `D <= 1` (the header is at the network's proof-of-work limit) the window
   is `W` shares. See "Bitcoin Cash window" below.
5. **Weights:** share difficulty x 10. Each uncle of a paid share: the
   uncle's miner gets 9/10 of its difficulty and the nephew's miner 1/10.
   Uncles use no window slots.
6. **Split:** addresses sorted by string, `amount * weight / total`
   truncated, and the last address gets the remainder.

## Invariants

- **Deterministic.** The distribution is a function of the chain below
  the anchor and, on Bitcoin Cash, the paying share's own header only. No
  config, no difficulty from a node's own bitcoin node, no local tip, and no
  validation status. The producer and every validator must build identical
  outputs, so any change to the walk, the window or the weights is a
  consensus change.
- **One code path.** The notifier (`Payout::fill_distribution_from_shares`)
  and the validator (`validate_bitcoin_payout`) call the same
  `PplnsWindow::get_distribution_from_start_hash` on the same shared window,
  and both turn bits into `D` with `bitcoin_block_difficulty`. The notifier
  reads the bits from its template. They are the bits the share's header
  carries, because a stratum miner cannot change them and a declared job must
  keep them (`validate_custom_job` checks `nbits`). The validator reads them
  from the header.
- **Payee is `miner_bitcoin_address`.** Never `miner_address`.
- **No fallback payee.** An empty window, zero total weight, an unresolved
  anchor or a store error is an `Err`. Never pay `bootstrap_address`: it
  is node-local.
- **Candidate shares count like confirmed shares** towards both the skip
  and the window.
- **Immature shares are a prefix of the walk.** Heights fall by one per
  parent step, so one skip count is exact. Do not filter per share.
- **The first `N` shares are always mature for payout only.** Spending
  still needs depth `N` (`check_prevouts`).
- **Uncles need no maturity rule.** An uncle is at most `MAX_UNCLES_DEPTH`
  below its nephew, so it is never shallower than it.
- **A truncated walk is refused.** If the cache runs out before `W` shares
  and the cache does not reach height 0, return `InsufficientEntries`.
  Validation maps it to `Unresolvable`.

## Bitcoin Cash window

Bitcoin Cash sets `D` every block with ASERT, so `K * D` is `K` blocks' worth
of work for the pool. The window therefore spans about `K` of the pool's own
blocks at any pool size: short for a large pool, long for a small one, and
shorter by itself if BCH blocks get faster (CHIP-2025-03). At 10-second
shares and 10-minute blocks the window is about `K * 60 / f` shares for a
pool holding fraction `f` of BCH's hashrate, so pools under about `K / 2016`
(0.15%) reach the cap and pay exactly upstream's fixed window.

| Pool share of BCH | Window (K = 3) |
|---|---|
| 0.05% | capped at 120,960 shares, about 14 days |
| 1% | about 18,000 shares, 50 hours |
| 10% | about 1,800 shares, 5 hours |
| 30% | about 600 shares, 100 minutes |

- **Why `D` comes from the paying header.** BCH accepts a block only with the
  correct ASERT bits, so a coinbase that reaches the chain was sized by the
  real difficulty. A share that is not a block can carry any bits, but its
  coinbase never reaches the chain, so mis-sizing it pays nobody. A node's
  own BCHN, template or config would differ between nodes; upstream dropped
  its earlier window sized by local difficulty and `difficulty_multiplier`
  for that reason.
- **Why `K = 3`.** It is P2Pool v1's value on BCH (below). A share is paid
  by the blocks found while it is in the window, a Poisson count with mean
  `K`. With 3, a share misses every block 5% of the time and its payout
  varies by 58%; with 2, 13.5% and 71%. The window, the delay to be paid and
  how long a miner is paid after stopping grow linearly with `K`. In the
  offline simulation (`pplns_compare`), 3 instead of 2 moves a 0.1% miner's
  daily income variation from 0.47 to 0.43 at 10% of BCH and from 0.44 to
  0.41 at 30%, close to the spread across seeds (about 0.03), for under 1.5
  hours more delay there and about 8 hours more at 1%. Either value is
  defensible; 3 is the one v1 ran on BCH.
- **Prior art.** P2Pool v1 for BCH
  ([jtoomim/p2pool](https://github.com/jtoomim/p2pool)) sized its window the
  same way. `p2pool/networks/bitcoincash.py` sets `SHARE_PERIOD = 60`,
  `REAL_CHAIN_LENGTH = 3*24*60` (4,320 shares, three days) and `SPREAD = 3`.
  `generate_transaction` in `p2pool/data.py` walks back from the previous
  share for at most `min(height, REAL_CHAIN_LENGTH) - 1` shares and stops at
  a desired weight of `65535 * SPREAD * target_to_average_attempts(block_target)`,
  three expected blocks of work, where `block_target` is the paying share's
  own header bits. Differences here: v1 scales the share that crosses the
  target down to hit it exactly, while this rule pays that share whole, so a
  window holds at most one share's work more than `K * D`; v1 had no
  maturity skip, a 0.5% finder bonus and a three-day cap at 60-second
  shares, where this fork keeps the maturity skip and a 14-day cap at
  10-second shares. The idea is reimplemented here; no v1 code is copied
  (plan decision 10).
- **Minimum-difficulty headers.** Chipnet and testnet accept a difficulty-1
  block 20 minutes after its parent, and every regtest block is at the
  proof-of-work limit. Such a header says nothing about the pool's block
  rate, so a `D` of 1 or less pays `W` shares, as on Bitcoin, instead of
  shrinking the window to one share. Falling back to an older header was
  rejected: only a found block's bits are checked by BCH, so the bits in any
  other share are the miner's choice. Mainnet never has such a block. The
  load-test sim runs on regtest, so it still pays `W` shares.
- **Truncation.** A walk that reaches `K * D` inside the cache is a property
  of the chain even when the cache no longer reaches height 0. Only a walk
  that runs out of cached entries before either bound is refused.
- **Activation.** The rule is consensus, and nodes on different rules
  rebuild different coinbases for every share and fork the share chain. The
  BCH chains are alpha and run by their operators, so the change ships as a
  flag day: every node upgrades in one release and starts from a new store
  path, as the upstream sync did, so no share on the new chain was made
  under the old rule. Nodes left on the old rule reject the new shares and
  keep their own chain; miners lose only their share-chain position, because
  payouts are coinbase outputs on BCH. Mainnet starts with the rule from its
  first share, so it needs no activation height.

## Depths

All sized from `PAYOUT_DEPTH = N + W` (127,008). If you change `N` or `W`,
these move with it. The Bitcoin Cash window is at most `W` shares, so it
needs no more depth than the fixed window.

| Quantity | Value | Where |
|---|---|---|
| Window cache | `N + W + W/100` | `PplnsWindow::cache_capacity` |
| Full-validation zone | `PAYOUT_DEPTH` | `is_in_pplns_zone` |
| Output expiry | `PAYOUT_DEPTH` | `validate_prevouts` (`min_coinbase_root_height`) |
| Body retention | `2 * PAYOUT_DEPTH` | `PRUNE_DEPTH` |

See `pruning.md` for the two-window retention model.

## Code map

| What | Where |
|---|---|
| Constants, weights | `accounting/payout/sharechain_pplns/pplns_window.rs` |
| Anchor walk | `PplnsWindow::resolve_start_hash`, `collect_candidate_headers` |
| Paying height | `PplnsWindow::paying_height` |
| Maturity skip | `PplnsWindow::immature_share_count` |
| Window rule | `PplnsWindow::for_chain`, `resolve_window` (`work_target`), `BCH_PPLNS_WINDOW_BLOCKS`, `MIN_SIZING_BLOCK_DIFFICULTY` |
| Bits to `D` | `bitcoin_block_difficulty` |
| Window walk and weights | `walk_window_entries` (with `ConfirmedEntry::work` for the BCH bound), `for_each_credit` (the only place the weights are applied) |
| Entry point | `PplnsWindow::get_distribution_from_start_hash` |
| Every miner's credits (API `/miner`, one walk per anchor) | `PplnsWindow::get_window_credits_from_start_hash`, same walk and weights; on BCH the API sizes it from the anchor share's own header |
| Producer | `Payout::fill_distribution_from_shares` (`sharechain_pplns/payout.rs`), from `build_output_distribution` (`stratum/work/notify.rs`); the window is built by `build_payout_for_mode` (`accounting/payout/mod.rs`) |
| Cuts and split | `include_address_and_cut`, `append_proportional_distribution` (`accounting/payout/payout_distribution.rs`) |
| Validator | `validate_bitcoin_payout` (`shares/validation/mod.rs`) |

## Tests that pin the rules

Use `PplnsWindow::new_with_window_sizes(network, maturity_skip, window)` to
test with small values (for example 3 and 2).

| Rule | Test (`pplns_window.rs` unless noted) |
|---|---|
| Skip, first paid share at depth `N` | `test_distribution_skips_immature_shares_from_anchor` |
| Skip spans candidate and confirmed | `test_distribution_skip_spans_candidate_and_confirmed_entries` |
| No skip while `p < N` | `test_distribution_does_not_skip_before_maturity_height` |
| Early shares stay mature | `test_distribution_keeps_early_shares_mature_after_bootstrap` |
| Full skip at `p = 2N - 1` | `test_distribution_skips_full_maturity_after_early_shares_age_out` |
| Truncated walk refused | `test_distribution_refuses_when_skip_and_window_exceed_cache` |
| Miner credits equal the distribution | `test_window_credits_match_the_distribution_for_every_payout_address` |
| BCH: large pool pays `K` blocks of work | `test_bch_window_large_pool_pays_three_blocks_of_work` |
| BCH: the share reaching `K * D` is paid | `test_bch_window_includes_the_share_that_reaches_the_work_target` |
| BCH: small pool capped at `W` | `test_bch_window_small_pool_is_capped_at_window_shares` |
| BCH: minimum-difficulty block pays `W` | `test_bch_window_minimum_difficulty_block_pays_the_capped_window`, `test_bch_window_zero_difficulty_block_pays_the_capped_window`, `test_chipnet_minimum_difficulty_bits_have_difficulty_one` |
| BCH: uncles count towards `K * D` | `test_bch_window_counts_uncle_work_towards_the_target` |
| BCH: truncation | `test_bch_window_refuses_when_work_target_runs_past_the_cache`, `test_bch_window_reached_inside_the_cache_is_paid` |
| Bitcoin keeps `W` | `test_bitcoin_window_ignores_paying_block_difficulty` |
| Producer and validator agree | `test_bch_notifier_and_validator_build_identical_outputs`, `test_bch_validator_with_other_header_bits_builds_other_outputs` (`sharechain_pplns/payout.rs`) |
| Output expiry | `test_validate_prevouts_expires_coinbase_roots_below_payout_depth` (`shares/validation/mod.rs`) |
| Fixture coinbases match | `test_fixture_coinbase_reconstruction_matches_bitcoin_merkle_root` (`shares/share_block/mod.rs`, mirrors the walk by hand) |

The offline `pplns_compare` binary (`p2poolv2_sim`, `sim` feature) pays one
drawn share chain per pool size with both window rules through the real
`PplnsWindow` and prints window length, payout delay and income variance; see
`docs/simulation/overview.md`.

End to end, the sim `late-miner` scenario checks the maturity rule against real
regtest coinbases (`load-tests/sim/maturity_check.py`, RUNBOOK Test G). It
lowers the maturity through `sim_overrides::coinbase_maturity()`, which is the
value `PplnsWindow::new` and `validate_prevouts` read; production builds
always use `COINBASE_MATURITY`.

## Example (N = 6,048)

| `p` | skip | newest paid height |
|---|---|---|
| 5,000 | 0 | 4,999 |
| 9,000 | 2,952 | 6,047 |
| 12,096 | 6,047 | 6,048 |
| 20,000 | 6,047 | 13,952 |

Between `p` = 6,048 and 12,095 the newest paid share stays at 6,047 while
newer shares mature.

## Related

- `mine-on-bitcoin-chain.md`: a window share whose bitcoin prev is not
  eligible keeps its slot and is weighted zero.
- `share-processing-pipeline.md`: where payout validation sits in the
  pipeline.
