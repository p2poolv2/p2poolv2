**The architecture files are LLM generated. The goal is make it easier
for new comers to the code base and other LLMs to quickly understand
the design and remain consistent with the design choices.**

# Payout Distribution

How a share that finds a bitcoin block splits the reward, in share chain
(P2Poolv2) mode. Hydrapool (`accounting/payout/simple_pplns/`) is out of
scope.

## Rules

`N` = `COINBASE_MATURITY` (6,048), `W` = `PPLNS_WINDOW_SHARES` (120,960),
`p` = paying share height.

1. **Outputs:** donation cut, then fee cut, then the remainder split over
   the window by weighted difficulty.
2. **Anchor:** the window is walked from the paying share's
   `prev_share_blockhash`, never from a node's tip.
3. **Maturity:** a share at height `h` is paid only if `h < N` or
   `p - h >= N`. The walk skips
   `min(N - 1, p.saturating_sub(N))` shares from the anchor, then takes `W`.
4. **Weights:** share difficulty x 10. Each uncle of a paid share: the
   uncle's miner gets 9/10 of its difficulty and the nephew's miner 1/10.
   Uncles use no window slots.
5. **Split:** addresses sorted by string, `amount * weight / total`
   truncated, and the last address gets the remainder.

## Invariants

- **Deterministic.** The distribution is a function of the chain below
  the anchor only. No config, no bitcoin difficulty, no local tip, and no
  validation status. The producer and every validator must build identical
  outputs, so any change to the walk or weights is a consensus change.
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

## Depths

All sized from `PAYOUT_DEPTH = N + W` (127,008). If you change `N` or `W`,
these move with it.

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
| Window walk and weights | `walk_window_entries`, `for_each_credit` (the only place the weights are applied) |
| Entry point | `PplnsWindow::get_distribution_from_start_hash` |
| Every miner's credits (API `/miner`, one walk per anchor) | `PplnsWindow::get_window_credits_from_start_hash`, same walk and weights |
| Producer | `Payout::fill_distribution_from_shares` (`sharechain_pplns/payout.rs`), from `build_output_distribution` (`stratum/work/notify.rs`) |
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
| Output expiry | `test_validate_prevouts_expires_coinbase_roots_below_payout_depth` (`shares/validation/mod.rs`) |
| Fixture coinbases match | `test_fixture_coinbase_reconstruction_matches_bitcoin_merkle_root` (`shares/share_block/mod.rs`, mirrors the walk by hand) |

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
