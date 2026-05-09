# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.10.11] - 2026-05-09

### Changed

- Share header sync now uses height-based DAG walking instead of
  confirmed-chain walk + uncle reference chasing. The sender collects
  ALL valid blocks at each height from the height index, producing a
  complete topologically sorted subgraph. This fixes sync failures
  caused by missing fork block ancestors that the old approach never
  included.

- Locator matching relaxed from confirmed-only to any valid block
  status (HeaderValid, Candidate, Confirmed, BlockValid). This
  prevents follow-up batch failures when the last header in a batch
  was a fork block.

- Receiver supports multiple chain anchors per batch, allowing
  height-based batches with blocks from different branches to
  validate correctly.

### Fixed

- Fork block ancestors missing from header sync response. The old
  confirmed-chain walk + `collect_uncle_chain` missed fork blocks whose
  `prev_share_blockhash` pointed to non-confirmed blocks, causing
  "parent not in batch or store" errors during testnet4 sync.

- Out-of-order header arrival no longer creates phantom entries at
  height 1 in the height index. `initialise_new_header` now returns an
  error when the parent is missing instead of silently defaulting.

- Missing external parents in a share headers batch now trigger a
  retry with a deeper locator instead of dropping the batch.
  HeaderSyncError enum distinguishes retryable errors (missing
  parent/uncle) from non-retryable errors (ASERT mismatch,
  insufficient work). Retry depth is computed from the lowest anchor
  height in the failed batch.

- `build_locator` and `send_getheaders` accept a depth parameter so
  the retry locator can start further back than the confirmed tip.

## [v0.10.10] - 2026-05-06

### Fixed

- Locator response now starts the confirmed chain walk from
  `anchor_height` - `MAX_UNCLES_DEPTH`, ensuring uncle blocks
  referenced by shares near the anchor are included in header
  batches. Previously the walk started at anchor_height + 1, causing
  "Declared uncle not delivered in batch and not in store" errors that
  broke sync between nodes.

- Block fetcher now dispatches body requests to the announcing peer
  (the inv/headers source) when the chain is current. Previously
  round-robin selection often picked a peer that hadn't received the
  body yet, resulting in NotFound responses and 2-7 second lag on
  non-mining nodes.

- Node now retries header sync every 60 seconds when the confirmed
  tip is stale (older than 300 seconds). Previously a single failed
  sync attempt during handshake left the node permanently stuck with
  no recovery path.

- Locator response now chases transitive uncle references
  (uncle-of-uncle chains) so the receiver has all declared uncle
  bodies available. Previously only direct uncles of confirmed blocks
  were included, causing "Declared uncle not delivered in batch"
  errors when an uncle itself referenced another uncle.

## [v0.10.9] - 2026-05-02

### Fixed

- Ignore verify_chain binary from cargo dist release binaries

## [v0.10.8] - 2026-05-02

### Changed

- Streamline header organisation by simplifying the candidate chain
  extension path and removing redundant lookups during header sync.

- Block fetcher now fetches missing blocks in batches instead of
  one at a time, reducing round-trips during sync.

- Buffer out-of-order blocks in the BlockReceiver actor until their
  parent and uncle dependencies are ready, then validate ASERT
  difficulty and commit atomically. Cascading descendants are driven
  iteratively when ancestors arrive.

- Remove `schedule_dependents` from the organise worker.
  `drain_pending_blocks` and the normal block pipeline already handle
  chain advancement, so scheduling dependents caused 40% redundant
  validation work during sync.

- Refactor `get_candidate_blocks_missing_data` into smaller functions
  for readability: `missing_data_scan_start` and
  `scan_heights_for_missing_blocks`.

### Fixed

- Use confirmed tip (not candidate) in `is_current()` to fix slow
  initial sync. The candidate tip is always recent during sync (each
  newly-received header has a fresh timestamp), which prevented inv
  suppression. Using the confirmed tip correctly identifies the node
  as not-current during initial sync, allowing bulk header-first sync
  to run in batches of 2000 instead of one block per inv message.

- BlockReceiver now checks uncle block bodies via `share_block_exists`
  and fetches missing uncles, preventing confirmation stalls when uncle
  bodies were never retrieved.

## [v0.10.7] - 2026-04-28

### Fixed

- Increase `MAX_TIP_AGE_SECS` from 60s to 300s to prevent chain stall
  where inventory messages were ignored after sync. The chance of a
  60s gap is about 1 in 400. At 5min we have a 1 in trillion chance
  now.

## [v0.10.6] - 2026-04-24

### Fixed

- Fix uncle sync errors by skipping uncles when looking for anchor
  and committing new headers so new branch lookups can see them.

- Respond to getdata block for all known blocks, not just confirmed
  ones.

- Update locator handling to use confirmed chain only and remove
  pre-seeding headers when handling headers messages.

- Initialise new header only if it doesn't exist, avoiding
  overwrites during sync.

- Include uncles when building block fetch list during sync.

- Clear block fetcher for any received block to avoid stale
  in-flight requests.

- Include details in Message::NotFound response.

### Changed

- Follow candidate chain for payout distribution.

- Change the testnet4 genesis to today. This is our testnet4 daa
  anchor. Genesis timestamps are now in genesis data.

- Stop clamping asert daa to bitcoin difficulty.

- Refactor extend and reorg candidate functions for clarity.

- Dashboard: show chain tip and height in page title, show
  difficulty, and fix layout for mobile.

### Added

- Add `debug_tools/share_latency.py` for computing share propagation and
  confirmation latencies across nodes from log files. Supports glob
  patterns, per-pair and aggregate statistics, and --include-uncles flag
  to separately track uncle vs confirmed chain latencies.

## [v0.10.5] - 2026-04-20

### Fixed

- Fix shared headers to always include uncles at chain boundary. This
  bug was causing sync to fail when this corner case was reached.

- Send getheaders in response to Inv blockhash for proper sync. We do
  not immediately send ShareBlock now, instead we let getheaders and
  headers sync drive the chain sync.

- Don't emit BlockFetch for ancestors on BlockReceive, reducing
  redundant fetches. Related to the fix in the previous point.

- Fallback to confirmed tip only on NotFound, propagating real store
  errors instead of silently masking them.

### Changed

- Per-peer rate limiting with dedicated service tasks. Each connected
  peer now gets its own spawned task with an independent rate limiter,
  so one flooding peer cannot block requests from others. Requests are
  forwarded via bounded channels with two-tier overload protection:
  channel full (instant disconnect) and rate limit timeout (sustained
  flood disconnect). Peer service tasks are spawned on connection and
  cleaned up on disconnect.

- Raise default max_requests_per_second from 1 to 100 to match sample
  config and support legitimate sync traffic.

- Remove rate limit window config option. The rate limit config uses
  per second semantics, so the window option was unnecessary.

- Check candidate chain (not just confirmed) for is_current

- Send Inv messages with peer block knowledge for protocol correctness

- Remove bitcoin transactions from ShareBlock to reduce message
  size. We will deal with building bitcoin blocks for submitting from
  other pool peers in a later version.

- Ignore Request ShareBlock messages during sync. This avoids block
  fetch storms during initial sync from both sides of the chain,
  genesis and tip.

- Clean up unused peer id from ShareBlockReceived as we don't respond
  to share block received to the same peer now.

## [v0.10.4] - 2026-04-18

## Added

- cargo dist artefact for dashboard static files

## [v0.10.3] - 2026-04-18

- Dashboard: add favicon
- Dashboard: switch to pico dark mode
- Dashboard: add P2Poolv2 logo in nav bar with mission tagline
- Dashboard: add link to p2poolv2.org landing page
- Dashboard: change logout to link style for consistency
- Dashboard: show difficulty alongside bits in share details

## [v0.10.2] - 2026-04-18

- Add testnet4 genesis block

## [v0.10.1] - 2026-04-16

### Changed

- Update version in Cargo.toml

## [v0.10.0] - 2026-04-16

### Added

- Input value sufficiency validation: non-coinbase share transactions
  are rejected if total input value is less than total output value,
  and total input value must not exceed `Amount::MAX_MONEY`
  
- Sigop cost validation: share blocks are rejected when the aggregate
  BIP141 sigop cost exceeds `MAX_BLOCK_SIGOPS_COST` (80000), using
  `Transaction::total_sigop_cost` with the collected spent outputs

- BIP141 witness commitment on the share coinbase: the coinbase now
  carries a second output containing `SHA256d(witness_root ||
  reserved_value)` over wtxids of the share transactions (coinbase
  wtxid replaced with all-zeros per BIP141), and the coinbase input
  carries the 32-byte witness reserved value on its witness stack

- `validate_share_witness_commitment` validator recomputes the
  witness root and compares it against the embedded commitment

- `StoredTxIn` wrapper persists TxIn witness data in the Inputs CF
  (bitcoin's `TxIn::consensus_encode` does not include witness, since
  BIP144 serializes witnesses at the Transaction level)

### Changed

- **Breaking database change**: the Inputs CF now stores TxIn bytes
  followed by the witness encoding via `StoredTxIn`. Existing
  databases populated by earlier versions cannot be read; users must
  resync from genesis. `rm -rf store.db` and then start again.

- `create_coinbase_transaction` now takes the other share
  transactions so it can compute the BIP141 witness commitment

- `validate_share_coinbase` expects two coinbase outputs (payout +
  witness commitment) instead of one

- `validate_scripts` refactored to `validate_scripts_values_and_sigops`
  which collects spent outputs once per transaction and runs script,
  value, and sigop validation in a single pass

### Fixed

- `test_three_nodes_share_sync` ignored: the
  `test_data/share_sync/share_blocks.json` fixture predates the
  BIP141 share coinbase format and needs regeneration

## [v0.9.1] - 2026-04-13

### Changed

- Updated version in Cargo.toml
- Updated release notes to sync with version

## [v0.9.0] - 2026-04-13

### Added

- Coinbase maturity validation: prevouts spending coinbase outputs are
  rejected unless the containing block is at least 6048 blocks deep
  (70% of blocks-per-day at 10s block time)

- StoredTxOut struct marking outputs with `is_coinbase` flag in Outputs
  CF

- Batch txid-to-blockhash lookups via `get_blockhashes_for_all_txids`

- Updated setup instructions to use prebuilt binaries

### Changed

- Replaced `is_missing_any_prevout` with
  `check_prevouts_and_find_coinbase` combining existence check and
  coinbase detection in a single batch read

- Optimised `are_all_txids_confirmed` to use two batch calls instead
  of per-txid individual lookups

- Deduplicate blockhashes before looking up metadata

## [v0.8.0] - 2026-04-12

### Added

- Sharechain PPLNS accounting with running payout distribution,
  reorg handling, fork buffer, and u128 difficulty (#402, #422, #425,
  #426, #429, #430, #433, #434)
- Share validation pipeline: context-free checks, header validation
  during sync, script validation via libbitcoinconsensus, coinbase
  commitment verification, coinbase payout validation, timestamp
  validation, and transaction prevout spend validation (#414, #417,
  #418, #419, #443, #454, #455, #468, #469)
- WebSocket API support and simple dashboard (#399, #400)
- Batch queries for API requests and API request tracing (#445, #453)
- Donation fees in share commitment with required pairing of
  donation/amount config (#438, #439)
- Prepared notify params as first step toward remote mode (#406, #407)
- Solo mode stratum support (#408)

### Changed

- Switched to address-based identification instead of pubkey (#403)
- Improved header and block storage layout (#415)
- Shared PPLNS window with notifier and validation workers (#436)
- Simplified uncles emissions and payout distribution trait (#401, #428)
- Optimised address map and payout distribution collection (#431)
- Changed coinbase nsecs to u64 and network magic (#456, #435)
- Extracted height computation and subsidy calculation (#442)
- Send notify when chain is extended (#421)
- Build system switched to just; brought back jmeter load testing
  (#471, #472)

### Fixed

- Write atomicity during sync (#466)
- Chain sync reliability and block fetching on reconnects (#459, #463)
- Wait for parent share blocks during normal runs (#464)
- Connection health monitoring improvements (#460)
- Docker setup fixes (#470)
- Task failure handling in main.rs (#437)
- Integration test compatibility with validation (#457)

### Removed

- Unused build_notify and extraneous config files (#440, #458)

## [v0.7.0] - 2026-01-24

### Changed

- Performance Optimizations - Replaced JobTracker actor pattern with
  optimized sync primitives, added TCP nodelay, preallocated hashmaps,
  implemented lazy transaction deserialization, and reused HTTP
  clients for Bitcoin RPC calls

- Graceful Shutdown & Signal Handling - Implemented proper exit signal
  handlers with cross-platform support (Unix + Windows), added
  shutdown reason tracking for correct exit codes, and automatic
  metrics saving on shutdown

- Storage Layer Enhancements - Added new database indexes (uncles,
  transactions, candidates/confirmed, spends tracking), implemented
  RocksDB merge operators for thread-safe updates, and reorganized
  store module architecture

- TLA+ Formal Specification - Created formal specifications for share
  chain candidate/confirmation/reorg logic, added fairness properties,
  and documented uncle chain handling

- Share Chain & Reorg Support - Implemented chain reorganization
  support, added uncle block handling with work contribution to
  chain_work, and improved share commitment mechanism linking miner
  shares to Bitcoin coinbase

- Stratum Protocol Improvements - Added duplicate share detection,
  configurable difficulty handling for testing, optional address
  validation, and two-strike policy for authorization failures

- Metrics & Monitoring Fixes - Fixed user/worker counting, improved
  Prometheus exposition for accepted/rejected shares, added coinbase
  reward split metrics, and filtered inactive users from reporting

- Standalone/Hydrapool Mode - Added support for running without chain
  maintenance, optional accounting bypass for 100% donation mode, and
  configurable miner pubkey coinbase building

## Pre v0.7.0

We used tags like hydrapool.v0.x.0 and we didn't keep a changelog.
