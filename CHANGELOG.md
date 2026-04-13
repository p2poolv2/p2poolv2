# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Coinbase maturity validation: prevouts spending coinbase outputs are
  rejected unless the containing block is at least 6048 blocks deep
  (70% of blocks-per-day at 10s block time)

- StoredTxOut struct marking outputs with `is_coinbase` flag in Outputs
  CF

- Batch txid-to-blockhash lookups via `get_blockhashes_for_all_txids`

### Changed

- Replaced `is_missing_any_prevout` with
  `check_prevouts_and_find_coinbase` combining existence check and
  coinbase detection in a single batch read

- Optimised `are_all_txids_confirmed` to use two batch calls instead
  of per-txid individual lookups

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
