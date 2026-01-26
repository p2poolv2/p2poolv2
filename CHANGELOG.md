# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
