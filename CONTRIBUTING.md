# Contributing to P2Poolv2

P2Poolv2 uses the Collective Code Construction Contract (C4) as
adapted in [docs/C4.md](docs/C4.md). It is based on
[42/C4](https://rfc.zeromq.org/spec/42/), and the differences are
listed at the end of that document. Please read it before you send a
patch. We are making changes to C4 as we go along to capture our own
requirements, i.e. this process is continuously under review.

P2Poolv2 is licensed under "MIT OR Apache-2.0". Patches are submitted
under the same license. Add yourself to [AUTHORS](AUTHORS) in your first
patch.

## Issues

Describe the problem you face or observe, not the solution you want.

Good ways to describe an issue:

- ✅ Wallets cannot fetch a transaction by its txid from the P2Poolv2
  Electrum server (`blockchain.transaction.get` is not implemented)
- ✅ Share chain transactions cannot be sent or received, because
  they cannot be serialized or deserialized

Bad ways to describe an issue:

- ❌ Add the `blockchain.transaction.get` method
- ❌ Add serde for share chain transactions

Feature requests and ideas that do not state a provable problem will be
closed.

## Patches

* Fork the repository and work on a topic branch in your fork. Send a
  pull request back to `main`.
* Each patch solves one clear, agreed problem with a minimal solution.
* Rebase your branch on `main` instead of merging `main` into it.
* You are responsible for any code an AI coding assistant wrote for
  you. You can add an "Assisted-by:" trailer of the form Assisted-by:
  NAME:MODEL_VERSION, for example Assisted-by: Claude:claude-opus-4.8

## Commit messages

```
stratum: reject shares for stale jobs

Problem: shares submitted for a job from a previous block are
accepted and wasted in the share chain.

Solution: check the job's prevhash against the current tip and
reject shares for stale jobs.
```

* Title of 50 characters or less, no trailing period, optionally
  prefixed with the area of code changed and a colon.
* A blank line, then a body wrapped at 72 characters that starts with
  "Problem:" and follows with "Solution:".

## Consensus changes

A change to a share chain consensus rule (share validity, proof of
work, difficulty, uncles, chain work, or payout distribution) starts
with a written specification in an issue, not with a patch. The patch
is merged only after the specification reaches consensus, as defined
in section 2.8 of [docs/C4.md](docs/C4.md).

## Before sending a pull request

All of these must pass:

```sh
cargo build --workspace
cargo nextest run --workspace
cargo clippy --workspace --all-targets
cargo fmt --all -- --check
```

Your patch must not lower the project's test coverage as measured by
CI. Add tests for the code you add or change.
