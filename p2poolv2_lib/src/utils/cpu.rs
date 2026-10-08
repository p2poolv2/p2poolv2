// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CPU topology helpers.
//!
//! `available_parallelism()` from the standard library respects
//! cgroups v1/v2 CPU limits (Docker, Kubernetes), CPU affinity masks,
//! and VM vCPU counts, so it returns the correct value in constrained
//! environments.

/// Return the number of CPUs available to this process, clamped to
/// at least 1. Falls back to 1 when the query fails (e.g. on exotic
/// platforms).
pub fn available_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_available_cpus_returns_at_least_one() {
        assert!(available_cpus() >= 1);
    }
}
