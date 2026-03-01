// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
// This file is part of P2Poolv2
//
// P2Poolv2 is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// P2Poolv2 is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// P2Poolv2. If not, see <https://www.gnu.org/licenses/>.

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
