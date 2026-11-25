// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::accounting::OutputPair;
use crate::config::StratumConfig;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use bitcoin::{Address, Amount, BlockHash};
use std::collections::HashMap;
use std::error::Error;

/// A trait for implementing a payout distribution.
///
/// payout::simple_pplns implements this trait to provide a payout
/// distribution based on centralised PPLNS algorithm.
///
/// payout::share_chain_payout implements this trait from the share
/// chain data.
#[cfg_attr(test, mockall::automock)]
pub trait PayoutDistribution {
    /// Fill distribution according to the the Payout mechanism.  The
    /// donation and fees amount have already been filled by the trait
    /// common implementation of get_outpoint_distribution
    #[allow(clippy::too_many_arguments)]
    fn fill_distribution_from_shares(
        &mut self,
        distribution: &mut Vec<OutputPair>,
        chain_store_handle: &ChainStoreHandle,
        anchor: BlockHash,
        bitcoin_difficulty: u128,
        total_amount: bitcoin::Amount,
        remaining_total_amount: Amount,
        bootstrap_address: Address,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Generate output distribution based on PPLNS shares weighted by difficulty.
    ///
    /// # Arguments
    /// * `store` - Handle to the chain store for querying PPLNS shares
    /// * `anchor` - Share the payout window is anchored on. The producer
    ///   passes the same tip it commits as `prev_share_blockhash`, so the
    ///   window it pays matches the one the validator reconstructs from
    ///   that prev, closing the read-tip-vs-payout-tip race.
    /// * `bitcoin_difficulty` - Difficulty of the bitcoin block being paid for.
    ///   Only Hydrapool's time-window PPLNS uses it, as its window target; the
    ///   share chain window is `PPLNS_WINDOW_SHARES` mature shares and
    ///   ignores it.
    /// * `total_amount` - Total bitcoin amount to distribute among contributors
    ///
    /// # Returns
    /// Vector of OutputPair containing addresses and their proportional amounts
    fn get_output_distribution(
        &mut self,
        chain_store_handle: &ChainStoreHandle,
        anchor: BlockHash,
        bitcoin_difficulty: u128,
        total_amount: bitcoin::Amount,
        config: &StratumConfig<crate::config::Parsed>,
    ) -> Result<Vec<OutputPair>, Box<dyn Error + Send + Sync>> {
        // Extra two places for potential cuts
        let mut distribution = Vec::<OutputPair>::new();
        let remaining_total_amount = include_address_and_cut(
            &mut distribution,
            total_amount,
            &config.donation_address_parsed,
            config.donation,
        );
        let remaining_total_amount = include_address_and_cut(
            &mut distribution,
            remaining_total_amount,
            &config.fee_address_parsed,
            config.fee,
        );

        self.fill_distribution_from_shares(
            &mut distribution,
            chain_store_handle,
            anchor,
            bitcoin_difficulty,
            total_amount,
            remaining_total_amount,
            config.bootstrap_address().clone(),
        )?;
        Ok(distribution)
    }
}

/// Maximum donation or fee cut, in basis points (100%).
pub(crate) const MAX_CUT_BASIS_POINTS: u16 = 10_000;

/// Appends new output pair to distribution and returns remaining amount
pub(crate) fn include_address_and_cut(
    distribution: &mut Vec<OutputPair>,
    total_amount: bitcoin::Amount,
    address: &Option<Address>,
    cut: Option<u16>, // in basis points
) -> Amount {
    const BASIS_POINT_FACTOR: u64 = MAX_CUT_BASIS_POINTS as u64; // 100 * 100

    // An over-100% cut would make the payout subtraction underflow. Ignore it
    // here as well as rejecting it during header validation, so every caller
    // remains panic-free.
    if let Some(cut_bp) = cut.filter(|c| *c > MAX_CUT_BASIS_POINTS) {
        tracing::warn!("Ignoring cut of {cut_bp} basis points; maximum is {MAX_CUT_BASIS_POINTS}");
        return total_amount;
    }

    if let (Some(addr), Some(cut_bp)) = (address.as_ref(), cut.filter(|c| *c > 0)) {
        if let Some(amount) = total_amount.checked_mul(cut_bp.into()) {
            if let Some(div_amount) = amount.checked_div(BASIS_POINT_FACTOR) {
                if let Some(remaining) = total_amount.checked_sub(div_amount) {
                    distribution.push(OutputPair {
                        address: addr.clone(),
                        amount: div_amount,
                    });
                    return remaining;
                }
                tracing::warn!(
                    "checked_sub failed for total_amount: {total_amount:?}, div_amount: {div_amount:?}"
                );
            } else {
                tracing::warn!("checked_div failed for amount: {amount:?}");
            }
        } else {
            tracing::warn!(
                "checked_mul failed for total_amount: {total_amount:?}, cut_bp: {cut_bp:?}"
            );
        }
    }
    total_amount
}

/// Appends proportional distribution of amount based on difficulty weights to the distribution.
///
/// Entries are sorted by address string to ensure the remainder from
/// integer truncation is always assigned to the same deterministic address.
pub(crate) fn append_proportional_distribution(
    address_difficulty_map: &HashMap<Address, u128>,
    total_amount: bitcoin::Amount,
    distribution: &mut Vec<OutputPair>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let total_difficulty = address_difficulty_map
        .values()
        .try_fold(0u128, |acc, difficulty| acc.checked_add(*difficulty))
        .ok_or_else(|| {
            "Total difficulty overflows u128 when computing proportional payout".to_string()
        })?;
    if total_difficulty == 0 {
        return Err(
            "Invalid total difficulty (0) when computing proportional payout"
                .to_string()
                .into(),
        );
    }

    let mut sorted_entries: Vec<(&Address, &u128)> = address_difficulty_map.iter().collect();
    sorted_entries.sort_by(|(address_a, _), (address_b, _)| {
        address_a.to_string().cmp(&address_b.to_string())
    });

    let mut distributed_amount = bitcoin::Amount::ZERO;
    let entry_count = sorted_entries.len();
    let total_sats = total_amount.to_sat() as u128;

    for (index, (address, difficulty)) in sorted_entries.into_iter().enumerate() {
        let amount = if index == entry_count - 1 {
            // Last address gets remainder from truncation
            total_amount - distributed_amount
        } else {
            let amount_sats = total_sats
                .checked_mul(*difficulty)
                .ok_or_else(|| {
                    format!(
                        "Difficulty {difficulty} too large to compute a proportional payout of {total_sats} sats"
                    )
                })?
                / total_difficulty;
            let amount_sats = amount_sats as u64;
            bitcoin::Amount::from_sat(amount_sats)
        };

        distributed_amount += amount;
        distribution.push(OutputPair {
            address: address.clone(),
            amount,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::parse_address_from_string;

    #[test]
    fn test_create_proportional_distribution() {
        let mut address_difficulty_map = HashMap::new();
        let address_a = parse_address_from_string("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
        let address_b = parse_address_from_string("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        address_difficulty_map.insert(address_a.clone(), 600);
        address_difficulty_map.insert(address_b.clone(), 400);

        let total_amount = bitcoin::Amount::from_sat(100_000_000); // 1.0 BTC
        let mut result = Vec::new();
        append_proportional_distribution(&address_difficulty_map, total_amount, &mut result)
            .unwrap();

        assert_eq!(result.len(), 2);

        let total_distributed: bitcoin::Amount = result.iter().map(|op| op.amount).sum();
        assert_eq!(total_distributed, total_amount);

        // Check proportional amounts (60% and 40%)
        let amounts: Vec<_> = result.iter().map(|op| op.amount.to_sat()).collect();
        assert!(amounts.contains(&60_000_000));
        assert!(amounts.contains(&40_000_000));
    }

    #[test]
    fn test_proportional_distribution_remainder_is_deterministic() {
        let address_a = parse_address_from_string("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
        let address_b = parse_address_from_string("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let address_c = parse_address_from_string("bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c");

        // 3 addresses splitting 1 sat that cannot divide evenly
        let mut address_difficulty_map = HashMap::new();
        address_difficulty_map.insert(address_a.clone(), 1);
        address_difficulty_map.insert(address_b.clone(), 1);
        address_difficulty_map.insert(address_c.clone(), 1);

        // 100 sats / 3 = 33 + 33 + 34 (1 sat remainder)
        let total_amount = bitcoin::Amount::from_sat(100);

        // Run multiple times to confirm the same address always gets the remainder
        let mut remainder_addresses: Vec<Address> = Vec::with_capacity(10);
        for _ in 0..10 {
            let mut result = Vec::new();
            append_proportional_distribution(&address_difficulty_map, total_amount, &mut result)
                .unwrap();

            let total_distributed: bitcoin::Amount = result.iter().map(|op| op.amount).sum();
            assert_eq!(total_distributed, total_amount);

            let remainder_entry = result
                .iter()
                .find(|output_pair| output_pair.amount.to_sat() == 34)
                .expect("one address should receive the 1 sat remainder");
            remainder_addresses.push(remainder_entry.address.clone());
        }

        let first_remainder = &remainder_addresses[0];
        assert!(
            remainder_addresses
                .iter()
                .all(|address| address == first_remainder),
            "remainder should always go to the same address across runs"
        );
    }

    #[test]
    fn test_include_address_and_cut_ignores_cuts_above_maximum() {
        let address = Some(parse_address_from_string(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        ));
        let total_amount = Amount::from_sat(100_000_000);

        for cut in [10_001, u16::MAX] {
            let mut distribution = Vec::new();
            let remaining =
                include_address_and_cut(&mut distribution, total_amount, &address, Some(cut));

            assert_eq!(remaining, total_amount);
            assert!(distribution.is_empty());
        }
    }

    #[test]
    fn test_include_address_and_cut_allows_one_hundred_percent() {
        let address = parse_address_from_string("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
        let total_amount = Amount::from_sat(100_000_000);
        let mut distribution = Vec::new();

        let remaining = include_address_and_cut(
            &mut distribution,
            total_amount,
            &Some(address.clone()),
            Some(10_000),
        );

        assert_eq!(remaining, Amount::ZERO);
        assert_eq!(distribution.len(), 1);
        assert_eq!(distribution[0].address, address);
        assert_eq!(distribution[0].amount, total_amount);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::test_utils::parse_address_from_string;
    use proptest::collection::hash_map;
    use proptest::prelude::*;

    /// Real, parseable mainnet addresses. The function sorts by address
    /// string, so these only need to be distinct.
    const ADDRESSES: [&str; 3] = [
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c",
    ];

    // Indices are unique by construction, so generated maps never collide on
    // a key, and every key is a parseable address.
    fn to_map(by_index: HashMap<usize, u128>) -> HashMap<Address, u128> {
        by_index
            .into_iter()
            .map(|(index, difficulty)| (parse_address_from_string(ADDRESSES[index]), difficulty))
            .collect()
    }

    /// Difficulties a real share chain can produce, so the properties below
    /// describe normal payout behaviour.
    fn realistic_maps() -> impl Strategy<Value = HashMap<Address, u128>> {
        hash_map(
            0..ADDRESSES.len(),
            1u128..=1_000_000,
            1usize..=ADDRESSES.len(),
        )
        .prop_map(to_map)
    }

    /// Any difficulty at all, up to u128::MAX. This is the shape a miner can
    /// put on the wire via its stratum password.
    fn unbounded_maps() -> impl Strategy<Value = HashMap<Address, u128>> {
        hash_map(0..ADDRESSES.len(), any::<u128>(), 2usize..=ADDRESSES.len()).prop_map(to_map)
    }

    fn totals(distribution: &[OutputPair]) -> (Vec<(String, u64)>, u64) {
        let entries: Vec<(String, u64)> = distribution
            .iter()
            .map(|pair| (pair.address.to_string(), pair.amount.to_sat()))
            .collect();
        let sum = entries.iter().map(|(_, sats)| *sats).sum();
        (entries, sum)
    }

    proptest! {
        /// Every sat being distributed comes back out: the outputs always add
        /// up to exactly the amount passed in, evenly divisible or not.
        #[test]
        fn distributed_amount_always_equals_input(
            map in realistic_maps(),
            total_sats in 0u64..=2_100_000_000_000_000u64,
        ) {
            let mut distribution = Vec::new();
            append_proportional_distribution(&map, Amount::from_sat(total_sats), &mut distribution)
                .unwrap();

            let (_, distributed) = totals(&distribution);
            prop_assert_eq!(distributed, total_sats);
        }

        /// The split depends on the weights, not on the order the map happens
        /// to hand entries back, so the same weights always pay the same way.
        #[test]
        fn result_is_independent_of_insertion_order(
            map in realistic_maps(),
            total_sats in 0u64..=2_100_000_000_000_000u64,
        ) {
            let entries: Vec<(Address, u128)> =
                map.iter().map(|(address, d)| (address.clone(), *d)).collect();

            let mut reversed: HashMap<Address, u128> = HashMap::new();
            for (address, difficulty) in entries.iter().rev() {
                reversed.insert(address.clone(), *difficulty);
            }

            let mut from_forward = Vec::new();
            append_proportional_distribution(
                &map,
                Amount::from_sat(total_sats),
                &mut from_forward,
            )
            .unwrap();

            let mut from_reversed = Vec::new();
            append_proportional_distribution(
                &reversed,
                Amount::from_sat(total_sats),
                &mut from_reversed,
            )
            .unwrap();

            prop_assert_eq!(totals(&from_forward), totals(&from_reversed));
        }

        /// Degenerate input is an error, not a panic: all-zero weights have no
        /// meaningful split.
        #[test]
        fn all_zero_difficulties_error_instead_of_panicking(
            total_sats in 0u64..=2_100_000_000_000_000u64,
            entries in 0usize..=ADDRESSES.len(),
        ) {
            let map: HashMap<Address, u128> = (0..entries)
                .map(|index| (parse_address_from_string(ADDRESSES[index]), 0))
                .collect();

            let mut distribution = Vec::new();
            let result =
                append_proportional_distribution(&map, Amount::from_sat(total_sats), &mut distribution);

            prop_assert!(result.is_err());
        }

        /// Extreme difficulties must produce a clean error, never a panic.
        /// Regression test for the unchecked `total_sats * difficulty` and
        /// `values().sum()` that used to overflow here.
        #[test]
        fn never_panics_for_any_difficulty(
            map in unbounded_maps(),
            total_sats in 2u64..=2_100_000_000_000_000u64,
        ) {
            let mut distribution = Vec::new();
            let _ = append_proportional_distribution(
                &map,
                Amount::from_sat(total_sats),
                &mut distribution,
            );
        }
    }
}
