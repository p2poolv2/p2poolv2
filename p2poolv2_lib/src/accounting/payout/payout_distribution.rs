// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
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

use crate::accounting::OutputPair;
use crate::config::StratumConfig;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use bitcoin::{Address, Amount};
use std::collections::HashMap;
use std::error::Error;

pub trait PayoutShare {
    fn get_btcaddress(&self) -> Option<String>;
    fn get_difficulty(&self) -> u64;
}

/// A trait for implementing a payout distribtuion
///
/// payout::simple_pplns implements this trait to provide a payout
/// distribtuion based on centralised PPLNS algorithm.
///
/// payout::share_chain_payout implments this trait from the share
/// chain data.
pub trait PayoutDistribution<P: PayoutShare> {
    /// Fill distribution according to the the Payout mechanism.  The
    /// donation and fees amount have already been filled by the trait
    /// common implmentation of get_outpoint_distribtuion
    fn fill_distribution_from_shares(
        &self,
        distribution: &mut Vec<OutputPair>,
        chain_store_handle: &ChainStoreHandle,
        total_difficulty: f64,
        total_amount: bitcoin::Amount,
        remaining_total_amount: Amount,
        address: Address,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;

    /// Generate output distribution based on PPLNS shares weighted by difficulty.
    ///
    /// # Arguments
    /// * `store` - Handle to the chain store for querying PPLNS shares
    /// * `total_difficulty` - Target cumulative difficulty to collect shares for
    /// * `total_amount` - Total bitcoin amount to distribute among contributors
    ///
    /// # Returns
    /// Vector of OutputPair containing addresses and their proportional amounts
    fn get_output_distribution(
        &self,
        chain_store_handle: &ChainStoreHandle,
        total_difficulty: f64,
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
            total_difficulty,
            total_amount,
            remaining_total_amount,
            config.bootstrap_address().clone(),
        )?;
        Ok(distribution)
    }
}

/// Appends new output pair to distribution and returns remaining amount
fn include_address_and_cut(
    distribution: &mut Vec<OutputPair>,
    total_amount: bitcoin::Amount,
    address: &Option<Address>,
    cut: Option<u16>, // in basis points
) -> Amount {
    const BASIS_POINT_FACTOR: u64 = 10_000; // 100 * 100
    if let (Some(addr), Some(cut_bp)) = (address.as_ref(), cut.filter(|c| *c > 0)) {
        if let Some(amount) = total_amount.checked_mul(cut_bp.into()) {
            if let Some(div_amount) = amount.checked_div(BASIS_POINT_FACTOR) {
                distribution.push(OutputPair {
                    address: addr.clone(),
                    amount: div_amount,
                });
                return total_amount - div_amount;
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

/// Groups shares by bitcoin address and sums their difficulties.
pub(crate) fn group_shares_by_address<P: PayoutShare>(shares: &[P]) -> HashMap<String, u64> {
    let mut address_difficulty_map = HashMap::new();
    for share in shares {
        if let Some(btcaddress) = &share.get_btcaddress() {
            *address_difficulty_map
                .entry(btcaddress.clone())
                .or_insert(0) += share.get_difficulty();
        }
    }
    address_difficulty_map
}

/// Appends proportional distribution of amount based on difficulty weights to the distribtuion
pub(crate) fn append_proportional_distribution(
    address_difficulty_map: HashMap<String, u64>,
    total_amount: bitcoin::Amount,
    distribution: &mut Vec<OutputPair>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let total_difficulty: u64 = address_difficulty_map.values().sum();
    let mut distributed_amount = bitcoin::Amount::ZERO;

    for (i, (address_str, difficulty)) in address_difficulty_map.iter().enumerate() {
        let address = address_str
            .parse::<bitcoin::Address<_>>()
            .map_err(|e| format!("Invalid bitcoin address '{address_str}': {e}"))?
            .assume_checked();

        let amount = if i == address_difficulty_map.len() - 1 {
            // Last address gets remainder to handle rounding
            total_amount - distributed_amount
        } else {
            let proportion = *difficulty as f64 / total_difficulty as f64;
            let amount_sats = (total_amount.to_sat() as f64 * proportion).round() as u64;
            bitcoin::Amount::from_sat(amount_sats)
        };

        distributed_amount += amount;
        distribution.push(OutputPair { address, amount });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::payout::simple_pplns::SimplePplnsShare;

    #[test]
    fn test_group_shares_by_address() {
        let shares = vec![
            SimplePplnsShare::new(
                1,
                100,
                "addr1".to_string(),
                "worker1".to_string(),
                1000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                2,
                200,
                "addr2".to_string(),
                "worker2".to_string(),
                2000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                1,
                300,
                "addr1".to_string(),
                "worker3".to_string(),
                3000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        let result = group_shares_by_address(&shares);

        assert_eq!(result.len(), 2);
        assert_eq!(result.get("addr1"), Some(&400)); // 100 + 300
        assert_eq!(result.get("addr2"), Some(&200));
    }

    #[test]
    fn test_create_proportional_distribution() {
        let mut address_difficulty_map = HashMap::new();
        address_difficulty_map.insert(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
            600,
        );
        address_difficulty_map.insert(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            400,
        );

        let total_amount = bitcoin::Amount::from_sat(100_000_000); // 1.0 BTC
        let mut result = Vec::new();
        append_proportional_distribution(address_difficulty_map, total_amount, &mut result)
            .unwrap();

        assert_eq!(result.len(), 2);

        let total_distributed: bitcoin::Amount = result.iter().map(|op| op.amount).sum();
        assert_eq!(total_distributed, total_amount);

        // Check proportional amounts (60% and 40%)
        let amounts: Vec<_> = result.iter().map(|op| op.amount.to_sat()).collect();
        assert!(amounts.contains(&60_000_000) || amounts.contains(&40_000_000));
    }
}
