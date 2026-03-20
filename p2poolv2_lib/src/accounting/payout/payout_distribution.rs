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
    fn fill_distribution_from_shares(
        &mut self,
        distribution: &mut Vec<OutputPair>,
        chain_store_handle: &ChainStoreHandle,
        total_difficulty: f64,
        total_amount: bitcoin::Amount,
        remaining_total_amount: Amount,
        bootstrap_address: Address,
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
        &mut self,
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

/// Appends proportional distribution of amount based on difficulty weights to the distribution
pub(crate) fn append_proportional_distribution(
    address_difficulty_map: &HashMap<String, f64>,
    total_amount: bitcoin::Amount,
    distribution: &mut Vec<OutputPair>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let total_difficulty: f64 = address_difficulty_map.values().sum();
    if !total_difficulty.is_finite() || total_difficulty <= 0.0 {
        return Err(format!(
            "Invalid total difficulty ({total_difficulty}) when computing proportional payout"
        )
        .into());
    }
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
            let proportion = *difficulty / total_difficulty;
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

    #[test]
    fn test_create_proportional_distribution() {
        let mut address_difficulty_map = HashMap::new();
        address_difficulty_map.insert(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
            600.0,
        );
        address_difficulty_map.insert(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            400.0,
        );

        let total_amount = bitcoin::Amount::from_sat(100_000_000); // 1.0 BTC
        let mut result = Vec::new();
        append_proportional_distribution(&address_difficulty_map, total_amount, &mut result)
            .unwrap();

        assert_eq!(result.len(), 2);

        let total_distributed: bitcoin::Amount = result.iter().map(|op| op.amount).sum();
        assert_eq!(total_distributed, total_amount);

        // Check proportional amounts (60% and 40%)
        let amounts: Vec<_> = result.iter().map(|op| op.amount.to_sat()).collect();
        assert!(amounts.contains(&60_000_000) || amounts.contains(&40_000_000));
    }
}
