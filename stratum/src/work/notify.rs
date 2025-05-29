// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
//  This file is part of P2Poolv2
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

use super::coinbase::{build_coinbase_transaction, split_coinbase};
use super::error::WorkError;
use super::gbt::{build_merkle_branches_for_template, BlockTemplate};
use crate::messages::{Notify, NotifyParams};
use crate::work::coinbase::OutputPair;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{self, rand::Rng};
use bitcoin::transaction::Version;
use std::borrow::Cow;

/// Extract flags from template coinbaseaux and convert to PushBytesBuf
/// If flags are empty, use a single byte with value 0
#[allow(dead_code)]
fn parse_flags(flags: Option<String>) -> PushBytesBuf {
    match flags {
        Some(flags) if flags.is_empty() => PushBytesBuf::from(&[0u8]),
        Some(flags) => PushBytesBuf::try_from(hex::decode(flags).unwrap()).unwrap(),
        None => PushBytesBuf::from(&[0u8]),
    }
}

#[allow(dead_code)]
pub fn build_notify(
    template: &BlockTemplate,
    output_distribution: Vec<OutputPair>,
) -> Result<Notify, WorkError> {
    let job_id: u64 = secp256k1::rand::thread_rng().gen();

    let coinbase = build_coinbase_transaction(
        Version(template.version),
        output_distribution,
        template.height as i64,
        parse_flags(template.coinbaseaux.get("flags").cloned()),
        template.default_witness_commitment.clone(),
    )
    .unwrap();
    let (coinbase1, coinbase2) = split_coinbase(&coinbase).unwrap();

    let merkle_branches = build_merkle_branches_for_template(template)
        .iter()
        .map(|branch| Cow::Owned(branch.to_string()))
        .collect::<Vec<_>>();

    let params = NotifyParams {
        job_id: Cow::Owned(format!("{:016x}", job_id)),
        prevhash: Cow::Owned(template.previousblockhash.clone()),
        coinbase1: Cow::Owned(coinbase1),
        coinbase2: Cow::Owned(coinbase2),
        merkle_branches,
        version: Cow::Owned(format!("{:08x}", template.version)),
        nbits: Cow::Owned(template.bits.clone()),
        ntime: Cow::Owned(format!("{:08x}", template.curtime)),
        clean_jobs: true,
    };

    Ok(Notify::new_notify(params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::work::coinbase::parse_address;
    use bitcoin::Amount;
    use std::fs;

    #[test]
    fn test_build_notify_from_gbt_and_compare_to_expected() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json");
        let data = fs::read_to_string(path).expect("Unable to read file");
        let gbt_json: serde_json::Value = serde_json::from_str(&data).expect("Invalid JSON");

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/test_data/gbt/regtest/ckpool/one-txn/notify.json");
        let data = fs::read_to_string(path).expect("Unable to read file");
        let notify_json: serde_json::Value = serde_json::from_str(&data).expect("Invalid JSON");

        // Parse BlockTemplate from GBT
        let template: BlockTemplate =
            serde_json::from_value(gbt_json.clone()).expect("Failed to parse BlockTemplate");

        // Address used in ckpool regtest conf
        let address = parse_address(
            "bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr",
            bitcoin::Network::Regtest,
        )
        .unwrap();

        // Build Notify
        let notify = build_notify(
            &template,
            vec![OutputPair {
                address,
                amount: Amount::from_sat(template.coinbasevalue),
            }],
        )
        .expect("Failed to build notify");

        // Load expected notify JSON
        let expected_notify_json = notify_json.clone();
        let expected_notify_value: serde_json::Value =
            serde_json::from_value(expected_notify_json).expect("Failed to convert to Value");
        let expected_notify: Notify<'static> = Notify::new_notify(
            serde_json::from_value(expected_notify_value["params"].clone())
                .expect("Failed to parse NotifyParams"),
        );

        // Compare all fields except job_id (random) coinbase which also have current time component
        assert_eq!(notify.params.version, expected_notify.params.version);
        assert_eq!(notify.params.nbits, expected_notify.params.nbits);
        assert_eq!(notify.params.ntime, "68300262"); // we use current time in notify, so it is diff from the ckpool og response
        assert_eq!(notify.params.clean_jobs, expected_notify.params.clean_jobs);

        // TODO: Fix comparison of using endian conversion. Also mock current time so we can compare coinbase1 and coinbase2
        // assert_eq!(notify.params.prevhash, expected_notify.params.prevhash);
        // // assert_eq!(notify.params.coinbase1, expected_notify.params.coinbase1);
        // // assert_eq!(notify.params.coinbase2, expected_notify.params.coinbase2);
        // assert_eq!(
        //     notify.params.merkle_branches,
        //     expected_notify.params.merkle_branches
        // );
    }

    #[test]
    fn test_parse_flags() {
        // Test with empty string
        let flags = parse_flags(Some(String::from("")));
        assert_eq!(flags.as_bytes(), &[0u8]);

        // Test with None
        let flags = parse_flags(None);
        assert_eq!(flags.as_bytes(), &[0u8]);

        // Test with valid hex string
        let flags = parse_flags(Some(String::from("deadbeef")));
        assert_eq!(flags.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    }
}
