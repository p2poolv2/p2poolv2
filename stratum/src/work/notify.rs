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

#[cfg(not(test))]
use crate::client_connections::ClientConnectionsHandle;
#[cfg(test)]
#[mockall_double::double]
use crate::client_connections::ClientConnectionsHandle;

use crate::messages::{Notify, NotifyParams};
use crate::work::coinbase::OutputPair;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{self, rand::Rng};
use bitcoin::transaction::Version;
use bitcoin::Address;
use std::borrow::Cow;
use std::sync::Arc;
use tokio::sync::mpsc;

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

/// Build the output distribution for the coinbase transaction.
/// For now we only work with the solo_address provided, it will be used as the recipient of the coinbase transaction.
fn build_output_distribution(
    template: &BlockTemplate,
    solo_address: Option<Address>,
) -> Vec<OutputPair> {
    let mut output_distribution = Vec::new();
    if let Some(address) = solo_address {
        output_distribution.push(OutputPair {
            address,
            amount: bitcoin::Amount::from_sat(template.coinbasevalue),
        });
    }
    output_distribution
}

#[allow(dead_code)]
pub fn build_notify(
    template: &BlockTemplate,
    solo_address: Option<Address>,
) -> Result<Notify, WorkError> {
    let job_id: u64 = secp256k1::rand::thread_rng().gen();

    let output_distribution = build_output_distribution(template, solo_address);

    let coinbase = build_coinbase_transaction(
        Version(template.version),
        output_distribution.as_slice(),
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

/// Start a task that listens for new block template events.
/// As new templates arrives, the tasks build new Notify messages and sends them to all connected clients.
///
/// The output distribution is provided and this works for solo mining. Later on we need to get the output
/// distribution from the server or any new component we add for share accounting.
pub async fn start_notify(
    mut notifier_rx: mpsc::Receiver<BlockTemplate>,
    connections: ClientConnectionsHandle,
    solo_address: Option<Address>,
) {
    while let Some(template) = notifier_rx.recv().await {
        match build_notify(&template, solo_address.clone()) {
            Ok(notify) => {
                let notify_str =
                    serde_json::to_string(&notify).expect("Failed to serialize Notify message");
                connections.send_to_all(Arc::new(notify_str)).await;
            }
            Err(e) => {
                eprintln!("Error building notify: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::work::coinbase::parse_address;
    use std::fs;
    use tokio::sync::mpsc;

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
        let notify = build_notify(&template, Some(address)).expect("Failed to build notify");

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

    #[tokio::test]
    async fn test_start_notify() {
        // Set up mock connections
        let mut mock_connections = ClientConnectionsHandle::default();

        // Set up expectations
        mock_connections
            .expect_send_to_all()
            .times(1)
            .returning(|_| ());

        // Create a channel for block template notifications
        let (notify_tx, notify_rx) = mpsc::channel::<BlockTemplate>(10);

        // Setup output distribution
        let address = parse_address(
            "bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr",
            bitcoin::Network::Regtest,
        )
        .unwrap();

        // Start the notify task in a separate task
        let task_handle = tokio::spawn(async move {
            start_notify(notify_rx, mock_connections, Some(address)).await;
        });

        // Load a sample block template
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json");
        let data = fs::read_to_string(path).expect("Unable to read file");
        let gbt_json: serde_json::Value = serde_json::from_str(&data).expect("Invalid JSON");
        let template: BlockTemplate =
            serde_json::from_value(gbt_json.clone()).expect("Failed to parse BlockTemplate");

        // Send the template through the channel
        notify_tx
            .send(template)
            .await
            .expect("Failed to send template");

        // Give some time for the message to be processed
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Cleanup
        drop(notify_tx); // Close the channel to terminate the task
        task_handle.await.expect("Task failed");
    }
}
