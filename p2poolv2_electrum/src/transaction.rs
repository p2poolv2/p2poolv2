// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `blockchain.transaction.get`: confirmed share chain transactions, raw or
//! decoded in the bitcoind `getrawtransaction` shape plus p2pool extras.

use crate::methods::{param, store_read_error};
use crate::protocol::{INTERNAL_ERROR, INVALID_PARAMS, RpcError};
use crate::script::script_pubkey_json;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hex::DisplayHex;
use bitcoin::{BlockHash, Network, Transaction, TxIn, TxOut, Txid};
use p2poolv2_lib::accounting::payout::sharechain_pplns::pplns_window::{
    COINBASE_MATURITY, PAYOUT_DEPTH,
};
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::store::transaction_store::OutputOrigin;
use p2poolv2_lib::store::writer::StoreError;
use serde_json::{Value, json};
use std::str::FromStr;

/// Captures details of the height of the block containing a tx and
/// related tip information.
///
/// The height of the block containing the confirmed transaction, the
/// confirmed tip and its output spendability heights.
struct ConfirmedTxLocation {
    /// The blockhash containing a tx
    blockhash: BlockHash,
    /// The height of the blockhash
    height: u32,
    /// Timestamp in the block header of the block containing the confirmed tx
    header_time: u32,
    /// Current tip of the chain
    tip_height: u32,
}

/// `blockchain.transaction.get [tx_hash, verbose=false]`.
///
/// Serves only a transaction in a block if it is on the confirmed
/// chain: the store also holds transactions of uncles, forks and
/// invalid blocks, none of which a wallet can spend, and there is no
/// mempool yet.
///
/// Anything else, or a transaction whose rows were pruned, is
/// `INVALID_PARAMS` "transaction not found".
///
/// Returns the serialized transaction as hex, or with `verbose` the
/// decoded transaction (see `verbose_transaction`).
pub(crate) fn transaction_get(
    chain_store_handle: &ChainStoreHandle,
    params: &Value,
) -> Result<Value, RpcError> {
    let txid = parse_txid(param(params, 0, "tx_hash"))?;
    let verbose = parse_verbose(param(params, 1, "verbose"))?;
    let location = confirmed_location(chain_store_handle, &txid)?;
    let (transaction, output_origins) = chain_store_handle
        .get_tx_with_output_origins(&txid)
        .map_err(|error| match error {
            StoreError::NotFound(_) => transaction_not_found(&txid),
            error => store_read_error(error),
        })?;
    if verbose {
        Ok(verbose_transaction(
            &transaction,
            &output_origins,
            &location,
            chain_store_handle.network(),
        ))
    } else {
        Ok(Value::from(serialize_hex(&transaction)))
    }
}

fn parse_txid(tx_hash: Option<&Value>) -> Result<Txid, RpcError> {
    tx_hash
        .and_then(Value::as_str)
        .and_then(|tx_hash| Txid::from_str(tx_hash).ok())
        .ok_or_else(|| {
            RpcError::new(
                INVALID_PARAMS,
                "tx_hash must be a 64 character hex transaction id",
            )
        })
}

fn parse_verbose(verbose: Option<&Value>) -> Result<bool, RpcError> {
    match verbose {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(verbose)) => Ok(*verbose),
        Some(_) => Err(RpcError::new(INVALID_PARAMS, "verbose must be a boolean")),
    }
}

/// The confirmed block containing `txid` (from
/// `ChainStoreHandle::get_confirmed_block_for_txid`), its header time, and
/// the confirmed tip. No confirmed block is "transaction not found".
fn confirmed_location(
    chain_store_handle: &ChainStoreHandle,
    txid: &Txid,
) -> Result<ConfirmedTxLocation, RpcError> {
    let (blockhash, height) = chain_store_handle
        .get_confirmed_block_for_txid(txid)
        .map_err(store_read_error)?
        .ok_or_else(|| transaction_not_found(txid))?;
    let time = chain_store_handle
        .get_share_header(&blockhash)
        .map_err(store_read_error)?
        .time;
    let tip_height = chain_store_handle
        .get_tip_height()
        .map_err(store_read_error)?
        .ok_or_else(|| RpcError::new(INTERNAL_ERROR, "no confirmed share chain"))?;
    Ok(ConfirmedTxLocation {
        blockhash,
        height,
        header_time: time,
        tip_height,
    })
}

fn transaction_not_found(txid: &Txid) -> RpcError {
    RpcError::new(INVALID_PARAMS, format!("transaction {txid} not found"))
}

/// The bitcoind `getrawtransaction` verbose object for a confirmed
/// transaction, with `value` in BTC, plus the p2pool extras: a `p2pool`
/// object per output (see `output_json`) and `p2pool_tip_height`, the
/// confirmed tip those heights are to be compared against (as tip + 1, the
/// next block).
fn verbose_transaction(
    transaction: &Transaction,
    output_origins: &[OutputOrigin],
    location: &ConfirmedTxLocation,
    network: Network,
) -> Value {
    let is_coinbase = transaction.is_coinbase();
    let inputs: Vec<Value> = transaction
        .input
        .iter()
        .map(|input| input_json(input, is_coinbase))
        .collect();
    let outputs: Vec<Value> = transaction
        .output
        .iter()
        .zip(output_origins)
        .enumerate()
        .map(|(index, (output, origin))| output_json(index, output, *origin, network))
        .collect();
    json!({
        "txid": transaction.compute_txid().to_string(),
        "hash": transaction.compute_wtxid().to_string(),
        "version": transaction.version.0,
        "size": transaction.total_size(),
        "vsize": transaction.vsize(),
        "weight": transaction.weight().to_wu(),
        "locktime": transaction.lock_time.to_consensus_u32(),
        "vin": inputs,
        "vout": outputs,
        "hex": serialize_hex(transaction),
        "blockhash": location.blockhash.to_string(),
        "confirmations": location.tip_height.saturating_sub(location.height) + 1,
        "time": location.header_time,
        "blocktime": location.header_time,
        "p2pool_tip_height": location.tip_height,
    })
}

/// A bitcoind `vin` entry. A coinbase input shows its script as
/// `coinbase`; any other shows the outpoint and `scriptSig`. `txinwitness`
/// appears only when the witness is non-empty, as in bitcoind.
fn input_json(input: &TxIn, is_coinbase: bool) -> Value {
    let mut entry = if is_coinbase {
        json!({ "coinbase": input.script_sig.to_hex_string() })
    } else {
        json!({
            "txid": input.previous_output.txid.to_string(),
            "vout": input.previous_output.vout,
            "scriptSig": {
                "asm": input.script_sig.to_asm_string(),
                "hex": input.script_sig.to_hex_string(),
            },
        })
    };
    if !input.witness.is_empty() {
        let witness: Vec<Value> = input
            .witness
            .iter()
            .map(|element| Value::from(element.to_lower_hex_string()))
            .collect();
        entry["txinwitness"] = Value::Array(witness);
    }
    entry["sequence"] = Value::from(input.sequence.0);
    entry
}

/// A bitcoind `vout` entry plus a `p2pool` object with the output's
/// spendability heights, mirroring `validate_prevouts` / `check_prevouts`:
///
/// - `last_spendable_height = coinbase_root_height + PAYOUT_DEPTH`: a block
///   at height H may spend the output only if
///   `coinbase_root_height >= H - PAYOUT_DEPTH`.
/// - `first_spendable_height = coinbase_root_height + COINBASE_MATURITY`
///   for a coinbase output; null otherwise, as only coinbase outputs
///   mature.
fn output_json(index: usize, output: &TxOut, origin: OutputOrigin, network: Network) -> Value {
    let coinbase_root_height = u64::from(origin.coinbase_root_height);
    let first_spendable_height = origin
        .is_coinbase
        .then_some(coinbase_root_height + COINBASE_MATURITY as u64);
    json!({
        "value": output.value.to_btc(),
        "n": index,
        "scriptPubKey": script_pubkey_json(&output.script_pubkey, network),
        "p2pool": {
            "coinbase": origin.is_coinbase,
            "coinbase_root_height": origin.coinbase_root_height,
            "first_spendable_height": first_spendable_height,
            "last_spendable_height": coinbase_root_height + PAYOUT_DEPTH as u64,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::methods::dispatch;
    use crate::protocol::NOT_SYNCED;
    use crate::test_utils::build_current_test_chain;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Witness};
    use p2poolv2_lib::address::Address;
    use p2poolv2_lib::test_utils::{
        TestShareBlockBuilder, build_confirmed_test_chain, make_test_share_address,
        setup_test_chain_store_handle, test_funding_transaction,
    };

    #[tokio::test]
    async fn raw_returns_hex_of_confirmed_transaction() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let coinbase = &blocks[1].transactions[0].0;

        let raw = dispatch(
            &chain_store_handle,
            "blockchain.transaction.get",
            &json!([coinbase.compute_txid().to_string()]),
        )
        .unwrap();

        assert_eq!(raw, json!(serialize_hex(coinbase)));
    }

    #[tokio::test]
    async fn named_params_with_verbose_false_return_raw() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let coinbase = &blocks[1].transactions[0].0;

        let raw = dispatch(
            &chain_store_handle,
            "blockchain.transaction.get",
            &json!({"tx_hash": coinbase.compute_txid().to_string(), "verbose": false}),
        )
        .unwrap();

        assert_eq!(raw, json!(serialize_hex(coinbase)));
    }

    #[tokio::test]
    async fn verbose_coinbase_reports_location_and_spendable_heights() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let coinbase = &blocks[1].transactions[0].0;
        let miner_address =
            Address::from_witness_program(blocks[1].header.miner_address, Network::Signet)
                .unwrap()
                .to_string();

        let verbose = dispatch(
            &chain_store_handle,
            "blockchain.transaction.get",
            &json!([coinbase.compute_txid().to_string(), true]),
        )
        .unwrap();

        assert_eq!(verbose["txid"], json!(coinbase.compute_txid().to_string()));
        assert_eq!(verbose["hex"], json!(serialize_hex(coinbase)));
        assert_eq!(
            verbose["blockhash"],
            json!(blocks[1].block_hash().to_string())
        );
        assert_eq!(verbose["confirmations"], json!(2));
        assert_eq!(verbose["time"], json!(blocks[1].header.time));
        assert_eq!(verbose["p2pool_tip_height"], json!(2));
        assert!(verbose["vin"][0].get("coinbase").is_some());
        assert_eq!(
            verbose["vout"][0]["value"],
            json!(coinbase.output[0].value.to_btc())
        );
        assert_eq!(
            verbose["vout"][0]["p2pool"],
            json!({
                "coinbase": true,
                "coinbase_root_height": 1,
                "first_spendable_height": 1 + COINBASE_MATURITY,
                "last_spendable_height": 1 + PAYOUT_DEPTH,
            })
        );
        let pays_miner = verbose["vout"]
            .as_array()
            .unwrap()
            .iter()
            .any(|output| output["scriptPubKey"]["addresses"] == json!([miner_address]));
        assert!(pays_miner, "no output pays {miner_address}: {verbose}");
    }

    /// The block is stored and on the candidate chain, so it has metadata,
    /// but is never confirmed, as an uncle or fork block would be. Its
    /// transactions are not served.
    #[tokio::test]
    async fn transaction_only_in_unconfirmed_block_is_not_found() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let unconfirmed = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[2].block_hash().to_string())
            .time(blocks[2].header.time)
            .add_transaction(test_funding_transaction(99))
            .build();
        chain_store_handle
            .add_share_block_and_organise_header(unconfirmed.clone())
            .await
            .unwrap();
        let txid = unconfirmed.transactions[0].0.compute_txid();
        assert!(
            chain_store_handle
                .store_handle()
                .store()
                .share_block_exists(&unconfirmed.block_hash())
        );

        let error = dispatch(
            &chain_store_handle,
            "blockchain.transaction.get",
            &json!([txid.to_string()]),
        )
        .unwrap_err();

        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn unknown_txid_is_not_found() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let error = dispatch(
            &chain_store_handle,
            "blockchain.transaction.get",
            &json!([Txid::from_byte_array([9; 32]).to_string()]),
        )
        .unwrap_err();

        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn malformed_tx_hash_is_invalid_params() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;

        let error = dispatch(
            &chain_store_handle,
            "blockchain.transaction.get",
            &json!(["not-a-txid"]),
        )
        .unwrap_err();

        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn non_boolean_verbose_is_invalid_params() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let txid = blocks[1].transactions[0].0.compute_txid();

        let error = dispatch(
            &chain_store_handle,
            "blockchain.transaction.get",
            &json!([txid.to_string(), "yes"]),
        )
        .unwrap_err();

        assert_eq!(error.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn stale_tip_is_not_synced() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        // Build a test chain with not current tip
        let blocks = build_confirmed_test_chain(&chain_store_handle, 2).await;
        let txid = blocks[1].transactions[0].0.compute_txid();

        let error = dispatch(
            &chain_store_handle,
            "blockchain.transaction.get",
            &json!([txid.to_string()]),
        )
        .unwrap_err();

        assert_eq!(error.code, NOT_SYNCED);
    }

    /// A traded share's output: not coinbase, so no maturity height, and
    /// its expiry follows the inherited coinbase root.
    #[test]
    fn non_coinbase_output_has_no_first_spendable_height() {
        let address = make_test_share_address(2, Network::Signet);
        let output = TxOut {
            value: Amount::from_sat(150_000_000),
            script_pubkey: address.script_pubkey(),
        };
        let origin = OutputOrigin {
            is_coinbase: false,
            coinbase_root_height: 5,
        };

        let rendered = output_json(3, &output, origin, Network::Signet);

        assert_eq!(rendered["n"], json!(3));
        assert_eq!(rendered["value"], json!(1.5));
        assert_eq!(
            rendered["p2pool"],
            json!({
                "coinbase": false,
                "coinbase_root_height": 5,
                "first_spendable_height": null,
                "last_spendable_height": 5 + PAYOUT_DEPTH,
            })
        );
        assert_eq!(
            rendered["scriptPubKey"]["addresses"],
            json!([address.to_string()])
        );
    }

    #[test]
    fn spending_input_shows_outpoint_script_sig_and_witness() {
        let input = TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([4; 32]), 2),
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xffff_fffd),
            witness: Witness::from_slice(&[vec![0xab, 0xcd], vec![0x01]]),
        };

        let rendered = input_json(&input, false);

        assert_eq!(
            rendered,
            json!({
                "txid": Txid::from_byte_array([4; 32]).to_string(),
                "vout": 2,
                "scriptSig": {"asm": "", "hex": ""},
                "txinwitness": ["abcd", "01"],
                "sequence": 0xffff_fffd_u32,
            })
        );
    }

    #[test]
    fn input_without_witness_has_no_txinwitness() {
        let input = TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([4; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        let rendered = input_json(&input, false);

        assert!(rendered.get("txinwitness").is_none());
    }
}
