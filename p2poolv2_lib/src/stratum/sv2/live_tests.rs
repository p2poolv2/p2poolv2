// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Explicit opt-in checks against two disposable BCHN regtest nodes.

use super::mining::MiningChannels;
use crate::shares::auxpow::{AuxPowProof, AuxiliaryTree, AuxiliaryWork};
use crate::shares::share_block::ShareHeader;
use crate::shares::transactions::coinbase::compute_non_coinbase_root;
use crate::stratum::work::block_template::BlockTemplate;
use crate::test_utils::{
    test_bch_custom_coinbase, test_bch_custom_job_with_aux, test_bch_prepared_for_template,
    test_bch_solve_custom_job, test_bch_stratum_context,
};
use binary_sv2::{B032, Deserialize, U256};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::{Address, Amount, Block, BlockHash, Network, PubkeyHash, Transaction};
use bitcoindrpc::BitcoindRpcClient;
use mining_sv2::{
    MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_SUCCESS,
    MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
    OpenExtendedMiningChannel, OpenExtendedMiningChannelSuccess, SetCustomMiningJob,
    SetCustomMiningJobSuccess, SubmitSharesExtended,
};
use p2poolv2_config::DEFAULT_VERSION_MASK;
use p2poolv2_wallet::bch_share::{BchShareNetwork, encode_payout_address};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{sleep, timeout};

#[tokio::test]
#[ignore = "requires two disposable BCHN nodes and a funded jd-regtest wallet; see docs/bch-job-declaration.md"]
async fn bchn_declared_jobs_reach_both_real_nodes() {
    let client_url = std::env::var("BCHN_JD_CLIENT_RPC").expect("set BCHN_JD_CLIENT_RPC");
    let pool_url = std::env::var("BCHN_JD_POOL_RPC").expect("set BCHN_JD_POOL_RPC");
    let client_socket: SocketAddr = client_url.strip_prefix("http://").unwrap().parse().unwrap();
    let pool_socket: SocketAddr = pool_url.strip_prefix("http://").unwrap().parse().unwrap();
    assert!(client_socket.ip().is_loopback() && pool_socket.ip().is_loopback());
    assert_ne!(client_socket, pool_socket);
    let client =
        BitcoindRpcClient::new(&client_url, "p2pool-jd-test", "local-regtest-only").unwrap();
    let pool = BitcoindRpcClient::new(&pool_url, "p2pool-jd-test", "local-regtest-only").unwrap();
    let wallet = BitcoindRpcClient::new(
        &format!("{client_url}/wallet/jd-regtest"),
        "p2pool-jd-test",
        "local-regtest-only",
    )
    .unwrap();
    let client_chain: Value = client.request("getblockchaininfo", vec![]).await.unwrap();
    let pool_chain: Value = pool.request("getblockchaininfo", vec![]).await.unwrap();
    assert_eq!(client_chain["chain"], "regtest");
    assert_eq!(pool_chain["chain"], "regtest");

    let payout = Address::p2pkh(PubkeyHash::from_byte_array([0x22; 20]), Network::Regtest);
    let identity = encode_payout_address(&payout, BchShareNetwork::Regtest).unwrap();
    let full_txid: String = wallet
        .request("sendtoaddress", vec![json!(identity), json!(1)])
        .await
        .unwrap();
    let template = timeout(Duration::from_secs(10), async {
        loop {
            let template: BlockTemplate =
                serde_json::from_str(&pool.get_bch_block_template().await.unwrap()).unwrap();
            if template
                .transactions
                .iter()
                .any(|transaction| transaction.txid == full_txid)
            {
                break template;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("transaction did not propagate to the pool node");
    let full_height = template.height;
    let full_value = template.coinbasevalue;
    let transactions = template
        .transactions
        .iter()
        .map(Transaction::try_from)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let prepared = test_bch_prepared_for_template(template);
    let (mut ctx, mut emissions, _dirs) = test_bch_stratum_context(&pool_url).await;
    ctx.bitcoindrpc_client = pool.clone();
    let mut channels = MiningChannels::new(ctx, DEFAULT_VERSION_MASK);
    let mut open = binary_sv2::to_bytes(OpenExtendedMiningChannel {
        request_id: 1,
        user_identity: identity.as_str().try_into().unwrap(),
        nominal_hash_rate: 1.0,
        max_target: U256::new(&[0xff; 32]).unwrap(),
        min_extranonce_size: 8,
    })
    .unwrap();
    let opened = channels
        .handle(
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
            &mut open,
            Some(Arc::clone(&prepared)),
        )
        .await
        .unwrap();
    let mut open_payload = opened[0][6..].to_vec();
    let opened = OpenExtendedMiningChannelSuccess::from_bytes(&mut open_payload).unwrap();
    let extranonce_prefix = opened.extranonce_prefix.as_bytes().to_vec();
    let token = prepared
        .mining_job_token([1; 32], prepared.template().curtime)
        .unwrap();
    let first_work = AuxiliaryWork {
        chain_id: 1,
        hash: sha256d::Hash::hash(b"token-A"),
    };
    let second_work = AuxiliaryWork {
        chain_id: 2,
        hash: sha256d::Hash::hash(b"token-B"),
    };
    let auxiliary_tree = AuxiliaryTree::build(&[first_work, second_work], 0).unwrap();
    let (mut request_bytes, declared) = test_bch_custom_job_with_aux(
        Arc::clone(&prepared),
        token,
        transactions,
        true,
        full_value,
        auxiliary_tree.commitment,
    );
    let request = SetCustomMiningJob::from_bytes(&mut request_bytes).unwrap();
    let installed = channels
        .install_custom_job(&request, declared, Some(prepared))
        .await
        .unwrap();
    assert_eq!(
        installed[0][2], MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_SUCCESS,
        "{installed:?}"
    );
    let mut installed_payload = installed[0][6..].to_vec();
    let installed = SetCustomMiningJobSuccess::from_bytes(&mut installed_payload).unwrap();
    let full_header = test_bch_solve_custom_job(&request, &extranonce_prefix);
    let mut submit = binary_sv2::to_bytes(SubmitSharesExtended {
        channel_id: 1,
        sequence_number: 1,
        job_id: installed.job_id,
        nonce: full_header.nonce,
        ntime: full_header.time,
        version: request.version,
        extranonce: B032::new(&[0; 8]).unwrap(),
    })
    .unwrap();
    let submitted = channels
        .handle(MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, &mut submit, None)
        .await
        .unwrap();
    assert_eq!(submitted[0][2], MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS);
    let pool_tip: BlockHash = pool.request("getbestblockhash", vec![]).await.unwrap();
    assert_eq!(pool_tip, full_header.block_hash());
    timeout(Duration::from_secs(10), async {
        loop {
            let tip: BlockHash = client.request("getbestblockhash", vec![]).await.unwrap();
            if tip == pool_tip {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the client node did not validate the full-template block");
    let emission = emissions.try_recv().unwrap();
    assert_eq!(emission.header, full_header);
    let share = ShareHeader::from_commitment_and_header(
        emission.share_commitment.unwrap(),
        compute_non_coinbase_root(&[]),
        emission.header,
        None,
        None,
        u64::from(full_height),
        0,
        emission.extranonce,
        emission.coinbase_proof.unwrap(),
    );
    assert_eq!(
        share
            .coinbase_proof
            .merkle_root(&share, &emission.template_merkle_branches)
            .unwrap(),
        full_header.merkle_root
    );
    let mut full_auxpow = AuxPowProof {
        parent_header: full_header,
        coinbase: test_bch_custom_coinbase(&request, &extranonce_prefix),
        coinbase_branch: emission.template_merkle_branches.clone(),
        auxiliary: auxiliary_tree.proofs[0].clone(),
    };
    full_auxpow
        .verify(first_work, full_header.target())
        .unwrap();
    full_auxpow.auxiliary = auxiliary_tree.proofs[1].clone();
    full_auxpow
        .verify(second_work, full_header.target())
        .unwrap();
    println!(
        "{}",
        json!({"mode": "full-template", "height": full_height, "hash": pool_tip.to_string(), "coinbase_value": full_value, "transaction": full_txid, "auxiliary_chains": 2, "auxpow_proof": full_auxpow})
    );

    let raw: String = wallet
        .request(
            "createrawtransaction",
            vec![json!([]), json!({identity.clone(): 1})],
        )
        .await
        .unwrap();
    let funded: Value = wallet
        .request("fundrawtransaction", vec![json!(raw)])
        .await
        .unwrap();
    let signed: Value = wallet
        .request("signrawtransactionwithwallet", vec![funded["hex"].clone()])
        .await
        .unwrap();
    assert_eq!(signed["complete"], true);
    let private_transaction: Transaction =
        deserialize(&hex::decode(signed["hex"].as_str().unwrap()).unwrap()).unwrap();
    let private_txid = private_transaction.compute_txid().to_string();
    let private_fee = Amount::from_btc(funded["fee"].as_f64().unwrap())
        .unwrap()
        .to_sat();
    let pool_mempool: Vec<String> = pool.request("getrawmempool", vec![]).await.unwrap();
    let client_mempool: Vec<String> = client.request("getrawmempool", vec![]).await.unwrap();
    assert!(!pool_mempool.contains(&private_txid));
    assert!(!client_mempool.contains(&private_txid));
    let template: BlockTemplate =
        serde_json::from_str(&pool.get_bch_block_template().await.unwrap()).unwrap();
    assert!(template.transactions.is_empty());
    let private_height = template.height;
    let private_value = template.coinbasevalue + private_fee;
    let prepared = test_bch_prepared_for_template(template);
    let token = prepared
        .mining_job_token([2; 32], prepared.template().curtime)
        .unwrap();
    let private_tree = AuxiliaryTree::build(&[second_work], 7).unwrap();
    assert_ne!(
        private_tree.commitment.merkle_root,
        auxiliary_tree.commitment.merkle_root
    );
    let (mut request_bytes, declared) = test_bch_custom_job_with_aux(
        Arc::clone(&prepared),
        token,
        vec![private_transaction.clone()],
        false,
        private_value,
        private_tree.commitment,
    );
    let request = SetCustomMiningJob::from_bytes(&mut request_bytes).unwrap();
    let private_header = test_bch_solve_custom_job(&request, &extranonce_prefix);
    let private_block = Block {
        header: private_header,
        txdata: vec![
            test_bch_custom_coinbase(&request, &extranonce_prefix),
            private_transaction,
        ],
    };
    client
        .validate_block_proposal(&private_block)
        .await
        .unwrap();
    let installed = channels
        .install_custom_job(&request, declared, Some(prepared))
        .await
        .unwrap();
    assert_eq!(
        installed[0][2], MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_SUCCESS,
        "{installed:?}"
    );
    let mut installed_payload = installed[0][6..].to_vec();
    let installed = SetCustomMiningJobSuccess::from_bytes(&mut installed_payload).unwrap();
    let mut submit = binary_sv2::to_bytes(SubmitSharesExtended {
        channel_id: 1,
        sequence_number: 2,
        job_id: installed.job_id,
        nonce: private_header.nonce,
        ntime: private_header.time,
        version: request.version,
        extranonce: B032::new(&[0; 8]).unwrap(),
    })
    .unwrap();
    let submitted = channels
        .handle(MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, &mut submit, None)
        .await
        .unwrap();
    assert_eq!(submitted[0][2], MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS);
    let emission = emissions.try_recv().unwrap();
    assert!(emission.blocktemplate.transactions.is_empty());
    assert_eq!(emission.header, private_header);
    let still_pool_tip: BlockHash = pool.request("getbestblockhash", vec![]).await.unwrap();
    assert_eq!(
        still_pool_tip, pool_tip,
        "private submissions must not broadcast an incomplete block"
    );
    let share = ShareHeader::from_commitment_and_header(
        emission.share_commitment.unwrap(),
        compute_non_coinbase_root(&[]),
        emission.header,
        None,
        None,
        u64::from(private_height),
        0,
        emission.extranonce,
        emission.coinbase_proof.unwrap(),
    );
    assert_eq!(
        share
            .coinbase_proof
            .merkle_root(&share, &emission.template_merkle_branches)
            .unwrap(),
        private_header.merkle_root
    );
    let mut excessive = private_block.clone();
    excessive.txdata[0].output[0].value += Amount::from_sat(1);
    excessive.header.merkle_root = excessive.compute_merkle_root().unwrap();
    assert!(
        client
            .validate_block_proposal(&excessive)
            .await
            .unwrap_err()
            .to_string()
            .contains("bad-cb-amount")
    );
    let result: Value = client
        .request(
            "submitblock",
            vec![json!(hex::encode(serialize(&private_block)))],
        )
        .await
        .unwrap();
    assert!(result.is_null());
    timeout(Duration::from_secs(10), async {
        loop {
            let tip: BlockHash = pool.request("getbestblockhash", vec![]).await.unwrap();
            if tip == private_header.block_hash() {
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the pool node did not validate the private block broadcast by the client");
    let private_auxpow = AuxPowProof {
        parent_header: private_header,
        coinbase: private_block.txdata[0].clone(),
        coinbase_branch: emission.template_merkle_branches,
        auxiliary: private_tree.proofs[0].clone(),
    };
    private_auxpow
        .verify(second_work, private_header.target())
        .unwrap();
    println!(
        "{}",
        json!({"mode": "coinbase-only", "height": private_height, "hash": private_header.block_hash().to_string(), "coinbase_value": private_value, "private_fee": private_fee, "transaction": private_txid, "auxiliary_chains": 1, "auxpow_proof": private_auxpow})
    );
}
