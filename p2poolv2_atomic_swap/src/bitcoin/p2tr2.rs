use crate::bitcoin::tx_utils::{
    build_input, build_output, build_transaction, compute_taproot_sighash, derive_keypair,
    sign_schnorr,
};
use crate::bitcoin::utils::Utxo;
use crate::swap::{Bitcoin, HTLCType, Swap};
use ldk_node::bitcoin::{
    opcodes,
    script::PushBytesBuf,
    secp256k1::Secp256k1,
    taproot::{LeafVersion, TaprootBuilder, TaprootBuilderError, TaprootSpendInfo},
    Address, Amount, KnownHrp, OutPoint, ScriptBuf, TapLeafHash, TapSighashType, Transaction, TxIn,
    TxOut, Txid, Witness, XOnlyPublicKey,
};
use log::{info, error};
use thiserror::Error;
use std::str::FromStr;

// Well-recognized NUMS point from BIP-341 (SHA-256 of generator point's compressed public key)
const NUMS_POINT: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

// Default fee for the transaction, can be adjusted based on network conditions
const DEFAULT_FEE: Amount = Amount::from_sat(200);

#[derive(Error, Debug)]
pub enum TaprootError {
    #[error("Invalid HTLC type for P2TR address: {0}")]
    InvalidHtlcType(String),
    #[error("Timelock must be positive")]
    InvalidTimelock,
    #[error("Invalid NUMS point: {0}")]
    InvalidNumsPoint(String),
    #[error("Failed to build Taproot spend info")]
    TaprootBuildError,
    #[error("Invalid payment hash: {0}")]
    InvalidPaymentHash(String),
    #[error("Failed to create PushBytesBuf: {0}")]
    PushBytesBufError(String),
    #[error("Invalid responder pubkey: {0}")]
    InvalidResponderPubkey(String),
    #[error("Invalid initiator pubkey: {0}")]
    InvalidInitiatorPubkey(String),
    #[error("Failed to get control block")]
    ControlBlockError,
    #[error("Invalid preimage hex: {0}")]
    InvalidPreimage(String),
    #[error("Failed to compute sighash for input {index}: {error}")]
    SighashError { index: usize, error: String },
    #[error("Invalid Txid: {0}")]
    InvalidTxid(String),
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
    #[error("Taproot builder error: {0}")]
    TaprootBuilderError(String),
}

impl From<std::io::Error> for TaprootError {
    fn from(e: std::io::Error) -> Self {
        TaprootError::InvalidPrivateKey(e.to_string())
    }
}

impl From<TaprootBuilderError> for TaprootError {
    fn from(e: TaprootBuilderError) -> Self {
        TaprootError::TaprootBuilderError(e.to_string())
    }
}

pub fn generate_p2tr_address(
    swap: &Swap,
    network: KnownHrp,
) -> Result<(Address, TaprootSpendInfo), TaprootError> {
    let secp = Secp256k1::new();
    let taproot_spend_info = get_spending_info(&swap.from_chain, &swap.payment_hash)?;
    let address = Address::p2tr(
        &secp,
        taproot_spend_info.internal_key(),
        taproot_spend_info.merkle_root(),
        network,
    );
    info!("Generated P2TR address: {}", address);
    Ok((address, taproot_spend_info))
}

pub fn redeem_taproot_htlc(
    swap: &Swap,
    preimage: &str,
    receiver_private_key: &str,
    utxos: Vec<Utxo>,
    transfer_to_address: &Address,
    fee_rate_per_vb: u64,
    network: KnownHrp,
) -> Result<Transaction, TaprootError> {
    let secp = Secp256k1::new();
    info!("Starting P2TR redeem for swap: {:?}", swap);

    // 1️⃣ Generate Taproot spend info (address + spend tree)
    let (htlc_address, spend_info) = generate_p2tr_address(swap, network)?;

    // 2️⃣ Get the HTLC redeem script and control block
    let redeem_script = p2tr2_redeem_script(&swap.payment_hash, &swap.from_chain.responder_pubkey)?;
    let script_ver = (redeem_script.clone(), LeafVersion::TapScript);

    let control_block = spend_info
        .control_block(&script_ver)
        .ok_or(TaprootError::ControlBlockError)?;

    // 3️⃣ Derive receiver's keypair
    let keypair = derive_keypair(receiver_private_key)
        .map_err(|e| TaprootError::InvalidPrivateKey(e.to_string()))?;

    // 4️⃣ Prepare inputs, prevouts, and total input amount
    let mut inputs = Vec::new();
    let mut prevouts = Vec::new();
    let mut total_amount = Amount::from_sat(0);

    for utxo in &utxos {
        let prev_txid = Txid::from_str(&utxo.txid).map_err(|e| TaprootError::InvalidTxid(e.to_string()))?;
        let outpoint = OutPoint::new(prev_txid, utxo.vout);
        let input = build_input(outpoint, None);
        inputs.push(input);

        let amount = Amount::from_sat(utxo.value);
        total_amount += amount;

        let prevout = TxOut {
            value: amount,
            script_pubkey: htlc_address.script_pubkey(),
        };
        prevouts.push(prevout);
    }

    let input_count = inputs.len();
    let output_count = 1;

    // 5️⃣ Estimate fees
    let witness_size_per_input = 1 + 65 + 33 + 81 + 34;
    let fee = estimate_htlc_fee(input_count, output_count, witness_size_per_input, fee_rate_per_vb);

    // 6️⃣ Build output
    let output = build_output(total_amount - fee, transfer_to_address);

    // 7️⃣ Build unsigned transaction
    let mut tx = build_transaction(inputs, vec![output]);

    // 8️⃣ Prepare shared data
    let leaf_hash = TapLeafHash::from_script(&redeem_script, LeafVersion::TapScript);
    let preimage_bytes = hex::decode(preimage)
        .map_err(|e| TaprootError::InvalidPreimage(e.to_string()))?;

    // 🔄 Sign each input individually and assign witness
    for i in 0..tx.input.len() {
        let msg = compute_taproot_sighash(
            &tx,
            i,
            &prevouts,
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| TaprootError::SighashError {
            index: i,
            error: e.to_string(),
        })?;

        let signature = sign_schnorr(&secp, &msg, &keypair);

        let mut witness = Witness::new();
        witness.push(signature.as_ref());
        witness.push(preimage_bytes.clone());
        witness.push(redeem_script.to_bytes());
        witness.push(&control_block.serialize());

        tx.input[i].witness = witness;
    }

    info!("Redeemed transaction: {:?}", tx);
    Ok(tx)
}

pub fn refund_taproot_htlc(
    swap: &Swap,
    sender_private_key: &str,
    utxos: Vec<Utxo>,
    refund_to_address: &Address,
    fee_rate_per_vb: u64,
    network: KnownHrp,
) -> Result<Transaction, TaprootError> {
    let secp = Secp256k1::new();
    info!("Starting P2TR refund for swap: {:?}", swap);

    // 1️⃣ Generate Taproot spend info
    let (htlc_address, spend_info) = generate_p2tr_address(swap, network)?;

    // 2️⃣ Get refund script and control block
    let initiator_pubkey = &swap.from_chain.initiator_pubkey;
    let refund_script = p2tr2_refund_script(swap.from_chain.timelock, initiator_pubkey)?;
    let script_ver = (refund_script.clone(), LeafVersion::TapScript);

    let control_block = spend_info
        .control_block(&script_ver)
        .ok_or(TaprootError::ControlBlockError)?;

    // 3️⃣ Derive sender's keypair
    let keypair = derive_keypair(sender_private_key)
        .map_err(|e| TaprootError::InvalidPrivateKey(e.to_string()))?;

    // 4️⃣ Prepare inputs, prevouts, total amount
    let mut inputs = Vec::new();
    let mut prevouts = Vec::new();
    let mut total_amount = Amount::from_sat(0);

    for utxo in utxos.iter() {
        let prev_txid = Txid::from_str(&utxo.txid).map_err(|e| TaprootError::InvalidTxid(e.to_string()))?;
        let outpoint = OutPoint::new(prev_txid, utxo.vout);
        let input = build_input(outpoint, Some(swap.from_chain.timelock as u32)); // locktime for refund
        inputs.push(input);

        let input_amount = Amount::from_sat(utxo.value);
        let prevout = TxOut {
            value: input_amount,
            script_pubkey: htlc_address.script_pubkey(),
        };

        total_amount += input_amount;
        prevouts.push(prevout);
    }

    let input_count = inputs.len();
    let output_count = 1;

    // 5️⃣ Estimate fee based on transaction weight
    let witness_size_per_input = 1 + 65 + 81 + 34; // Sig + Script + ControlBlock
    let fee_amount = estimate_htlc_fee(
        input_count,
        output_count,
        witness_size_per_input,
        fee_rate_per_vb,
    );

    // 6️⃣ Build output
    let output = build_output(total_amount - fee_amount, refund_to_address);

    // 7️⃣ Build transaction
    let mut tx = build_transaction(inputs, vec![output]);

    // 8️⃣ Compute Taproot sighash
    let leaf_hash = TapLeafHash::from_script(&refund_script, LeafVersion::TapScript);
    
    for i in 0..tx.input.len() {
        let msg = compute_taproot_sighash(
            &tx,
            i,
            &prevouts,
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| TaprootError::SighashError {
            index: i,
            error: e.to_string(),
        })?;

        let signature = sign_schnorr(&secp, &msg, &keypair);

        // 🔟 Build witness stack (Sig | RefundScript | ControlBlock)
        let mut witness = Witness::new();
        witness.push(signature.as_ref());
        witness.push(refund_script.as_bytes());
        witness.push(&control_block.serialize());

        tx.input[i].witness = witness;
    }

    info!("Refunded transaction: {:?}", tx);
    Ok(tx)
}

fn get_spending_info(
    bitcoin: &Bitcoin,
    payment_hash: &String,
) -> Result<TaprootSpendInfo, TaprootError> {
    if bitcoin.htlc_type != HTLCType::P2tr2 {
        return Err(TaprootError::InvalidHtlcType(format!("{:?}", bitcoin.htlc_type)));
    }

    // Validate timelock
    if bitcoin.timelock == 0 {
        return Err(TaprootError::InvalidTimelock);
    }

    // Create redeem script: OP_SHA256 <hash> OP_EQUALVERIFY <responder_pubkey> OP_CHECKSIG
    let redeem_script = p2tr2_redeem_script(payment_hash, &bitcoin.responder_pubkey)?;

    // Create refund script: <timelock> OP_CSV OP_DROP <initiator_pubkey> OP_CHECKSIG
    let refund_script = p2tr2_refund_script(bitcoin.timelock, &bitcoin.initiator_pubkey)?;

    // Use a NUMS point as the internal key
    let internal_key =
        XOnlyPublicKey::from_str(NUMS_POINT).map_err(|e| TaprootError::InvalidNumsPoint(e.to_string()))?;

    // Build Taproot script tree with redeem and refund paths
    let taproot_builder = TaprootBuilder::new()
        .add_leaf(1, redeem_script)?
        .add_leaf(1, refund_script)?;

    let secp = Secp256k1::new();
    let taproot_spend_info = taproot_builder
        .finalize(&secp, internal_key)
        .map_err(|_| TaprootError::TaprootBuildError)?;

    Ok(taproot_spend_info)
}

fn p2tr2_redeem_script(
    payment_hash: &String,
    responder_pubkey: &String,
) -> Result<ScriptBuf, TaprootError> {
    let payment_hash_bytes =
        hex::decode(payment_hash).map_err(|e| TaprootError::InvalidPaymentHash(e.to_string()))?;
    let paymenthash_buf = PushBytesBuf::try_from(payment_hash_bytes)
        .map_err(|e| TaprootError::PushBytesBufError(e.to_string()))?;
    let responder_pubkey = XOnlyPublicKey::from_str(responder_pubkey)
        .map_err(|e| TaprootError::InvalidResponderPubkey(e.to_string()))?;

    let redeem_script = ScriptBuf::builder()
        .push_opcode(opcodes::all::OP_SHA256)
        .push_slice(paymenthash_buf)
        .push_opcode(opcodes::all::OP_EQUALVERIFY)
        .push_x_only_key(&responder_pubkey)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();

    Ok(redeem_script)
}

fn p2tr2_refund_script(
    timelock: u64,
    initiator_pubkey: &String,
) -> Result<ScriptBuf, TaprootError> {
    let initiator_pubkey = XOnlyPublicKey::from_str(initiator_pubkey)
        .map_err(|e| TaprootError::InvalidInitiatorPubkey(e.to_string()))?;
    let redeem_script = ScriptBuf::builder()
        .push_int(timelock as i64)
        .push_opcode(opcodes::all::OP_CSV)
        .push_opcode(opcodes::all::OP_DROP)
        .push_x_only_key(&initiator_pubkey)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();
    Ok(redeem_script)
}

fn estimate_htlc_fee(
    input_count: usize,
    output_count: usize,
    witness_size_per_input: usize,
    fee_rate_per_vb: u64,
) -> Amount {
    let base_size = 6 + (input_count * 40) + 1 + (output_count * 43) + 4;
    let total_witness_size = input_count * witness_size_per_input;
    let total_weight = base_size * 4 + total_witness_size;
    let vsize = (total_weight + 3) / 4;
    Amount::from_sat(vsize as u64 * fee_rate_per_vb)
}

#[cfg(test)]
mod tests {
    use core::net;

    use super::*;
    use crate::swap::{Bitcoin, HTLCType, Lightning, Swap};
    use ldk_node::bitcoin;
    use ldk_node::bitcoin::Network;
    use log::info;

    #[test]
    fn test_generate_p2tr_address() -> Result<(), TaprootError> {
        info!("Testing P2TR2 address generation...");
        let swap = Swap {
            payment_hash: "48eb4ce3939c3b70bde47cd38610fc9cb8e419498d6fd46d63e66638e7cd104e"
                .to_string(),
            from_chain: Bitcoin {
                initiator_pubkey:
                    "fdfbf55076737c3b8e150ab1fcf138caa7a8671d2185695944c2581ef11aa866".to_string(),
                responder_pubkey:
                    "456db773aa5c4cc6ed3a4780243d16bd58220be318702603b219fe79eceb848f".to_string(),
                timelock: 100,
                amount: 500000,
                htlc_type: HTLCType::P2tr2,
            },
            to_chain: Lightning {
                timelock: 2000,
                amount: 500000,
            },
        };
        info!("Swap details: {:?}", swap);
        let network = KnownHrp::Testnets; // Use Testnet for testing
        let address = generate_p2tr_address(&swap, network)?;
        assert_eq!(
            address.0.to_string(),
            "tb1p9qg094ppmsx39cnl0sffgu4uhtggj9vy9ll4lq9nvjnn762t4jgsdygfae"
        );
        info!("Generated P2TR2 address: {}", address.0);
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_redeem_taproot_htlc() -> Result<(), TaprootError> {
        info!("Testing P2TR2 redeem ...");
        let swap = Swap {
            payment_hash: "48eb4ce3939c3b70bde47cd38610fc9cb8e419498d6fd46d63e66638e7cd104e"
                .to_string(),
            from_chain: Bitcoin {
                initiator_pubkey:
                    "fdfbf55076737c3b8e150ab1fcf138caa7a8671d2185695944c2581ef11aa866".to_string(),
                responder_pubkey:
                    "456db773aa5c4cc6ed3a4780243d16bd58220be318702603b219fe79eceb848f".to_string(),
                timelock: 100,
                amount: 500000,
                htlc_type: HTLCType::P2tr2,
            },
            to_chain: Lightning {
                timelock: 2000,
                amount: 500000,
            },
        };
        info!("Swap details: {:?}", swap);
        let network = KnownHrp::Testnets; // Use Testnet for testing
        let to_address = Address::from_str("tb1qsa7xa5npxkwnjaafnenmy70ggwvsea4rmlkq0j")
            .unwrap()
            .require_network(Network::Signet)
            .unwrap();
        let utxos = vec![Utxo {
            txid: "7a1e40414520e2b53566627e7420a135fd0b4ab05183f3016ae41a2050ff382d".to_string(),
            vout: 1,
            value: 1000,
            status: Default::default(),
        }];
        let trx = redeem_taproot_htlc(
            &swap,
            "2a0353768872c7e5b6b9c164f1ca3d3a9d359af9931ffdabefba3416de962907",
            "c929c768be0902d5bb7ae6e38bdc6b3b24cefbe93650da91975756a09e408460",
            utxos,
            &to_address,
            0,
            network,
        )?;

        info!("Redeemed transaction: {:?}", trx);

        let tx_hex = bitcoin::consensus::encode::serialize_hex(&trx);

        assert_eq!(tx_hex,"020000000001012d38ff50201ae46a01f38351b04a0bfd35a120747e626635b5e2204541401e7a0100000000fdffffff012003000000000000160014877c6ed261359d3977a99e67b279e843990cf6a304408419213f0c56f2e45d5662ae0fea1c57bae1d990f7c253b847af2231a66662b1825b5b3c9ba301c276408b536d2cb554829ad3cb41b8ebdd68401a6e4b61333f202a0353768872c7e5b6b9c164f1ca3d3a9d359af9931ffdabefba3416de96290745a82048eb4ce3939c3b70bde47cd38610fc9cb8e419498d6fd46d63e66638e7cd104e8820456db773aa5c4cc6ed3a4780243d16bd58220be318702603b219fe79eceb848fac41c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac027da14456052b30b39acba882180211e444c8460303075491a7dc1f221e3dc5400000000");
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_refund_taproot_htlc() -> Result<(), TaprootError> {
        info!("Testing P2TR2 refund ...");
        let swap = Swap {
            payment_hash: "b64a936fb0bf9898ef881907887b4e1104c81dbc84f8970b94e20e6596ba41b8"
                .to_string(),
            from_chain: Bitcoin {
                initiator_pubkey:
                    "fdfbf55076737c3b8e150ab1fcf138caa7a8671d2185695944c2581ef11aa866".to_string(),
                responder_pubkey:
                    "456db773aa5c4cc6ed3a4780243d16bd58220be318702603b219fe79eceb848f".to_string(),
                timelock: 5,
                amount: 500000,
                htlc_type: HTLCType::P2tr2,
            },
            to_chain: Lightning {
                timelock: 2000,
                amount: 500000,
            },
        };
        info!("Swap details: {:?}", swap);
        let network = KnownHrp::Testnets; // Use Testnet for testing
        let to_address = Address::from_str("tb1qt0gnwxn5ejspy0tlpyw4pjyt3ydskmwptc5ecr")
            .unwrap()
            .require_network(Network::Signet)
            .unwrap();
        let utxos = vec![Utxo {
            txid: "3f0bcef29476ccd8d6f6c758b1cb6b87c99a238f549cea313da9f4f655b4d361".to_string(),
            vout: 0,
            value: 1000,
            status: Default::default(),
        }];
        let trx = refund_taproot_htlc(
            &swap,
            "8957096d6d79f8ba171bcce36eb0e6e6a6c02f17546180d849745988b2f5b0ee",
            utxos,
            &to_address,
            0,
            network,
        )?;

        info!("Refunded transaction: {:?}", trx);

        let tx_hex = bitcoin::consensus::encode::serialize_hex(&trx);

        assert_eq!(tx_hex,"0200000000010161d3b455f6f4a93d31ea9c548f239ac9876bcbb158c7f6d6d8cc7694f2ce0b3f0000000000050000000120030000000000001600145bd1371a74cca0123d7f091d50c88b891b0b6dc1034075c4d455a491a2618656dd5776eed4dc8c82d085cc4a00ef47691a070936b816501f44fbd648fad5bd5f060da054a1a931a910f55e9945a74a6d2356f3c77bce2555b27520fdfbf55076737c3b8e150ab1fcf138caa7a8671d2185695944c2581ef11aa866ac41c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac048e28665843ab4618bef68a6a5ae7040f87c719c6d535139147eb812bdd1178400000000");
        Ok(())
    }
}