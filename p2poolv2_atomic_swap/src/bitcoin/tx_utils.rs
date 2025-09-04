use ldk_node::bitcoin;
use ldk_node::bitcoin::key::Keypair;
use ldk_node::bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use ldk_node::bitcoin::sighash::{Prevouts, SighashCache};
use ldk_node::bitcoin::{
    Address, Amount, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn,
    TxOut, Witness,
};
use log::{error, info};
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TxUtilsError {
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
    #[error("Failed to compute Taproot sighash: {0}")]
    SighashComputationError(String),
}

/// Builds a basic transaction with given inputs and outputs.
pub fn build_transaction(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    };
    info!(
        "Built transaction with {} inputs and {} outputs",
        tx.input.len(),
        tx.output.len()
    );
    tx
}

/// Creates a transaction input.
pub fn build_input(prev_txid: OutPoint, sequence: Option<u32>) -> TxIn {
    let sequence = sequence.map_or(Sequence::ENABLE_RBF_NO_LOCKTIME, |s| {
        Sequence::from_height(s as u16)
    });
    let input = TxIn {
        previous_output: prev_txid,
        script_sig: ScriptBuf::new(),
        sequence,
        witness: Witness::default(),
    };
    info!("Created transaction input for outpoint: {:?}", prev_txid);
    input
}

/// Creates a transaction output.
pub fn build_output(value: Amount, address: &Address) -> TxOut {
    let output = TxOut {
        value,
        script_pubkey: address.script_pubkey(),
    };
    info!(
        "Created transaction output with value {} to address {}",
        value, address
    );
    output
}

/// Computes the Taproot script spend sighash.
pub fn compute_taproot_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    leaf_hash: TapLeafHash,
    sighash_type: TapSighashType,
) -> Result<Message, TxUtilsError> {
    let mut sighash_cache = SighashCache::new(tx);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            leaf_hash,
            sighash_type,
        )
        .map_err(|e| {
            error!(
                "Failed to compute Taproot sighash for input {}: {}",
                input_index, e
            );
            TxUtilsError::SighashComputationError(e.to_string())
        })?;
    info!("Computed Taproot sighash for input {}", input_index);
    Message::from_digest_slice(&sighash[..]).map_err(|e| {
        error!("Failed to create message from sighash: {}", e);
        TxUtilsError::SighashComputationError(e.to_string())
    })
}

/// Signs a Taproot sighash with a Schnorr signature.
pub fn sign_schnorr(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    msg: &Message,
    keypair: &Keypair,
) -> bitcoin::secp256k1::schnorr::Signature {
    let signature = secp.sign_schnorr_no_aux_rand(msg, keypair);
    info!("Generated Schnorr signature for message");
    signature
}

/// Derives a keypair from a private key string.
pub fn derive_keypair(private_key: &str) -> Result<Keypair, TxUtilsError> {
    let secret_key = SecretKey::from_str(private_key).map_err(|e| {
        error!("Invalid private key: {}", e);
        TxUtilsError::InvalidPrivateKey(e.to_string())
    })?;
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), &secret_key);
    info!("Derived keypair from private key");
    Ok(keypair)
}
