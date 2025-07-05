use ldk_node::bitcoin;
use ldk_node::bitcoin::{
    Address, Amount, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType, Transaction, TxIn,
    TxOut, Witness};
use ldk_node::bitcoin::key::Keypair;
use ldk_node::bitcoin::secp256k1::{Secp256k1, Message,SecretKey};
use ldk_node::bitcoin::sighash::{SighashCache, Prevouts};
use std::io::Error;
use std::str::FromStr;

pub const DEFAULT_FEE: Amount = Amount::from_sat(200); // Define as a constant

/// Builds a basic transaction with given inputs and outputs.
pub fn build_transaction(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

/// Creates a transaction input.
pub fn build_input(prev_txid: OutPoint, sequence: Option<u32>) -> TxIn {
    TxIn {
        previous_output: prev_txid,
        script_sig: ScriptBuf::new(),
        sequence: sequence.map_or(Sequence::ENABLE_RBF_NO_LOCKTIME, |s| Sequence::from_height(s as u16)),
        witness: Witness::default(),
    }
}

/// Creates a transaction output.
pub fn build_output(value: Amount, address: &Address) -> TxOut {
    TxOut {
        value,
        script_pubkey: address.script_pubkey(),
    }
}

/// Computes the Taproot script spend sighash.
pub fn compute_taproot_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    leaf_hash: TapLeafHash,
    sighash_type: TapSighashType,
) -> Result<Message, bitcoin::secp256k1::Error> {
    let mut sighash_cache = SighashCache::new(tx);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            leaf_hash,
            sighash_type,
        ).expect("Failed to compute signature");
    Message::from_digest_slice(&sighash[..])
}

/// Signs a Taproot sighash with a Schnorr signature.
pub fn sign_schnorr(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    msg: &Message,
    keypair: &Keypair,
) -> bitcoin::secp256k1::schnorr::Signature {
   secp.sign_schnorr_no_aux_rand(&msg, keypair)
}

/// Derives a keypair from a private key string.
pub fn derive_keypair(private_key: &str) -> Result<Keypair, Error> {
    let secret_key = SecretKey::from_str(private_key)
        .map_err(|_| Error::new(std::io::ErrorKind::InvalidInput, "Invalid private key"))?;
    Ok(Keypair::from_secret_key(&Secp256k1::new(), &secret_key))
}