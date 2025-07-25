use crate::swap::Swap;
use crate::configuration::HtlcConfig;
use crate::htlc::generate_htlc_address;
use crate::bitcoin::utils::{fetch_utxos_for_address,fetch_tip_block_height,Utxo};
use ldk_node::lightning_invoice::Bolt11Invoice;


/// Checks if a UTXO is confirmed with required confirmations
/// and still within the claimable swap window.
pub fn is_valid_htlc_utxo(
    utxo: &Utxo,
    confirmation_threshold: u32,
    timelock: u32,
    min_buffer_blocks: u32,
    current_block_height: u32,
) -> bool {
    // 1️⃣ Check confirmation status and depth
    if utxo.status.confirmed {
        let confirmations = current_block_height.saturating_sub(utxo.status.block_height);
        if confirmations < confirmation_threshold {
            println!(
                "UTXO has {} confirmations, requires minimum {}.",
                confirmations, confirmation_threshold
            );
            return false;
        }
    } else {
        println!("UTXO is unconfirmed.");
        return false;
    }

    // 2️⃣ Check if within swap claim window
    let expiry_height = utxo.status.block_height + timelock;
    if expiry_height.saturating_sub(min_buffer_blocks) > current_block_height {
        println!(
            "UTXO is within the swap window. Expires at block {}.",
            expiry_height
        );
    } else {
        println!(
            "UTXO is outside the swap window. Expired at {}, current height {}.",
            expiry_height, current_block_height
        );
        return false;
    }

    true
}

/// Checks if a given UTXO is eligible for refund based on timelock expiry.
pub fn is_utxo_refundable(
    utxo_block_height: u32,
    timelock: u32,
    current_block_height: u32,
) -> bool {
    let refund_height = utxo_block_height + timelock;

    if current_block_height >= refund_height {
        println!(
            "UTXO is in refund window. Refund allowed since block {}, current block {}.",
            refund_height, current_block_height
        );
        true
    } else {
        println!(
            "UTXO is not yet refundable. Refund at block {}, current block {}.",
            refund_height, current_block_height
        );
        false
    }
}




#[cfg(test)]
mod tests {
    use super::*;
    use ldk_node::bitcoin;
    use ldk_node::bitcoin::Network;
    use crate::swap::{Bitcoin, HTLCType, Lightning, Swap};
    use ldk_node::lightning_invoice::SignedRawBolt11Invoice;
    use std::error::Error;
    use crate::configuration::HtlcConfig;

    #[tokio::test]
    async fn test_check_lighting_invoice_to_payable() -> Result<(), Box<dyn Error>>{
         println!("Testing P2TR2 address generation...");
        let swap = Swap {
            payment_hash: "380a03bf6e5bb373c82084e80e1c999e3a9db565d6c09f57547ed86bca95b88c".to_string(),
            from_chain: Bitcoin {
                initiator_pubkey: "fdfbf55076737c3b8e150ab1fcf138caa7a8671d2185695944c2581ef11aa866".to_string(),
                responder_pubkey: "456db773aa5c4cc6ed3a4780243d16bd58220be318702603b219fe79eceb848f".to_string(),
                timelock: 5,
                amount: 1000,
                htlc_type: HTLCType::P2tr2,
            },
            to_chain: Lightning {
                timelock: 2000,
                amount: 500000,
              
            },
        };

        let inv = "lntbs10u1p5x8u0ydq5w3jhxapqd9h8vmmfvdjsnp4q0svv2k4d2ca24r4rprcgpma7mk3t6cltwduvxj8lannxqng2en7spp58q9q80mwtweh8jpqsn5qu8yencafmdt96mqf74650mvxhj54hzxqsp54a67xeeyqjr4yfs6hrdvvzggkzaulyu0z3pgtlypkdmgstm8e8ps9qyysgqcqpcxqzrc2l060cxra9c0h35cc8vtmrjjwww6538mdegr495ckxee7wz4fl6n60z8gp3ucm7r4uzsqf5qdk9pcwmzgge8wc4l992yr36tdw9nglspjl27gz".parse::<Bolt11Invoice>().unwrap();

        let htlc_config = HtlcConfig {
            db_path : "data/htlc_db".to_string(),
            private_key :"8957096d6d79f8ba171bcce36eb0e6e6a6c02f17546180d849745988b2f5b0ee".to_string(),
            rpc_url : "https://mutinynet.com/api/".to_string(),
            confirmation_threshold : 3,
            min_buffer_block_for_refund : 2
        };

        let result = check_lighting_invoice_to_payable(swap.clone(), &htlc_config,inv).await;
        assert!(!result, "The invoice should be payable for the swap");

        let result = check_bitcoin_from_initiate(swap.clone(), &htlc_config).await;
        assert!(!result, "The Bitcoin UTXO should be valid for the swap");

        let result = check_refund(swap, &htlc_config).await;
        assert!(result, "The Bitcoin UTXO should be valid for the refund");

       

        Ok(())

    }




}
