use crate::swap::Swap;
use crate::configuration::HtlcConfig;
use crate::htlc::generate_htlc_address;
use crate::bitcoin::utils::{fetch_utxos_for_address,fetch_tip_block_height};
use ldk_node::lightning_invoice::Bolt11Invoice;


async fn check_bitcoin_from_initiate(swap: Swap, htlc_config: HtlcConfig ) -> bool {
    //getting address 
    let address = generate_htlc_address(&swap).expect("Failed to generate HTLC address");

    // Fetch UTXOs for the generated address
    let utxos = fetch_utxos_for_address(&htlc_config.rpc_url, &address)
        .await
        .expect("Failed to fetch UTXOs");

    if utxos.is_empty() {
        println!("No UTXOs found for the HTLC address: {}", address);
        return false;
    };

    // as of now we will be checking only first utxo not all
    let utxo = &utxos[0];
    let current_height = fetch_tip_block_height(&htlc_config.rpc_url).await
        .expect("Failed to fetch current block height");

    // Checks amount 
    if utxo.value < swap.from_chain.amount {
        println!("Insufficient UTXO value: {} for the required amount: {}", utxo.value, swap.from_chain.amount);
        return false;
    };

    //Checks if the utxo is confirmed 
    if utxo.status.confirmed == true && current_height-utxo.status.block_height >= htlc_config.confirmation_threshold {
        println!("UTXO is confirmed and meets the confirmation threshold.");
    } else {
        println!("UTXO is not confirmed or does not meet the confirmation threshold.");
        return false;
    };

    // checking utxo is in swap window 
    //need to change timelock  to u32 all place 
    if (utxo.status.block_height + swap.from_chain.timelock as u32 - htlc_config.min_buffer_block_for_refund) > current_height {
        println!("UTXO is within the swap window.");
    } else {
        println!("UTXO is outside the swap window.");
        return false;
    };
    

    true
}

pub async fn check_lighting_invoice_to_payable(swap: Swap, htlc_config: HtlcConfig, invoice: Bolt11Invoice) -> bool {
    //getting address 
    let address = generate_htlc_address(&swap).expect("Failed to generate HTLC address");

    // Fetch UTXOs for the generated address
    let utxos = fetch_utxos_for_address(&htlc_config.rpc_url, &address)
        .await
        .expect("Failed to fetch UTXOs");

    // checking if the payment_hack in invoice
    if invoice.payment_hash().to_string() != swap.payment_hash {
        println!("Payment hash in invoice does not match the swap's payment hash.");
        return false;
    }

 
    let invoice_cltv_time = invoice.min_final_cltv_expiry_delta();
    let utxo = &utxos[0];
    let current_height = fetch_tip_block_height(&htlc_config.rpc_url).await
        .expect("Failed to fetch current block height");
    println!("Invoice CLTV Time: {}", invoice_cltv_time);

    // checking invocice time fits the swap window
    // need to fix u32 covertion to full u64 

    let a = (utxo.status.block_height + swap.to_chain.timelock as u32 - htlc_config.min_buffer_block_for_refund);

    let b = current_height + invoice_cltv_time as u32;

    println!("a: {}, b: {}", a, b);

    if (utxo.status.block_height + swap.from_chain.timelock as u32 - htlc_config.min_buffer_block_for_refund) > current_height + invoice_cltv_time as u32 {
        println!("Invoice CLTV time fits within the swap window.");
    } else {
        println!("Invoice CLTV time does not fit within the swap window.");
        return false;
    }


    // checking invoice amount 
    let amount = invoice.amount_milli_satoshis().unwrap() * 1000; // Convert milli-satoshis to satoshis

    if invoice.amount_milli_satoshis().unwrap()*1000 < swap.to_chain.amount {
        println!("Invoice amount is greater than the required amount for the swap.");
        return false;
    }


    true
}

pub async fn check_refund(swap:Swap, htlc_config: HtlcConfig) -> bool {
    // getting address 
    let address = generate_htlc_address(&swap).expect("Failed to generate HTLC address");

    // Fetch UTXOs for the generated address
    let utxos = fetch_utxos_for_address(&htlc_config.rpc_url, &address)
        .await
        .expect("Failed to fetch UTXOs");

    if utxos.is_empty() {
        println!("No UTXOs found for the HTLC address: {}", address);
        return false;
    };

    // as of now we will be checking only first utxo not all
    let utxo = &utxos[0];
    let current_height = fetch_tip_block_height(&htlc_config.rpc_url).await
        .expect("Failed to fetch current block height");

    // checking if the utxo is in refund window
    if (utxo.status.block_height + swap.from_chain.timelock as u32) <= current_height {
        println!("UTXO is within the refund window.");
    } else {
        println!("UTXO is outside the refund window.");
        return false;
    };
    

    true
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
                htlc_type: None,
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

        let result = check_lighting_invoice_to_payable(swap.clone(), htlc_config.clone(),inv).await;
        assert!(!result, "The invoice should be payable for the swap");

        let result = check_bitcoin_from_initiate(swap.clone(), htlc_config.clone()).await;
        assert!(!result, "The Bitcoin UTXO should be valid for the swap");

        let result = check_refund(swap, htlc_config).await;
        assert!(result, "The Bitcoin UTXO should be valid for the refund");

       

        Ok(())

    }




}
