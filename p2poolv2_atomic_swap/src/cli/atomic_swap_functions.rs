use crate::bitcoin::utils::{broadcast_trx, fetch_tip_block_height, fetch_utxos_for_address,};
use crate::configuration::HtlcConfig;
use crate::htlc::{generate_htlc_address, redeem_htlc_address, refund_htlc_address};
use crate::lightning_node::{getinvoice, onchaintransfer, payinvoice,getaddress};
use crate::swap::{create_swap,retrieve_swap, Swap, HTLCType, Bitcoin, Lightning};
use ldk_node::lightning_invoice::Bolt11Invoice;
use ldk_node::payment::{PaymentKind};
use ldk_node::Node;
use std::{thread, time::Duration};
use crate::bitcoin::checks::{filter_valid_htlc_utxos,filter_refundable_utxos};
use crate::lightning_node::checks::is_invoice_payable_simple;



pub async fn initiate_onchain_to_lightning_swap(node : &Node,db_path:&str,initiator_pubkey: String,responder_pubkey: String,timelock: u64,from_amount: u64,htlc_type: HTLCType, to_amount: u64){
    // Creating a invoice to get payment hash 
    let invoice = getinvoice(node, to_amount*1000 ).await.expect("error in creating invoice ");

    let payment_hash = invoice.payment_hash().to_string();

    //constructing from chain 
    let from_chain = Bitcoin{
        initiator_pubkey: initiator_pubkey,
        responder_pubkey :responder_pubkey,
        timelock: timelock,
        amount:from_amount,
        htlc_type: htlc_type,
    };

    //caonstruct to chain 
    let to_chain = Lightning{
        timelock: invoice.min_final_cltv_expiry_delta(),
        amount: to_amount,
    };

    //creating swap 
    let swap = Swap{
        payment_hash: payment_hash,
        from_chain: from_chain,
        to_chain: to_chain
    };

    //uploading this swap to db 
    let _swap_result= create_swap(&swap, db_path).expect("Error in creating a swap");

    //sending onchain bitcoin to the htlc address 
    let htlc_address = generate_htlc_address(&swap).expect("Error in creating a address");

    let txid =onchaintransfer(node, &htlc_address, from_amount).await.expect("Error in getting txid");

    println!("Swap created {:?}", swap);
    println!("Lightining invoice {}",invoice);
    println!("Onchain trx done and submited {}", txid);



    
 
}

pub async fn store_swap_to_db(db_path:&str,initiator_pubkey: String,responder_pubkey: String,timelock: u64,from_amount: u64,htlc_type: HTLCType, to_amount: u64,payment_hash: String){

    let from_chain = Bitcoin{
        initiator_pubkey: initiator_pubkey,
        responder_pubkey :responder_pubkey,
        timelock: timelock,
        amount:from_amount,
        htlc_type: htlc_type,
    };

    let to_chain = Lightning{
        timelock: timelock,
        amount: to_amount,
    };

    let swap = Swap{
        payment_hash: payment_hash,
        from_chain: from_chain,
        to_chain: to_chain
    };

    let swap_result= create_swap(&swap, db_path).expect("Error in creating a swap");

    println!("Swap stored to db {:?}", swap_result);

}

pub async fn read_swap_from_db(db_path:&str,swap_id: &str){
    let swap = retrieve_swap(db_path, swap_id)
        .expect("Error in fetching data from db")
        .expect("swap id not found in database");

    println!("Swap read from db {:?}", swap);
}

pub async fn redeem_swap(
    node: &Node,
    htlc_config: &HtlcConfig,
    db_path: &str,
    swap_id: &str,
    invoice: &Bolt11Invoice,
) {
    let private_key = &htlc_config.private_key;
    let swap = retrieve_swap(db_path, swap_id)
        .expect("Error fetching swap from db")
        .expect("Swap ID not found in database");

    println!("Loaded swap from db: {:?}", swap);

    let htlc_address = generate_htlc_address(&swap).expect("Error generating HTLC address");

    let utxos = fetch_utxos_for_address(&htlc_config.rpc_url, &htlc_address)
        .await
        .expect("Error fetching UTXOs");

    let current_block_height = fetch_tip_block_height(&htlc_config.rpc_url)
        .await
        .expect("Error fetching current block height");

    let (valid_utxos, min_swap_window, total_sats) = filter_valid_htlc_utxos(
        utxos.iter().collect(),
        htlc_config.confirmation_threshold,
        swap.from_chain.timelock as u32,
        htlc_config.min_buffer_block_for_refund,
        current_block_height,
    );

    if valid_utxos.is_empty() {
        println!("No valid UTXOs found");
        return;
    }

    if swap.from_chain.amount < total_sats {
        println!("Required amount not met by UTXOs");
        return;
    }

    // Check if the Lightning invoice is payable
    let invoice_payable = is_invoice_payable_simple(
        &swap.payment_hash,
        swap.to_chain.amount,
        invoice,
        min_swap_window as u64,
    );

    if invoice_payable.is_err() {
        println!("Invoice is not payable: checks failed");
        return;
    }

    // Get a new address from the node (not used here, but could be for change)
    let _funding_address = getaddress(node).await.expect("Error getting address");

    // Pay the invoice
    match payinvoice(node, invoice).await {
        Ok(payment_id) => {
            println!("Paid invoice successfully. Follow up using this payment ID: {:?}", payment_id);

            thread::sleep(Duration::from_secs(5));

            let payment_kind = node.payment(&payment_id).expect("Errror in getting payment id").kind;

            if let PaymentKind::Bolt11 {  preimage, .. } = payment_kind{
                let preimage = preimage.expect("error in getting preimage");
                //calling redeem 
                let raw_tx = redeem_htlc_address(&swap, preimage.to_string().as_str(), private_key.as_str(), utxos, &_funding_address).expect("error in sending trx");
                let tx_hex = ldk_node::bitcoin::consensus::encode::serialize_hex(&raw_tx);
                let result = broadcast_trx(&htlc_config.rpc_url, &tx_hex).await.expect("error broadcasting trx");

                println!("the result is {}", result);

            } 
        }
        Err(e) => {
            println!("Error paying the invoice: {}", e);
        }
    }

    

    
}

pub async fn refund_swap(
    node: &Node,
    htlc_config: &HtlcConfig,
    db_path: &str,
    swap_id: &str,
) {
    let swap = retrieve_swap(db_path, swap_id)
        .expect("Error fetching swap from db")
        .expect("Swap ID not found in database");

    println!("Loaded swap from db: {:?}", swap);

    let htlc_address = generate_htlc_address(&swap).expect("Error generating HTLC address");

    let utxos = fetch_utxos_for_address(&htlc_config.rpc_url, &htlc_address)
        .await
        .expect("Error fetching UTXOs");

    let current_block_height = fetch_tip_block_height(&htlc_config.rpc_url)
        .await
        .expect("Error fetching current block height");

    let filter_refundable_utxos = filter_refundable_utxos(
        utxos.iter().collect(),
        swap.from_chain.timelock as u32,
        current_block_height,
    );

    if filter_refundable_utxos.is_empty() {
        println!("No refundable UTXOs found");
        return;
    }

    // Get a new address from the node (not used here, but could be for change)
    let _funding_address = getaddress(node).await.expect("Error getting address");

    // Refund the HTLC address
    let refund_result = refund_htlc_address(&swap, &htlc_config.private_key, utxos, &_funding_address).expect("Error refunding HTLC address");

    let tx_hex = ldk_node::bitcoin::consensus::encode::serialize_hex(&refund_result);
    let result = broadcast_trx(&htlc_config.rpc_url, &tx_hex)
        .await
        .expect("Error broadcasting transaction");
    println!("Refund transaction broadcasted successfully: {}", result);


}




