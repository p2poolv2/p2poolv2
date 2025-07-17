use ldk_node::lightning_invoice::Bolt11Invoice;

/// Check if a Lightning invoice is payable under given swap constraints.
pub fn is_invoice_payable_simple(
    expected_payment_hash: &str,
    min_required_amount_sat: u64,
    invoice: &Bolt11Invoice,
    max_allowed_cltv_expiry: u64,
) -> bool {
    // 1️⃣ Payment hash match
    if invoice.payment_hash().to_string() != expected_payment_hash {
        println!("❌ Invoice payment hash does not match expected swap payment hash.");
        return false;
    }

    // 2️⃣ Invoice CLTV expiry constraint
    let invoice_cltv = invoice.min_final_cltv_expiry_delta() as u64;
    println!("🔍 Invoice CLTV expiry delta: {}", invoice_cltv);

    if invoice_cltv > max_allowed_cltv_expiry {
        println!(
            "❌ Invoice CLTV delta ({}) exceeds maximum allowed swap window ({}).",
            invoice_cltv, max_allowed_cltv_expiry
        );
        return false;
    }

    // 3️⃣ Invoice amount constraint
    let invoice_amount_sat = match invoice.amount_milli_satoshis() {
        Some(msat) => msat / 1000, // convert msat to sat
        None => {
            println!("❌ Invoice has no amount specified.");
            return false;
        }
    };

    println!(
        "🔍 Invoice amount: {} sat, required minimum: {} sat",
        invoice_amount_sat, min_required_amount_sat
    );

    if invoice_amount_sat < min_required_amount_sat {
        println!("❌ Invoice amount is less than required swap amount.");
        return false;
    }

    println!("✅ Invoice is payable.");
    true
}
