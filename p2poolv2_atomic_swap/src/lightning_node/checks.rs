use ldk_node::lightning_invoice::Bolt11Invoice;
use log::info;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum InvoiceValidationError {
    #[error("Invoice payment hash does not match expected swap payment hash: got {got}, expected {expected}")]
    PaymentHashMismatch { got: String, expected: String },
    #[error("Invoice CLTV delta ({got}) exceeds maximum allowed swap window ({expected})")]
    CltvExceedsMax { got: u64, expected: u64 },
    #[error("Invoice has no amount specified")]
    NoAmountSpecified,
    #[error("Invoice amount ({got} sat) is less than required swap amount ({expected} sat)")]
    AmountTooLow { got: u64, expected: u64 },
}

/// Check if a Lightning invoice is payable under given swap constraints.
pub fn is_invoice_payable_simple(
    expected_payment_hash: &str,
    min_required_amount_sat: u64,
    invoice: &Bolt11Invoice,
    max_allowed_cltv_expiry: u64,
) -> Result<(), InvoiceValidationError> {
    // 1️⃣ Payment hash match
    let invoice_payment_hash = invoice.payment_hash().to_string();
    if invoice_payment_hash != expected_payment_hash {
        info!(
            "❌ Invoice payment hash does not match expected swap payment hash: got {}, expected {}",
            invoice_payment_hash, expected_payment_hash
        );
        return Err(InvoiceValidationError::PaymentHashMismatch {
            got: invoice_payment_hash,
            expected: expected_payment_hash.to_string(),
        });
    }

    // 2️⃣ Invoice CLTV expiry constraint
    let invoice_cltv = invoice.min_final_cltv_expiry_delta() as u64;
    info!("🔍 Invoice CLTV expiry delta: {}", invoice_cltv);

    if invoice_cltv > max_allowed_cltv_expiry {
        info!(
            "❌ Invoice CLTV delta ({}) exceeds maximum allowed swap window ({}).",
            invoice_cltv, max_allowed_cltv_expiry
        );
        return Err(InvoiceValidationError::CltvExceedsMax {
            got: invoice_cltv,
            expected: max_allowed_cltv_expiry,
        });
    }

    // 3️⃣ Invoice amount constraint
    let invoice_amount_sat = match invoice.amount_milli_satoshis() {
        Some(msat) => msat / 1000, // convert msat to sat
        None => {
            info!("❌ Invoice has no amount specified.");
            return Err(InvoiceValidationError::NoAmountSpecified);
        }
    };

    info!(
        "🔍 Invoice amount: {} sat, required minimum: {} sat",
        invoice_amount_sat, min_required_amount_sat
    );

    if invoice_amount_sat < min_required_amount_sat {
        info!("❌ Invoice amount is less than required swap amount.");
        return Err(InvoiceValidationError::AmountTooLow {
            got: invoice_amount_sat,
            expected: min_required_amount_sat,
        });
    }

    info!("✅ Invoice is payable.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldk_node::lightning_invoice::Bolt11Invoice;
    use std::str::FromStr;

    #[test]
    fn test_is_invoice_payable_simple() {
        let invoice_str = "lntbs10u1p5g3f4cdq62qe9qmm0d3mrygzfdemx76trv5np4qtu70hpmszfyyhcw5xcpkgv90t5hkmrcvjmwwa63c4dzpx92mhw62pp5vxhp3yxe6fhaht22lka53al8gh6eshngq7vs4r28n7e8pthjflgqsp5sjtvyzzxxm0hc4w2ys3mw934d59hvnw0jma6g8yl9q0a8zv50z8q9qyysgqcqpcxqyz5vqrzjqwsce3827s585x5jd4zap4upqsgwtpada92wjpqpyxcx222pacaf5qehlcqq8eqqq5qqqqlgqqqqqqqqfqj04e0qw4k087z3l39z8l2g508lumkc4s8jyjzxxye4r6anze5clpkezfgsgltfwvracqwxf2qj7cwduyvdpkyfjehman5ssrfn295fcp889szc";
        let invoice = Bolt11Invoice::from_str(invoice_str).expect("Failed to parse invoice");

        let expected_payment_hash = "61ae1890d9d26fdbad4afdbb48f7e745f5985e6807990a8d479fb270aef24fd0";
        let min_required_amount_sat = 1000;
        let max_allowed_cltv_expiry = 24;

        // Test valid invoice
        let result = is_invoice_payable_simple(
            expected_payment_hash,
            min_required_amount_sat,
            &invoice,
            max_allowed_cltv_expiry,
        );  
        assert!(result.is_ok(), "Expected invoice to be payable, but got error: {:?}", result);

    }
    #[test]
    fn test_is_inovice_payable_less_amount(){
         let invoice_str = "lntbs10u1p5g3f4cdq62qe9qmm0d3mrygzfdemx76trv5np4qtu70hpmszfyyhcw5xcpkgv90t5hkmrcvjmwwa63c4dzpx92mhw62pp5vxhp3yxe6fhaht22lka53al8gh6eshngq7vs4r28n7e8pthjflgqsp5sjtvyzzxxm0hc4w2ys3mw934d59hvnw0jma6g8yl9q0a8zv50z8q9qyysgqcqpcxqyz5vqrzjqwsce3827s585x5jd4zap4upqsgwtpada92wjpqpyxcx222pacaf5qehlcqq8eqqq5qqqqlgqqqqqqqqfqj04e0qw4k087z3l39z8l2g508lumkc4s8jyjzxxye4r6anze5clpkezfgsgltfwvracqwxf2qj7cwduyvdpkyfjehman5ssrfn295fcp889szc";
        let invoice = Bolt11Invoice::from_str(invoice_str).expect("Failed to parse invoice");

        let expected_payment_hash = "61ae1890d9d26fdbad4afdbb48f7e745f5985e6807990a8d479fb270aef24fd0";
        let min_required_amount_sat = 2000;// Set to a value greater than the invoice amount
        let max_allowed_cltv_expiry = 24;

        // Test valid invoice
        let result = is_invoice_payable_simple(
            expected_payment_hash,
            min_required_amount_sat,
            &invoice,
            max_allowed_cltv_expiry,
        );  
        assert!(result.is_err(), "Expected invoice to be not payable, but got success: {:?}", result);
        
    }
    #[test]
    fn test_is_invoice_payable_higher_cltv_time(){
        let invoice_str = "lntbs10u1p5g3f4cdq62qe9qmm0d3mrygzfdemx76trv5np4qtu70hpmszfyyhcw5xcpkgv90t5hkmrcvjmwwa63c4dzpx92mhw62pp5vxhp3yxe6fhaht22lka53al8gh6eshngq7vs4r28n7e8pthjflgqsp5sjtvyzzxxm0hc4w2ys3mw934d59hvnw0jma6g8yl9q0a8zv50z8q9qyysgqcqpcxqyz5vqrzjqwsce3827s585x5jd4zap4upqsgwtpada92wjpqpyxcx222pacaf5qehlcqq8eqqq5qqqqlgqqqqqqqqfqj04e0qw4k087z3l39z8l2g508lumkc4s8jyjzxxye4r6anze5clpkezfgsgltfwvracqwxf2qj7cwduyvdpkyfjehman5ssrfn295fcp889szc";
        let invoice = Bolt11Invoice::from_str(invoice_str).expect("Failed to parse invoice");

        let expected_payment_hash = "61ae1890d9d26fdbad4afdbb48f7e745f5985e6807990a8d479fb270aef24fd0";
        let min_required_amount_sat = 1000;
        let max_allowed_cltv_expiry = 17; // Set to a value lower than the invoice's CLTV

        // Test valid invoice
        let result = is_invoice_payable_simple(
            expected_payment_hash,
            min_required_amount_sat,
            &invoice,
            max_allowed_cltv_expiry,
        );  
        assert!(result.is_err(), "Expected invoice to be not payable, but got success: {:?}", result);
    }

    #[test]
    fn test_is_invoice_payable_wrong_hash(){
        let invoice_str = "lntbs10u1p5g3f4cdq62qe9qmm0d3mrygzfdemx76trv5np4qtu70hpmszfyyhcw5xcpkgv90t5hkmrcvjmwwa63c4dzpx92mhw62pp5vxhp3yxe6fhaht22lka53al8gh6eshngq7vs4r28n7e8pthjflgqsp5sjtvyzzxxm0hc4w2ys3mw934d59hvnw0jma6g8yl9q0a8zv50z8q9qyysgqcqpcxqyz5vqrzjqwsce3827s585x5jd4zap4upqsgwtpada92wjpqpyxcx222pacaf5qehlcqq8eqqq5qqqqlgqqqqqqqqfqj04e0qw4k087z3l39z8l2g508lumkc4s8jyjzxxye4r6anze5clpkezfgsgltfwvracqwxf2qj7cwduyvdpkyfjehman5ssrfn295fcp889szc";
        let invoice = Bolt11Invoice::from_str(invoice_str).expect("Failed to parse invoice");

        let expected_payment_hash = "d7748c771dbaae23b575c83a1f22f4ed9b37675fee1fa6d4c9147af39aeffe20"; // Set to a wrong hash
        let min_required_amount_sat = 1000;
        
        let max_allowed_cltv_expiry = 24;

        // Test valid invoice
        let result = is_invoice_payable_simple(
            expected_payment_hash,
            min_required_amount_sat,
            &invoice,
            max_allowed_cltv_expiry,
        );  
        assert!(result.is_err(), "Expected invoice to be not payable, but got success: {:?}", result);
    }

}



