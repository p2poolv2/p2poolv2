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