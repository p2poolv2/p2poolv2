use ldk_node::{Node, Event};

/// Handles Lightning node events in a loop, logging each event and acknowledging it.
pub async fn handle_events(node: &Node) {
    println!("Event handler loop started");
    loop {
        // println!("Waiting for events in the background...");
        let event = node.wait_next_event();
        match event {
            Event::ChannelPending {
                channel_id: _,
                user_channel_id: _,
                former_temporary_channel_id: _,
                counterparty_node_id: _,
                funding_txo: _,
            } => {
                println!("Channel pending event received");
                let _ = node.event_handled();
            }

            Event::ChannelReady {
                channel_id: _,
                user_channel_id: _,
                counterparty_node_id: _,
            } => {
                println!("Channel ready event received");
                let _ = node.event_handled();
            }

            Event::ChannelClosed {
                channel_id: _,
                user_channel_id: _,
                counterparty_node_id: _,
                reason: _,
            } => {
                println!("Channel closed event received");
                let _ = node.event_handled();
            }

            Event::PaymentSuccessful {
                payment_id: _,
                payment_hash: _,
                payment_preimage: _,
                fee_paid_msat: _,
            } => {
                println!("Payment successful event received");
                let _ = node.event_handled();
            }

            Event::PaymentFailed {
                payment_id: _,
                payment_hash: _,
                reason: _,
            } => {
                println!("Payment failed event received");
                let _ = node.event_handled();
            }

            Event::PaymentReceived {
                payment_id: _,
                payment_hash: _,
                amount_msat: _,
                custom_records: _,
            } => {
                println!("Payment received event received");
                let _ = node.event_handled();
            }

            Event::PaymentClaimable {
                payment_id: _,
                payment_hash: _,
                claimable_amount_msat: _,
                claim_deadline: _,
                custom_records: _,
            } => {
                println!("Payment claimable event received");
                let _ = node.event_handled();
            }

            Event::PaymentForwarded {
                prev_channel_id: _,
                next_channel_id: _,
                prev_user_channel_id: _,
                next_user_channel_id: _,
                prev_node_id: _,
                next_node_id: _,
                total_fee_earned_msat: _,
                skimmed_fee_msat: _,
                claim_from_onchain_tx: _,
                outbound_amount_forwarded_msat: _,
            } => {
                println!("Payment forwarded event received");
                let _ = node.event_handled();
            }
        }
    }
}