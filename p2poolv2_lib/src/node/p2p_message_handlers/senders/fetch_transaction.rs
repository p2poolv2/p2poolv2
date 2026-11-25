// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::node::messages::{GetData, Message};
use crate::node::request_sender::RequestSender;
use bitcoin::Txid;
use libp2p::PeerId;
use tracing::debug;

/// Request `txid` from `peer` with `GetData::Txid`.
///
/// Kept for downstream use: upcoming changes will send transaction requests
/// through the `RequestSender` path (e.g. from handlers that own the swarm
/// directly). Not yet called in production wiring.
///
/// Sends directly via the swarm so the caller does not await on the bounded
/// `swarm_tx` channel that the actor also drains.
pub fn send_getdata_tx(peer: PeerId, txid: Txid, request_sender: &mut impl RequestSender) {
    debug!("Requesting transaction {txid} from peer {peer}");
    request_sender.send_request(&peer, Message::GetData(GetData::Txid(txid)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::request_sender::MockRequestSender;
    use crate::test_utils::test_coinbase_transaction;

    fn make_txid(value: usize) -> Txid {
        test_coinbase_transaction(value).compute_txid()
    }

    #[test]
    fn test_send_getdata_tx_requests_from_peer() {
        let peer = PeerId::random();
        let txid = make_txid(1);

        let mut mock_sender = MockRequestSender::new();
        mock_sender
            .expect_send_request()
            .withf(move |sent_peer_id, message| {
                *sent_peer_id == peer && *message == Message::GetData(GetData::Txid(txid))
            })
            .return_const(());

        send_getdata_tx(peer, txid, &mut mock_sender);
    }

    #[test]
    fn test_send_getdata_tx_with_different_txid() {
        let peer = PeerId::random();
        let txid = make_txid(2);

        let mut mock_sender = MockRequestSender::new();
        mock_sender
            .expect_send_request()
            .withf(move |_, message| *message == Message::GetData(GetData::Txid(txid)))
            .return_const(());

        send_getdata_tx(peer, txid, &mut mock_sender);
    }
}
