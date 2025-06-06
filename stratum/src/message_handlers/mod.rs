// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
//  This file is part of P2Poolv2
//
// P2Poolv2 is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// P2Poolv2 is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// P2Poolv2. If not, see <https://www.gnu.org/licenses/>.

use std::net::SocketAddr;

use crate::error::Error;
use crate::messages::{Request, Response};
use crate::session::Session;
use crate::work::tracker::TrackerHandle;
use bitcoindrpc::BitcoinRpcConfig;

pub mod authorize;
pub mod submit;
pub mod subscribe;

use crate::work::notify::NotifyCmd;
use authorize::handle_authorize;
use submit::handle_submit;
use subscribe::handle_subscribe;

/// Handle incoming Stratum messages
/// This function processes the incoming Stratum messages and returns a response
/// The function accepts a mutable reference to a `Session` object, which informs the responses.
/// The session is also updated in response to received messages, if required.
///
/// Return a vector of responses to be sent back to the client.
#[allow(dead_code)]
#[allow(clippy::needless_lifetimes)]
pub(crate) async fn handle_message<'a>(
    message: Request<'a>,
    session: &mut Session,
    addr: SocketAddr,
    notify_tx: tokio::sync::mpsc::Sender<NotifyCmd>,
    tracker_handle: TrackerHandle,
    bitcoinrpc_config: BitcoinRpcConfig,
) -> Result<Response<'a>, Error> {
    match message.method.as_ref() {
        "mining.subscribe" => handle_subscribe(message, session).await,
        "mining.authorize" => handle_authorize(message, session, addr, notify_tx).await,
        "mining.submit" => handle_submit(message, session, tracker_handle, bitcoinrpc_config).await,
        method => Err(Error::InvalidMethod(method.to_string())),
    }
}
