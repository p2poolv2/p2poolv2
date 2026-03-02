// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// This file is part of P2Poolv2
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

use crate::stratum::difficulty_adjuster::DifficultyAdjusterTrait;
use crate::stratum::error::Error;
use crate::stratum::messages::{Message, Request, SimpleRequest};
use crate::stratum::server::StratumContext;
use crate::stratum::session::Session;
use authorize_response::handle_authorize;
use configure::handle_configure;
use submit::handle_submit;
use subscribe::handle_subscribe;
use suggest_difficulty::handle_suggest_difficulty;
use tracing::debug;

pub mod authorize_response;
pub mod configure;
pub mod submit;
pub mod subscribe;
pub mod suggest_difficulty;

/// Handle incoming Stratum messages
/// This function processes the incoming Stratum messages and returns a response
/// The function accepts a mutable reference to a `Session` object, which informs the responses.
/// The session is also updated in response to received messages, if required.
///
/// Return a vector of responses to be sent back to the client.
#[allow(dead_code)]
#[allow(clippy::needless_lifetimes)]
pub(crate) async fn handle_message<'a, D: DifficultyAdjusterTrait>(
    message: Request<'a>,
    session: &mut Session<D>,
    addr: SocketAddr,
    ctx: StratumContext,
) -> Result<Vec<Message<'a>>, Error> {
    match message {
        Request::MiningConfigureRequest(_) => handle_configure(message, session).await,
        Request::SuggestDifficultyRequest(suggest_difficulty_request) => {
            handle_suggest_difficulty(suggest_difficulty_request, session).await
        }
        Request::SimpleRequest(simple_request) => {
            handle_simple_request(simple_request, session, addr, ctx).await
        }
    }
}

async fn handle_simple_request<'a, D: DifficultyAdjusterTrait>(
    message: SimpleRequest<'a>,
    session: &mut Session<D>,
    addr: SocketAddr,
    ctx: StratumContext,
) -> Result<Vec<Message<'a>>, Error> {
    debug!("Handling simple request: {}", message.method);
    match message.method.as_ref() {
        "mining.subscribe" => handle_subscribe(message, session, ctx.start_difficulty).await,
        "mining.authorize" => handle_authorize(message, session, addr, ctx).await,
        "mining.submit" => handle_submit(message, session, ctx).await,
        method => Err(Error::InvalidMethod(method.to_string())),
    }
}
