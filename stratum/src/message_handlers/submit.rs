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

use crate::error::Error;
use crate::messages::{Request, Response};
use crate::session::Session;
use crate::work::difficulty::validate::validate_submission_difficulty;
use crate::work::tracker::{JobId, TrackerHandle};
use serde_json::json;
use tracing::debug;

/// Handle the "mining.submit" message
/// This function is called when a miner submits a share to the Stratum server.
/// It sends a response with the submission status.
/// The function accepts a mutable reference to a `Session` object, which informs the responses.
/// The session is also updated in response to received messages, if required.
pub async fn handle_submit<'a>(
    message: Request<'a>,
    _session: &mut Session,
    tracker_handle: TrackerHandle,
) -> Result<Response<'a>, Error> {
    debug!("Handling mining.submit message");
    if message.params.len() < 4 {
        return Err(Error::InvalidParams);
    }

    let job_id = u64::from_str_radix(&message.params[0], 16).map_err(|_| Error::InvalidParams)?;

    let job = match tracker_handle.get_job(JobId(job_id)).await {
        Ok(job) => match job {
            Some(job) => job,
            None => {
                return Err(Error::SubmitFailure(
                    "No job found for the given ID".to_string(),
                ))
            }
        },
        Err(_) => {
            return Err(Error::SubmitFailure(
                "No job found for the given ID".to_string(),
            ))
        }
    };

    // Validate the difficulty of the submitted share
    if let Ok(block) = validate_submission_difficulty(&job, &message) {
        bitcoind
            .submit_block(&block)
            .await
            .map_err(|e| Error::SubmitFailure(format!("Failed to submit block: {}", e)))?;
    }
    Ok(Response::new_ok(message.id, json!(true)))
}
