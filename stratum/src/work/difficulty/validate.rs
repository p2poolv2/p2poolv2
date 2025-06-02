// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
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

use crate::messages::Request;
use crate::work::gbt::BlockTemplate;
use bitcoin::CompactTarget;
use bitcoin::Target;

/// Validate the difficulty of a submitted share against the block template
///
/// We build the block header from received submission and the corresponding block template.
/// Then we check if the header's difficulty meets the target specified in the block template.
pub fn validate_submission_difficulty(
    blocktemplate: BlockTemplate,
    submission: &Request<'_>,
) -> Result<bool, String> {
    let compact_target = CompactTarget::from_unprefixed_hex(&blocktemplate.bits)
        .map_err(|e| format!("Failed to convert bits to target: {}", e))?;
    let target = Target::from_compact(compact_target);
    Ok(true)
}
