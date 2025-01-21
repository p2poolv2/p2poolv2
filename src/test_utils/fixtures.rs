// Copyright (C) 2024 [Kulpreet Singh]
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

use crate::shares::miner_message::MinerShare;
#[cfg(test)]
use rust_decimal::Decimal;
use rust_decimal_macros::dec;

#[cfg(test)]
pub fn simple_miner_share(
    workinfoid: Option<u64>,
    clientid: Option<u64>,
    diff: Option<Decimal>,
    sdiff: Option<Decimal>,
) -> MinerShare {
    MinerShare {
        workinfoid: workinfoid.unwrap_or(7452731920372203525),
        clientid: clientid.unwrap_or(1),
        enonce1: "336c6d67".to_string(),
        nonce2: "0000000000000000".to_string(),
        nonce: "2eb7b82b".to_string(),
        ntime: "676d6caa".to_string(),
        diff: diff.unwrap_or(dec!(1.0)),
        sdiff: sdiff.unwrap_or(dec!(1.9041854952356509)),
        hash: "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5".to_string(),
        result: true,
        errn: 0,
        createdate: "1735224559,536904211".to_string(),
        createby: "code".to_string(),
        createcode: "parse_submit".to_string(),
        createinet: "0.0.0.0:3333".to_string(),
        workername: "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string(),
        username: "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string(),
        address: "172.19.0.4".to_string(),
        agent: "cpuminer/2.5.1".to_string(),
    }
}
