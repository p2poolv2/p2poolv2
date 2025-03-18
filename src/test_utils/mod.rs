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

#[cfg(test)]
use crate::shares::miner_message::Gbt;
#[cfg(test)]
use crate::shares::miner_message::{
    CkPoolMessage, MinerShare, MinerWorkbase, UserWorkbase, UserWorkbaseParams,
};
#[cfg(test)]
use crate::shares::{ShareBlock, ShareBlockHash, ShareHeader};
#[cfg(test)]
use bitcoin::absolute::Time;
#[cfg(test)]
use bitcoin::BlockHash;
#[cfg(test)]
use bitcoin::PublicKey;
#[cfg(test)]
use bitcoin::Transaction;
#[cfg(test)]
use bitcoin::TxMerkleNode;
#[cfg(test)]
use rand;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;

#[cfg(test)]
/// Build a simple miner share with consant values
pub fn simple_miner_share(
    blockhash: Option<&str>,
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
        ntime: bitcoin::absolute::Time::from_hex("676d6caa").unwrap(),
        diff: diff.unwrap_or(dec!(1.0)),
        sdiff: sdiff.unwrap_or(dec!(1.9041854952356509)),
        hash: blockhash
            .unwrap_or("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .parse::<BlockHash>()
            .unwrap(),
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

#[cfg(test)]
pub fn simple_miner_workbase() -> MinerWorkbase {
    let json_str = include_str!("../../tests/test_data/simple_miner_workbase.json");
    serde_json::from_str(&json_str).unwrap()
}

#[cfg(test)]
/// Generate a random hex string of specified length (defaults to 64 characters)
pub fn random_hex_string(length: usize, leading_zeroes: usize) -> String {
    use rand::{thread_rng, Rng};

    let mut rng = thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..length / 2]);
    // Set the specified number of leading bytes to zero
    for i in 0..leading_zeroes {
        bytes[i] = 0;
    }
    bytes[..length / 2]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

#[cfg(test)]
pub fn test_coinbase_transaction() -> bitcoin::Transaction {
    let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
        .parse::<bitcoin::PublicKey>()
        .unwrap();

    crate::shares::transactions::coinbase::create_coinbase_transaction(
        &pubkey,
        bitcoin::Network::Regtest,
    )
}

#[cfg(test)]
pub fn load_valid_workbases_userworkbases_and_shares(
) -> (Vec<MinerWorkbase>, Vec<UserWorkbase>, Vec<MinerShare>) {
    let workbases_str = include_str!("../../tests/test_data/validation/workbases.json");
    let shares_str = include_str!("../../tests/test_data/validation/shares.json");
    let userworkbases_str = include_str!("../../tests/test_data/validation/userworkbases.json");
    let workbases: Vec<CkPoolMessage> = serde_json::from_str(&workbases_str).unwrap();
    let shares: Vec<CkPoolMessage> = serde_json::from_str(&shares_str).unwrap();
    let userworkbases: Vec<CkPoolMessage> = serde_json::from_str(&userworkbases_str).unwrap();
    let workbases = workbases
        .into_iter()
        .filter_map(|msg| match msg {
            CkPoolMessage::Workbase(w) => Some(w),
            _ => None,
        })
        .collect::<Vec<MinerWorkbase>>();

    let userworkbases = userworkbases
        .into_iter()
        .filter_map(|msg| match msg {
            CkPoolMessage::UserWorkbase(w) => Some(w),
            _ => None,
        })
        .collect::<Vec<UserWorkbase>>();

    let shares = shares
        .into_iter()
        .filter_map(|msg| match msg {
            CkPoolMessage::Share(s) => Some(s),
            _ => None,
        })
        .collect::<Vec<MinerShare>>();

    (workbases, userworkbases, shares)
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub struct TestBlockBuilder {
    blockhash: Option<String>,
    prev_share_blockhash: Option<String>,
    uncles: Vec<ShareBlockHash>,
    miner_pubkey: Option<String>,
    workinfoid: Option<u64>,
    clientid: Option<u64>,
    diff: Option<Decimal>,
    sdiff: Option<Decimal>,
    transactions: Vec<Transaction>,
}

#[cfg(test)]
impl TestBlockBuilder {
    pub fn new() -> Self {
        Self {
            blockhash: None,
            prev_share_blockhash: None,
            uncles: Vec::new(),
            miner_pubkey: None,
            workinfoid: None,
            clientid: None,
            diff: None,
            sdiff: None,
            transactions: Vec::new(),
        }
    }

    pub fn blockhash(mut self, blockhash: &str) -> Self {
        self.blockhash = Some(blockhash.to_string());
        self
    }

    pub fn prev_share_blockhash(mut self, prev_share_blockhash: ShareBlockHash) -> Self {
        self.prev_share_blockhash = Some(prev_share_blockhash.to_string());
        self
    }

    pub fn uncles(mut self, uncles: Vec<ShareBlockHash>) -> Self {
        self.uncles = uncles;
        self
    }

    pub fn miner_pubkey(mut self, miner_pubkey: &str) -> Self {
        self.miner_pubkey = Some(miner_pubkey.to_string());
        self
    }

    pub fn workinfoid(mut self, workinfoid: u64) -> Self {
        self.workinfoid = Some(workinfoid);
        self
    }

    pub fn clientid(mut self, clientid: u64) -> Self {
        self.clientid = Some(clientid);
        self
    }

    pub fn diff(mut self, diff: Decimal) -> Self {
        self.diff = Some(diff);
        self
    }

    pub fn sdiff(mut self, sdiff: Decimal) -> Self {
        self.sdiff = Some(sdiff);
        self
    }

    pub fn add_transaction(mut self, transaction: Transaction) -> Self {
        self.transactions.push(transaction);
        self
    }

    pub fn build(mut self) -> ShareBlock {
        test_share_block(
            self.blockhash.as_deref(),
            self.prev_share_blockhash.as_deref(),
            self.uncles,
            self.miner_pubkey.as_deref(),
            self.workinfoid,
            self.clientid,
            self.diff,
            self.sdiff,
            &mut self.transactions,
        )
    }
}

#[cfg(test)]
fn test_share_block(
    blockhash: Option<&str>,
    prev_share_blockhash: Option<&str>,
    uncles: Vec<ShareBlockHash>,
    miner_pubkey: Option<&str>,
    workinfoid: Option<u64>,
    clientid: Option<u64>,
    diff: Option<Decimal>,
    sdiff: Option<Decimal>,
    include_transactions: &mut Vec<Transaction>,
) -> ShareBlock {
    use crate::shares::ShareBlockBuilder;

    let prev_share_blockhash = match prev_share_blockhash {
        Some(prev_share_blockhash) => Some(prev_share_blockhash.into()),
        None => None,
    };
    let miner_pubkey = match miner_pubkey {
        Some(miner_pubkey) => miner_pubkey.parse().unwrap(),
        None => "020202020202020202020202020202020202020202020202020202020202020202"
            .parse()
            .unwrap(),
    };
    let mut transactions = vec![test_coinbase_transaction()];
    transactions.append(include_transactions);
    let header = ShareHeader {
        miner_share: simple_miner_share(blockhash, workinfoid, clientid, diff, sdiff),
        prev_share_blockhash,
        uncles,
        miner_pubkey,
        merkle_root: bitcoin::merkle_tree::calculate_root(
            transactions.iter().map(Transaction::compute_txid),
        )
        .unwrap()
        .into(),
    };
    ShareBlockBuilder::new(header)
        .with_transactions(transactions)
        .build()
}

/// Builder for creating test MinerShare instances
#[cfg(test)]
pub struct TestMinerShareBuilder {
    workinfoid: Option<u64>,
    clientid: Option<u64>,
    enonce1: Option<String>,
    nonce2: Option<String>,
    nonce: Option<String>,
    ntime: Option<bitcoin::absolute::Time>,
    diff: Option<rust_decimal::Decimal>,
    sdiff: Option<rust_decimal::Decimal>,
    hash: Option<bitcoin::BlockHash>,
}

#[cfg(test)]
impl Default for TestMinerShareBuilder {
    fn default() -> Self {
        Self {
            workinfoid: None,
            clientid: None,
            enonce1: None,
            nonce2: None,
            nonce: None,
            ntime: None,
            diff: None,
            sdiff: None,
            hash: None,
        }
    }
}

#[cfg(test)]
impl TestMinerShareBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn workinfoid(mut self, workinfoid: u64) -> Self {
        self.workinfoid = Some(workinfoid);
        self
    }

    pub fn clientid(mut self, clientid: u64) -> Self {
        self.clientid = Some(clientid);
        self
    }

    pub fn enonce1(mut self, enonce1: &str) -> Self {
        self.enonce1 = Some(enonce1.to_string());
        self
    }

    pub fn nonce2(mut self, nonce2: &str) -> Self {
        self.nonce2 = Some(nonce2.to_string());
        self
    }

    pub fn nonce(mut self, nonce: &str) -> Self {
        self.nonce = Some(nonce.to_string());
        self
    }

    pub fn ntime(mut self, ntime: bitcoin::absolute::Time) -> Self {
        self.ntime = Some(ntime);
        self
    }

    pub fn diff(mut self, diff: rust_decimal::Decimal) -> Self {
        self.diff = Some(diff);
        self
    }

    pub fn sdiff(mut self, sdiff: rust_decimal::Decimal) -> Self {
        self.sdiff = Some(sdiff);
        self
    }

    pub fn blockhash(mut self, blockhash: &str) -> Self {
        self.hash = Some(blockhash.parse().unwrap());
        self
    }

    pub fn build(self) -> crate::shares::miner_message::MinerShare {
        use crate::shares::miner_message::MinerShare;
        use rust_decimal_macros::dec;

        MinerShare {
            workinfoid: self.workinfoid.unwrap_or(7452731920372203525),
            clientid: self.clientid.unwrap_or(1),
            enonce1: self.enonce1.unwrap_or_else(|| "fdf8b667".to_string()),
            nonce2: self
                .nonce2
                .unwrap_or_else(|| "0000000000000000".to_string()),
            nonce: self.nonce.unwrap_or_else(|| "f15f1590".to_string()),
            ntime: self
                .ntime
                .unwrap_or_else(|| bitcoin::absolute::Time::from_consensus(1740044600).unwrap()),
            diff: self.diff.unwrap_or(dec!(1.0)),
            sdiff: self.sdiff.unwrap_or(dec!(1.9041854952356509)),
            hash: self.hash.unwrap_or_else(|| {
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"
                    .parse()
                    .unwrap()
            }),
            result: true,
            errn: 0,
            createdate: "1735224559".to_string(),
            createby: "code".to_string(),
            createcode: "parse_submit".to_string(),
            createinet: "0.0.0.0:3333".to_string(),
            workername: "testworker".to_string(),
            username: "testuser".to_string(),
            address: "localhost".to_string(),
            agent: "cpuminer/2.5.1".to_string(),
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub struct TestMinerWorkbaseBuilder {
    workinfoid: Option<u64>,
    txns: Option<Vec<String>>,
    merkles: Option<Vec<String>>,
    coinb1: Option<String>,
    coinb2: Option<String>,
    coinb3: Option<String>,
    header: Option<ShareHeader>,
    gbt: Option<crate::shares::miner_message::Gbt>,
}

#[cfg(test)]
impl TestMinerWorkbaseBuilder {
    pub fn new() -> Self {
        Self {
            workinfoid: None,
            txns: None,
            merkles: None,
            coinb1: None,
            coinb2: None,
            coinb3: None,
            header: None,
            gbt: None,
        }
    }

    pub fn workinfoid(mut self, workinfoid: u64) -> Self {
        self.workinfoid = Some(workinfoid);
        self
    }

    pub fn txns(mut self, txns: Vec<String>) -> Self {
        self.txns = Some(txns);
        self
    }

    pub fn merkles(mut self, merkles: Vec<String>) -> Self {
        self.merkles = Some(merkles);
        self
    }

    pub fn coinb1(mut self, coinb1: &str) -> Self {
        self.coinb1 = Some(coinb1.to_string());
        self
    }

    pub fn coinb2(mut self, coinb2: &str) -> Self {
        self.coinb2 = Some(coinb2.to_string());
        self
    }

    pub fn coinb3(mut self, coinb3: &str) -> Self {
        self.coinb3 = Some(coinb3.to_string());
        self
    }

    pub fn header(mut self, header: ShareHeader) -> Self {
        self.header = Some(header);
        self
    }

    pub fn gbt(mut self, gbt: crate::shares::miner_message::Gbt) -> Self {
        self.gbt = Some(gbt);
        self
    }

    pub fn build(self) -> crate::shares::miner_message::MinerWorkbase {
        use crate::shares::miner_message::{Gbt, MinerWorkbase};

        MinerWorkbase {
            workinfoid: self.workinfoid.unwrap_or(7473434392883363843),
            txns: vec![],
            merkles: vec![],
            coinb1: self.coinb1.unwrap_or_else(|| "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2c017b000438f9b667049c0fc52d0c".to_string()),
            coinb2: self.coinb2.unwrap_or_else(|| "0a636b706f6f6c0a2f7032706f6f6c76322fffffffff030011102401000000".to_string()),
            coinb3: self.coinb3.unwrap_or_else(|| "00e1f50500000000160014a248cf2f99f449511b22bab1a3d001719f84cd090000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000000".to_string()),
            header: "000000000822bbfaf34d53fc43d0c1382054d3aafe31893020c315db8b0a19f9".to_string(),
            gbt: TestGbtBuilder::default().build(),
        }
    }
}

/// Builder for creating test UserWorkbase instances
#[cfg(test)]
pub struct TestUserWorkbaseBuilder {
    params: Option<UserWorkbaseParams>,
    id: Option<String>,
    method: Option<String>,
    workinfoid: Option<u64>,
}

#[cfg(test)]
impl Default for TestUserWorkbaseBuilder {
    fn default() -> Self {
        let (_, user_workbases, _) = load_valid_workbases_userworkbases_and_shares();
        let user_workbase = user_workbases.first().unwrap();
        Self {
            params: Some(user_workbase.params.clone()),
            id: Some(user_workbase.id.clone().unwrap_or_else(|| "".to_string())),
            method: Some("mining.notify".to_string()),
            workinfoid: Some(user_workbase.workinfoid),
        }
    }
}

#[cfg(test)]
impl TestUserWorkbaseBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn params(mut self, params: UserWorkbaseParams) -> Self {
        self.params = Some(params);
        self
    }

    pub fn id(mut self, id: String) -> Self {
        self.id = Some(id);
        self
    }

    pub fn method(mut self, method: &str) -> Self {
        self.method = Some(method.to_string());
        self
    }

    pub fn workinfoid(mut self, workinfoid: u64) -> Self {
        self.workinfoid = Some(workinfoid);
        self
    }

    pub fn build(self) -> crate::shares::miner_message::UserWorkbase {
        UserWorkbase {
            params: self.params.unwrap(),
            id: self.id,
            method: self.method.unwrap(),
            workinfoid: self.workinfoid.unwrap(),
        }
    }
}

/// Builder for creating test Gbt instances
#[cfg(test)]
pub struct TestGbtBuilder {
    version: Option<i32>,
    previousblockhash: Option<String>,
    transactions: Option<Vec<serde_json::Value>>,
    coinbaseaux: Option<serde_json::Value>,
    coinbasevalue: Option<u64>,
    coinbasetxn: Option<serde_json::Value>,
    target: Option<String>,
    mintime: Option<u64>,
    mutable: Option<Vec<String>>,
    noncerange: Option<String>,
    sigoplimit: Option<u32>,
    sizelimit: Option<u32>,
    weightlimit: Option<u32>,
    curtime: Option<Time>,
    bits: Option<String>,
    height: Option<u32>,
    default_witness_commitment: Option<String>,
    diff: Option<f64>,
    ntime: Option<bitcoin::absolute::Time>,
    bbversion: Option<String>,
    nbit: Option<String>,
}

#[cfg(test)]
impl Default for TestGbtBuilder {
    fn default() -> Self {
        let (workbases, _, _) = load_valid_workbases_userworkbases_and_shares();
        let workbase = workbases.first().unwrap();
        let gbt = workbase.gbt.clone();
        Self {
            version: Some(gbt.version),
            previousblockhash: Some(gbt.previousblockhash),
            transactions: Some(gbt.transactions),
            coinbaseaux: Some(gbt.coinbaseaux),
            coinbasevalue: Some(gbt.coinbasevalue),
            coinbasetxn: None,
            target: Some(gbt.target),
            mintime: Some(gbt.mintime),
            mutable: Some(gbt.mutable),
            noncerange: Some(gbt.noncerange),
            sigoplimit: Some(gbt.sigoplimit),
            sizelimit: Some(gbt.sizelimit),
            weightlimit: Some(gbt.weightlimit),
            curtime: Some(gbt.curtime),
            bits: Some(gbt.bits),
            height: Some(gbt.height),
            default_witness_commitment: Some(gbt.default_witness_commitment),
            diff: Some(gbt.diff),
            ntime: Some(gbt.ntime),
            bbversion: Some(gbt.bbversion),
            nbit: Some(gbt.nbit),
        }
    }
}

#[cfg(test)]
impl TestGbtBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn version(mut self, version: i32) -> Self {
        self.version = Some(version);
        self
    }

    pub fn previousblockhash(mut self, previousblockhash: &str) -> Self {
        self.previousblockhash = Some(previousblockhash.to_string());
        self
    }

    pub fn transactions(mut self, transactions: Vec<serde_json::Value>) -> Self {
        self.transactions = Some(transactions);
        self
    }

    pub fn coinbaseaux(mut self, coinbaseaux: serde_json::Value) -> Self {
        self.coinbaseaux = Some(coinbaseaux);
        self
    }

    pub fn coinbasevalue(mut self, coinbasevalue: u64) -> Self {
        self.coinbasevalue = Some(coinbasevalue);
        self
    }

    pub fn coinbasetxn(mut self, coinbasetxn: serde_json::Value) -> Self {
        self.coinbasetxn = Some(coinbasetxn);
        self
    }

    pub fn target(mut self, target: &str) -> Self {
        self.target = Some(target.to_string());
        self
    }

    pub fn mintime(mut self, mintime: u64) -> Self {
        self.mintime = Some(mintime);
        self
    }

    pub fn mutable(mut self, mutable: Vec<String>) -> Self {
        self.mutable = Some(mutable);
        self
    }

    pub fn noncerange(mut self, noncerange: &str) -> Self {
        self.noncerange = Some(noncerange.to_string());
        self
    }

    pub fn sigoplimit(mut self, sigoplimit: u32) -> Self {
        self.sigoplimit = Some(sigoplimit);
        self
    }

    pub fn sizelimit(mut self, sizelimit: u32) -> Self {
        self.sizelimit = Some(sizelimit);
        self
    }

    pub fn weightlimit(mut self, weightlimit: u32) -> Self {
        self.weightlimit = Some(weightlimit);
        self
    }

    pub fn curtime(mut self, curtime: Time) -> Self {
        self.curtime = Some(curtime);
        self
    }

    pub fn bits(mut self, bits: &str) -> Self {
        self.bits = Some(bits.to_string());
        self
    }

    pub fn height(mut self, height: u32) -> Self {
        self.height = Some(height);
        self
    }

    pub fn default_witness_commitment(mut self, default_witness_commitment: &str) -> Self {
        self.default_witness_commitment = Some(default_witness_commitment.to_string());
        self
    }

    pub fn diff(mut self, diff: f64) -> Self {
        self.diff = Some(diff);
        self
    }

    pub fn ntime(mut self, ntime: bitcoin::absolute::Time) -> Self {
        self.ntime = Some(ntime);
        self
    }

    pub fn bbversion(mut self, bbversion: &str) -> Self {
        self.bbversion = Some(bbversion.to_string());
        self
    }

    pub fn nbit(mut self, nbit: &str) -> Self {
        self.nbit = Some(nbit.to_string());
        self
    }

    pub fn build(self) -> crate::shares::miner_message::Gbt {
        Gbt {
            version: self.version.unwrap(),
            transactions: self.transactions.unwrap(),
            capabilities: vec![],
            rules: vec![],
            vbavailable: serde_json::Value::Array(vec![]),
            vbrequired: 0,
            longpollid: String::new(),
            signet_challenge: String::new(),
            diff: self.diff.unwrap(),
            ntime: self.ntime.unwrap(),
            bbversion: self.bbversion.unwrap(),
            nbit: self.nbit.unwrap(),
            previousblockhash: self.previousblockhash.unwrap(),
            coinbaseaux: self.coinbaseaux.unwrap(),
            coinbasevalue: self.coinbasevalue.unwrap(),
            target: self.target.unwrap(),
            mintime: self.mintime.unwrap(),
            mutable: self.mutable.unwrap(),
            noncerange: self.noncerange.unwrap(),
            sigoplimit: self.sigoplimit.unwrap(),
            sizelimit: self.sizelimit.unwrap(),
            weightlimit: self.weightlimit.unwrap(),
            curtime: self.curtime.unwrap(),
            bits: self.bits.unwrap(),
            height: self.height.unwrap(),
            default_witness_commitment: self.default_witness_commitment.unwrap(),
        }
    }
}

/// Builder for creating test ShareHeader instances
#[cfg(test)]
pub struct TestShareHeaderBuilder {
    miner_share: Option<MinerShare>,
    prev_share_blockhash: Option<ShareBlockHash>,
    uncles: Vec<ShareBlockHash>,
    miner_pubkey: Option<PublicKey>,
    merkle_root: Option<TxMerkleNode>,
}

#[cfg(test)]
impl Default for TestShareHeaderBuilder {
    fn default() -> Self {
        Self {
            miner_share: None,
            prev_share_blockhash: None,
            uncles: Vec::new(),
            miner_pubkey: None,
            merkle_root: None,
        }
    }
}

#[cfg(test)]
impl TestShareHeaderBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn miner_share(mut self, miner_share: MinerShare) -> Self {
        self.miner_share = Some(miner_share);
        self
    }

    pub fn prev_share_blockhash(mut self, prev_share_blockhash: ShareBlockHash) -> Self {
        self.prev_share_blockhash = Some(prev_share_blockhash);
        self
    }

    pub fn uncles(mut self, uncles: Vec<ShareBlockHash>) -> Self {
        self.uncles = uncles;
        self
    }

    pub fn add_uncle(mut self, uncle: ShareBlockHash) -> Self {
        self.uncles.push(uncle);
        self
    }

    pub fn miner_pubkey(mut self, miner_pubkey: PublicKey) -> Self {
        self.miner_pubkey = Some(miner_pubkey);
        self
    }

    pub fn merkle_root(mut self, merkle_root: TxMerkleNode) -> Self {
        self.merkle_root = Some(merkle_root);
        self
    }

    pub fn build(self) -> ShareHeader {
        let default_pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<PublicKey>()
            .unwrap();

        let default_merkle_root = {
            let tx = test_coinbase_transaction();
            bitcoin::merkle_tree::calculate_root(std::iter::once(tx.compute_txid()))
                .unwrap()
                .into()
        };

        ShareHeader {
            miner_share: self
                .miner_share
                .unwrap_or_else(|| simple_miner_share(None, None, None, None, None)),
            prev_share_blockhash: self.prev_share_blockhash,
            uncles: self.uncles,
            miner_pubkey: self.miner_pubkey.unwrap_or(default_pubkey),
            merkle_root: self.merkle_root.unwrap_or(default_merkle_root),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_random_hex_string() {
        // Generate two random strings
        let str1 = random_hex_string(64, 8);
        let str2 = random_hex_string(64, 8);

        // Verify length is 64 characters
        assert_eq!(str1.len(), 64);
        assert_eq!(str2.len(), 64);

        // Verify strings are different (extremely unlikely to be equal)
        assert_ne!(str1, str2);

        // Verify strings only contain valid hex characters
        let is_hex = |s: &str| s.chars().all(|c| c.is_ascii_hexdigit());
        assert!(is_hex(&str1));
        assert!(is_hex(&str2));
    }
}
