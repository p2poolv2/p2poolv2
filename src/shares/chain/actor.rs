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

use super::chain::Chain;
use crate::shares::store::Store;
use crate::shares::ShareBlock;
use crate::shares::{miner_message::MinerWorkbase, BlockHash};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::collections::HashSet;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{debug, error};

#[derive(Debug)]
pub enum ChainMessage {
    GetTips,
    Reorg(ShareBlock, Decimal),
    IsConfirmed(ShareBlock),
    AddShare(ShareBlock),
    StoreWorkbase(MinerWorkbase),
    GetWorkbase(u64),
    GetShare(BlockHash),
    GetTotalDifficulty,
    GetChainTip,
    GetChainTipAndUncles,
    GetDepth(BlockHash),
}

#[derive(Debug)]
pub enum ChainResponse {
    Tips(HashSet<BlockHash>),
    TotalDifficulty(Decimal),
    ReorgResult(Result<(), Box<dyn Error + Send + Sync>>),
    IsConfirmedResult(bool),
    AddShareResult(Result<(), Box<dyn Error + Send + Sync>>),
    StoreWorkbaseResult(Result<(), Box<dyn Error + Send + Sync>>),
    GetWorkbaseResult(Option<MinerWorkbase>),
    GetShareResult(Option<ShareBlock>),
    ChainTip(Option<BlockHash>),
    ChainTipAndUncles(Option<BlockHash>, HashSet<BlockHash>),
    Depth(Option<usize>),
}

pub struct ChainActor {
    chain: Chain,
    receiver: mpsc::Receiver<(ChainMessage, mpsc::Sender<ChainResponse>)>,
}

impl ChainActor {
    pub fn new(
        chain: Chain,
        receiver: mpsc::Receiver<(ChainMessage, mpsc::Sender<ChainResponse>)>,
    ) -> Self {
        Self { chain, receiver }
    }

    pub async fn run(&mut self) {
        while let Some((msg, response_sender)) = self.receiver.recv().await {
            debug!("Chain actor received message: {:?}", msg);
            match msg {
                ChainMessage::GetTips => {
                    let tips = self.chain.tips.clone();
                    if let Err(e) = response_sender.send(ChainResponse::Tips(tips)).await {
                        error!("Failed to send chain response: {}", e);
                    }
                }
                ChainMessage::Reorg(share_block, total_difficulty_upto_prev_share_blockhash) => {
                    let result = self
                        .chain
                        .reorg(share_block, total_difficulty_upto_prev_share_blockhash);
                    if let Err(e) = response_sender
                        .send(ChainResponse::ReorgResult(result))
                        .await
                    {
                        error!("Failed to send reorg response: {}", e);
                    }
                }
                ChainMessage::IsConfirmed(share_block) => {
                    let result = self.chain.is_confirmed(share_block);
                    if let Err(e) = response_sender
                        .send(ChainResponse::IsConfirmedResult(result))
                        .await
                    {
                        error!("Failed to send is_confirmed response: {}", e);
                    }
                }
                ChainMessage::AddShare(share_block) => {
                    let result = self.chain.add_share(share_block);
                    if let Err(e) = response_sender
                        .send(ChainResponse::AddShareResult(result))
                        .await
                    {
                        error!("Failed to send add_share response: {}", e);
                    }
                }
                ChainMessage::StoreWorkbase(workbase) => {
                    let result = self.chain.add_workbase(workbase);
                    if let Err(e) = response_sender
                        .send(ChainResponse::StoreWorkbaseResult(result))
                        .await
                    {
                        error!("Failed to send store_workbase response: {}", e);
                    }
                }
                ChainMessage::GetWorkbase(workinfoid) => {
                    let result = self.chain.get_workbase(workinfoid);
                    if let Err(e) = response_sender
                        .send(ChainResponse::GetWorkbaseResult(result))
                        .await
                    {
                        error!("Failed to send get_workbase response: {}", e);
                    }
                }
                ChainMessage::GetShare(share_hash) => {
                    let result = self.chain.get_share(&share_hash);
                    if let Err(e) = response_sender
                        .send(ChainResponse::GetShareResult(result))
                        .await
                    {
                        error!("Failed to send get_share response: {}", e);
                    }
                }
                ChainMessage::GetTotalDifficulty => {
                    let result = self.chain.get_total_difficulty();
                    if let Err(e) = response_sender
                        .send(ChainResponse::TotalDifficulty(result))
                        .await
                    {
                        error!("Failed to send get_total_difficulty response: {}", e);
                    }
                }
                ChainMessage::GetChainTip => {
                    let result = self.chain.chain_tip.clone();
                    if let Err(e) = response_sender.send(ChainResponse::ChainTip(result)).await {
                        error!("Failed to send get_chain_tip response: {}", e);
                    }
                }
                ChainMessage::GetChainTipAndUncles => {
                    let (chain_tip, uncles) = self.chain.get_chain_tip_and_uncles();
                    if let Err(e) = response_sender
                        .send(ChainResponse::ChainTipAndUncles(chain_tip, uncles))
                        .await
                    {
                        error!("Failed to send get_chain_tip_and_uncles response: {}", e);
                    }
                }
                ChainMessage::GetDepth(blockhash) => {
                    let result = self.chain.get_depth(&blockhash);
                    if let Err(e) = response_sender.send(ChainResponse::Depth(result)).await {
                        error!("Failed to send get_depth response: {}", e);
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct ChainHandle {
    sender: mpsc::Sender<(ChainMessage, mpsc::Sender<ChainResponse>)>,
}

impl ChainHandle {
    pub fn new(store_path: String) -> Self {
        tracing::info!("Creating ChainHandle with store_path: {}", store_path);
        let (sender, receiver) = mpsc::channel(1);
        let store = Store::new(store_path);
        let mut chain_actor = ChainActor::new(Chain::new(store), receiver);
        tokio::spawn(async move { chain_actor.run().await });
        Self { sender }
    }

    pub async fn get_tips(&self) -> HashSet<BlockHash> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        if let Err(e) = self
            .sender
            .send((ChainMessage::GetTips, response_sender))
            .await
        {
            error!("Failed to send GetTips message: {}", e);
            return HashSet::new();
        }

        match response_receiver.recv().await {
            Some(ChainResponse::Tips(tips)) => tips,
            _ => HashSet::new(),
        }
    }

    pub async fn reorg(
        &self,
        share_block: ShareBlock,
        total_difficulty_upto_prev_share_blockhash: Decimal,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        if let Err(e) = self
            .sender
            .send((
                ChainMessage::Reorg(share_block, total_difficulty_upto_prev_share_blockhash),
                response_sender,
            ))
            .await
        {
            error!("Failed to send Reorg message: {}", e);
            return Err(e.into());
        }

        match response_receiver.recv().await {
            Some(ChainResponse::ReorgResult(result)) => result,
            _ => Err("Failed to receive reorg result".into()),
        }
    }

    pub async fn is_confirmed(
        &self,
        share_block: ShareBlock,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        if let Err(e) = self
            .sender
            .send((ChainMessage::IsConfirmed(share_block), response_sender))
            .await
        {
            error!("Failed to send IsConfirmed message: {}", e);
            return Err(e.into());
        }

        match response_receiver.recv().await {
            Some(ChainResponse::IsConfirmedResult(result)) => Ok(result),
            _ => Err("Failed to receive is_confirmed result".into()),
        }
    }

    pub async fn add_share(
        &self,
        share_block: ShareBlock,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        if let Err(e) = self
            .sender
            .send((ChainMessage::AddShare(share_block), response_sender))
            .await
        {
            error!("Failed to send AddShare message: {}", e);
            return Err(e.into());
        }

        match response_receiver.recv().await {
            Some(ChainResponse::AddShareResult(result)) => result,
            _ => Err("Failed to receive add_share result".into()),
        }
    }

    pub async fn get_share(&self, share_hash: BlockHash) -> Option<ShareBlock> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        if let Err(e) = self
            .sender
            .send((ChainMessage::GetShare(share_hash), response_sender))
            .await
        {
            error!("Failed to send GetShare message: {}", e);
            return None;
        }
        match response_receiver.recv().await {
            Some(ChainResponse::GetShareResult(result)) => result,
            _ => None,
        }
    }

    pub async fn add_workbase(
        &self,
        workbase: MinerWorkbase,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        tracing::debug!("Adding workbase to chain: {:?}", workbase.workinfoid);
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        if let Err(e) = self
            .sender
            .send((ChainMessage::StoreWorkbase(workbase), response_sender))
            .await
        {
            error!("Failed to send StoreWorkbase message: {}", e);
            return Err(e.into());
        }

        match response_receiver.recv().await {
            Some(ChainResponse::StoreWorkbaseResult(result)) => result,
            _ => Err("Failed to receive add workbase result".into()),
        }
    }

    pub async fn get_workbase(&self, workinfoid: u64) -> Option<MinerWorkbase> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        self.sender
            .send((ChainMessage::GetWorkbase(workinfoid), response_sender))
            .await
            .unwrap();
        match response_receiver.recv().await {
            Some(ChainResponse::GetWorkbaseResult(result)) => result,
            _ => None,
        }
    }

    pub async fn get_total_difficulty(&self) -> Decimal {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        self.sender
            .send((ChainMessage::GetTotalDifficulty, response_sender))
            .await
            .unwrap();
        match response_receiver.recv().await {
            Some(ChainResponse::TotalDifficulty(result)) => result,
            _ => dec!(0.0),
        }
    }

    pub async fn get_chain_tip(&self) -> Option<BlockHash> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        self.sender
            .send((ChainMessage::GetChainTip, response_sender))
            .await
            .unwrap();
        match response_receiver.recv().await {
            Some(ChainResponse::ChainTip(result)) => result,
            _ => None,
        }
    }

    pub async fn get_chain_tip_and_uncles(&self) -> (Option<BlockHash>, HashSet<BlockHash>) {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        self.sender
            .send((ChainMessage::GetChainTipAndUncles, response_sender))
            .await
            .unwrap();
        match response_receiver.recv().await {
            Some(ChainResponse::ChainTipAndUncles(chain_tip, uncles)) => (chain_tip, uncles),
            _ => (None, HashSet::new()),
        }
    }

    pub async fn get_depth(&self, blockhash: BlockHash) -> Option<usize> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        self.sender
            .send((ChainMessage::GetDepth(blockhash), response_sender))
            .await
            .unwrap();
        match response_receiver.recv().await {
            Some(ChainResponse::Depth(result)) => result,
            _ => None,
        }
    }

    /// Set up the share to use chain_tip as the previous blockhash and other tips as uncles
    /// This should be used only when the share is being for the local miner.
    /// Shares received from peers should not be modified``.
    pub async fn setup_share_for_chain(&self, mut share_block: ShareBlock) -> ShareBlock {
        let (chain_tip, tips) = self.get_chain_tip_and_uncles().await;
        share_block.header.prev_share_blockhash = chain_tip;
        share_block.header.uncles = tips.into_iter().collect();
        share_block
    }
}

#[cfg(test)]
use mockall::mock;

#[cfg(test)]
mock! {
    pub ChainHandle {
        pub fn new(store_path: String) -> Self;
        pub async fn get_tips(&self) -> HashSet<BlockHash>;
        pub async fn reorg(&self, share_block: ShareBlock, total_difficulty_upto_prev_share_blockhash: Decimal) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub async fn is_confirmed(&self, share_block: ShareBlock) -> Result<bool, Box<dyn Error + Send + Sync>>;
        pub async fn add_share(&self, share_block: ShareBlock) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub async fn add_workbase(&self, workbase: MinerWorkbase) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub async fn get_workbase(&self, workinfoid: u64) -> Option<MinerWorkbase>;
        pub async fn get_chain_tip(&self) -> Option<BlockHash>;
        pub async fn get_chain_tip_and_uncles(&self) -> (Option<BlockHash>, HashSet<BlockHash>);
        pub async fn get_depth(&self, blockhash: BlockHash) -> Option<usize>;
        pub async fn setup_share_for_chain(&self, share_block: ShareBlock) -> ShareBlock;
    }

    impl Clone for ChainHandle {
        fn clone(&self) -> Self {
            Self { sender: self.sender.clone() }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::miner_message::Gbt;
    use crate::shares::ShareHeader;
    use crate::test_utils::random_hex_string;
    use crate::test_utils::simple_miner_share;
    use crate::test_utils::test_coinbase_transaction;
    use crate::test_utils::test_share_block;
    use rust_decimal_macros::dec;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_get_tips() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(temp_dir.path().to_str().unwrap().to_string());

        let tips = chain_handle.get_tips().await;
        assert!(tips.is_empty()); // New chain should have no tips

        // Add a share block
        let share_block = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"),
            None,
            vec![],
            None,
            None,
            None,
            None,
            None,
            &mut vec![],
        );

        let result = chain_handle.add_share(share_block.clone()).await;
        assert!(result.is_ok());

        // Get tips should now return the blockhash
        let tips = chain_handle.get_tips().await;
        let mut expected_tips = HashSet::new();
        expected_tips.insert(share_block.header.blockhash);
        assert_eq!(tips, expected_tips);

        let total_difficulty = chain_handle.get_total_difficulty().await;
        assert_eq!(total_difficulty, dec!(1.0));
    }

    #[tokio::test]
    async fn test_reorg() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(temp_dir.path().to_str().unwrap().to_string());

        let share_block = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"),
            None,
            vec![],
            None,
            None,
            None,
            None,
            None,
            &mut vec![],
        );

        // Add initial share block
        let result = chain_handle.add_share(share_block.clone()).await;
        assert!(result.is_ok());

        // Create another share block with higher difficulty
        let higher_diff_share = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6"),
            Some(share_block.header.blockhash.to_string().as_str()),
            vec![],
            None,
            None,
            None,
            Some(dec!(2.0)),
            Some(dec!(2.0)),
            &mut vec![],
        );

        let result = chain_handle.add_share(higher_diff_share.clone()).await;
        assert!(result.is_ok());

        // Check if the chain tips are updated
        let tips = chain_handle.get_tips().await;
        let mut expected_tips = HashSet::new();
        expected_tips.insert(higher_diff_share.header.blockhash);
        assert_eq!(tips, expected_tips);

        let total_difficulty = chain_handle.get_total_difficulty().await;
        assert_eq!(total_difficulty, dec!(3.0));
    }

    #[tokio::test]
    async fn test_is_confirmed() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(temp_dir.path().to_str().unwrap().to_string());

        let share_block = test_share_block(
            Some(random_hex_string(64, 8).as_str()),
            Some(random_hex_string(64, 8).as_str()),
            vec![],
            Some("020202020202020202020202020202020202020202020202020202020202020202"),
            None,
            None,
            None,
            None,
            &mut vec![],
        );

        let result = chain_handle.is_confirmed(share_block).await;
        assert!(result.is_ok());
        assert!(!result.unwrap()); // New block should not be confirmed
    }

    #[tokio::test]
    async fn test_add_workbase() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(temp_dir.path().to_str().unwrap().to_string());
        let time = bitcoin::absolute::Time::from_hex("676d6caa").unwrap();

        let workbase = MinerWorkbase {
            workinfoid: 1,
            gbt: Gbt {
                capabilities: vec!["proposal".to_string()],
                version: 1,
                rules: vec![],
                vbavailable: serde_json::Value::Null,
                vbrequired: 0,
                previousblockhash: "prev_hash".to_string(),
                transactions: vec![],
                coinbaseaux: serde_json::Value::Null,
                coinbasevalue: 5000000000,
                longpollid: "longpoll".to_string(),
                target: "target".to_string(),
                mintime: 1,
                mutable: vec!["time".to_string()],
                noncerange: "00000000ffffffff".to_string(),
                sigoplimit: 80000,
                sizelimit: 4000000,
                weightlimit: 4000000,
                curtime: time,
                bits: "bits".to_string(),
                height: 1,
                signet_challenge: "51".to_string(),
                default_witness_commitment: "commitment".to_string(),
                diff: 1.0,
                ntime: time,
                bbversion: "20000000".to_string(),
                nbit: "1e0377ae".to_string(),
            },
            txns: vec![],
            merkles: vec![],
            coinb1: "01".to_string(),
            coinb2: "02".to_string(),
            coinb3: "03".to_string(),
            header: "01".to_string(),
            txnbinlen: "16".to_string(),
            txnbin: "001496142b6e2f10deaa471f460ad34aeb085f25698f".to_string(),
        };

        let result = chain_handle.add_workbase(workbase).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_depth() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(temp_dir.path().to_str().unwrap().to_string());

        // Create initial share
        let share1 = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5"),
            None,
            vec![],
            Some("020202020202020202020202020202020202020202020202020202020202020202"),
            None,
            None,
            None,
            None,
            &mut vec![],
        );

        // Add first share and verify depth is 0
        chain_handle.add_share(share1.clone()).await.unwrap();
        let depth = chain_handle.get_depth(share1.header.blockhash).await;
        assert_eq!(depth, Some(0));

        // Create and add second share
        let share2 = test_share_block(
            Some("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6"),
            Some(share1.header.blockhash.to_string().as_str()),
            vec![],
            Some("020202020202020202020202020202020202020202020202020202020202020202"),
            None,
            None,
            None,
            None,
            &mut vec![],
        );

        // Add second share and verify depths
        chain_handle.add_share(share2.clone()).await.unwrap();
        assert_eq!(
            chain_handle.get_depth(share2.header.blockhash).await,
            Some(0)
        );
        assert_eq!(
            chain_handle.get_depth(share1.header.blockhash).await,
            Some(1)
        );

        // Test non-existent hash returns None
        let non_existent = "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7"
            .parse()
            .unwrap();
        assert_eq!(chain_handle.get_depth(non_existent).await, None);
    }
}
