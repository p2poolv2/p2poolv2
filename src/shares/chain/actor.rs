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
use crate::shares::miner_message::MinerWorkbase;
use crate::shares::store::Store;
use crate::shares::ShareBlock;
use rust_decimal::Decimal;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{debug, error};

#[derive(Debug)]
pub enum ChainMessage {
    GetTip,
    Reorg(ShareBlock, Decimal),
    IsConfirmed(ShareBlock),
    AddShare(ShareBlock),
    StoreWorkbase(MinerWorkbase),
}

#[derive(Debug)]
pub enum ChainResponse {
    Tip(Option<Vec<u8>>),
    ReorgResult(Result<(), Box<dyn Error + Send + Sync>>),
    IsConfirmedResult(bool),
    AddShareResult(Result<(), Box<dyn Error + Send + Sync>>),
    StoreWorkbaseResult(Result<(), Box<dyn Error + Send + Sync>>),
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
                ChainMessage::GetTip => {
                    let tip = self.chain.tip.clone();
                    if let Err(e) = response_sender.send(ChainResponse::Tip(tip)).await {
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
        let (sender, receiver) = mpsc::channel(1);
        let store = Store::new(store_path);
        let mut chain_actor = ChainActor::new(Chain::new(store), receiver);
        tokio::spawn(async move { chain_actor.run().await });
        Self { sender }
    }

    pub async fn get_tip(&self) -> Option<Vec<u8>> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        if let Err(e) = self
            .sender
            .send((ChainMessage::GetTip, response_sender))
            .await
        {
            error!("Failed to send GetTip message: {}", e);
            return None;
        }

        match response_receiver.recv().await {
            Some(ChainResponse::Tip(tip)) => tip,
            _ => None,
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

    pub async fn add_workbase(
        &self,
        workbase: MinerWorkbase,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
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
}

#[cfg(test)]
use mockall::mock;

#[cfg(test)]
mock! {
    pub ChainHandle {
        pub fn new(store_path: String) -> Self;
        pub async fn get_tip(&self) -> Option<Vec<u8>>;
        pub async fn reorg(&self, share_block: ShareBlock, total_difficulty_upto_prev_share_blockhash: Decimal) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub async fn is_confirmed(&self, share_block: ShareBlock) -> Result<bool, Box<dyn Error + Send + Sync>>;
        pub async fn add_share(&self, share_block: ShareBlock) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub async fn add_workbase(&self, workbase: MinerWorkbase) -> Result<(), Box<dyn Error + Send + Sync>>;
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
    use crate::test_utils::fixtures::simple_miner_share;
    use rust_decimal_macros::dec;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_get_tip() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(temp_dir.path().to_str().unwrap().to_string());

        let tip = chain_handle.get_tip().await;
        assert_eq!(tip, None); // New chain should have no tip

        // Add a share block
        let share_block = ShareBlock {
            nonce: vec![1],
            blockhash: vec![1],
            prev_share_blockhash: vec![],
            uncles: vec![],
            miner_pubkey: vec![1],
            timestamp: 1,
            tx_hashes: vec![],
            miner_share: simple_miner_share(None, None, None, None),
        };

        // Add the share block
        let result = chain_handle.add_share(share_block).await;
        tracing::info!("result: {:?}", result);
        assert!(result.is_ok());

        // Get tip should now return the blockhash
        let tip = chain_handle.get_tip().await;
        assert_eq!(tip, Some(vec![1]));
    }

    #[tokio::test]
    async fn test_reorg() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(temp_dir.path().to_str().unwrap().to_string());

        let share_block = ShareBlock {
            nonce: vec![1],
            blockhash: vec![1],
            prev_share_blockhash: vec![],
            uncles: vec![],
            miner_pubkey: vec![1],
            timestamp: 1,
            tx_hashes: vec![],
            miner_share: simple_miner_share(None, None, Some(dec!(1.0)), Some(dec!(1.0))),
        };

        // Add initial share block
        let result = chain_handle.add_share(share_block.clone()).await;
        assert!(result.is_ok());

        // Create another share block with higher difficulty
        let higher_diff_share = ShareBlock {
            nonce: vec![2],
            blockhash: vec![2],
            prev_share_blockhash: vec![1], // Points to previous block
            uncles: vec![],
            miner_pubkey: vec![1],
            timestamp: 2,
            tx_hashes: vec![],
            miner_share: simple_miner_share(None, None, Some(dec!(2.0)), Some(dec!(2.0))), // Higher difficulty
        };

        let result = chain_handle.reorg(higher_diff_share, dec!(1.0)).await;
        assert!(result.is_ok());

        // Check if the chain tip is updated
        let tip = chain_handle.get_tip().await;
        assert_eq!(tip, Some(vec![2]));
    }

    #[tokio::test]
    async fn test_is_confirmed() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(temp_dir.path().to_str().unwrap().to_string());

        let share_block = ShareBlock {
            nonce: vec![1],
            blockhash: vec![1],
            prev_share_blockhash: vec![],
            uncles: vec![],
            miner_pubkey: vec![1],
            timestamp: 1,
            tx_hashes: vec![],
            miner_share: simple_miner_share(None, None, Some(dec!(1.0)), Some(dec!(1.0))),
        };

        let result = chain_handle.is_confirmed(share_block).await;
        assert!(result.is_ok());
        assert!(!result.unwrap()); // New block should not be confirmed
    }

    #[tokio::test]
    async fn test_add_workbase() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(temp_dir.path().to_str().unwrap().to_string());

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
                curtime: 1,
                bits: "bits".to_string(),
                height: 1,
                signet_challenge: "51".to_string(),
                default_witness_commitment: "commitment".to_string(),
                diff: 1.0,
                ntime: "ntime".to_string(),
                bbversion: "20000000".to_string(),
                nbit: "1e0377ae".to_string(),
            },
        };

        let result = chain_handle.add_workbase(workbase).await;
        assert!(result.is_ok());
    }
}
