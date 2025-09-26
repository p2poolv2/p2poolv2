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

use super::chain_store::ChainStore;
use crate::shares::miner_message::{MinerWorkbase, UserWorkbase};
use crate::shares::{ShareBlock, ShareBlockHash, ShareHeader};
use crate::store::Store;
use p2poolv2_accounting::simple_pplns::{SimplePplnsShare, payout::PplnsShareProvider};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::time::SystemTime;
use tokio::sync::mpsc;
use tracing::error;

#[derive(Debug)]
#[allow(dead_code)]
pub enum ChainMessage {
    GetTips,
    Reorg(ShareBlock, Decimal),
    IsConfirmed(ShareBlock),
    AddShare(ShareBlock),
    AddPplnsShare(SimplePplnsShare),
    GetPplnsShares(
        usize,
        Option<u64>,
        Option<u64>,
        tokio::sync::oneshot::Sender<Result<Vec<SimplePplnsShare>, Box<dyn Error + Send + Sync>>>,
    ),
    StoreWorkbase(MinerWorkbase),
    StoreUserWorkbase(UserWorkbase),
    GetWorkbase(u64),
    GetWorkbases(Vec<u64>),
    GetUserWorkbase(u64),
    GetUserWorkbases(Vec<u64>),
    GetShare(ShareBlockHash),
    GetSharesAtHeight(u32),
    GetShareHeaders(Vec<ShareBlockHash>),
    GetTotalDifficulty,
    GetChainTip,
    GetChainTipAndUncles,
    GetDepth(ShareBlockHash),
    GetHeadersForLocator(Vec<ShareBlockHash>, ShareBlockHash, usize),
    GetBlockhashesForLocator(Vec<ShareBlockHash>, ShareBlockHash, usize),
    BuildLocator,
    GetMissingBlockhashes(Vec<ShareBlockHash>),
    GetTipHeight,
    SaveJob(
        String,
        tokio::sync::oneshot::Sender<Result<(), Box<dyn Error + Send + Sync>>>,
    ),
    GetJobs(
        u64,
        Option<u64>,
        usize,
        tokio::sync::oneshot::Sender<Result<Vec<(u64, String)>, Box<dyn Error + Send + Sync>>>,
    ),
}

#[derive(Debug)]
#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
pub enum ChainResponse {
    Tips(HashSet<ShareBlockHash>),
    TotalDifficulty(Decimal),
    ReorgResult(Result<(), Box<dyn Error + Send + Sync>>),
    IsConfirmedResult(bool),
    AddShareResult(Result<(), Box<dyn Error + Send + Sync>>),
    AddPplnsShareResult(Result<(), Box<dyn Error + Send + Sync>>),
    StoreWorkbaseResult(Result<(), Box<dyn Error + Send + Sync>>),
    StoreUserWorkbaseResult(Result<(), Box<dyn Error + Send + Sync>>),
    GetWorkbaseResult(Option<MinerWorkbase>),
    GetWorkbasesResult(Vec<MinerWorkbase>),
    GetUserWorkbaseResult(Option<UserWorkbase>),
    GetUserWorkbasesResult(Vec<UserWorkbase>),
    GetShareResult(Option<ShareBlock>),
    GetSharesAtHeightResult(HashMap<ShareBlockHash, ShareBlock>),
    GetShareHeadersResult(Vec<ShareHeader>),
    ChainTip(Option<ShareBlockHash>),
    ChainTipAndUncles(Option<ShareBlockHash>, HashSet<ShareBlockHash>),
    Depth(Option<usize>),
    GetHeadersForLocatorResult(Vec<ShareHeader>),
    BuildLocatorResult(Vec<ShareBlockHash>),
    GetBlockhashesForLocatorResult(Vec<ShareBlockHash>),
    GetMissingBlockhashesResult(Vec<ShareBlockHash>),
    TipHeight(Option<u32>),
}

pub struct ChainActor {
    chain_store: ChainStore,
    receiver: mpsc::Receiver<(ChainMessage, mpsc::Sender<ChainResponse>)>,
}

impl ChainActor {
    pub fn new(
        chain_store: ChainStore,
        receiver: mpsc::Receiver<(ChainMessage, mpsc::Sender<ChainResponse>)>,
    ) -> Self {
        Self {
            chain_store,
            receiver,
        }
    }

    pub async fn run(&mut self) {
        while let Some((msg, response_sender)) = self.receiver.recv().await {
            match msg {
                ChainMessage::GetTips => {
                    let tips = self.chain_store.tips.clone();
                    if let Err(e) = response_sender.send(ChainResponse::Tips(tips)).await {
                        error!("Failed to send chain response: {}", e);
                    }
                }
                ChainMessage::Reorg(share_block, total_difficulty_upto_prev_share_blockhash) => {
                    let result = self
                        .chain_store
                        .reorg(share_block, total_difficulty_upto_prev_share_blockhash);
                    if let Err(e) = response_sender
                        .send(ChainResponse::ReorgResult(result))
                        .await
                    {
                        error!("Failed to send reorg response: {}", e);
                    }
                }
                ChainMessage::IsConfirmed(share_block) => {
                    let result = self.chain_store.is_confirmed(share_block);
                    if let Err(e) = response_sender
                        .send(ChainResponse::IsConfirmedResult(result))
                        .await
                    {
                        error!("Failed to send is_confirmed response: {}", e);
                    }
                }
                ChainMessage::AddShare(share_block) => {
                    let result = self.chain_store.add_share(share_block);
                    if let Err(e) = response_sender
                        .send(ChainResponse::AddShareResult(result))
                        .await
                    {
                        error!("Failed to send add_share response: {}", e);
                    }
                }
                ChainMessage::AddPplnsShare(pplns_share) => {
                    let result = self.chain_store.add_pplns_share(pplns_share);
                    if let Err(e) = response_sender
                        .send(ChainResponse::AddPplnsShareResult(result))
                        .await
                    {
                        error!("Failed to send add_pplns_share response: {}", e);
                    }
                }
                ChainMessage::GetPplnsShares(limit, start_time, end_time, response_tx) => {
                    let result = self
                        .chain_store
                        .get_pplns_shares_filtered(limit, start_time, end_time);
                    if let Err(e) = response_tx.send(result) {
                        error!("Failed to send get_pplns_shares response: {:?}", e);
                    }
                }
                ChainMessage::StoreWorkbase(workbase) => {
                    let result = self.chain_store.add_workbase(workbase);
                    if let Err(e) = response_sender
                        .send(ChainResponse::StoreWorkbaseResult(result))
                        .await
                    {
                        error!("Failed to send store_workbase response: {}", e);
                    }
                }
                ChainMessage::GetWorkbase(workinfoid) => {
                    let result = self.chain_store.get_workbase(workinfoid);
                    if let Err(e) = response_sender
                        .send(ChainResponse::GetWorkbaseResult(result))
                        .await
                    {
                        error!("Failed to send get_workbase response: {}", e);
                    }
                }
                ChainMessage::GetWorkbases(workinfoids) => {
                    let result = self.chain_store.get_workbases(&workinfoids);
                    if let Err(e) = response_sender
                        .send(ChainResponse::GetWorkbasesResult(result))
                        .await
                    {
                        error!("Failed to send get_workbases response: {}", e);
                    }
                }
                ChainMessage::GetShare(share_hash) => {
                    let result: Option<ShareBlock> = self.chain_store.get_share(&share_hash);
                    if let Err(e) = response_sender
                        .send(ChainResponse::GetShareResult(result))
                        .await
                    {
                        error!("Failed to send get_share response: {}", e);
                    }
                }
                ChainMessage::GetSharesAtHeight(height) => {
                    let result = self.chain_store.get_shares_at_height(height);
                    if let Err(e) = response_sender
                        .send(ChainResponse::GetSharesAtHeightResult(result))
                        .await
                    {
                        error!("Failed to send get_share_at_height response: {}", e);
                    }
                }
                ChainMessage::GetShareHeaders(share_hashes) => {
                    let result = self.chain_store.get_share_headers(&share_hashes);
                    if let Err(e) = response_sender
                        .send(ChainResponse::GetShareHeadersResult(result))
                        .await
                    {
                        error!("Failed to send get_share_headers response: {}", e);
                    }
                }
                ChainMessage::GetTotalDifficulty => {
                    let result = self.chain_store.get_total_difficulty();
                    if let Err(e) = response_sender
                        .send(ChainResponse::TotalDifficulty(result))
                        .await
                    {
                        error!("Failed to send get_total_difficulty response: {}", e);
                    }
                }
                ChainMessage::GetChainTip => {
                    let result = self.chain_store.chain_tip;
                    if let Err(e) = response_sender.send(ChainResponse::ChainTip(result)).await {
                        error!("Failed to send get_chain_tip response: {}", e);
                    }
                }
                ChainMessage::GetChainTipAndUncles => {
                    let (chain_tip, uncles) = self.chain_store.get_chain_tip_and_uncles();
                    if let Err(e) = response_sender
                        .send(ChainResponse::ChainTipAndUncles(chain_tip, uncles))
                        .await
                    {
                        error!("Failed to send get_chain_tip_and_uncles response: {}", e);
                    }
                }
                ChainMessage::GetDepth(blockhash) => {
                    let result = self.chain_store.get_depth(&blockhash);
                    if let Err(e) = response_sender.send(ChainResponse::Depth(result)).await {
                        error!("Failed to send get_depth response: {}", e);
                    }
                }
                ChainMessage::StoreUserWorkbase(user_workbase) => {
                    let result = self.chain_store.add_user_workbase(user_workbase);
                    if let Err(e) = response_sender
                        .send(ChainResponse::StoreUserWorkbaseResult(result))
                        .await
                    {
                        error!("Failed to send add_user_workbase response: {}", e);
                    }
                }
                ChainMessage::GetUserWorkbase(workinfoid) => {
                    let result = self.chain_store.get_user_workbase(workinfoid);
                    if let Err(e) = response_sender
                        .send(ChainResponse::GetUserWorkbaseResult(result))
                        .await
                    {
                        error!("Failed to send get_user_workbase response: {}", e);
                    }
                }
                ChainMessage::GetUserWorkbases(workinfoids) => {
                    let result = self.chain_store.get_user_workbases(&workinfoids);
                    if let Err(e) = response_sender
                        .send(ChainResponse::GetUserWorkbasesResult(result))
                        .await
                    {
                        error!("Failed to send get_user_workbases response: {}", e);
                    }
                }
                ChainMessage::GetHeadersForLocator(block_hashes, stop_block_hash, limit) => {
                    let result = self.chain_store.get_headers_for_locator(
                        &block_hashes,
                        &stop_block_hash,
                        limit,
                    );
                    if let Err(e) = response_sender
                        .send(ChainResponse::GetHeadersForLocatorResult(result))
                        .await
                    {
                        error!("Failed to send get_blocks_for_locator response: {}", e);
                    }
                }
                ChainMessage::GetBlockhashesForLocator(
                    locator,
                    stop_block_hash,
                    max_blockhashes,
                ) => {
                    let result = self.chain_store.get_blockhashes_for_locator(
                        &locator,
                        &stop_block_hash,
                        max_blockhashes,
                    );
                    if let Err(e) = response_sender
                        .send(ChainResponse::GetBlockhashesForLocatorResult(result))
                        .await
                    {
                        error!("Failed to send get_blockhashes_for_locator response: {}", e);
                    }
                }
                ChainMessage::BuildLocator => {
                    let result = self.chain_store.build_locator();
                    let result = match result {
                        Ok(locator) => locator,
                        Err(e) => {
                            error!("Failed to build locator: {}", e);
                            return;
                        }
                    };
                    if let Err(e) = response_sender
                        .send(ChainResponse::BuildLocatorResult(result))
                        .await
                    {
                        error!("Failed to send build_locator response: {}", e);
                    }
                }
                ChainMessage::GetMissingBlockhashes(blockhashes) => {
                    let result = self.chain_store.get_missing_blockhashes(&blockhashes);
                    if let Err(e) = response_sender
                        .send(ChainResponse::GetMissingBlockhashesResult(result))
                        .await
                    {
                        error!("Failed to send get_missing_blockhashes response: {}", e);
                    }
                }
                ChainMessage::GetTipHeight => {
                    let result = self.chain_store.get_tip_height();
                    if let Err(e) = response_sender.send(ChainResponse::TipHeight(result)).await {
                        error!("Failed to send get_tip_height response: {}", e);
                    }
                }
                ChainMessage::SaveJob(serialized_notify, response_tx) => {
                    let result = self.chain_store.save_job(serialized_notify);
                    if let Err(e) = response_tx.send(result) {
                        error!("Failed to send save_job response: {:?}", e);
                    }
                }
                ChainMessage::GetJobs(start_time, end_time, limit, response_tx) => {
                    let result = self.chain_store.get_jobs(start_time, end_time, limit);
                    if let Err(e) = response_tx.send(result) {
                        error!("Failed to send get_jobs response: {:?}", e);
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

#[allow(dead_code)]
impl ChainHandle {
    pub fn new(store_path: String, genesis_block: ShareBlock) -> Self {
        tracing::info!("Creating ChainHandle with store_path: {}", store_path);
        let (sender, receiver) = mpsc::channel(1);
        let store = Store::new(store_path, false).unwrap();
        let chain = ChainStore::new(store, genesis_block);
        let mut chain_actor = ChainActor::new(chain, receiver);
        tokio::spawn(async move { chain_actor.run().await });
        Self { sender }
    }

    pub async fn get_tips(&self) -> HashSet<ShareBlockHash> {
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

    pub async fn add_pplns_share(
        &self,
        pplns_share: SimplePplnsShare,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        if let Err(e) = self
            .sender
            .send((ChainMessage::AddPplnsShare(pplns_share), response_sender))
            .await
        {
            error!("Failed to send AddPplnsShare message: {}", e);
            return Err(e.into());
        }

        match response_receiver.recv().await {
            Some(ChainResponse::AddPplnsShareResult(result)) => result,
            _ => Err("Failed to receive add_pplns_share result".into()),
        }
    }

    pub async fn get_share(&self, share_hash: ShareBlockHash) -> Option<ShareBlock> {
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

    pub async fn get_pplns_shares_filtered(
        &self,
        limit: usize,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> Result<Vec<SimplePplnsShare>, Box<dyn Error + Send + Sync>> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        if let Err(e) = self
            .sender
            .send((
                ChainMessage::GetPplnsShares(limit, start_time, end_time, response_tx),
                mpsc::channel(1).0,
            ))
            .await
        {
            error!("Failed to send GetPplnsShares message: {}", e);
            return Err(e.into());
        }
        match response_rx.await {
            Ok(result) => result,
            Err(e) => Err(e.into()),
        }
    }

    pub async fn get_shares_at_height(&self, height: u32) -> HashMap<ShareBlockHash, ShareBlock> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        if let Err(e) = self
            .sender
            .send((ChainMessage::GetSharesAtHeight(height), response_sender))
            .await
        {
            error!("Failed to send GetSharesAtHeight message: {}", e);
            return HashMap::new();
        }

        match response_receiver.recv().await {
            Some(ChainResponse::GetSharesAtHeightResult(result)) => result,
            _ => HashMap::new(),
        }
    }

    pub async fn get_share_headers(&self, share_hashes: Vec<ShareBlockHash>) -> Vec<ShareHeader> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        if let Err(e) = self
            .sender
            .send((ChainMessage::GetShareHeaders(share_hashes), response_sender))
            .await
        {
            error!("Failed to send GetShareHeaders message: {}", e);
            return vec![];
        }

        match response_receiver.recv().await {
            Some(ChainResponse::GetShareHeadersResult(result)) => result,
            _ => vec![],
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

    pub async fn add_user_workbase(
        &self,
        user_workbase: UserWorkbase,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        if let Err(e) = self
            .sender
            .send((
                ChainMessage::StoreUserWorkbase(user_workbase),
                response_sender,
            ))
            .await
        {
            error!("Failed to send StoreUserWorkbase message: {}", e);
            return Err(e.into());
        }

        match response_receiver.recv().await {
            Some(ChainResponse::StoreUserWorkbaseResult(result)) => result,
            _ => Err("Failed to receive store user workbase result".into()),
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

    pub async fn get_workbases(&self, workinfoids: &[u64]) -> Vec<MinerWorkbase> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        self.sender
            .send((
                ChainMessage::GetWorkbases(workinfoids.to_vec()),
                response_sender,
            ))
            .await
            .unwrap();
        match response_receiver.recv().await {
            Some(ChainResponse::GetWorkbasesResult(result)) => result,
            _ => vec![],
        }
    }

    pub async fn get_user_workbase(&self, workinfoid: u64) -> Option<UserWorkbase> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        self.sender
            .send((ChainMessage::GetUserWorkbase(workinfoid), response_sender))
            .await
            .unwrap();
        match response_receiver.recv().await {
            Some(ChainResponse::GetUserWorkbaseResult(result)) => result,
            _ => None,
        }
    }

    pub async fn get_user_workbases(&self, workinfoids: &[u64]) -> Vec<UserWorkbase> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        self.sender
            .send((
                ChainMessage::GetUserWorkbases(workinfoids.to_vec()),
                response_sender,
            ))
            .await
            .unwrap();
        match response_receiver.recv().await {
            Some(ChainResponse::GetUserWorkbasesResult(result)) => result,
            _ => vec![],
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

    pub async fn get_chain_tip(&self) -> Option<ShareBlockHash> {
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

    pub async fn get_chain_tip_and_uncles(
        &self,
    ) -> (Option<ShareBlockHash>, HashSet<ShareBlockHash>) {
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

    pub async fn get_depth(&self, blockhash: ShareBlockHash) -> Option<usize> {
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
        tracing::debug!(
            "Setting up share for share blockhash: {:?} with chain_tip: {:?} and tips: {:?}",
            share_block.cached_blockhash,
            chain_tip,
            tips
        );
        share_block.header.prev_share_blockhash = chain_tip;
        share_block.header.uncles = tips.into_iter().collect();
        share_block.compute_blockhash();
        share_block
    }

    pub async fn get_headers_for_locator(
        &self,
        block_hashes: Vec<ShareBlockHash>,
        stop_block_hash: ShareBlockHash,
        limit: usize,
    ) -> Vec<ShareHeader> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        self.sender
            .send((
                ChainMessage::GetHeadersForLocator(block_hashes, stop_block_hash, limit),
                response_sender,
            ))
            .await
            .unwrap();
        match response_receiver.recv().await {
            Some(ChainResponse::GetHeadersForLocatorResult(result)) => result,
            _ => vec![],
        }
    }

    pub async fn get_blockhashes_for_locator(
        &self,
        locator: Vec<ShareBlockHash>,
        stop_block_hash: ShareBlockHash,
        max_blockhashes: usize,
    ) -> Vec<ShareBlockHash> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        self.sender
            .send((
                ChainMessage::GetBlockhashesForLocator(locator, stop_block_hash, max_blockhashes),
                response_sender,
            ))
            .await
            .unwrap();
        match response_receiver.recv().await {
            Some(ChainResponse::GetBlockhashesForLocatorResult(result)) => result,
            _ => vec![],
        }
    }

    pub async fn build_locator(&self) -> Vec<ShareBlockHash> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        self.sender
            .send((ChainMessage::BuildLocator, response_sender))
            .await
            .unwrap();
        match response_receiver.recv().await {
            Some(ChainResponse::BuildLocatorResult(result)) => result,
            _ => vec![],
        }
    }

    pub async fn get_missing_blockhashes(
        &self,
        blockhashes: &[ShareBlockHash],
    ) -> Vec<ShareBlockHash> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        self.sender
            .send((
                ChainMessage::GetMissingBlockhashes(blockhashes.to_vec()),
                response_sender,
            ))
            .await
            .unwrap();
        match response_receiver.recv().await {
            Some(ChainResponse::GetMissingBlockhashesResult(result)) => result,
            _ => vec![],
        }
    }

    pub async fn get_tip_height(&self) -> Option<u32> {
        let (response_sender, mut response_receiver) = mpsc::channel(1);
        if let Err(e) = self
            .sender
            .send((ChainMessage::GetTipHeight, response_sender))
            .await
        {
            error!("Failed to send GetTipHeight message: {}", e);
            return None;
        }

        match response_receiver.recv().await {
            Some(ChainResponse::TipHeight(height)) => height,
            _ => None,
        }
    }

    /// Save a job with timestamp-prefixed key
    async fn save_job(
        &self,
        serialized_notify: String,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        if let Err(e) = self
            .sender
            .send((
                ChainMessage::SaveJob(serialized_notify, response_tx),
                mpsc::channel(1).0,
            ))
            .await
        {
            error!("Failed to send SaveJob message: {}", e);
            return Err(e.into());
        }
        match response_rx.await {
            Ok(result) => result,
            Err(e) => Err(e.into()),
        }
    }

    /// Get jobs within a time range
    /// End time < job time <= Start time
    /// If start_time is None, it defaults to current time
    pub async fn get_jobs(
        &self,
        start_time: Option<u64>,
        end_time: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, String)>, Box<dyn Error + Send + Sync>> {
        let start_time = start_time.unwrap_or(
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64,
        );
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        if let Err(e) = self
            .sender
            .send((
                ChainMessage::GetJobs(start_time, end_time, limit, response_tx),
                mpsc::channel(1).0,
            ))
            .await
        {
            error!("Failed to send GetJobs message: {}", e);
            return Err(e.into());
        }
        match response_rx.await {
            Ok(result) => result,
            Err(e) => Err(e.into()),
        }
    }
}

impl PplnsShareProvider for ChainHandle {
    async fn get_pplns_shares_filtered(
        &self,
        limit: usize,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> Result<Vec<SimplePplnsShare>, Box<dyn std::error::Error + Send + Sync>> {
        self.get_pplns_shares_filtered(limit, start_time, end_time)
            .await
    }
}

impl p2poolv2_accounting::simple_pplns::payout::JobSaver for ChainHandle {
    async fn save_job(
        &self,
        serialized_notify: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.save_job(serialized_notify).await
    }

    async fn get_jobs(
        &self,
        start_time: Option<u64>,
        end_time: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, String)>, Box<dyn std::error::Error + Send + Sync>> {
        self.get_jobs(start_time, end_time, limit).await
    }
}

#[cfg(test)]
use mockall::mock;

#[cfg(test)]
mock! {
    pub ChainHandle {
        pub fn new(store_path: String, genesis_block: ShareBlock) -> Self;
        pub async fn get_tips(&self) -> HashSet<ShareBlockHash>;
        pub async fn reorg(&self, share_block: ShareBlock, total_difficulty_upto_prev_share_blockhash: Decimal) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub async fn is_confirmed(&self, share_block: ShareBlock) -> Result<bool, Box<dyn Error + Send + Sync>>;
        pub async fn add_share(&self, share_block: ShareBlock) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub async fn add_pplns_share(&self, pplns_share: SimplePplnsShare) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub async fn add_workbase(&self, workbase: MinerWorkbase) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub async fn get_workbase(&self, workinfoid: u64) -> Option<MinerWorkbase>;
        pub async fn get_chain_tip(&self) -> Option<ShareBlockHash>;
        pub async fn get_chain_tip_and_uncles(&self) -> (Option<ShareBlockHash>, HashSet<ShareBlockHash>);
        pub async fn get_depth(&self, blockhash: ShareBlockHash) -> Option<usize>;
        pub async fn setup_share_for_chain(&self, share_block: ShareBlock) -> ShareBlock;
        pub async fn add_user_workbase(&self, user_workbase: UserWorkbase) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub async fn get_user_workbase(&self, workinfoid: u64) -> Option<UserWorkbase>;
        pub async fn get_share(&self, share_hash: ShareBlockHash) -> Option<ShareBlock>;
        pub async fn get_pplns_shares_filtered(&self, limit: usize, start_time: Option<u64>, end_time: Option<u64>) -> Result<Vec<SimplePplnsShare>, Box<dyn Error + Send + Sync>>;
        pub async fn get_shares_at_height(&self, height: u32) -> HashMap<ShareBlockHash, ShareBlock>;
        pub async fn get_share_headers(&self, share_hashes: Vec<ShareBlockHash>) -> Vec<ShareHeader>;
        pub async fn get_headers_for_locator(&self, block_hashes: Vec<ShareBlockHash>, stop_block_hash: ShareBlockHash, max_headers: usize) -> Vec<ShareHeader>;
        pub async fn get_blockhashes_for_locator(&self, locator: Vec<ShareBlockHash>, stop_block_hash: ShareBlockHash, max_blockhashes: usize) -> Vec<ShareBlockHash>;
        pub async fn build_locator(&self) -> Vec<ShareBlockHash>;
        pub async fn get_missing_blockhashes(&self, blockhashes: &[ShareBlockHash]) -> Vec<ShareBlockHash>;
        pub async fn get_tip_height(&self) -> Option<u32>;
        pub async fn save_job(&self, serialized_notify: String) -> Result<(), Box<dyn Error + Send + Sync>>;
        pub async fn get_jobs(&self, start_time: u64, end_time: Option<u64>, limit: usize) -> Result<Vec<(u64, String)>, Box<dyn Error + Send + Sync>>;
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
    use crate::test_utils::TestBlockBuilder;
    use crate::test_utils::TestMinerWorkbaseBuilder;
    use crate::test_utils::genesis_for_testnet;
    use crate::test_utils::load_valid_workbases_userworkbases_and_shares;
    use crate::test_utils::random_hex_string;
    use rust_decimal_macros::dec;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_get_tips() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        let tips = chain_handle.get_tips().await;
        assert_eq!(tips.len(), 1); // New chain should genesis block as the only tip

        // Add a share block
        let share_block = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .prev_share_blockhash(genesis_for_testnet().cached_blockhash.unwrap())
            .diff(dec!(1.0))
            .build();

        let result = chain_handle.add_share(share_block.clone()).await;
        assert!(result.is_ok());

        // Get tips should now return the blockhash
        let tips = chain_handle.get_tips().await;
        assert_eq!(tips.len(), 1);
        assert!(tips.contains(&share_block.cached_blockhash.unwrap()));

        let total_difficulty = chain_handle.get_total_difficulty().await;
        assert_eq!(total_difficulty, dec!(2.0));
    }

    #[tokio::test]
    async fn test_reorg() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        let share_block = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .prev_share_blockhash(genesis_for_testnet().cached_blockhash.unwrap())
            .build();

        // Add initial share block
        let result = chain_handle.add_share(share_block.clone()).await;
        assert!(result.is_ok());

        // Create another share block with higher difficulty
        let higher_diff_share = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
            .prev_share_blockhash(share_block.cached_blockhash.unwrap())
            .diff(dec!(2.0))
            .sdiff(dec!(2.0))
            .build();

        let result = chain_handle.add_share(higher_diff_share.clone()).await;
        assert!(result.is_ok());

        // Check if the chain tips are updated
        let tips = chain_handle.get_tips().await;
        let mut expected_tips = HashSet::new();
        expected_tips.insert(higher_diff_share.cached_blockhash.unwrap());
        assert_eq!(tips, expected_tips);

        let total_difficulty = chain_handle.get_total_difficulty().await;
        assert_eq!(total_difficulty, dec!(4.0));
    }

    #[tokio::test]
    async fn test_is_confirmed() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        let share_block = TestBlockBuilder::new()
            .blockhash(random_hex_string(64, 8).as_str())
            .prev_share_blockhash(random_hex_string(64, 8).as_str().into())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        let result = chain_handle.is_confirmed(share_block).await;
        assert!(result.is_ok());
        assert!(!result.unwrap()); // New block should not be confirmed
    }

    #[tokio::test]
    async fn test_add_workbase() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );
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
                signet_challenge: Some("51".to_string()),
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
        };

        let result = chain_handle.add_workbase(workbase).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_depth() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        // Create initial share
        let share1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .prev_share_blockhash(genesis_for_testnet().cached_blockhash.unwrap())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        // Add first share and verify depth is 0
        chain_handle.add_share(share1.clone()).await.unwrap();
        let depth = chain_handle
            .get_depth(share1.cached_blockhash.unwrap())
            .await;
        assert_eq!(depth, Some(0));

        // Create and add second share
        let share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
            .prev_share_blockhash(share1.cached_blockhash.unwrap())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        // Add second share and verify depths
        chain_handle.add_share(share2.clone()).await.unwrap();
        assert_eq!(
            chain_handle
                .get_depth(share2.cached_blockhash.unwrap())
                .await,
            Some(0)
        );
        assert_eq!(
            chain_handle
                .get_depth(share1.cached_blockhash.unwrap())
                .await,
            Some(1)
        );

        // Test non-existent hash returns None
        let non_existent =
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7".into();
        assert_eq!(chain_handle.get_depth(non_existent).await, None);
    }

    #[tokio::test]
    async fn test_get_share_headers() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        // Create initial share
        let share1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5")
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        // Create second share
        let share2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb6")
            .prev_share_blockhash(share1.cached_blockhash.unwrap())
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .build();

        // Add both shares
        chain_handle.add_share(share1.clone()).await.unwrap();
        chain_handle.add_share(share2.clone()).await.unwrap();

        // Get headers for both shares
        let share_hashes = vec![
            share1.cached_blockhash.unwrap(),
            share2.cached_blockhash.unwrap(),
        ];
        let headers = chain_handle.get_share_headers(share_hashes).await;

        // Verify we got both headers back correctly
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0], share1.header);
        assert_eq!(headers[1], share2.header);

        // Test getting headers with non-existent hash
        let non_existent =
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb7".into();
        let share_hashes = vec![non_existent];
        let headers = chain_handle.get_share_headers(share_hashes).await;
        assert!(headers.is_empty());
    }

    #[tokio::test]
    async fn test_get_headers_for_locator() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        // Create test blocks
        let block1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb1")
            .build();

        let block2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb2")
            .prev_share_blockhash(block1.cached_blockhash.unwrap())
            .build();

        let block3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb3")
            .prev_share_blockhash(block2.cached_blockhash.unwrap())
            .build();

        let locator = vec![block1.cached_blockhash.unwrap()];
        let stop_hash = block3.cached_blockhash.unwrap();

        chain_handle.add_share(block1.clone()).await.unwrap();
        chain_handle.add_share(block2.clone()).await.unwrap();
        chain_handle.add_share(block3.clone()).await.unwrap();

        // Call the function and verify results
        let headers = chain_handle
            .get_headers_for_locator(locator, stop_hash, 2000)
            .await;
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0], block2.header);
        assert_eq!(headers[1], block3.header);
    }

    #[tokio::test]
    async fn test_build_locator() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        // Create test blocks in a chain
        let block1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb1")
            .prev_share_blockhash(genesis_for_testnet().cached_blockhash.unwrap())
            .build();

        let block2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb2")
            .prev_share_blockhash(block1.cached_blockhash.unwrap())
            .build();

        let block3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb3")
            .prev_share_blockhash(block2.cached_blockhash.unwrap())
            .build();

        // Add blocks to chain
        chain_handle.add_share(block1.clone()).await.unwrap();
        chain_handle.add_share(block2.clone()).await.unwrap();
        chain_handle.add_share(block3.clone()).await.unwrap();

        // Get locator and verify results
        let locator = chain_handle.build_locator().await;

        // Should return blocks in reverse order since locator starts from tip
        assert_eq!(locator.len(), 4);
        assert_eq!(locator[0], block3.cached_blockhash.unwrap());
        assert_eq!(locator[1], block2.cached_blockhash.unwrap());
        assert_eq!(locator[2], block1.cached_blockhash.unwrap());
        assert_eq!(locator[3], genesis_for_testnet().cached_blockhash.unwrap());
    }

    // add test for get_blockhashes_for_locator
    #[tokio::test]
    async fn test_get_blockhashes_for_locator() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        // Create test blocks
        let block1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb1")
            .build();

        let block2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb2")
            .prev_share_blockhash(block1.cached_blockhash.unwrap())
            .build();

        let block3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb3")
            .prev_share_blockhash(block2.cached_blockhash.unwrap())
            .build();

        let locator = vec![block1.cached_blockhash.unwrap()];
        let stop_hash = block3.cached_blockhash.unwrap();

        chain_handle.add_share(block1.clone()).await.unwrap();
        chain_handle.add_share(block2.clone()).await.unwrap();
        chain_handle.add_share(block3.clone()).await.unwrap();

        // Call the function and verify results
        let blockhashes = chain_handle
            .get_blockhashes_for_locator(locator, stop_hash, 2000)
            .await;
        assert_eq!(blockhashes.len(), 2);
        assert_eq!(blockhashes[0], block2.cached_blockhash.unwrap());
        assert_eq!(blockhashes[1], block3.cached_blockhash.unwrap());
    }

    #[tokio::test]
    async fn test_get_workbases() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        let workbase1 = TestMinerWorkbaseBuilder::new().workinfoid(1000).build();
        let workbase2 = TestMinerWorkbaseBuilder::new().workinfoid(2000).build();

        chain_handle.add_workbase(workbase1.clone()).await.unwrap();
        chain_handle.add_workbase(workbase2.clone()).await.unwrap();

        // Test getting all workbases
        let retrieved_workbases = chain_handle.get_workbases(&[1000, 2000]).await;
        assert_eq!(retrieved_workbases.len(), 2);

        // Verify workbases are retrieved correctly
        let retrieved_workinfoid_set: HashSet<u64> =
            retrieved_workbases.iter().map(|wb| wb.workinfoid).collect();

        assert!(retrieved_workinfoid_set.contains(&1000));
        assert!(retrieved_workinfoid_set.contains(&2000));

        // Test getting a subset of workbases
        let subset_ids = vec![1000];
        let subset_workbases = chain_handle.get_workbases(&subset_ids).await;

        assert_eq!(subset_workbases.len(), 1);
        assert_eq!(subset_workbases[0].workinfoid, subset_ids[0]);

        // Test getting non-existent workbases
        let nonexistent_ids = vec![u64::MAX, u64::MAX - 1];
        let nonexistent_workbases = chain_handle.get_workbases(&nonexistent_ids).await;
        assert_eq!(nonexistent_workbases.len(), 0);

        // Test getting a mix of existent and non-existent workbases
        let mixed_ids = vec![1000, u64::MAX];
        let mixed_workbases = chain_handle.get_workbases(&mixed_ids).await;

        assert_eq!(mixed_workbases.len(), 1);
        assert_eq!(mixed_workbases[0].workinfoid, 1000);
    }

    #[tokio::test]
    async fn test_get_missing_blockhashes() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        // Create and add some blocks to the chain
        let block1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb1")
            .build();
        let block2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb2")
            .prev_share_blockhash(block1.cached_blockhash.unwrap())
            .build();

        // Add only block1 to the chain
        chain_handle.add_share(block1.clone()).await.unwrap();

        // Create some blockhashes that don't exist in the chain
        let missing_hash1 =
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb3".into();
        let missing_hash2 =
            "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4".into();

        // Test with all missing blockhashes
        let all_missing = vec![missing_hash1, missing_hash2];
        let result = chain_handle.get_missing_blockhashes(&all_missing).await;
        assert_eq!(result.len(), 2);
        assert!(result.contains(&missing_hash1));
        assert!(result.contains(&missing_hash2));

        // Test with a mix of existing and missing blockhashes
        let mixed_hashes = vec![
            block1.cached_blockhash.unwrap(),
            block2.cached_blockhash.unwrap(), // Not added to chain
            missing_hash1,
        ];

        let result = chain_handle.get_missing_blockhashes(&mixed_hashes).await;
        assert_eq!(result.len(), 2);
        assert!(result.contains(&block2.cached_blockhash.unwrap()));
        assert!(result.contains(&missing_hash1));
        assert!(!result.contains(&block1.cached_blockhash.unwrap()));

        // Test with only existing blockhashes
        let existing_hashes = vec![block1.cached_blockhash.unwrap()];
        let result = chain_handle.get_missing_blockhashes(&existing_hashes).await;
        assert_eq!(result.len(), 0);

        // Test with empty input
        let empty_hashes: Vec<ShareBlockHash> = vec![];
        let result = chain_handle.get_missing_blockhashes(&empty_hashes).await;
        assert_eq!(result.len(), 0);
    }

    #[tokio::test]
    async fn test_get_user_workbases() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        // Create test user workbases
        let (_, user_workbases, _) = load_valid_workbases_userworkbases_and_shares();
        let user_workbase1 = user_workbases[0].clone();
        let mut user_workbase2 = user_workbase1.clone();
        user_workbase2.workinfoid = 7473434392883363844;

        // Store the user workbases
        chain_handle
            .add_user_workbase(user_workbase1.clone())
            .await
            .unwrap();
        chain_handle
            .add_user_workbase(user_workbase2.clone())
            .await
            .unwrap();

        // Test getting all user workbases
        let workinfoid1 = user_workbase1.workinfoid;
        let workinfoid2 = user_workbase2.workinfoid;
        let retrieved_workbases = chain_handle
            .get_user_workbases(&[workinfoid1, workinfoid2])
            .await;
        assert_eq!(retrieved_workbases.len(), 2);

        // Verify user workbases are retrieved correctly
        let retrieved_workinfoid_set: HashSet<u64> =
            retrieved_workbases.iter().map(|wb| wb.workinfoid).collect();

        assert!(retrieved_workinfoid_set.contains(&workinfoid1));
        assert!(retrieved_workinfoid_set.contains(&workinfoid2));

        // Test getting a subset of user workbases
        let subset_ids = vec![workinfoid1];
        let subset_workbases = chain_handle.get_user_workbases(&subset_ids).await;

        assert_eq!(subset_workbases.len(), 1);
        assert_eq!(subset_workbases[0].workinfoid, subset_ids[0]);

        // Test getting non-existent user workbases
        let nonexistent_ids = vec![u64::MAX, u64::MAX - 1];
        let nonexistent_workbases = chain_handle.get_user_workbases(&nonexistent_ids).await;
        assert_eq!(nonexistent_workbases.len(), 0);

        // Test getting a mix of existent and non-existent user workbases
        let mixed_ids = vec![workinfoid1, u64::MAX];
        let mixed_workbases = chain_handle.get_user_workbases(&mixed_ids).await;

        assert_eq!(mixed_workbases.len(), 1);
        assert_eq!(mixed_workbases[0].workinfoid, workinfoid1);
    }

    #[tokio::test]
    async fn test_get_tip_height() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        // Initially the chain should have no tip height
        let tip_height = chain_handle.get_tip_height().await;
        assert_eq!(tip_height, Some(0));

        // Create and add several blocks with increasing heights
        let block1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb1")
            .prev_share_blockhash(genesis_for_testnet().cached_blockhash.unwrap())
            .build();

        let block2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb2")
            .prev_share_blockhash(block1.cached_blockhash.unwrap())
            .build();

        let block3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb3")
            .prev_share_blockhash(block2.cached_blockhash.unwrap())
            .build();

        // Add all blocks to the chain
        chain_handle.add_share(block1).await.unwrap();
        chain_handle.add_share(block2).await.unwrap();
        chain_handle.add_share(block3.clone()).await.unwrap();

        // Check if tip height returns the correct height
        let tip_height = chain_handle.get_tip_height().await;
        assert_eq!(tip_height, Some(3));

        // Create a higher-difficulty block with a different height
        let higher_diff_block = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4")
            .prev_share_blockhash(block3.cached_blockhash.unwrap())
            .diff(dec!(10.0))
            .build();

        // Add the higher difficulty block which should cause a reorg
        chain_handle.add_share(higher_diff_block).await.unwrap();

        let tip_height = chain_handle.get_tip_height().await;
        assert_eq!(tip_height, Some(4));
    }

    #[tokio::test]
    async fn test_loading_chain_from_store() {
        let temp_dir = tempdir().unwrap();
        let store_path = temp_dir.path().to_str().unwrap().to_string();
        let chain_handle = ChainHandle::new(store_path.clone(), genesis_for_testnet());

        // Initially the chain should have no tip height
        let tip_height = chain_handle.get_tip_height().await;
        assert_eq!(tip_height, Some(0));

        // Create and add several blocks with increasing heights
        let block1 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb1")
            .prev_share_blockhash(genesis_for_testnet().cached_blockhash.unwrap())
            .build();

        let block2 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb2")
            .prev_share_blockhash(block1.cached_blockhash.unwrap())
            .build();

        let block3 = TestBlockBuilder::new()
            .blockhash("0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb3")
            .prev_share_blockhash(block2.cached_blockhash.unwrap())
            .build();

        // Add all blocks to the chain
        chain_handle.add_share(block1).await.unwrap();
        chain_handle.add_share(block2).await.unwrap();
        chain_handle.add_share(block3.clone()).await.unwrap();

        assert_eq!(chain_handle.get_tip_height().await, Some(3));

        let read_only_store = Store::new(store_path, true).unwrap();
        let read_only_chain = ChainStore::new(read_only_store, genesis_for_testnet());

        // Check if tip height returns the correct height
        let tip_height = read_only_chain.get_tip_height();
        assert_eq!(tip_height, Some(3));

        let (tip, _uncles) = read_only_chain.get_chain_tip_and_uncles();
        assert_eq!(tip.unwrap(), block3.cached_blockhash.unwrap());

        let total_difficulty = read_only_chain.get_total_difficulty();
        assert_eq!(total_difficulty, dec!(4.0));
    }

    #[tokio::test]
    async fn test_get_pplns_shares_filtered_empty() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        // Test with empty store
        let result = chain_handle.get_pplns_shares_filtered(10, None, None).await;
        assert!(result.is_ok());
        let shares = result.unwrap();
        assert_eq!(shares.len(), 0);
    }

    #[tokio::test]
    async fn test_get_pplns_shares_filtered_with_shares() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        // Add some PPLNS shares
        let share1 = SimplePplnsShare::new(100, "addr1".to_string(), "worker1".to_string(), 1000);
        let share2 = SimplePplnsShare::new(200, "addr2".to_string(), "worker2".to_string(), 2000);
        let share3 = SimplePplnsShare::new(300, "addr3".to_string(), "worker3".to_string(), 3000);

        chain_handle.add_pplns_share(share1.clone()).await.unwrap();
        chain_handle.add_pplns_share(share2.clone()).await.unwrap();
        chain_handle.add_pplns_share(share3.clone()).await.unwrap();

        // Test getting all shares
        let result = chain_handle.get_pplns_shares_filtered(10, None, None).await;
        assert!(result.is_ok());
        let shares = result.unwrap();
        assert_eq!(shares.len(), 3);

        // Verify shares are returned in correct order (most recent first)
        assert_eq!(shares[0].timestamp, 3000);
        assert_eq!(shares[1].timestamp, 2000);
        assert_eq!(shares[2].timestamp, 1000);
    }

    #[tokio::test]
    async fn test_get_pplns_shares_filtered_with_limit() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        // Add some PPLNS shares
        let share1 = SimplePplnsShare::new(100, "addr1".to_string(), "worker1".to_string(), 1000);
        let share2 = SimplePplnsShare::new(200, "addr2".to_string(), "worker2".to_string(), 2000);
        let share3 = SimplePplnsShare::new(300, "addr3".to_string(), "worker3".to_string(), 3000);

        chain_handle.add_pplns_share(share1).await.unwrap();
        chain_handle.add_pplns_share(share2).await.unwrap();
        chain_handle.add_pplns_share(share3).await.unwrap();

        // Test with limit
        let result = chain_handle.get_pplns_shares_filtered(2, None, None).await;
        assert!(result.is_ok());
        let shares = result.unwrap();
        assert_eq!(shares.len(), 2);

        // Should return the 2 most recent shares
        assert_eq!(shares[0].timestamp, 3000);
        assert_eq!(shares[1].timestamp, 2000);
    }

    #[tokio::test]
    async fn test_get_pplns_shares_filtered_with_time_range() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        // Add some PPLNS shares with different timestamps
        let share1 = SimplePplnsShare::new(100, "addr1".to_string(), "worker1".to_string(), 1000);
        let share2 = SimplePplnsShare::new(200, "addr2".to_string(), "worker2".to_string(), 2000);
        let share3 = SimplePplnsShare::new(300, "addr3".to_string(), "worker3".to_string(), 3000);
        let share4 = SimplePplnsShare::new(400, "addr4".to_string(), "worker4".to_string(), 4000);

        chain_handle.add_pplns_share(share1).await.unwrap();
        chain_handle.add_pplns_share(share2).await.unwrap();
        chain_handle.add_pplns_share(share3).await.unwrap();
        chain_handle.add_pplns_share(share4).await.unwrap();

        // Test with start_time filter
        let result = chain_handle
            .get_pplns_shares_filtered(10, Some(2500), None)
            .await;
        assert!(result.is_ok());
        let shares = result.unwrap();
        assert_eq!(shares.len(), 2); // Should include shares with timestamp >= 2500
        assert_eq!(shares[0].timestamp, 4000);
        assert_eq!(shares[1].timestamp, 3000);

        // Test with end_time filter
        let result = chain_handle
            .get_pplns_shares_filtered(10, None, Some(2500))
            .await;
        assert!(result.is_ok());
        let shares = result.unwrap();
        assert_eq!(shares.len(), 2); // Should include shares with timestamp <= 2500
        assert_eq!(shares[0].timestamp, 2000);
        assert_eq!(shares[1].timestamp, 1000);

        // Test with both start_time and end_time
        let result = chain_handle
            .get_pplns_shares_filtered(10, Some(1500), Some(3500))
            .await;
        assert!(result.is_ok());
        let shares = result.unwrap();
        assert_eq!(shares.len(), 2); // Should include shares between 1500 and 3500
        assert_eq!(shares[0].timestamp, 3000);
        assert_eq!(shares[1].timestamp, 2000);
    }

    #[tokio::test]
    async fn test_save_job_and_get_jobs() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        // Test saving jobs
        let job1_notify = r#"{"id":"job1","notify":"data1"}"#.to_string();
        let job1_id = "job_123".to_string();

        let job2_notify = r#"{"id":"job2","notify":"data2"}"#.to_string();
        let job2_id = "job_456".to_string();

        let job3_notify = r#"{"id":"job3","notify":"data3"}"#.to_string();
        let job3_id = "job_789".to_string();

        // Save all jobs
        let result1 = chain_handle.save_job(job1_notify.clone()).await;
        assert!(result1.is_ok());

        // Add a small delay to ensure different timestamps
        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;

        let result2 = chain_handle.save_job(job2_notify.clone()).await;
        assert!(result2.is_ok());

        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;

        let result3 = chain_handle.save_job(job3_notify.clone()).await;
        assert!(result3.is_ok());

        // Test with current time as start_time (should return all jobs)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        let recent_jobs_result = chain_handle.get_jobs(Some(current_time), None, 10).await;
        assert!(recent_jobs_result.is_ok());
        let recent_jobs = recent_jobs_result.unwrap();
        assert_eq!(recent_jobs.len(), 0); // No jobs should be returned since start_time is current time

        // Test with future start_time (should return no jobs)
        let past_time = current_time + 1_000_000; // 1 second in the future
        let future_jobs_result = chain_handle.get_jobs(None, Some(past_time), 10).await;
        assert!(future_jobs_result.is_ok());
        let future_jobs = future_jobs_result.unwrap();
        assert_eq!(future_jobs.len(), 0);
    }

    #[tokio::test]
    async fn test_get_jobs_empty_store() {
        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        // Test getting jobs from empty store
        let jobs_result = chain_handle.get_jobs(None, None, 10).await;
        assert!(jobs_result.is_ok());
        let jobs = jobs_result.unwrap();
        assert_eq!(jobs.len(), 0);

        // Test with time filters on empty store
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        let filtered_jobs_result = chain_handle
            .get_jobs(Some(current_time - 1000), Some(current_time + 1000), 10)
            .await;
        assert!(filtered_jobs_result.is_ok());
        let filtered_jobs = filtered_jobs_result.unwrap();
        assert_eq!(filtered_jobs.len(), 0);
    }

    #[tokio::test]
    async fn test_job_saver_trait_implementation() {
        use p2poolv2_accounting::simple_pplns::payout::JobSaver;

        let temp_dir = tempdir().unwrap();
        let chain_handle = ChainHandle::new(
            temp_dir.path().to_str().unwrap().to_string(),
            genesis_for_testnet(),
        );

        // Test JobSaver trait methods
        let notify_data = r#"{"job":"test_trait"}"#.to_string();

        // Test save_job through trait
        let save_result = JobSaver::save_job(&chain_handle, notify_data.clone()).await;
        assert!(save_result.is_ok());

        let end_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64
            - 1_000_000; // 1 second in the past

        // Test get_jobs through trait
        let get_result = JobSaver::get_jobs(&chain_handle, None, Some(end_time), 10).await;
        assert!(get_result.is_ok());
        let jobs = get_result.unwrap();
        assert_eq!(jobs.len(), 1);

        let (_, retrieved_notify) = &jobs[0];
        assert_eq!(retrieved_notify, &notify_data);
    }
}
