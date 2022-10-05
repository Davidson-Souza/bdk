//! A demo backend using utreexo, a novel accumulator for allowing lightweight fully
//! validating nodes. See https://github.com/ut&reexo/utreexo for more details.
//! Author: Davidson Souza
//! Year: 2022
//!
use self::{peer::Mempool, store::ChainStore};
use crate::{BlockTime, FeeRate, KeychainKind, LocalUtxo, TransactionDetails};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
    time::Duration,
};

use super::{Blockchain, Capability, GetBlockHash, GetHeight, GetTx, WalletSync};
use bitcoin::{
    network::{
        message::NetworkMessage,
        message_blockdata::{GetHeadersMessage, Inventory},
    },
    Block, OutPoint, Script, Transaction, TxOut, Txid,
};

use rand::random;
use rocksdb::DB;
use rustreexo::accumulator::{proof::Proof, stump::Stump};

mod peer;
mod store;

use peer::Peer;

/// A utreexo blockchain is a collection of UTXOs and proofs, along with the current
/// chain state' accumulator. It can't update itself, if you need something that
/// proactively connects to the network, use [UtreexoNode] instead.
/// You can use custom ways of getting roots and UTXOs, and update it using UtreexoBlockchain
/// public interface.
#[derive(Debug, Clone)]
#[allow(unused)]
pub struct UtreexoState {
    accumulator: Stump,
    utxos: HashMap<Txid, String>,
}
impl UtreexoState {
    /// Verify a proof given the current accumulator.
    /// # Example
    pub fn verify(
        &self,
        target_hashes: &Vec<bitcoin_hashes::sha256::Hash>,
        proof: &Proof,
    ) -> Result<bool, UtreexoError> {
        proof
            .verify(target_hashes, &self.accumulator)
            .map_err(|_| UtreexoError::InvalidResponse)
    }
    /// Creates a new utreexo state
    pub fn new() -> Self {
        let accumulator = Stump::new();
        UtreexoState {
            accumulator,
            utxos: HashMap::new(),
        }
    }
    /// Modify an accumulator. This function is a pure function, and returns a new owned state
    pub fn update(
        &self,
        utxos: &Vec<bitcoin_hashes::sha256::Hash>,
        del_hashes: &Vec<bitcoin_hashes::sha256::Hash>,
        proof: &Proof,
    ) -> Result<Self, String> {
        let accumulator = self.accumulator.modify(utxos, del_hashes, proof)?;
        Ok(UtreexoState {
            accumulator,
            utxos: self.utxos.clone(),
        })
    }
}
/// A utreexo node is a node that connects to the p2p network, and updates
/// our [UtreexoBlockchain]. This is useful if you need a utreexo backend working
/// out-of-the-box.
#[derive(Debug)]
#[allow(unused)]
pub struct UtreexoBlockchain {
    chain: RefCell<UtreexoState>,
    peers: Arc<RwLock<Vec<Peer>>>,
    mempool: Arc<Mempool>,
    blocks: Arc<ChainStore>,

    ext_spks: Vec<Script>,
    int_spks: Vec<Script>,
}
impl UtreexoBlockchain {
    /// Bumps the height for this storage
    pub fn bump_height(&self) -> Result<(), UtreexoError> {
        let next_height = self.blocks.get_height()? + 1;
        self.blocks.bump_height(next_height)
    }
    /// Scans a single block
    pub fn request_blocks(
        &self,
        start_height: usize,
        end_height: usize,
    ) -> Result<(), UtreexoError> {
        let mut hash = vec![];
        for block in start_height..=end_height {
            if let Some(block_hash) = self.blocks.get_block_hash(block)? {
                hash.push(Inventory::Block(block_hash));
            }
        }

        let request = NetworkMessage::GetData(hash);
        let unlocked_peers = self
            .peers
            .read()
            .expect("UtreexoBlockchain::request_blocks - Can't lock peers.");
        let idx: usize = random::<usize>() % unlocked_peers.len();

        let peer = unlocked_peers.get(idx).expect(
            "UtreexoBlockchain::request_blocks - Can't read peers. Perhaps we got no peers?",
        );
        peer.send(request)?;

        Ok(())
    }
    /// Verify a single tx
    fn _verify_tx(&self, tx: Transaction, prevouts: Vec<TxOut>) -> Result<bool, UtreexoError> {
        let mut prevouts = prevouts.into_iter();
        tx.verify(|_| prevouts.next())
            .map_err(|_| UtreexoError::TxValidationErr)?;
        let amount_in = prevouts.fold(0, |val, p_out| val + p_out.value);
        let amount_out = tx.output.iter().fold(0, |val, out| val + out.value);

        Ok(amount_in >= amount_out)
    }
    /// Filters a block
    pub fn filter_block(
        &self,
        block: Block,
        height: u32,
        spks: &HashSet<Script>,
    ) -> Option<Vec<(LocalUtxo, TransactionDetails)>> {
        let mut my_utxos = vec![];
        for transaction in block.txdata {
            for (outpoint, vout) in transaction.output.iter().enumerate() {
                if spks.contains(&vout.script_pubkey) {
                    let outpoint = OutPoint {
                        txid: transaction.txid(),
                        vout: outpoint as u32,
                    };

                    let utxo = LocalUtxo {
                        is_spent: false,
                        keychain: KeychainKind::External,
                        outpoint,
                        txout: vout.clone(),
                    };
                    let transaction = TransactionDetails {
                        confirmation_time: Some(BlockTime {
                            height,
                            timestamp: block.header.time as u64,
                        }),
                        transaction: Some(transaction.clone()),
                        txid: transaction.txid(),
                        received: utxo.txout.value,
                        sent: 0,
                        fee: None,
                    };
                    my_utxos.push((utxo, transaction.clone()));
                    break;
                }
            }
        }
        if my_utxos.is_empty() {
            return None;
        }
        Some(my_utxos)
    }
    /// Sync headers
    pub fn sync_headers(&self) -> Result<u32, UtreexoError> {
        let unlocked_peers = self
            .peers
            .read()
            .expect("UtreexoBlockchain::sync_headers - Can't lock peers.");
        if unlocked_peers.is_empty() {
            return Err(UtreexoError::NoPeer);
        }
        let idx: usize = random::<usize>() % unlocked_peers.len();
        let peer = unlocked_peers
            .get(idx)
            .expect("UtreexoBlockchain::sync_headers - Can't read peers. Perhaps we got no peers?");

        let max_tip = peer.get_version().start_height;
        assert!(max_tip > 0);
        let mut cur_height = self.blocks.get_height()?;
        let mut last_hash = self
            .blocks
            .get_block_hash(cur_height as usize)?
            .expect("UtreexoBlockchain::sync_headers - Our index says we have more blocks that we actually have");
        if (cur_height as i32) >= max_tip {
            return Ok(0);
        }
        let missing = (max_tip as u32) - cur_height;

        // We use self.blocks.get_height because we can't miss a block. If something odd
        // happens and we don't catch a given height, we need retry.
        while self.blocks.get_height()? < (max_tip as u32) {
            peer.send(NetworkMessage::GetHeaders(GetHeadersMessage::new(
                vec![last_hash],
                Default::default(),
            )))?;
            if let NetworkMessage::Headers(headers) = peer
                .recv("headers", Some(Duration::from_secs(10)))?
                .ok_or(UtreexoError::Timeout)?
            {
                for header in headers {
                    cur_height += 1;
                    assert!(header.validate_pow(&header.target()).is_ok());
                    self.blocks
                        .save_block_header(&header, cur_height as usize)?;
                    self.bump_height()?;
                }
                println!("Current tip: {}", cur_height);

                assert_eq!(self.blocks.get_height()?, cur_height);
            } else {
                return Err(UtreexoError::InvalidResponse);
            }
            last_hash = self
                .blocks
                .get_block_hash(self.blocks.get_height()? as usize)?
                .expect("UtreexoBlockchain::sync_headers - We advanced more than we should");
        }

        Ok(missing)
    }
    /// Builds a new node
    pub fn new(peers: Vec<&str>, network: bitcoin::Network) -> Self {
        let path = "/tmp/utreexo/test_create_chain_store/";
        let mut opts = rocksdb::Options::default();

        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let mempool = Arc::new(Mempool::default());
        let chain = UtreexoState::new();
        let db = DB::open_cf(&opts, &path, vec!["default"])
            .expect("UtreexoBlockchain::new - db error: can't open the default cf");

        let blocks = ChainStore::new(db, network)
            .expect("UtreexoBlockchain::new - db_error: can't instantiate the database");
        let blocks = Arc::new(blocks);

        let peers: Vec<_> = peers
            .iter()
            .map(|peer| Peer::connect(*peer, mempool.clone(), network, blocks.clone()))
            .filter(|peer| peer.is_ok())
            .map(|peer| peer.expect("UtreexoBlockchain::new - We filtered this, it has to be ok"))
            .collect();
        let peers = Arc::from(RwLock::from(peers));

        UtreexoBlockchain {
            chain: RefCell::new(chain),
            peers,
            mempool,
            blocks,
            ext_spks: vec![],
            int_spks: vec![],
        }
    }
}

impl WalletSync for UtreexoBlockchain {
    fn wallet_sync<D: crate::database::BatchDatabase>(
        &self,
        database: &mut D,
        _progress_update: Box<dyn super::Progress>,
    ) -> Result<(), crate::Error> {
        let ext_spks = database.iter_script_pubkeys(Some(KeychainKind::External))?;
        let pk_hash_set: HashSet<Script> = ext_spks.into_iter().collect();

        let unlocked_peers = self
            .peers
            .read()
            .expect("UtreexoBlockchain::wallet_setup - can't acquire peer's lock ");
        // This while is here to prevent missing a block that is mined while we catch on
        // with the chain tip.
        loop {
            let stop_height = self.get_height()?;
            const BUNDLE_LENGTH: u32 = 10000;
            // Instead of asking for blocks one-by-one, we ask for multiple (BUNDLE_LENGTH blocks)
            // Bundle is a moving pointer that represents the integer part of our current
            // height divided by BUNDLE_LENGTH. So the height'll always be in
            // [BUNDLE_LENGTH * bundle, BUNDLE_LENGTH * bundle + BUNDLE_LENGTH].

            // An alternative way to do this would be having the outer for's range use a BUNDLE_LENGTH
            // step, instead of 1
            for bundle in 0..=(stop_height / BUNDLE_LENGTH) {
                let height = bundle * BUNDLE_LENGTH;

                // Shuffle peers if possible, we don't want to overload then
                let idx: usize = random::<usize>() % unlocked_peers.len();
                let peer = unlocked_peers.get(idx).expect(
                    "UtreexoBlockchain::sync_headers - Can't read peers. Perhaps we got no peers?",
                );

                println!("Sync at block: {}", height);
                self.request_blocks((height) as usize, (height + BUNDLE_LENGTH) as usize)?;
                for i in (bundle * BUNDLE_LENGTH)..=(height + BUNDLE_LENGTH) {
                    let message = peer.recv("block", Some(Duration::from_secs(10)))?;
                    if let Some(message) = message {
                        if let NetworkMessage::Block(block) = message {
                            if let Some(my_utxos) = self.filter_block(block, i, &pk_hash_set) {
                                for (utxo, transaction) in my_utxos {
                                    database.set_utxo(&utxo)?;
                                    database.set_tx(&transaction)?;
                                }
                            }
                        }
                    } else {
                        return Err(crate::Error::UtreexoError(UtreexoError::Timeout));
                    }
                    if i == stop_height {
                        break;
                    }
                }
            }
            if self.sync_headers()? == 0 {
                break;
            }
        }

        Ok(())
    }
    fn wallet_setup<D: crate::database::BatchDatabase>(
        &self,
        database: &mut D,
        _progress_update: Box<dyn super::Progress>,
    ) -> Result<(), crate::Error> {
        self.wallet_sync(database, _progress_update)?;
        Ok(())
    }
}
impl GetBlockHash for UtreexoBlockchain {
    fn get_block_hash(&self, height: u64) -> Result<bitcoin::BlockHash, crate::Error> {
        let hash = self.blocks.get_block_hash(height as usize)?;

        if let Some(hash) = hash {
            Ok(hash)
        } else {
            Err(crate::Error::UtreexoError(UtreexoError::BlockNotFound(
                height,
            )))
        }
    }
}
impl GetTx for UtreexoBlockchain {
    fn get_tx(&self, txid: &bitcoin::Txid) -> Result<Option<bitcoin::Transaction>, crate::Error> {
        let tx = self
            .mempool
            .iter_txs()
            .into_iter()
            .find(|tx| tx.txid() == *txid);
        Ok(tx)
    }
}
impl GetHeight for UtreexoBlockchain {
    fn get_height(&self) -> Result<u32, crate::Error> {
        let height = self.blocks.get_height()?;
        Ok(height)
    }
}

impl Blockchain for UtreexoBlockchain {
    fn get_capabilities(&self) -> std::collections::HashSet<super::Capability> {
        let capabilities: HashSet<_> = vec![Capability::FullHistory].into_iter().collect();
        capabilities
    }

    fn broadcast(&self, tx: &bitcoin::Transaction) -> Result<(), crate::Error> {
        let unlocked_peers = self
            .peers
            .read()
            .expect("UtreexoBlockchain::broadcast - peers lock error: Failed to lock peers");
        let idx: usize = random::<usize>() % unlocked_peers.len();

        let peer = unlocked_peers.get(idx).expect(
            "UtreexoBlockchain::broadcast - Failed reading peers: Perhaps we have no peers?",
        );

        let transaction = NetworkMessage::Tx(tx.clone());
        let _ = peer.send(transaction)?;
        Ok(())
    }

    fn estimate_fee(&self, _: usize) -> Result<crate::FeeRate, crate::Error> {
        Ok(FeeRate::default())
    }
}
#[allow(missing_docs)]
#[derive(Debug)]
pub enum UtreexoError {
    DeserializationError,
    Db(rocksdb::Error),
    IoError(std::io::Error),
    TimeError(std::time::SystemTimeError),
    InvalidResponse,
    DataCorruption,
    Timeout,
    UtreexoError(String),
    InvalidPeer,
    BlockNotFound(u64),
    NoPeer,
    TxValidationErr,
}
impl From<rocksdb::Error> for UtreexoError {
    fn from(err: rocksdb::Error) -> Self {
        UtreexoError::Db(err)
    }
}
impl From<std::io::Error> for UtreexoError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}
impl From<std::time::SystemTimeError> for UtreexoError {
    fn from(err: std::time::SystemTimeError) -> Self {
        Self::TimeError(err)
    }
}
impl From<UtreexoError> for crate::Error {
    fn from(error: UtreexoError) -> Self {
        crate::Error::UtreexoError(error)
    }
}
