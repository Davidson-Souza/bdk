//! A store is a database that stores useful chain data, like headers, proofs and UTXOS
//! This is intended to be used only with the utreexo mod
//!
//! Author: Davidson Souza
//! Year: 2022
//!
//! Since this is a lightweight node, we don't save full blocks, only block headers.
//! We need this for fiding ourselves in the chain, verify Merkle Proofs, ask some useful
//! data and so one. Headers are light, only 80 bytes long, so having a couple of them is
//! not a big deal.

use std::convert::TryInto;
use std::sync::{Arc, RwLock};

use super::UtreexoError;
use bitcoin::consensus::{deserialize, serialize, Decodable, Encodable};
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::Hash;
use bitcoin::util::uint::Uint256;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::BlockHeader;
use bitcoin::Network;
use lazy_static::lazy_static;
use rocksdb::{WriteBatch, DB};

lazy_static! {
    static ref MAINNET_GENESIS: Block = deserialize(&Vec::<u8>::from_hex("0100000000000000000000000000000000000000000000000000000000000000000000003BA3EDFD7A7B12B27AC72C3E67768F617FC81BC3888A51323A9FB8AA4B1E5E4A29AB5F49FFFF001D1DAC2B7C0101000000010000000000000000000000000000000000000000000000000000000000000000FFFFFFFF4D04FFFF001D0104455468652054696D65732030332F4A616E2F32303039204368616E63656C6C6F72206F6E206272696E6B206F66207365636F6E64206261696C6F757420666F722062616E6B73FFFFFFFF0100F2052A01000000434104678AFDB0FE5548271967F1A67130B7105CD6A828E03909A67962E0EA1F61DEB649F6BC3F4CEF38C4F35504E51EC112DE5C384DF7BA0B8D578A4C702B6BF11D5FAC00000000").unwrap()).unwrap();
    static ref TESTNET_GENESIS: Block = deserialize(&Vec::<u8>::from_hex("0100000000000000000000000000000000000000000000000000000000000000000000003BA3EDFD7A7B12B27AC72C3E67768F617FC81BC3888A51323A9FB8AA4B1E5E4ADAE5494DFFFF001D1AA4AE180101000000010000000000000000000000000000000000000000000000000000000000000000FFFFFFFF4D04FFFF001D0104455468652054696D65732030332F4A616E2F32303039204368616E63656C6C6F72206F6E206272696E6B206F66207365636F6E64206261696C6F757420666F722062616E6B73FFFFFFFF0100F2052A01000000434104678AFDB0FE5548271967F1A67130B7105CD6A828E03909A67962E0EA1F61DEB649F6BC3F4CEF38C4F35504E51EC112DE5C384DF7BA0B8D578A4C702B6BF11D5FAC00000000").unwrap()).unwrap();
    static ref REGTEST_GENESIS: Block = deserialize(&Vec::<u8>::from_hex("0100000000000000000000000000000000000000000000000000000000000000000000003BA3EDFD7A7B12B27AC72C3E67768F617FC81BC3888A51323A9FB8AA4B1E5E4ADAE5494DFFFF7F20020000000101000000010000000000000000000000000000000000000000000000000000000000000000FFFFFFFF4D04FFFF001D0104455468652054696D65732030332F4A616E2F32303039204368616E63656C6C6F72206F6E206272696E6B206F66207365636F6E64206261696C6F757420666F722062616E6B73FFFFFFFF0100F2052A01000000434104678AFDB0FE5548271967F1A67130B7105CD6A828E03909A67962E0EA1F61DEB649F6BC3F4CEF38C4F35504E51EC112DE5C384DF7BA0B8D578A4C702B6BF11D5FAC00000000").unwrap()).unwrap();
    static ref SIGNET_GENESIS: Block = deserialize(&Vec::<u8>::from_hex("0100000000000000000000000000000000000000000000000000000000000000000000003BA3EDFD7A7B12B27AC72C3E67768F617FC81BC3888A51323A9FB8AA4B1E5E4A008F4D5FAE77031E8AD222030101000000010000000000000000000000000000000000000000000000000000000000000000FFFFFFFF4D04FFFF001D0104455468652054696D65732030332F4A616E2F32303039204368616E63656C6C6F72206F6E206272696E6B206F66207365636F6E64206261696C6F757420666F722062616E6B73FFFFFFFF0100F2052A01000000434104678AFDB0FE5548271967F1A67130B7105CD6A828E03909A67962E0EA1F61DEB649F6BC3F4CEF38C4F35504E51EC112DE5C384DF7BA0B8D578A4C702B6BF11D5FAC00000000").unwrap()).unwrap();
}

/// Every flavor of data we store
pub enum StoreEntry {
    /// A block header, it's indexed by it's height
    BlockHeader(Option<usize>),
    /// A block (header + transactions), also indexed by a height
    Block(Option<usize>),
    /// A header index is a map to know a particular block's hash
    BlockHeaderIndex(Option<BlockHash>),
    /// Where are we? This is a unique key to store our curent sync state
    Status,
}

impl StoreEntry {
    /// Get the data prefix
    pub fn get_prefix(&self) -> Vec<u8> {
        match self {
            StoreEntry::BlockHeader(_) => b"z",
            StoreEntry::Block(_) => b"x",
            StoreEntry::BlockHeaderIndex(_) => b"i",
            StoreEntry::Status => b"s",
        }
        .to_vec()
    }
    /// Retuns the entry's key
    pub fn get_key(&self) -> Vec<u8> {
        let mut prefix = self.get_prefix();
        match self {
            StoreEntry::BlockHeader(Some(height)) => {
                prefix.extend_from_slice(&height.to_be_bytes())
            }
            StoreEntry::Block(Some(height)) => prefix.extend_from_slice(&height.to_be_bytes()),
            StoreEntry::BlockHeaderIndex(Some(hash)) => {
                prefix.extend_from_slice(&hash.into_inner())
            }
            _ => {}
        }

        prefix
    }
}

/// A trait for types that serialize as a db value
pub trait SerializeDb: Sized {
    /// Writes contained values to a Vec
    fn serialize(&self) -> Vec<u8>;
    /// Read values from a Vec
    fn deserialize(data: &[u8]) -> Result<Self, UtreexoError>;
}

impl<T> SerializeDb for T
where
    T: Encodable + Decodable,
{
    fn serialize(&self) -> Vec<u8> {
        serialize(self)
    }

    fn deserialize(data: &[u8]) -> Result<Self, UtreexoError> {
        deserialize(data).map_err(|_| UtreexoError::DeserializationError)
    }
}
/// The actual store
#[allow(unused)]
#[derive(Debug)]
pub struct ChainStore {
    store: Arc<RwLock<DB>>,
    min_height: usize,
    network: Network,
    cf_name: String,
}
#[allow(unused)]
impl ChainStore {
    /// Creates a new store
    pub fn new(store: DB, network: Network) -> Result<Self, UtreexoError> {
        let genesis: Block = match network {
            Network::Bitcoin => MAINNET_GENESIS.clone(),
            Network::Testnet => TESTNET_GENESIS.clone(),
            Network::Regtest => REGTEST_GENESIS.clone(),
            Network::Signet => SIGNET_GENESIS.clone(),
        };

        let genesis_key = StoreEntry::BlockHeader(Some(0)).get_key();
        let cf_name = "default".to_string();
        if let Some(cf_handle) = store.cf_handle(&cf_name) {
            if store.get_pinned_cf(cf_handle, &genesis_key)?.is_none() {
                let mut batch = WriteBatch::default();
                batch.put_cf(
                    cf_handle,
                    genesis_key,
                    (genesis.header, genesis.header.work()).serialize(),
                );
                batch.put_cf(
                    cf_handle,
                    StoreEntry::BlockHeaderIndex(Some(genesis.block_hash())).get_key(),
                    &0usize.to_be_bytes(),
                );
                store.write(batch)?;
            }
        }
        Ok(ChainStore {
            store: Arc::new(RwLock::new(store)),
            min_height: 0,
            network,
            cf_name,
        })
    }
    /// Returns the height of the curent chain
    pub fn get_height(&self) -> Result<u32, UtreexoError> {
        let read_store = self.store.read().unwrap();
        let cf_handle = read_store.cf_handle(&self.cf_name).unwrap();

        let height = read_store.get_cf(&cf_handle, StoreEntry::Status.get_key())?;

        let height: u32 =
            SerializeDb::deserialize(&(height.unwrap_or_default().as_slice())).unwrap_or(0);
        Ok(height)
    }
    /// This function is called after processing blocks, updates the curent height.
    pub fn bump_height(&self, height: u32) -> Result<(), UtreexoError> {
        let key = StoreEntry::Status.get_key();
        let value = height.serialize();

        let mut batch = WriteBatch::default();
        let read_store = self.store.read().unwrap();
        let cf_handle = read_store.cf_handle(&self.cf_name).unwrap();

        batch.put_cf(cf_handle, key, value);
        read_store.write(batch)?;
        Ok(())
    }
    /// Creates a transaction locator over curently know blocks
    pub fn get_locators(&self) -> Result<Vec<(BlockHash, u32)>, UtreexoError> {
        let mut step = 1;
        let mut index = self.get_height()?;
        let mut answer = Vec::new();

        let store_read = self.store.read().unwrap();
        let cf_handle = store_read.cf_handle(&self.cf_name).unwrap();

        loop {
            if answer.len() > 10 {
                step *= 2;
            }

            let (header, _): (BlockHeader, Uint256) = SerializeDb::deserialize(
                &store_read
                    .get_pinned_cf(
                        cf_handle,
                        StoreEntry::BlockHeader(Some(index as usize)).get_key(),
                    )?
                    .unwrap(),
            )?;
            answer.push((header.block_hash(), index));

            if let Some(new_index) = index.checked_sub(step) {
                index = new_index;
            } else {
                break;
            }
        }

        Ok(answer)
    }
    /// Returns the height of a block, given it's hash
    pub fn get_height_for(&self, block_hash: &BlockHash) -> Result<Option<usize>, UtreexoError> {
        let read_store = self.store.read().unwrap();
        let cf_handle = read_store.cf_handle(&self.cf_name).unwrap();

        let key = StoreEntry::BlockHeaderIndex(Some(*block_hash)).get_key();
        let data = read_store.get_pinned_cf(cf_handle, key)?;
        data.map(|data| {
            Ok::<_, UtreexoError>(usize::from_be_bytes(
                data.as_ref()
                    .try_into()
                    .map_err(|_| UtreexoError::DeserializationError)?,
            ))
        })
        .transpose()
    }
    /// Returns the hash of a block at a given height in our current chain
    pub fn get_block_hash(&self, height: usize) -> Result<Option<BlockHash>, UtreexoError> {
        let read_store = self.store.read().unwrap();
        let cf_handle = read_store.cf_handle(&self.cf_name).unwrap();

        let key = StoreEntry::BlockHeader(Some(height)).get_key();
        let data = read_store.get_pinned_cf(cf_handle, key)?;
        if let None = data {
            return Ok(None);
        }
        data.map(|data| {
            let (header, _): (BlockHeader, Uint256) =
                deserialize(&data).map_err(|_| UtreexoError::DeserializationError)?;
            Ok::<_, UtreexoError>(header.block_hash())
        })
        .transpose()
    }
    /// Save only a header, not the full block
    pub fn save_block_header(
        &self,
        block: &BlockHeader,
        height: usize,
    ) -> Result<(), UtreexoError> {
        let index_key = StoreEntry::BlockHeader(Some(height)).get_key();
        let hash_key = StoreEntry::BlockHeaderIndex(Some(block.block_hash())).get_key();

        let mut batch = WriteBatch::default();
        let read_store = self.store.read().unwrap();
        let cf_handle = read_store.cf_handle(&self.cf_name).unwrap();

        batch.put_cf(
            cf_handle,
            index_key,
            (block.clone(), block.work()).serialize(),
        );
        batch.put_cf(cf_handle, hash_key, &height.to_be_bytes());
        read_store.write(batch)?;
        Ok(())
    }
    /// Retrieves a full block
    pub fn get_full_block(&self, height: usize) -> Result<Option<Block>, UtreexoError> {
        let read_store = self.store.read().unwrap();

        let key = StoreEntry::Block(Some(height)).get_key();
        let opt_block = read_store.get_pinned(key)?;

        opt_block
            .map(|data| deserialize(&data))
            .transpose()
            .map_err(|_| UtreexoError::DeserializationError)
    }
    /// Delete blocks from the first know block until `height`, useful for pruning
    pub fn delete_blocks_until(&self, height: usize) -> Result<(), UtreexoError> {
        let from_key = StoreEntry::Block(Some(0)).get_key();
        let to_key = StoreEntry::Block(Some(height)).get_key();

        let mut batch = WriteBatch::default();
        batch.delete_range(&from_key, &to_key);

        self.store.read().unwrap().write(batch)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use bitcoin::{consensus::deserialize, hashes::hex::FromHex, BlockHeader};
    use rocksdb::DB;

    use super::{ChainStore, MAINNET_GENESIS};

    #[test]
    fn test_create_chain_store() {
        let path = "/tmp/utreexo/test_create_chain_store/";
        let genesis = MAINNET_GENESIS.clone().block_hash();
        let mut opts = rocksdb::Options::default();

        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let db = DB::open_cf(&opts, &path, vec!["default"]).unwrap();
        let cs = ChainStore::new(db, bitcoin::Network::Bitcoin).expect("Unexpected db errror");
        let res = cs.get_block_hash(0).unwrap();

        assert_eq!(res, Some(genesis));
    }
    #[test]
    fn test_saving_block() {
        let block = deserialize::<BlockHeader>(&Vec::<u8>::from_hex("010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299").unwrap()).unwrap();

        let path = "/tmp/utreexo/test_create_chain_store/";
        let mut opts = rocksdb::Options::default();

        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let db = DB::open_cf(&opts, &path, vec!["default"]).unwrap();
        let cs = ChainStore::new(db, bitcoin::Network::Bitcoin).expect("Unexpected db errror");

        let _ = cs.save_block_header(&block, 1);
        let res = cs.get_block_hash(1).expect("Fail");

        assert_eq!(res, Some(block.block_hash()));
    }
}
