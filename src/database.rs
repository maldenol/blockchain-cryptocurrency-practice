//! Blockchain database.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::{create_dir_all, read, read_dir, write};
use std::net::SocketAddr;
use std::ops::{Bound, RangeBounds};
use std::str::FromStr;

use bincode::{deserialize, serialize};
use rocksdb::{IteratorMode, Options, DB};

use obj2str::Obj2Str;
use obj2str_derive::Obj2Str;

use crate::block::{Block, UTXOPool, UTXPool};
use crate::consts::*;
use crate::digsig::PrivateKey;

/// Blockchain database.
pub struct BlockchainDB {
    /// The path to the saving directory.
    path: String,
    /// The height of the last block.
    height: Option<u32>,
    /// The queue of recently accessed blocks.
    /// Blocks are saved in multiple files
    /// each containing 'BLOCK_PER_FILE' blocks at most.
    blocks_cache: RefCell<VecDeque<(u32, Block)>>,
    /// The pool of UTXO (Unspent 'TxOutput's).
    /// The latest value of the UTXO pool is saved in a single file.
    utxo_pool: UTXOPool,
    /// The pool of UTX (Unrecorded 'Tx's).
    /// The latest value of the UTX pool is saved in a single file.
    utx_pool: UTXPool,
}

/// Wallet database.
#[derive(Obj2Str)]
pub struct WalletDB {
    /// The path to the saving directory.
    path: String,
}

/// NetDriver database.
pub struct NetDriverDB {
    /// The path to the saving directory.
    path: String,
}

impl BlockchainDB {
    /// Returns a newly created 'BlockchainDB'.
    pub fn new(mut path: String) -> Self {
        // Adding a slash to the end of the path if it is missing
        if !path.ends_with('/') {
            path += "/";
        }

        path += BLOCKCHAIN_SAVE_DIR;

        let mut db = BlockchainDB {
            path,
            height: None,
            blocks_cache: RefCell::new(VecDeque::with_capacity(RECENT_BLOCK_NUMBER)),
            utxo_pool: Vec::new(),
            utx_pool: Vec::new(),
        };

        // Trying to load height, UTXO and UTX pools
        db.height = db.load_height();
        if let Some(utxo_pool) = db.load_utxo_pool() {
            db.utxo_pool = utxo_pool;
        }
        if let Some(utx_pool) = db.load_utx_pool() {
            db.utx_pool = utx_pool;
        }

        db
    }

    /// Increments the 'height' field of the 'BlockchainDB'.
    fn increment_height(&mut self) {
        if let Some(height) = self.height {
            self.height = Some(height + 1);
        } else {
            self.height = Some(0);
        }
    }

    /// Decrements the 'height' field of the 'BlockchainDB'.
    fn decrement_height(&mut self) {
        if let Some(height) = self.height {
            if height == 0 {
                self.height = None;
            } else {
                self.height = Some(height - 1);
            }
        }
    }

    /// Returns the 'height' field of the 'BlockchainDB'.
    pub fn get_height(&self) -> Option<u32> {
        self.height
    }

    /// Load the 'height' field of the 'BlockchainDB' from the save file.
    fn load_height(&mut self) -> Option<u32> {
        // Getting all the files in the save directory
        let paths = read_dir(self.path.clone()).ok()?;

        // Getting all the block save files
        let paths: Vec<_> = paths
            .filter_map(|path| {
                if let Ok(path) = path {
                    let path = path.file_name().into_string().unwrap();
                    if path.ends_with(BLOCK_FILE_EXTENSION) {
                        return Some(path);
                    }
                }
                None
            })
            .collect();

        // Getting the last block save file
        let Some(path) = paths.iter().max_by(|path_left, path_right| {
            let number_left =
                u32::from_str(path_left.replace(BLOCK_FILE_EXTENSION, "").as_str()).unwrap();
            let number_right =
                u32::from_str(path_right.replace(BLOCK_FILE_EXTENSION, "").as_str()).unwrap();
            number_left.cmp(&number_right)
        }) else {
            return None;
        };
        let path = self.path.clone() + path.as_str();

        let mut db_opts = Options::default();
        db_opts.create_if_missing(false);
        let db = DB::open(&db_opts, path).unwrap();

        // Getting all the keys in the save file
        let keys: Vec<_> = db
            .iterator(IteratorMode::End)
            .filter_map(|key| {
                let Ok(key) = key else {
                    return None;
                };

                let key = [key.0[0], key.0[1], key.0[2], key.0[3]];
                Some(u32::from_be_bytes(key))
            })
            .collect();

        // Returning the biggest key (height)
        keys.iter().max().copied()
    }

    /// Adds a 'Block' to the end of the 'BlockchainDB'.
    /// It is saved to the file corresponding to its height.
    pub fn add_block(&mut self, block: Block) {
        self.increment_height();

        let current_height = self.height.unwrap();

        let path = self.get_block_path_by_height(current_height);

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        let db = DB::open(&db_opts, path).unwrap();

        let key = current_height.to_be_bytes();

        // Saving the block to the database
        db.put(key, serialize(&block).unwrap()).unwrap();

        let mut blocks_cache = self.blocks_cache.borrow_mut();

        // If the block cache is at its maximum size
        if blocks_cache.len() >= RECENT_BLOCK_NUMBER {
            // Remove the front element as the oldest one
            let _ = blocks_cache.pop_front();
        }

        // Adding the block to the block cache
        blocks_cache.push_back((current_height, block));
    }

    /// Removes the last 'Block' from the 'BlockchainDB'.
    pub fn remove_block(&mut self) -> Option<Block> {
        // Checking if the blockchain is not empty
        let Some(current_height) = self.get_height() else {
            return None;
        };

        {
            let mut blocks_cache = self.blocks_cache.borrow_mut();

            // If the last block is in the block cache
            if let Some(index) = blocks_cache
                .iter()
                .position(|(block_height, _)| *block_height == current_height)
            {
                // Removing it
                let _ = blocks_cache.remove(index).unwrap();
            }
        }

        let path = self.get_block_path_by_height(current_height);

        let mut db_opts = Options::default();
        db_opts.create_if_missing(false);
        let db = DB::open(&db_opts, path).unwrap();

        let key = current_height.to_be_bytes();

        // Getting the last block from the database
        let block = db.get(key).unwrap().unwrap();
        let block = deserialize(block.as_slice()).ok();

        // Removing the last block from the database
        db.delete(key).unwrap();

        self.decrement_height();

        block
    }

    /// Returns the 'Block' at specific height.
    pub fn get_block(&self, height: u32) -> Option<Block> {
        // Checking if the blockchain is not empty
        let Some(current_height) = self.get_height() else {
            return None;
        };

        // If there is no block with such height
        if height > current_height {
            return None;
        }

        let mut blocks_cache = self.blocks_cache.borrow_mut();

        // If the block is in the block cache
        if let Some(index) = blocks_cache
            .iter()
            .position(|(block_height, _)| *block_height == height)
        {
            // Moving the block to the back of the cache as the most recent one
            let block = blocks_cache.remove(index).unwrap();
            blocks_cache.push_back(block.clone());

            Some(block.1)
        } else {
            let path = self.get_block_path_by_height(height);

            let mut db_opts = Options::default();
            db_opts.create_if_missing(false);
            let Ok(db) = DB::open(&db_opts, path.clone()) else {
                return None;
            };

            let key = height.to_be_bytes();

            // Getting the block from the database
            let block = db.get(key).unwrap().unwrap();
            let block = deserialize::<Block>(block.as_slice()).unwrap();

            // If the block cache is at its maximum size
            if blocks_cache.len() >= RECENT_BLOCK_NUMBER {
                // Remove the front element as the oldest one
                let _ = blocks_cache.pop_front();
            }

            // Adding the block to the block cache
            blocks_cache.push_back((height, block.clone()));

            Some(block)
        }
    }

    /// Returns 'Block's at specific range.
    /// # Arguments
    /// * 'range' - The range.
    /// * 'rev' - Whether the range must be reversed.
    pub fn get_block_range<R>(&self, range: R, rev: bool) -> Vec<Block>
    where
        R: RangeBounds<u32>,
    {
        let Some(current_height) = self.get_height() else {
            return Vec::new();
        };

        let mut blocks = Vec::new();

        let start = match range.start_bound() {
            Bound::Included(bound) => *bound,
            Bound::Excluded(bound) => *bound + 1,
            Bound::Unbounded => 0,
        };

        let end = match range.end_bound() {
            Bound::Included(bound) => *bound,
            Bound::Excluded(bound) => *bound - 1,
            Bound::Unbounded => current_height,
        };

        if !rev {
            for height in start..=end {
                if let Some(block) = self.get_block(height) {
                    blocks.push(block);
                } else {
                    break;
                }
            }
        } else {
            for height in (start..=end).rev() {
                #[allow(clippy::collapsible_else_if)]
                if let Some(block) = self.get_block(height) {
                    blocks.push(block);
                } else {
                    if blocks.is_empty() {
                        continue;
                    } else {
                        panic!();
                    }
                }
            }
        }

        blocks
    }

    /// Returns the last 'Block' in the 'BlockchainDB'.
    pub fn get_last_block(&self) -> Option<Block> {
        if let Some(current_height) = self.height {
            self.get_block(current_height)
        } else {
            None
        }
    }

    /// Returns the height of the 'Block' in the 'BlockchainDB'.
    /// Searches from the beginning.
    pub fn find_block<P>(&self, mut predicate: P) -> Option<u32>
    where
        P: FnMut(&Block) -> bool,
    {
        // Checking if the blockchain is not empty
        let Some(current_height) = self.height else {
            return None;
        };

        // For each block in the blockchain
        for height in 0..=current_height {
            // If there is the block with such height
            if let Some(block) = self.get_block(height) {
                // If the block satisfies the predicate
                if predicate(&block) {
                    return Some(height);
                }
            } else {
                break;
            }
        }

        None
    }

    /// Returns the height of the 'Block' in the 'BlockchainDB'.
    /// Searches from the end.
    pub fn find_block_rev<P>(&self, mut predicate: P) -> Option<u32>
    where
        P: FnMut(&Block) -> bool,
    {
        // Checking if the blockchain is not empty
        let Some(current_height) = self.height else {
            return None;
        };

        // For each block in the blockchain
        for height in (0..=current_height).rev() {
            // If there is the block with such height
            if let Some(block) = self.get_block(height) {
                // If the block satisfies the predicate
                if predicate(&block) {
                    return Some(height);
                }
            }
        }

        None
    }

    /// Returns a shared reference to the UTXO pool.
    pub fn get_utxo_pool(&self) -> &UTXOPool {
        &self.utxo_pool
    }

    /// Returns a mutable reference to the UTXO pool.
    pub fn get_utxo_pool_mut(&mut self) -> &mut UTXOPool {
        &mut self.utxo_pool
    }

    /// Saves the UTXO pool to the save file.
    pub fn save_utxo_pool(&mut self) {
        let utxo_pool = serialize(&self.utxo_pool).unwrap();
        create_dir_all(self.path.clone()).unwrap();
        write(self.get_utxo_path(), utxo_pool).unwrap();
    }

    /// Loads the UTXO pool from the save file and returns it.
    fn load_utxo_pool(&mut self) -> Option<UTXOPool> {
        let Ok(utxo_pool) = read(self.get_utxo_path()) else {
            return None;
        };

        let Ok(utxo_pool) = deserialize(utxo_pool.as_slice()) else {
            return None;
        };

        Some(utxo_pool)
    }

    /// Returns a shared reference to the UTX pool.
    pub fn get_utx_pool(&self) -> &UTXPool {
        &self.utx_pool
    }

    /// Returns a mutable reference to the UTX pool.
    pub fn get_utx_pool_mut(&mut self) -> &mut UTXPool {
        &mut self.utx_pool
    }

    /// Saves the UTX pool to the save file.
    pub fn save_utx_pool(&mut self) {
        let utx_pool = serialize(&self.utx_pool).unwrap();
        create_dir_all(self.path.clone()).unwrap();
        write(self.get_utx_path(), utx_pool).unwrap();
    }

    /// Loads the UTX pool from the save file and returns it.
    fn load_utx_pool(&mut self) -> Option<UTXPool> {
        let Ok(utx_pool) = read(self.get_utx_path()) else {
            return None;
        };

        let Ok(utx_pool) = deserialize(utx_pool.as_slice()) else {
            return None;
        };

        Some(utx_pool)
    }

    /// Returns the path to the save file of the 'Block' based on its height.
    fn get_block_path_by_height(&self, height: u32) -> String {
        let first_block_in_file_height = height / BLOCK_PER_FILE * BLOCK_PER_FILE;
        self.path.clone() + first_block_in_file_height.to_string().as_str() + BLOCK_FILE_EXTENSION
    }

    /// Returns the path to the save file of the UTXO pool.
    fn get_utxo_path(&self) -> String {
        self.path.clone() + UTXO_FILE_NAME
    }

    /// Returns the path to the save file of the UTX pool.
    fn get_utx_path(&self) -> String {
        self.path.clone() + UTX_FILE_NAME
    }
}

impl WalletDB {
    /// Returns a newly created 'WalletDB'.
    pub fn new(mut path: String) -> Self {
        // Adding a slash to the end of the path if it is missing
        if !path.ends_with('/') {
            path += "/";
        }

        path += WALLET_SAVE_DIR;

        WalletDB { path }
    }

    /// Loads private keys from the save file and returns them.
    pub fn load(&self) -> Option<Vec<PrivateKey>> {
        let Ok(private_keys) = read(self.get_wallet_path()) else {
            return None;
        };

        let Ok(private_keys) = deserialize(private_keys.as_slice()) else {
            return None;
        };

        Some(private_keys)
    }

    /// Saves private keys to the save file.
    pub fn save(&mut self, private_keys: &Vec<PrivateKey>) {
        let private_keys = serialize(private_keys).unwrap();
        create_dir_all(self.path.clone()).unwrap();
        write(self.get_wallet_path(), private_keys).unwrap();
    }

    /// Returns the path to the save file of the 'Wallet'.
    fn get_wallet_path(&self) -> String {
        self.path.clone() + WALLET_FILE_NAME
    }
}

impl NetDriverDB {
    /// Returns a newly created 'NetDriverDB'.
    pub fn new(mut path: String) -> Self {
        // Adding a slash to the end of the path if it is missing
        if !path.ends_with('/') {
            path += "/";
        }

        path += NETDRIVER_SAVE_DIR;

        NetDriverDB { path }
    }

    /// Loads addresses of peers from the save file and returns them.
    pub fn load(&self) -> Option<Vec<SocketAddr>> {
        let Ok(addrs) = read(self.get_netdriver_path()) else {
            return None;
        };

        let Ok(addrs) = deserialize(addrs.as_slice()) else {
            return None;
        };

        Some(addrs)
    }

    /// Saves addresses of peers to the save file.
    pub fn save(&mut self, addrs: &Vec<SocketAddr>) {
        let addrs = serialize(addrs).unwrap();
        create_dir_all(self.path.clone()).unwrap();
        write(self.get_netdriver_path(), addrs).unwrap();
    }

    /// Returns the path to the save file of the 'NetDriver'.
    fn get_netdriver_path(&self) -> String {
        self.path.clone() + NETDRIVER_FILE_NAME
    }
}
