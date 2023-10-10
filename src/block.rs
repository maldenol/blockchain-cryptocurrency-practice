//! Blockchain and blocks.

use std::mem::size_of;
use std::ops::{DivAssign, MulAssign};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bincode::{deserialize, serialize};
use hmac_sha256::Hash as SHA256;
use num_bigint::BigUint;
use serde_derive::{Deserialize, Serialize};

use obj2str::Obj2Str;
use obj2str_derive::Obj2Str;
use semaphore::{Semaphore, SemaphoreGuard};

use crate::consts::*;
use crate::hash::Hash;
use crate::merkle::merkle_root;
use crate::netdriver::NetDriver;
use crate::tx::*;
use crate::wallet::Wallet;

const IMPOSSIBLE_BLOCK_HASH: Hash = Hash([255u8; 32]);

/// Blockchain.
pub struct Blockchain {
    blocks: Vec<Block>,
    /// The pool of UTX (Unrecorded 'Tx's).
    utx_pool: Vec<(Tx, u64)>,
    /// The pool of UTXO (Unspent 'TxOutput's).
    utxo_pool: Vec<TxOutputRef>,
    data_mtx: Semaphore,
    wallet: Arc<Mutex<Wallet>>,
    net_driver: Arc<Mutex<Box<NetDriver>>>,
}

/// Block.
#[derive(Clone, Serialize, Deserialize, Obj2Str)]
pub struct Block {
    header: BlockHeader,
    txs: Vec<Tx>,
}

/// Block's header.
#[derive(Clone, Serialize, Deserialize, Obj2Str)]
pub struct BlockHeader {
    version: u32,
    /// The 'Hash' of the previous 'Block' (its 'BlockHeader').
    prev_hash: Hash,
    /// The value of the root of the Merkle tree generated from 'Tx's in the 'Block'.
    merkle_root: Hash,
    timestamp: u64,
    /// The mining difficulty.
    difficulty: f32,
    /// The main value being tweaked during mining.
    nonce: u32,
}

/// Network message.
#[derive(Serialize, Deserialize)]
enum Message {
    BlockDownloadRequest(Hash),
    BlockDownloadResponse(Vec<Block>),
    TxDownloadRequest(Hash),
    TxDownloadResponse(Vec<Tx>),
    BlockBroadcast(Block),
    TxBroadcast(Tx),
}

impl Blockchain {
    /// Returns a newly created 'Blockchain'.
    pub fn new(wallet: Arc<Mutex<Wallet>>, net_driver: Arc<Mutex<Box<NetDriver>>>) -> Self {
        Blockchain {
            blocks: Vec::new(),
            utx_pool: Vec::new(),
            utxo_pool: Vec::new(),
            data_mtx: Semaphore::new(1),
            wallet,
            net_driver,
        }
    }

    /// Mines a 'Block'.
    /// Thread-safe.
    pub fn mine(&mut self) {
        // Acquiring read-write access to the blockchain
        self.data_mtx.acquire();

        // If there is no blocks yet, mine the genesis one
        let Some(current_height) = self.get_height() else {
            self.blocks.push(Block::mine(
                &IMPOSSIBLE_BLOCK_HASH,
                self.calculate_difficulty(0),
                vec![Blockchain::generate_coinbase_tx(
                    &self.wallet.lock().unwrap(),
                    0,
                    0,
                )],
            ));

            self.data_mtx.release();
            return;
        };

        // Choosing transactions with the biggest fees
        let (mut txs, fees, used_utxo) = self.choose_txs_with_fee();

        // Generating a coinbase transaction
        let coinbase_tx =
            Blockchain::generate_coinbase_tx(&self.wallet.lock().unwrap(), fees, current_height);
        txs.insert(0, coinbase_tx);

        // Getting the hash of the previous block and a new difficulty
        let prev_hash = self.blocks.last().unwrap().header.hash();
        let difficulty = self.calculate_difficulty(current_height + 1);

        // Releasing read-write access to the blockchain
        self.data_mtx.release();

        // Mining a block
        let block = Block::mine(&prev_hash, difficulty, txs);

        // Acquiring read-write access to the blockchain
        self.data_mtx.acquire();

        // Checking that the block is still valid (no blocks were added from another threads)
        if !block.validate(self, self.get_height().unwrap() + 1) {
            self.data_mtx.release();
            return;
        }

        // Removing used outputs from the UTXO pool
        for index in used_utxo.iter().rev() {
            self.utxo_pool.remove(*index);
        }

        // Adding outputs to the UTXO pool
        for tx in block.txs.iter() {
            let hash = tx.hash();
            for output_index in 0..tx.get_outputs().len() {
                self.utxo_pool.push(TxOutputRef {
                    tx_hash: hash,
                    output_index: output_index as u32,
                });
            }
        }

        // Adding the block to the blockchain
        self.blocks.push(block.clone());

        // Broadcasting the block
        self.broadcast_block(block);

        // Releasing read-write access to the blockchain
        self.data_mtx.release();
    }

    /// Returns the difficulty of the 'Block' based on its height.
    fn calculate_difficulty(&self, height: u32) -> f32 {
        if height == 0 {
            return 1f32;
        }

        let last_block = self.blocks.last().unwrap();
        let difficulty = last_block.header.difficulty;

        // If the time has come
        if height % DIFFICULTY_ADJUSTMENT_PERIOD == 0 {
            // Updating the difficulty
            let first_block = &self.blocks[(height - DIFFICULTY_ADJUSTMENT_PERIOD) as usize];

            let target_time =
                (DIFFICULTY_ADJUSTMENT_PERIOD * BLOCK_MINING_TIME) as f32 * 1_000_000_000f32;
            let actual_time = (last_block.header.timestamp - first_block.header.timestamp) as f32;

            f32::max(difficulty * target_time / actual_time, 1f32)
        } else {
            // Keeping the current difficulty
            difficulty
        }
    }

    /// Returns the reward for mining a 'Block' based on its height.
    fn calculate_block_reward(height: u32) -> u64 {
        MINING_REWARD / 2u64.pow(height / HALVING_PERIOD)
    }

    /// Returns a coinbase 'Tx' based on the fees and the height of the 'Block'.
    fn generate_coinbase_tx(wallet: &Wallet, fees: u64, height: u32) -> Tx {
        let block_reward = Blockchain::calculate_block_reward(height);

        Tx {
            version: TX_VERSION,
            inputs: vec![TxInput {
                output_ref: TxOutputRef {
                    tx_hash: Hash([0u8; 32]),
                    output_index: 0,
                },
                signature: None,
            }],
            outputs: vec![TxOutput {
                amount: block_reward + fees,
                public_key: wallet.get_public_keys()[0].clone(),
            }],
        }
    }

    /// Validates the coinbase 'Tx'
    /// based on the other transactions in the 'Block' and the height of the 'Block'.
    fn validate_coinbase_tx(&self, coinbase_tx: &Tx, other_txs: &[Tx], height: u32) -> bool {
        // Checking if the inputs and the outputs are not empty
        if coinbase_tx.inputs.is_empty() || coinbase_tx.outputs.is_empty() {
            return false;
        }

        // Calculating fees of the rest transaction of the block
        let mut fees = 0;
        for tx in other_txs {
            if let Some(fee) = tx.get_fee(self, height) {
                fees += fee;
            } else {
                return false;
            }
        }

        // Calculating the block's reward
        let mut block_reward = 0u64;
        for output in coinbase_tx.outputs.iter() {
            block_reward += output.amount;
        }

        // Checking if the block's reward is correct
        block_reward == Blockchain::calculate_block_reward(height) + fees
    }

    /// Returns a tuple of 'Tx's with the biggest fees that can fit in a single 'Block',
    /// the sum of these fees and indexes in the UTXO pool of UTXO that will be used.
    fn choose_txs_with_fee(&mut self) -> (Vec<Tx>, u64, Vec<usize>) {
        // Checking if the blockchain is not empty
        let Some(current_height) = self.get_height() else {
            return (Vec::new(), 0, Vec::new());
        };

        let mut txs = Vec::new();
        let mut fees = 0u64;
        let mut used_utxo = Vec::new();

        let mut mem_available = MAX_BLOCK_SIZE - size_of::<BlockHeader>();

        // For each transaction in the UTX pool
        'utx_pool: for _ in 0..self.utx_pool.len() {
            // Getting the UTX with the biggest fee
            // because the UTX pool is sorted in ascending order
            let (tx, fee) = self.utx_pool.pop().unwrap();

            // Checking for available memory in the block
            let (new_mem_available, not_available) = mem_available.overflowing_sub(tx.get_size());
            if not_available {
                // Push the transaction back and break
                self.utx_pool.push((tx, fee));
                break;
            }
            mem_available = new_mem_available;

            // Validating the transaction
            if !tx.validate(self, current_height) {
                continue;
            }

            // Getting UTXOs used by the transaction
            let mut inner_used_utxo = Vec::new();
            for input in tx.inputs.iter() {
                let index = self
                    .utxo_pool
                    .iter()
                    .position(|utxo| *utxo == input.output_ref);

                // If there is such UTXO in the pool
                if let Some(index) = index {
                    // If there is no such UTXO among the used UTXO yet
                    if !used_utxo.contains(&index) && !inner_used_utxo.contains(&index) {
                        inner_used_utxo.push(index);
                    } else {
                        continue 'utx_pool;
                    }
                } else {
                    continue 'utx_pool;
                }
            }

            // Adding transaction, its fee and used UTXO
            txs.push(tx);
            fees += fee;
            used_utxo.append(&mut inner_used_utxo);
        }

        (txs, fees, used_utxo)
    }

    /// Returns a UTXO pool calculated from the beginning based on the height.
    fn calculate_utxo_pool(&self, height: u32) -> Vec<TxOutputRef> {
        // Checking if the blockchain is not empty
        let Some(current_height) = self.get_height() else {
            return Vec::new();
        };

        // Checking if the height is not greater than the current one
        if height > current_height {
            return Vec::new();
        }

        let mut utxo_pool = Vec::new();

        // For each block from the beginning of the blockchain to the specific height
        for block in self.blocks.iter().take(height as usize + 1) {
            // For each transaction in the block
            for (tx_index, tx) in block.txs.iter().enumerate() {
                // If the transaction is a not coinbase transaction
                if tx_index > 0 {
                    // For each input in the transaction
                    for input in tx.inputs.iter() {
                        // Removing used UTXO from the UTXO pool
                        utxo_pool.remove(
                            utxo_pool
                                .iter()
                                .position(|output_ref| *output_ref == input.output_ref)
                                .unwrap(),
                        );
                    }
                }

                let hash = tx.hash();

                // For each output in the transaction
                for index in 0..tx.outputs.len() {
                    // Adding a new UTXO to the UTXO pool
                    utxo_pool.push(TxOutputRef {
                        tx_hash: hash,
                        output_index: index as u32,
                    });
                }
            }
        }

        utxo_pool
    }

    /// Returns a UTXO pool calculated from the end based on the height.
    fn calculate_utxo_pool_rev(&self, height: u32) -> Vec<TxOutputRef> {
        // Checking if the blockchain is not empty
        let Some(current_height) = self.get_height() else {
            return Vec::new();
        };

        // Checking if the height is not greater than the current one
        if height > current_height {
            return Vec::new();
        }

        let mut utxo_pool = self.utxo_pool.clone();

        // For each block from the end of the blockchain to the specific height
        for block in self
            .blocks
            .iter()
            .rev()
            .take((current_height - height) as usize)
        {
            // For each transaction in the block
            for (tx_index, tx) in block.txs.iter().enumerate() {
                // If the transaction is a not coinbase transaction
                if tx_index > 0 {
                    // For each input in the transaction
                    for input in tx.inputs.iter() {
                        // Adding used UTXO to the UTXO pool
                        utxo_pool.push(input.output_ref.clone());
                    }
                }

                let hash = tx.hash();

                // For each output in the transaction
                for index in 0..tx.outputs.len() {
                    // Removing a new UTXO from the UTXO pool
                    utxo_pool.remove(
                        utxo_pool
                            .iter()
                            .position(|output_ref| {
                                *output_ref
                                    == TxOutputRef {
                                        tx_hash: hash,
                                        output_index: index as u32,
                                    }
                            })
                            .unwrap(),
                    );
                }
            }
        }

        utxo_pool
    }

    /// Adds a 'Tx' to the UTX pool.
    /// Thread-safe.
    pub fn add_utx(&mut self, tx: Tx) {
        // Checking if the blockchain is not empty
        let Some(current_height) = self.get_height() else {
            return;
        };

        let Some(fee) = tx.get_fee(self, current_height) else {
            return;
        };

        // Broadcasting the transaction
        self.broadcast_tx(tx.clone());

        // Acquiring read-write access to the blockchain
        self.data_mtx.acquire();

        // Inserting the transaction to the UTX pool
        // so that all the transactions are sorted in ascending order by fee
        let mut index = 0;
        for (_, utx_fee) in self.utx_pool.iter() {
            if fee >= *utx_fee {
                index += 1;
            } else {
                break;
            }
        }

        self.utx_pool.insert(index, (tx, fee));

        // Releasing read-write access to the blockchain
        self.data_mtx.release();
    }

    /// Returns 'Block's in the 'Blockchain'.
    /// Thread-safe.
    pub fn get_blocks(&self) -> Vec<Block> {
        // Acquiring read-write access to the blockchain
        let _data_mtx = SemaphoreGuard::acquire(&self.data_mtx);

        self.blocks.clone()
    }

    /// Returns the height of the last 'Block' in the 'Blockchain'.
    /// Thread-unsafe.
    pub fn get_height(&self) -> Option<u32> {
        if !self.blocks.is_empty() {
            Some((self.blocks.len() - 1) as u32)
        } else {
            None
        }
    }

    /// Returns the 'Tx' found in the 'Blockchain' by its 'Hash' with the specified height.
    /// Thread-unsafe.
    /// # Arguments
    /// * 'hash' - The 'Hash' of the 'Tx.
    /// * 'height' - Must be not less than the height of the 'Block' containing the 'Tx'.
    pub fn get_tx(&self, hash: &Hash, height: u32) -> Option<&Tx> {
        // Searching for the transaction in the blockchain starting from the last block
        // with specific height
        for block in self.blocks.iter().take(height as usize + 1).rev() {
            // For each transaction in the block
            for tx in block.txs.iter() {
                // Comparing by hashes
                if tx.hash() == *hash {
                    return Some(tx);
                }
            }
        }

        None
    }

    /// Returns the 'TxOutput' found in the 'Blockchain' by its 'TxOutputRef' with the specified height.
    /// Thread-unsafe.
    /// # Arguments
    /// * 'output_ref' - 'TxOutputRef' referencing the 'TxOutput'.
    /// * 'height' - Must be not less than the height of the 'Block' containing the 'Tx'.
    pub fn get_tx_output(&self, output_ref: &TxOutputRef, height: u32) -> Option<&TxOutput> {
        let tx = self.get_tx(&output_ref.tx_hash, height)?;
        tx.outputs.get(output_ref.output_index as usize)
    }

    /// Returns whether the 'TxOutput' is an UTXO in the 'Blockchain' with the specified height.
    /// Thread-unsafe.
    /// # Arguments
    /// * 'output_ref' - 'TxOutputRef' referencing the 'TxOutput'.
    /// * 'height' - Must be not less than the height of the 'Block' containing the 'Tx'.
    pub fn is_utxo(&self, output_ref: &TxOutputRef, height: u32) -> bool {
        // Checking if the blockchain is not empty
        let Some(current_height) = self.get_height() else {
            return false;
        };

        // If the height is greater or equals to the current one
        if height >= current_height {
            // Checking if the output is an UTXO using the current UTXO pool
            self.utxo_pool.contains(output_ref)
        } else if height <= current_height / 2 {
            // Checking if the output is an UTXO using the calculated from the beginning UTXO pool
            self.calculate_utxo_pool(height).contains(output_ref)
        } else {
            // Checking if the output is an UTXO using the calculated from the end UTXO pool
            self.calculate_utxo_pool_rev(height).contains(output_ref)
        }
    }

    /// Returns the first 'Block' with specific 'Hash' and all the 'Block's after him.
    /// If there is no 'Block' with such 'Hash'
    /// it returns 'MAX_BLOCKS_PER_DOWNLOAD' of 'Block's from the beginning.
    /// Thread-unsafe.
    pub fn get_next_blocks(&self, hash: Hash) -> Vec<Block> {
        // Checking if the blockchain is not empty
        if self.get_height().is_none() {
            return Vec::new();
        }

        // If there is a block with such hash
        if hash != IMPOSSIBLE_BLOCK_HASH {
            if let Some(height) = self
                .blocks
                .iter()
                .position(|block| block.header.hash() == hash)
            {
                // Returning that block and all the next ones
                return self.blocks[height..].to_vec();
            }
        }

        // Returning the first several blocks
        self.blocks
            .iter()
            .take(MAX_BLOCKS_PER_DOWNLOAD)
            .cloned()
            .collect()
    }

    /// Returns the 'Hash' of the 'Block'
    /// that is located 'MAX_ACCIDENTAL_FORK_HEIGHT' 'Block's before the last one.
    /// If there are no 'Block's at all it returns the 'IMPOSSIBLE_BLOCK_HASH'.
    /// Thread-unsafe.
    pub fn get_oldest_accidental_fork_block_hash(&self) -> Hash {
        // Checking if the blockchain is not empty
        if self.get_height().is_none() {
            // Returning the impossible block hash
            return IMPOSSIBLE_BLOCK_HASH;
        }

        let index = self
            .blocks
            .len()
            .saturating_sub(1 + MAX_ACCIDENTAL_FORK_HEIGHT as usize);
        self.blocks[index].header.hash()
    }

    /// Tries to fast-forward the 'Blockchain' with the given 'Block's.
    /// Thread-unsafe.
    pub fn fast_forward(&mut self, blocks: &[Block]) -> bool {
        let mut blocks_updated = false;

        // For each block
        for block in blocks.iter() {
            // Checking if the blockchain is not empty
            let Some(current_height) = self.get_height() else {
                // If the block is valid
                if block.validate(self, 0) {
                    // Adding the block to the blockchain
                    self.blocks.push(block.clone());
                    blocks_updated = true;
                } else {
                    // Finishing because next blocks are invalid as well
                    break;
                }

                continue;
            };

            // If the block is the next one in the blockchain
            // (will be valid if placed after the current last one)
            let last_block_hash = self.blocks.last().unwrap().header.hash();
            if block.header.prev_hash == last_block_hash {
                // If the block is valid
                if block.validate(self, current_height + 1) {
                    // Adding the block to the blockchain
                    self.blocks.push(block.clone());
                    blocks_updated = true;
                } else {
                    // Finishing because next blocks are invalid as well
                    break;
                }
            }
        }

        blocks_updated
    }

    /// Tries to rebase the 'Blockchain' with the given 'Block's.
    /// Thread-unsafe.
    pub fn rebase(&mut self, blocks: &[Block]) -> bool {
        // Checking if the blockchain is not empty
        if self.get_height().is_none() {
            // Trying to fast-forward
            return self.fast_forward(blocks);
        }

        // Finding the oldest block that is common for the local and the remote blockchains
        let Some(oldest_common_block_height) = self
            .blocks
            .iter()
            .position(|local_block| local_block.header.hash() == blocks[0].header.hash())
        else {
            return false;
        };

        // Checking that it is not an intentional fork
        let Some(latest_common_block_index) = self.blocks.iter().rev().position(|local_block| {
            blocks
                .iter()
                .any(|remote_block| local_block.header.hash() == remote_block.header.hash())
        }) else {
            return false;
        };
        // During this search indexes are going backwards so they are equal to the length of the fork
        let fork_length = latest_common_block_index as u32;
        if fork_length > MAX_ACCIDENTAL_FORK_HEIGHT {
            return false;
        }

        // Checking that the height of the remote blockchain is greater than the height of the local one
        let local_chain_length = self.blocks.len() - oldest_common_block_height;
        let remote_chain_length = blocks.len();
        if remote_chain_length <= local_chain_length {
            return false;
        }

        // Saving the part of the local blockchain that will be replaced
        let mut old_local_chain = self.blocks.drain(oldest_common_block_height..).collect();

        // If the genesis block is the oldest common one
        if self.get_height().is_none() {
            // If the new genesis block is valid
            if blocks[0].validate(self, 0) {
                // Replacing the genesis block with the new one
                self.blocks.push(blocks[0].clone());

                // Trying to fast-forward the rest of the new blocks
                let _ = self.fast_forward(&blocks[1..]);
            }
        } else {
            // Trying to fast-forward the new blocks
            let _ = self.fast_forward(blocks);
        }

        // If the blockchain didn't become longer
        let new_local_chain_length = self.blocks.len() - oldest_common_block_height;
        if new_local_chain_length <= local_chain_length {
            // Restoring the changes
            self.blocks.drain(oldest_common_block_height..);
            self.blocks.append(&mut old_local_chain);
            return false;
        }

        true
    }

    /// Tries to rebase the 'Blockchain' with the given 'Block's
    /// if the remote and the local genesis blocks are different.
    /// Thread-unsafe.
    pub fn rebase_root(&mut self, blocks: &[Block]) -> bool {
        // Checking if the blockchain is not empty
        let Some(current_height) = self.get_height() else {
            // Trying to fast-forward
            return self.fast_forward(blocks);
        };

        // Checking that the genesis block can be rebased
        if current_height > MAX_ACCIDENTAL_FORK_HEIGHT {
            return false;
        }

        // Checking that the height of the remote blockchain is greater than the height of the local one
        let local_chain_length = self.blocks.len();
        let remote_chain_length = blocks.len();
        if remote_chain_length <= local_chain_length {
            return false;
        }

        // Saving the part of the local blockchain that will be replaced
        let mut old_local_chain = self.blocks.drain(..).collect();

        // Checking that the new genesis block is valid
        if !blocks[0].validate(self, 0) {
            return false;
        }

        // Replacing the genesis block with the new one
        self.blocks.push(blocks[0].clone());

        // Trying to fast-forward the rest of the new blocks
        let _ = self.fast_forward(&blocks[1..]);

        // If the blockchain didn't become longer
        let new_local_chain_length = self.blocks.len();
        if new_local_chain_length <= local_chain_length {
            // Restoring the changes
            self.blocks.drain(..);
            self.blocks.append(&mut old_local_chain);
            return false;
        }

        true
    }

    /// Handles a network messages.
    /// Thread-safe.
    pub fn handle_message(&mut self, conn_index: usize, msg: Vec<u8>) {
        // If the message has been deserialized correctly
        if let Ok(msg) = deserialize(&msg) {
            // Acquiring read-write access to the blockchain
            self.data_mtx.acquire();

            // Handling the message based on its type
            match msg {
                Message::BlockDownloadRequest(hash) => {
                    self.handle_block_download_request(conn_index, hash)
                }
                Message::BlockDownloadResponse(blocks) => {
                    self.handle_block_download_response(blocks)
                }
                Message::TxDownloadRequest(hash) => {
                    self.handle_tx_download_request(conn_index, hash)
                }
                Message::TxDownloadResponse(txs) => self.handle_tx_download_response(txs),
                Message::BlockBroadcast(block) => self.handle_block_broadcast(block),
                Message::TxBroadcast(tx) => self.handle_tx_broadcast(tx),
            }

            // Releasing read-write access to the blockchain
            self.data_mtx.release();
        }
    }

    /// Handles a 'Block' download request.
    fn handle_block_download_request(&mut self, conn_index: usize, hash: Hash) {
        // Checking if the blockchain is not empty
        if self.get_height().is_none() {
            return;
        }

        let mut blocks = self.get_next_blocks(hash);

        let msg = Message::BlockDownloadResponse(blocks.clone());
        let mut msg = serialize(&msg).unwrap();

        // Making sure that the size of the message is not exceeded
        while msg.len() > MAX_NET_DATA_SIZE {
            let _ = blocks.pop();

            let new_msg = Message::BlockDownloadResponse(blocks.clone());
            msg = serialize(&new_msg).unwrap();
        }

        self.net_driver
            .lock()
            .unwrap()
            .send_custom_message(conn_index, msg);
    }

    /// Handles a 'Block' download response.
    fn handle_block_download_response(&mut self, blocks: Vec<Block>) {
        if blocks.is_empty() {
            return;
        }

        // Trying to fast-forward the downloaded blocks
        if !self.fast_forward(&blocks) {
            // If failed trying to rebase
            if !self.rebase(&blocks) {
                // If failed trying to rebase the genesis block
                let _ = self.rebase_root(&blocks);
            }
        }
    }

    /// Handles a 'Tx' download request.
    fn handle_tx_download_request(&mut self, conn_index: usize, hash: Hash) {
        // Checking if the blockchain is not empty
        if self.get_height().is_none() {
            return;
        }

        // Checking that the requester and the responder have equal blockchains
        if self.blocks.last().unwrap().get_header().hash() != hash {
            return;
        }

        let mut txs: Vec<_> = self.utx_pool.iter().map(|(tx, _)| tx).cloned().collect();

        if txs.is_empty() {
            return;
        }

        let msg = Message::TxDownloadResponse(txs.clone());
        let mut msg = serialize(&msg).unwrap();

        // Making sure that the size of the message is not exceeded
        while msg.len() > MAX_NET_DATA_SIZE {
            let _ = txs.pop();

            let new_msg = Message::TxDownloadResponse(txs.clone());
            msg = serialize(&new_msg).unwrap();
        }

        self.net_driver
            .lock()
            .unwrap()
            .send_custom_message(conn_index, msg);
    }

    /// Handles a 'Tx' download response.
    fn handle_tx_download_response(&mut self, txs: Vec<Tx>) {
        if txs.is_empty() {
            return;
        }

        // Checking if the blockchain is not empty
        let Some(current_height) = self.get_height() else {
            return;
        };

        // For each transaction
        for tx in txs {
            // Checking that it is not in the UTX pool yet and is valid
            if !self.utx_pool.iter().any(|(inner_tx, _)| tx == *inner_tx)
                && tx.validate(self, current_height)
            {
                // Adding the transaction to the UTX pool
                let fee = tx.get_fee(self, current_height).unwrap();
                self.utx_pool.push((tx, fee));
            }
        }
    }

    /// Handles a 'Block' broadcast.
    fn handle_block_broadcast(&mut self, block: Block) {
        // Checking if the blockchain is not empty
        let Some(current_height) = self.get_height() else {
            if self.fast_forward(&[block.clone()]) {
                self.broadcast_block(block);
            }

            return;
        };

        // If the remote and the local blockchains have equal heights
        // there is no need to continue
        let last_block_header = &self.blocks.last().unwrap().header;
        if block.header.prev_hash == last_block_header.prev_hash {
            return;
        }

        // If the broadcast block is the next block
        let last_block_hash = last_block_header.hash();
        if block.header.prev_hash == last_block_hash {
            // If the block is valid
            if block.validate(self, current_height + 1) {
                // Adding the block to the blockchain
                // and rebroadcasting it
                self.blocks.push(block.clone());
                self.broadcast_block(block);
            }
        } else {
            // Requesting to download missing blocks
            let hash = self.get_oldest_accidental_fork_block_hash();
            self.request_block_download(hash);
        }
    }

    /// Handles a 'Tx' broadcast.
    fn handle_tx_broadcast(&mut self, tx: Tx) {
        // Checking if the blockchain is not empty
        let Some(current_height) = self.get_height() else {
            return;
        };

        // Checking that it is not in the UTX pool yet and is valid
        if !self.utx_pool.iter().any(|(inner_tx, _)| tx == *inner_tx)
            && tx.validate(self, current_height)
        {
            // Releasing read-write access to the blockchain
            self.data_mtx.release();

            // Adding the transaction to the UTX pool
            self.add_utx(tx.clone());

            // Acquiring read-write access to the blockchain
            self.data_mtx.acquire();

            // Rebroadcasting the transaction
            self.broadcast_tx(tx);
        }
    }

    /// Requests a 'Block' download.
    fn request_block_download(&mut self, hash: Hash) {
        let msg = Message::BlockDownloadRequest(hash);
        let msg = serialize(&msg).unwrap();
        self.net_driver
            .lock()
            .unwrap()
            .broadcast_custom_message(msg);
    }

    /// Requests a 'Tx' download.
    fn request_tx_download(&mut self, hash: Hash) {
        let msg = Message::TxDownloadRequest(hash);
        let msg = serialize(&msg).unwrap();
        self.net_driver
            .lock()
            .unwrap()
            .broadcast_custom_message(msg);
    }

    /// Broadcasts a 'Block'.
    fn broadcast_block(&mut self, block: Block) {
        let msg = Message::BlockBroadcast(block);
        let msg = serialize(&msg).unwrap();
        self.net_driver
            .lock()
            .unwrap()
            .broadcast_custom_message(msg);
    }

    /// Broadcasts a 'Tx'.
    fn broadcast_tx(&mut self, tx: Tx) {
        let msg = Message::TxBroadcast(tx);
        let msg = serialize(&msg).unwrap();
        self.net_driver
            .lock()
            .unwrap()
            .broadcast_custom_message(msg);
    }
}

impl Block {
    /// Returns a newly mined 'Block'.
    fn mine(prev_hash: &Hash, difficulty: f32, mut txs: Vec<Tx>) -> Self {
        Block {
            header: BlockHeader::mine(prev_hash, difficulty, &mut txs),
            txs,
        }
    }

    /// Validates the 'Block'.
    /// # Arguments
    /// * 'blockchain' - The 'Blockchain' instance which the 'Block' is part of.
    /// * 'height' - The height of the 'Block' in the 'Blockchain'.
    fn validate(&self, blockchain: &Blockchain, height: u32) -> bool {
        // Validating the header
        if !self.header.validate(blockchain, &self.txs, height) {
            return false;
        }

        // Checking if the transactions are not empty
        if self.txs.is_empty() {
            return false;
        }

        // Checking if the maximum size is not exceeded
        if self.get_size() > MAX_BLOCK_SIZE {
            return false;
        }

        // Validating the coinbase transaction
        if !blockchain.validate_coinbase_tx(&self.txs[0], &self.txs[1..], height) {
            return false;
        }

        // Validating all the transactions except for the coinbase one
        for (index, tx) in self.txs.iter().enumerate() {
            if index > 0 && !tx.validate(blockchain, height) {
                return false;
            }
        }

        true
    }

    /// Returns the size of the 'Block'.
    fn get_size(&self) -> usize {
        let mut size = size_of::<BlockHeader>();
        for tx in self.txs.iter() {
            size += tx.get_size();
        }
        size
    }

    /// Returns the 'BlockHeader' of the 'Block'.
    pub fn get_header(&self) -> &BlockHeader {
        &self.header
    }

    /// Returns 'Tx's in the 'Block'.
    pub fn get_txs(&self) -> &[Tx] {
        &self.txs
    }
}

impl BlockHeader {
    /// Returns a newly mined 'BlockHeader'.
    fn mine(prev_hash: &Hash, difficulty: f32, txs: &mut [Tx]) -> Self {
        // Closure to get current timestamp
        let get_timestamp = || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        };

        // Preparing a header of the block
        let mut header = BlockHeader {
            version: BLOCK_VERSION,
            prev_hash: *prev_hash,
            merkle_root: merkle_root(txs),
            timestamp: get_timestamp(),
            difficulty,
            nonce: 0,
        };

        // While hash of the block is not valid
        while !header.validate_hash() {
            // Incrementing nonce until it overflows
            header.nonce = header.nonce.wrapping_add(1);
            if header.nonce == 0 {
                // Incrementing extra nonce (input of the coinbase transaction) until it overflows
                let extra_nonce = &mut txs[0].inputs[0].output_ref.output_index;
                *extra_nonce = extra_nonce.wrapping_add(1);
                if *extra_nonce == 0 {
                    // Updating timestamp
                    header.timestamp = get_timestamp();
                }
                // Updating Merkle tree root of the transactions
                header.merkle_root = merkle_root(txs);
            }
        }

        header
    }

    /// Returns a 'Hash' of the 'BlockHeader'.
    pub fn hash(&self) -> Hash {
        let mut hasher = SHA256::new();
        hasher.update(self.version.to_be_bytes());
        hasher.update(*self.prev_hash);
        hasher.update(*self.merkle_root);
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.difficulty.to_be_bytes());
        hasher.update(self.nonce.to_be_bytes());
        let hash = hasher.finalize();
        SHA256::hash(hash.as_slice()).into()
    }

    /// Validates the 'BlockHeader'.
    /// # Arguments
    /// * 'blockchain' - The 'Blockchain' instance which the 'Block' is part of.
    /// * 'txs' - 'Tx's in the 'Block'.
    /// * 'height' - The height of the 'Block' in the 'Blockchain'.
    fn validate(&self, blockchain: &Blockchain, txs: &[Tx], height: u32) -> bool {
        // Validating the hash
        if !self.validate_hash() {
            return false;
        }

        // If it is a genesis block
        if height == 0 {
            // Validating previous block's hash in the header
            if self.prev_hash != IMPOSSIBLE_BLOCK_HASH {
                return false;
            }

            return true;
        }

        let prev_block_header = &blockchain.blocks[height as usize - 1].header;

        // Validating previous block's hash in the header
        if self.prev_hash != prev_block_header.hash() {
            return false;
        }

        // Validating the Merkle tree root
        if self.merkle_root != merkle_root(txs) {
            return false;
        }

        // Validating the timestamp
        if self.timestamp > prev_block_header.timestamp {
            if self.timestamp - prev_block_header.timestamp > MAX_TIMESTAMP_DELTA {
                return false;
            }
        } else if prev_block_header.timestamp - self.timestamp > MAX_TIMESTAMP_DELTA {
            return false;
        }

        // Validating the difficulty
        if self.difficulty - blockchain.calculate_difficulty(height) > 0.0000001f32 {
            return false;
        }

        true
    }

    /// Validates the 'Hash' of the 'BlockHeader'.
    fn validate_hash(&self) -> bool {
        let hash = BigUint::from_bytes_be(&*self.hash());

        let target = BlockHeader::difficulty_to_target(self.difficulty);

        // If hash is equal to or less then the difficulty target
        hash <= target
    }

    /// Returns the difficulty target corresponding to the given difficulty.
    fn difficulty_to_target(difficulty: f32) -> BigUint {
        let mut max_target = [0u8; 32];

        // The first two bytes are exponent
        let exponent = 33 - (MAX_DIFFICULTY_TARGET >> 24) as usize;

        // The next six bytes are mantissa
        max_target[exponent] = MAX_DIFFICULTY_TARGET as u8;
        max_target[exponent + 1] = (MAX_DIFFICULTY_TARGET >> 8) as u8;
        max_target[exponent + 2] = (MAX_DIFFICULTY_TARGET >> 16) as u8;

        let mut target = BigUint::from_bytes_be(&max_target);

        const BIG_NUMBER: u128 = 10_000_000;
        target.mul_assign(BIG_NUMBER);
        target.div_assign((difficulty * BIG_NUMBER as f32) as u128);

        target
    }
}
