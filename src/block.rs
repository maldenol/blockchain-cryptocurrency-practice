//! Blockchain and blocks.

use std::mem::size_of;
use std::ops::{DivAssign, MulAssign};
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicBool, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use bincode::{deserialize, serialize};
use hmac_sha256::Hash as SHA256;
use num_bigint::BigUint;
use serde_derive::{Deserialize, Serialize};

use obj2str::Obj2Str;
use obj2str_derive::Obj2Str;

use crate::consts::*;
use crate::database::BlockchainDB;
use crate::digsig::PublicKey;
use crate::hash::Hash;
use crate::merkle::merkle_root;
use crate::netdriver::{Connection, NetDriver};
use crate::tx::*;

const IMPOSSIBLE_BLOCK_HASH: Hash = Hash([255u8; 32]);

/// Blockchain.
pub struct Blockchain {
    db: Mutex<BlockchainDB>,
    blocks_received: AtomicBool,
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

/// The type of the UTXO pool.
pub type UTXOPool = Vec<TxOutputRef>;

/// The type of the UTX pool.
/// 'Tx' is the 'Tx' itself and 'u64' is its fee.
/// They are stored sorted by fees in descending order.
pub type UTXPool = Vec<(Tx, u64)>;

impl Blockchain {
    /// Returns a newly created 'Blockchain'.
    pub fn new(db_path: String) -> Self {
        Blockchain {
            db: Mutex::new(BlockchainDB::new(db_path)),
            blocks_received: AtomicBool::new(false),
        }
    }

    /// Mines a 'Block'.
    /// Returns whether it should be restarted.
    pub fn mine(
        &mut self,
        should_mine: &AtomicBool,
        public_key: PublicKey,
        net_driver: &mut NetDriver,
    ) -> bool {
        let prev_hash;
        let difficulty;
        let txs;

        {
            let mut db = self.db.lock().unwrap();

            // If there is no blocks yet, mine the genesis one
            let Some(current_height) = db.get_height() else {
                let block = Block::mine(
                    &IMPOSSIBLE_BLOCK_HASH,
                    Blockchain::calculate_difficulty(&db, 0),
                    vec![Blockchain::generate_coinbase_tx(&public_key, 0, 0)],
                    should_mine,
                );
                Blockchain::add_block(&mut db, block);

                return true;
            };

            // Choosing transactions with the biggest fees
            let (mut inner_txs, fees) = Blockchain::choose_txs_with_fee(&db);

            // Generating a coinbase transaction
            let coinbase_tx = Blockchain::generate_coinbase_tx(&public_key, fees, current_height);
            inner_txs.insert(0, coinbase_tx);

            // Getting the hash of the previous block and a new difficulty
            prev_hash = db.get_last_block().unwrap().header.hash();
            difficulty = Blockchain::calculate_difficulty(&db, current_height + 1);

            txs = inner_txs;
        }

        // Mining a block
        let block = Block::mine(&prev_hash, difficulty, txs, should_mine);

        // If should not mine
        if !should_mine.load(Ordering::Relaxed) {
            return false;
        }

        // If new blocks were received
        if self.blocks_received.fetch_and(false, Ordering::Relaxed) {
            return true;
        }

        {
            // It is crucial to lock 'connections' before 'db' to avoid deadlock.
            let mut connections = net_driver.get_connections_mut();
            let mut db = self.db.lock().unwrap();

            // Checking that the block is still valid (no blocks were added from another threads)
            if !block.validate(&db, db.get_height().unwrap() + 1) {
                return true;
            }

            // Adding the block to the blockchain
            Blockchain::add_block(&mut db, block.clone());

            // Broadcasting the block
            Blockchain::broadcast_block(&mut connections, block);
        }

        true
    }

    /// Adds a 'Block' to the end of the 'Blockchain'.
    fn add_block(db: &mut BlockchainDB, block: Block) {
        // For each transaction in the block
        for (index, tx) in block.txs.iter().enumerate() {
            // If it is not a coinbase transaction
            if index > 0 {
                // Removing recorded transactions from the UTX pool
                if let Some(index) = db.get_utx_pool().iter().position(|(utx, _)| *utx == *tx) {
                    db.get_utx_pool_mut().remove(index);
                }

                // Removing used outputs from the UTXO pool
                for input in tx.inputs.iter() {
                    let index = db
                        .get_utxo_pool()
                        .iter()
                        .position(|utxo| *utxo == input.output_ref)
                        .unwrap();
                    db.get_utxo_pool_mut().remove(index);
                }
            }

            // Adding outputs to the UTXO pool
            let hash = tx.hash();
            for output_index in 0..tx.outputs.len() {
                db.get_utxo_pool_mut().push(TxOutputRef {
                    tx_hash: hash,
                    output_index: output_index as u32,
                });
            }
        }

        // Saving the UTXO and the UTX pools
        db.save_utxo_pool();
        db.save_utx_pool();

        // Adding the block to the blockchain
        db.add_block(block);
    }

    /// Removes and returns the last 'Block' from the 'Blockchain'.
    fn remove_block(db: &mut BlockchainDB) -> Block {
        // Removing the block from the blockchain
        let block = db.remove_block().unwrap();

        let mut new_utxs = Vec::new();

        // For each transaction in the block
        for (index, tx) in block.txs.iter().enumerate() {
            // If it is not a coinbase transaction
            if index > 0 {
                // Remembering unrecorded transactions
                new_utxs.push(tx.clone());

                // Adding used outputs to the UTXO pool
                for input in tx.inputs.iter() {
                    db.get_utxo_pool_mut().push(input.output_ref.clone());
                }
            }

            // Removing new outputs from the UTXO pool
            let hash = tx.hash();
            for output_index in 0..tx.outputs.len() {
                let index = db
                    .get_utxo_pool()
                    .iter()
                    .position(|utxo| {
                        *utxo
                            == TxOutputRef {
                                tx_hash: hash,
                                output_index: output_index as u32,
                            }
                    })
                    .unwrap();
                db.get_utxo_pool_mut().remove(index);
            }
        }

        // Saving the UTXO pool
        db.save_utxo_pool();

        // Adding unrecorded transactions to the UTX pool
        for utx in new_utxs {
            Blockchain::_add_utx(db, None, utx);
        }

        // Saving the UTX pool
        db.save_utx_pool();

        block
    }

    /// Returns the difficulty of the 'Block' based on its height.
    fn calculate_difficulty(db: &BlockchainDB, height: u32) -> f32 {
        if height == 0 {
            return 1f32;
        }

        let last_block = db.get_last_block().unwrap();
        let difficulty = last_block.header.difficulty;

        // If the time has come
        if height % DIFFICULTY_ADJUSTMENT_PERIOD == 0 {
            // Updating the difficulty
            let first_block = db.get_block(height - DIFFICULTY_ADJUSTMENT_PERIOD).unwrap();

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
    fn generate_coinbase_tx(public_key: &PublicKey, fees: u64, height: u32) -> Tx {
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
                public_key: public_key.clone(),
            }],
        }
    }

    /// Validates the coinbase 'Tx'
    /// based on the other transactions in the 'Block' and the height of the 'Block'.
    fn validate_coinbase_tx(
        db: &BlockchainDB,
        coinbase_tx: &Tx,
        other_txs: &[Tx],
        height: u32,
    ) -> bool {
        // Checking if the inputs and the outputs are not empty
        if coinbase_tx.inputs.is_empty() || coinbase_tx.outputs.is_empty() {
            return false;
        }

        // Calculating fees of the rest transaction of the block
        let mut fees = 0;
        for tx in other_txs {
            if let Some(fee) = tx.get_fee(db, height) {
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

    /// Returns a tuple of 'Tx's with the biggest fees that can fit in a single 'Block'
    /// and the sum of these fees.
    fn choose_txs_with_fee(db: &BlockchainDB) -> (Vec<Tx>, u64) {
        // Checking if the blockchain is not empty
        let Some(current_height) = db.get_height() else {
            return (Vec::new(), 0);
        };

        let mut txs = Vec::new();
        let mut fees = 0u64;

        let mut mem_available = MAX_BLOCK_SIZE - size_of::<BlockHeader>();

        // For each transaction in the UTX pool
        for (tx, fee) in db.get_utx_pool() {
            // Checking for available memory in the block
            let (new_mem_available, not_available) = mem_available.overflowing_sub(tx.get_size());
            if not_available {
                break;
            }
            mem_available = new_mem_available;

            // Validating the transaction
            if !tx.validate(db, current_height) {
                continue;
            }

            // Adding the transaction and its fee
            txs.push(tx.clone());
            fees += fee;
        }

        (txs, fees)
    }

    /// Returns a UTXO pool calculated from the beginning based on the height.
    fn calculate_utxo_pool(db: &BlockchainDB, height: u32) -> Vec<TxOutputRef> {
        // Checking if the blockchain is not empty
        let Some(current_height) = db.get_height() else {
            return Vec::new();
        };

        // Checking if the height is not greater than the current one
        if height > current_height {
            return Vec::new();
        }

        let mut utxo_pool = Vec::new();

        // For each block from the beginning of the blockchain to the specific height
        for block in db.get_block_range(..=height, false) {
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
    fn calculate_utxo_pool_rev(db: &BlockchainDB, height: u32) -> Vec<TxOutputRef> {
        // Checking if the blockchain is not empty
        let Some(current_height) = db.get_height() else {
            return Vec::new();
        };

        // Checking if the height is not greater than the current one
        if height > current_height {
            return Vec::new();
        }

        let mut utxo_pool = db.get_utxo_pool().clone();

        // For each block from the end of the blockchain to the specific height
        for block in db.get_block_range((height + 1)..=current_height, true) {
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
    fn _add_utx(db: &mut BlockchainDB, connections: Option<&mut [Connection]>, tx: Tx) {
        // Checking if the blockchain is not empty
        let Some(current_height) = db.get_height() else {
            return;
        };

        let Some(fee) = tx.get_fee(db, current_height) else {
            return;
        };

        // Inserting the transaction to the UTX pool
        // so that all the transactions are sorted in ascending order by fee
        let mut index = 0;
        for (_, utx_fee) in db.get_utx_pool().iter() {
            if fee >= *utx_fee {
                index += 1;
            } else {
                break;
            }
        }

        // Adding the UTX to the UTX pool and saving it
        db.get_utx_pool_mut().insert(index, (tx.clone(), fee));
        db.save_utx_pool();

        if let Some(connections) = connections {
            // Broadcasting the transaction
            Blockchain::broadcast_tx(connections, tx);
        }
    }

    /// Public variant of the private method.
    pub fn add_utx(&mut self, tx: Tx, net_driver: &mut NetDriver) {
        // It is crucial to lock 'connections' before 'db' to avoid deadlock.
        let mut connections = net_driver.get_connections_mut();
        let mut db = self.db.lock().unwrap();

        Blockchain::_add_utx(&mut db, Some(&mut connections), tx);
    }

    /// Returns the 'Block' with specific height in the 'Blockchain'.
    pub fn get_block(&self, height: u32) -> Option<Block> {
        self.db.lock().unwrap().get_block(height)
    }

    /// Returns the height of the last 'Block' in the 'Blockchain'.
    pub fn get_height(&self) -> Option<u32> {
        self.db.lock().unwrap().get_height()
    }

    /// Returns the UTX pool of the 'Blockchain'.
    pub fn get_utx_pool(&self) -> UTXPool {
        self.db.lock().unwrap().get_utx_pool().clone()
    }

    /// Returns the UTXO pool of the 'Blockchain'.
    pub fn get_utxo_pool(&self) -> UTXOPool {
        self.db.lock().unwrap().get_utxo_pool().clone()
    }

    /// Returns the 'BlockchainDB' of the 'Blockchain'.
    pub fn get_db_mut(&mut self) -> MutexGuard<BlockchainDB> {
        self.db.lock().unwrap()
    }

    /// Returns the 'Tx' found in the 'Blockchain' by its 'Hash' with the specified height.
    /// # Arguments
    /// * 'hash' - The 'Hash' of the 'Tx.
    /// * 'height' - Must be not less than the height of the 'Block' containing the 'Tx'.
    pub fn get_tx(db: &BlockchainDB, hash: &Hash, height: u32) -> Option<Tx> {
        // Searching for the transaction in the blockchain starting from the last block
        // with specific height
        for block in db.get_block_range(0..=height, true) {
            // For each transaction in the block
            for tx in block.txs.iter() {
                // Comparing by hashes
                if tx.hash() == *hash {
                    return Some(tx.clone());
                }
            }
        }

        None
    }

    /// Returns the 'TxOutput' found in the 'Blockchain' by its 'TxOutputRef' with the specified height.
    /// # Arguments
    /// * 'output_ref' - 'TxOutputRef' referencing the 'TxOutput'.
    /// * 'height' - Must be not less than the height of the 'Block' containing the 'Tx'.
    pub fn get_tx_output(
        db: &BlockchainDB,
        output_ref: &TxOutputRef,
        height: u32,
    ) -> Option<TxOutput> {
        let tx = Blockchain::get_tx(db, &output_ref.tx_hash, height)?;
        tx.outputs.get(output_ref.output_index as usize).cloned()
    }

    /// Returns whether the 'TxOutput' is an UTXO in the 'Blockchain' with the specified height.
    /// # Arguments
    /// * 'output_ref' - 'TxOutputRef' referencing the 'TxOutput'.
    /// * 'height' - Must be not less than the height of the 'Block' containing the 'Tx'.
    pub fn is_utxo(db: &BlockchainDB, output_ref: &TxOutputRef, height: u32) -> bool {
        // Checking if the blockchain is not empty
        let Some(current_height) = db.get_height() else {
            return false;
        };

        // If the height is greater or equals to the current one
        if height >= current_height {
            // Checking if the output is an UTXO using the current UTXO pool
            db.get_utxo_pool().contains(output_ref)
        } else if height <= current_height / 2 {
            // Checking if the output is an UTXO using the calculated from the beginning UTXO pool
            Blockchain::calculate_utxo_pool(db, height).contains(output_ref)
        } else {
            // Checking if the output is an UTXO using the calculated from the end UTXO pool
            Blockchain::calculate_utxo_pool_rev(db, height).contains(output_ref)
        }
    }

    /// Returns the first 'Block' with specific 'Hash' and all the 'Block's after him.
    /// If there is no 'Block' with such 'Hash'
    /// it returns 'MAX_BLOCKS_PER_DOWNLOAD' of 'Block's from the beginning.
    fn get_next_blocks(db: &BlockchainDB, hash: Hash) -> Vec<Block> {
        // Checking if the blockchain is not empty
        if db.get_height().is_none() {
            return Vec::new();
        }

        // If there is a block with such hash
        if hash != IMPOSSIBLE_BLOCK_HASH {
            if let Some(height) = db.find_block_rev(|block| block.header.hash() == hash) {
                // Returning that block and all the next ones
                return db.get_block_range(height.., false);
            }
        }

        // Returning the first several blocks
        db.get_block_range(..MAX_BLOCKS_PER_DOWNLOAD, false)
    }

    /// Returns the 'Hash' of the 'Block'
    /// that is located 'MAX_ACCIDENTAL_FORK_HEIGHT' 'Block's before the last one.
    /// If there are no 'Block's at all it returns the 'IMPOSSIBLE_BLOCK_HASH'.
    pub fn get_oldest_accidental_fork_block_hash(db: &BlockchainDB) -> Hash {
        // Checking if the blockchain is not empty
        let Some(current_height) = db.get_height() else {
            // Returning the impossible block hash
            return IMPOSSIBLE_BLOCK_HASH;
        };

        let height = current_height.saturating_sub(MAX_ACCIDENTAL_FORK_HEIGHT);
        db.get_block(height).unwrap().header.hash()
    }

    /// Tries to fast-forward the 'Blockchain' with the given 'Block's.
    fn fast_forward(db: &mut BlockchainDB, blocks: &[Block]) -> bool {
        let mut blocks_updated = false;

        // For each block
        for block in blocks.iter() {
            // Checking if the blockchain is not empty
            let Some(current_height) = db.get_height() else {
                // If the block is valid
                if block.validate(db, 0) {
                    // Adding the block to the blockchain
                    Blockchain::add_block(db, block.clone());
                    blocks_updated = true;
                } else {
                    // Finishing because next blocks are invalid as well
                    break;
                }

                continue;
            };

            // If the block is the next one in the blockchain
            // (will be valid if placed after the current last one)
            let last_block_hash = db.get_last_block().unwrap().header.hash();
            if block.header.prev_hash == last_block_hash {
                // If the block is valid
                if block.validate(db, current_height + 1) {
                    // Adding the block to the blockchain
                    Blockchain::add_block(db, block.clone());
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
    fn rebase(db: &mut BlockchainDB, blocks: &[Block]) -> bool {
        // Checking if the blockchain is not empty
        let Some(current_height) = db.get_height() else {
            // Trying to fast-forward
            return Blockchain::fast_forward(db, blocks);
        };

        // Finding the oldest block that is common for the local and the remote blockchains
        let Some(oldest_common_block_height) =
            db.find_block(|local_block| local_block.header.hash() == blocks[0].header.hash())
        else {
            return false;
        };

        // Checking that it is not an intentional fork
        let Some(latest_common_block_height) = db.find_block_rev(|local_block| {
            blocks
                .iter()
                .any(|remote_block| local_block.header.hash() == remote_block.header.hash())
        }) else {
            return false;
        };
        let fork_length = current_height - latest_common_block_height;
        if fork_length > MAX_ACCIDENTAL_FORK_HEIGHT {
            return false;
        }

        // Checking that the height of the remote blockchain is greater than the height of the local one
        let local_chain_length = current_height + 1 - oldest_common_block_height;
        let remote_chain_length = blocks.len() as u32;
        if remote_chain_length <= local_chain_length {
            return false;
        }

        // Saving the part of the local blockchain that will be replaced
        let mut old_local_chain = Vec::new();
        for _ in oldest_common_block_height..=current_height {
            old_local_chain.push(Blockchain::remove_block(db));
        }

        // If the genesis block is the oldest common one
        if db.get_height().is_none() {
            // If the new genesis block is valid
            if blocks[0].validate(db, 0) {
                // Replacing the genesis block with the new one
                Blockchain::add_block(db, blocks[0].clone());

                // Trying to fast-forward the rest of the new blocks
                let _ = Blockchain::fast_forward(db, &blocks[1..]);
            }
        } else {
            // Trying to fast-forward the new blocks
            let _ = Blockchain::fast_forward(db, blocks);
        }

        // If the blockchain didn't become longer
        let current_height = db.get_height().unwrap();
        let new_local_chain_length = current_height + 1 - oldest_common_block_height;
        if new_local_chain_length <= local_chain_length {
            // Restoring the changes
            for _ in oldest_common_block_height..=current_height {
                let _ = Blockchain::remove_block(db);
            }

            for block in old_local_chain {
                Blockchain::add_block(db, block);
            }

            return false;
        }

        true
    }

    /// Tries to rebase the 'Blockchain' with the given 'Block's
    /// if the remote and the local genesis blocks are different.
    fn rebase_root(db: &mut BlockchainDB, blocks: &[Block]) -> bool {
        // Checking if the blockchain is not empty
        let Some(current_height) = db.get_height() else {
            // Trying to fast-forward
            return Blockchain::fast_forward(db, blocks);
        };

        // Checking that the genesis block can be rebased
        if current_height > MAX_ACCIDENTAL_FORK_HEIGHT {
            return false;
        }

        // Checking that the height of the remote blockchain is greater than the height of the local one
        let local_chain_length = current_height + 1;
        let remote_chain_length = blocks.len() as u32;
        if remote_chain_length <= local_chain_length {
            return false;
        }

        // Saving the part of the local blockchain that will be replaced
        let mut old_local_chain = Vec::new();
        for _ in 0..=current_height {
            old_local_chain.push(Blockchain::remove_block(db));
        }

        // Checking that the new genesis block is valid
        if !blocks[0].validate(db, 0) {
            return false;
        }

        // Replacing the genesis block with the new one
        Blockchain::add_block(db, blocks[0].clone());

        // Trying to fast-forward the rest of the new blocks
        let _ = Blockchain::fast_forward(db, &blocks[1..]);

        // If the blockchain didn't become longer
        let current_height = db.get_height().unwrap();
        let new_local_chain_length = current_height + 1;
        if new_local_chain_length <= local_chain_length {
            // Restoring the changes
            for _ in 0..=current_height {
                let _ = Blockchain::remove_block(db);
            }

            for block in old_local_chain {
                Blockchain::add_block(db, block);
            }

            return false;
        }

        true
    }

    /// Handles a network messages.
    pub fn handle_message(
        &mut self,
        connections: &mut [Connection],
        conn_index: usize,
        msg: Vec<u8>,
    ) {
        // If the message has been deserialized correctly
        if let Ok(msg) = deserialize(&msg) {
            // It is crucial to lock 'connections' before 'db' to avoid deadlock
            // because here 'connections' are locked before 'db' already.
            let mut db = self.db.lock().unwrap();
            let blocks_received = &self.blocks_received;

            // Handling the message based on its type
            match msg {
                Message::BlockDownloadRequest(hash) => {
                    Blockchain::handle_block_download_request(&db, connections, conn_index, hash)
                }
                Message::BlockDownloadResponse(blocks) => {
                    Blockchain::handle_block_download_response(&mut db, blocks, blocks_received)
                }
                Message::TxDownloadRequest(hash) => {
                    Blockchain::handle_tx_download_request(&db, connections, conn_index, hash)
                }
                Message::TxDownloadResponse(txs) => {
                    Blockchain::handle_tx_download_response(&mut db, txs)
                }
                Message::BlockBroadcast(block) => {
                    Blockchain::handle_block_broadcast(&mut db, connections, block, blocks_received)
                }
                Message::TxBroadcast(tx) => {
                    Blockchain::handle_tx_broadcast(&mut db, connections, tx)
                }
            }
        }
    }

    /// Handles a 'Block' download request.
    fn handle_block_download_request(
        db: &BlockchainDB,
        connections: &mut [Connection],
        conn_index: usize,
        hash: Hash,
    ) {
        // Checking if the blockchain is not empty
        if db.get_height().is_none() {
            return;
        }

        let mut blocks = Blockchain::get_next_blocks(db, hash);

        let msg = Message::BlockDownloadResponse(blocks.clone());
        let mut msg = serialize(&msg).unwrap();

        // Making sure that the size of the message is not exceeded
        while msg.len() > MAX_NET_DATA_SIZE {
            let _ = blocks.pop();

            let new_msg = Message::BlockDownloadResponse(blocks.clone());
            msg = serialize(&new_msg).unwrap();
        }

        NetDriver::send_custom_message(connections, conn_index, msg);
    }

    /// Handles a 'Block' download response.
    fn handle_block_download_response(
        db: &mut BlockchainDB,
        blocks: Vec<Block>,
        blocks_received: &AtomicBool,
    ) {
        if blocks.is_empty() {
            return;
        }

        // Trying to fast-forward the downloaded blocks
        if !Blockchain::fast_forward(db, &blocks) {
            // If failed trying to rebase
            if !Blockchain::rebase(db, &blocks) {
                // If failed trying to rebase the genesis block
                if Blockchain::rebase_root(db, &blocks) {
                    return;
                }
            }
        }

        // Signaling that blocks were received and the blockchain has been updated
        blocks_received.store(true, Ordering::Relaxed);
    }

    /// Handles a 'Tx' download request.
    fn handle_tx_download_request(
        db: &BlockchainDB,
        connections: &mut [Connection],
        conn_index: usize,
        hash: Hash,
    ) {
        // Checking if the blockchain is not empty
        if db.get_height().is_none() {
            return;
        }

        // Checking that the requester and the responder have equal blockchains
        if db.get_last_block().unwrap().get_header().hash() != hash {
            return;
        }

        let mut txs: Vec<_> = db
            .get_utx_pool()
            .iter()
            .map(|(tx, _)| tx)
            .cloned()
            .collect();

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

        NetDriver::send_custom_message(connections, conn_index, msg);
    }

    /// Handles a 'Tx' download response.
    fn handle_tx_download_response(db: &mut BlockchainDB, txs: Vec<Tx>) {
        if txs.is_empty() {
            return;
        }

        // Checking if the blockchain is not empty
        let Some(current_height) = db.get_height() else {
            return;
        };

        // For each transaction
        for tx in txs {
            // Checking that it is not in the UTX pool yet and is valid
            if !db
                .get_utx_pool()
                .iter()
                .any(|(inner_tx, _)| tx == *inner_tx)
                && tx.validate(db, current_height)
            {
                // Adding the transaction to the UTX pool
                let fee = tx.get_fee(db, current_height).unwrap();
                db.get_utx_pool_mut().push((tx, fee));
            }
        }

        // Saving the UTX pool
        db.save_utx_pool();
    }

    /// Handles a 'Block' broadcast.
    fn handle_block_broadcast(
        db: &mut BlockchainDB,
        connections: &mut [Connection],
        block: Block,
        blocks_received: &AtomicBool,
    ) {
        // Checking if the blockchain is not empty
        let Some(current_height) = db.get_height() else {
            if Blockchain::fast_forward(db, &[block.clone()]) {
                Blockchain::broadcast_block(connections, block);

                // Signaling that a block was received and the blockchain has been updated
                blocks_received.store(true, Ordering::Relaxed);
            }

            return;
        };

        // If the remote and the local blockchains have equal heights
        // there is no need to continue
        let last_block_header = db.get_last_block().unwrap().header;
        if block.header.prev_hash == last_block_header.prev_hash {
            return;
        }

        // If the broadcast block is the next block
        let last_block_hash = last_block_header.hash();
        if block.header.prev_hash == last_block_hash {
            // If the block is valid
            if block.validate(db, current_height + 1) {
                // Adding the block to the blockchain
                // and rebroadcasting it
                Blockchain::add_block(db, block.clone());
                Blockchain::broadcast_block(connections, block);

                // Signaling that a block was received and the blockchain has been updated
                blocks_received.store(true, Ordering::Relaxed);
            }
        } else {
            // Requesting to download missing blocks
            let hash = Blockchain::get_oldest_accidental_fork_block_hash(db);
            Blockchain::request_block_download(connections, hash);
        }
    }

    /// Handles a 'Tx' broadcast.
    fn handle_tx_broadcast(db: &mut BlockchainDB, connections: &mut [Connection], tx: Tx) {
        // Checking if the blockchain is not empty
        let Some(current_height) = db.get_height() else {
            return;
        };

        // Checking that it is not in the UTX pool yet and is valid
        if !db
            .get_utx_pool()
            .iter()
            .any(|(inner_tx, _)| tx == *inner_tx)
            && tx.validate(db, current_height)
        {
            // Adding the transaction to the UTX pool
            Blockchain::_add_utx(db, Some(connections), tx.clone());

            // Rebroadcasting the transaction
            Blockchain::broadcast_tx(connections, tx);
        }
    }

    /// Requests a 'Block' download.
    pub fn request_block_download(connections: &mut [Connection], hash: Hash) {
        let msg = Message::BlockDownloadRequest(hash);
        let msg = serialize(&msg).unwrap();
        NetDriver::broadcast_custom_message(connections, msg);
    }

    /// Requests a 'Tx' download.
    pub fn request_tx_download(connections: &mut [Connection], hash: Hash) {
        let msg = Message::TxDownloadRequest(hash);
        let msg = serialize(&msg).unwrap();
        NetDriver::broadcast_custom_message(connections, msg);
    }

    /// Broadcasts a 'Block'.
    fn broadcast_block(connections: &mut [Connection], block: Block) {
        let msg = Message::BlockBroadcast(block);
        let msg = serialize(&msg).unwrap();
        NetDriver::broadcast_custom_message(connections, msg);
    }

    /// Broadcasts a 'Tx'.
    fn broadcast_tx(connections: &mut [Connection], tx: Tx) {
        let msg = Message::TxBroadcast(tx);
        let msg = serialize(&msg).unwrap();
        NetDriver::broadcast_custom_message(connections, msg);
    }
}

unsafe impl Send for Blockchain {}

unsafe impl Sync for Blockchain {}

impl Block {
    /// Returns a newly mined 'Block'.
    fn mine(prev_hash: &Hash, difficulty: f32, mut txs: Vec<Tx>, should_mine: &AtomicBool) -> Self {
        Block {
            header: BlockHeader::mine(prev_hash, difficulty, &mut txs, should_mine),
            txs,
        }
    }

    /// Validates the 'Block'.
    /// # Arguments
    /// * 'blockchain' - The 'Blockchain' instance which the 'Block' is part of.
    /// * 'height' - The height of the 'Block' in the 'Blockchain'.
    fn validate(&self, db: &BlockchainDB, height: u32) -> bool {
        // Validating the header
        if !self.header.validate(db, &self.txs, height) {
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
        if !Blockchain::validate_coinbase_tx(db, &self.txs[0], &self.txs[1..], height) {
            return false;
        }

        // Validating all the transactions except for the coinbase one
        for (index, tx) in self.txs.iter().enumerate() {
            if index > 0 && !tx.validate(db, height) {
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
    fn mine(prev_hash: &Hash, difficulty: f32, txs: &mut [Tx], should_mine: &AtomicBool) -> Self {
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

        // While hash of the block is not valid and still should mine
        while !header.validate_hash() && should_mine.load(Ordering::Relaxed) {
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
    fn validate(&self, db: &BlockchainDB, txs: &[Tx], height: u32) -> bool {
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

        let prev_block_header = db.get_block(height - 1).unwrap().header;

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
        if self.difficulty - Blockchain::calculate_difficulty(db, height) > 0.0000001f32 {
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
