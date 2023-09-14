use std::mem::size_of;
use std::ops::{DivAssign, MulAssign};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac_sha256::Hash as SHA256;
use num_bigint::BigUint;

use obj2str::Obj2Str;
use obj2str_derive::Obj2Str;

use crate::consts::*;
use crate::hash::Hash;
use crate::merkle::merkle_root;
use crate::tx::*;

const IMPOSSIBLE_BLOCK_HASH: Hash = Hash([255u8; 32]);

#[derive(Obj2Str)]
pub struct Blockchain {
    blocks: Vec<Block>,
    utx_pool: Vec<Tx>,
    utxo_pool: Vec<TxOutputRef>,
}

#[derive(Obj2Str)]
pub struct Block {
    header: BlockHeader,
    txs: Vec<Tx>,
}

#[derive(Obj2Str)]
pub struct BlockHeader {
    version: u32,
    prev_hash: Hash,
    merkle_root: Hash,
    timestamp: u64,
    difficulty: f32,
    nonce: u32,
}

impl Blockchain {
    pub fn new() -> Self {
        Blockchain {
            blocks: Vec::new(),
            utx_pool: Vec::new(),
            utxo_pool: Vec::new(),
        }
    }

    pub fn mine(&mut self) {
        // If there is no blocks yet, mine the genesis one
        let Some(current_height) = self.get_height() else {
            self.blocks.push(Block::mine(
                &IMPOSSIBLE_BLOCK_HASH,
                self.calculate_difficulty(0),
                vec![Blockchain::generate_coinbase_tx(0, 0)],
            ));
            return;
        };

        // Choosing transactions with the biggest fees
        let (mut txs, fees, used_utxo) = self.choose_txs_with_fee();

        // Generating a coinbase transaction
        let coinbase_tx = Blockchain::generate_coinbase_tx(fees, current_height);
        txs.insert(0, coinbase_tx);

        // Mining a block
        let prev_hash = self.blocks.last().unwrap().header.hash();
        let difficulty = self.calculate_difficulty(current_height + 1);
        let block = Block::mine(&prev_hash, difficulty, txs);

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
        self.blocks.push(block);
    }

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

    fn calculate_block_reward(height: u32) -> u64 {
        MINING_REWARD / 2u64.pow(height / HALVING_PERIOD)
    }

    fn generate_coinbase_tx(fees: u64, height: u32) -> Tx {
        let block_reward = Blockchain::calculate_block_reward(height);

        Tx {
            version: TX_VERSION,
            inputs: vec![TxInput {
                output_ref: TxOutputRef {
                    tx_hash: Hash([0u8; 32]),
                    output_index: 0,
                },
            }],
            outputs: vec![TxOutput {
                amount: block_reward + fees,
            }],
        }
    }

    fn choose_txs_with_fee(&mut self) -> (Vec<Tx>, u64, Vec<usize>) {
        // Checking if the blockchain is not empty
        if self.get_height().is_none() {
            return (Vec::new(), 0, Vec::new());
        }

        let mut txs = Vec::new();
        let mut fees = 0u64;
        let mut used_utxo = Vec::new();

        let mut mem_available = MAX_BLOCK_SIZE - size_of::<BlockHeader>();

        // For each transaction in the UTX pool
        'utx_pool: for _ in 0..self.utx_pool.len() {
            let tx = self.utx_pool.pop().unwrap();

            // Checking for available memory in the block
            let (new_mem_available, not_available) = mem_available.overflowing_sub(tx.get_size());
            if not_available {
                // Push the transaction back and break
                self.utx_pool.push(tx);
                break;
            }
            mem_available = new_mem_available;

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

            // If the transaction is valid
            if let Some(fee) = tx.validate_and_get_fee(self) {
                // Adding transaction, its fee and used UTXO
                txs.push(tx);
                fees += fee;
                used_utxo.append(&mut inner_used_utxo);
            }
        }

        (txs, fees, used_utxo)
    }

    pub fn get_blocks(&self) -> &[Block] {
        &self.blocks
    }

    pub fn get_height(&self) -> Option<u32> {
        if !self.blocks.is_empty() {
            Some((self.blocks.len() - 1) as u32)
        } else {
            None
        }
    }

    pub fn get_tx(&self, hash: &Hash) -> Option<&Tx> {
        // Searching for the transaction in the blockchain starting from the last block
        for block in self.blocks.iter().rev() {
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

    pub fn get_tx_output(&self, output_ref: &TxOutputRef) -> Option<&TxOutput> {
        let tx = self.get_tx(&output_ref.tx_hash)?;
        tx.outputs.get(output_ref.output_index as usize)
    }

    pub fn is_utxo(&self, output_ref: &TxOutputRef) -> bool {
        self.utxo_pool.contains(output_ref)
    }
}

impl Block {
    fn mine(prev_hash: &Hash, difficulty: f32, mut txs: Vec<Tx>) -> Self {
        Block {
            header: BlockHeader::mine(prev_hash, difficulty, &mut txs),
            txs,
        }
    }

    pub fn get_header(&self) -> &BlockHeader {
        &self.header
    }

    pub fn get_txs(&self) -> &[Tx] {
        &self.txs
    }
}

impl BlockHeader {
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

    fn hash(&self) -> Hash {
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

    fn validate_hash(&self) -> bool {
        let hash = BigUint::from_bytes_be(&*self.hash());

        let target = BlockHeader::difficulty_to_target(self.difficulty);

        // If hash is equal to or less then the difficulty target
        hash <= target
    }

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
