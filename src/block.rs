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
use crate::wallet::Wallet;

const IMPOSSIBLE_BLOCK_HASH: Hash = Hash([255u8; 32]);

#[derive(Obj2Str)]
pub struct Blockchain {
    blocks: Vec<Block>,
    utx_pool: Vec<(Tx, u64)>,
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

    pub fn mine(&mut self, wallet: &Wallet) {
        // If there is no blocks yet, mine the genesis one
        let Some(current_height) = self.get_height() else {
            self.blocks.push(Block::mine(
                &IMPOSSIBLE_BLOCK_HASH,
                self.calculate_difficulty(0),
                vec![Blockchain::generate_coinbase_tx(wallet, 0, 0)],
            ));
            return;
        };

        // Choosing transactions with the biggest fees
        let (mut txs, fees, used_utxo) = self.choose_txs_with_fee();

        // Generating a coinbase transaction
        let coinbase_tx = Blockchain::generate_coinbase_tx(wallet, fees, current_height);
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

    pub fn add_utx(&mut self, tx: Tx) {
        // Checking if the blockchain is not empty
        let Some(current_height) = self.get_height() else {
            return;
        };

        let Some(fee) = tx.get_fee(self, current_height) else {
            return;
        };

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

    pub fn get_tx_output(&self, output_ref: &TxOutputRef, height: u32) -> Option<&TxOutput> {
        let tx = self.get_tx(&output_ref.tx_hash, height)?;
        tx.outputs.get(output_ref.output_index as usize)
    }

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
}

impl Block {
    fn mine(prev_hash: &Hash, difficulty: f32, mut txs: Vec<Tx>) -> Self {
        Block {
            header: BlockHeader::mine(prev_hash, difficulty, &mut txs),
            txs,
        }
    }

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

    fn get_size(&self) -> usize {
        let mut size = size_of::<BlockHeader>();
        for tx in self.txs.iter() {
            size += tx.get_size();
        }
        size
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
