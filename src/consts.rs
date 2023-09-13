// Blockchain
pub const BLOCK_VERSION: u32 = 1;
//pub const DIFFICULTY_ADJUSTMENT_PERIOD: u32 = 2_016;
pub const DIFFICULTY_ADJUSTMENT_PERIOD: u32 = 10;
//pub const MAX_DIFFICULTY_TARGET: u32 = 0x1D00FFFF;
pub const MAX_DIFFICULTY_TARGET: u32 = 0x21000100;
//pub const BLOCK_MINING_TIME: u32 = 10 * 60;
pub const BLOCK_MINING_TIME: u32 = 1;
pub const MAX_BLOCK_SIZE: usize = 1024 * 1024;

// Cryptocurrency
pub const TX_VERSION: u32 = 1;
pub const CENTS_IN_COIN: u64 = 100_000_000;
pub const MINING_REWARD: u64 = 50 * CENTS_IN_COIN;
pub const HALVING_PERIOD: u32 = 210_000;
