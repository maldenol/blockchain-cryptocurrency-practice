use std::time::Duration;

// Blockchain
pub const BLOCK_VERSION: u32 = 1;
//pub const DIFFICULTY_ADJUSTMENT_PERIOD: u32 = 2_016;
pub const DIFFICULTY_ADJUSTMENT_PERIOD: u32 = 10;
//pub const MAX_DIFFICULTY_TARGET: u32 = 0x1D00FFFF;
pub const MAX_DIFFICULTY_TARGET: u32 = 0x21000100;
//pub const BLOCK_MINING_TIME: u32 = 10 * 60;
pub const BLOCK_MINING_TIME: u32 = 1;
pub const MAX_TIMESTAMP_DELTA: u64 = 24 * 60 * 60 * 1_000_000_000;
pub const MAX_ACCIDENTAL_FORK_HEIGHT: u32 = 10;
pub const MAX_BLOCK_SIZE: usize = 1024 * 1024;

// Cryptocurrency
pub const TX_VERSION: u32 = 1;
pub const CENTS_IN_COIN: u64 = 100_000_000;
pub const MINING_REWARD: u64 = 50 * CENTS_IN_COIN;
pub const HALVING_PERIOD: u32 = 210_000;

// Network
pub const MIN_CONNECTION_NUMBER: usize = 10;
pub const MAX_CONNECTION_NUMBER: usize = 20;
pub const NET_CONNECT_TIMEOUT: Duration = Duration::from_millis(5000);
pub const NET_LISTEN_TIMEOUT: Duration = Duration::from_millis(5000);
pub const NET_READ_TIMEOUT: Duration = Duration::from_millis(1000);
pub const NET_WRITE_TIMEOUT: Duration = Duration::from_millis(1000);
pub const MAX_NET_DATA_SIZE: usize = 20 * 1024 * 1024;
pub const MAX_BLOCKS_PER_DOWNLOAD: usize = 100;
