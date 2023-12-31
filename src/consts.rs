//! General constants.

use std::time::Duration;

// Blockchain constants.

/// 'Block' version.
pub const BLOCK_VERSION: u32 = 1;
/// The period of adjusting the mining difficulty (in 'Block's).
pub const DIFFICULTY_ADJUSTMENT_PERIOD: u32 = 20;
/// The maximum difficulty target ('Hash').
/// The first two bytes are exponent and the next six are mantissa of the target.
pub const MAX_DIFFICULTY_TARGET: u32 = 0x21000100;
/// Target mining time of a single 'Block' (in seconds).
pub const BLOCK_MINING_TIME: u32 = 15;
/// Maximum permissible timestamp difference between consecutive 'Block's (in seconds).
pub const MAX_TIMESTAMP_DELTA: u64 = 24 * 60 * 60 * 1_000_000_000;
/// Maximum permissible amount of 'Block's that can be rebased during an accidental fork.
/// Rebasing bigger amount of 'Block's is considered an intentional fork.
pub const MAX_ACCIDENTAL_FORK_HEIGHT: u32 = 10;
/// Maximum size of a single 'Block' (in bytes).
pub const MAX_BLOCK_SIZE: usize = 1024 * 1024;

// Cryptocurrency constants.

/// 'Tx' version.
pub const TX_VERSION: u32 = 1;
/// The amount of cents in a single coin.
pub const CENTS_IN_COIN: u64 = 100_000_000;
/// The reward for mining a 'Block' (in cents).
pub const MINING_REWARD: u64 = 50 * CENTS_IN_COIN;
/// The period of halving the reward for mining a 'Block' (in 'Block's).
pub const HALVING_PERIOD: u32 = 210_000;

// Network constants.

pub const MIN_CONNECTION_NUMBER: usize = 10;
pub const MAX_CONNECTION_NUMBER: usize = 20;
pub const NET_CONNECT_TIMEOUT: Duration = Duration::from_millis(5000);
pub const NET_LISTEN_TIMEOUT: Duration = Duration::from_millis(5000);
pub const NET_READ_TIMEOUT: Duration = Duration::from_millis(1000);
pub const NET_WRITE_TIMEOUT: Duration = Duration::from_millis(1000);
pub const MAX_NET_DATA_SIZE: usize = 20 * 1024 * 1024;
pub const MAX_BLOCKS_PER_DOWNLOAD: u32 = 100;

// Saving constants.

/// The amount of recent blocks to keep in memory.
pub const RECENT_BLOCK_NUMBER: usize = 1000;
/// The amount of blocks per single file.
pub const BLOCK_PER_FILE: u32 = 1000;
pub const BLOCKCHAIN_SAVE_DIR: &str = "blockchain/";
pub const BLOCK_FILE_EXTENSION: &str = ".blocks";
pub const UTXO_FILE_NAME: &str = "current.utxo";
pub const UTX_FILE_NAME: &str = "current.utx";
pub const WALLET_SAVE_DIR: &str = "wallet/";
pub const WALLET_FILE_NAME: &str = "my.wallet";
pub const NETDRIVER_SAVE_DIR: &str = "netdriver/";
pub const NETDRIVER_FILE_NAME: &str = "p2p.addresses";
