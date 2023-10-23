//! Miscellaneous utilities.

use std::io::{stdin, stdout, Write};

use crate::block::Blockchain;
use crate::database::BlockchainDB;
use crate::tx::TxOutputRef;
use crate::wallet::Wallet;

/// Returns read line without trailing newline symbols.
pub fn readln(new_line: bool) -> String {
    if new_line {
        print!("\n> ");
        let _ = stdout().flush();
    }

    let mut input = String::new();

    if stdin().read_line(&mut input).is_err() {
        return String::new();
    };

    while input.ends_with('\n') || input.ends_with('\r') {
        input.pop();
    }

    input
}

/// Converts a HEX string into bytes.
pub fn hex_to_bytes(hex: &str, bytes: &mut [u8]) -> Result<usize, ()> {
    let mut byte_number = 0;

    if hex.is_empty() != bytes.is_empty() {
        return Err(());
    }

    let mut chars = hex.chars();
    for byte in bytes.iter_mut() {
        let mut hex = String::new();

        let Some(first_byte) = chars.next() else {
            break;
        };
        hex.push(first_byte);

        let Some(second_byte) = chars.next() else {
            return Err(());
        };
        hex.push(second_byte);

        *byte = u8::from_str_radix(hex.as_str(), 16).map_err(|_| ())?;

        byte_number += 1;
    }

    Ok(byte_number)
}

/// Coin selection algorithm. Selects best inputs for specific coin amount.
pub fn select_inputs(
    blockchain_db: &BlockchainDB,
    wallet: &Wallet,
    amount: u64,
) -> Vec<TxOutputRef> {
    let Some(current_height) = blockchain_db.get_height() else {
        return Vec::new();
    };

    if amount == 0 {
        return Vec::new();
    }

    // Getting own UTXOs
    let mut utxo_pool: Vec<_> = blockchain_db
        .get_utxo_pool()
        .iter()
        .filter_map({
            let public_keys = wallet.get_public_keys();
            |output_ref| {
                let output = Blockchain::get_tx_output(blockchain_db, output_ref, current_height)?;
                if public_keys.contains(&output.public_key) {
                    Some((output_ref, output))
                } else {
                    None
                }
            }
        })
        .collect();

    // Trying to find exact UTXO
    for (output_ref, output) in utxo_pool.iter() {
        if output.amount == amount {
            return vec![(**output_ref).clone()];
        }
    }

    // Sorting UTXOs
    utxo_pool.sort_by(|(_, output_left), (_, output_right)| {
        output_left.amount.cmp(&output_right.amount)
    });

    // Trying to find UTXOs beginning from the smallest ones
    // sum of which will give at least needed amount
    {
        let mut current_amount = 0;
        let mut output_refs = Vec::new();
        for (output_ref, output) in utxo_pool.iter() {
            output_refs.push((**output_ref).clone());
            current_amount += output.amount;

            if current_amount >= amount {
                return output_refs;
            }
        }
    }

    Vec::new()
}

/// Returns the availabe amount of coins for specific wallet.
pub fn get_available_coin_amount(blockchain: &mut Blockchain, wallet: &Wallet) -> u64 {
    let blockchain_db = blockchain.get_db_mut();

    let Some(current_height) = blockchain_db.get_height() else {
        return 0;
    };

    // Getting own UTXOs and finding their sum
    blockchain_db
        .get_utxo_pool()
        .iter()
        .filter_map({
            let public_keys = wallet.get_public_keys();
            |output_ref| {
                let output = Blockchain::get_tx_output(&blockchain_db, output_ref, current_height)?;
                if public_keys.contains(&output.public_key) {
                    Some(output.amount)
                } else {
                    None
                }
            }
        })
        .sum()
}
