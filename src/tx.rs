use std::mem::{size_of, size_of_val};

use hmac_sha256::Hash as SHA256;

use obj2str::Obj2Str;
use obj2str_derive::Obj2Str;

use crate::block::Blockchain;
use crate::hash::Hash;

#[derive(Obj2Str)]
pub struct Tx {
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

#[derive(Obj2Str)]
pub struct TxInput {
    pub output_ref: TxOutputRef,
    // unlocking script
}

#[derive(Obj2Str)]
pub struct TxOutput {
    pub amount: u64,
    // locking script
}

#[derive(Obj2Str, PartialEq)]
pub struct TxOutputRef {
    pub tx_hash: Hash,
    pub output_index: u32,
}

impl Tx {
    pub fn hash(&self) -> Hash {
        let mut hasher = SHA256::new();
        hasher.update(self.version.to_be_bytes());
        for input in self.inputs.iter() {
            hasher.update(*input.output_ref.tx_hash);
            hasher.update(input.output_ref.output_index.to_be_bytes());
        }
        for output in self.outputs.iter() {
            hasher.update(output.amount.to_be_bytes());
        }
        let hash = hasher.finalize();
        SHA256::hash(hash.as_slice()).into()
    }

    pub fn validate_and_get_fee(&self, blockchain: &Blockchain) -> Option<u64> {
        // Transaction fee (the sum of all inputs minus the sum of all outputs)
        let mut fee = 0i64;

        // For each input in the transaction
        for input in self.inputs.iter() {
            let output_ref = &input.output_ref;

            // Checking if the input uses UTXO
            if !blockchain.is_utxo(output_ref) {
                return None;
            }

            // Getting the output by the reference to it
            let output = blockchain.get_tx_output(output_ref)?;

            // Add input's amount to the fee
            fee += output.amount as i64;
        }

        // For each output in the transaction
        for output in self.outputs.iter() {
            // Subtract output's amount from the fee
            fee -= output.amount as i64;
        }

        // If the fee is equal to or greater than zero
        if fee >= 0 {
            // Transaction if valid, returning the fee
            Some(fee as u64)
        } else {
            None
        }
    }

    pub fn get_size(&self) -> usize {
        size_of_val(&self.version)
            + self.inputs.len() * size_of::<TxInput>()
            + self.outputs.len() * size_of::<TxOutput>()
    }

    pub fn get_outputs(&self) -> &[TxOutput] {
        &self.outputs
    }
}
