use std::cmp::Ordering;
use std::mem::{size_of, size_of_val};

use hmac_sha256::Hash as SHA256;
use serde_derive::{Deserialize, Serialize};

use obj2str::Obj2Str;
use obj2str_derive::Obj2Str;

use crate::block::Blockchain;
use crate::digsig::{PublicKey, Signat};
use crate::hash::Hash;
use crate::wallet::Wallet;

#[derive(Clone, Serialize, Deserialize, Obj2Str)]
pub struct Tx {
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

#[derive(Clone, Serialize, Deserialize, Obj2Str)]
pub struct TxInput {
    pub output_ref: TxOutputRef,
    pub signature: Option<Signat>,
}

#[derive(Clone, Serialize, Deserialize, Obj2Str)]
pub struct TxOutput {
    pub amount: u64,
    pub public_key: PublicKey,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Obj2Str)]
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
            hasher.update(output.public_key.to_sec1_bytes());
        }
        let hash = hasher.finalize();
        SHA256::hash(hash.as_slice()).into()
    }

    pub fn validate(&self, blockchain: &Blockchain, height: u32) -> bool {
        // Checking if the inputs and the outputs are not empty
        if self.inputs.is_empty() || self.outputs.is_empty() {
            return false;
        }

        // For each input in the transaction
        for input in self.inputs.iter() {
            let output_ref = &input.output_ref;

            // Checking if the input uses UTXO
            if !blockchain.is_utxo(output_ref, height) {
                return false;
            }

            // Getting the output by the reference to it
            let Some(output) = blockchain.get_tx_output(output_ref, height) else {
                return false;
            };

            // Checking if the signature is valid
            if let Some(signature) = input.signature.clone() {
                if !output.public_key.verify(self.hash().as_slice(), &signature) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Checking if the sum of outputs is equal to or less than the sum of inputs
        self.get_fee(blockchain, height).is_some()
    }

    pub fn sign(&mut self, blockchain: &Blockchain, wallet: &Wallet) -> bool {
        // If there are no inputs
        if self.inputs.is_empty() {
            return false;
        }

        // For each input creating a signature of the whole transaction's hash
        // using public key of corresponding output
        let hash = self.hash();

        // For each input in the transaction
        for input in self.inputs.iter_mut() {
            // Getting public key from the referenced output
            let Some(output) =
                blockchain.get_tx_output(&input.output_ref, blockchain.get_height().unwrap())
            else {
                return false;
            };
            let Some(private_key) = wallet.find_private_key(&output.public_key) else {
                return false;
            };

            // Signing the input (a signature of the whole transaction) with the public key
            input.signature = Some(private_key.sign(hash.as_slice()));
        }

        true
    }

    pub fn get_fee(&self, blockchain: &Blockchain, height: u32) -> Option<u64> {
        // Transaction fee (the sum of all inputs minus the sum of all outputs)
        let mut fee = 0i64;

        // For each input
        for input in self.inputs.iter() {
            let output = blockchain.get_tx_output(&input.output_ref, height)?;

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

impl PartialEq for Tx {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl Eq for Tx {}

impl PartialOrd for Tx {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.hash().cmp(&other.hash()))
    }
}

impl Ord for Tx {
    fn cmp(&self, other: &Self) -> Ordering {
        self.hash().cmp(&other.hash())
    }
}
