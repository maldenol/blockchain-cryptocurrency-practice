use std::mem::{size_of, size_of_val};

use hmac_sha256::Hash as SHA256;

use crate::block::Blockchain;
use crate::hash::Hash;
use crate::obj2str::Obj2Str;

pub struct Tx {
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

pub struct TxInput {
    pub output_ref: TxOutputRef,
    // unlocking script
}

pub struct TxOutput {
    pub amount: u64,
    // locking script
}

#[derive(PartialEq)]
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

impl Obj2Str for Tx {
    fn to_str(&self, tab_num: i8, brief_depth: i8) -> String {
        if brief_depth <= 0 {
            return String::from("Tx");
        }

        let mut string = String::with_capacity(1024);

        string.push_str("Tx {");

        Self::indent(&mut string, tab_num);
        string.push_str(format!("version: {}", self.version).as_str());
        string.push(',');

        Self::indent(&mut string, tab_num);
        if brief_depth == 1 {
            string.push_str(format!("inputs: TxInput[{}]", self.inputs.len()).as_str());
        } else {
            string.push_str("inputs: [");
            for index in 0..self.inputs.len() {
                Self::indent(&mut string, Self::intern_tab_num(tab_num));
                string.push_str(format!("({}) ", index).as_str());
                string.push_str(
                    self.inputs[index]
                        .to_str(
                            Self::intern_tab_num(Self::intern_tab_num(tab_num)),
                            brief_depth - 1,
                        )
                        .as_str(),
                );
                if tab_num > 0 || index < self.inputs.len() - 1 {
                    string.push(',');
                }
            }
            Self::indent(&mut string, tab_num);
            string.push(']');
        }
        string.push(',');

        Self::indent(&mut string, tab_num);
        if brief_depth == 1 {
            string.push_str(format!("outputs: TxOutput[{}]", self.inputs.len()).as_str());
        } else {
            string.push_str("outputs: [");
            for index in 0..self.outputs.len() {
                Self::indent(&mut string, Self::intern_tab_num(tab_num));
                string.push_str(format!("({}) ", index).as_str());
                string.push_str(
                    self.outputs[index]
                        .to_str(
                            Self::intern_tab_num(Self::intern_tab_num(tab_num)),
                            brief_depth - 1,
                        )
                        .as_str(),
                );
                if tab_num > 0 || index < self.inputs.len() - 1 {
                    string.push(',');
                }
            }
            Self::indent(&mut string, tab_num);
            string.push(']');
        }
        if tab_num > 0 {
            string.push(',');
        }

        Self::indent_last(&mut string, tab_num);
        string.push('}');

        string
    }
}

impl Obj2Str for TxInput {
    fn to_str(&self, tab_num: i8, brief_depth: i8) -> String {
        if brief_depth <= 0 {
            return String::from("TxInput");
        }

        let mut string = String::with_capacity(1024);

        string.push_str("TxInput {");

        Self::indent(&mut string, tab_num);
        string.push_str(
            format!(
                "output_ref: {}",
                self.output_ref
                    .to_str(Self::intern_tab_num(tab_num), brief_depth - 1)
            )
            .as_str(),
        );
        if tab_num > 0 {
            string.push(',');
        }

        Self::indent_last(&mut string, tab_num);
        string.push('}');

        string
    }
}

impl Obj2Str for TxOutput {
    fn to_str(&self, tab_num: i8, brief_depth: i8) -> String {
        if brief_depth <= 0 {
            return String::from("TxOutput");
        }

        let mut string = String::with_capacity(1024);

        string.push_str("TxOutput {");

        Self::indent(&mut string, tab_num);
        string.push_str(format!("amount: {}", self.amount).as_str());
        if tab_num > 0 {
            string.push(',');
        }

        Self::indent_last(&mut string, tab_num);
        string.push('}');

        string
    }
}

impl Obj2Str for TxOutputRef {
    fn to_str(&self, tab_num: i8, brief_depth: i8) -> String {
        if brief_depth <= 0 {
            return String::from("TxOutputRef");
        }

        let mut string = String::with_capacity(1024);

        string.push_str("TxOutputRef {");

        Self::indent(&mut string, tab_num);
        string.push_str(format!("tx_hash: {}", self.tx_hash.to_str(0, 0)).as_str());
        string.push(',');

        Self::indent(&mut string, tab_num);
        string.push_str(format!("output_index: {}", self.output_index).as_str());
        if tab_num > 0 {
            string.push(',');
        }

        Self::indent_last(&mut string, tab_num);
        string.push('}');

        string
    }
}
