use obj2str::Obj2Str;
use obj2str_derive::Obj2Str;

use crate::digsig::{PrivateKey, PublicKey};

#[derive(Obj2Str)]
pub struct Wallet {
    private_keys: Vec<PrivateKey>,
    public_keys: Vec<PublicKey>,
}

impl Wallet {
    pub fn new() -> Self {
        Wallet {
            private_keys: Vec::new(),
            public_keys: Vec::new(),
        }
    }

    pub fn insert(&mut self, index: usize, private_key: PrivateKey) -> bool {
        if index <= self.get_key_number() {
            let public_key = private_key.get_public_key();

            self.private_keys.insert(index, private_key);
            self.public_keys.insert(index, public_key);

            true
        } else {
            false
        }
    }

    pub fn remove(&mut self, index: usize) -> bool {
        if index < self.get_key_number() {
            self.private_keys.remove(index);
            self.public_keys.remove(index);

            true
        } else {
            false
        }
    }

    pub fn get_key(&self, index: usize) -> Option<&PrivateKey> {
        if index < self.get_key_number() {
            self.private_keys.get(index)
        } else {
            None
        }
    }

    pub fn find_private_key(&self, public_key: &PublicKey) -> Option<&PrivateKey> {
        let index = self
            .public_keys
            .iter()
            .position(|inner_public_key| *inner_public_key == *public_key)?;
        Some(&self.private_keys[index])
    }

    pub fn get_key_number(&self) -> usize {
        self.private_keys.len()
    }

    pub fn get_private_keys(&self) -> &[PrivateKey] {
        &self.private_keys
    }

    pub fn get_public_keys(&self) -> &[PublicKey] {
        &self.public_keys
    }
}
