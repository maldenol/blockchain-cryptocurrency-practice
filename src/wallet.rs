//! Wallet.

use obj2str::Obj2Str;
use obj2str_derive::Obj2Str;

use crate::database::WalletDB;
use crate::digsig::{PrivateKey, PublicKey};

/// 'Wallet' is a collection of private and according to them public keys
/// used by a single peer.
#[derive(Obj2Str)]
pub struct Wallet {
    private_keys: Vec<PrivateKey>,
    public_keys: Vec<PublicKey>,
    db: WalletDB,
}

impl Wallet {
    /// Returns a newly created 'Wallet'.
    pub fn new(db_path: String) -> Self {
        // Getting private and public keys from the save file.
        let db = WalletDB::new(db_path);
        let (private_keys, public_keys) = if let Some(private_keys) = db.load() {
            let public_keys = private_keys
                .iter()
                .map(|private_key| private_key.get_public_key())
                .collect();
            (private_keys, public_keys)
        } else {
            (Vec::new(), Vec::new())
        };

        Wallet {
            private_keys,
            public_keys,
            db,
        }
    }

    /// Inserts a private key into the 'Wallet' with the specified position.
    /// Public key is inserted automatically.
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

    /// Removes the private key from the 'Wallet' with the specified position.
    /// Public key is removed automatically.
    pub fn remove(&mut self, index: usize) -> bool {
        if index < self.get_key_number() {
            self.private_keys.remove(index);
            self.public_keys.remove(index);

            true
        } else {
            false
        }
    }

    /// Returns the private key by the given index.
    pub fn get_key(&self, index: usize) -> Option<&PrivateKey> {
        if index < self.get_key_number() {
            self.private_keys.get(index)
        } else {
            None
        }
    }

    /// Returns the private key by the given public one.
    pub fn find_private_key(&self, public_key: &PublicKey) -> Option<&PrivateKey> {
        let index = self
            .public_keys
            .iter()
            .position(|inner_public_key| *inner_public_key == *public_key)?;
        Some(&self.private_keys[index])
    }

    /// Returns the number of keys.
    pub fn get_key_number(&self) -> usize {
        self.private_keys.len()
    }

    /// Returns private keys.
    pub fn get_private_keys(&self) -> &[PrivateKey] {
        &self.private_keys
    }

    /// Returns public keys.
    pub fn get_public_keys(&self) -> &[PublicKey] {
        &self.public_keys
    }
}

impl Drop for Wallet {
    /// Saves private keys.
    fn drop(&mut self) {
        self.db.save(&self.private_keys);
    }
}
