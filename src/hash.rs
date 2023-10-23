//! SHA-256 hash.

use std::ops::Deref;

use serde_derive::{Deserialize, Serialize};

use obj2str::Obj2Str;

use crate::utils::hex_to_bytes;

/// SHA-256 hash.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Hash(pub [u8; 32]);

impl Deref for Hash {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; 32]> for Hash {
    fn from(value: [u8; 32]) -> Self {
        Hash(value)
    }
}

impl TryFrom<&str> for Hash {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut hash = [0u8; 32];
        hex_to_bytes(value, &mut hash)?;

        Ok(Hash(hash))
    }
}

impl Obj2Str for Hash {
    fn obj2str(&self, _tab_num: i8, _brief_depth: i8) -> String {
        let mut string = String::with_capacity(64);

        for byte in self.iter() {
            string.push_str(format!("{:02X}", byte).as_str());
        }

        string
    }
}
