//! Secp256k1 + ECDSA wrappers.

use std::ops::Deref;

use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_derive::{Deserialize, Serialize};

use obj2str::Obj2Str;

/// Secp256k1 + ECDSA private key wrapper.
#[derive(Clone)]
#[repr(transparent)]
pub struct PrivateKey(pub SigningKey);

/// Secp256k1 + ECDSA public key wrapper.
#[derive(Clone, PartialEq)]
#[repr(transparent)]
pub struct PublicKey(pub VerifyingKey);

/// Secp256k1 + ECDSA signature wrapper.
#[derive(Clone, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Signat(pub Signature);

impl PrivateKey {
    /// Returns a newly created random 'PrivateKey'.
    pub fn random() -> Self {
        SigningKey::random(&mut OsRng).into()
    }

    /// Signs the message with the 'PrivateKey' and returns the signature.
    pub fn sign(&self, msg: &[u8]) -> Signat {
        Signat(self.0.sign(msg))
    }

    /// Returns the appropriate 'PublicKey'.
    pub fn get_public_key(&self) -> PublicKey {
        (*self.verifying_key()).into()
    }
}

impl Deref for PrivateKey {
    type Target = SigningKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<SigningKey> for PrivateKey {
    fn from(value: SigningKey) -> Self {
        PrivateKey(value)
    }
}

impl Obj2Str for PrivateKey {
    fn obj2str(&self, _tab_num: i8, _brief_depth: i8) -> String {
        let mut string = String::with_capacity(64);

        for byte in self.to_bytes() {
            string.push_str(format!("{:02X}", byte).as_str());
        }

        string
    }
}

impl PublicKey {
    /// Verifies the message by the signature.
    pub fn verify(&self, msg: &[u8], signature: &Signat) -> bool {
        self.0.verify(msg, &signature.0).is_ok()
    }
}

impl Deref for PublicKey {
    type Target = VerifyingKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<VerifyingKey> for PublicKey {
    fn from(value: VerifyingKey) -> Self {
        PublicKey(value)
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.0.to_sec1_bytes();
        bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let verifying_key =
            VerifyingKey::from_sec1_bytes(&bytes).map_err(serde::de::Error::custom)?;
        Ok(PublicKey(verifying_key))
    }
}

impl Obj2Str for PublicKey {
    fn obj2str(&self, _tab_num: i8, _brief_depth: i8) -> String {
        let mut string = String::with_capacity(64);

        for byte in self.to_sec1_bytes().iter() {
            string.push_str(format!("{:02X}", byte).as_str());
        }

        string
    }
}

impl Deref for Signat {
    type Target = Signature;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Signature> for Signat {
    fn from(value: Signature) -> Self {
        Signat(value)
    }
}

impl Obj2Str for Signat {
    fn obj2str(&self, _tab_num: i8, _brief_depth: i8) -> String {
        let mut string = String::with_capacity(64);

        for byte in self.to_bytes() {
            string.push_str(format!("{:02X}", byte).as_str());
        }

        string
    }
}
