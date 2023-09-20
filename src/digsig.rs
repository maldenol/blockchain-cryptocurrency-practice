use std::ops::Deref;

use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use rand_core::OsRng;

use obj2str::Obj2Str;

#[derive(Clone)]
#[repr(transparent)]
pub struct PrivateKey(pub SigningKey);

#[derive(Clone, PartialEq)]
#[repr(transparent)]
pub struct PublicKey(pub VerifyingKey);

#[derive(Clone)]
#[repr(transparent)]
pub struct Signat(pub Signature);

impl PrivateKey {
    pub fn random() -> Self {
        SigningKey::random(&mut OsRng).into()
    }

    pub fn sign(&self, msg: &[u8]) -> Signat {
        Signat(self.0.sign(msg))
    }

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