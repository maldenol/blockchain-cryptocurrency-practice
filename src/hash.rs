use std::ops::Deref;

use obj2str::Obj2Str;

#[derive(Clone, Copy, PartialEq)]
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

impl Obj2Str for Hash {
    fn obj2str(&self, _tab_num: i8, _brief_depth: i8) -> String {
        let mut string = String::with_capacity(64);

        for byte in self.iter() {
            string.push_str(format!("{:02X}", byte).as_str());
        }

        string
    }
}
