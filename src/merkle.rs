//! Merkle tree.

use hmac_sha256::Hash as SHA256;

use crate::hash::Hash;
use crate::tx::Tx;

/// Builds a Merkle tree from given transactions and returns the value of its root.
pub fn merkle_root(txs: &[Tx]) -> Hash {
    match txs.len() {
        0 => panic!("List of transactions cannot be empty"),
        1 => {
            let hash = txs[0].hash();
            merkle_node(&hash, &hash)
        }
        2 => {
            let l_hash = txs[0].hash();
            let r_hash = txs[1].hash();
            merkle_node(&l_hash, &r_hash)
        }
        len => {
            let (l, r) = txs.split_at(len / 2);
            let l_hash = merkle_root(l);
            let r_hash = merkle_root(r);
            merkle_node(&l_hash, &r_hash)
        }
    }
}

/// Returns the value of the parent node given the child ones.
fn merkle_node(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = SHA256::new();
    hasher.update(**left);
    hasher.update(**right);
    let hash = hasher.finalize();
    SHA256::hash(hash.as_slice()).into()
}
