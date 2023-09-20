mod block;
mod consts;
mod digsig;
mod hash;
mod merkle;
mod tx;
mod wallet;

use std::time::Instant;

use obj2str::Obj2Str;

use block::Blockchain;
use consts::*;
use digsig::PrivateKey;
use wallet::Wallet;

fn main() {
    let mut wallet = Wallet::new();
    wallet.insert(0, PrivateKey::random());

    println!("{}\n", wallet.obj2str(1, 2));

    let mut blockchain = Blockchain::new();

    for _ in 0..10 {
        let before = Instant::now();

        for _ in 0..DIFFICULTY_ADJUSTMENT_PERIOD {
            blockchain.mine(&wallet);
            println!(
                "{}\n",
                blockchain.get_blocks().last().unwrap().obj2str(1, 5)
            );
        }

        let after = Instant::now();
        let dur = after - before;
        println!(
            "Average mining time = {} seconds",
            dur.as_nanos() as f32 / 1_000_000_000f32 / DIFFICULTY_ADJUSTMENT_PERIOD as f32
        );
    }
}
