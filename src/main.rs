mod block;
mod consts;
mod hash;
mod merkle;
mod obj2str;
mod tx;

use std::time::Instant;

use block::Blockchain;
use consts::*;
use obj2str::Obj2Str;

fn main() {
    let mut blockchain = Blockchain::new();

    for _ in 0..10 {
        let before = Instant::now();

        for _ in 0..DIFFICULTY_ADJUSTMENT_PERIOD {
            blockchain.mine();
            println!("{}\n", blockchain.get_blocks().last().unwrap().to_str(1, 2));
        }

        let after = Instant::now();
        let dur = after - before;
        println!(
            "Average mining time = {} seconds",
            dur.as_nanos() as f32 / 1_000_000_000f32 / DIFFICULTY_ADJUSTMENT_PERIOD as f32
        );
    }
}
