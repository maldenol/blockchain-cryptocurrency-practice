mod block;
mod consts;
mod digsig;
mod hash;
mod merkle;
mod netdriver;
mod tx;
mod wallet;

use std::io::{stdout, Write};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

use obj2str::Obj2Str;

use block::Blockchain;
use consts::*;
use digsig::PrivateKey;
use netdriver::NetDriver;
use wallet::Wallet;

fn main() {
    // It is better to use them separately
    test_fork_01(); // make MAX_ACCIDENTAL_FORK_HEIGHT 3
    test_fork_02(); // make MAX_ACCIDENTAL_FORK_HEIGHT 1 and MAX_BLOCKS_PER_DOWNLOAD 3
    test_network_01();
}

fn test_fork_01() {
    println!("\n\nTEST: FORK 01");

    const INSTANCE_NUMBER: usize = 2;

    let mut wallets = Vec::with_capacity(INSTANCE_NUMBER);
    let mut blockchains = Vec::with_capacity(INSTANCE_NUMBER);
    let mut net_drivers = Vec::with_capacity(INSTANCE_NUMBER);

    for index in 0..INSTANCE_NUMBER {
        let wallet = Arc::new(Mutex::new(Wallet::new()));
        wallet.lock().unwrap().insert(0, PrivateKey::random());
        println!("{} {}", index, wallet.lock().unwrap().obj2str(0, 2));
        wallets.push(Arc::clone(&wallet));

        #[allow(clippy::arc_with_non_send_sync)]
        let net_driver = Arc::new(Mutex::new(NetDriver::new(
            format!("127.0.0.1:80{:02}", index).parse().unwrap(),
        )));
        net_drivers.push(Arc::clone(&net_driver));

        let blockchain = Blockchain::new(wallet, net_driver);
        blockchains.push(blockchain);

        net_drivers[index]
            .lock()
            .unwrap()
            .set_custom_message_handler(Some(Box::new({
                let blockchain = unsafe { &mut *(&mut blockchains[index] as *mut Blockchain) };
                move |conn_index, msg| {
                    blockchain.handle_message(conn_index, msg);
                }
            })));
    }
    println!();

    println!("Initial");
    blockchains[0].mine();
    blockchains[1].mine();
    show_blockchains(&blockchains);
    println!();

    println!("TESTING longer chain is the truth");

    print!("Merging 1 into 0: ");
    let from = unsafe { &*(&blockchains[1] as *const Blockchain) };
    let to = unsafe { &mut *(&mut blockchains[0] as *mut Blockchain) };
    merge(from, to);

    print!("Merging 0 into 1: ");
    let from = unsafe { &*(&blockchains[0] as *const Blockchain) };
    let to = unsafe { &mut *(&mut blockchains[1] as *mut Blockchain) };
    merge(from, to);

    show_blockchains(&blockchains);
    println!();

    println!("TESTING root rebase");
    blockchains[0].mine();

    println!("0 mined a block");
    show_blockchains(&blockchains);

    print!("Merging 0 into 1: ");
    let from = unsafe { &*(&blockchains[0] as *const Blockchain) };
    let to = unsafe { &mut *(&mut blockchains[1] as *mut Blockchain) };
    merge(from, to);

    show_blockchains(&blockchains);
    println!();

    println!("TESTING fast-forward");
    println!("0 is mining (MAX_ACCIDENTAL_FORK_HEIGHT + 1) blocks");
    for _ in 0..(MAX_ACCIDENTAL_FORK_HEIGHT + 1) {
        blockchains[0].mine();
        print!("* ");
        let _ = stdout().flush();
    }
    println!();

    show_blockchains(&blockchains);

    print!("Merging 0 into 1: ");
    let from = unsafe { &*(&blockchains[0] as *const Blockchain) };
    let to = unsafe { &mut *(&mut blockchains[1] as *mut Blockchain) };
    merge(from, to);

    show_blockchains(&blockchains);
    println!();

    println!("TESTING rebase (accidental fork)");
    println!("0 is mining (MAX_ACCIDENTAL_FORK_HEIGHT + 1) blocks");
    for _ in 0..(MAX_ACCIDENTAL_FORK_HEIGHT + 1) {
        blockchains[0].mine();
        print!("* ");
        let _ = stdout().flush();
    }
    println!();
    println!("1 is mining MAX_ACCIDENTAL_FORK_HEIGHT blocks");
    for _ in 0..MAX_ACCIDENTAL_FORK_HEIGHT {
        blockchains[1].mine();
        print!("* ");
        let _ = stdout().flush();
    }
    println!();

    show_blockchains(&blockchains);

    print!("Merging 1 into 0: ");
    let from = unsafe { &*(&blockchains[1] as *const Blockchain) };
    let to = unsafe { &mut *(&mut blockchains[0] as *mut Blockchain) };
    merge(from, to);

    print!("Merging 0 into 1: ");
    let from = unsafe { &*(&blockchains[0] as *const Blockchain) };
    let to = unsafe { &mut *(&mut blockchains[1] as *mut Blockchain) };
    merge(from, to);

    show_blockchains(&blockchains);
    println!();

    println!("TESTING rebase (intentional fork)");
    println!("0 is mining (MAX_ACCIDENTAL_FORK_HEIGHT + 2) blocks");
    for _ in 0..(MAX_ACCIDENTAL_FORK_HEIGHT + 2) {
        blockchains[0].mine();
        print!("* ");
        let _ = stdout().flush();
    }
    println!();
    println!("1 is mining (MAX_ACCIDENTAL_FORK_HEIGHT + 1) blocks");
    for _ in 0..(MAX_ACCIDENTAL_FORK_HEIGHT + 1) {
        blockchains[1].mine();
        print!("* ");
        let _ = stdout().flush();
    }
    println!();

    show_blockchains(&blockchains);

    print!("Merging 1 into 0: ");
    let from = unsafe { &*(&blockchains[1] as *const Blockchain) };
    let to = unsafe { &mut *(&mut blockchains[0] as *mut Blockchain) };
    merge(from, to);

    print!("Merging 0 into 1: ");
    let from = unsafe { &*(&blockchains[0] as *const Blockchain) };
    let to = unsafe { &mut *(&mut blockchains[1] as *mut Blockchain) };
    merge(from, to);

    show_blockchains(&blockchains);
}

fn test_fork_02() {
    println!("\n\nTEST: FORK 02");

    const INSTANCE_NUMBER: usize = 2;

    let mut wallets = Vec::with_capacity(INSTANCE_NUMBER);
    let mut blockchains = Vec::with_capacity(INSTANCE_NUMBER);
    let mut net_drivers = Vec::with_capacity(INSTANCE_NUMBER);

    for index in 0..INSTANCE_NUMBER {
        let wallet = Arc::new(Mutex::new(Wallet::new()));
        wallet.lock().unwrap().insert(0, PrivateKey::random());
        println!("{} {}", index, wallet.lock().unwrap().obj2str(0, 2));
        wallets.push(Arc::clone(&wallet));

        #[allow(clippy::arc_with_non_send_sync)]
        let net_driver = Arc::new(Mutex::new(NetDriver::new(
            format!("127.0.0.1:80{:02}", index).parse().unwrap(),
        )));
        net_drivers.push(Arc::clone(&net_driver));

        let blockchain = Blockchain::new(wallet, net_driver);
        blockchains.push(blockchain);

        net_drivers[index]
            .lock()
            .unwrap()
            .set_custom_message_handler(Some(Box::new({
                let blockchain = unsafe { &mut *(&mut blockchains[index] as *mut Blockchain) };
                move |conn_index, msg| {
                    blockchain.handle_message(conn_index, msg);
                }
            })));
    }
    println!();

    println!("Initial");

    blockchains[0].mine();

    let from = unsafe { &*(&blockchains[0] as *const Blockchain) };
    let to = unsafe { &mut *(&mut blockchains[1] as *mut Blockchain) };
    merge(from, to);

    show_blockchains(&blockchains);
    println!();

    println!("TESTING too many blocks are missed");

    println!("0 is mining 3 * MAX_BLOCKS_PER_DOWNLOAD blocks");
    for _ in 0..(3 * MAX_BLOCKS_PER_DOWNLOAD) {
        blockchains[0].mine();
        print!("* ");
        let _ = stdout().flush();
    }
    println!();

    for _ in 0..10 {
        print!("Merging 0 into 1: ");
        let from = unsafe { &*(&blockchains[0] as *const Blockchain) };
        let to = unsafe { &mut *(&mut blockchains[1] as *mut Blockchain) };
        merge(from, to);

        show_blockchains(&blockchains);
    }
}

fn test_network_01() {
    println!("\n\nTEST: NETWORK 01");

    const INSTANCE_NUMBER: usize = 5;
    const ITERATION_NUMBER: usize = 5;

    let mut wallets = Vec::with_capacity(INSTANCE_NUMBER);
    let mut blockchains = Vec::with_capacity(INSTANCE_NUMBER);
    let mut net_drivers = Vec::with_capacity(INSTANCE_NUMBER);

    for index in 0..INSTANCE_NUMBER {
        let wallet = Arc::new(Mutex::new(Wallet::new()));
        wallet.lock().unwrap().insert(0, PrivateKey::random());
        println!("{} {}", index, wallet.lock().unwrap().obj2str(0, 2));
        wallets.push(Arc::clone(&wallet));

        #[allow(clippy::arc_with_non_send_sync)]
        let net_driver = Arc::new(Mutex::new(NetDriver::new(
            format!("127.0.0.1:80{:02}", index).parse().unwrap(),
        )));
        net_drivers.push(Arc::clone(&net_driver));

        let blockchain = Blockchain::new(wallet, net_driver);
        blockchains.push(blockchain);

        net_drivers[index]
            .lock()
            .unwrap()
            .set_custom_message_handler(Some(Box::new({
                let blockchain = unsafe { &mut *(&mut blockchains[index] as *mut Blockchain) };
                move |conn_index, msg| {
                    blockchain.handle_message(conn_index, msg);
                }
            })));
    }
    println!();

    for net_driver in net_drivers.iter_mut() {
        for inner_index in 0..INSTANCE_NUMBER {
            net_driver.lock().unwrap().add_connections(vec![format!(
                "127.0.0.1:80{:02}",
                inner_index
            )
            .parse()
            .unwrap()]);
        }
    }

    for blockchain in blockchains.iter_mut() {
        blockchain.mine();
    }

    for _ in 0..ITERATION_NUMBER {
        use rand::random;
        let blockchain_index = random::<usize>() % INSTANCE_NUMBER;
        let block_number = random::<u32>() % MAX_ACCIDENTAL_FORK_HEIGHT + 1;

        println!(
            "{}'th instance is mining {} blocks",
            blockchain_index, block_number
        );

        sleep(Duration::from_secs(3));

        println!("Before");
        show_blockchains(&blockchains);

        for _ in 0..block_number {
            blockchains[blockchain_index].mine();
            print!("* ");
            let _ = stdout().flush();
        }
        println!();

        sleep(Duration::from_secs(3));

        println!("After");
        show_blockchains(&blockchains);

        println!();
    }

    sleep(Duration::from_secs(10));

    println!("\nResult");
    show_blockchains(&blockchains);
}

fn show_blockchains(blockchains: &[Blockchain]) {
    for blockchain in blockchains.iter() {
        println!(
            "{} ({})",
            blockchain
                .get_blocks()
                .last()
                .unwrap()
                .get_header()
                .hash()
                .obj2str(0, 0),
            blockchain.get_blocks().len()
        );
    }
}

fn merge(from: &Blockchain, to: &mut Blockchain) {
    let hash = to.get_oldest_accidental_fork_block_hash();
    let blocks = from.get_next_blocks(hash);
    let blocks: Vec<_> = blocks
        .iter()
        .take(MAX_BLOCKS_PER_DOWNLOAD)
        .cloned()
        .collect();

    #[allow(clippy::collapsible_else_if)]
    if to.fast_forward(&blocks) {
        println!("Fast-forwarded");
    } else {
        if to.rebase(&blocks) {
            println!("Rebased");
        } else {
            if to.rebase_root(&blocks) {
                println!("Rebased genesis");
            } else {
                println!("No merge");
            }
        }
    }
}
