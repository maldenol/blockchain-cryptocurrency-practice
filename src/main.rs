mod block;
mod consts;
mod database;
mod digsig;
mod hash;
mod merkle;
mod netdriver;
mod tx;
mod wallet;

use std::fs::remove_dir_all;
use std::io::{stdout, Write};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

use obj2str::Obj2Str;

use block::Blockchain;
use consts::*;
use digsig::PrivateKey;
use netdriver::NetDriver;
use tx::*;
use wallet::Wallet;

fn main() {
    // Removing databases of tests
    let _ = remove_dir_all("test_databases");

    // Test them separately
    test_fork_01(); // make MAX_ACCIDENTAL_FORK_HEIGHT 3
    test_fork_02(); // make MAX_ACCIDENTAL_FORK_HEIGHT 1 and MAX_BLOCKS_PER_DOWNLOAD 3
    test_utx_and_utxo_update_01(); // make MAX_ACCIDENTAL_FORK_HEIGHT 3
    test_network_01();
    test_database_01(); // make BLOCK_PER_FILE 2
}

fn test_fork_01() {
    println!("\n\nTEST: FORK 01");

    const INSTANCE_NUMBER: usize = 2;

    let mut wallets = Vec::with_capacity(INSTANCE_NUMBER);
    let mut blockchains = Vec::with_capacity(INSTANCE_NUMBER);
    let mut net_drivers = Vec::with_capacity(INSTANCE_NUMBER);

    for index in 0..INSTANCE_NUMBER {
        let db_path = format!("test_databases/test_fork_01 ({})", index);

        let wallet = Arc::new(Mutex::new(Wallet::new(db_path.clone())));
        wallet.lock().unwrap().insert(0, PrivateKey::random());
        println!("{} {}", index, wallet.lock().unwrap().obj2str(0, 2));
        wallets.push(Arc::clone(&wallet));

        #[allow(clippy::arc_with_non_send_sync)]
        let net_driver = Arc::new(Mutex::new(NetDriver::new(
            db_path.clone(),
            format!("127.0.0.1:80{:02}", index).parse().unwrap(),
        )));
        net_drivers.push(Arc::clone(&net_driver));

        let blockchain = Blockchain::new(db_path, wallet, net_driver);
        blockchains.push(blockchain);

        net_drivers[index]
            .lock()
            .unwrap()
            .set_custom_message_handler(Some(Box::new({
                let blockchain = unsafe { &mut *(&mut blockchains[index] as *mut Blockchain) };
                move |connections, conn_index, msg| {
                    blockchain.handle_message(connections, conn_index, msg);
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
        let db_path = format!("test_databases/test_fork_02 ({})", index);

        let wallet = Arc::new(Mutex::new(Wallet::new(db_path.clone())));
        wallet.lock().unwrap().insert(0, PrivateKey::random());
        println!("{} {}", index, wallet.lock().unwrap().obj2str(0, 2));
        wallets.push(Arc::clone(&wallet));

        #[allow(clippy::arc_with_non_send_sync)]
        let net_driver = Arc::new(Mutex::new(NetDriver::new(
            db_path.clone(),
            format!("127.0.0.1:80{:02}", index).parse().unwrap(),
        )));
        net_drivers.push(Arc::clone(&net_driver));

        let blockchain = Blockchain::new(db_path, wallet, net_driver);
        blockchains.push(blockchain);

        net_drivers[index]
            .lock()
            .unwrap()
            .set_custom_message_handler(Some(Box::new({
                let blockchain = unsafe { &mut *(&mut blockchains[index] as *mut Blockchain) };
                move |connections, conn_index, msg| {
                    blockchain.handle_message(connections, conn_index, msg);
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

fn test_utx_and_utxo_update_01() {
    println!("\n\nTEST: UTX and UTXO update 01");

    const INSTANCE_NUMBER: usize = 2;

    let mut wallets = Vec::with_capacity(INSTANCE_NUMBER);
    let mut blockchains = Vec::with_capacity(INSTANCE_NUMBER);
    let mut net_drivers = Vec::with_capacity(INSTANCE_NUMBER);

    for index in 0..INSTANCE_NUMBER {
        let db_path = format!("test_databases/test_utx_and_utxo_update_01 ({})", index);

        let wallet = Arc::new(Mutex::new(Wallet::new(db_path.clone())));
        wallet.lock().unwrap().insert(0, PrivateKey::random());
        println!("{} {}", index, wallet.lock().unwrap().obj2str(0, 2));
        wallets.push(Arc::clone(&wallet));

        #[allow(clippy::arc_with_non_send_sync)]
        let net_driver = Arc::new(Mutex::new(NetDriver::new(
            db_path.clone(),
            format!("127.0.0.1:80{:02}", index).parse().unwrap(),
        )));
        net_drivers.push(Arc::clone(&net_driver));

        let blockchain = Blockchain::new(db_path, wallet, net_driver);
        blockchains.push(blockchain);

        net_drivers[index]
            .lock()
            .unwrap()
            .set_custom_message_handler(Some(Box::new({
                let blockchain = unsafe { &mut *(&mut blockchains[index] as *mut Blockchain) };
                move |connections, conn_index, msg| {
                    blockchain.handle_message(connections, conn_index, msg);
                }
            })));
    }
    println!();

    println!("Initial");

    blockchains[0].mine();

    let from = unsafe { &*(&blockchains[0] as *const Blockchain) };
    let to = unsafe { &mut *(&mut blockchains[1] as *mut Blockchain) };
    merge(from, to);

    for (utx, _) in blockchains[1].get_utx_pool() {
        blockchains[0].add_utx(utx);
    }

    show_blockchains(&blockchains);
    println!();

    println!("TESTING root rebase");
    add_utx(&mut blockchains[0], &wallets[0].lock().unwrap());
    blockchains[0].mine();

    println!("0 mined a block");
    show_blockchains(&blockchains);

    print!("Merging 0 into 1: ");
    let from = unsafe { &*(&blockchains[0] as *const Blockchain) };
    let to = unsafe { &mut *(&mut blockchains[1] as *mut Blockchain) };
    merge(from, to);

    for (utx, _) in blockchains[1].get_utx_pool() {
        blockchains[0].add_utx(utx);
    }

    show_blockchains(&blockchains);
    println!();

    assert_utx_and_utxo(&blockchains[0], &blockchains[1]);

    println!("TESTING fast-forward");
    println!("0 is mining (MAX_ACCIDENTAL_FORK_HEIGHT + 1) blocks");
    for _ in 0..(MAX_ACCIDENTAL_FORK_HEIGHT + 1) {
        add_utx(&mut blockchains[0], &wallets[0].lock().unwrap());
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

    for (utx, _) in blockchains[1].get_utx_pool() {
        blockchains[0].add_utx(utx);
    }

    show_blockchains(&blockchains);
    println!();

    assert_utx_and_utxo(&blockchains[0], &blockchains[1]);

    println!("TESTING rebase (accidental fork)");
    println!("0 is mining (MAX_ACCIDENTAL_FORK_HEIGHT + 1) blocks");
    for _ in 0..(MAX_ACCIDENTAL_FORK_HEIGHT + 1) {
        add_utx(&mut blockchains[0], &wallets[0].lock().unwrap());
        blockchains[0].mine();
        print!("* ");
        let _ = stdout().flush();
    }
    println!();
    println!("1 is mining MAX_ACCIDENTAL_FORK_HEIGHT blocks");
    for _ in 0..MAX_ACCIDENTAL_FORK_HEIGHT {
        add_utx(&mut blockchains[1], &wallets[1].lock().unwrap());
        blockchains[1].mine();
        print!("* ");
        let _ = stdout().flush();
    }
    println!();

    show_blockchains(&blockchains);

    print!("Merging 0 into 1: ");
    let from = unsafe { &*(&blockchains[0] as *const Blockchain) };
    let to = unsafe { &mut *(&mut blockchains[1] as *mut Blockchain) };
    merge(from, to);

    for (utx, _) in blockchains[1].get_utx_pool() {
        blockchains[0].add_utx(utx);
    }

    show_blockchains(&blockchains);
    println!();

    assert_utx_and_utxo(&blockchains[0], &blockchains[1]);

    println!("TESTING rebase (intentional fork)");
    println!("0 is mining (MAX_ACCIDENTAL_FORK_HEIGHT + 2) blocks");
    for _ in 0..(MAX_ACCIDENTAL_FORK_HEIGHT + 2) {
        add_utx(&mut blockchains[0], &wallets[0].lock().unwrap());
        blockchains[0].mine();
        print!("* ");
        let _ = stdout().flush();
    }
    println!();
    println!("1 is mining (MAX_ACCIDENTAL_FORK_HEIGHT + 1) blocks");
    for _ in 0..(MAX_ACCIDENTAL_FORK_HEIGHT + 1) {
        add_utx(&mut blockchains[1], &wallets[1].lock().unwrap());
        blockchains[1].mine();
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
}

fn test_network_01() {
    println!("\n\nTEST: NETWORK 01");

    const INSTANCE_NUMBER: usize = 5;
    const ITERATION_NUMBER: usize = 5;

    let mut wallets = Vec::with_capacity(INSTANCE_NUMBER);
    let mut blockchains = Vec::with_capacity(INSTANCE_NUMBER);
    let mut net_drivers = Vec::with_capacity(INSTANCE_NUMBER);

    for index in 0..INSTANCE_NUMBER {
        let db_path = format!("test_databases/test_network_01 ({})", index);

        let wallet = Arc::new(Mutex::new(Wallet::new(db_path.clone())));
        wallet.lock().unwrap().insert(0, PrivateKey::random());
        println!("{} {}", index, wallet.lock().unwrap().obj2str(0, 2));
        wallets.push(Arc::clone(&wallet));

        #[allow(clippy::arc_with_non_send_sync)]
        let net_driver = Arc::new(Mutex::new(NetDriver::new(
            db_path.clone(),
            format!("127.0.0.1:80{:02}", index).parse().unwrap(),
        )));
        net_drivers.push(Arc::clone(&net_driver));

        let blockchain = Blockchain::new(db_path, wallet, net_driver);
        blockchains.push(blockchain);

        net_drivers[index]
            .lock()
            .unwrap()
            .set_custom_message_handler(Some(Box::new({
                let blockchain = unsafe { &mut *(&mut blockchains[index] as *mut Blockchain) };
                move |connections, conn_index, msg| {
                    blockchain.handle_message(connections, conn_index, msg);
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

    println!("Result");
    show_blockchains(&blockchains);
}

fn test_database_01() {
    println!("\n\nTEST: DATABASE 01");

    const INSTANCE_NUMBER: usize = 5;
    const ITERATION_NUMBER: usize = 5;
    const MINE_NUMBER: usize = 5;

    for iteration_index in 0..ITERATION_NUMBER {
        let mut wallets = Vec::with_capacity(INSTANCE_NUMBER);
        let mut blockchains = Vec::with_capacity(INSTANCE_NUMBER);
        let mut net_drivers = Vec::with_capacity(INSTANCE_NUMBER);

        for index in 0..INSTANCE_NUMBER {
            let db_path = format!("test_databases/test_database_01 ({})", index);

            let wallet = Arc::new(Mutex::new(Wallet::new(db_path.clone())));
            wallet.lock().unwrap().insert(0, PrivateKey::random());
            println!("{} {}", index, wallet.lock().unwrap().obj2str(1, 2));
            wallets.push(Arc::clone(&wallet));

            #[allow(clippy::arc_with_non_send_sync)]
            let net_driver = Arc::new(Mutex::new(NetDriver::new(
                db_path.clone(),
                format!("127.0.0.1:80{:02}", index).parse().unwrap(),
            )));
            net_drivers.push(Arc::clone(&net_driver));

            let blockchain = Blockchain::new(db_path, wallet, net_driver);
            blockchains.push(blockchain);

            net_drivers[index]
                .lock()
                .unwrap()
                .set_custom_message_handler(Some(Box::new({
                    let blockchain = unsafe { &mut *(&mut blockchains[index] as *mut Blockchain) };
                    move |connections, conn_index, msg| {
                        blockchain.handle_message(connections, conn_index, msg);
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

        if iteration_index == 0 {
            for blockchain in blockchains.iter_mut() {
                blockchain.mine();
            }
        }

        println!("Number of connections for each NetDriver:");
        for net_driver in net_drivers.iter() {
            println!("{}", net_driver.lock().unwrap().get_connection_number());
        }
        println!();

        for mine_index in 0..MINE_NUMBER {
            use rand::random;
            let blockchain_index = random::<usize>() % INSTANCE_NUMBER;

            println!(
                "{} {}'th instance is mining a block",
                mine_index, blockchain_index
            );

            println!("Before");
            show_blockchains(&blockchains);

            add_utx(
                &mut blockchains[blockchain_index],
                &wallets[blockchain_index].lock().unwrap(),
            );
            blockchains[blockchain_index].mine();

            println!("After");
            show_blockchains(&blockchains);

            println!();
        }

        println!("Result {}", iteration_index);
        show_blockchains(&blockchains);
        println!();
    }
}

fn show_blockchains(blockchains: &[Blockchain]) {
    for blockchain in blockchains.iter() {
        println!(
            "{} ({:?})",
            blockchain
                .get_last_block()
                .unwrap()
                .get_header()
                .hash()
                .obj2str(0, 0),
            blockchain.get_height()
        );
    }
}

fn merge(from: &Blockchain, to: &mut Blockchain) {
    let hash = to.get_oldest_accidental_fork_block_hash_pub();
    let blocks = from.get_next_blocks_pub(hash);
    let blocks: Vec<_> = blocks
        .iter()
        .take(MAX_BLOCKS_PER_DOWNLOAD as usize)
        .cloned()
        .collect();

    #[allow(clippy::collapsible_else_if)]
    if to.fast_forward_pub(&blocks) {
        println!("Fast-forwarded");
    } else {
        if to.rebase_pub(&blocks) {
            println!("Rebased");
        } else {
            if to.rebase_root_pub(&blocks) {
                println!("Rebased genesis");
            } else {
                println!("No merge");
            }
        }
    }
}

fn assert_utx_and_utxo(blockchain_0: &Blockchain, blockchain_1: &Blockchain) {
    let utx_pool_0 = blockchain_0.get_utx_pool();
    let utx_pool_1 = blockchain_1.get_utx_pool();
    let utxo_pool_0 = blockchain_0.get_utxo_pool();
    let utxo_pool_1 = blockchain_1.get_utxo_pool();

    println!(
        "UTX (0): {}\nUTX (1): {}",
        utx_pool_0.obj2str(1, 5),
        utx_pool_1.obj2str(1, 5)
    );

    assert!(utx_pool_0.iter().all(|utx_0| utx_pool_1.contains(utx_0)));
    assert!(utx_pool_1.iter().all(|utx_1| utx_pool_0.contains(utx_1)));
    println!("UTX pools are identical\n");

    println!(
        "UTXO (0): {}\nUTXO (1): {}",
        utxo_pool_0.obj2str(1, 2),
        utxo_pool_1.obj2str(1, 2)
    );

    assert!(utxo_pool_0
        .iter()
        .all(|utxo_0| utxo_pool_1.contains(utxo_0)));
    assert!(utxo_pool_1
        .iter()
        .all(|utxo_1| utxo_pool_0.contains(utxo_1)));
    println!("UTXO pools are identical");

    println!("\n");
}

fn add_utx(blockchain: &mut Blockchain, wallet: &Wallet) {
    let mut tx = Tx {
        version: TX_VERSION,
        inputs: vec![TxInput {
            output_ref: blockchain.get_utxo_pool()[0].clone(),
            signature: None,
        }],
        outputs: vec![TxOutput {
            amount: MINING_REWARD,
            public_key: wallet.get_public_keys()[0].clone(),
        }],
    };

    let _ = tx.sign(&blockchain.get_db_mut(), wallet);

    blockchain.add_utx(tx);
}
