mod block;
mod consts;
mod database;
mod digsig;
mod hash;
mod merkle;
mod netdriver;
mod tx;
mod utils;
mod wallet;

use std::env::args;
use std::fs::read_to_string;
use std::io::{stdout, Write};
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Weak,
};
use std::thread::{sleep, spawn, JoinHandle};
use std::time::Duration;

use obj2str::Obj2Str;

use block::{Block, Blockchain};
use consts::*;
use digsig::{PrivateKey, PublicKey};
use netdriver::NetDriver;
use tx::*;
use utils::*;
use wallet::Wallet;

fn main() {
    // Declaring program options
    let (mut blockchain_save_path, mut wallet_save_path, mut net_driver_save_path) =
        ("./".to_string(), "./".to_string(), "./".to_string());
    let mut listen_addr = "0.0.0.0:8000".parse().unwrap();
    let mut peer_addrs = Vec::new();
    let (mut mine_handle, mut should_mine) = (Arc::new(None), Arc::new(AtomicBool::new(false)));
    let mut initial_mine_callback = None;
    let mut quiet = false;

    // Reading program options
    {
        let mut args: Vec<String> = args().collect();
        args.remove(0);

        for arg in args {
            if &arg[..1] != "-" {
                println!("Unknown option \"{}\", use \"help\" to get help", arg);
                return;
            }

            let key_value: Vec<_> = arg[1..].split('=').collect();

            match key_value.len() {
                1 => {
                    match key_value[0] {
                        "h" | "-help" => {
                            println!("Usage: blockchain-cryptocurrency-practice [OPTIONS]");
                            println!();
                            println!("Options:");
                            println!("-h, --help                       Display this message");
                            println!("-b, --blockchain_save=[PATH]     Path to the blockchain's save directory");
                            println!("-w, --wallet_save=[PATH]         Path to the wallet's save directory");
                            println!("-n, --net_save=[PATH]            Path to the net driver's save directory");
                            println!("-l, --listen_addr=[ADDR]         Listen address of the host");
                            println!("-p, --peer_addrs=[PATH]          Path to the file with peer addresses");
                            println!(
                                "-m, --mine=[KEY]                 Run the mining process at start"
                            );
                            println!("    [KEY]: public key for mining reward accrual");
                            println!("-q, --quiet                      Run in the quiet mode");
                            return;
                        }
                        "q" | "-quiet" => quiet = true,
                        option => {
                            println!("Unknown option \"-{}\", use \"help\" to get help", option);
                            return;
                        }
                    }
                }
                2 => match key_value[0] {
                    "b" | "-blockchain_save" => blockchain_save_path = key_value[1].to_string(),
                    "w" | "-wallet_save" => wallet_save_path = key_value[1].to_string(),
                    "n" | "-net_save" => net_driver_save_path = key_value[1].to_string(),
                    "l" | "-listen_addr" => {
                        let Ok(addr) = key_value[1].parse() else {
                            println!("Invalid listen address");
                            return;
                        };

                        listen_addr = addr;
                    }
                    "p" | "-peer_addrs" => {
                        let Ok(addrs) = read_to_string(key_value[1]) else {
                            println!("No such file");
                            return;
                        };

                        peer_addrs = addrs
                            .split(' ')
                            .filter_map(|addr| addr.parse().ok())
                            .collect()
                    }
                    "m" | "-mine" => {
                        let Some(public_key) = PublicKey::from_hex(key_value[1]) else {
                            println!("Invalid public key for mining reward accrual");
                            return;
                        };

                        initial_mine_callback = Some({
                            let mine_handle = &mut mine_handle;
                            let should_mine = &mut should_mine;

                            move |blockchain: Weak<Blockchain>, net_driver: Weak<NetDriver>| {
                                start_mining(
                                    Arc::downgrade(mine_handle),
                                    Arc::downgrade(should_mine),
                                    blockchain,
                                    public_key,
                                    net_driver,
                                )
                            }
                        });
                    }
                    option => {
                        println!("Unknown option \"-{}\", use \"help\" to get help", option);
                        return;
                    }
                },
                _ => println!("Invalid number of arguments"),
            }
        }
    }

    // Initializing a Wallet
    let mut wallet = Wallet::new(wallet_save_path);

    // Initializing a NetDriver
    let net_driver = NetDriver::new(net_driver_save_path, listen_addr);

    // Initializing a Blockchain
    let blockchain = Arc::new(Blockchain::new(blockchain_save_path));

    {
        let net_driver =
            unsafe { &mut *(net_driver.as_ref() as *const NetDriver as *mut NetDriver) };

        // Setting the callback for the 'net_driver'
        net_driver.set_custom_message_handler(Some(Box::new({
            let blockchain = Arc::downgrade(&blockchain);
            move |connections, conn_index, msg| {
                let Some(blockchain) = blockchain.upgrade() else {
                    return;
                };
                let blockchain_ref =
                    unsafe { &mut *(blockchain.as_ref() as *const Blockchain as *mut Blockchain) };

                blockchain_ref.handle_message(connections, conn_index, msg);
            }
        })));

        // Adding peer addresses to connect read from the file
        if !peer_addrs.is_empty() {
            net_driver.add_connections(peer_addrs);
        }
    }

    start_updating_blockchain(Arc::downgrade(&blockchain), Arc::downgrade(&net_driver));

    // Initially starting mining if requested
    if let Some(initial_mine_callback) = initial_mine_callback {
        initial_mine_callback(Arc::downgrade(&blockchain), Arc::downgrade(&net_driver));
    }

    let net_driver_ref =
        unsafe { &mut *(net_driver.as_ref() as *const NetDriver as *mut NetDriver) };
    let blockchain_ref =
        unsafe { &mut *(blockchain.as_ref() as *const Blockchain as *mut Blockchain) };

    if !quiet {
        println!("Welcome to blockchain-cryptocurrency-practice!");
    } else {
        println!("Enter 'q' to quit");
    }

    // Main loop
    loop {
        if quiet {
            let input = readln(false);

            if input == "q" || input == "Q" {
                break;
            } else {
                continue;
            }
        }

        let input = readln(true);

        let command: Vec<_> = input.split(' ').collect();

        match command[0] {
            "h" | "help" => {
                println!("Commands:");
                println!("h, help                          Display this message");
                println!("q, quit                          Quit the program");
                println!("m, mine                          Mining process controls");
                println!("s, show                          Blockchain explorer");
                println!("t, transfer                      Coin transfer wizard");
                println!("    use with: [MODE]");
                println!("    [MODE] - manual | automatic");
                println!("w, wallet                        Wallet manager");
                println!("n, net                           Network manager");
                println!("Run \"[COMMAND]\" help to see additional help");
            }
            "q" | "quit" => break,
            "m" | "mine" => mine(
                Arc::downgrade(&mine_handle),
                Arc::downgrade(&should_mine),
                Arc::downgrade(&blockchain),
                &wallet,
                Arc::downgrade(&net_driver),
            ),
            "s" | "show" => show(&command[1..], blockchain_ref, &wallet),
            "t" | "transfer" => {
                coin_transfer_wizard(&command[1..], blockchain_ref, &wallet, net_driver_ref)
            }
            "w" | "wallet" => wallet_manager(&command[1..], &mut wallet),
            "n" | "net" => network_manager(&command[1..], net_driver_ref),
            option => println!("Unknown option \"{}\", use \"help\" to get help", option),
        }
    }

    if !quiet {
        println!("Quitting the program");
    }
}

fn mine(
    mine_handle: Weak<Option<JoinHandle<()>>>,
    should_mine: Weak<AtomicBool>,
    blockchain: Weak<Blockchain>,
    wallet: &Wallet,
    net_driver: Weak<NetDriver>,
) {
    let Some(should_mine_ref) = should_mine.upgrade() else {
        return;
    };
    let should_mine_ref = should_mine_ref.as_ref();

    // If the mining process is running already
    if should_mine_ref.load(Ordering::Relaxed) {
        println!("Are you sure you want to stop the mining process? Y/N");
        let decision = readln(false);

        if decision.len() != 1 {
            return;
        }

        if &decision[..1] != "y" && &decision[..1] != "Y" {
            return;
        }

        finish_mining(mine_handle, should_mine);
        println!("The mining process has just finished");
    } else {
        print!("Enter the hash or the index in the wallet of the public key for mining reward accrual: ");
        let _ = stdout().flush();
        let key_reference = readln(false);

        let public_key;

        if let Ok(key_index) = usize::from_str(&key_reference) {
            let Some(private_key) = wallet.get_key(key_index) else {
                println!("No key with such index");
                return;
            };

            public_key = private_key.get_public_key();
        } else if let Some(_public_key) = PublicKey::from_hex(&key_reference) {
            public_key = _public_key;
        } else {
            println!("Invalid public key index/hash");
            return;
        }

        start_mining(mine_handle, should_mine, blockchain, public_key, net_driver);
        println!("The mining process has just started");
    }
}

fn show(args: &[&str], blockchain: &mut Blockchain, wallet: &Wallet) {
    let Some(operation) = args.first().copied() else {
        println!("No operation specified");
        return;
    };

    match operation {
        "h" | "help" => {
            println!("Commands:");
            println!("h, help                          Display this message");
            println!("g, general                       Show general blockchain information");
            println!("b, block                         Show block");
            println!("    use with: [PART] [BLOCK]");
            println!("    [PART] - block part: header | transactions | full");
            println!("    [BLOCK] - block hash or height");
            println!("t, transaction                   Show transaction");
            println!("    use with: [TX] or [BLOCK] [TX_INDEX]");
            println!("    [TX] - tx hash");
            println!("    [BLOCK] - block hash or height");
            println!("    [TX_INDEX] - transaction index in the block");
            println!("o, utxo                          Show UTXO pool");
            println!("    use with: [OWNERSHIP]");
            println!("    [OWNERSHIP] - UTXO ownership: own | all");
            println!("u, utx                           Show UTX pool");
            println!("    use with: [OWNERSHIP]");
            println!("    [OWNERSHIP] - UTX ownership: own | all");
        }
        "g" | "general" => show_blockchain(blockchain),
        "b" | "block" => show_block(&args[1..], blockchain),
        "t" | "transaction" => show_tx(&args[1..], blockchain),
        "o" | "utxo" => show_utxo(&args[1..], blockchain, wallet),
        "u" | "utx" => show_utx(&args[1..], blockchain, wallet),
        option => println!("Unknown option \"{}\", use \"help\" to get help", option),
    }
}

fn show_blockchain(blockchain: &Blockchain) {
    let Some(current_height) = blockchain.get_height() else {
        println!("The local blockchain is empty");
        return;
    };

    println!("Last block height: {}", current_height);
    println!(
        "Last block hash:   {}",
        blockchain
            .get_block(current_height)
            .unwrap()
            .get_header()
            .hash()
            .obj2str(0, 0)
    );
    println!("Number of UTXOs:   {}", blockchain.get_utxo_pool().len());
    println!("Number of UTXs:    {}", blockchain.get_utx_pool().len());
}

fn show_block(args: &[&str], blockchain: &mut Blockchain) {
    let Some(part) = args.first().copied() else {
        println!("No block part specified");
        return;
    };

    let Some(block_reference) = args.get(1).copied() else {
        println!("No block height/hash specified");
        return;
    };

    let Some((block_height, block)) = get_block_by_reference(blockchain, block_reference) else {
        return;
    };

    let mut show_header = false;
    let mut show_txs = false;

    match part {
        "h" | "header" => show_header = true,
        "t" | "transactions" => show_txs = true,
        "f" | "full" => {
            show_header = true;
            show_txs = true;
        }
        option => println!("Unknown option \"{}\", use \"help\" to get help", option),
    }

    println!(
        "{} {}",
        block_height,
        block.get_header().hash().obj2str(0, 0)
    );
    if show_header {
        println!("{} ", block.get_header().obj2str(1, 1));
    }
    if show_txs {
        println!("{} ", block.get_txs().to_vec().obj2str(1, 5));
    }
}

fn show_tx(args: &[&str], blockchain: &mut Blockchain) {
    match args.len() {
        1 => {
            let Some(tx_hash) = args.first().copied() else {
                println!("No transaction hash specified");
                return;
            };

            let Ok(tx_hash) = tx_hash.try_into() else {
                println!("Invalid transaction hash");
                return;
            };

            let blockchain_db = blockchain.get_db_mut();

            let Some(current_height) = blockchain_db.get_height() else {
                println!("The local blockchain is empty");
                return;
            };

            let Some(tx) = Blockchain::get_tx(&blockchain_db, &tx_hash, current_height) else {
                println!("No transaction with such hash");
                return;
            };

            println!("{}", tx.hash().obj2str(0, 0));
            println!("{}", tx.obj2str(1, 4));
        }
        2 => {
            let Some(block_reference) = args.first().copied() else {
                println!("No height or hash of the block specified");
                return;
            };

            let Some(tx_index) = args.get(1).copied() else {
                println!("No transaction index specified");
                return;
            };

            let Ok(tx_index) = usize::from_str(tx_index) else {
                println!("Invalid transaction index");
                return;
            };

            let Some((_, block)) = get_block_by_reference(blockchain, block_reference) else {
                return;
            };

            let Some(tx) = block.get_txs().get(tx_index) else {
                println!("No transaction with such index");
                return;
            };

            println!("{}", tx.hash().obj2str(0, 0));
            println!("{}", tx.obj2str(1, 4));
        }
        _ => println!("Invalid number of arguments"),
    };
}

fn show_utxo(args: &[&str], blockchain: &mut Blockchain, wallet: &Wallet) {
    let Some(ownership) = args.first().copied() else {
        println!("No UTXO ownership specified");
        return;
    };

    let blockchain_db = blockchain.get_db_mut();

    let Some(current_height) = blockchain_db.get_height() else {
        println!("The local blockchain is empty");
        return;
    };

    let mut utxo_pool: Vec<_> = blockchain_db
        .get_utxo_pool()
        .iter()
        .filter_map(|output_ref| {
            let output = Blockchain::get_tx_output(&blockchain_db, output_ref, current_height)?;
            Some((output_ref.clone(), output))
        })
        .collect();

    match ownership {
        "o" | "own" => utxo_pool.retain({
            let public_keys = wallet.get_public_keys();
            |(_, output)| public_keys.contains(&output.public_key)
        }),
        "a" | "all" => (),
        option => println!("Unknown option \"{}\", use \"help\" to get help", option),
    }

    println!("{}", utxo_pool.obj2str(1, 3));
}

fn show_utx(args: &[&str], blockchain: &mut Blockchain, wallet: &Wallet) {
    let Some(ownership) = args.first().copied() else {
        println!("No UTX ownership specified");
        return;
    };

    let mut utx_pool = blockchain.get_utx_pool();

    match ownership {
        "o" | "own" => utx_pool.retain(|(tx, _)| tx.clone().sign(&blockchain.get_db_mut(), wallet)),
        "a" | "all" => (),
        option => println!("Unknown option \"{}\", use \"help\" to get help", option),
    }

    println!("{}", utx_pool.obj2str(1, 6));
}

fn coin_transfer_wizard(
    args: &[&str],
    blockchain: &mut Blockchain,
    wallet: &Wallet,
    net_driver: &mut NetDriver,
) {
    let Some(mode) = args.first().copied() else {
        println!("No mode specified");
        return;
    };

    match mode {
        "m" | "manual" => transfer_manual(blockchain, wallet, net_driver),
        "a" | "automatic" => transfer_automatic(blockchain, wallet, net_driver),
        option => println!("Unknown option \"{}\", use \"help\" to get help", option),
    }
}

fn transfer_manual(blockchain: &mut Blockchain, wallet: &Wallet, net_driver: &mut NetDriver) {
    println!("Coin transfer wizard: manual mode");
    println!("Remember to add change address output!");

    let mut tx = Tx {
        version: TX_VERSION,
        inputs: Vec::new(),
        outputs: Vec::new(),
    };

    loop {
        let input = readln(true);

        let command: Vec<_> = input.split(' ').collect();

        match command[0] {
            "h" | "help" => {
                println!("Commands:");
                println!("h, help                          Display this message");
                println!("q, quit                          Quit the coin transfer wizard");
                println!("i, input                         Add transaction input");
                println!("    use with: [TX] [INDEX]");
                println!("    [TX] - output transaction hash");
                println!("    [INDEX] - output index in the transaction");
                println!("o, output                        Add transaction output");
                println!("    use with: [AMOUNT] [PUBLIC_KEY]");
                println!("    [AMOUNT] - coin amount");
                println!("    [PUBLIC_KEY] - receiver's public key");
                println!("s, sign                          Sign and broadcast the transaction");
                println!("a, available                     Show available coins");
            }
            "q" | "quit" => {
                break;
            }
            "i" | "input" => {
                let Some(tx_hash) = command.get(1).copied() else {
                    println!("No output transaction hash specified");
                    continue;
                };

                let Some(output_index) = command.get(2).copied() else {
                    println!("No output index specified");
                    continue;
                };

                let Ok(tx_hash) = tx_hash.try_into() else {
                    println!("Invalid output transaction hash");
                    continue;
                };

                let Ok(output_index) = u32::from_str(output_index) else {
                    println!("Invalid output index");
                    continue;
                };

                tx.inputs.push(TxInput {
                    output_ref: TxOutputRef {
                        tx_hash,
                        output_index,
                    },
                    signature: None,
                });

                println!("The input has been added");
            }
            "o" | "output" => {
                let Some(amount) = command.get(1).copied() else {
                    println!("No coin amount specified");
                    continue;
                };

                let Some(public_key) = command.get(2).copied() else {
                    println!("No receiver's public key specified");
                    continue;
                };

                let Ok(amount) = f64::from_str(amount) else {
                    println!("Invalid coin amount");
                    continue;
                };
                let amount = (amount * CENTS_IN_COIN as f64) as u64;

                let Some(public_key) = PublicKey::from_hex(public_key) else {
                    println!("Invalid receiver's public key");
                    continue;
                };

                tx.outputs.push(TxOutput { amount, public_key });

                println!("The output has been added");
            }
            "s" | "sign" => {
                if tx.sign(&blockchain.get_db_mut(), wallet) {
                    blockchain.add_utx(tx.clone(), net_driver);
                    println!("The transaction has been signed and broadcast successfully");
                    println!(
                        "Wait at most {} blocks to be sure it is submitted",
                        MAX_ACCIDENTAL_FORK_HEIGHT
                    );
                } else {
                    println!("Cannot sign the transaction");
                    println!("Maybe it is invalid or maybe UTXOs are not valid anymore");
                }
                break;
            }
            "a" | "available" => {
                let cents = get_available_coin_amount(blockchain, wallet);
                let coins = cents as f64 / CENTS_IN_COIN as f64;
                println!("Available coin amount: {:.8}", coins);
            }
            option => println!("Unknown option \"{}\", use \"help\" to get help", option),
        }
    }

    println!("Quitting the coin transfer wizard");
}

fn transfer_automatic(blockchain: &mut Blockchain, wallet: &Wallet, net_driver: &mut NetDriver) {
    println!("Coin transfer wizard: automatic mode");

    let mut tx = Tx {
        version: TX_VERSION,
        inputs: Vec::new(),
        outputs: Vec::new(),
    };

    loop {
        let input = readln(true);

        let command: Vec<_> = input.split(' ').collect();

        match command[0] {
            "h" | "help" => {
                println!("Commands:");
                println!("h, help                          Display this message");
                println!("q, quit                          Quit the coin transfer wizard");
                println!("o, output                        Add transaction output");
                println!("    use with: [AMOUNT] [PUBLIC_KEY]");
                println!("    [AMOUNT] - coin amount");
                println!("    [PUBLIC_KEY] - receiver's public key");
                println!(
                    "s, sign                          Set fee, sign and broadcast the transaction"
                );
                println!("a, available                     Show available coins");
            }
            "q" | "quit" => {
                break;
            }
            "o" | "output" => {
                let Some(amount) = command.get(1).copied() else {
                    println!("No coin amount specified");
                    continue;
                };

                let Some(public_key) = command.get(2).copied() else {
                    println!("No receiver's public key specified");
                    continue;
                };

                let Ok(amount) = f64::from_str(amount) else {
                    println!("Invalid coin amount");
                    continue;
                };
                let amount = (amount * CENTS_IN_COIN as f64) as u64;

                let Some(public_key) = PublicKey::from_hex(public_key) else {
                    println!("Invalid receiver's public key");
                    continue;
                };

                tx.outputs.push(TxOutput { amount, public_key });

                println!("The output has been added");
            }
            "s" | "sign" => {
                let Some(current_height) = blockchain.get_height() else {
                    println!("The local blockchain is empty");
                    continue;
                };

                if tx.outputs.is_empty() {
                    println!("No transaction outputs");
                    continue;
                }

                print!("Enter transaction fee: ");
                let _ = stdout().flush();
                let fee = readln(false);

                let Ok(fee) = f64::from_str(&fee) else {
                    println!("Invalid coin amount");
                    continue;
                };
                let fee = (fee * CENTS_IN_COIN as f64) as u64;

                let output_amount =
                    tx.outputs.iter().map(|output| output.amount).sum::<u64>() + fee;

                let output_refs = select_inputs(&blockchain.get_db_mut(), wallet, output_amount);
                if output_refs.is_empty() {
                    println!("Not enough coins available");
                    continue;
                }

                for output_ref in output_refs {
                    tx.inputs.push(TxInput {
                        output_ref,
                        signature: None,
                    });
                }

                print!("Enter change address: ");
                let _ = stdout().flush();
                let public_key = readln(false);

                let Some(public_key) = PublicKey::from_hex(&public_key) else {
                    println!("Invalid change address");
                    continue;
                };

                let Some(current_fee) = tx.get_fee(&blockchain.get_db_mut(), current_height) else {
                    println!("There is more output amount than input");
                    continue;
                };

                let change_address_amount = current_fee - fee;

                if change_address_amount > 0 {
                    let change_address_output = TxOutput {
                        amount: change_address_amount,
                        public_key,
                    };

                    tx.outputs.push(change_address_output);
                }

                if tx.sign(&blockchain.get_db_mut(), wallet) {
                    blockchain.add_utx(tx.clone(), net_driver);
                    println!("The transaction has been signed and broadcast successfully");
                    println!(
                        "Wait at most {} blocks to be sure it is submitted",
                        MAX_ACCIDENTAL_FORK_HEIGHT
                    );
                } else {
                    println!("Cannot sign the transaction");
                    println!("Maybe it is invalid or maybe UTXOs are not valid anymore");
                }
                break;
            }
            "a" | "available" => {
                let cents = get_available_coin_amount(blockchain, wallet);
                let coins = cents as f64 / CENTS_IN_COIN as f64;
                println!("Available coin amount: {:.8}", coins);
            }
            option => println!("Unknown option \"{}\", use \"help\" to get help", option),
        }
    }

    println!("Quitting the coin transfer wizard");
}

fn wallet_manager(args: &[&str], wallet: &mut Wallet) {
    let Some(operation) = args.first().copied() else {
        println!("No operation specified");
        return;
    };

    match operation {
        "h" | "help" => {
            println!("Operations:");
            println!("h, help                          Display this message");
            println!("a, add                           Add a key to the wallet");
            println!("    use with: [KEY]");
            println!("    [KEY] - private key in HEX format,");
            println!("            random if not specified");
            println!("r, remove                        Remove the key from the wallet");
            println!("    use with: [INDEX]");
            println!("    [INDEX] - key index in the wallet");
            println!("s, show                          Show the whole wallet or a specific key");
            println!("    use with: [PART] [INDEX]");
            println!("    [PART] - key part: private, public, full");
            println!("    [INDEX] - key index in the wallet,");
            println!("              shows the whole wallet if not specified");
        }
        "a" | "add" => wallet_add(&args[1..], wallet),
        "r" | "remove" => wallet_remove(&args[1..], wallet),
        "s" | "show" => wallet_show(&args[1..], wallet),
        option => println!("Unknown option \"{}\", use \"help\" to get help", option),
    }
}

fn wallet_add(args: &[&str], wallet: &mut Wallet) {
    let private_key;

    if let Some(key_hash) = args.first().copied() {
        let Some(_private_key) = PrivateKey::from_hex(key_hash) else {
            println!("Invalid private key hash");
            return;
        };

        private_key = _private_key;
    } else {
        private_key = PrivateKey::random();
        println!("Successfully created a random key");
    }

    let index = wallet.get_key_number();
    if wallet.insert(index, private_key) {
        println!("Successfully inserted the key with the index of {}", index);
    } else {
        println!("An error has occurred");
    }
}

fn wallet_remove(args: &[&str], wallet: &mut Wallet) {
    let Some(key_index) = args.first().copied() else {
        println!("No key index specified");
        return;
    };

    println!("Are you sure you want to remove the key? Y/N");
    println!("It cannot be restored and your coins will be lost!");
    println!("Indices start from zero!");
    let decision = readln(false);

    if decision.len() != 1 {
        return;
    }

    if &decision[..1] != "y" && &decision[..1] != "Y" {
        return;
    }

    let Ok(key_index) = usize::from_str(key_index) else {
        println!("Invalid key index");
        return;
    };

    if wallet.remove(key_index) {
        println!("Successfully removed the key");
    } else {
        println!("No key with such index");
    }
}

fn wallet_show(args: &[&str], wallet: &mut Wallet) {
    let Some(part) = args.first().copied() else {
        println!("No key part specified");
        return;
    };

    let mut show_private = false;
    let mut show_public = false;

    match part {
        "priv" | "private" => show_private = true,
        "pub" | "public" => show_public = true,
        "f" | "full" => {
            show_private = true;
            show_public = true;
        }
        option => {
            println!("Unknown option \"{}\", use \"help\" to get help", option);
            return;
        }
    }

    if let Some(key_index) = args.get(1).copied() {
        let Ok(key_index) = usize::from_str(key_index) else {
            println!("Invalid key index");
            return;
        };

        let Some(private_key) = wallet.get_key(key_index) else {
            println!("No key with such index");
            return;
        };

        print!("{} ", key_index);
        if show_private {
            print!("{} ", private_key.obj2str(0, 0));
        }
        if show_public {
            print!("{} ", private_key.get_public_key().obj2str(0, 0));
        }
        println!();
    } else {
        let private_keys = wallet.get_private_keys();

        if private_keys.is_empty() {
            println!("The wallet is empty");
        } else {
            for (key_index, private_key) in private_keys.iter().enumerate() {
                print!("{} ", key_index);
                if show_private {
                    print!("{} ", private_key.obj2str(0, 0));
                }
                if show_public {
                    print!("{} ", private_key.get_public_key().obj2str(0, 0));
                }
                println!();
            }
        }
    }
}

fn network_manager(args: &[&str], net_driver: &mut NetDriver) {
    let Some(operation) = args.first().copied() else {
        println!("No operation specified");
        return;
    };

    match operation {
        "h" | "help" => {
            println!("Operations:");
            println!("h, help                          Display this message");
            println!("a, add                           Add peer connections");
            println!("    use with: [ADDRS]");
            println!("    [ADDRS] - peer addresses separated by spaces");
            println!("r, remove                        Remove peer connections");
            println!("    use with: [ADDRS]");
            println!("    [ADDRS] - peer addresses separated by spaces");
            println!("s, show                          Show peer connections");
        }
        "a" | "add" => net_add(&args[1..], net_driver),
        "r" | "remove" => net_remove(&args[1..], net_driver),
        "s" | "show" => net_show(net_driver),
        option => println!("Unknown option \"{}\", use \"help\" to get help", option),
    }
}

fn net_add(args: &[&str], net_driver: &mut NetDriver) {
    if args.is_empty() {
        println!("No addresses specified");
        return;
    };

    let addrs = args.iter().filter_map(|addr| addr.parse().ok()).collect();

    net_driver.add_connections(addrs);
}

fn net_remove(args: &[&str], net_driver: &mut NetDriver) {
    if args.is_empty() {
        println!("No addresses specified");
        return;
    };

    let addrs = args.iter().filter_map(|addr| addr.parse().ok()).collect();

    net_driver.remove_connections(addrs);
}

fn net_show(net_driver: &NetDriver) {
    let addrs = net_driver.get_addresses();
    if addrs.is_empty() {
        println!("No connections");
    } else {
        for addr in addrs {
            print!("{} ", addr)
        }
        println!();
    }
}

fn get_block_by_reference(
    blockchain: &mut Blockchain,
    block_reference: &str,
) -> Option<(u32, Block)> {
    if let Ok(block_height) = u32::from_str(block_reference) {
        if let Some(block) = blockchain.get_block(block_height) {
            Some((block_height, block))
        } else {
            println!("No block with such height");
            None
        }
    } else if let Ok(block_hash) = block_reference.try_into() {
        let block_height = blockchain
            .get_db_mut()
            .find_block_rev(|block| block.get_header().hash() == block_hash);
        if let Some(block_height) = block_height {
            blockchain
                .get_block(block_height)
                .map(|block| (block_height, block))
        } else {
            println!("No block with such hash");
            None
        }
    } else {
        println!("Invalid block height/hash");
        None
    }
}

fn start_updating_blockchain(blockchain: Weak<Blockchain>, net_driver: Weak<NetDriver>) {
    spawn(move || loop {
        sleep(Duration::from_secs(10));

        let Some(net_driver) = net_driver.upgrade() else {
            return;
        };
        let net_driver_ref =
            unsafe { &mut *(net_driver.as_ref() as *const NetDriver as *mut NetDriver) };

        let Some(blockchain) = blockchain.upgrade() else {
            return;
        };
        let blockchain_ref =
            unsafe { &mut *(blockchain.as_ref() as *const Blockchain as *mut Blockchain) };

        // It is crucial to lock 'connections' before 'db' to avoid deadlock.
        let mut connections = net_driver_ref.get_connections_mut();
        let blockchain_db = blockchain_ref.get_db_mut();

        // Requesting latest blocks
        {
            let hash = Blockchain::get_oldest_accidental_fork_block_hash(&blockchain_db);
            Blockchain::request_block_download(&mut connections, hash);
        }

        // Requesting latest unrecorded transactions
        {
            if let Some(block) = blockchain_db.get_last_block() {
                let hash = block.get_header().hash();
                Blockchain::request_tx_download(&mut connections, hash);
            }
        }
    });
}

fn start_mining(
    mine_handle: Weak<Option<JoinHandle<()>>>,
    should_mine: Weak<AtomicBool>,
    blockchain: Weak<Blockchain>,
    public_key: PublicKey,
    net_driver: Weak<NetDriver>,
) {
    let Some(should_mine_ref) = should_mine.upgrade() else {
        return;
    };
    let should_mine_ref = should_mine_ref.as_ref();
    should_mine_ref.store(true, Ordering::Relaxed);

    let Some(mine_handle) = mine_handle.upgrade() else {
        return;
    };
    let mine_handle_ref = unsafe {
        &mut *(mine_handle.as_ref() as *const Option<JoinHandle<()>> as *mut Option<JoinHandle<()>>)
    };

    let _ = mine_handle_ref.insert(spawn(move || {
        loop {
            let Some(should_mine) = should_mine.upgrade() else {
                return;
            };
            let should_mine_ref = should_mine.as_ref();

            let Some(net_driver) = net_driver.upgrade() else {
                return;
            };
            let net_driver_ref =
                unsafe { &mut *(net_driver.as_ref() as *const NetDriver as *mut NetDriver) };

            let Some(blockchain) = blockchain.upgrade() else {
                return;
            };
            let blockchain_ref =
                unsafe { &mut *(blockchain.as_ref() as *const Blockchain as *mut Blockchain) };

            // If should mine
            if should_mine_ref.load(Ordering::Relaxed) {
                // Mining and breaking if don't need to restart
                if !blockchain_ref.mine(should_mine_ref, public_key.clone(), net_driver_ref) {
                    break;
                }
            }
        }
    }));
}

fn finish_mining(mine_handle: Weak<Option<JoinHandle<()>>>, should_mine: Weak<AtomicBool>) {
    let Some(should_mine) = should_mine.upgrade() else {
        return;
    };

    let Some(mine_handle) = mine_handle.upgrade() else {
        return;
    };
    let mine_handle_ref = unsafe {
        &mut *(mine_handle.as_ref() as *const Option<JoinHandle<()>> as *mut Option<JoinHandle<()>>)
    };

    should_mine.store(false, Ordering::Relaxed);
    if let Some(mine_handle) = mine_handle_ref.take() {
        let _ = mine_handle.join();
    }
}
