# blockchain-cryptocurrency-practice
blockchain-cryptocurrency-practice is a first generation cryptocurrency blockchain
written in Rust for educational purposes.  
It is very similar to the Bitcoin protocol, but is simpler or different in some cases.

## What have been done
 - Blockchain
   - PoW consensus mechanism (mining).
     - Difficulty adjustment.
   - Block reward halving.
   - Block hashing, mining and validation.
   - Transaction hashing, signing and verifying.
   - Block and transaction broadcasting.
   - Accidental and intentional forks handling.
   - etc.
 - Wallet - storage for private and public keys.
 - NetDriver - driver for P2P network
   - The network is self-expandable.
 - Database - module that saves and loads all the listed objects.
   - Blocks are saved in multiple files, or clusters.
 - Command line client - command line options and user interface.
   - Use '--help' for additional information.

## What could be better
This project is made for educational purposes only.  
Some things could be done better or in differently, some things have not been done at all,
but I don't intent to spend my whole life making it production-ready.  
Each vital blockchain component has its basic or even robust version implemented
so the goal of the project was achieved.

Here are some things that have not been done:
 - Protocol
   - There are no block limit, no Sig and PubKey scripts like in Bitcoin,
     only P2PK is supported.
 - Network
   - There are a lot of DDoS attack possibilities in the network architecture
     and that is okay, because networking is not a part of blockchain technology at all.
 - Database
   - Databases open and close for each block access, which is not performant.
   - UTXO pool can be saved efficiently in as a hash map rather than a vector.
   - Environmental errors are not handled.
   - There is no validation or correction of corrupted saved data.
 - Mining
   - There are no mining optimizations such as SHA-256 first block optimization and SIMD,
     multithreading and GPU computing, and that is okay because of two reasons:
     firstly, Proof-of-Work is the one of many consensus mechanisms and is not
     the main focus of the project, and, secondly, ASICs exist.
 - Tests
   - There are no tests at all and that is okay, because the project is not meant
     to be developed any further and all the cases (hopefully)
     were tested during the development.

## License
blockchain-cryptocurrency-practice is licensed under the MIT License, see [LICENSE](LICENSE) for more information.
