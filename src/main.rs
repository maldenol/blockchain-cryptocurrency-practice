mod block;
mod consts;
mod digsig;
mod hash;
mod merkle;
mod netdriver;
mod tx;
mod wallet;

use std::thread::sleep;
use std::time::Duration;

use crate::consts::{MAX_CONNECTION_NUMBER, MIN_CONNECTION_NUMBER};
use netdriver::NetDriver;

fn main() {
    const INSTANCE_NUMBER: usize = 10;
    const ITERATION_NUMBER: usize = 20;

    let mut net_drivers = Vec::new();

    print!("Initializing NetDrivers: ");
    for index in 0..INSTANCE_NUMBER {
        let net_driver = NetDriver::new(format!("127.0.0.1:80{:02}", index).parse().unwrap());
        net_drivers.push(net_driver);
        print!("{:02} ", index);
    }
    println!();

    print!("Providing NetDrivers with connection addresses: ");
    for (index, net_driver) in net_drivers.iter_mut().enumerate() {
        // Example 1 (fully linked)
        // for inner_index in 0..INSTANCE_NUMBER {
        //     net_driver.add_connections(vec![format!("127.0.0.1:80{:02}", inner_index).parse().unwrap()]);
        // }
        // Example 2 (first fully linked)
        // for inner_index in 0..(if index == 0 { INSTANCE_NUMBER } else { 1 }) {
        //     net_driver.add_connections(vec![format!("127.0.0.1:80{:02}", inner_index).parse().unwrap()]);
        // }
        // Example 3 (first fully linked)
        // for inner_index in 0..(if index == 0 { INSTANCE_NUMBER } else { 0 }) {
        //     net_driver.add_connections(vec![format!("127.0.0.1:80{:02}", inner_index).parse().unwrap()]);
        // }
        // Example 4 (linked chain, try several times, it shows the result the best)
        net_driver.add_connections(vec![format!("127.0.0.1:80{:02}", index + 1)
            .parse()
            .unwrap()]);
        print!("{:02} ", index);
    }
    println!();

    println!(
        "Number of connections of each NetDriver (must be {} <= n <= {}):",
        usize::min(MIN_CONNECTION_NUMBER, INSTANCE_NUMBER - 1),
        usize::min(MAX_CONNECTION_NUMBER, INSTANCE_NUMBER - 1),
    );
    for _ in 0..ITERATION_NUMBER {
        sleep(Duration::from_secs(1));
        for net_driver in net_drivers.iter() {
            print!("{:02} ", net_driver.get_connection_number());
        }
        println!();
    }
}
