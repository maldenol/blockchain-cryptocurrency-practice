//! P2P network driver.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex, MutexGuard,
};
use std::thread::{sleep, spawn, JoinHandle};
use std::time::{Duration, Instant};

use bincode::{deserialize, serialize};
use rand::random;
use serde_derive::{Deserialize, Serialize};

use crate::consts::*;
use crate::database::NetDriverDB;

/// P2P network driver.
pub struct NetDriver {
    is_running: AtomicBool,
    connect_thr: Option<JoinHandle<()>>,
    listen_thr: Option<JoinHandle<()>>,
    respond_thr: Option<JoinHandle<()>>,
    listener: TcpListener,
    /// The ID of the 'NetDriver'.
    id: u32,
    connections: Mutex<Vec<Connection>>,
    /// Addresses of peers to connect to.
    addresses_to_connect: Mutex<Vec<SocketAddr>>,
    custom_message_handler: Mutex<Option<CustomMessageHandler>>,
    db: NetDriverDB,
}

/// P2P connection.
pub struct Connection {
    socket: TcpStream,
    port: u16,
    id: u32,
    alive: bool,
}

/// Network message.
#[derive(Serialize, Deserialize)]
enum NetMsg {
    AddressesRequest,
    AddressesResponse(Vec<SocketAddr>),
    Custom(Vec<u8>),
}

type CustomMessageHandler = Box<dyn FnMut(&mut [Connection], usize, Vec<u8>)>;

impl NetDriver {
    /// Returns a newly created 'NetDriver'.
    pub fn new(db_path: String, listen_addr: SocketAddr) -> Box<Self> {
        let mut net_driver = Box::new(NetDriver {
            is_running: AtomicBool::new(true),
            connect_thr: None,
            listen_thr: None,
            respond_thr: None,
            listener: TcpListener::bind(listen_addr).unwrap(),
            id: random::<u32>(),
            connections: Mutex::new(Vec::new()),
            addresses_to_connect: Mutex::new(Vec::new()),
            custom_message_handler: Mutex::new(None),
            db: NetDriverDB::new(db_path),
        });

        // Making the listener non-blocking
        loop {
            if net_driver.listener.set_nonblocking(true).is_ok() {
                break;
            }
        }

        // Spawning a connecting, a listening and a responding threads
        let net_driver_ptr = net_driver.as_mut() as *mut NetDriver as usize;
        net_driver.connect_thr = Some(spawn({
            let net_driver_ptr = net_driver_ptr;
            move || {
                let net_driver = unsafe { &mut *(net_driver_ptr as *mut NetDriver) };
                net_driver.connect();
            }
        }));
        net_driver.listen_thr = Some(spawn({
            let net_driver_ptr = net_driver_ptr;
            move || {
                let net_driver = unsafe { &mut *(net_driver_ptr as *mut NetDriver) };
                net_driver.listen();
            }
        }));
        net_driver.respond_thr = Some(spawn({
            let net_driver_ptr = net_driver_ptr;
            move || {
                let net_driver = unsafe { &mut *(net_driver_ptr as *mut NetDriver) };
                net_driver.respond();
            }
        }));

        // Loading and adding saved addresses of peers
        if let Some(addrs) = net_driver.db.load() {
            net_driver.add_connections(addrs);
        }

        net_driver
    }

    /// Adds addresses of the peers to connect to.
    fn _add_connections(
        addresses_to_connect: &mut Vec<SocketAddr>,
        listener: &TcpListener,
        mut addrs: Vec<SocketAddr>,
    ) {
        // Checking if the addrs are not empty
        if addrs.is_empty() {
            return;
        }

        // Removing own addresses
        let local_addr = listener.local_addr().unwrap();
        addrs.retain(|addr| *addr != local_addr);

        // Removing duplicates
        addrs.sort_unstable();
        addrs.dedup();

        // Adding addresses to the vector for the connecting thread to connect to
        addresses_to_connect.append(&mut addrs);

        // Sorting the vector and removing duplicates
        addresses_to_connect.sort_unstable();
        addresses_to_connect.dedup();
    }

    /// Public variant of the private method.
    pub fn add_connections(&mut self, addrs: Vec<SocketAddr>) {
        let mut addresses_to_connect = self.addresses_to_connect.lock().unwrap();

        NetDriver::_add_connections(&mut addresses_to_connect, &self.listener, addrs);
    }

    /// Returns the connections.
    pub fn get_connections_mut(&mut self) -> MutexGuard<Vec<Connection>> {
        self.connections.lock().unwrap()
    }

    /// Returns the number of connections.
    pub fn get_connection_number(&self) -> usize {
        self.connections.lock().unwrap().len()
    }

    /// Connects to peers.
    fn connect(&mut self) {
        while self.is_running.load(Ordering::Relaxed) {
            let mut addrs = Vec::new();

            // Getting addresses to connect to
            {
                let mut addrs_to_connect = self.addresses_to_connect.lock().unwrap();

                if addrs_to_connect.is_empty() {
                    continue;
                }

                addrs.append(&mut *addrs_to_connect);
            }

            // For each address
            for addr in addrs {
                // If connected successfully
                if let Ok(mut conn) = TcpStream::connect_timeout(&addr, NET_CONNECT_TIMEOUT) {
                    // Setting read and write timeouts for the connection
                    conn.set_read_timeout(Some(NET_READ_TIMEOUT)).unwrap();
                    conn.set_write_timeout(Some(NET_WRITE_TIMEOUT)).unwrap();

                    // Sending this NetDriver's ID
                    let own_id = self.id.to_be_bytes();
                    if NetDriver::wait_send(&mut conn, &own_id).is_err() {
                        continue;
                    }

                    // Receiving the other NetDriver's ID
                    let mut other_id = [0u8; 4];
                    match NetDriver::wait_receive(&mut conn, &mut other_id) {
                        Ok(success) => {
                            if !success {
                                continue;
                            }
                        }
                        Err(()) => {
                            continue;
                        }
                    }
                    let other_id = u32::from_be_bytes(other_id);

                    let mut connections = self.connections.lock().unwrap();

                    // Checking if the number of connections is not exceeded
                    let connection_number = connections.len();
                    if connection_number > MAX_CONNECTION_NUMBER {
                        break;
                    }

                    // If the other NetDriver's ID doesn't equal to the ID of this one
                    // and there is no connection with the other NetDriver yet
                    if other_id != self.id
                        && !connections
                            .iter()
                            .any(|Connection { id: conn_id, .. }| *conn_id == other_id)
                    {
                        // Sending this NetDriver's listening port
                        let own_listen_port =
                            self.listener.local_addr().unwrap().port().to_be_bytes();
                        if NetDriver::wait_send(&mut conn, &own_listen_port).is_err() {
                            continue;
                        }

                        let other_listen_port = addr.port();

                        // Adding the connection
                        connections.push(Connection {
                            socket: conn,
                            port: other_listen_port,
                            id: other_id,
                            alive: true,
                        });
                    }
                }
            }
        }

        sleep(Duration::from_millis(10));
    }

    /// Listens for new connections.
    fn listen(&mut self) {
        while self.is_running.load(Ordering::Relaxed) {
            let begin = Instant::now();

            // Accepting an incoming connection
            for conn in self.listener.incoming() {
                match conn {
                    Ok(mut conn) => {
                        // Setting read and write timeouts for the connection
                        conn.set_read_timeout(Some(NET_READ_TIMEOUT)).unwrap();
                        conn.set_write_timeout(Some(NET_WRITE_TIMEOUT)).unwrap();

                        // Receiving the other NetDriver's ID
                        let mut other_id = [0u8; 4];
                        match NetDriver::wait_receive(&mut conn, &mut other_id) {
                            Ok(success) => {
                                if !success {
                                    continue;
                                }
                            }
                            Err(()) => {
                                continue;
                            }
                        }
                        let other_id = u32::from_be_bytes(other_id);

                        let mut connections = self.connections.lock().unwrap();

                        // Checking if the number of connections is not exceeded
                        let connection_number = connections.len();
                        if connection_number > MAX_CONNECTION_NUMBER {
                            break;
                        }

                        // If the other NetDriver's ID doesn't equal to the ID of this one
                        // and there is no connection with the other NetDriver yet
                        if other_id != self.id
                            && !connections
                                .iter()
                                .any(|Connection { id: conn_id, .. }| *conn_id == other_id)
                        {
                            // Sending this NetDriver's ID
                            let own_id = self.id.to_be_bytes();
                            if NetDriver::wait_send(&mut conn, &own_id).is_err() {
                                continue;
                            }

                            // Sending the other NetDriver's listening port
                            let mut other_listen_port = [0u8; 2];
                            match NetDriver::wait_receive(&mut conn, &mut other_listen_port) {
                                Ok(success) => {
                                    if !success {
                                        continue;
                                    }
                                }
                                Err(()) => {
                                    continue;
                                }
                            }
                            let other_listen_port = u16::from_be_bytes(other_listen_port);

                            // Adding the connection
                            connections.push(Connection {
                                socket: conn,
                                port: other_listen_port,
                                id: other_id,
                                alive: true,
                            });
                        }
                    }
                    Err(err) => {
                        let now = Instant::now();
                        let elapsed = now - begin;

                        // If there is an error (other than the signaling for connection absence one)
                        // or the listening timed out
                        if err.kind() != ErrorKind::WouldBlock || elapsed >= NET_LISTEN_TIMEOUT {
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Responds to connections.
    fn respond(&mut self) {
        let mut msg = vec![0; MAX_NET_DATA_SIZE];

        while self.is_running.load(Ordering::Relaxed) {
            let mut connections = self.connections.lock().unwrap();

            // For each connection
            for conn_index in 0..connections.len() {
                // If a message has been received
                if NetDriver::receive(&mut connections, conn_index, &mut msg) {
                    // If the message has been deserialized correctly
                    if let Ok(msg) = deserialize(&msg) {
                        // Handling the message based on its type
                        match msg {
                            NetMsg::AddressesRequest => NetDriver::handle_addresses_request(
                                &mut connections,
                                &self.listener,
                                conn_index,
                            ),
                            NetMsg::AddressesResponse(addrs) => {
                                let mut addresses_to_connect =
                                    self.addresses_to_connect.lock().unwrap();
                                NetDriver::handle_addresses_response(
                                    &mut connections,
                                    &mut addresses_to_connect,
                                    &self.listener,
                                    addrs,
                                )
                            }
                            NetMsg::Custom(msg) => NetDriver::handle_custom_message(
                                &self.custom_message_handler,
                                &mut connections,
                                conn_index,
                                msg,
                            ),
                        }
                    }
                }
            }

            // Updating connections
            NetDriver::update_connections(&mut connections);
        }
    }

    /// Removes bad connections and requests new ones if needed.
    fn update_connections(connections: &mut Vec<Connection>) {
        // Removing bad connections
        connections.retain(|conn| conn.alive);

        // If there are not enough connections
        let connection_number = connections.len();
        if connection_number < MIN_CONNECTION_NUMBER {
            // Requesting addresses to connect to
            NetDriver::request_addresses(connections);
        }
    }

    /// Broadcasts a message.
    fn broadcast(connections: &mut [Connection], msg: &[u8]) {
        // Getting the size of the message
        let msg_size = msg.len() as u32;
        let msg_size = msg_size.to_be_bytes();

        // For each connection
        for conn in connections.iter_mut() {
            // Sending the size of the message
            if NetDriver::wait_send(&mut conn.socket, msg_size.as_slice()).is_err() {
                conn.alive = false;
                continue;
            }

            // Sending the message
            if NetDriver::wait_send(&mut conn.socket, msg).is_err() {
                conn.alive = false;
                continue;
            }
        }
    }

    /// Sends a message.
    fn send(connections: &mut [Connection], conn_index: usize, msg: &[u8]) {
        let conn = &mut connections[conn_index];

        // Getting the size of the message
        let msg_size = msg.len() as u32;
        let msg_size = msg_size.to_be_bytes();

        // Sending the size of the message
        if NetDriver::wait_send(&mut conn.socket, msg_size.as_slice()).is_err() {
            // Removing the connection on failure
            conn.alive = false;
            return;
        }

        // Sending the message
        if NetDriver::wait_send(&mut conn.socket, msg).is_err() {
            // Removing the connection on failure
            conn.alive = false;
        }
    }

    /// Receives a message.
    fn receive(connections: &mut [Connection], conn_index: usize, msg: &mut [u8]) -> bool {
        let conn = &mut connections[conn_index];

        // Receiving the size of the message
        let mut msg_size = [0; 4];
        match NetDriver::try_receive(&mut conn.socket, &mut msg_size) {
            Ok(success) => {
                if !success {
                    return false;
                }
            }
            Err(()) => {
                // Removing the connection on failure
                conn.alive = false;
                return false;
            }
        }
        let msg_size = u32::from_be_bytes(msg_size) as usize;

        // Checking if the size of the message is not exceeded
        if msg_size > MAX_NET_DATA_SIZE {
            return false;
        }

        // Receiving the message
        let msg = &mut msg[..msg_size];
        match NetDriver::wait_receive(&mut conn.socket, msg) {
            Ok(success) => success,
            Err(()) => {
                // Removing the connection on failure
                conn.alive = false;
                false
            }
        }
    }

    /// Sends a message and waits if needed.
    fn wait_send(conn: &mut TcpStream, msg: &[u8]) -> Result<(), ()> {
        if conn.write_all(msg).is_ok() {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Receives a message and waits if needed.
    fn wait_receive(conn: &mut TcpStream, msg: &mut [u8]) -> Result<bool, ()> {
        let begin = Instant::now();

        loop {
            match conn.read_exact(msg) {
                Ok(_) => {
                    break Ok(true);
                }
                Err(err) => {
                    // If there is an error (other than the signaling for connection absence one)
                    if err.kind() != ErrorKind::WouldBlock {
                        break Err(());
                    } else {
                        let now = Instant::now();
                        let elapsed = now - begin;

                        // If the reading timed out
                        if elapsed >= NET_READ_TIMEOUT {
                            break Ok(false);
                        }
                    }
                }
            }
        }
    }

    /// Tries to receive a message without waiting.
    fn try_receive(conn: &mut TcpStream, msg: &mut [u8]) -> Result<bool, ()> {
        match conn.read_exact(msg) {
            Ok(_) => Ok(true),
            Err(err) => {
                // If there are no errors (other than the signaling for connection absence one)
                if err.kind() == ErrorKind::WouldBlock {
                    Ok(false)
                } else {
                    Err(())
                }
            }
        }
    }

    /// Requests addresses of peers to connect to.
    fn request_addresses(connections: &mut [Connection]) {
        let msg = NetMsg::AddressesRequest;
        let msg = serialize(&msg).unwrap();
        NetDriver::broadcast(connections, &msg);
    }

    /// Broadcasts a custom message.
    pub fn broadcast_custom_message(connections: &mut [Connection], msg: Vec<u8>) {
        let msg = NetMsg::Custom(msg);
        let msg = serialize(&msg).unwrap();

        // Checking that the size of the message is not exceeded
        if msg.len() > MAX_NET_DATA_SIZE {
            return;
        }

        NetDriver::broadcast(connections, &msg);
    }

    /// Sends a custom message.
    pub fn send_custom_message(connections: &mut [Connection], conn_index: usize, msg: Vec<u8>) {
        let msg = NetMsg::Custom(msg);
        let msg = serialize(&msg).unwrap();

        // Checking that the size of the message is not exceeded
        if msg.len() > MAX_NET_DATA_SIZE {
            return;
        }

        NetDriver::send(connections, conn_index, &msg);
    }

    /// Handles a peer addresses request.
    fn handle_addresses_request(
        connections: &mut [Connection],
        listener: &TcpListener,
        conn_index: usize,
    ) {
        // Getting addresses for the requesting NetDriver to connect to
        // excluding this NetDriver's and the other NetDriver's addresses
        let mut addrs: Vec<_> = connections
            .iter()
            .filter_map({
                let own_addr = listener.local_addr().unwrap();
                let own_ip = own_addr.ip();
                let own_port = own_addr.port();

                let other_conn = &connections[conn_index].socket;
                let other_addr = other_conn.peer_addr().unwrap();
                let other_ip = other_addr.ip();
                let other_port = connections[conn_index].port;

                move |Connection {
                          socket: conn, port, ..
                      }| {
                    let ip = conn.peer_addr().unwrap().ip();
                    if ip == own_ip && *port == own_port || ip == other_ip && *port == other_port {
                        None
                    } else {
                        Some(SocketAddr::new(ip, *port))
                    }
                }
            })
            .collect();

        // Checking if addrs are not empty
        if addrs.is_empty() {
            return;
        }

        let msg = NetMsg::AddressesResponse(addrs.clone());
        let mut msg = serialize(&msg).unwrap();

        // Making sure that the size of the message is not exceeded
        while msg.len() > MAX_NET_DATA_SIZE {
            let _ = addrs.pop();

            let new_msg = NetMsg::AddressesResponse(addrs.clone());
            msg = serialize(&new_msg).unwrap();
        }

        NetDriver::send(connections, conn_index, &msg);
    }

    /// Handles a peer addresses response.
    fn handle_addresses_response(
        connections: &mut [Connection],
        addresses_to_connect: &mut Vec<SocketAddr>,
        listener: &TcpListener,
        addrs: Vec<SocketAddr>,
    ) {
        // If addrs are not empty
        // and there are not enough connections
        let connection_number = connections.len();
        if !addrs.is_empty() && connection_number < MIN_CONNECTION_NUMBER {
            // Adding addresses to connect to
            NetDriver::_add_connections(addresses_to_connect, listener, addrs);
        }
    }

    /// Handles a custom message.
    fn handle_custom_message(
        custom_message_handler: &Mutex<Option<CustomMessageHandler>>,
        connections: &mut [Connection],
        conn_index: usize,
        msg: Vec<u8>,
    ) {
        // If the custom message handler callback is set
        if let Some(custom_message_handler) = custom_message_handler.lock().unwrap().as_mut() {
            // Pass the message to the custom message handler callback
            (custom_message_handler)(connections, conn_index, msg);
        }
    }

    /// Sets a custom messages handler.
    pub fn set_custom_message_handler(
        &mut self,
        custom_message_handler: Option<CustomMessageHandler>,
    ) {
        *self.custom_message_handler.lock().unwrap() = custom_message_handler;
    }
}

impl Drop for NetDriver {
    /// Joins the running threads and saves addresses of the peers.
    fn drop(&mut self) {
        // Joining the connecting, the listening and the responding threads
        self.is_running.store(false, Ordering::Relaxed);
        let _ = self.connect_thr.take().unwrap().join();
        let _ = self.listen_thr.take().unwrap().join();
        let _ = self.respond_thr.take().unwrap().join();

        // Saving addresses of the peers
        let addrs = self
            .connections
            .lock()
            .unwrap()
            .iter()
            .map(
                |Connection {
                     socket: conn, port, ..
                 }| {
                    (conn.peer_addr().unwrap().ip().to_string() + ":" + port.to_string().as_str())
                        .parse()
                        .unwrap()
                },
            )
            .collect();
        self.db.save(&addrs);
    }
}
