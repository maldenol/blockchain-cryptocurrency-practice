//! P2P network driver.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::thread::{spawn, JoinHandle};
use std::time::Instant;

use bincode::{deserialize, serialize};
use rand::random;
use serde_derive::{Deserialize, Serialize};

use semaphore::{Semaphore, SemaphoreGuard};

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
    /// The tuple of a connection with some peer, the peer's listening port and ID.
    connections: Vec<(TcpStream, u16, u32)>,
    connections_mtx: Semaphore,
    /// Indexes of bad connections.
    connections_to_remove: Vec<usize>,
    /// Addresses of peers to connect to.
    addresses_to_connect: Mutex<Vec<SocketAddr>>,
    custom_message_handler: Mutex<Option<CustomMessageHandler>>,
    db: NetDriverDB,
}

/// Network message.
#[derive(Serialize, Deserialize)]
enum NetMsg {
    AddressesRequest,
    AddressesResponse(Vec<SocketAddr>),
    Custom(Vec<u8>),
}

type CustomMessageHandler = Box<dyn FnMut(usize, Vec<u8>)>;

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
            connections: Vec::new(),
            connections_mtx: Semaphore::new(1),
            connections_to_remove: Vec::new(),
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
    /// Thread-safe.
    pub fn add_connections(&mut self, mut addrs: Vec<SocketAddr>) {
        // Checking if the addrs are not empty
        if addrs.is_empty() {
            return;
        }

        // Removing own addresses
        let local_addr = self.listener.local_addr().unwrap();
        addrs.retain(|addr| *addr != local_addr);

        // Removing duplicates
        addrs.sort_unstable();
        addrs.dedup();

        {
            let mut addrs_to_connect = self.addresses_to_connect.lock().unwrap();

            // Adding addresses to the vector for the connecting thread to connect to
            addrs_to_connect.append(&mut addrs);

            // Sorting the vector and removing duplicates
            addrs_to_connect.sort_unstable();
            addrs_to_connect.dedup();
        }
    }

    /// Returns the number of connections.
    /// Thread-unsafe.
    pub fn get_connection_number(&self) -> usize {
        self.connections.len()
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

                    // Acquiring read-write access to the connections
                    let _connections_mtx = SemaphoreGuard::acquire(&self.connections_mtx);

                    // Checking if the number of connections is not exceeded
                    let connection_number = self.connections.len();
                    if connection_number > MAX_CONNECTION_NUMBER {
                        break;
                    }

                    // If the other NetDriver's ID doesn't equal to the ID of this one
                    // and there is no connection with the other NetDriver yet
                    if other_id != self.id
                        && !self
                            .connections
                            .iter()
                            .any(|(_, _, conn_id)| *conn_id == other_id)
                    {
                        // Sending this NetDriver's listening port
                        let own_listen_port =
                            self.listener.local_addr().unwrap().port().to_be_bytes();
                        if NetDriver::wait_send(&mut conn, &own_listen_port).is_err() {
                            continue;
                        }

                        let other_listen_port = addr.port();

                        // Adding the connection
                        self.connections.push((conn, other_listen_port, other_id));
                    }
                }
            }
        }
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

                        // Acquiring read-write access to the connections
                        let _connections_mtx = SemaphoreGuard::acquire(&self.connections_mtx);

                        // Checking if the number of connections is not exceeded
                        let connection_number = self.connections.len();
                        if connection_number > MAX_CONNECTION_NUMBER {
                            break;
                        }

                        // If the other NetDriver's ID doesn't equal to the ID of this one
                        // and there is no connection with the other NetDriver yet
                        if other_id != self.id
                            && !self
                                .connections
                                .iter()
                                .any(|(_, _, conn_id)| *conn_id == other_id)
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
                            self.connections.push((conn, other_listen_port, other_id));
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
            // Acquiring read-write access to the connections
            self.connections_mtx.acquire();

            // For each connection
            for conn_index in 0..self.connections.len() {
                // If a message has been received
                if self.receive(conn_index, &mut msg) {
                    // If the message has been deserialized correctly
                    if let Ok(msg) = deserialize(&msg) {
                        // Handling the message based on its type
                        match msg {
                            NetMsg::AddressesRequest => self.handle_addresses_request(conn_index),
                            NetMsg::AddressesResponse(addrs) => {
                                self.handle_addresses_response(addrs)
                            }
                            NetMsg::Custom(msg) => self.handle_custom_message(conn_index, msg),
                        }
                    }
                }
            }

            // Updating connections
            self.update_connections();

            // Releasing read-write access to the connections
            self.connections_mtx.release();
        }
    }

    /// Removes bad connections and requests new ones if needed.
    fn update_connections(&mut self) {
        // Sorting and removing duplicates
        self.connections_to_remove.sort_unstable();
        self.connections_to_remove.dedup();

        // Removing bad connections
        for conn_index in self.connections_to_remove.drain(..).rev() {
            self.connections.remove(conn_index);
        }

        // If there are not enough connections
        let connection_number = self.connections.len();
        if connection_number < MIN_CONNECTION_NUMBER {
            // Requesting addresses to connect to
            self.request_addresses();
        }
    }

    /// Broadcasts a message.
    fn broadcast(&mut self, msg: &[u8]) {
        // Getting the size of the message
        let msg_size = msg.len() as u32;
        let msg_size = msg_size.to_be_bytes();

        // For each connection
        for (conn_index, conn) in self.connections.iter_mut().enumerate() {
            let conn = &mut conn.0;

            // Sending the size of the message
            if NetDriver::wait_send(conn, msg_size.as_slice()).is_err() {
                self.connections_to_remove.push(conn_index);
                continue;
            }

            // Sending the message
            if NetDriver::wait_send(conn, msg).is_err() {
                self.connections_to_remove.push(conn_index);
                continue;
            }
        }
    }

    /// Sends a message.
    fn send(&mut self, conn_index: usize, msg: &[u8]) {
        let conn = &mut self.connections[conn_index].0;

        // Getting the size of the message
        let msg_size = msg.len() as u32;
        let msg_size = msg_size.to_be_bytes();

        // Sending the size of the message
        if NetDriver::wait_send(conn, msg_size.as_slice()).is_err() {
            // Removing the connection on failure
            self.connections_to_remove.push(conn_index);
            return;
        }

        // Sending the message
        if NetDriver::wait_send(conn, msg).is_err() {
            // Removing the connection on failure
            self.connections_to_remove.push(conn_index);
        }
    }

    /// Receives a message.
    fn receive(&mut self, conn_index: usize, msg: &mut [u8]) -> bool {
        let conn = &mut self.connections[conn_index].0;

        // Receiving the size of the message
        let mut msg_size = [0; 4];
        match NetDriver::try_receive(conn, &mut msg_size) {
            Ok(success) => {
                if !success {
                    return false;
                }
            }
            Err(()) => {
                // Removing the connection on failure
                self.connections_to_remove.push(conn_index);
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
        match NetDriver::wait_receive(conn, msg) {
            Ok(success) => success,
            Err(()) => {
                // Removing the connection on failure
                self.connections_to_remove.push(conn_index);
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
    fn request_addresses(&mut self) {
        let msg = NetMsg::AddressesRequest;
        let msg = serialize(&msg).unwrap();
        self.broadcast(&msg);
    }

    /// Broadcasts a custom message.
    /// Thread-safe.
    pub fn broadcast_custom_message(&mut self, msg: Vec<u8>) {
        let msg = NetMsg::Custom(msg);
        let msg = serialize(&msg).unwrap();

        // Checking that the size of the message is not exceeded
        if msg.len() > MAX_NET_DATA_SIZE {
            return;
        }

        self.connections_mtx.acquire();
        self.broadcast(&msg);
        self.connections_mtx.release();
    }

    /// Sends a custom message.
    /// Thread-safe.
    pub fn send_custom_message(&mut self, conn_index: usize, msg: Vec<u8>) {
        let msg = NetMsg::Custom(msg);
        let msg = serialize(&msg).unwrap();

        // Checking that the size of the message is not exceeded
        if msg.len() > MAX_NET_DATA_SIZE {
            return;
        }

        self.connections_mtx.acquire();
        self.send(conn_index, &msg);
        self.connections_mtx.release();
    }

    /// Handles a peer addresses request.
    fn handle_addresses_request(&mut self, conn_index: usize) {
        // Getting addresses for the requesting NetDriver to connect to
        // excluding this NetDriver's and the other NetDriver's addresses
        let mut addrs: Vec<_> = self
            .connections
            .iter()
            .filter_map({
                let own_addr = self.listener.local_addr().unwrap();
                let own_ip = own_addr.ip();
                let own_port = own_addr.port();

                let other_conn = &self.connections[conn_index].0;
                let other_addr = other_conn.peer_addr().unwrap();
                let other_ip = other_addr.ip();
                let other_port = self.connections[conn_index].1;

                move |(conn, port, _)| {
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

        self.send(conn_index, &msg);
    }

    /// Handles a peer addresses response.
    fn handle_addresses_response(&mut self, addrs: Vec<SocketAddr>) {
        // If addrs are not empty
        // and there are not enough connections
        let connection_number = self.connections.len();
        if !addrs.is_empty() && connection_number < MIN_CONNECTION_NUMBER {
            // Adding addresses to connect to
            self.add_connections(addrs);
        }
    }

    /// Handles a custom message.
    fn handle_custom_message(&mut self, conn_index: usize, msg: Vec<u8>) {
        // If the custom message handler callback is set
        if let Some(custom_message_handler) = self.custom_message_handler.lock().unwrap().as_mut() {
            // Pass the message to the custom message handler callback
            self.connections_mtx.release();
            (custom_message_handler)(conn_index, msg);
            self.connections_mtx.acquire();
        }
    }

    /// Sets a custom messages handler.
    /// Thread-safe.
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
            .iter()
            .map(|(conn, port, _)| {
                (conn.peer_addr().unwrap().ip().to_string() + ":" + port.to_string().as_str())
                    .parse()
                    .unwrap()
            })
            .collect();
        self.db.save(&addrs);
    }
}
