#![feature(libc)]
//#![deny(unused)]
///
/// Rust version of Firewall camkes component
/// see `firewall.c` for the original C version
/// Original source: `https://github.com/seL4/camkes-vm/tree/master/components/Firewall`
///
extern crate libc;
extern crate smoltcp;
use libc::{c_void, memcpy};
use std::slice;
use std::io::{Error, ErrorKind};

use smoltcp::phy::Sel4Device;

use std::sync::{Arc, Mutex, Once, ONCE_INIT};
use std::mem;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};
use smoltcp::iface::{NeighborCache, EthernetInterfaceBuilder, EthernetInterface};
use smoltcp::socket::{SocketSet, SocketHandle};
use smoltcp::wire::{IpVersion, IpProtocol};
use smoltcp::socket::{RawSocket, RawSocketBuffer, RawPacketBuffer};
use smoltcp::time::{Duration, Instant};
use std::collections::BTreeMap;

#[derive(Clone)]
struct Firewall {
    iface: Arc<Mutex<EthernetInterface<'static, 'static, Sel4Device>>>,
    sockets: Arc<Mutex<SocketSet<'static, 'static, 'static>>>,
    handle: Arc<Mutex<SocketHandle>>,
}

fn firewall_init() -> Firewall {
    // Initialize it to a null value
    static mut SINGLETON: *const Firewall = 0 as *const Firewall;
    static ONCE: Once = ONCE_INIT;

    unsafe {
        ONCE.call_once(|| {
            // do some parsing of the config here
            println!("Firewall init");

            let neighbor_cache = NeighborCache::new(BTreeMap::new());

            let ip_addrs = [IpCidr::new(IpAddress::v4(192, 168, 69, 3), 24)];
            let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x01, 0x01]);

            let device = Sel4Device::new();
            let iface = EthernetInterfaceBuilder::new(device)
                .ethernet_addr(ethernet_addr)
                .neighbor_cache(neighbor_cache)
                .ip_addrs(ip_addrs)
                .finalize();

            let rx_buffer = RawSocketBuffer::new(vec![RawPacketBuffer::new(vec![0; 1500])]);
            let tx_buffer = RawSocketBuffer::new(vec![RawPacketBuffer::new(vec![0; 1500])]);
            let raw_socket = RawSocket::new(IpVersion::Ipv4, IpProtocol::Udp, rx_buffer, tx_buffer);

            let mut sockets = SocketSet::new(vec![]);
            let raw_handle = sockets.add(raw_socket);

            // Make it
            let fw = Firewall {
                iface: Arc::new(Mutex::new(iface)),
                sockets: Arc::new(Mutex::new(sockets)),
                handle: Arc::new(Mutex::new(raw_handle)),
            };

            // Put it in the heap so it can outlive this call
            SINGLETON = mem::transmute(Box::new(fw));
        });

        // Now we give out a copy of the data that is safe to use concurrently.
        (*SINGLETON).clone()
    }
}

extern "C" {
    // to match C signatures
    static ethdriver_buf: *mut c_void;
    fn ethdriver_mac(b1: *mut u8, b2: *mut u8, b3: *mut u8, b4: *mut u8, b5: *mut u8, b6: *mut u8);
    fn ethdriver_tx(len: i32) -> i32;
    fn ethdriver_rx(len: *mut i32) -> i32;

    // For accessing client's buffer
    fn client_buf(cliend_id: u32) -> *mut c_void;
    fn client_emit(badge: u32);
}

/// To be called from `client_tx`
/// Coverts client data into `Vec<u8>` and returns it.
/// The vector can be empty.
fn sel4_client_transmute(len: usize) -> Vec<u8> {
    unsafe {
        assert!(!client_buf(1).is_null());
        // create a slice of length `len` from `client_buf`
        let local_buf_ptr = std::mem::transmute::<*mut c_void, *mut u8>(client_buf(1));
        let slice = slice::from_raw_parts(local_buf_ptr, len);

        // instead of dealing with the borrow checker, copy the slice in to a vector
        let mut vec = Vec::new();
        vec.extend_from_slice(slice);
        vec
    }
}

/// To be called from camkes VM app.
/// Transmits `len` bytes from `client_buf` to `ethdriver_buf`.
/// Returns -1 if some error happens, other values are OK (typically it is 0).
/// Expects raw ethernet frames.
///
/// 1. copy client data
/// 2. construct an ethernet frame and perform checks
/// 3. if all good, then transnmit
#[no_mangle]
pub extern "C" fn client_tx(len: i32) -> i32 {
    assert!(len >= 0);
    // get data to transmit as a vector
    let mut tx_data = sel4_client_transmute(len as usize);

    // perform checks
    if check_frame_out(tx_data.as_mut()) {
        // all OK, pass data to ethdriver's transmit buffer
        let s = firewall_init();
        let mut iface = s.iface.lock().unwrap();
        let mut sockets = s.sockets.lock().unwrap();
        let timestamp = Instant::now();
        let handle = *s.handle.lock().unwrap();

        iface.poll(&mut sockets, timestamp).expect("poll error");
        let mut socket = sockets.get::<RawSocket>(handle);

        if socket.can_send() {
            println!("sending slice: {:?}", tx_data);
            match socket.send_slice(tx_data.as_slice()) {
                Ok(_) => println!("data was sent"),
                Err(e) => println!("data not sent, error: {}", e),
            }
        }
        0
    } else {
        // checks failed, no packet transmitted
        -1
    }
}

/// To be called from camkes VM app.
/// Receives `len` bytes of data into `client_buf`.
/// Returns -1 if some error happens, other values are OK (typically it is 0).
/// Returns raw ethernet frames.
///
/// 1. receive data from ethernet driver
/// 2. perform checks
/// 3. if all good, copy to client buffer
#[no_mangle]
pub extern "C" fn client_rx(len: *mut i32) -> i32 {
    // get data from ethernet driver
    let s = firewall_init();
    let mut iface = s.iface.lock().unwrap();
    let mut sockets = s.sockets.lock().unwrap();
    let timestamp = Instant::now();
    let handle = *s.handle.lock().unwrap();

    iface.poll(&mut sockets, timestamp).expect("poll error");
    let mut socket = sockets.get::<RawSocket>(handle);

    if socket.can_recv() {
        println!("Raw socket can receive");
        let mut rx_data = Vec::new();
        rx_data.extend_from_slice(socket.recv().unwrap());
        println!("just got data: {:?}", rx_data);

        // perform checks
        if check_frame_in(rx_data.as_mut()) {
            // checks OK, return data
            unsafe {
                memcpy(
                    client_buf(1),
                    rx_data.as_ptr() as *mut c_void,
                    rx_data.len(),
                );
                *len = rx_data.len() as i32;
            }
            return 0;
        } else {
            // checks failed, no packet transmitted
            unsafe {
                *len = 0;
            }
            return -1;
        }
    }
    0 // default
}

/// Event callback I believe
/// `badge` is not used
#[no_mangle]
pub extern "C" fn ethdriver_has_data_callback(_badge: u32) {
    unsafe {
        client_emit(1);
    }
}

/// Perform checks on an outgoing packet
/// returns `true` if the packet is OK to be sent
/// Bonus: call the external firewall function
fn check_frame_out(_tx_data: &mut Vec<u8>) -> bool {
    // TODO: Dummy for now
    true
}

/// Perform checks on an incoming packet
/// returns `true` if the packet is OK to be received
/// Bonus: call the external firewall function
fn check_frame_in(_rx_data: &mut Vec<u8>) -> bool {
    // TODO: Dummy for now
    true
}

/// get eth device's MAC address
/// `void client_mac(uint8_t *b1, uint8_t *b2, uint8_t *b3, uint8_t *b4, uint8_t *b5, uint8_t *b6)`
#[no_mangle]
pub extern "C" fn client_mac(
    b1: &mut u8,
    b2: &mut u8,
    b3: &mut u8,
    b4: &mut u8,
    b5: &mut u8,
    b6: &mut u8,
) {
    println!(
        "client_mac: b1={:?}, b2={:?}, b3={:?}, b4={:?}, b5={:?}, b6={:?}",
        b1, b2, b3, b4, b5, b6
    );

    let s = firewall_init();
    let iface = s.iface.lock().unwrap();
    println!("eth addr: {}", iface.ethernet_addr());
    //println!("It is: {}", *data);

    unsafe {
        ethdriver_mac(b1, b2, b3, b4, b5, b6);
    }
}

/*
static CONFIG_STR: &'static str = include_str!("../config.ini");
use std::sync::{Arc, Mutex, Once, ONCE_INIT};
use std::mem;

#[derive(Clone)]
struct SingletonReader {
    // Since we will be used in many threads, we need to protect
    // concurrent access
    //inner: Arc<Mutex<&'static str>>,
}

fn singleton() -> SingletonReader {
    // Initialize it to a null value
    static mut SINGLETON: *const SingletonReader = 0 as *const SingletonReader;
    static ONCE: Once = ONCE_INIT;

    unsafe {
        ONCE.call_once(|| {
            // do some parsing of the config here

            // Make it
            let singleton = SingletonReader {
                inner: Arc::new(Mutex::new(CONFIG_STR)),
            };

            // Put it in the heap so it can outlive this call
            SINGLETON = mem::transmute(Box::new(singleton));
        });

        // Now we give out a copy of the data that is safe to use concurrently.
        (*SINGLETON).clone()
    }
}
*/
