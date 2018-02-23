#![feature(libc)]
//#![deny(unused)]
///
/// Rust version of Firewall camkes component
/// see `firewall.c` for the original C version
/// Original source: `https://github.com/seL4/camkes-vm/tree/master/components/Firewall`
///
extern crate libc;
extern crate smoltcp;
use libc::{c_void,memcpy};
use std::slice;
use std::io::{Error, ErrorKind};

use smoltcp::phy::Sel4Device;

/*
static CONFIG_STR: &'static str = include_str!("../config.ini");
use std::sync::{Arc, Mutex, Once, ONCE_INIT};
use std::mem;

#[derive(Clone)]
struct SingletonReader {
    // Since we will be used in many threads, we need to protect
    // concurrent access
    inner: Arc<Mutex<&'static str>>,
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

/// A backend for smoltcp, to be called from its `phy` module
/// Transmits a slice from the client application by copying data
/// into `ethdriver_buf` and consequently calling `ethdriver_tx()`
/// Returns either number of transmitted bytes or an error
fn sel4_eth_transmit(buf: &mut [u8]) -> Result<i32, std::io::Error> {
    unsafe {
        let local_buf_ptr = std::mem::transmute::<*mut u8, *mut c_void>(buf.as_mut_ptr());
        assert!(!ethdriver_buf.is_null());
        memcpy(ethdriver_buf, local_buf_ptr, buf.len());
        match ethdriver_tx(buf.len() as i32) {
            -1 => Err(Error::new(ErrorKind::Other, "ethdriver_tx error")),
            _ => Ok(buf.len() as i32),
        }
    }
}

/// A backend for smoltcp, to be called from its `phy` module
/// Attempt to receive data from the ethernet driver
/// Call `ethdriver_rx` and cast the results.
/// Returns either a vector of received bytes, or an error
fn sel4_eth_receive() -> Result<Vec<u8>, std::io::Error> {
    let mut len = 0;
    unsafe {
        if ethdriver_rx(&mut len) == -1 {
            return Err(Error::new(ErrorKind::Other, "ethdriver_rx error"));
        }

        assert!(!ethdriver_buf.is_null());
        // create a slice of length `len` from `ethdriver_buf`
        let local_buf_ptr = std::mem::transmute::<*mut c_void, *mut u8>(ethdriver_buf);
        let slice = slice::from_raw_parts(local_buf_ptr, len as usize);

        // instead of dealing with the borrow checker, copy slice in to a vector
        let mut vec = Vec::new();
        vec.extend_from_slice(slice);
        Ok(vec)
    }
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
        match sel4_eth_transmit(tx_data.as_mut_slice()) {
            Ok(_) => 0,
            Err(e) => {
                println!("sel4_eth_transmit Error: {}", e);
                -1
            }
        }
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
    let mut rx_data = match sel4_eth_receive() {
        Ok(data) => data,
        Err(e) => {
            println!("sel4_eth_receive Error: {}", e);
            unsafe {
                *len = 0;
            }
            return -1;
        }
    };

    // perform checks
    if check_frame_in(rx_data.as_mut()) {
        // checks OK, return data
        unsafe {
            memcpy(client_buf(1), rx_data.as_ptr() as *mut c_void, rx_data.len());
            *len = rx_data.len() as i32;
        }
        0
    } else {
        // checks failed, no packet transmitted
        unsafe {
            *len = 0;
        }
        -1
    }
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
    let _device = Sel4Device::new();
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

    /*
    let s = singleton();
    let data = s.inner.lock().unwrap();
    println!("It is: {}", *data);
    */

    unsafe {
        ethdriver_mac(b1, b2, b3, b4, b5, b6);
    }
}