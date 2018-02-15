#![feature(libc)]
///
/// Rust version of Firewall camkes component
/// see `firewall.c` for the original C version
/// Original source: https://github.com/seL4/camkes-vm/tree/master/components/Firewall
///
extern crate libc;
extern crate smoltcp;
use libc::c_void;
use libc::memcpy;
use std::slice;
use smoltcp::wire::Ipv4Packet;

extern "C" {
    static ethdriver_buf: *mut c_void;
    //static ethdriver_buf: *mut u8;
    fn ethdriver_mac(b1: *mut u8, b2: *mut u8, b3: *mut u8, b4: *mut u8, b5: *mut u8, b6: *mut u8);
    fn ethdriver_tx(len: i32) -> i32;
    fn ethdriver_rx(len: *mut i32) -> i32;

    /// For accessing client's buffer
    fn client_buf(cliend_id: u32) -> *mut c_void;
    //fn client_buf(cliend_id: u32) -> *mut u8;
    fn client_emit(badge: u32);
}

/// get eth device's MAC address
/// void client_mac(uint8_t *b1, uint8_t *b2, uint8_t *b3, uint8_t *b4, uint8_t *b5, uint8_t *b6)
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
    unsafe {
        ethdriver_mac(b1, b2, b3, b4, b5, b6);
    }
}

/// transmit `len` bytes from `client_buf` to `ethdriver_buf`
/// return -1 if some error happened, other values are OK (typically it is 0) [
///
/// 1. copy from client buffer into an interim buffer
/// 2. construct a IP (v4?) packet and perform checks
/// 3. if all good, copy over to ethdriver_buf
/// Bonus: call the external firewall function
#[no_mangle]
pub extern "C" fn client_tx(len: i32) -> i32 {
    // initial pointer checks
    unsafe {
        assert!(!client_buf(1).is_null());
        assert!(len >= 0);
    }

    // create a slice of length `len` from `client_buf`
    let local_buf_ptr = unsafe { std::mem::transmute::<*mut c_void, *mut u8>(client_buf(1)) };
    let slice = unsafe { slice::from_raw_parts(local_buf_ptr, len as usize) };

    // create a packet
    let ipv4_packet = Ipv4Packet::new(slice);

    // perform checks
    if check_packet_out(ipv4_packet) {
        // passed, copy packet data to ethdriver's transmit buffer
        unsafe {
            memcpy(ethdriver_buf, client_buf(1), len as usize);
            // transmit and return result
            return ethdriver_tx(len);
        }
    } else {
    	// checks failed, no packet transmitted
        return -1;
    }
}

/// copy `len` data from `ethdriver_buf` into `client_buf`
/// return -1 if some error happened, other values are OK (typically it is 0)
///
/// 1. copy data to an interim buffer
/// 2. perform checks on the constructed Ip packet
/// 3. if all good, copy to client buffer
/// Bonus: call the external firewall function
#[no_mangle]
pub extern "C" fn client_rx(len: *mut i32) -> i32 {
    // get `len` data into ethdriver buffer
    let mut result = unsafe { ethdriver_rx(len) };
    if result != -1 {
        // pointer checks
        unsafe {
            assert!(!ethdriver_buf.is_null());
            assert!(!len.is_null());
        }

        // create a slice of length `len` from `ethdriver_buf`
        let local_buf_ptr = unsafe { std::mem::transmute::<*mut c_void, *mut u8>(ethdriver_buf) };
        let slice = unsafe { slice::from_raw_parts(local_buf_ptr, *len as usize) };

        // create a packet
        let ipv4_packet = Ipv4Packet::new(slice);

        // perform checks
        if check_packet_in(ipv4_packet) {
            // passed, copy data to client buffer
            unsafe {
                memcpy(client_buf(1), ethdriver_buf, *len as usize);
            }
        } else {
        	// checks failed, no packet received
        	unsafe { *len = 0; }
        	result = -1;
        }
    }
    return result;
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
fn check_packet_out(_ipv4_packet: Ipv4Packet<&[u8]>) -> bool {
    // TODO: Dummy for now
    return true;
}

/// Perform checks on an incoming packet
/// returns `true` if the packet is OK to be received
fn check_packet_in(_ipv4_packet: Ipv4Packet<&[u8]>) -> bool {
    // TODO: Dummy for now
    return true;
}
