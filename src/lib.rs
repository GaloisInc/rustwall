//
// Rust version of Firewall camkes component
// see `firewall.c` for the original C version
// Original source: https://github.com/seL4/camkes-vm/tree/master/components/Firewall
//
#![feature(libc)]
#![feature(lang_items)]
#![no_std]

extern crate libc;
use libc::c_void;
use libc::memcpy;

#[lang = "eh_personality"]
#[no_mangle]
pub extern "C" fn eh_personality() {
    unimplemented!();
}

#[lang = "panic_fmt"]
#[no_mangle]
pub extern "C" fn rust_begin_unwind(
    _fmt: &core::fmt::Arguments,
    _file_line: &(&'static str, usize),
) -> ! {
    unimplemented!();
}

extern "C" {
    static ethdriver_buf: *mut c_void;
    fn ethdriver_mac(b1: *mut u8, b2: *mut u8, b3: *mut u8, b4: *mut u8, b5: *mut u8, b6: *mut u8);
    fn ethdriver_tx(len: i32) -> i32;
    fn ethdriver_rx(len: *mut i32) -> i32;

    /// For accessing client's buffer
    fn client_buf(cliend_id: u32) -> *mut c_void;
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
    unsafe {
        ethdriver_mac(b1, b2, b3, b4, b5, b6);
    }
}

/// transmit `len` bytes from `client_buf` to `ethdriver_buf`
/// returns number of transmitted bytes
/// int client_tx(int len)
#[no_mangle]
pub extern "C" fn client_tx(len: i32) -> i32 {
    unsafe {
        memcpy(ethdriver_buf, client_buf(1), len as usize);
    }
    return unsafe { ethdriver_tx(len) };
}

/// copy `len` data from `ethdriver_buf` into `client_buf`
/// return -1 if some error happened, other values are OK (typically it is 0)
#[no_mangle]
pub extern "C" fn client_rx(len: *mut i32) -> i32 {
    let result = unsafe { ethdriver_rx(len) };
    if result != -1 {
        unsafe {
            memcpy(client_buf(1), ethdriver_buf, *len as usize);
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
