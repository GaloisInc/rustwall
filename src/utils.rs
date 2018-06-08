use super::*;
use libc::c_void;
use std::sync::Arc;

/// Custom implementation of a mutex struct
/// Basically a wrapper around seL4/Camkes lock/unlock calls
#[derive(Debug)]
pub struct Mutex {
    inner_lock: unsafe extern "C" fn(),
    inner_unlock: unsafe extern "C" fn(),
}

impl Mutex {
    pub fn new(lock: unsafe extern "C" fn(), unlock: unsafe extern "C" fn()) -> Mutex {
        Mutex {
            inner_lock: lock,
            inner_unlock: unlock,
        }
    }

    pub fn lock(&self) {
        unsafe {
            (self.inner_lock)();
        }
    }

    pub fn unlock(&self) {
        unsafe {
            (self.inner_unlock)();
        }
    }
}

/// Declare static mutexes we wish to use
lazy_static! {
    /// client/ethdriver protection
    static ref MTX_ETHDRIVER_BUF: Arc<Mutex> = Arc::new(Mutex::new(externs::ethdriver_buf_lock, externs::ethdriver_buf_unlock));
    static ref MTX_CLIENT_BUF: Arc<Mutex> = Arc::new(Mutex::new(externs::client_buf_lock, externs::client_buf_unlock));

    /// data structs
    static ref FRAGMENTS_RX: Arc<spin::Mutex<FragmentSet<'static>>> = {
        let mut fragments = FragmentSet::new(vec![]);
        for _idx in 0..constants::SUPPORTED_FRAGMENTS {
            let fragment = FragmentedPacket::new(vec![0; constants::MAX_REASSEMBLED_FRAGMENT_SIZE]);
            fragments.add(fragment);
        }
        Arc::new(spin::Mutex::new(fragments))
    };
    static ref FRAGMENTS_TX: Arc<spin::Mutex<FragmentSet<'static>>> = {
        let mut fragments = FragmentSet::new(vec![]);
        for _idx in 0..constants::SUPPORTED_FRAGMENTS {
            let fragment = FragmentedPacket::new(vec![0; constants::MAX_REASSEMBLED_FRAGMENT_SIZE]);
            fragments.add(fragment);
        }
        Arc::new(spin::Mutex::new(fragments))
    };
    pub static ref PACKETS_TX: Arc<spin::Mutex<Vec<Vec<u8>>>> = Arc::new(spin::Mutex::new(vec![]));
    pub static ref PACKETS_RX: Arc<spin::Mutex<Vec<Vec<u8>>>> = Arc::new(spin::Mutex::new(vec![]));
}

/// A safe wrapper around `client_buf` ptr
pub fn client_buf_value() -> *mut c_void {
    unsafe {
        let val = externs::client_buf(1);
        assert!(!val.is_null());
        val
    }
}

/// A safe wrapper around `ethdriver_buf` ptr
pub fn ethdriver_buf_value() -> *mut c_void {
    unsafe {
        let val = externs::ethdriver_buf;
        assert!(!val.is_null());
        val
    }
}

/// Generic insertion of `data` into a `buffer`, returns number of inserted bytes
fn sel4_buffer_insert(data: Vec<u8>, buffer: *mut c_void) -> usize {
    unsafe {
        let len = data.len();
        let buf_ptr = std::mem::transmute::<*mut c_void, *mut u8>(buffer);
        let slice = std::slice::from_raw_parts_mut(buf_ptr, len);
        slice[..].clone_from_slice(data.as_slice());
        slice.len()
    }
}

/// Generic fetch of `len` bytes from `buffer`
fn sel4_buffer_fetch(len: usize, buffer: *mut c_void) -> Vec<u8> {
    unsafe {
        assert!(!buffer.is_null());
        assert!(len < constants::BUFFER_SIZE);
        // create a slice of length `len` from the buffer
        let local_buf_ptr = std::mem::transmute::<*mut c_void, *mut u8>(buffer);
        let slice = std::slice::from_raw_parts(local_buf_ptr, len);
        let mut v = Vec::with_capacity(slice.len());
        v.extend_from_slice(slice);
        v
    }
}

/// attempt to send `data` to the outside world
/// return 0 if data were successfully queued to the ethdriver
/// return -1 otherwise
/// Note that we don't know if the data were transmitted, as the ethdriver
/// doesn't provide a notification for that
pub fn dispatch_data_to_ethdriver(data: Vec<u8>) -> i32 {
    MTX_ETHDRIVER_BUF.lock();
    let len = sel4_buffer_insert(data, ethdriver_buf_value());
    let ret = unsafe { externs::ethdriver_tx(len as i32) };
    MTX_ETHDRIVER_BUF.unlock();
    ret
}

/// Possible return values from calling `ethdriver_rx` and subsequent
/// `sel4_buffer_fetch()`
#[derive(Debug)]
pub enum EthdriverRxStatus {
    NoData,
    Data(Vec<u8>),
    MoreData(Vec<u8>),
    MaybeMoreData,
}

/// Attempt to recieve data from the ethdriver
pub fn fetch_data_from_ethdriver() -> EthdriverRxStatus {
    MTX_ETHDRIVER_BUF.lock();
    let mut len: i32 = 0;
    let ret = unsafe { externs::ethdriver_rx(&mut len) };

    let status = match ret {
        -1 => EthdriverRxStatus::NoData, // no data available
        0 => {
            let data = sel4_buffer_fetch(len as usize, client_buf_value());
            EthdriverRxStatus::Data(data)
        }
        1 => {
            let data = sel4_buffer_fetch(len as usize, client_buf_value());
            EthdriverRxStatus::MoreData(data)
        }
        _ => panic!("Unexpected return value from ethdriver_rx"),
    };
    MTX_ETHDRIVER_BUF.unlock();
    status
}

/// copy `data` to client_buffer, return the length of the enqueued data
pub fn copy_data_to_client_buf(data: Vec<u8>) -> i32 {
    MTX_CLIENT_BUF.lock();
    let val = sel4_buffer_insert(data, client_buf_value());
    MTX_CLIENT_BUF.unlock();
    val as i32
}

/// copy `len` bytes from client buffer and return as `Vec<u8>`
pub fn fetch_client_data(len: usize) -> Vec<u8> {
    MTX_CLIENT_BUF.lock();
    let data = sel4_buffer_fetch(len, client_buf_value());
    MTX_CLIENT_BUF.unlock();
    data
}


/// Pass the device MAC address to the callee
pub fn get_device_mac() -> EthernetAddress {
    let mut b1: u8 = 0;
    let mut b2: u8 = 0;
    let mut b3: u8 = 0;
    let mut b4: u8 = 0;
    let mut b5: u8 = 0;
    let mut b6: u8 = 0;

    unsafe {
        externs::ethdriver_mac(&mut b1, &mut b2, &mut b3, &mut b4, &mut b5, &mut b6);
    }

    EthernetAddress([b1, b2, b3, b4, b5, b6])
}


/// Returns a new ID for a set of fragmented packets
/// Note that this would normally be a regular random
/// number generator, but sadly, seL4 + Rust doesn't have
/// the right bindings for it (yet)
pub fn client_tx_get_pseudorandom_packet_id() -> u16 {
    static mut SEED: u16 = 42;
    unsafe {
        SEED += 1;
        SEED
    }
}