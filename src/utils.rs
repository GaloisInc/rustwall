use super::*;
use libc::c_void;
use std::sync::Arc;

use smoltcp::wire::{EthernetAddress, EthernetProtocol, EthernetFrame};
use smoltcp::wire::{IpProtocol, IpAddress, Ipv4Repr, Ipv4Packet, Ipv4Address};
use smoltcp::{Error, Result};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{UdpRepr, UdpPacket};
use smoltcp::time::Instant;
use smoltcp::iface::{FragmentSet, FragmentedPacket};

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

pub struct ExternalFirewallWrapper {
    f: unsafe extern "C" fn(u32, u16, u32, u16, u16, *const u8, u16) -> i32,
}

impl ExternalFirewallWrapper {
    pub fn new(
        f: unsafe extern "C" fn(u32, u16, u32, u16, u16, *const u8, u16) -> i32,
    ) -> ExternalFirewallWrapper {
        ExternalFirewallWrapper { f: f }
    }

    pub fn call(
        &self,
        src_addr: u32,
        src_port: u16,
        dst_addr: u32,
        dst_port: u16,
        payload_len: u16,
        payload: *const u8,
        max_payload_len: u16,
    ) -> i32 {
        unsafe {
            (self.f)(
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                payload_len,
                payload,
                max_payload_len,
            )
        }
    }
}

/// Declare static mutexes we wish to use
lazy_static! {
    /// client/ethdriver protection
    static ref MTX_ETHDRIVER_BUF: Arc<Mutex> = Arc::new(Mutex::new(externs::ethdriver_buf_lock, externs::ethdriver_buf_unlock));
    static ref MTX_CLIENT_BUF: Arc<Mutex> = Arc::new(Mutex::new(externs::client_buf_lock, externs::client_buf_unlock));

    /// a wrapper for `packet_in`
    pub static ref FN_PACKET_IN: Arc<spin::Mutex<ExternalFirewallWrapper>> = {
        let inner = ExternalFirewallWrapper::new(externs::packet_in);
        Arc::new(spin::Mutex::new(inner))
    };

    /// a wrapper for `packet_out`
    pub static ref FN_PACKET_OUT: Arc<spin::Mutex<ExternalFirewallWrapper>> = {
        let inner = ExternalFirewallWrapper::new(externs::packet_out);
        Arc::new(spin::Mutex::new(inner))
    };

    /// fragments on rx side
    pub static ref FRAGMENTS_RX: Arc<spin::Mutex<FragmentSet<'static>>> = {
        let mut fragments = FragmentSet::new(vec![]);
        for _idx in 0..constants::SUPPORTED_FRAGMENTS {
            let fragment = FragmentedPacket::new(vec![0; constants::MAX_REASSEMBLED_FRAGMENT_SIZE]);
            fragments.add(fragment);
        }
        Arc::new(spin::Mutex::new(fragments))
    };

    /// fragments on tx side
    pub static ref FRAGMENTS_TX: Arc<spin::Mutex<FragmentSet<'static>>> = {
        let mut fragments = FragmentSet::new(vec![]);
        for _idx in 0..constants::SUPPORTED_FRAGMENTS {
            let fragment = FragmentedPacket::new(vec![0; constants::MAX_REASSEMBLED_FRAGMENT_SIZE]);
            fragments.add(fragment);
        }
        Arc::new(spin::Mutex::new(fragments))
    };

    /// enqued eth_frames to be send
    pub static ref PACKETS_TX: Arc<spin::Mutex<Vec<Vec<u8>>>> = Arc::new(spin::Mutex::new(vec![]));

    /// enqued eth_frames to be passed to the client
    pub static ref PACKETS_RX: Arc<spin::Mutex<Vec<Vec<u8>>>> = Arc::new(spin::Mutex::new(vec![]));

    /// kludge to prevent reentrancy around client_rx/tx calls
    pub static ref RET_CLIENT_TX: Arc<spin::Mutex<i32>> = Arc::new(spin::Mutex::new(-1));
    pub static ref RET_CLIENT_RX: Arc<spin::Mutex<i32>> = Arc::new(spin::Mutex::new(-1));
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
        assert!(!buffer.is_null());
        assert!(len < constants::BUFFER_SIZE);
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

/// Return OK if an eth_packet was enqued to the packet buffer,
/// otherwise return an error message
pub fn process_ethernet(
    frame: Vec<u8>,
    packet_buffer: Arc<spin::Mutex<Vec<Vec<u8>>>>,
    fragment_buffer: Arc<spin::Mutex<FragmentSet<'static>>>,
    external_firewall_fn: Arc<spin::Mutex<ExternalFirewallWrapper>>,
    check_mac: bool,
) -> Result<()> {
    let eth_frame = EthernetFrame::new_checked(frame)?;

    if check_mac {
        // Ignore any packets not directed at our hardware address.
        let local_ethernet_addr = get_device_mac();
        #[cfg(feature = "debug-print")]
        println_sel4(format!(
            "Firewall process_ethernet: local eth addr: {}",
            local_ethernet_addr
        ));
        #[cfg(feature = "mac-check")]
        {
            // check the MAC address of the incoming frame
            if !eth_frame.dst_addr().is_broadcast() && !eth_frame.dst_addr().is_multicast()
                && eth_frame.dst_addr() != local_ethernet_addr
            {
                // The packet wasn't for us, quitely drop it
                return Ok(());
            }
        }
    }

    #[cfg(feature = "debug-print")]
    println_sel4(format!(
        "Firewall process_ethernet: EthernetProtocol = {}",
        eth_frame.ethertype()
    ));

    match eth_frame.ethertype() {
        EthernetProtocol::Ipv4 => {
            #[cfg(feature = "debug-print")]
            println_sel4(format!("Firewall process_ethernet: processing IPv4"));
            match process_ipv4(eth_frame, fragment_buffer, external_firewall_fn) {
                Ok(mut packets) => {
                    // enqueue frames
                    let mut buffer = packet_buffer.lock();
                    while !packets.is_empty() {
                        let eth_frame = packets.remove(0);
                        buffer.push(eth_frame.into_inner());
                    }
                }
                Err(e) => return Err(e),
            }
        }
        EthernetProtocol::Ipv6 => {
            /* Ipv6 traffic is not allowed */
            #[cfg(feature = "debug-print")]
            println_sel4(format!("Firewall process_ethernet: dropping IPV6 traffic"));
        }
        EthernetProtocol::Arp => {
            /* Arp traffic is allowed, pass-through */
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "process_ethernet client_tx: passing through ARP traffic"
            ));
            // enqueue unchanged frame
            packet_buffer.lock().push(eth_frame.into_inner());
        }
        _ => {
            /* drop unrecognized protocol */
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall process_ethernet: drop unrecognized eth protocol"
            ));
        }
    }

    Ok(())
}

/// Return a vector of ethernet frames resulting from processing the `eth_frame`, an empty vector is
/// expected. Return error otherwise.
fn process_ipv4(
    eth_frame: EthernetFrame<Vec<u8>>,
    fragment_buffer: Arc<spin::Mutex<FragmentSet<'static>>>,
    external_firewall_fn: Arc<spin::Mutex<ExternalFirewallWrapper>>,
) -> Result<Vec<EthernetFrame<Vec<u8>>>> {
    // change the type of the frame
    let data = eth_frame.into_inner();
    // return structure
    let mut ret: Vec<EthernetFrame<Vec<u8>>> = vec![];
    {
        let eth_frame = EthernetFrame::new_checked(&data)?;
        #[cfg(feature = "debug-print")]
        println_sel4(format!(
            "Firewall process_ipv4: eth_fram payload len = {}",
            eth_frame.payload().len()
        ));

        let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload())?;

        /*
        let ipv4_packet_in = Ipv4Packet::new_checked(eth_frame.payload())?;
        
        let ipv4_packet;
        if ipv4_packet_in.more_frags() || ipv4_packet_in.frag_offset() > 0 {
            #[cfg(feature = "debug-print")]
            println_sel4(format!("Firewall process_ipv4: fragmented packet detected"));
            static mut MS: i64 = 0;
            unsafe {
                MS += 1; // helper for managing too-old fragments
            }
            let timestamp = unsafe { Instant::from_millis(MS) };
            let mut fragments = fragment_buffer.lock();
            match process_ipv4_fragment(ipv4_packet_in, timestamp, &mut fragments)? {
                Some(assembled_packet) => {
                    ipv4_packet = assembled_packet;
                }
                None => return Err(Error::Fragmented),
            }
        } else {
            // non-fragmented packet
            ipv4_packet = ipv4_packet_in;
        }
*/

        let checksum_caps = ChecksumCapabilities::default();
        let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps)?;
        let ip_payload = ipv4_packet.payload();

        #[cfg(feature = "debug-print")]
        println_sel4(format!(
            "Firewall process_ipv4: ipv4 protocol = {}",
            ipv4_repr.protocol
        ));

        match ipv4_repr.protocol {
            IpProtocol::Icmp => {
                /* passthrough */
                #[cfg(feature = "debug-print")]
                println_sel4(format!(
                    "Firewall process_ipv4: ICMP protocol, returning unchanged"
                ));
            }
            IpProtocol::Igmp => {
                /* passthrough */
                #[cfg(feature = "debug-print")]
                println_sel4(format!(
                    "Firewall process_ipv4: I protocol, returning unchanged"
                ));
            }
            IpProtocol::Udp => {
                // check with external firewall
                #[cfg(feature = "debug-print")]
                println_sel4(format!(
                    "Firewall process_ipv4: UDP protocol, parsing further"
                ));
            }
            _ => {
                /* unknown protocol, drop packet */
                let e = Err(Error::Unrecognized);
                #[cfg(feature = "debug-print")]
                println_sel4(format!(
                    "Firewall process_ipv4: Unknown protocol, returning error = {:?}",
                    e
                ));
                return e;
            }
        }
    }

    // make sure the packets are small enough
    if data.len() > constants::MTU {
        // TODO: fragment the packet
    } else {
        ret.push(EthernetFrame::new_checked(data)?);    
    }

    Ok(ret)
}
/*
// Process an IPv4 fragment
/// Returns etiher a vector representing an assembled packet,
/// nothing (in case no packets are available),
/// or and error caused by fragment processing
fn process_ipv4_fragment<'frame, 'r>(
    ipv4_packet: Ipv4Packet<&'frame [u8]>,
    timestamp: Instant,
    fragments: &'r mut FragmentSet<'static>,
) -> Result<Option<Ipv4Packet<&'r [u8]>>> {
    #[cfg(feature = "debug-print")]
    println_sel4(format!(
        "Firewall process_ipv4_fragment: got a fragment with id = {}",
        ipv4_packet.ident()
    ));
    // get an existing fragment or attempt to get a new one
    let fragment = match fragments.get_packet(
        ipv4_packet.ident(),
        ipv4_packet.src_addr(),
        ipv4_packet.dst_addr(),
        timestamp,
    ) {
        Some(frag) => frag,
        None => return Err(Error::FragmentSetFull),
    };

    if fragment.is_empty() {
        // this is a new packet
        #[cfg(feature = "debug-print")]
        println_sel4(format!("Firewall process_ipv4_fragment: fragment is empty"));
        fragment.start(
            ipv4_packet.ident(),
            ipv4_packet.src_addr(),
            ipv4_packet.dst_addr(),
        );
    }

    if !ipv4_packet.more_frags() {
        // last fragment, remember data length
        #[cfg(feature = "debug-print")]
        println_sel4(format!(
            "Firewall process_ipv4_fragment: this is the last fragment"
        ));
        fragment
            .set_total_len(ipv4_packet.frag_offset() as usize + ipv4_packet.total_len() as usize);
    }

    match fragment.add(
        ipv4_packet.header_len() as usize,
        ipv4_packet.frag_offset() as usize,
        ipv4_packet.payload().len(),
        ipv4_packet.into_inner(),
        timestamp,
    ) {
        Ok(_) => {
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall process_ipv4_fragment: adding fragment OK"
            ));
        }
        Err(_e) => {
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall process_ipv4_fragment: adding fragment error {:?}",
                _e
            ));
            fragment.reset();
            return Err(Error::TooManyFragments);
        }
    }

    if fragment.check_contig_range() {
        // this is the last packet, attempt reassembly
        let front = match fragment.front() {
            Some(f) => {
                #[cfg(feature = "debug-print")]
                println_sel4(format!(
                    "Firewall process_ipv4_fragment: fragment reassembly Some"
                ));
                f
            }
            None => {
                #[cfg(feature = "debug-print")]
                println_sel4(format!(
                    "Firewall process_ipv4_fragment: fragment reassebly None, return Ok(None)"
                ));
                return Ok(None);
            }
        };
        {
            // because the different mutability of the underlying buffers, we have to do this exercise
            let mut ipv4_packet = Ipv4Packet::new_checked(fragment.get_buffer_mut(0, front))?;
            ipv4_packet.set_total_len(front as u16);
            ipv4_packet.fill_checksum();
        }
        let ret = Ipv4Packet::new_checked(fragment.get_buffer(0, front))?;
        fragment.reset();
        return Ok(Some(ret));
    }

    // not the last fragment
    let r = Ok(None);
    #[cfg(feature = "debug-print")]
    println_sel4(format!(
        "Firewall process_ipv4_fragment: this wasn't the last fragment, returning {:?}",
        r
    ));
    return r;
}
*/
