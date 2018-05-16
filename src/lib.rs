//
// Rust version of Firewall camkes component
// see `firewall.c` for the original C version
// Original source: https://github.com/seL4/camkes-vm/tree/master/components/Firewall
//
#![feature(libc)]
#![feature(lang_items)]

extern crate libc;
use libc::c_void;
use libc::memcpy;

extern crate smoltcp;
use smoltcp::wire::{EthernetAddress, EthernetProtocol, EthernetFrame};
use smoltcp::wire::{IpProtocol, IpAddress, Ipv4Repr, Ipv4Packet};
use smoltcp::{Error, Result};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{UdpRepr, UdpPacket};
use smoltcp::time::Instant;
use smoltcp::iface::{FragmentSet, FragmentedPacket};

use std::cell::UnsafeCell;

#[allow(dead_code)]
#[no_mangle]
extern "C" {
    fn printf(val: *const i8);
}

const ETHERNET_FRAME_PAYLOAD: usize = 14;
const BUFFER_SIZE: usize = 64000;
const UDP_HEADER_SIZE: usize = 8;
const IPV4_HEADER_SIZE: usize = 20;
const SUPPORTED_FRAGMENTS: usize = 6;

static mut TX_UDP_PAYLOAD_BUFFER: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
static mut TX_UDP_PACKET_BUFFER: [u8; BUFFER_SIZE + UDP_HEADER_SIZE] =
    [0; BUFFER_SIZE + UDP_HEADER_SIZE];
static mut TX_IPV4_PACKET_BUFFER: [u8; BUFFER_SIZE + UDP_HEADER_SIZE + IPV4_HEADER_SIZE] =
    [0; BUFFER_SIZE + UDP_HEADER_SIZE + IPV4_HEADER_SIZE];

static mut RX_UDP_PAYLOAD_BUFFER: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
static mut RX_UDP_PACKET_BUFFER: [u8; BUFFER_SIZE + UDP_HEADER_SIZE] =
    [0; BUFFER_SIZE + UDP_HEADER_SIZE];
static mut RX_IPV4_PACKET_BUFFER: [u8; BUFFER_SIZE + UDP_HEADER_SIZE + IPV4_HEADER_SIZE] =
    [0; BUFFER_SIZE + UDP_HEADER_SIZE + IPV4_HEADER_SIZE];

extern "C" {
    static ethdriver_buf: *mut c_void;
    fn ethdriver_mac(b1: *mut u8, b2: *mut u8, b3: *mut u8, b4: *mut u8, b5: *mut u8, b6: *mut u8);
    fn ethdriver_tx(len: i32) -> i32;
    fn ethdriver_rx(len: *mut i32) -> i32;

    /// For accessing client's buffer
    fn client_buf(cliend_id: u32) -> *mut c_void;
    fn client_emit(badge: u32);

    /// for communicating with external firewall
    /// Called after veryifying port and checksum of the UDP packet
    /// Input:
    /// `src_addr`    	 - IPv4 source address encoded as u32, first octet is the MSB,
    ///				       for example 192.168.69.42 is encoded as [192,168,69,42] in memory
    /// `src_port`	     - source port
    /// `dst_addr` 	     - Ipv4 destination address encoded as u32, first octet is the MSB
    /// `dst_port`       - destination port
    /// `payload_len`    - length of UDP packet payload, i.e. the packed payload starts
    ///				       at `payload[0]` and ends at `payload[payload_len-1]`
    /// `payload` 	  	 - pointer to an array containing UDP packet payload
    /// `max_payload_len - maximal length of payload, i.e. the maximal length of the allocated
    ///					   array in the memory. If packet needs to be modified, data can be added
    ///					   to `payload` until `payload[max_payload_len-1]`
    ///
    /// Output: length of the UDP payload to be received from `src_addr:src_port` at `dst_addr:dst_port`
    ///		    Note that if the UDP payload is approved and was unchanged, simply return `payload_len`
    ///         Return 0 if the payload is rejected.
    fn packet_in(
        src_addr: u32,
        src_port: u16,
        dst_addr: u32,
        dst_port: u16,
        payload_len: u16,
        payload: *const u8,
        max_payload_len: u16,
    ) -> u16;

    /// for communicating with external firewall
    /// Called after constructing a UDP packet and verifying its checksum and port number
    /// Input:
    /// `src_addr`    	 - IPv4 source address encoded as u32, first octet is the MSB,
    ///				       for example 192.168.69.42 is encoded as [192,168,69,42] in memory
    /// `src_port`	     - source port
    /// `dst_addr` 	     - Ipv4 destination address encoded as u32, first octet is the MSB
    /// `dst_port`       - destination port
    /// `payload_len`    - length of UDP packet payload, i.e. the packed payload starts
    ///				       at `payload[0]` and ends at `payload[payload_len-1]`
    /// `payload` 	  	 - pointer to an array containing UDP packet payload
    /// `max_payload_len - maximal length of payload, i.e. the maximal length of the allocated
    ///					   array in the memory. If packet needs to be modified, data can be added
    ///					   to `payload` until `payload[max_payload_len-1]`
    ///
    /// Output: length of the UDP payload to be received from `src_addr:src_port` at `dst_addr:dst_port`
    ///		    Note that if the UDP payload is approved and was unchanged, simply return `payload_len`
    ///         Return 0 if the payload is rejected.
    fn packet_out(
        src_addr: u32,
        src_port: u16,
        dst_addr: u32,
        dst_port: u16,
        payload_len: u16,
        payload: *const u8,
        max_payload_len: u16,
    ) -> u16;
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

/// Pass the device MAC address to the callee
fn get_device_mac() -> EthernetAddress {
    let mut b1: u8 = 0;
    let mut b2: u8 = 0;
    let mut b3: u8 = 0;
    let mut b4: u8 = 0;
    let mut b5: u8 = 0;
    let mut b6: u8 = 0;

    unsafe {
        ethdriver_mac(&mut b1, &mut b2, &mut b3, &mut b4, &mut b5, &mut b6);
    }

    EthernetAddress([b1, b2, b3, b4, b5, b6])
}

/// transmit `len` bytes from `client_buf` to `ethdriver_buf`
/// returns number of transmitted bytes
/// int client_tx(int len)
/// returns -1 if the ethernet driver fails, 0 otherwise
#[no_mangle]
pub extern "C" fn client_tx(len: i32) -> i32 {
    let mut len = len;
    // client_buf contains ethernet frame, attempt to parse it
    let eth_frame = match EthernetFrame::new_checked(sel4_ethdriver_tx_transmute(len)) {
        Ok(frame) => frame,
        Err(_) => return -1,
    };

    // Check if we have ipv4 traffic
    match eth_frame.ethertype() {
        EthernetProtocol::Ipv4 => {
            #[cfg(feature = "debug-print")]
            unsafe {
                printf(b"TX: client_rx_process_ipv4\n\0".as_ptr() as *const i8);
            }
            match client_tx_process_ipv4(&eth_frame) {
                Ok(result) => {
                    match result {
                        Some(ipv4_packet_len) => {
                            /* copy ipv4 packet data to the client_buf and pass it on */
                            unsafe {
                                len = (ETHERNET_FRAME_PAYLOAD + ipv4_packet_len) as i32;
                                let local_buf_ptr =
                                    std::mem::transmute::<*mut c_void, *mut u8>(client_buf(1));
                                let slice =
                                    std::slice::from_raw_parts_mut(local_buf_ptr, len as usize);
                                slice[ETHERNET_FRAME_PAYLOAD..]
                                    .clone_from_slice(&TX_IPV4_PACKET_BUFFER[0..ipv4_packet_len]);
                            }
                        }
                        None => { /* pass the packet unchanged */ }
                    }
                }
                Err(_) => {
                    /* error during packet processing occured */
                    return -1;
                }
            }
        }
        #[cfg(feature = "proto-ipv6")]
        EthernetProtocol::Ipv6 => {
            // Ipv6 traffic is not allowed
            return -1;
        }
        // passthrough the traffic
        _ => { /* do nothing */ }
    }

    // copy data to the ehdriver buffer
    unsafe {
        memcpy(ethdriver_buf, client_buf(1), len as usize);
    }
    return unsafe { ethdriver_tx(len) };
}

/// Process ipv4 packet (only when external firewall is allowed)
/// Returns OK if:
/// - Ipv4 packet is well formed && of ICMP protocol (passthrough)
/// - Ipv4 packet is well formed && of UDP protocol && passes external firewall (external firewall)
/// otherwise returns error
fn client_tx_process_ipv4<'frame>(
    eth_frame: &'frame EthernetFrame<&'frame [u8]>,
) -> Result<Option<usize>> {
    let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload())?;
    let checksum_caps = ChecksumCapabilities::default();
    let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps)?;
    let ip_payload = ipv4_packet.payload();

    match ipv4_repr.protocol {
        IpProtocol::Icmp => return Ok(None),
        IpProtocol::Udp => {
            /* check with external firewall */
            match client_tx_process_udp(ipv4_repr, ip_payload) {
                Ok(udp_packet_len) => {
                    let ip_repr = Ipv4Repr {
                        src_addr: ipv4_repr.src_addr,
                        dst_addr: ipv4_repr.dst_addr,
                        protocol: IpProtocol::Udp,
                        payload_len: udp_packet_len,
                        hop_limit: 64,
                    };
                    let ip_packet = unsafe {
                        let mut ip_packet = Ipv4Packet::new(
                            &mut TX_IPV4_PACKET_BUFFER[0..udp_packet_len + ip_repr.buffer_len()],
                        );
                        ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::default());
                        ip_packet
                            .payload_mut()
                            .copy_from_slice(&TX_UDP_PACKET_BUFFER[0..udp_packet_len]);
                        ip_packet.set_ident(ipv4_packet.ident());
                        ip_packet.fill_checksum();
                        ip_packet
                    };
                    return Ok(Some(ip_packet.total_len() as usize));
                }
                Err(e) => return Err(e),
            }
        }
        _ => {
            /* unknown protocol */
            return Err(Error::Unrecognized);
        }
    }
}

/// Process UDP payload
/// return OK if UDP packet is well formed && passes external firewall
/// Ok returns the udp packet length
/// return Err otherwise
fn client_tx_process_udp<'frame>(ip_repr: Ipv4Repr, ip_payload: &'frame [u8]) -> Result<usize> {
    let udp_packet = UdpPacket::new_checked(ip_payload)?;
    let checksum_caps = ChecksumCapabilities::default();
    let _udp_repr = UdpRepr::parse(
        &udp_packet,
        &IpAddress::from(ip_repr.src_addr),
        &IpAddress::from(ip_repr.dst_addr),
        &checksum_caps,
    )?; // to force checksum

    // get proper addresses
    let src_addr_bytes = {
        let mut bytes = [0, 0, 0, 0];
        bytes[..].clone_from_slice(ip_repr.src_addr.as_bytes());
        let bytes = unsafe { std::mem::transmute::<[u8; 4], u32>(bytes) };
        bytes
    };

    let dst_addr_bytes = {
        let mut bytes = [0, 0, 0, 0];
        bytes[..].clone_from_slice(ip_repr.dst_addr.as_bytes());
        let bytes = unsafe { std::mem::transmute::<[u8; 4], u32>(bytes) };
        bytes
    };

    #[cfg(feature = "debug-print")]
    unsafe {
        printf(b"TX: Calling external firewall\n\0".as_ptr() as *const i8);
    }

    // copy data to the buffer
    unsafe {
        TX_UDP_PAYLOAD_BUFFER[0..udp_packet.payload().len()].copy_from_slice(udp_packet.payload());
    }

    // call external firewall
    let payload_len = unsafe {
        packet_out(
            src_addr_bytes,
            udp_packet.src_port(),
            dst_addr_bytes,
            udp_packet.dst_port(),
            udp_packet.payload().len() as u16,
            TX_UDP_PAYLOAD_BUFFER.as_mut_ptr(),
            BUFFER_SIZE as u16,
        )
    };

    // if non-zero return, parse payload and return it
    if payload_len > 0 {
        unsafe {
            let udp_data = &TX_UDP_PAYLOAD_BUFFER[0..payload_len as usize];
            let udp_repr = UdpRepr {
                src_port: udp_packet.src_port(),
                dst_port: udp_packet.dst_port(),
                payload: &udp_data,
            };

            let mut udp_packet =
                UdpPacket::new(&mut TX_UDP_PACKET_BUFFER[0..udp_repr.buffer_len()]);
            udp_repr.emit(
                &mut udp_packet,
                &IpAddress::from(ip_repr.src_addr),
                &IpAddress::from(ip_repr.dst_addr),
                &ChecksumCapabilities::default(),
            );
            udp_packet.fill_checksum(
                &IpAddress::from(ip_repr.src_addr),
                &IpAddress::from(ip_repr.dst_addr),
            );

            Ok(udp_repr.buffer_len())
        }
    } else {
        Err(Error::Dropped)
    }
}

/// The only way how to store fragments in the heap without
/// using any synchronization primitives
unsafe fn client_rx_get_fragments_set() -> &'static Option<UnsafeCell<FragmentSet<'static>>> {
    static mut FRAGMENTS: Option<UnsafeCell<FragmentSet>> = None;
    static mut INIT: bool = false;

    if !INIT {
        let mut fragments = FragmentSet::new(vec![]);
        
        for _ in 0..SUPPORTED_FRAGMENTS {
            let fragment = FragmentedPacket::new(vec![0; 65535]);
            fragments.add(fragment);    
        }

        let val = UnsafeCell::new(fragments);
        FRAGMENTS = Some(val);

        INIT = true;
    }

    &FRAGMENTS
}

/// copy `len` data from `ethdriver_buf` into `client_buf`
/// return 0 if data are received, 1 if more data are in the buffer and `client_rx()`
/// should be called again, -1 if no data are received (either the packet was dropped,
/// or `clien_rx` was called without any data being available)
#[no_mangle]
pub extern "C" fn client_rx(len: *mut i32) -> i32 {
    let result = unsafe { ethdriver_rx(len) };
    if result == -1 {
        return -1;
    }

    #[cfg(feature = "debug-print")]
    unsafe {
        printf(b"RX: parsing eth frame\n\0".as_ptr() as *const i8);
    }

    // ethdriver_buf contains ethernet frame, attempt to parse it
    let eth_frame = match EthernetFrame::new_checked(sel4_ethdriver_rx_transmute(len)) {
        Ok(frame) => frame,
        Err(_) => {
          unsafe {*len = 0;}
          return -1;
        },
    };

    // Ignore any packets not directed to our hardware address.
    let local_ethernet_addr = get_device_mac();
    if !eth_frame.dst_addr().is_broadcast() && !eth_frame.dst_addr().is_multicast()
        && eth_frame.dst_addr() != local_ethernet_addr
    {
        #[cfg(feature = "debug-print")]
        unsafe {
            printf(b"RX: not my address\n\0".as_ptr() as *const i8);
        }
        unsafe {*len = 0;}
        return -1;
    }

    // Check if we have ipv4 traffic
    match eth_frame.ethertype() {
        EthernetProtocol::Ipv4 => {
            #[cfg(feature = "debug-print")]
            unsafe {
                printf(b"RX: client_rx_process_ipv4\n\0".as_ptr() as *const i8);
            }
            let mut fragments = unsafe {
                match client_rx_get_fragments_set() {
                    None => None,
                    Some(cell) => Some(&mut*cell.get()),
                }
            };
            match client_rx_process_ipv4(&eth_frame, &mut fragments) {
                Ok(result) => {
                    match result {
                        Some(ipv4_packet_len) => {
                            /* copy ipv4 packet data to the ethernetdriver_buf and pass it on */
                            unsafe {
                                *len = (ETHERNET_FRAME_PAYLOAD + ipv4_packet_len) as i32;
                                let local_buf_ptr =
                                    std::mem::transmute::<*mut c_void, *mut u8>(ethdriver_buf);
                                let slice =
                                    std::slice::from_raw_parts_mut(local_buf_ptr, *len as usize);
                                slice[ETHERNET_FRAME_PAYLOAD..]
                                    .clone_from_slice(&RX_IPV4_PACKET_BUFFER[0..ipv4_packet_len]);
                            }
                        }
                        None => { /* pass the packet unchanged */ }
                    }
                }
                Err(_) => {
                    /* error during packet processing occured */
                    unsafe {*len = 0;}
                    return -1;
                }
            }
        }
        #[cfg(feature = "proto-ipv6")]
        EthernetProtocol::Ipv6 => {
            // Ipv6 traffic is not allowed
          unsafe {*len = 0;}
          return -1;
        }
        // passthrough the traffic
        _ => { /* do nothing */ }
    }

    unsafe {
        memcpy(client_buf(1), ethdriver_buf, *len as usize);
    }

    return result;
}

/// Process an IPv4 fragment
/// Returns etiher an assembled packet, or nothing (if no packet is available),
/// or an error caused by processing a packet.
fn client_rx_process_ipv4_fragment<'frame, 'r>(
    ipv4_packet: Ipv4Packet<&'frame [u8]>,
    timestamp: Instant,
    fragments: &'r mut Option<&'r mut FragmentSet<'static>>,
) -> Result<Option<Ipv4Packet<&'r [u8]>>> {
    match fragments {
        Some(ref mut fragments) => {
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
                fragment.start(
                    ipv4_packet.ident(),
                    ipv4_packet.src_addr(),
                    ipv4_packet.dst_addr(),
                );
            }

            if !ipv4_packet.more_frags() {
                // last fragment, remember data length
                fragment.set_total_len(
                    ipv4_packet.frag_offset() as usize + ipv4_packet.total_len() as usize,
                );
            }

            match fragment.add(
                ipv4_packet.header_len() as usize,
                ipv4_packet.frag_offset() as usize,
                ipv4_packet.payload().len(),
                ipv4_packet.into_inner(),
                timestamp,
            ) {
                Ok(_) => {}
                Err(_) => {
                    fragment.reset();
                    return Err(Error::TooManyFragments);
                }
            }

            if fragment.check_contig_range() {
                // this is the last packet, attempt reassembly
                let front = fragment.front().unwrap();
                {
                    // because the different mutability of the underlying buffers, we have to do this exercise
                    let mut ipv4_packet =
                        Ipv4Packet::new_checked(fragment.get_buffer_mut(0, front))?;
                    ipv4_packet.set_total_len(front as u16);
                    ipv4_packet.fill_checksum();
                }
                return Ok(Some(Ipv4Packet::new_checked(
                    fragment.get_buffer(0, front),
                )?));
            }

            // not the last fragment
            return Ok(None);
        }
        None => {
            return Err(Error::NoFragmentSet);
        }
    }
}

/// Process ipv4 packet (only when external firewall is allowed)
/// Returns OK if:
/// - Ipv4 packet is well formed && of ICMP protocol (passthrough)
/// - Ipv4 packet is well formed && of UDP protocol && passes external firewall (external firewall)
/// otherwise returns error
fn client_rx_process_ipv4<'frame>(
    eth_frame: &'frame EthernetFrame<&'frame [u8]>,
    fragments: &'frame mut Option<&'frame mut FragmentSet<'static>>,
) -> Result<Option<usize>> {
    let ipv4_packet_in = Ipv4Packet::new_checked(eth_frame.payload())?;

    let ipv4_packet;
    if ipv4_packet_in.more_frags() || ipv4_packet_in.frag_offset() > 0 {
        static mut MS: i64 = 0;
        unsafe {
            MS += 1; // helper for managing too-old fragments
        }
        let timestamp = unsafe { Instant::from_millis(MS) };
        match client_rx_process_ipv4_fragment(ipv4_packet_in, timestamp, fragments)? {
            Some(assembled_packet) => {
                ipv4_packet = assembled_packet;
            }
            None => return Err(Error::Fragmented),
        }
    } else {
        // non-fragmented packet
        ipv4_packet = ipv4_packet_in;
    }

    let checksum_caps = ChecksumCapabilities::default();
    let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps)?;
    let ip_payload = ipv4_packet.payload();

    match ipv4_repr.protocol {
        IpProtocol::Icmp => return Ok(None),
        IpProtocol::Udp => {
            /* check with external firewall */
            match client_rx_process_udp(ipv4_repr, ip_payload) {
                Ok(udp_packet_len) => {
                    let ip_repr = Ipv4Repr {
                        src_addr: ipv4_repr.src_addr,
                        dst_addr: ipv4_repr.dst_addr,
                        protocol: IpProtocol::Udp,
                        payload_len: udp_packet_len,
                        hop_limit: 64,
                    };
                    let ip_packet = unsafe {
                        let mut ip_packet = Ipv4Packet::new(
                            &mut RX_IPV4_PACKET_BUFFER[0..udp_packet_len + ip_repr.buffer_len()],
                        );
                        ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::default());
                        ip_packet
                            .payload_mut()
                            .copy_from_slice(&RX_UDP_PACKET_BUFFER[0..udp_packet_len]);
                        ip_packet.set_ident(ipv4_packet.ident());
                        ip_packet.fill_checksum();
                        ip_packet
                    };
                    return Ok(Some(ip_packet.total_len() as usize));
                }
                Err(e) => return Err(e),
            }
        }
        _ => {
            /* unknown protocol */
            return Err(Error::Unrecognized);
        }
    }
}

/// Process UDP payload
/// return OK if UDP packet is well formed && passes external firewall
/// return Err otherwise
fn client_rx_process_udp<'frame>(ip_repr: Ipv4Repr, ip_payload: &'frame [u8]) -> Result<usize> {
    let udp_packet = UdpPacket::new_checked(ip_payload)?;
    let checksum_caps = ChecksumCapabilities::default();
    let _udp_repr = UdpRepr::parse(
        &udp_packet,
        &IpAddress::from(ip_repr.src_addr),
        &IpAddress::from(ip_repr.dst_addr),
        &checksum_caps,
    )?; // to force checksum

    // get proper addresses
    let src_addr_bytes = {
        let mut bytes = [0, 0, 0, 0];
        bytes[..].clone_from_slice(ip_repr.src_addr.as_bytes());
        let bytes = unsafe { std::mem::transmute::<[u8; 4], u32>(bytes) };
        bytes
    };

    let dst_addr_bytes = {
        let mut bytes = [0, 0, 0, 0];
        bytes[..].clone_from_slice(ip_repr.dst_addr.as_bytes());
        let bytes = unsafe { std::mem::transmute::<[u8; 4], u32>(bytes) };
        bytes
    };

    // call external firewall
    #[cfg(feature = "debug-print")]
    unsafe {
        printf(b"RX: Calling external firewall\n\0".as_ptr() as *const i8);
    }

    // copy data to the buffer
    unsafe {
        RX_UDP_PAYLOAD_BUFFER[0..udp_packet.payload().len()].copy_from_slice(udp_packet.payload());
    }

    // call external firewall
    let payload_len = unsafe {
        packet_in(
            src_addr_bytes,
            udp_packet.src_port(),
            dst_addr_bytes,
            udp_packet.dst_port(),
            udp_packet.payload().len() as u16,
            RX_UDP_PAYLOAD_BUFFER.as_mut_ptr(),
            BUFFER_SIZE as u16,
        )
    };

    // if non-zero return, parse payload and return it
    if payload_len > 0 {
        unsafe {
            let udp_data = &RX_UDP_PAYLOAD_BUFFER[0..payload_len as usize];
            let udp_repr = UdpRepr {
                src_port: udp_packet.src_port(),
                dst_port: udp_packet.dst_port(),
                payload: &udp_data,
            };

            let mut udp_packet =
                UdpPacket::new(&mut RX_UDP_PACKET_BUFFER[0..udp_repr.buffer_len()]);
            udp_repr.emit(
                &mut udp_packet,
                &IpAddress::from(ip_repr.src_addr),
                &IpAddress::from(ip_repr.dst_addr),
                &ChecksumCapabilities::default(),
            );
            udp_packet.fill_checksum(
                &IpAddress::from(ip_repr.src_addr),
                &IpAddress::from(ip_repr.dst_addr),
            );

            Ok(udp_repr.buffer_len())
        }
    } else {
        Err(Error::Dropped)
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

/// To be called from `client_rx`
/// Coverts client data into `[u8]` and returns it.
/// The slice can be empty
fn sel4_ethdriver_rx_transmute<'a>(len: *mut i32) -> &'a [u8] {
    unsafe {
        assert!(!ethdriver_buf.is_null());
        // create a slice of length `len` from the buffer
        let local_buf_ptr = std::mem::transmute::<*mut c_void, *mut u8>(ethdriver_buf);
        let slice = std::slice::from_raw_parts(local_buf_ptr, *len as usize);
        slice
    }
}

/// To be called from `client_tx`
/// Coverts client data into `[u8]` and returns it.
/// The slice can be empty
fn sel4_ethdriver_tx_transmute<'a>(len: i32) -> &'a [u8] {
    unsafe {
        assert!(!client_buf(1).is_null());
        // create a slice of length `len` from the buffer
        let local_buf_ptr = std::mem::transmute::<*mut c_void, *mut u8>(client_buf(1));
        let slice = std::slice::from_raw_parts(local_buf_ptr, len as usize);
        slice
    }
}
