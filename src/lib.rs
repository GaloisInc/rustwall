//
// Rust version of Firewall camkes component
// see `firewall.c` for the original C version
// Original source: https://github.com/seL4/camkes-vm/tree/master/components/Firewall
//
#![feature(libc)]
#![feature(lang_items)]

#![feature(alloc_system, global_allocator, allocator_api)]
extern crate alloc_system;
use alloc_system::System;

#[global_allocator]
static A: System = System;

extern crate libc;
use libc::c_void;
use libc::memcpy;

extern crate smoltcp;
use smoltcp::wire::{EthernetAddress, EthernetProtocol, EthernetFrame};
use smoltcp::wire::{IpProtocol, IpAddress, Ipv4Repr, Ipv4Packet, Ipv4Address};
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

#[allow(dead_code)]
fn println_sel4(s: String) {
    unsafe {
        printf((s + "\n\0").as_ptr() as *const i8);
    }
}

/// default sel4 buffer size is 4096, subtract
/// udp header size and ipv4 header size, as well as
/// the ethernet header size, so the whole packet
/// can fit into the sel4 buffer, i.e.:
/// BUFFER_SIZE = 4096 - UDP_HEADER_SIZE - IPV4_HEADER_SIZE - ETH_HEADER_SIZE
///             = 4096  - 8 - 20 - 14
///             = 4054
const BUFFER_SIZE: usize = 4068;

/// The index of ethernet frame payload. Also the size of
/// the ethernet frame header
const ETHERNET_FRAME_PAYLOAD: usize = 14;
const UDP_HEADER_SIZE: usize = 8;
const IPV4_HEADER_SIZE: usize = 20;

/// The max size of the reassembled packet
const MAX_REASSEMBLED_FRAGMENT_SIZE: usize = 65535;

/// Number of supported fragments. Make sure you allocate enough heap space!!
const SUPPORTED_FRAGMENTS: usize = 10;

/// Max ethernet MTU
const MTU: usize = 1500;

/// To get max permissible udp packet size, we have to subtract
/// IPv4 header size from MTU
const MAX_UDP_PACKET_SIZE: usize = MTU - IPV4_HEADER_SIZE;

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

    fn ethdriver_buf_crit_lock();
    fn ethdriver_buf_crit_unlock();

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
    ) -> i32;

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
    ) -> i32;
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

/// Helper function to copy single Ipv4 packet from TX_IPV4_PACKET_BUFFER
/// to client_buf(1)
fn client_tx_copy_to_client_buf(ipv4_packet_len: usize, len: &mut i32) {
    unsafe {
        *len = (ETHERNET_FRAME_PAYLOAD + ipv4_packet_len) as i32;
        let local_buf_ptr = std::mem::transmute::<*mut c_void, *mut u8>(client_buf(1));
        let slice = std::slice::from_raw_parts_mut(local_buf_ptr, *len as usize);
        slice[ETHERNET_FRAME_PAYLOAD..]
            .clone_from_slice(&TX_IPV4_PACKET_BUFFER[0..ipv4_packet_len]);
        #[cfg(feature = "debug-print")]
        println_sel4(format!(
            "Firewall client_tx_copy_to_client_buf: Updating buffer, len = {}",
            *len
        ));
        #[cfg(feature = "debug-print")]
        println_sel4(format!(
            "Firewall client_tx_copy_to_client_buf: Updating buffer, slice = {:?}",
            slice
        ));
    }
}

/// Helper function to copy Ipv4 packet to the client_buf and then send it
fn client_tx_transmit_fragmented_packet(ipv4_packet: Vec<u8>) -> i32 {
    unsafe {
        let len = (ETHERNET_FRAME_PAYLOAD + ipv4_packet.len()) as i32;
        let local_buf_ptr = std::mem::transmute::<*mut c_void, *mut u8>(client_buf(1));
        let slice = std::slice::from_raw_parts_mut(local_buf_ptr, len as usize);
        slice[ETHERNET_FRAME_PAYLOAD..].clone_from_slice(&ipv4_packet[..]);
        #[cfg(feature = "debug-print")]
        println_sel4(format!(
            "Firewall client_tx_transmit_fragmented_packet: Updating buffer, len = {}",
            len
        ));
        #[cfg(feature = "debug-print")]
        println_sel4(format!(
            "Firewall client_tx_transmit_fragmented_packet: Updating buffer, slice = {:?}",
            slice
        ));

        ethdriver_buf_crit_lock();
        // copy data to ethdriver buffer
        memcpy(ethdriver_buf, client_buf(1), len as usize);

        // attemp to send
        let ret = ethdriver_tx(len);
        ethdriver_buf_crit_unlock();
        ret
    }
}

/// Returns a new ID for a set of fragmented packets
/// Note that this would normally be a regular random
/// number generator, but sadly, seL4 + Rust doesn't have
/// the right bindings for it (yet)
fn client_tx_get_pseudorandom_packet_id() -> u16 {
    static mut SEED: u16 = 42;
    unsafe {
        SEED += 1;
        SEED
    }
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
        Ok(frame) => {
            #[cfg(feature = "debug-print")]
            println_sel4(format!("Firewall client_tx: got eth_frame = {}", frame));
            frame
        }
        Err(_e) => {
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_tx: error parsing eth frame: {}, returning -1",
                _e
            ));
            return -1;
        }
    };

    #[cfg(feature = "debug-print")]
    println_sel4(format!(
        "Firewall client_tx: EthernetProtocol = {}",
        eth_frame.ethertype()
    ));

    // Check if we have ipv4 traffic
    match eth_frame.ethertype() {
        EthernetProtocol::Ipv4 => {
            #[cfg(feature = "debug-print")]
            println_sel4(format!("Firewall client_tx: processing IPv4"));
            match client_tx_process_ipv4(&eth_frame) {
                Ok(result) => {
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                        "Firewall client_tx: client_tx_process_ipv4 returned with OK"
                    ));
                    match result {
                        Some(client_tx_result) => {
                            match client_tx_result {
                                ClientTxResult::SingleIpv4Packet(ipv4_packet_len) => {
                                    /* copy ipv4 packet data to the client_buf and pass it on */
                                    #[cfg(feature = "debug-print")]
                                    println_sel4(format!("Firewall client_tx: client_tx_process_ipv4 returned ipv4_packet_len = {}
                                        so it was a single UDP packet",
                                        ipv4_packet_len
                                    ));
                                    client_tx_copy_to_client_buf(ipv4_packet_len, &mut len);
                                }
                                ClientTxResult::MultipleIpv4Packets(mut ipv4_packet_buffer) => {
                                    /* iteratively copy data from each fragment and transmit them */
                                    #[cfg(feature = "debug-print")]
                                    println_sel4(format!("Firewall client_tx: client_tx_process_ipv4 returned MultiplePackets, processing"
                                    ));
                                    let mut res = -1;
                                    while !ipv4_packet_buffer.is_empty() {
                                        let packet = ipv4_packet_buffer.remove(0);
                                        #[cfg(feature = "debug-print")]
                                        println_sel4(format!("Firewall client_tx: got a packet of len = {}, there are {} packets remaining",
                                            packet.len(), ipv4_packet_buffer.len()
                                        ));
                                        res = client_tx_transmit_fragmented_packet(packet);
                                        if res == -1 {
                                            /* if the transmission fails at any point, abort*/
                                            return res;
                                        }
                                    }
                                    /* all packets sent, return last result code*/
                                    return res;
                                }
                            }
                        }
                        None => {
                            /* pass the packet unchanged */
                            #[cfg(feature = "debug-print")]
                            println_sel4(format!(
                                "Firewall client_tx: passing packet unchanged (not a UDP packet)"
                            ));
                        }
                    }
                }
                Err(_e) => {
                    /* error during packet processing occured */
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                        "Firewall client_tx: client_tx_process_ipv4 returned with error: {}, returning -1",
                        _e
                    ));
                    return -1;
                }
            }
        }
        EthernetProtocol::Ipv6 => {
            /* Ipv6 traffic is not allowed */
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_tx: dropping IPV6 traffic, returning -1"
            ));
            return -1;
        }
        EthernetProtocol::Arp => {
            /* Arp traffic is allowed, pass-through */
            #[cfg(feature = "debug-print")]
            println_sel4(format!("Firewall client_tx: passing through ARP traffic"));
        }
        _ => {
            /* drop unrecognized protocol */
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_tx: drop unrecognized eth protocol, returning -1"
            ));
            return -1;
        }
    }

    // copy data to the ehdriver buffer
    #[cfg(feature = "debug-print")]
    println_sel4(format!(
        "Firewall client_tx: copying {} bytes from client_buf(1) to ethdriver_buf",
        len
    ));
    let ret = unsafe {
        ethdriver_buf_crit_lock();
        memcpy(ethdriver_buf, client_buf(1), len as usize);
        let ret = ethdriver_tx(len);
        ethdriver_buf_crit_unlock();
        ret
    };
    #[cfg(feature = "debug-print")]
    println_sel4(format!(
        "Firewall client_tx: returing {} after calling ethdriver_tx({})",
        ret, len
    ));
    ret
}

/// Enum encompassing possible positive results from client_tx_process_ipv4
#[derive(Debug)]
enum ClientTxResult {
    SingleIpv4Packet(usize),
    MultipleIpv4Packets(Vec<Vec<u8>>),
}

/// A helper function that splits a large UDP packet into multiple fragmented
/// Ipv4 packets
fn client_tx_fragment_large_udp_packet(
    udp_packet_len: usize,
    src_addr: Ipv4Address,
    dst_addr: Ipv4Address,
) -> Vec<Vec<u8>> {
    // initialize variables
    let mut start_len = 0;
    let mut end_len = MAX_UDP_PACKET_SIZE;
    let mut fragment_offset = 0;
    let mut remaining_len = udp_packet_len;

    let packet_id = client_tx_get_pseudorandom_packet_id();
    let mut ipv4_packet_buffer = vec![];
    {
        /* create the first packet */
        let ip_repr = Ipv4Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
            payload_len: MAX_UDP_PACKET_SIZE,
            hop_limit: 64,
        };
        let ip_packet = unsafe {
            let mut ip_packet = Ipv4Packet::new(vec![]);
            ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::default());
            ip_packet
                .payload_mut()
                .copy_from_slice(&TX_UDP_PACKET_BUFFER[start_len..end_len]);
            ip_packet.set_ident(packet_id);
            ip_packet.set_frag_offset(fragment_offset); // first packet
            ip_packet.set_more_frags(true); // more fragments
            ip_packet.set_dont_frag(false);
            ip_packet.fill_checksum();
            ip_packet
        };
        ipv4_packet_buffer.push(ip_packet.into_inner());
    }

    // update remaining len
    remaining_len -= MAX_UDP_PACKET_SIZE;

    while remaining_len > MAX_UDP_PACKET_SIZE {
        /* create middle packets*/

        // update indices
        start_len += MAX_UDP_PACKET_SIZE;
        end_len += MAX_UDP_PACKET_SIZE;
        fragment_offset += MAX_UDP_PACKET_SIZE as u16;

        let ip_repr = Ipv4Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
            payload_len: MAX_UDP_PACKET_SIZE,
            hop_limit: 64,
        };
        let ip_packet = unsafe {
            let mut ip_packet = Ipv4Packet::new(vec![]);
            ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::default());
            ip_packet
                .payload_mut()
                .copy_from_slice(&TX_UDP_PACKET_BUFFER[start_len..end_len]);
            ip_packet.set_ident(packet_id);
            ip_packet.set_frag_offset(fragment_offset); // last packet
            ip_packet.set_more_frags(true); // more fragmentrs
            ip_packet.set_dont_frag(false);
            ip_packet.fill_checksum();
            ip_packet
        };
        ipv4_packet_buffer.push(ip_packet.into_inner());
        // update remaining len
        remaining_len -= MAX_UDP_PACKET_SIZE;
    }

    {
        /* create the last packet */
        // update indices
        start_len += MAX_UDP_PACKET_SIZE;
        fragment_offset += MAX_UDP_PACKET_SIZE as u16;

        let ip_repr = Ipv4Repr {
            src_addr: src_addr,
            dst_addr: dst_addr,
            protocol: IpProtocol::Udp,
            payload_len: remaining_len,
            hop_limit: 64,
        };
        let ip_packet = unsafe {
            let mut ip_packet = Ipv4Packet::new(vec![]);
            ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::default());
            ip_packet
                .payload_mut()
                .copy_from_slice(&TX_UDP_PACKET_BUFFER[start_len..udp_packet_len]);
            ip_packet.set_ident(packet_id);
            ip_packet.set_frag_offset(fragment_offset); // last packet
            ip_packet.set_more_frags(false); // no more fragmentrs
            ip_packet.set_dont_frag(false);
            ip_packet.fill_checksum();
            ip_packet
        };
        ipv4_packet_buffer.push(ip_packet.into_inner());
    }
    ipv4_packet_buffer
}

/// Process ipv4 packet (only when external firewall is allowed)
/// Returns OK if:
/// - Ipv4 packet is well formed && of ICMP protocol (passthrough)
/// - Ipv4 packet is well formed && of UDP protocol && passes external firewall (external firewall)
/// otherwise returns error
fn client_tx_process_ipv4<'frame>(
    eth_frame: &'frame EthernetFrame<&'frame [u8]>,
) -> Result<Option<ClientTxResult>> {
    let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload())?;
    let checksum_caps = ChecksumCapabilities::default();
    let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps)?;
    let ip_payload = ipv4_packet.payload();

    #[cfg(feature = "debug-print")]
    println_sel4(format!(
        "Firewall client_tx_process_ipv4: ipv4 protocol = {}",
        ipv4_repr.protocol
    ));

    match ipv4_repr.protocol {
        IpProtocol::Icmp => {
            /* passthrough */
            let r = Ok(None);
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_tx_process_ipv4: ICMP protocol, returning {:?}",
                r
            ));
            return r;
        }
        IpProtocol::Igmp => {
            /* passthrough */
            let r = Ok(None);
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_tx_process_ipv4: I protocol, returning {:?}",
                r
            ));
            return r;
        }
        IpProtocol::Udp => {
            /* check with external firewall */
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_tx_process_ipv4: UDP protocol, parsing further"
            ));
            match client_tx_process_udp(ipv4_repr, ip_payload) {
                Ok(udp_packet_len) => {
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                        "Firewall client_tx_process_ipv4: keep UDP packet, udp_packet_len={}",
                        udp_packet_len
                    ));
                    if udp_packet_len > MAX_UDP_PACKET_SIZE {
                        /* the payload is too big, we have to fragment it*/

                        /* always return an empty vector is the re-fragmentation is disabled (drops the packet) */
                        #[cfg(feature = "no-fragments")]
                        return Ok(Some(ClientTxResult::MultipleIpv4Packets(vec![])));

                        /* call a helper function*/
                        let ipv4_packet_buffer = client_tx_fragment_large_udp_packet(
                            udp_packet_len,
                            ipv4_repr.src_addr,
                            ipv4_repr.dst_addr,
                        );

                        /* return packet buffer */
                        return Ok(Some(ClientTxResult::MultipleIpv4Packets(
                            ipv4_packet_buffer,
                        )));
                    } else {
                        /* the payload fits into a single packet*/
                        let ip_repr = Ipv4Repr {
                            src_addr: ipv4_repr.src_addr,
                            dst_addr: ipv4_repr.dst_addr,
                            protocol: IpProtocol::Udp,
                            payload_len: udp_packet_len,
                            hop_limit: 64,
                        };
                        let ip_packet = unsafe {
                            let mut ip_packet = Ipv4Packet::new(
                                &mut TX_IPV4_PACKET_BUFFER
                                    [0..udp_packet_len + ip_repr.buffer_len()],
                            );
                            ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::default());
                            ip_packet
                                .payload_mut()
                                .copy_from_slice(&TX_UDP_PACKET_BUFFER[0..udp_packet_len]);
                            ip_packet.set_ident(ipv4_packet.ident()); // keep ident
                            ip_packet.fill_checksum();
                            ip_packet
                        };
                        let r = Ok(Some(ClientTxResult::SingleIpv4Packet(
                            ip_packet.total_len() as usize,
                        )));
                        #[cfg(feature = "debug-print")]
                        println_sel4(format!(
                            "Firewall client_tx_process_ipv4: return IP packet of length = {:?}",
                            r
                        ));
                        return r;
                    }
                }
                Err(e) => {
                    /* drop packet */
                    let e = Err(e);
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                        "Firewall client_tx_process_ipv4: drop UDP packet, return {:?}",
                        e
                    ));
                    return e;
                }
            }
        }
        _ => {
            /* unknown protocol, drop packet */
            let e = Err(Error::Unrecognized);
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_tx_process_ipv4: Unknown protocol, returning error = {:?}",
                e
            ));
            return e;
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

    // copy data to the buffer
    unsafe {
        TX_UDP_PAYLOAD_BUFFER[0..udp_packet.payload().len()].copy_from_slice(udp_packet.payload());
    }

    #[cfg(feature = "debug-print")]
    println_sel4(format!(
        "Firewall client_tx_process_udp: calling external firewall.
        src_addr_byes = {:?},
        udp_packet.src_port = {},
        dst_addr_bytes = {:?},
        udp_packet.dst_port = {},
        udp payload len = {}
        buffer size = {}",
        src_addr_bytes,
        udp_packet.src_port(),
        dst_addr_bytes,
        udp_packet.dst_port(),
        udp_packet.payload().len() as u16,
        BUFFER_SIZE as u16,
    ));

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
        #[cfg(feature = "debug-print")]
        println_sel4(format!(
            "Firewall client_tx_process_udp: returned payload len = {}",
            payload_len
        ));
        if payload_len as usize > BUFFER_SIZE {
            let e = Err(Error::Dropped);
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_tx_process_udp: payload len > buffer size, returning {:?}",
                e
            ));
            return e;
        }
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

            let r = Ok(udp_repr.buffer_len());
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_tx_process_udp: udp packet created, returning {:?}",
                r
            ));
            return r;
        }
    } else {
        let e = Err(Error::Dropped);
        #[cfg(feature = "debug-print")]
        println_sel4(format!(
            "Firewall client_tx_process_udp: packet dropped, returning {:?}",
            e
        ));
        return e;
    }
}

/// copy `len` data from `ethdriver_buf` into `client_buf`
/// return 0 if data are received, 1 if more data are in the buffer and `client_rx()`
/// should be called again, -1 if no data are received (either the packet was dropped,
/// or `clien_rx` was called without any data being available)
#[no_mangle]
pub extern "C" fn client_rx(len: *mut i32) -> i32 {
    unsafe {
        /* preventively erase length */
        *len = 0;

        match FIREWALL_RX {
            None => {
                /* nothing to see here*/
                #[cfg(feature = "debug-print")]
                println_sel4(format!("Firewall client_rx: no data, returning -1"));
                return -1;
            }
            Some(ref mut packet_buffer) => {
                /* shared data vector was initialized*/
                if !packet_buffer.is_empty() {
                    /* we have some data, get the oldest packet */
                    let packet = packet_buffer.remove(0);
                    /* copy data to client buffer */
                    *len = packet.len() as i32;
                    let packet_ptr =
                        std::mem::transmute::<*const u8, *const c_void>(packet.as_ptr());
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                        "Firewall client_rx: copying data from the buffer, {} bytes",
                        packet.len()
                    ));
                    memcpy(client_buf(1), packet_ptr, packet.len());
                    if packet_buffer.len() > 0 {
                        /* we have more packets to receive */
                        #[cfg(feature = "debug-print")]
                        println_sel4(format!("Firewall client_rx: more data, returning 1"));
                        return 1;
                    } else {
                        /* we have only this packet */
                        #[cfg(feature = "debug-print")]
                        println_sel4(format!("Firewall client_rx: only one packet, returning 0"));
                        return 0;
                    }
                }
                /* no data to return */
                #[cfg(feature = "debug-print")]
                println_sel4(format!(
                    "Firewall client_rx: packet_buffer is empty, returning -1"
                ));
                return -1;
            }
        }
    }
}

/// The only way how to store fragments in the heap without
/// using any synchronization primitives
unsafe fn client_rx_get_fragments_set() -> &'static Option<UnsafeCell<FragmentSet<'static>>> {
    static mut FRAGMENTS: Option<UnsafeCell<FragmentSet>> = None;
    static mut INIT: bool = false;

    if !INIT {
        #[cfg(feature = "debug-print")]
        println_sel4(format!(
            "Firewall client_rx_get_fragments_set: initializing fragment set"
        ));

        let mut fragments = FragmentSet::new(vec![]);
        for _idx in 0..SUPPORTED_FRAGMENTS {
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_rx_get_fragments_set: adding fragment {}",
                _idx
            ));
            let fragment = FragmentedPacket::new(vec![0; MAX_REASSEMBLED_FRAGMENT_SIZE]);
            fragments.add(fragment);
        }

        #[cfg(feature = "debug-print")]
        println_sel4(format!(
            "Firewall client_rx_get_fragments_set: Creating unsafe cell"
        ));
        let val = UnsafeCell::new(fragments);
        FRAGMENTS = Some(val);
        INIT = true;
    }
    #[cfg(feature = "debug-print")]
    println_sel4(format!(
        "Firewall client_rx_get_fragments_set: Returning fragment set"
    ));
    &FRAGMENTS
}

/// Process an IPv4 fragment
/// Returns etiher an assembled packet, or nothing (if no packet is available),
/// or an error caused by processing a packet.
fn client_rx_process_ipv4_fragment<'frame, 'r>(
    ipv4_packet: Ipv4Packet<&'frame [u8]>,
    timestamp: Instant,
    fragments: &'r mut Option<&'r mut FragmentSet<'static>>,
) -> Result<Option<Ipv4Packet<&'r [u8]>>> {
    match *fragments {
        Some(ref mut fragments) => {
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_rx_process_ipv4_fragment: got a fragment with id = {}",
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
                println_sel4(format!(
                    "Firewall client_rx_process_ipv4_fragment: fragment is empty"
                ));
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
                    "Firewall client_rx_process_ipv4_fragment: this is the last fragment"
                ));
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
                Ok(_) => {
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                        "Firewall client_rx_process_ipv4_fragment: adding fragment OK"
                    ));
                }
                Err(_e) => {
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                        "Firewall client_rx_process_ipv4_fragment: adding fragment error {:?}",
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
                            "Firewall client_rx_process_ipv4_fragment: fragment reassembly Some"
                        ));
                        f
                    }
                    None => {
                        #[cfg(feature = "debug-print")]
                        println_sel4(format!(
                            "Firewall client_rx_process_ipv4_fragment: fragment reassebly None, return Ok(None)"
                        ));
                        return Ok(None);
                    }
                };
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
            let r = Ok(None);
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_rx_process_ipv4_fragment: this wasn't the last fragment, returning {:?}",
                r
            ));
            return r;
        }
        None => {
            let e = Error::NoFragmentSet;
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_rx_process_ipv4_fragment: no fragment set provided, returning {}",
                e
            ));
            return Err(e);
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
    #[cfg(feature = "debug-print")]
    println_sel4(format!(
        "Firewall client_rx_process_ipv4: eth_fram payload len = {}",
        eth_frame.payload().len()
    ));
    let ipv4_packet_in = Ipv4Packet::new_checked(eth_frame.payload())?;

    let ipv4_packet;
    if ipv4_packet_in.more_frags() || ipv4_packet_in.frag_offset() > 0 {
        #[cfg(feature = "debug-print")]
        println_sel4(format!(
            "Firewall client_rx_process_ipv4: fragmented packet detected"
        ));
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

    #[cfg(feature = "debug-print")]
    println_sel4(format!(
        "Firewall client_rx_process_ipv4: ipv4 protocol = {}",
        ipv4_repr.protocol
    ));

    match ipv4_repr.protocol {
        IpProtocol::Icmp => {
            /* passthrough */
            let r = Ok(None);
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_rx_process_ipv4: ICMP protocol, returning {:?}",
                r
            ));
            return r;
        }
        IpProtocol::Igmp => {
            /* passthrough */
            let r = Ok(None);
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_rx_process_ipv4: I protocol, returning {:?}",
                r
            ));
            return r;
        }
        IpProtocol::Udp => {
            /* check with external firewall */
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_rx_process_ipv4: UDP protocol, parsing further"
            ));
            match client_rx_process_udp(ipv4_repr, ip_payload) {
                Ok(udp_packet_len) => {
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                        "Firewall client_rx_process_ipv4: keep UDP packet, udp_packet_len={}",
                        udp_packet_len
                    ));
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
                    let r = Ok(Some(ip_packet.total_len() as usize));
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                        "Firewall client_rx_process_ipv4: return IP packet of length = {:?}",
                        r
                    ));
                    return r;
                }
                Err(e) => {
                    /* drop packet */
                    let e = Err(e);
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                        "Firewall client_rx_process_ipv4: drop UDP packet, return {:?}",
                        e
                    ));
                    return e;
                }
            }
        }
        _ => {
            /* unknown protocol, drop packet */
            let e = Err(Error::Unrecognized);
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_rx_process_ipv4: Unknown protocol, returning error = {:?}",
                e
            ));
            return e;
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

    // copy data to the buffer
    unsafe {
        RX_UDP_PAYLOAD_BUFFER[0..udp_packet.payload().len()].copy_from_slice(udp_packet.payload());
    }

    #[cfg(feature = "debug-print")]
    println_sel4(format!(
        "Firewall client_rx_process_udp: calling external firewall.
        src_addr_byes = {:?},
        udp_packet.src_port = {},
        dst_addr_bytes = {:?},
        udp_packet.dst_port = {},
        udp payload len = {}
        buffer size = {}",
        src_addr_bytes,
        udp_packet.src_port(),
        dst_addr_bytes,
        udp_packet.dst_port(),
        udp_packet.payload().len() as u16,
        BUFFER_SIZE as u16,
    ));

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
        #[cfg(feature = "debug-print")]
        println_sel4(format!(
            "Firewall client_rx_process_udp: returned payload len = {}",
            payload_len
        ));
        if payload_len as usize > BUFFER_SIZE {
            let e = Err(Error::Dropped);
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_rx_process_udp: payload len > buffer size, returning {:?}",
                e
            ));
            return e;
        }
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

            let r = Ok(udp_repr.buffer_len());
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall client_rx_process_udp: udp packet created, returning {:?}",
                r
            ));
            return r;
        }
    } else {
        let e = Err(Error::Dropped);
        #[cfg(feature = "debug-print")]
        println_sel4(format!(
            "Firewall client_rx_process_udp: packet dropped, returning {:?}",
            e
        ));
        return e;
    }
}

static mut FIREWALL_RX: Option<Vec<Vec<u8>>> = None;

/// Event callback I believe
/// `badge` is not used
#[no_mangle]
pub extern "C" fn ethdriver_has_data_callback(_badge: u32) {
    #[cfg(feature = "debug-print")]
    println_sel4(format!(
        "Firewall ethdriver_has_data_callback: got badge = {}, processing...",
        _badge
    ));

    unsafe {
        loop {
            match firewall_rx() {
                FirewallRx::NoData => {
                    /* no data */
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                        "Firewall ethdriver_has_data_callback: firewall_rx() returned NoData, breaking"
                    ));
                    break;
                }
                FirewallRx::Data(packet) => {
                    /* add exactly one packet and break */
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                        "Firewall ethdriver_has_data_callback: firewall_rx() returned Data, add exactly one packet and break"
                    ));
                    match FIREWALL_RX {
                        None => {
                            /* Initialize FwRx */
                            #[cfg(feature = "debug-print")]
                            println_sel4(format!(
                            "Firewall ethdriver_has_data_callback: initialize FwRx with packet of length {}",
                            packet.len()
                            ));
                            FIREWALL_RX = Some(vec![packet]);
                        }
                        Some(ref mut packet_buffer) => {
                            /* add a packet to the buffer */
                            #[cfg(feature = "debug-print")]
                            println_sel4(format!(
                            "Firewall ethdriver_has_data_callback: add packet of length {} to a buffer with len {}",
                            packet.len(), packet_buffer.len()
                            ));
                            packet_buffer.push(packet);
                        }
                    }
                    break;
                }
                FirewallRx::MoreData(packet) => {
                    /* more packets in the queue, add one and keep looping */
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                        "Firewall ethdriver_has_data_callback: firewall_rx() returned MoreData, add  one packet and continue"
                    ));
                    match FIREWALL_RX {
                        None => {
                            /* Initialize FwRx */
                            #[cfg(feature = "debug-print")]
                            println_sel4(format!(
                            "Firewall ethdriver_has_data_callback: initialize FwRx with packet of length {}",
                            packet.len()
                            ));
                            FIREWALL_RX = Some(vec![packet]);
                        }
                        Some(ref mut packet_buffer) => {
                            /* add a packet to the buffer */
                            #[cfg(feature = "debug-print")]
                            println_sel4(format!(
                            "Firewall ethdriver_has_data_callback: add packet of length {} to a buffer with len {}",
                            packet.len(), packet_buffer.len()
                            ));
                            packet_buffer.push(packet);
                        }
                    }
                }
                FirewallRx::MaybeMoreData => {
                    /* no data now, but keep looping */
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                        "Firewall ethdriver_has_data_callback: got MaybeMoreData, keep looping"
                    ));
                }
            }
        } /* end of loop, no more data*/

        #[cfg(feature = "debug-print")]
        println_sel4(format!(
            "Firewall ethdriver_has_data_callback: loop ended, decide whether to emit"
        ));
        match FIREWALL_RX {
            Some(ref packet_buffer) => {
                /* check if the packet buffer is empty*/
                #[cfg(feature = "debug-print")]
                println_sel4(format!(
                    "Firewall ethdriver_has_data_callback: FwRx has some packet buffer, check if it is empty"
                ));
                if !packet_buffer.is_empty() {
                    /* we have some data in the queeue, emit*/
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                        "Firewall ethdriver_has_data_callback: packet buffer is not empty, len={}, client emit!",
                        packet_buffer.len()
                    ));
                    client_emit(1);
                } else {
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                        "Firewall ethdriver_has_data_callback: packet buffer is empty, don't emit"
                    ));
                }
            }
            None => {
                /* no data, do not emit */
                #[cfg(feature = "debug-print")]
                println_sel4(format!(
                    "Firewall ethdriver_has_data_callback: FwRx == None, don't emit"
                ));
            }
        }
    }
}

#[derive(Debug)]
enum FirewallRx {
    NoData,
    Data(Vec<u8>),
    MoreData(Vec<u8>),
    MaybeMoreData,
}

/// Call ethdriver_rx and return packet if possible
fn firewall_rx() -> FirewallRx {
    let mut len: i32 = 0;
    unsafe {ethdriver_buf_crit_lock();}
    let result = unsafe { ethdriver_rx(&mut len) };
    if result == -1 {
        let r = FirewallRx::NoData;
        #[cfg(feature = "debug-print")]
        println_sel4(format!(
            "Firewall firewall_rx: error reading ethdriver_rx: {}, returning {:?}",
            result, r
        ));
        unsafe {ethdriver_buf_crit_unlock();}
        return r;
    }

    // ethdriver_buf contains ethernet frame, attempt to parse it
    let eth_frame = match EthernetFrame::new_checked(sel4_ethdriver_rx_transmute(len)) {
        Ok(frame) => {
            #[cfg(feature = "debug-print")]
            println_sel4(format!("Firewall firewall_rx: got eth_frame = {}", frame));
            frame
        }
        Err(_e) => {
            let r;
            if result == 1 {
                r = FirewallRx::MaybeMoreData;
            } else {
                r = FirewallRx::NoData;
            }
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall firewall_rx: error parsing eth frame: {}, returning {:?}",
                _e, r
            ));
            unsafe {ethdriver_buf_crit_unlock();}
            return r;
        }
    };

    // Ignore any packets not directed to our hardware address.
    let local_ethernet_addr = get_device_mac();
    #[cfg(feature = "debug-print")]
    println_sel4(format!(
        "Firewall firewall_rx: local eth addr: {}",
        local_ethernet_addr
    ));
    #[cfg(feature = "mac-check")]
    {
        /* check the MAC address of the incoming frame */
        if !eth_frame.dst_addr().is_broadcast() && !eth_frame.dst_addr().is_multicast()
            && eth_frame.dst_addr() != local_ethernet_addr
        {
            let r;
            if result == 1 {
                r = FirewallRx::MaybeMoreData;
            } else {
                r = FirewallRx::NoData;
            }
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall firewall_rx: not the right destination address,
            is dst addr broadcast = {}, is dst addr multicast = {}, returning {:?}",
                eth_frame.dst_addr().is_broadcast(),
                eth_frame.dst_addr().is_multicast(),
                r
            ));
            unsafe {ethdriver_buf_crit_unlock();}
            return r;
        }
    }

    #[cfg(feature = "debug-print")]
    println_sel4(format!(
        "Firewall firewall_rx: EthernetProtocol = {}",
        eth_frame.ethertype()
    ));

    // Check if we have ipv4 traffic
    match eth_frame.ethertype() {
        EthernetProtocol::Ipv4 => {
            #[cfg(feature = "debug-print")]
            println_sel4(format!("Firewall firewall_rx: processing IPv4"));
            let mut fragments = unsafe {
                match client_rx_get_fragments_set() {
                    &None => None,
                    &Some(ref cell) => Some(&mut *cell.get()),
                }
            };

            // to disable reassembly of fragmented packets
            #[cfg(feature = "no-fragments")]
            let mut fragments = None;

            match client_rx_process_ipv4(&eth_frame, &mut fragments) {
                Ok(result) => {
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                        "Firewall firewall_rx: client_rx_process_ipv4 returned with OK"
                    ));
                    match result {
                        Some(ipv4_packet_len) => {
                            /* copy ipv4 packet data to the ethernetdriver_buf and pass it on */
                            #[cfg(feature = "debug-print")]
                            println_sel4(format!("Firewall firewall_rx: client_rx_process_ipv4 returned ipv4_packet_len = {}
                                                  so it was an UDP packet",ipv4_packet_len));
                            unsafe {
                                len = (ETHERNET_FRAME_PAYLOAD + ipv4_packet_len) as i32;
                                let local_buf_ptr =
                                    std::mem::transmute::<*mut c_void, *mut u8>(ethdriver_buf);
                                let slice =
                                    std::slice::from_raw_parts_mut(local_buf_ptr, len as usize);
                                slice[ETHERNET_FRAME_PAYLOAD..]
                                    .clone_from_slice(&RX_IPV4_PACKET_BUFFER[0..ipv4_packet_len]);
                                #[cfg(feature = "debug-print")]
                                println_sel4(format!(
                                    "Firewall firewall_rx: Updating buffer, len = {}",
                                    len
                                ));
                                #[cfg(feature = "debug-print")]
                                println_sel4(format!(
                                    "Firewall firewall_rx: Updating buffer, slice = {:?}",
                                    slice
                                ));
                            }
                        }
                        None => {
                            /* pass the packet unchanged */
                            #[cfg(feature = "debug-print")]
                            println_sel4(format!(
                                "Firewall firewall_rx: passing packet unchanged (not a UDP packet)"
                            ));
                        }
                    }
                }
                Err(_e) => {
                    /* error during packet processing occured */
                    let r;
                    if result == 1 {
                        r = FirewallRx::MaybeMoreData;
                    } else {
                        r = FirewallRx::NoData;
                    }
                    #[cfg(feature = "debug-print")]
                    println_sel4(format!(
                            "Firewall firewall_rx: client_rx_process_ipv4 returned with error: {}, returning {:?}",
                            _e, r
                    ));
                    unsafe {ethdriver_buf_crit_unlock();}
                    return r;
                }
            }
        }
        EthernetProtocol::Ipv6 => {
            /* Ipv6 traffic is not allowed */
            let r;
            if result == 1 {
                r = FirewallRx::MaybeMoreData;
            } else {
                r = FirewallRx::NoData;
            }
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall firewall_rx: dropping IPV6 traffic, returning {:?}",
                r
            ));
            unsafe {ethdriver_buf_crit_unlock();}
            return r;
        }
        EthernetProtocol::Arp => {
            /* Arp traffic is allowed, pass-through */
            #[cfg(feature = "debug-print")]
            println_sel4(format!("Firewall firewall_rx: passing through ARP traffic"));
        }
        _ => {
            /* drop unrecognized protocol */
            let r;
            if result == 1 {
                r = FirewallRx::MaybeMoreData;
            } else {
                r = FirewallRx::NoData;
            }
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall firewall_rx: drop unrecognized eth protocol, returning {:?}",
                r
            ));
            unsafe {ethdriver_buf_crit_unlock();}
            return r;
        }
    }

    // create a vector and return it
    unsafe {
        let mut data = Vec::with_capacity(len as usize);
        let local_buf_ptr = std::mem::transmute::<*mut c_void, *mut u8>(ethdriver_buf);
        let slice = std::slice::from_raw_parts_mut(local_buf_ptr, len as usize);
        data.extend_from_slice(slice);
        // extend_from_slice clones the data, so we can release the lock here.
        ethdriver_buf_crit_unlock();

        match result {
            0 => {
                // only one packet was available
                #[cfg(feature = "debug-print")]
                println_sel4(format!(
                    "Firewall firewall_rx: one packet, returning FirewallRx::Data(data)"
                ));
                return FirewallRx::Data(data);
            }
            1 => {
                // more than one packet was available
                #[cfg(feature = "debug-print")]
                println_sel4(format!(
                    "Firewall firewall_rx: more packets, returning FirewallRx::MoreData(data)"
                ));
                return FirewallRx::MoreData(data);
            }
            _ => {
                // this should never happen
                #[cfg(feature = "debug-print")]
                println_sel4(format!("Firewall firewall_rx: this should never happen"));
                unreachable!();
            }
        }
    }
}

/// To be called from `client_rx`
/// Coverts client data into `[u8]` and returns it.
/// The slice can be empty
fn sel4_ethdriver_rx_transmute<'a>(len: i32) -> &'a [u8] {
    unsafe {
        if ethdriver_buf.is_null() {
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall sel4_ethdriver_rx_transmute: ethdriver_buf is NULL! Aborting."
            ));
        }
        assert!(!ethdriver_buf.is_null());
        // create a slice of length `len` from the buffer
        let local_buf_ptr = std::mem::transmute::<*mut c_void, *mut u8>(ethdriver_buf);
        let slice = std::slice::from_raw_parts(local_buf_ptr, len as usize);
        slice
    }
}

/// To be called from `client_tx`
/// Coverts client data into `[u8]` and returns it.
/// The slice can be empty
fn sel4_ethdriver_tx_transmute<'a>(len: i32) -> &'a [u8] {
    unsafe {
        if client_buf(1).is_null() {
            #[cfg(feature = "debug-print")]
            println_sel4(format!(
                "Firewall sel4_ethdriver_tx_transmute: client_buf(1) is NULL! Aborting."
            ));
        }
        assert!(!client_buf(1).is_null());
        // create a slice of length `len` from the buffer
        let local_buf_ptr = std::mem::transmute::<*mut c_void, *mut u8>(client_buf(1));
        let slice = std::slice::from_raw_parts(local_buf_ptr, len as usize);
        slice
    }
}
