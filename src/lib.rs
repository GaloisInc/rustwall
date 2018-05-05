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

extern crate smoltcp;
use smoltcp::wire::{EthernetAddress, EthernetProtocol, EthernetFrame};
use smoltcp::wire::{IpProtocol, IpRepr, IpAddress, Ipv4Repr, Ipv4Packet};
use smoltcp::{Error, Result};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{UdpRepr, UdpPacket};

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

#[no_mangle]
extern "C" {
    fn printf(val: *const i8);
}

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
    #[cfg(feature = "external-firewall")]
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
    #[cfg(feature = "external-firewall")]
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
#[no_mangle]
pub extern "C" fn client_tx(len: i32) -> i32 {
    // client_buf contains ethernet frame, attempt to parse it
    let eth_frame = match EthernetFrame::new_checked(sel4_ethdriver_transmute(len, client_buf(1))) {
        Ok(frame) => frame,
        Err(_) => return 0,
    };

    // Check if we have ipv4 traffic
    match eth_frame.ethertype() {
        #[cfg(feature = "external-firewall")]
        EthernetProtocol::Ipv4 => {
            #[cfg(feature = "debug-print")]
            unsafe {
                printf(b"TX: client_rx_process_ipv4\n\0".as_ptr() as *const i8);
            }
            match client_tx_process_ipv4(&eth_frame, len) {
                Ok(_) => { /* pass the packet */ }
                Err(_) => {
                    /* error occured */
                    return 0;
                }
            }
        }
        #[cfg(feature = "proto-ipv6")]
        EthernetProtocol::Ipv6 => {
            // Ipv6 traffic is not allowed
            return 0;
        }
        // passthrough the traffic ?
        _ => {
            #[cfg(feature = "debug-print")]
            unsafe {
                printf(b"TX: unknown ethertype\n\0".as_ptr() as *const i8);
            }
            #[cfg(not(feature = "passthrough"))]
            return 0;
        }
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
#[cfg(feature = "external-firewall")]
fn client_tx_process_ipv4<'frame>(
    eth_frame: &'frame EthernetFrame<&'frame [u8]>,
    len: *mut i32) -> Result<&'frame EthernetFrame<&'frame [u8]>> {
    let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload())?;
    let checksum_caps = ChecksumCapabilities::default();
    let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps)?;

    let ip_repr = IpRepr::Ipv4(ipv4_repr);
    let ip_payload = ipv4_packet.payload();

    match ipv4_repr.protocol {
        IpProtocol::Icmp => return Ok(eth_frame),
        IpProtocol::Udp => {
            /* check with external firewall */
            match client_tx_process_udp(ip_repr, ip_payload, len) {
                Ok(_) => return Ok(eth_frame),
                Err(_) => return Err(Error::Illegal),
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
#[cfg(feature = "external-firewall")]
fn client_rx_process_udp<'frame>(ip_repr: IpRepr, ip_payload: &'frame [u8], _len: *mut i32) -> Result<()> {
    let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
    let udp_packet = UdpPacket::new_checked(ip_payload)?;
    let checksum_caps = ChecksumCapabilities::default();
    let _udp_repr = UdpRepr::parse(&udp_packet, &src_addr, &dst_addr, &checksum_caps)?;

    // get proper addresses
    let src_addr_bytes = match src_addr {
        IpAddress::Ipv4(adr) => {
            let mut bytes = [0, 0, 0, 0];
            bytes[..].clone_from_slice(adr.as_bytes());
            unsafe { core::mem::transmute::<[u8; 4], u32>(bytes) }
        }
        _ => return Err(Error::Illegal),
    };

    let dst_addr_bytes = match dst_addr {
        IpAddress::Ipv4(adr) => {
            let mut bytes = [0, 0, 0, 0];
            bytes[..].clone_from_slice(adr.as_bytes());
            unsafe { core::mem::transmute::<[u8; 4], u32>(bytes) }
        }
        _ => return Err(Error::Illegal),
    };

    // call external firewall
    #[cfg(feature = "debug-print")]
    unsafe {
        printf(b"TX: Calling external firewall\n\0".as_ptr() as *const i8);
    }
    let ret_len = unsafe {
        packet_out(
            src_addr_bytes,
            udp_packet.src_port(),
            dst_addr_bytes,
            udp_packet.dst_port(),
            udp_packet.len() as u16,
            udp_packet.payload().as_ptr(),
            udp_packet.len() as u16,
        )
    };

    if ret_len > 0 {
        Ok(())
    } else {
        Err(Error::Dropped)
    }
}


/// copy `len` data from `ethdriver_buf` into `client_buf`
/// return -1 if some error happened, other values are OK (typically it is 0)
#[no_mangle]
pub extern "C" fn client_rx(len: *mut i32) -> i32 {
    let result = unsafe { ethdriver_rx(len) };
    if result == -1 {
        return result;
    }

    #[cfg(feature = "debug-print")]
    unsafe {
        printf(b"RX: parsing eth frame\n\0".as_ptr() as *const i8);
    }

    // ethdriver_buf contains ethernet frame, attempt to parse it
    let eth_frame = match EthernetFrame::new_checked(sel4_ethdriver_transmute(*len, ethdriver_buf)) {
        Ok(frame) => frame,
        Err(_) => return 0,
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
        return 0;
    }

    // Check if we have ipv4 traffic
    match eth_frame.ethertype() {
        #[cfg(feature = "external-firewall")]
        EthernetProtocol::Ipv4 => {
            #[cfg(feature = "debug-print")]
            unsafe {
                printf(b"RX: client_rx_process_ipv4\n\0".as_ptr() as *const i8);
            }
            match client_rx_process_ipv4(&eth_frame, len) {
                Ok(_) => { /* pass the packet */ }
                Err(_) => {
                    /* error occured */
                    return 0;
                }
            }
        }
        #[cfg(feature = "proto-ipv6")]
        EthernetProtocol::Ipv6 => {
            // Ipv6 traffic is not allowed
            return 0;
        }
        // passthrough the traffic ?
        _ => {
            #[cfg(feature = "debug-print")]
            unsafe {
                printf(b"RX: unknown ethertype\n\0".as_ptr() as *const i8);
            }
            #[cfg(not(feature = "passthrough"))]
            return 0;
        }
    }

    if result != -1 {
        unsafe {
            memcpy(client_buf(1), ethdriver_buf, *len as usize);
        }
    }
    return result;
}

/// Process ipv4 packet (only when external firewall is allowed)
/// Returns OK if:
/// - Ipv4 packet is well formed && of ICMP protocol (passthrough)
/// - Ipv4 packet is well formed && of UDP protocol && passes external firewall (external firewall)
/// otherwise returns error
#[cfg(feature = "external-firewall")]
fn client_rx_process_ipv4<'frame>(
    eth_frame: &'frame EthernetFrame<&'frame [u8]>,
    len: *mut i32) -> Result<&'frame EthernetFrame<&'frame [u8]>> {
    let ipv4_packet = Ipv4Packet::new_checked(eth_frame.payload())?;
    let checksum_caps = ChecksumCapabilities::default();
    let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps)?;

    let ip_repr = IpRepr::Ipv4(ipv4_repr);
    let ip_payload = ipv4_packet.payload();

    match ipv4_repr.protocol {
        IpProtocol::Icmp => return Ok(eth_frame),
        IpProtocol::Udp => {
            /* check with external firewall */
            match client_rx_process_udp(ip_repr, ip_payload, len) {
                Ok(_) => return Ok(eth_frame),
                Err(_) => return Err(Error::Illegal),
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
#[cfg(feature = "external-firewall")]
fn client_rx_process_udp<'frame>(ip_repr: IpRepr, ip_payload: &'frame [u8], _len: *mut i32) -> Result<()> {
    let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
    let udp_packet = UdpPacket::new_checked(ip_payload)?;
    let checksum_caps = ChecksumCapabilities::default();
    let _udp_repr = UdpRepr::parse(&udp_packet, &src_addr, &dst_addr, &checksum_caps)?;

    // get proper addresses
    let src_addr_bytes = match src_addr {
        IpAddress::Ipv4(adr) => {
            let mut bytes = [0, 0, 0, 0];
            bytes[..].clone_from_slice(adr.as_bytes());
            unsafe { core::mem::transmute::<[u8; 4], u32>(bytes) }
        }
        _ => return Err(Error::Illegal),
    };

    let dst_addr_bytes = match dst_addr {
        IpAddress::Ipv4(adr) => {
            let mut bytes = [0, 0, 0, 0];
            bytes[..].clone_from_slice(adr.as_bytes());
            unsafe { core::mem::transmute::<[u8; 4], u32>(bytes) }
        }
        _ => return Err(Error::Illegal),
    };

    // call external firewall
    #[cfg(feature = "debug-print")]
    unsafe {
        printf(b"RX: Calling external firewall\n\0".as_ptr() as *const i8);
    }
    let ret_len = unsafe {
        packet_in(
            src_addr_bytes,
            udp_packet.src_port(),
            dst_addr_bytes,
            udp_packet.dst_port(),
            udp_packet.len() as u16,
            udp_packet.payload().as_ptr(),
            udp_packet.len() as u16,
        )
    };

    if ret_len > 0 {
        Ok(())
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
fn sel4_ethdriver_transmute<'a>(len: usize, buffer: *mut c_void) -> &'a [u8] {
    unsafe {
        assert!(!buffer.is_null());
        // create a slice of length `len` from the buffer
        let local_buf_ptr = core::mem::transmute::<*mut c_void, *mut u8>(buffer);
        let slice = core::slice::from_raw_parts(local_buf_ptr, len);
        slice
    }
}
