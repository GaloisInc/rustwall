#![feature(libc)]
#![deny(unused)]
///
/// Rust version of Firewall camkes component
/// see `firewall.c` for the original C version
/// Original source: `https://github.com/seL4/camkes-vm/tree/master/components/Firewall`
///
extern crate libc;
extern crate smoltcp;
extern crate xml;

use xml::reader::{EventReader, XmlEvent};
use xml::attribute::OwnedAttribute;

use libc::{c_void, memcpy};
use std::str::FromStr;
use std::slice;
use std::fmt;

use std::sync::{Arc, Mutex, Once, ONCE_INIT};
use std::mem;
use std::collections::BTreeMap;

use smoltcp::phy::Sel4Device;
use smoltcp::wire::{EthernetAddress, EthernetProtocol, EthernetFrame};
use smoltcp::wire::{IpProtocol, IpAddress, IpCidr, IpEndpoint, Ipv4Repr, Ipv4Packet, Ipv4Address};
use smoltcp::wire::{UdpRepr, UdpPacket};
use smoltcp::iface::{NeighborCache, EthernetInterfaceBuilder, EthernetInterface};
use smoltcp::socket::{SocketSet, SocketHandle};
use smoltcp::socket::{UdpSocketBuffer, UdpSocket, UdpPacketMetadata};
use smoltcp::time::Instant;
use smoltcp::phy::ChecksumCapabilities;

/// add extra 20 bytes to each UDP payload to allow for packet modification in the external firewall
static EXTRA_PACKET_CAPACITY: usize = 20;
static HOP_LIMIT: u8 = 64;
static ETHERNET_FRAME_LEN: usize = 14; // 6 bytes src MAC, 6 bytes dest MAC, 2 bytes Protocol

static CONFIG_STR: &'static str = include_str!("../config.xml"); // main configuration file

/// Main struct encompasing firewall network interface,
/// socket set with associated handles and configuration struct
///
/// <b>TODO:</b> convert into a single Arc<Mutex<T>> struct for easier handling.
#[derive(Clone)]
struct Firewall {
    iface: Arc<Mutex<EthernetInterface<'static, 'static, Sel4Device>>>,
    sockets: Arc<Mutex<SocketSet<'static, 'static, 'static>>>,
    handles: Arc<Mutex<Vec<SocketHandle>>>,
    config: Arc<Mutex<FirewallConfig>>,
}

/// Basic firewall configuration struct
/// Initialized from `CONFIG_STR` xml configuration, it currently provides:
/// - IP address of the network interface (and its netmask)
/// - open ports
#[derive(Debug)]
struct FirewallConfig {
    ports: Vec<u16>,
    local_ip: Ipv4Address,
    netmask: u8,
}

impl fmt::Display for FirewallConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut s = format!("IP addr: {}, netmask: {}\n", self.local_ip, self.netmask);
        s += "Ports:\n";
        for port in &self.ports {
            s += &format!("- {},\n", port);
        }
        write!(f, "{}", s)
    }
}

/// Auxilliary enum to make xml parsing cleaner
#[derive(Debug)]
enum ConfigTags {
    Firewall,
    OpenPorts,
    Port,
}

impl FromStr for ConfigTags {
    type Err = ();

    fn from_str(s: &str) -> Result<ConfigTags, ()> {
        match s {
            "firewall" => Ok(ConfigTags::Firewall),
            "open_ports" => Ok(ConfigTags::OpenPorts),
            "port" => Ok(ConfigTags::Port),
            _ => Err(()),
        }
    }
}

/// Check presence of an attribute in an xml tag
fn has_attribute(attributes: &Vec<OwnedAttribute>, value: &str) -> (bool, usize) {
    let mut idx = 0;
    for attr in attributes {
        if attr.name.local_name == value {
            return (true, idx);
        }
        idx += 1;
    }
    return (false, idx);
}

/// Parse configuration string (an xml file) and return
/// a `FirewallConfig` struct.
///
/// <b>TODO:</b> better error handling to avoid panic?
/// <b>TODO:</b>
fn parse_config_string(config: &str) -> FirewallConfig {
    let mut ports = Vec::new();
    let mut ip_addr = Ipv4Address::default();
    let mut netmask = 0;

    let parser = EventReader::from_str(config);
    for e in parser {
        match e {
            Ok(XmlEvent::StartElement {
                name, attributes, ..
            }) => {
                match ConfigTags::from_str(name.local_name.as_ref()).unwrap() {
                    ConfigTags::Port => {
                        let (name_ok, idx) = has_attribute(&attributes, "number");
                        if name_ok {
                            ports.push(attributes[idx].value.parse::<u16>().unwrap());
                        } else {
                            panic!(
                                "No attribute 'number' present. Attributes: {:?}",
                                attributes
                            );
                        }
                    }
                    ConfigTags::Firewall => {
                        let (addr_ok, idx) = has_attribute(&attributes, "ip_addr");
                        if addr_ok {
                            let octets: Vec<u8> = attributes[idx]
                                .value
                                .split('.')
                                .map(|x| x.parse::<u8>().unwrap())
                                .collect();
                            ip_addr = Ipv4Address::from_bytes(&octets);
                        } else {
                            panic!(
                                "No attribute 'ip_addr' present. Attributes: {:?}",
                                attributes
                            );
                        }
                        let (mask_ok, idx) = has_attribute(&attributes, "netmask");
                        if mask_ok {
                            netmask = attributes[idx].value.parse::<u8>().unwrap();
                        } else {
                            panic!(
                                "No attribute 'netmask' present. Attributes: {:?}",
                                attributes
                            );
                        }
                    }
                    ConfigTags::OpenPorts => {
                        // TODO: check gthe existence of this tag before reading the ports?
                        // do nothing
                    }
                }
            }
            Ok(XmlEvent::EndElement { .. }) => {
                // do nothing for now
            }
            Err(e) => {
                println!("Error: {}", e);
                break;
            }
            _ => {}
        }
    }

    FirewallConfig {
        ports: ports,
        local_ip: ip_addr,
        netmask: netmask,
    }
}

/// Initialize singleton
fn firewall_init() -> Firewall {
    static mut SINGLETON: *const Firewall = 0 as *const Firewall;
    static ONCE: Once = ONCE_INIT;

    unsafe {
        ONCE.call_once(|| {
            println!("Firewall init");
            let conf = parse_config_string(CONFIG_STR);
            println!("Firewall Config: {}", conf);

            let neighbor_cache = NeighborCache::new(BTreeMap::new());

            let ip_addrs = [IpCidr::new(IpAddress::Ipv4(conf.local_ip), conf.netmask)];
            let ethernet_addr = get_device_mac();

            println!("Firewall MAC: {}", ethernet_addr);

            let device = Sel4Device::new();
            let iface = EthernetInterfaceBuilder::new(device)
                .ethernet_addr(ethernet_addr)
                .neighbor_cache(neighbor_cache)
                .ip_addrs(ip_addrs)
                .finalize();

            let mut sockets = SocketSet::new(vec![]);
            let mut handles = Vec::new();

            // initialize buffers
            for _ in 0..conf.ports.len() {
                let udp_rx_buffer =
                    UdpSocketBuffer::new(vec![UdpPacketMetadata::empty()], vec![0; 1500]);
                let udp_tx_buffer =
                    UdpSocketBuffer::new(vec![UdpPacketMetadata::empty()], vec![0; 1500]);
                let udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);

                handles.push(sockets.add(udp_socket));
            }

            {
                // bind sockets to proper ports
                for (handle, port) in handles.iter().zip(&conf.ports) {
                    // Bind UDP sockets to their respective ports
                    let mut socket = sockets.get::<UdpSocket>(*handle);
                    if !socket.is_open() {
                        socket
                            .bind(IpEndpoint::new(IpAddress::Ipv4(conf.local_ip), *port))
                            .unwrap()
                    }
                }
            }

            // Create firewall struct
            let fw = Firewall {
                iface: Arc::new(Mutex::new(iface)),
                sockets: Arc::new(Mutex::new(sockets)),
                handles: Arc::new(Mutex::new(handles)),
                config: Arc::new(Mutex::new(conf)),
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
    fn ethdriver_mac(b1: *mut u8, b2: *mut u8, b3: *mut u8, b4: *mut u8, b5: *mut u8, b6: *mut u8);

    // For accessing client's buffer
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
/// Returns -1 if some error happens (such as a packet is declined), other values are OK (typically it is 0).
/// Expects raw ethernet frames.
/// Allows transmission of only UDP packets at explicitly specified ports (see `FirewallConfig`)
/// Validates packet checksum before transmission
///
/// 1. copy and parse client data (ethernet frame -> Ipv4 packet -> UDP packet)
/// 2. call external firewall if the source port is allowed
/// 3. if the packet is approved to be transmitted, reconstruct a Ipv4 packet and an ethernet frame
///    with the potentially modified UDP payload (i.e. UDP Payload -> IPv4 packet -> Ethernet frame)
/// 4. copy the ethernet frame to the ethdriver buffer
#[no_mangle]
pub extern "C" fn client_tx(len: i32) -> i32 {
    assert!(len >= 0);
    // get data to transmit as a vector
    let frame = sel4_client_transmute(len as usize);
    let eth_frame = EthernetFrame::new_checked(frame).unwrap();
    println!("Client_tx: eth_frame {}", eth_frame);

    // drop any non-ipv4 packets
    // no other ethernet checks are necessary
    if let EthernetProtocol::Ipv4 = eth_frame.ethertype() {
        println!("network protocol OK");
    } else {
        return -1;
    }

    // create a Ipv4 packet
    let data = &eth_frame.into_inner()[ETHERNET_FRAME_LEN..];
    let ipv4_packet = Ipv4Packet::new_checked(&data).unwrap();

    let ip_payload = ipv4_packet.payload();

    // drop any non-UDP packets
    if let IpProtocol::Udp = ipv4_packet.protocol() {
        println!("IP protocol OK (UDP)");
    } else {
        println!("Not a UDP packet, silently dropping");
        return 0;
    }

    // create UDP packet
    let udp_packet = UdpPacket::new_checked(ip_payload).unwrap();

    // get endpoints
    let dst_endpoint = IpEndpoint::new(
        IpAddress::Ipv4(ipv4_packet.dst_addr()),
        udp_packet.dst_port(),
    );
    let src_endpoint = IpEndpoint::new(
        IpAddress::Ipv4(ipv4_packet.src_addr()),
        udp_packet.src_port(),
    );

    let s = firewall_init();
    let mut iface = s.iface.lock().unwrap();
    let mut sockets = s.sockets.lock().unwrap();
    let timestamp = Instant::now();
    let handles = s.handles.lock().unwrap();

    // now iterate over sockets, and send from the one that is bound to src_endpoint
    for handle in handles.iter() {
        let mut socket = sockets.get::<UdpSocket>(*handle);
        if socket.can_send() && socket.endpoint() == src_endpoint {
            if socket.can_send() {
                // get proper addresses
                let src_addr_bytes = match src_endpoint.addr {
                    IpAddress::Ipv4(adr) => {
                        let mut bytes = [0, 0, 0, 0];
                        bytes[..].clone_from_slice(adr.as_bytes());
                        unsafe { mem::transmute::<[u8; 4], u32>(bytes) }
                    }
                    _ => panic!("unsupported address"),
                };

                let dst_addr_bytes = match dst_endpoint.addr {
                    IpAddress::Ipv4(adr) => {
                        let mut bytes = [0, 0, 0, 0];
                        bytes[..].clone_from_slice(adr.as_bytes());
                        unsafe { mem::transmute::<[u8; 4], u32>(bytes) }
                    }
                    _ => panic!("unsupported address"),
                };

                // make data mutable
                let mut udp_data =
                    Vec::with_capacity(udp_packet.payload().len() + EXTRA_PACKET_CAPACITY);
                udp_data.extend_from_slice(udp_packet.payload());

                let data_len = udp_data.len();
                let max_data_len = udp_data.capacity();
                let data_ptr = udp_data.as_mut_ptr();

                // call external firewall
                let ret_len = unsafe {
                    packet_out(
                        src_addr_bytes,
                        src_endpoint.port,
                        dst_addr_bytes,
                        dst_endpoint.port,
                        data_len as u16,
                        data_ptr,
                        max_data_len as u16,
                    )
                };

                // update vector
                unsafe {
                    mem::forget(udp_data);
                    udp_data = Vec::from_raw_parts(data_ptr, ret_len as usize, max_data_len);
                }

                if ret_len > 0 {
                    // packet was approved, send it
                    match socket.send_slice(&udp_data, dst_endpoint) {
                        Ok(_) => println!("data was sent"),
                        Err(e) => println!("data not sent, error: {}", e),
                    }
                } else {
                    println!("Checks failed, no packet transmitted");
                    return -1;
                }
            }
        }
    }

    iface.poll(&mut sockets, timestamp).expect("client tx poll error");
    0
}

/// To be called from camkes VM app.
/// Receives `len` bytes of data into `client_buf`.
/// Returns -1 if some error happens (such as a packet is declined), other values are OK (typically it is 0).
/// Returns raw ethernet frames.
/// Allows reception of only UDP packets at explicitly specified ports (see `FirewallConfig`)
/// Validates packet checksum upon reception.
///
/// 1. receive data from at most one bound socket
/// 2. call external firewall
/// 3. if the packet is approved, construct a full IPv4 packet and an etherent frame
///    from the potentially modified payload (i.e. UDP payload -> IPv4 packet -> Ethernet frame)
///    before passing data to the client buffer
/// 4. copy the ethernet frame to the client buffer
#[no_mangle]
pub extern "C" fn client_rx(len: *mut i32) -> i32 {
    // get data from ethernet driver
    let s = firewall_init();
    let mut iface = s.iface.lock().unwrap();
    let mut sockets = s.sockets.lock().unwrap();
    let timestamp = Instant::now();
    let handles = s.handles.lock().unwrap();

    iface.poll(&mut sockets, timestamp).expect("client_rx poll error");

    for handle in handles.iter() {
        let mut socket = sockets.get::<UdpSocket>(*handle);

        if socket.can_recv() {
            // return dst endpoint
            let dst_endpoint = socket.endpoint();

            let (data, src_endpoint) = socket.recv().unwrap(); // data: payload, endpoint: sender (IP+port)
            println!("Rust got data from {}", src_endpoint);

            // get proper addresses
            let src_addr_bytes = match src_endpoint.addr {
                IpAddress::Ipv4(adr) => {
                    let mut bytes = [0, 0, 0, 0];
                    bytes[..].clone_from_slice(adr.as_bytes());
                    unsafe { mem::transmute::<[u8; 4], u32>(bytes) }
                }
                _ => panic!("unsupported address"),
            };

            let dst_addr_bytes = match dst_endpoint.addr {
                IpAddress::Ipv4(adr) => {
                    let mut bytes = [0, 0, 0, 0];
                    bytes[..].clone_from_slice(adr.as_bytes());
                    unsafe { mem::transmute::<[u8; 4], u32>(bytes) }
                }
                _ => panic!("unsupported address"),
            };

            // make data mutable
            let mut udp_data = Vec::with_capacity(data.len() + EXTRA_PACKET_CAPACITY);
            udp_data.extend_from_slice(data);

            let data_len = udp_data.len();
            let max_data_len = udp_data.capacity();
            let data_ptr = udp_data.as_mut_ptr();

            // call external firewall
            let ret_len = unsafe {
                packet_in(
                    src_addr_bytes,
                    src_endpoint.port,
                    dst_addr_bytes,
                    dst_endpoint.port,
                    data_len as u16,
                    data_ptr,
                    max_data_len as u16,
                )
            };

            // update vector
            unsafe {
                mem::forget(udp_data);
                udp_data = Vec::from_raw_parts(data_ptr, ret_len as usize, max_data_len);
            }

            if ret_len > 0 {
                // checks OK, build the frame again

                // First generate UDP packet
                let udp_repr = UdpRepr {
                    src_port: src_endpoint.port,
                    dst_port: dst_endpoint.port,
                    payload: &udp_data,
                }; // can get raw UDP bytes
                let mut udp_bytes = vec![0xa5; udp_repr.buffer_len()]; // UDP packet
                let udp_packet_len = udp_bytes.len();
                let mut udp_packet = UdpPacket::new(&mut udp_bytes);
                udp_repr.emit(
                    &mut udp_packet,
                    &src_endpoint.addr,
                    &iface.ip_addrs()[0].address(),
                    &ChecksumCapabilities::default(),
                );

                // Then wrap it in an IP packet
                let src_addr = match src_endpoint.addr {
                    IpAddress::Ipv4(adr) => adr,
                    _ => panic!("unsupported address"),
                };

                let dst_addr = match dst_endpoint.addr {
                    IpAddress::Ipv4(adr) => adr,
                    _ => panic!("unsupported address"),
                };

                let ip_repr = Ipv4Repr {
                    src_addr: src_addr,        // original src addr
                    dst_addr: dst_addr,        // iface (dest) addr
                    protocol: IpProtocol::Udp, // udp only
                    payload_len: udp_repr.buffer_len(),
                    hop_limit: HOP_LIMIT,
                }; // to get raw IP packet
                let mut ip_bytes = vec![0xa5; ip_repr.buffer_len() + udp_packet_len];
                let mut ip_packet = Ipv4Packet::new(ip_bytes.as_mut_slice());
                ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::default());
                ip_packet
                    .payload_mut()
                    .copy_from_slice(&udp_packet.into_inner());

                // Finally wrap it with an Ethernet frame
                let mut eth_bytes = vec![0xa5; ETHERNET_FRAME_LEN + ip_packet.total_len() as usize];
                let mut frame = EthernetFrame::new(&mut eth_bytes);
                frame.set_dst_addr(iface.ethernet_addr());
                frame.set_src_addr(iface.ethernet_addr()); // This might be a problem for the VM net stack (src == dst mac)
                                                           //frame.set_src_addr(EthernetAddress([0x06, 0xb4, 0x88, 0x85, 0xaa, 0xb4])); // Just a dummy for now (TODO)
                frame.set_ethertype(EthernetProtocol::Ipv4);
                frame.payload_mut().copy_from_slice(&ip_packet.into_inner());

                let frame = frame.into_inner();

                // finally copy data to the caller's buffer
                unsafe {
                    memcpy(client_buf(1), frame.as_ptr() as *mut c_void, frame.len());
                    *len = frame.len() as i32;
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
    unsafe {
        ethdriver_mac(b1, b2, b3, b4, b5, b6);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn print_array(name: &str, b: &[u8]) {
        print!("{}[{}]=[", name, b.len());
        for i in b {
            print!("0x{:x},", i);
        }
        println!("];");
    }

    #[test]
    fn basic() {
        println!("hello testing here");
    }
}
