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

use std::sync::{Arc, Mutex, Once, ONCE_INIT};
use std::mem;
use std::collections::BTreeMap;

use smoltcp::phy::Sel4Device;
use smoltcp::wire::{EthernetAddress, EthernetProtocol, EthernetFrame};
use smoltcp::wire::{IpProtocol, IpAddress, IpCidr, IpEndpoint, Ipv4Repr, Ipv4Packet};
use smoltcp::wire::{UdpRepr, UdpPacket};
use smoltcp::iface::{NeighborCache, EthernetInterfaceBuilder, EthernetInterface};
use smoltcp::socket::{SocketSet, SocketHandle};
use smoltcp::socket::{UdpSocket, UdpSocketBuffer, UdpPacketBuffer};
use smoltcp::time::Instant;
use smoltcp::phy::ChecksumCapabilities;

static PORT: u16 = 6969;
static HOP_LIMIT: u8 = 64;
static ETHERNET_FRAME_LEN: usize = 14; // 6 bytes src MAC, 6 bytes dest MAC, 2 bytes Protocol
                                       //static IFACE_ADDR: IpAddress = IpAddress::v4(192, 168, 69, 3); (lazy_static!)

#[derive(Clone)]
struct Firewall {
    iface: Arc<Mutex<EthernetInterface<'static, 'static, Sel4Device>>>,
    sockets: Arc<Mutex<SocketSet<'static, 'static, 'static>>>,
    handle: Arc<Mutex<SocketHandle>>,
}

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
            let ethernet_addr = get_device_mac();

            println!("IP: {}", ip_addrs[0]);
            println!("MAC: {}", ethernet_addr);

            let device = Sel4Device::new();
            let iface = EthernetInterfaceBuilder::new(device)
                .ethernet_addr(ethernet_addr)
                .neighbor_cache(neighbor_cache)
                .ip_addrs(ip_addrs)
                .finalize();

            let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketBuffer::new(vec![0; 1500])]);
            let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketBuffer::new(vec![0; 1500])]);
            let udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);

            let mut sockets = SocketSet::new(vec![]);
            let udp_handle = sockets.add(udp_socket);

            {
                // Bind UDP sockets to their respective ports
                let mut socket = sockets.get::<UdpSocket>(udp_handle);

                if !socket.is_open() {
                    socket
                        .bind(IpEndpoint::new(IpAddress::v4(192, 168, 69, 3), PORT))
                        .unwrap()
                }
            }

            // Make it
            let fw = Firewall {
                iface: Arc::new(Mutex::new(iface)),
                sockets: Arc::new(Mutex::new(sockets)),
                handle: Arc::new(Mutex::new(udp_handle)),
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
        println!("Sending vec/len() = {}, vec = {:?}", vec.len(), vec);
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
    println!("EthFrame = {:?}", &eth_frame);
    let data = &eth_frame.into_inner()[14..];
    let ipv4_packet = Ipv4Packet::new_checked(&data).unwrap();

    /*
	let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &ChecksumCapabilities::default()).unwrap();
    if !ipv4_repr.src_addr.is_unicast() {
        // Discard packets with non-unicast source addresses.
        return -1;
    }
    */

    let ip_payload = ipv4_packet.payload();

    // drop any non-UDP packets
    if let IpProtocol::Udp = ipv4_packet.protocol() {
        println!("IP protocol OK");
    } else {
        return -1;
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

    // perform checks
    if check_frame_out(&udp_packet.payload(), src_endpoint, dst_endpoint) {
        // all OK, pass data to ethdriver's transmit buffer
        let s = firewall_init();
        let mut iface = s.iface.lock().unwrap();
        let mut sockets = s.sockets.lock().unwrap();
        let timestamp = Instant::now();
        let handle = *s.handle.lock().unwrap();

        {
            let mut socket = sockets.get::<UdpSocket>(handle);

            println!("Sending data");
            if socket.can_send() {
                match socket.send_slice(udp_packet.payload(), dst_endpoint) {
                    Ok(_) => println!("data was sent"),
                    Err(e) => println!("data not sent, error: {}", e),
                }
            }
        }
        iface.poll(&mut sockets, timestamp).expect("poll error");
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

    println!("Rust client_rx: polling iface");
    iface.poll(&mut sockets, timestamp).expect("poll error");

    let mut socket = sockets.get::<UdpSocket>(handle); // just one handle for now (with a given port)

    if socket.can_recv() {
        let (data, src_endpoint) = socket.recv().unwrap(); // data: payload, endpoint: sender (IP+port)
        println!("Rust got data from {}: {:?}", src_endpoint, data);

        // make dst endpoint
        let dst_endpoint = IpEndpoint::new(iface.ip_addrs()[0].address(), 6969);

        // perform checks
        if check_frame_in(data, src_endpoint, dst_endpoint) {
            // checks OK, build the frame again

            // First generate UDP packet
            let udp_repr = UdpRepr {
                src_port: src_endpoint.port, // original source port
                dst_port: 6969,              // hardcoded for now
                payload: data,               // original payload
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
            println!("UDP packet: {:?}", udp_packet);

            // Then wrap it in an IP packet
            let src_addr = match src_endpoint.addr {
                IpAddress::Ipv4(adr) => adr,
                _ => panic!("unsupported address"),
            };

            let dst_addr = match iface.ip_addrs()[0].address() {
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

            println!("IP packet: {:?}", ip_packet);

            // Finally wrap it with an Ethernet frame
            let mut eth_bytes = vec![0xa5; ETHERNET_FRAME_LEN + ip_packet.total_len() as usize];
            let mut frame = EthernetFrame::new(&mut eth_bytes);
            frame.set_dst_addr(iface.ethernet_addr());
            frame.set_src_addr(EthernetAddress([0x06, 0xb4, 0x88, 0x85, 0xaa, 0xb4])); // Just a dummy for now (TODO)
            frame.set_ethertype(EthernetProtocol::Ipv4);
            frame.payload_mut().copy_from_slice(&ip_packet.into_inner());

            println!("Ethernet frame: {:?}", frame);
            let frame = frame.into_inner();
            println!("Ethernet frame len = {}", frame.len());

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
///
/// Input: UDP packet payload
///		   destination's endpoint (Ip addr + port)
/// Sender is obvious.
///
/// We are checking for:
/// 1. destination IP is allowed
/// 2. destination port is allowed
/// 3. source port is allowed (one from the bound sockets) // TODO: check if a separate port for sending is needed
fn check_frame_out(_tx_data: &[u8], _src: IpEndpoint, _dst: IpEndpoint) -> bool {
    // TODO: Dummy for now
    true
}

/// Perform checks on an incoming packet
/// returns `true` if the packet is OK to be received
/// Bonus: call the external firewall function
///
/// Input: UDP packet payload
///		   sender's IpEndpoint (Ip addr + port)
/// Destination is obvious. Port is statically set,
/// and can be retrieved from a socket handle. So no UDP packet
/// is received unless a socket is explicitly bound to a port
///
/// We are checking for:
/// 1. sender IP is allowed
/// 2. Maybe sender port?
fn check_frame_in(_rx_data: &[u8], _src: IpEndpoint, _dst: IpEndpoint) -> bool {
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