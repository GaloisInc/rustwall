/// Rustwall example
///
/// Initialize tap device with:
///
///#!/bin/bash
///sudo ip tuntap add dev tap1 mode tap
///sudo ip addr add 192.168.69.1/24 broadcast 192.168.69.255 dev tap1
///sudo ip link set tap1 up
///
/// That will create a tap device with IP 192.168.69.1
/// The rustwall has itself an IP address of 192,168.69.2, so it appears to be on the same network,
/// but connected over the wire.
///
/// We then have a Virtualbox VM with a host-only adapter vboxnet0 with IP 192.168.56.1
/// In the VM we run a rustsocket helper program, that simulates virtio interface - it uses another
/// tap device created with the same command as above (IP 192.168.69.1).
///
/// Sockets are connected over vboxnet0 and when rustsocket is run, we can forward information as if it was
/// coming from real device behind the rustwall.
extern crate smoltcp;

use smoltcp::phy::wait as phy_wait;
use smoltcp::phy::TapInterface;
use std::net::UdpSocket;
use smoltcp::socket::{RawSocket, RawSocketBuffer, RawPacketBuffer, AsSocket, SocketSet};
use smoltcp::iface::{ArpCache, SliceArpCache, EthernetInterface};
use smoltcp::wire::{EthernetAddress, IpVersion, IpProtocol, IpAddress, Ipv4Address, Ipv4Packet,
                    UdpPacket, Ipv4Repr, UdpRepr};

use std::os::unix::io::AsRawFd;
use std::time::Instant;
use std::thread;
use std::sync::mpsc;

const INF_0: &str = "tap1";

/// Configuration struct that holds
/// data about which packeets to pass
struct FirewallConfiguration {
    name: String,
    addr_ok_to_send_to: Vec<Ipv4Address>,
    addr_ok_to_recv_from: Vec<Ipv4Address>,
    allowed_ports: Vec<u16>,
    allowed_protocols: Vec<IpProtocol>,
}

impl FirewallConfiguration {
    fn new(name: &str) -> FirewallConfiguration {
        FirewallConfiguration {
            name: String::from(name),
            addr_ok_to_send_to: vec![],
            addr_ok_to_recv_from: vec![],
            allowed_ports: vec![],
            allowed_protocols: vec![],
        }
    }

    /// Is the given port allowed to be used?
    /// Note: if the list of ports is empty, all ports are allowed
    fn is_allowed_port(&self, port: u16) -> bool {
        if self.allowed_ports.is_empty() {
            return true;
        }
        self.allowed_ports.contains(&port)
    }

    /// Is the given IP address allowed to be send to?
    /// Note: if the list of allowed addresses is empty, any address is allowed
    fn is_ok_to_send_to(&self, addr: Ipv4Address) -> bool {
        if self.addr_ok_to_send_to.is_empty() {
            return true;
        }
        self.addr_ok_to_send_to.contains(&addr)
    }

    /// Is the given IP address allowed to be received from?
    /// Note: if the list of allowed addresses is empty, any address is allowed
    fn is_ok_to_recv_from(&self, addr: Ipv4Address) -> bool {
        if self.addr_ok_to_recv_from.is_empty() {
            return true;
        }
        self.addr_ok_to_recv_from.contains(&addr)
    }

    /// Is the given IP protocol allowed to be used?
    /// Note: if the list of protocols is empty, all Ip protocols are allowed
    fn is_allowed_protocol(&self, protocol: IpProtocol) -> bool {
        if self.allowed_protocols.is_empty() {
            return true;
        }
        self.allowed_protocols.contains(&protocol)
    }
}



///
/// helper function
///
pub fn millis_since(startup_time: Instant) -> u64 {
    let duration = Instant::now().duration_since(startup_time);
    let duration_ms = (duration.as_secs() * 1000) + (duration.subsec_nanos() / 1000000) as u64;
    duration_ms
}


///
/// Main function
///
fn main() {
    let hardware_addr_0 = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);

    let local_addr = Ipv4Address::new(192, 168, 69, 2); // for VM:(192, 168, 69, 1) 

    let (tx_0, rx_0) = mpsc::channel();
    let (tx_1, rx_1) = mpsc::channel();

    let cfg_0 = FirewallConfiguration::new(INF_0);

    // FIXME: allow all pass-through
    //cfg_0.allowed_ports.push(6969);
    //cfg_0.allowed_protocols.push(IpProtocol::Udp);

    println!("Rustwall starting.");

    let th_0 =
        thread::spawn(move || thread_iface(INF_0, hardware_addr_0, local_addr, rx_0, tx_1, cfg_0));

    // Sending socket
    // Passes data to the VM interface
    let _ = thread::spawn(move || {
        let name = "socketTx";

        // bind to an IP address assigned to an existing interface & specific port
        let socket = UdpSocket::bind("192.168.56.1:6666").expect("couldn't bind to address"); // port at local interface
		// would be 6667 for VM

        println!("{} starting", name);
        loop {
            let data = rx_1.recv().expect("Couldn't receive data");
            let len = socket
                .send_to(data.as_slice(), "192.168.56.101:6666") 
                .expect("Couldn't send data");
            println!("{} Sent {} data.", name, len);
        }
    });


    // Receiving socket
    // Receives data from the VM interface and passes it to the firewall
    let _ = thread::spawn(move || {
        let name = "socketRx";

        // bind to an IP address assigned to an existing interface & specific port
        let socket = UdpSocket::bind("192.168.56.1:6667").expect("couldn't bind to address");
        // would be 6666 for VM
        
        socket
            .connect("192.168.56.101:6667")
            .expect("connect function failed");

        let mut buf = vec![0; 256];

        println!("{} starting", name);
        loop {
            match socket.recv(&mut buf) {
                Ok(len) => {
                    println!("{} received {} data.", name, len);
                    let data = buf[0..len].to_vec();
                    tx_0.send(data).expect("Couldn't send data");
                }
                Err(e) => println!("{} recv function failed: {:?}", name, e),
            }
        }
    });



    th_0.join().expect("Thread 0 error");
    println!("Rustwall terminating.");
}


///
/// Interface thread
///
fn thread_iface(iface_name: &str,
                hardware_addr: EthernetAddress,
                ipaddr: Ipv4Address,
                rx: mpsc::Receiver<Vec<u8>>,
                tx: mpsc::Sender<Vec<u8>>,
                cfg: FirewallConfiguration) {
    let startup_time = Instant::now();

    let device = TapInterface::new(iface_name).unwrap();
    //let device = PhySocket::new(iface_name).unwrap();
    let fd = device.as_raw_fd();

    let raw_rx_buffer = RawSocketBuffer::new(vec![RawPacketBuffer::new(vec![0; 256])]);
    let raw_tx_buffer = RawSocketBuffer::new(vec![RawPacketBuffer::new(vec![0; 256])]);
    let raw_socket = RawSocket::new(IpVersion::Ipv4,
                                    IpProtocol::Udp,
                                    raw_rx_buffer,
                                    raw_tx_buffer);

    let arp_cache = SliceArpCache::new(vec![Default::default(); 8]);

    println!("{} Creating interface {}", cfg.name, iface_name);
    let mut iface = EthernetInterface::new(Box::new(device),
                                           Box::new(arp_cache) as Box<ArpCache>,
                                           hardware_addr,
                                           [IpAddress::from(ipaddr)]);

    let mut sockets = SocketSet::new(vec![]);
    let raw_handle = sockets.add(raw_socket);

    println!("{} Starting", cfg.name);

    loop {
        {
            let socket: &mut RawSocket = sockets.get_mut(raw_handle).as_socket();

            // Receive a new packet from the socket
            if socket.can_recv() {
                println!("{} Got data", cfg.name);
                let payload = socket.recv().unwrap();
                //println!("{} raw packet: {:?}", cfg.name, payload);

                // first check source and destination IP
                let ipv4_packet = Ipv4Packet::new(payload);
                if !cfg.is_ok_to_recv_from(ipv4_packet.src_addr()) {
                    println!("{} Warning: Source IP: {:?} is not allowed",
                             cfg.name,
                             ipv4_packet.src_addr());
                    continue;
                }
                if !cfg.is_ok_to_send_to(ipv4_packet.dst_addr()) {
                    println!("{} Warning: Dest IP: {:?} is not allowed.",
                             cfg.name,
                             ipv4_packet.dst_addr());
                    continue;
                }

                // check protocol
                if !cfg.is_allowed_protocol(ipv4_packet.protocol()) {
                    println!("{} Warning: Protocol: {:?} is not allowed",
                             cfg.name,
                             ipv4_packet.protocol());
                    continue;
                }

                let payload = ipv4_packet.payload();
                let packet = UdpPacket::new(payload); // FIXME: Udp only now
                /* TODO: figure it out (UDP and TCP in common, possibly others)
                let packet = match ipv4_packet.protocol() {
                	IpProtocol::Udp => UdpPacket::new(payload),
                	IpProtocol::Tcp => TcpPacket::new(payload),
                	_ => panic!(),
                };
                */

                // check destination port
                if !cfg.is_allowed_port(packet.dst_port()) {
                    println!("{} Warning: Destination port: {} is not allowed.",
                             cfg.name,
                             packet.dst_port());
                    continue;
                }

                // checks passed, send the packet through
                println!("{} Checks passed, sending data through", cfg.name);
                tx.send(ipv4_packet.into_inner().to_vec()).unwrap();
            } // if socket.can_recv()


            // Check if we have a packet to send
            if socket.can_send() {
                //println!("{} Checking data to send", cfg.name);
                match rx.try_recv() {
                    Ok(payload) => {
                        println!("{} Sending data", cfg.name);

                        //println!("data: {:?}", payload);

                        // TODO: analyze packet with cfg and either drop/send it
                        //let ipv4_packet = Ipv4Packet::new(payload);
                        //println!("dest addr: {}", ipv4_packet.dst_addr());
                        //println!("src addr: {}", ipv4_packet.src_addr());

                        println!("Payload len = {}", payload.len());
                        let raw_payload = socket.send(payload.len()).unwrap();


                        let ipv4_packet = Ipv4Packet::new(payload.as_slice());
                        println!("ipv4_packet = {:?}", ipv4_packet);
                        let ipv4_repr = Ipv4Repr::parse(&ipv4_packet).unwrap();
                        println!("ipv4_repr = {:?}", ipv4_repr);


                        let mut ipv4_packet_tx = Ipv4Packet::new(raw_payload);
                        ipv4_repr.emit(&mut ipv4_packet_tx);
                        
                        
                        {
	                        let udp_payload = ipv4_packet_tx.payload_mut();
	                        println!("udp_payload ={:?}",udp_payload);
	                        let udp_packet = UdpPacket::new(ipv4_packet.payload());
	                        println!("udp_packet ={:?}",udp_packet);
	                        
	                        let src = IpAddress::Ipv4(ipv4_packet.src_addr());
	                        let dst = IpAddress::Ipv4(ipv4_packet.dst_addr());
	                        let udp_repr = UdpRepr::parse(&udp_packet, &src, &dst).unwrap();
	                        
	                        let mut udp_packet_tx = UdpPacket::new(udp_payload);
	                        udp_repr.emit(&mut udp_packet_tx, &src, &dst);
                        }
                        

                        /*
                        {
                        	let  payload = ipv4_packet_tx.payload_mut();
                        payload[0] = 0xb1;
                        payload[1] = 0x97;
                        payload[2] = 0x1b;
                        }
                        */

                        println!("ipv4_packet_tx = {:?}", ipv4_packet_tx);



                        /*
                                                print!("Raw payload = [");
                        for i in 0..payload.len() {
                            //raw_payload[i] = payload[i];
                            print!("{:x},",raw_payload[i]);
                        }
                        println!("];");
                        */

                        // just send out for now
                        //match socket.send(ipv4_packet.into_inner().len()) {
                        /*
                        match socket.send(payload.len()) {
                        //match socket.send_slice(payload.as_slice()) {
                        	Ok(raw_payload) => {
	                        	for i in 0..payload.len() {
	                        		raw_payload[i] = payload[i];
	                        	}
                        	},
                        	Err(e) => {
                        		println!("{} Error at socket.send_slice(payload.as_slice(): {}", cfg.name, e);
                        	}
                        }
                        */
                    }
                    Err(err) => {
                        println!("{} Error receiving data: {}", cfg.name, err);
                    }
                }
            } // if socket.can_send()
        }


        let timestamp = millis_since(startup_time);

        let poll_at = iface.poll(&mut sockets, timestamp).expect("poll error");
        println!("{} poll_at: {:?}", cfg.name, poll_at);
        //phy_wait(fd, poll_at.map(|at| at.saturating_sub(timestamp))).expect("wait error");
        phy_wait(fd, poll_at).expect("wait error");

        //phy_wait(fd, Some(1)).expect("wait error");

        //let poll_at = iface.poll(&mut sockets, timestamp).expect("poll error");
        //let resume_at = [poll_at, Some(send_at)].iter().flat_map(|x| *x).min();
        //phy_wait(fd, resume_at.map(|at| at.saturating_sub(timestamp))).expect("wait error");
    }
}
