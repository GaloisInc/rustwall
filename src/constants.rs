/// Size of the seL4 buffer for data exchange
/// can be defined in CAMKES
/// MTU cannot be large than (BUFFER_SIZE + Eth_header)
/// Default value is 4096
pub const BUFFER_SIZE: usize = 4096;

/// The max size of the reassembled Ipv4 packet
/// Should fit the largest expected packet
/// Default is 65535
pub const MAX_REASSEMBLED_FRAGMENT_SIZE: usize = 65535;

/// Max size of a reassembled UDP packet, includes the header
/// Technically also the max Ipv4 payload size
pub const MAX_UDP_PACKET_SIZE: usize = MAX_REASSEMBLED_FRAGMENT_SIZE - IPV4_HEADER_SIZE - ETHERNET_FRAME_PAYLOAD;

/// Max size of a reassmbled UDP payload, no header
pub const MAX_UDP_PAYLOAD_SIZE: usize = MAX_REASSEMBLED_FRAGMENT_SIZE - UDP_HEADER_SIZE - IPV4_HEADER_SIZE - ETHERNET_FRAME_PAYLOAD;

/// The index of ethernet frame payload. Also the size of
/// the ethernet frame header
pub const ETHERNET_FRAME_PAYLOAD: usize = 14;
pub const UDP_HEADER_SIZE: usize = 8;
pub const IPV4_HEADER_SIZE: usize = 20;

/// Number of supported fragments. Make sure you allocate enough heap space!!
pub const SUPPORTED_FRAGMENTS: usize = 10;

/// Max ethernet MTU (max size of a single IPv4 packet)
pub const MTU: usize = 1500;

/// Max size of an individual UDP packet
pub const MTU_UDP: usize = MTU - IPV4_HEADER_SIZE;

/// For managing the extra CRC fields
pub const ETH_CRC_LEN: usize = 4;

/// Maximum number of packets (up to MTU size) in the packet queue
pub const MAX_ENQUEUED_PACKETS: usize = 20;