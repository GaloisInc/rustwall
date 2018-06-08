pub const BUFFER_SIZE: usize = 4096;

/// default sel4 buffer size is 4096, subtract
/// udp header size and ipv4 header size, as well as
/// the ethernet header size, so the whole packet
/// can fit into the sel4 buffer, i.e.:
/// BUFFER_SIZE = 4096 - UDP_HEADER_SIZE - IPV4_HEADER_SIZE - ETH_HEADER_SIZE
///             = 4096  - 8 - 20 - 14
///             = 4054
pub const UDP_BUFFER_SIZE: usize = BUFFER_SIZE - UDP_HEADER_SIZE - IPV4_HEADER_SIZE - ETHERNET_FRAME_PAYLOAD;

/// The index of ethernet frame payload. Also the size of
/// the ethernet frame header
pub const ETHERNET_FRAME_PAYLOAD: usize = 14;
pub const UDP_HEADER_SIZE: usize = 8;
pub const IPV4_HEADER_SIZE: usize = 20;

/// The max size of the reassembled packet
pub const MAX_REASSEMBLED_FRAGMENT_SIZE: usize = 65535;

/// Number of supported fragments. Make sure you allocate enough heap space!!
pub const SUPPORTED_FRAGMENTS: usize = 10;

/// Max ethernet MTU
pub const MTU: usize = 1500;

/// To get max permissible udp packet size, we have to subtract
/// IPv4 header size from MTU
pub const MAX_UDP_PACKET_SIZE: usize = MTU - IPV4_HEADER_SIZE;