use libc::c_void;

extern "C" {
    pub static ethdriver_buf: *mut c_void;
    pub fn ethdriver_mac(
        b1: *mut u8,
        b2: *mut u8,
        b3: *mut u8,
        b4: *mut u8,
        b5: *mut u8,
        b6: *mut u8,
    );
    pub fn ethdriver_tx(len: i32) -> i32;
    pub fn ethdriver_rx(len: *mut i32) -> i32;

    pub fn ethdriver_buf_lock();
    pub fn ethdriver_buf_unlock();
    pub fn client_buf_lock();
    pub fn client_buf_unlock();

    /// For accessing client's buffer
    pub fn client_buf(cliend_id: u32) -> *mut c_void;
    pub fn client_emit(badge: u32);

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
    pub fn packet_in(
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
    pub fn packet_out(
        src_addr: u32,
        src_port: u16,
        dst_addr: u32,
        dst_port: u16,
        payload_len: u16,
        payload: *const u8,
        max_payload_len: u16,
    ) -> i32;
}

#[allow(dead_code)]
#[no_mangle]
extern "C" {
    fn printf(val: *const i8);
}

#[allow(dead_code)]
pub fn println_sel4(s: String) {
    unsafe {
        printf((s + "\n\0").as_ptr() as *const i8);
    }
}
