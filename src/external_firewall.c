/**
 * Example of an external packet filter for UDP packet, a trivial case
 */
#include <stdint.h>
#include<string.h>

int32_t packet_in(uint32_t src_addr, uint16_t src_port, uint32_t dst_addr,
    uint16_t dst_port, uint16_t payload_len, uint8_t *payload,
    uint16_t max_payload_len);

int32_t packet_out(uint32_t src_addr, uint16_t src_port, uint32_t dst_addr,
    uint16_t dst_port, uint16_t payload_len, uint8_t *payload,
    uint16_t max_payload_len);

// For now always let the packet pass
int32_t packet_in(uint32_t src_addr, uint16_t src_port, uint32_t dst_addr,
    uint16_t dst_port, uint16_t payload_len, uint8_t *payload,
    uint16_t max_payload_len)
{
  if (dst_port == 6969) {
    // drop packets going to 6969 port
    return (int32_t)0;
  } else {
    // do nothing and return the original payload length => the packet is approved to be
    // sent unchanged
    return (int32_t)payload_len;
  }
}

// For now always let the packet pass
int32_t packet_out(uint32_t src_addr, uint16_t src_port, uint32_t dst_addr,
    uint16_t dst_port, uint16_t payload_len, uint8_t *payload,
    uint16_t max_payload_len)
{
  if (dst_port == 6966) {
    // drop packets going to 6966 port
    return (int32_t)0;
  } else {
    // do nothing and return the original payload length => the packet is approved to be
    // sent unchanged
    return (int32_t)payload_len;
  }
}
