/**
 * Example of an external packet filter for UDP packet, a trivial case
 */
#include <stdint.h>
#include<string.h>

uint16_t packet_in(uint32_t src_addr, uint16_t src_port, uint32_t dst_addr,
    uint16_t dst_port, uint16_t payload_len, uint8_t *payload,
    uint16_t max_payload_len);

uint16_t packet_out(uint32_t src_addr, uint16_t src_port, uint32_t dst_addr,
    uint16_t dst_port, uint16_t payload_len, uint8_t *payload,
    uint16_t max_payload_len);

// For now always let the packet pass
uint16_t packet_in(uint32_t src_addr, uint16_t src_port, uint32_t dst_addr,
    uint16_t dst_port, uint16_t payload_len, uint8_t *payload,
    uint16_t max_payload_len)
{
#ifdef PACKET_MODIFICATION_TEST
  // fill the extra data with 'a'
  for (int16_t idx = payload_len; idx < max_payload_len; idx++) {
    payload[idx] = 'a';
  }
  return max_payload_len;
#else
  // do nothing and return the original payload length => the packet is approved to be
  // sent unchanged
  return payload_len;
#endif
}

// For now always let the packet pass
uint16_t packet_out(uint32_t src_addr, uint16_t src_port, uint32_t dst_addr,
    uint16_t dst_port, uint16_t payload_len, uint8_t *payload,
    uint16_t max_payload_len)
{
#ifdef PACKET_MODIFICATION_TEST
  // fill the extra data with 'a'
  for (int16_t idx = payload_len; idx < max_payload_len; idx++) {
    payload[idx] = 'a';
  }
  return max_payload_len;
#else
  // do nothing and return the original payload length => the packet is approved to be
  // sent unchanged
  return payload_len;
#endif
}
