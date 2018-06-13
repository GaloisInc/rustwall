/**
 * C helper file for testing whether `lib.rs` actually compiles
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <fcntl.h>

#include "server_glue.h"


extern void client_mac(uint8_t *b1, uint8_t *b2, uint8_t *b3, uint8_t *b4,
    uint8_t *b5, uint8_t *b6);
extern int client_tx(int len);
extern int client_rx(int *len);
extern void ethdriver_has_data_callback(seL4_Word badge);

char packet_bytes[] = { 2, 0, 0, 0, 1, 1, 82, 84, 0, 0, 0, 0, 8, 0, 69, 0, 0,
    31, 0, 0, 64, 0, 64, 17, 47, 120, 192, 168, 69, 3, 192, 168, 69, 2, 175,
    211, 27, 57, 0, 11, 190, 19, 97, 97, 10 };

/**
 * Main program
 */
int main()
{
  /* Connect to the device */
  strcpy(tun_name, "tap1");
  tun_fd = tun_alloc(tun_name, IFF_TAP | IFF_NO_PI | O_NONBLOCK); /* tun interface */

  if (tun_fd < 0) {
    perror("Allocating interface");
    exit(1);
  }

  FD_ZERO(&set); /* clear the set */
  FD_SET(tun_fd, &set); /* add our file descriptor to the set */

  printf("hello from C\n");

  int len = 0;
  int returnval = 0;


  // client receive
  printf("Client receive call 1\n");
  returnval = client_rx(&len);
  printf("client_rx received %u bytes with return value %i\n", len, returnval);

   // data callback
   ethdriver_has_data_callback(66);

  char* buf = (char*)client_buf(1);
   // client transmit
   for (int i = 0; i <= sizeof(packet_bytes); i++) {
     //to_client_1_data.content[i] = packet_bytes[i];
     buf[i] = packet_bytes[i];
     len = i;
   }

   returnval = client_tx(len);
   printf("client_tx transmitted %u bytes with return value %i\n", len,
   returnval);

   returnval = client_tx(len);
   printf("client_tx transmitted %u bytes with return value %i\n", len,
   returnval);


  printf("done\n");
}
