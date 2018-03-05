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

extern int client_tx(int len);

typedef uint32_t seL4_Word;
extern void *client_buf(seL4_Word client_id);

char packet_bytes[] = { 2, 0, 0, 0, 1, 1, 82, 84, 0, 0, 0, 0, 8, 0, 69, 0, 0,
    31, 0, 0, 64, 0, 64, 17, 47, 120, 192, 168, 69, 3, 192, 168, 69, 2, 175,
    211, 27, 57, 0, 11, 190, 19, 97, 97, 10 };


/**
 * Main program
 */
int main()
{
   int len = 0;

  char* buf = (char*)client_buf(1);
  for (int i = 0; i <= sizeof(packet_bytes); i++) {
     buf[i] = packet_bytes[i];
     len = i;
   }

   int returnval = client_tx(len);
   printf("client_tx transmitted %u bytes with return value %i\n", len,
   returnval);

   returnval = client_tx(len);
   printf("client_tx transmitted %u bytes with return value %i\n", len,
   returnval);

}
