#ifndef SERVER_GLUE_H
#define SERVER_GLUE_H

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
#include <stdbool.h>

int tun_alloc(char *dev, int flags);

/**
 * A helper define to make this look more like an actual seL4 file
 */
typedef uint32_t seL4_Word;

// Rust
extern void client_mac(uint8_t *b1, uint8_t *b2, uint8_t *b3, uint8_t *b4,
    uint8_t *b5, uint8_t *b6);
extern int client_tx(int len);
extern int client_rx(int *len);
extern void ethdriver_has_data_callback(seL4_Word badge);

// Local
int ethdriver_tx(int len);
int ethdriver_rx(int* len);
void ethdriver_mac(uint8_t *b1, uint8_t *b2, uint8_t *b3, uint8_t *b4,
    uint8_t *b5, uint8_t *b6);

bool ethdriver_init();

int tun_fd;
char tun_name[IFNAMSIZ];
char tun_buffer[1500];
fd_set set;
struct timeval timeout;
int rv;

#endif /* SERVER_GLUE_H */
