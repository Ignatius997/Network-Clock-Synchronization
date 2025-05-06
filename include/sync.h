#ifndef NCS_SYNC_H
#define NCS_SYNC_H

#include <arpa/inet.h>
#include <stdint.h>

#define SYNC_NONE 255

uint8_t sync_get_expected_message(void);
void sync_reset(const struct sockaddr_in *peer_address);

#endif // NCS_SYNC_H