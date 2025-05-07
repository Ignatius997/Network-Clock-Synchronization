#ifndef TIMEOUTMAN_H
#define TIMEOUTMAN_H

#include <arpa/inet.h>

void timeout_sync_start(const struct sockaddr_in *peer_address);
void timeout_delay(void);

#endif // TIMEOUTMAN_H