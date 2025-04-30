#ifndef NETHANDLE_H
#define NETHANDLE_H

#include "netrecv.h"

void nhandle_message(const struct sockaddr_in *peer_address, const uint8_t *buf, const ssize_t recv_len);
void 

#endif // NETHANDLE_H