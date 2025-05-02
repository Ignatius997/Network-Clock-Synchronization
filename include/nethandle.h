#ifndef NETHANDLE_H
#define NETHANDLE_H

#include <arpa/inet.h>

void nhandle_message(const struct sockaddr_in *peer_address, const ssize_t recv_len);

#endif // NETHANDLE_H