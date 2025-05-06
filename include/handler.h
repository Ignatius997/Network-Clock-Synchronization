#ifndef NCS_HANDLER_H
#define NCS_HANDLER_H

#include <arpa/inet.h>

void handle_message(const struct sockaddr_in *peer_address, const ssize_t recv_len);
void handle_recv_fail(const struct sockaddr_in *peer_address);

#endif // NCS_HANDLER_H