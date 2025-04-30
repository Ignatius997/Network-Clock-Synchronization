#ifndef NETUTIL_H
#define NETUTIL_H

#include <stdint.h>
#include <arpa/inet.h>

#include "message.h"
#include "peer.h"

void cmn_close_socket(const int sockfd);

void     nutil_set_address(char const *peer_ip_str, const uint16_t port, struct sockaddr_in *addr);
void     nutil_init_socket(int *sockfd, struct sockaddr_in *bind_address, const char *addr, const uint16_t port);
void     nutil_extract_address(const Peer *p, struct sockaddr_in *addr);
void     nutil_establish_connection(const struct sockaddr_in *peer_address);
int      nutil_validate_received_data(const struct sockaddr_in *peer_address, const uint8_t *buf, const ssize_t recv_len);
uint16_t nutil_read_port(char const *string);

#endif // NETUTIL_H