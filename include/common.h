#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <arpa/inet.h>

void cmn_close_socket(const int sockfd);
void cmn_set_address(char const *peer_ip_str, const uint16_t port, struct sockaddr_in *addr);
void cmn_init_socket(int *sockfd, struct sockaddr_in *bind_address, const char *addr, const uint16_t port);

uint16_t cmn_read_port(char const *string);
uint32_t cmn_extract_ip4(const char *addr);

#endif // COMMON_H