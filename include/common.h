#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <netinet/in.h>

void syserr(const char *msg); // To tu nie pasuje
void close_socket(const int sockfd);
void cmn_set_address(char const *peer_ip_str, const uint16_t port, struct sockaddr_in *addr);

#endif // COMMON_H