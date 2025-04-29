#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../include/common.h"

// TODO: Skopiować mimową bibliotekę errorową. Czy można?
void syserr(const char *msg) {
    fprintf(stderr, "%s, exiting...\n", msg);
    exit(1);
}

void close_socket(const int sockfd) {
    if (sockfd >= 0) {
        close(sockfd);
        fprintf(stderr, "Socket closed.\n");
    }
}

/**
 * Zajumane z labów udp: funkcja `get_server_address`.
 * `port` must be in network order
 */
void cmn_set_address(char const *peer_ip_str, const uint16_t port, struct sockaddr_in *addr) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    struct addrinfo *address_result;
    int errcode = getaddrinfo(peer_ip_str, NULL, &hints, &address_result);
    if (errcode != 0) {
        syserr("getaddrinfo"); // OG: `fatal("getaddrinfo: %s", gai_strerror(errcode));`
    }

    addr->sin_family = AF_INET; // IPv4
    addr->sin_addr.s_addr =     // IP address
        ((struct sockaddr_in *) (address_result->ai_addr))->sin_addr.s_addr;
    addr->sin_port = port;

    freeaddrinfo(address_result);
}