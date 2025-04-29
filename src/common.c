#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>

#include "../include/common.h"
#include "../include/err.h"

void cmn_close_socket(const int sockfd) {
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

/** Kod i komentarz zajumany z echo-server.c z labów udp. */
static void _init_addr(struct sockaddr_in *bind_address, const char *addr, const uint16_t port) {
    // Bind the socket to a concrete address
    bind_address->sin_family = AF_INET; // IPv4
    bind_address->sin_addr.s_addr = cmn_extract_ip4(addr);
    bind_address->sin_port = htons(port);
}

// TODO obsłużyć przypadek bez podanego portu (chyba obsluzony, bo port wtedy jest rowny 0)
void cmn_init_socket(int *sockfd, struct sockaddr_in *bind_address, const char *addr, const uint16_t port) {
    *sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (*sockfd < 0) {
        syserr("Socket creation failed");
    }

    _init_addr(bind_address, addr, port);

    if (bind(*sockfd, (struct sockaddr *) bind_address, (socklen_t) sizeof(*bind_address)) < 0) {
        cmn_close_socket(*sockfd);
        syserr("bind");
    }

    fprintf(stderr, "Listening on port %" PRIu16 "\n", port);
}

/**
 * "Ukradzione" z kodu z laboratoriów.
 */
uint16_t cmn_read_port(char const *string) {
    char *endptr;
    errno = 0; // TODO Czy mamy używać errno w całym projekcie?
    unsigned long port = strtoul(string, &endptr, 10);
    
    if (errno != 0 || *endptr != 0 || port == 0 || port > UINT16_MAX) {
        syserr("Given port is not a valid port number"); // FIXME w oryginalne `fatal`.
        // OG: fatal("%s is not a valid port number", string);
    }

    return (uint16_t) port;
}

uint32_t cmn_extract_ip4(const char *addr) {
    uint32_t inaddr = addr == NULL ? htonl(INADDR_ANY) : inet_addr(addr);
    if (inaddr == INADDR_NONE && addr != NULL) {
        syserr("Invalid IPv4 address");
    }

    return inaddr;
}
