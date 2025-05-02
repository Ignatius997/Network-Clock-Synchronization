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

#include "../include/netutil.h"
#include "../include/message.h"
#include "../include/peer.h"
#include "../include/globals.h"
#include "../include/err.h"

// ==== Internal helper functions ====

static uint32_t _extract_ip4(const char *addr) {
    uint32_t inaddr = addr == NULL ? htonl(INADDR_ANY) : inet_addr(addr);
    if (inaddr == INADDR_NONE && addr != NULL) {
        syserr("Invalid IPv4 address");
    }

    return inaddr;
}

/** Kod i komentarz zajumany z echo-server.c z labów udp. */
static void _init_addr(struct sockaddr_in *bind_address, const char *addr,
                       const uint16_t port) {
    // Bind the socket to a concrete address
    bind_address->sin_family = AF_INET; // IPv4
    bind_address->sin_addr.s_addr = _extract_ip4(addr);
    bind_address->sin_port = htons(port);
}

static int _validate_address(const struct sockaddr_in *addr) {
    // NOTE czy powinniśmy to w ogóle walidować?
    if (addr->sin_family != AF_INET) {
        syserr("Invalid address family"); // Nie powinno się wywalać
        return 1;
    }

    return 0;
}

static int _validate_received_length(const ssize_t recv_len) {
    // NOTE Program nie powinien się wywalać przy jednym złym receive, ale początkowo tak zróbmy dla świętego spokoju i debugowania
    Message *msg = (Message *)ncs_buf;

    if (recv_len < 0) {
        syserr("recvfrom failed"); // NOTE nie powinno się wywalać
        return -1;
    }

    if (recv_len < (ssize_t) msg_size(msg)) {
        syserr("recvfrom less bytes than message size."); // Można dodać rodzaj msg
        return -1;
    }

    return 0;
}

static int _validate_peer(const Peer *p) {
    if (p->peer_address_length != NUTIL_IPV4_ADDR_LEN) {
        syserr("Received incorrect peers"); // NOTE ofc nie powinno się wywalać
        return -1;
    }
    
    return 0;
}

/** Function does not assume, that there are any peers to validate in `ncs_buf`. */
static int _validate_peers() {
    Message *msg = (Message *)ncs_buf;

    if (msg->message == MSG_HELLO_REPLY) {
        uint16_t peers_count = ntohs(((HelloReplyMessage *)msg)->count);
        
        if (peers_count > 0) {
            size_t offset = msg_size(msg);
            
            fprintf(stderr, "Validating peers:\n");
            for (size_t i = 0; i < peers_count; ++i) {
                Peer *p = (Peer *) (ncs_buf + offset);
                if (_validate_peer(p) != 0) return -1; // Failure
                offset += sizeof(Peer);
            }
        }
        fprintf(stderr, "\n");
    }
    
    return 0;
}

// ==== Public library functions ====

/**
 * Zajumane z labów udp: funkcja `get_server_address`.
 * `port` must be in network order
 */
void nutil_set_address(char const *peer_ip_str, const uint16_t port,
                       struct sockaddr_in *addr) {
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

// TODO obsłużyć przypadek bez podanego portu (chyba obsluzony, bo port wtedy jest rowny 0)
void nutil_init_socket(struct sockaddr_in *bind_address,
                       const char *addr, const uint16_t port) {
    ncs_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ncs_sockfd < 0) {
        syserr("Socket creation failed");
    }

    _init_addr(bind_address, addr, port);

    if (bind(ncs_sockfd, (struct sockaddr *) bind_address,
             (socklen_t) sizeof(*bind_address)) < 0) {
        g_close_socket();
        syserr("bind");
    }
}

void nutil_extract_address(const Peer *p, struct sockaddr_in *addr) {
    char peer_ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, (struct in_addr *)p->peer_address,
                  peer_ip_str, INET_ADDRSTRLEN) == NULL) {
        syserr("inet_ntop failed");
    }

    nutil_set_address(peer_ip_str, p->peer_port, addr);
}

// TODO Możnaby to jakoś ujednolicić, żeby dołączający z _ar_provided też mógł użyć takiej funkcji WTF? O co mi chodziło?

/** Function assumes values in `peer_address` are in network order. */
void nutil_establish_connection(const struct sockaddr_in *peer_address) {
    uint8_t ip[16] = {0};
    memset(ip, 0, sizeof(ip));
    memcpy(ip, &peer_address->sin_addr, NUTIL_IPV4_ADDR_LEN);

    Peer p;
    p.peer_address_length = NUTIL_IPV4_ADDR_LEN;
    memcpy(p.peer_address, ip, sizeof(ip));
    p.peer_port = peer_address->sin_port;

    peer_add(&p);
}

int nutil_validate_received_data(const struct sockaddr_in *peer_address,
                                 const ssize_t recv_len) {
    int ret = _validate_received_length(recv_len);
    if (ret != 0) ret = _validate_address(peer_address);
    if (ret != 0) ret = _validate_peers();

    return ret;
}

/**
 * "Ukradzione" z kodu z laboratoriów.
 */
uint16_t nutil_read_port(char const *string) {
    char *endptr;
    errno = 0; // TODO Czy mamy używać errno w całym projekcie?
    unsigned long port = strtoul(string, &endptr, 10);
    
    if (errno != 0 || *endptr != 0 || port == 0 || port > UINT16_MAX) {
        syserr("Given port is not a valid port number"); // FIXME w oryginalne `fatal`.
        // OG: fatal("%s is not a valid port number", string);
    }

    return (uint16_t) port;
}
