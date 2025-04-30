#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "../include/peer.h"
#include "../include/err.h"

typedef struct {
    Peer *peers;
    uint16_t count;
    uint16_t capacity;
} PeerManager;

static PeerManager peer_manager = {NULL, 0, 0};

void peer_cleanup(void) {
    free(peer_manager.peers);
    peer_manager.peers = NULL;
    peer_manager.count = 0;
    peer_manager.capacity = 0;
}

void peer_add(const Peer *p) {
    if (peer_manager.count == UINT16_MAX) {
        syserr("Too many peers"); // TODO czy może coś innego zrobić.
    }

    if (peer_manager.count + 1 >= peer_manager.capacity) {
        peer_manager.capacity = (peer_manager.capacity == 0) ? 1 : peer_manager.capacity << 1;
        peer_manager.peers = (Peer *) realloc(peer_manager.peers, peer_manager.capacity * sizeof(Peer));
        if (peer_manager.peers == NULL) syserr("realloc");
    }

    memcpy(&peer_manager.peers[peer_manager.count++], p, sizeof(Peer));
}

/** O(peer_manager.count) */
Peer* peer_find(const struct sockaddr_in *peer_address) {
    uint16_t port = peer_address->sin_port;
    uint32_t addr = peer_address->sin_addr.s_addr;

    Peer *p = NULL;
    for (size_t i = 0; i < peer_manager.count; ++i) {
        if (peer_manager.peers[i].peer_port == port &&
            memcmp(peer_manager.peers[i].peer_address, &addr, 4 /*FIXME IPV4_ADDR_LEN*/) == 0) {
            p = &peer_manager.peers[i];
            break;
        }
    }

    return p;
}

ssize_t peer_index(const Peer *p) {
    return (ssize_t) (((uintptr_t) p - (uintptr_t) peer_manager.peers) / sizeof(Peer));
}

uint16_t peer_get_count(void) {
    return peer_manager.count;
}

Peer* peer_get_all(void) {
    return peer_manager.peers;
}

void peer_print(const Peer *p) {
    fprintf(stderr, "Peer %p:\n", (void*) p);
    fprintf(stderr, "  Address Length: %u\n", p->peer_address_length);
    fprintf(stderr, "  Address: ");
    for (uint8_t i = 0; i < p->peer_address_length; ++i) {
        fprintf(stderr, "%s%u", (i > 0 ? "." : ""), p->peer_address[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "  Port: %u\n", ntohs(p->peer_port));
}

void peer_all_print(const Peer *peers, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        peer_print(&peers[i]);
    }
    fprintf(stderr, "\n");
}