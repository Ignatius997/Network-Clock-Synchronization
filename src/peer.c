#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>

#include "../include/peer.h"
#include "../include/err.h"

typedef struct {
    Peer peers[PEER_MAX];
    uint16_t count;
    uint16_t capacity;
} PeerManager;

static bool limit_reached = false;
static PeerManager peer_manager = {0};

void peer_cleanup(void) {
    // free(peer_manager.peers);
    // peer_manager.peers = {0}; // czy też NULL dla ptr
    peer_manager.count = 0;
    peer_manager.capacity = 0;
}

void peer_add(const Peer *p) {
    if (peer_manager.count == 0 && limit_reached) { // Sleek.
        syserr("Too many peers"); // TODO czy może coś innego zrobić.
    }

    if (peer_manager.count == PEER_MAX) limit_reached = true;

    // TODO Delete when sure about a static memory table.
    // if (peer_manager.count + 1 >= peer_manager.capacity) {
    //     peer_manager.capacity = (peer_manager.capacity == 0) ? 1 : peer_manager.capacity << 1;
    //     peer_manager.peers = (Peer *) realloc(peer_manager.peers, peer_manager.capacity * sizeof(Peer));
    //     if (peer_manager.peers == NULL) syserr("realloc");
    // }

    memcpy(&peer_manager.peers[peer_manager.count++], p, sizeof(Peer));
}

// TODO Delete when sure about a static memory table.
void peer_free_all(void) {
    // free(peer_manager.peers); // NOTE Invalid for static table.
}

/** O(peer_manager.count)
 * We do not have to worry about infinite loop caused by `<=` check in for loop condition,
 * because size_t exceeds `peer_manager.count` type limit by far.
*/
Peer* peer_find(const struct sockaddr_in *peer_address) {
    uint16_t port = peer_address->sin_port;
    uint32_t addr = peer_address->sin_addr.s_addr;

    Peer *p = NULL;
    for (size_t i = 0; i <= peer_manager.count; ++i) {
        if (peer_manager.peers[i].peer_port == port &&
            memcmp(peer_manager.peers[i].peer_address, &addr, 4 /*FIXME powinno być makro z nutil, ale są zależności między modułami*/) == 0) {
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

const Peer* peer_get_all(void) {
    return peer_manager.peers;
}

void peer_print(const Peer *p) {
    if (p == NULL) {
        fprintf(stderr, "Peer is NULL.\n");
        return;
    }

    fprintf(stderr, "Peer %p:\n", (void*) p);
    fprintf(stderr, "  Address Length: %u\n", p->peer_address_length);
    fprintf(stderr, "  Address: ");
    for (uint8_t i = 0; i < p->peer_address_length; ++i) {
        fprintf(stderr, "%s%u", (i > 0 ? "." : ""), p->peer_address[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "  Port: %u\n", ntohs(p->peer_port));
}

void peer_all_print(const Peer *peers) {
    for (size_t i = 0; i < peer_manager.count; ++i) {
        peer_print(&peers[i]);
    }
    fprintf(stderr, "\n");
}