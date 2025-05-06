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

/**
 * PeerManager
 * 
 * A structure responsible for managing the list of known peers in the P2P network.
 * It maintains a static array of `Peer` structures and tracks the number of currently
 * stored peers.
 *
 * Fields:
 * - `peers`   : A static array of `Peer` structures storing information about known peers.
 * - `count`   : The current number of peers stored in the `peers` array.
 *
 * Notes:
 * - If `count` reaches the value of `PEER_MAX_COUNT`, no more peers can be added.
 */
typedef struct {
    Peer peers[PEER_MAX_COUNT];
    uint16_t count;
} PeerManager;

static PeerManager peer_manager = {0};
static bool limit_reached = false; // Tells, whether limit in `peers` table has been reached

/**
 * SyncManager
 *
 * A structure responsible for managing synchronization information for the node.
 * It tracks the synchronization level and the timestamp of the last synchronization
 * with a peer in the P2P network.
 *
 * Fields:
 * - `sync_id`        : The index of the peer in the `peers` array with which the node is synchronized.
 *                      This value is irrelevant if `sync_lvl` equals 255, indicating no synchronization.
 * - `sync_lvl`       : Synchronization level, stored in network byte order.
 *                      A value of 255 indicates no synchronization.
 * - `sync_timestamp` : The value of `ncs_natural_clock` at the moment of the last
 *                      synchronization, stored in host byte order. This field is
 *                      irrelevant if `sync_lvl` equals 255.
 *
 * Notes:
 * - This structure is initialized automatically using the `_init_sync_manager` function.
 */
typedef struct {
    uint16_t sync_id;
    uint16_t sync_lvl;
    uint64_t sync_timestamp;
} SyncManager;

static SyncManager sync_man = {0};

__attribute__((constructor)) static void _init_sync_manager() {
    sync_man.sync_lvl = htons(255);
}

// TODO Delete - static table.
void peer_cleanup(void) {
    peer_manager.count = 0;
    peer_manager.capacity = 0;
}

void peer_add(const Peer *p) {
    if (peer_manager.count == 0 && limit_reached) { // Sleek.
        syserr("Too many peers"); // TODO czy może coś innego zrobić.
    }

    if (peer_manager.count == PEER_MAX_COUNT) limit_reached = true;

    memcpy(&peer_manager.peers[peer_manager.count++], p, sizeof(Peer));
}

// TODO Delete - static table.
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