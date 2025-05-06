#include <stdint.h>
#include <arpa/inet.h>

#include "../include/sync.h"
#include "../include/message.h"

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
    sync_man.sync_lvl = htons(SYNC_NONE);
}

uint8_t sync_get_expected_message(void) {
    return MSG_SYNC_START; // FIXME Fake
}

void sync_reset(const struct sockaddr_in *peer_address) {
    sync_man.sync_lvl = htons(SYNC_NONE);
    (void)peer_address;
}