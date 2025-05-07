#include <stdint.h>
#include <arpa/inet.h>
#include <assert.h>

#include "../include/sync.h"
#include "../include/message.h"
#include "../include/peer.h"

/**
 * SyncManager
 *
 * A structure responsible for managing synchronization information for the node.
 * It tracks the synchronization level and the timestamp of the last synchronization
 * with a peer in the P2P network.
 *
 * Fields:
 * - `id`        : The index of the peer in the `peers` array with which the node is synchronized.
 *                 This value is irrelevant if `lvl` equals 255, indicating no synchronization.
 * - `lvl`       : Synchronization level, stored in network byte order.
 *                 A value of 255 indicates no synchronization.
 * - `timestamp` : The value of `ncs_natural_clock` at the moment of the last
 *                 synchronization, stored in host byte order. This field is
 *                 irrelevant if `lvl` equals 255.
 * - `exp_msg`   : The type of the next expected message from the synchronized peer.
 *                 This value is used to track the protocol state and ensure that
 *                 messages are received in the correct order. It is irrelevant if
 *                 `lvl` equals 255, indicating no synchronization.
 * 
 * Notes:
 * - This structure is initialized automatically using the `_init_sync_manager` function.
 */
typedef struct {
    uint16_t id;
    uint16_t lvl;
    uint64_t timestamp;
    uint8_t  exp_msg;
} SyncManager;

static SyncManager sync_man = {0};

__attribute__((constructor)) static void _init_sync_manager() {
    sync_man.lvl = htons(SYNC_NONE);
}

uint8_t sync_get_exp_msg(void) {
    return sync_man.exp_msg;
}

void sync_set_exp_msg(const uint8_t msg) {
    assert(msg == MSG_NONE ||
           msg == MSG_SYNC_START ||
           msg == MSG_DELAY_REQUEST ||
           msg == MSG_DELAY_RESPONSE);
    sync_man.exp_msg = msg;
}

void sync_update_exp_msg(const Message *msg) {
    /*
     * Cases explanation:
     *  case MSG_HELLO & MSG_HELLO_REPLY:
     *      Node can receive those messages in every phase of a program.
     *      Thus the expected message can change only if the node does not have any peers yet,
     *      de facto meaning he is awaiting to join the network.
     * 
     *  case MSG_SYNC_START:
     *      Node handles MSG_SYNC_START by sending MSG_DELAY_REQUEST, then awaits MSG_DELAY_RESPONSE.
     * 
     *  case MSG_DELAY_REQUEST & MSG_DELAY_RESPONSE:
     *      After receiving and handling one of those two messages, the synchronisation is complete
     *      and node is ready to begin another synchronisation.
     * 
     *  default:
     *      All other messages can not change the expected message in synchronisation process.
     */

    switch (msg->message) {
        case MSG_HELLO:
        case MSG_HELLO_REPLY:
            if (peer_get_count() == 0) {
                sync_set_exp_msg(MSG_SYNC_START);
            }
            break;
                
        case MSG_SYNC_START:
            sync_set_exp_msg(MSG_DELAY_RESPONSE);
            break;
        
        case MSG_DELAY_REQUEST:
        case MSG_DELAY_RESPONSE:
            sync_set_exp_msg(MSG_SYNC_START);
            break;

        // TODO Co zrobić z MSG_LEADER?
                
        default:
            break;
    }
}

void sync_cancel(void) {
    sync_man.lvl = htons(SYNC_NONE);
}
