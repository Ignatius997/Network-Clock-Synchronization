#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "../include/handler.h"
#include "../include/send.h"
#include "../include/sync.h"
#include "../include/netutil.h"
#include "../include/recvinfo.h"
#include "../include/loglib.h"
#include "../include/message.h"
#include "../include/peer.h"
#include "../include/timeoutman.h"
#include "../include/err.h" // FIXME Później do wywałki
#include "../include/sync.h"

/**
 * @brief Handles a received MSG_HELLO message.
 *
 * This function processes a MSG_HELLO message by sending a MSG_HELLO_REPLY 
 * back to the sender. If the sender is not already known, it attempts to 
 * establish a connection with the sender.
 *
 * @param h_rinfo A pointer to the HelloReceiveInfo structure containing 
 *                information about the received MSG_HELLO message.
 * @return 0 if the message was successfully handled, or -1 if an error occurred.
 */
static int _hello(const HelloReceiveInfo *h_rinfo) { 
    SendInfo sinfo = {
        .peer_address = h_rinfo->base.peer_address,
    };
    send_hello_reply(&sinfo);

    if (!sinfo.known) {
        nutil_establish_connection(&h_rinfo->base.peer_address); // TODO Co jak zabraknie miejsca? Chyba trzeba zwrócić -1
    }

    return 0;
}

/**
 * @brief Handles a received MSG_HELLO_REPLY message.
 *
 * This function processes a MSG_HELLO_REPLY message by extracting the list of peers 
 * provided in the message. It sends a MSG_CONNECT message to each peer in the list
 * to establish connections.
 *
 * @param hr_rinfo A pointer to the HelloReplyReceiveInfo structure containing 
 *                 information about the received MSG_HELLO_REPLY message.
 * @return 0 if the message was successfully handled, or -1 if an error occurred.
 */
static int _hello_reply(const HelloReplyReceiveInfo *hr_rinfo) {
    uint16_t peers_count = ntohs(hr_rinfo->msg.count);

    if (peers_count > 0) {
        Peer *peers = malloc(peers_count * sizeof(Peer));
        if (peers == NULL) syserr("malloc failed");
        memcpy(peers, hr_rinfo->peers, peers_count * sizeof(Peer));

        // FIXME Dać to gdzieś indziej, zrobić to sprytniej.
        fprintf(stderr, "Peers from HELLO_REPLY:\n");
        peer_all_print(peers);

        // Send connect messages.
        for (uint16_t i = 0; i < peers_count; ++i) {
            SendInfo sinfo = {.len = -1};
            nutil_extract_address(&peers[i], &sinfo.peer_address);
            send_connect(&sinfo);
        }

        free(peers);
    }

    return 0;
}

/**
 * @brief Handles a received MSG_CONNECT message.
 *
 * This function processes a MSG_CONNECT message by checking if the sender is 
 * already known. If the sender is unknown, it attempts to establish a connection 
 * with the sender. Afterward, it sends a MSG_ACK_CONNECT message back to the sender 
 * to acknowledge the connection.
 *
 * @param c_rinfo A pointer to the ConnectReceiveInfo structure containing 
 *                information about the received MSG_CONNECT message.
 * @return 0 if the message was successfully handled, or -1 if an error occurred.
 */
static int _connect(const ConnectReceiveInfo *c_rinfo) {
    if (peer_find(&c_rinfo->base.peer_address) == NULL) { // Unknown peer.
        nutil_establish_connection(&c_rinfo->base.peer_address);
    }

    SendInfo sinfo = {
        .peer_address = c_rinfo->base.peer_address,
        .len = -1,
    };
    send_ack_connect(&sinfo);

    return 0;
}

/**
 * @brief Handles a received MSG_ACK_CONNECT message.
 *
 * This function processes a MSG_ACK_CONNECT message by checking if the sender 
 * is already known. If the sender is unknown, it attempts to establish a 
 * connection with the sender. This message serves as an acknowledgment of a 
 * previously sent MSG_CONNECT message.
 *
 * @param ac_rinfo A pointer to the AckConnectReceiveInfo structure containing 
 *                 information about the received MSG_ACK_CONNECT message.
 * @return 0 if the message was successfully handled, or -1 if an error occurred.
 */
static int _ack_connect(const AckConnectReceiveInfo *ac_rinfo) {
    if (peer_find(&ac_rinfo->base.peer_address) == NULL) { // Unknown peer.
        nutil_establish_connection(&ac_rinfo->base.peer_address);
    }

    return 0;
}

static int _sync_start(const SyncStartReceiveInfo *info) {
    (void)info;
    // TODO: Implement this function

    return 0;
}

static int _delay_request(const DelayRequestReceiveInfo *info) {
    (void)info;
    // TODO: Implement this function

    return 0;
}

static int _delay_response(const DelayResponseReceiveInfo *info) {
    (void)info;
    // TODO: Implement this function

    return 0;
}

static int _leader(const LeaderReceiveInfo *info) {
    (void)info;
    // TODO: Implement this function

    return 0;
}

static int _get_time(const GetTimeReceiveInfo *info) {
    (void)info;
    // TODO: Implement this function

    return 0;
}

static int _time(const TimeReceiveInfo *info) {
    (void)info;
    // TODO: Implement this function

    return 0;
}

/**
 * @brief Dispatches a received message to the appropriate handler function.
 *
 * This function determines the type of the received message and calls the 
 * corresponding handler function to process it. Each message type has a 
 * dedicated handler that performs the necessary actions based on the message 
 * content.
 *
 * @param msg A pointer to the received message structure.
 * @param rinfo A pointer to the additional information associated with the 
 *              received message, such as the sender's address.
 * @return 0 if the message was successfully handled, or -1 if the message type 
 *         is unknown or unhandled.
 */
static int _handle(const Message *msg, const ReceiveInfo *rinfo) {
    switch (msg->message) {
        case MSG_HELLO:
            return _hello((HelloReceiveInfo *)rinfo);

        case MSG_HELLO_REPLY:
            return _hello_reply((HelloReplyReceiveInfo *)rinfo);

        case MSG_CONNECT:
            return _connect((ConnectReceiveInfo *)rinfo);

        case MSG_ACK_CONNECT:
            return _ack_connect((AckConnectReceiveInfo *)rinfo);

        case MSG_SYNC_START:
            return _sync_start((SyncStartReceiveInfo *)rinfo);

        case MSG_DELAY_REQUEST:
            return _delay_request((DelayRequestReceiveInfo *)rinfo);

        case MSG_DELAY_RESPONSE:
            return _delay_response((DelayResponseReceiveInfo *)rinfo);

        case MSG_LEADER:
            return _leader((LeaderReceiveInfo *)rinfo);

        case MSG_GET_TIME:
            return _get_time((GetTimeReceiveInfo *)rinfo);

        case MSG_TIME:
            return _time((TimeReceiveInfo *)rinfo);

        default:
            return -1;
    }
}

void handle_message(const struct sockaddr_in *sender_address, const ssize_t recv_len) {
    Message *msg = msg_load(); // Interpret data as a Message structure.
    
    if (!msg_allows_unknown_sender(msg) && peer_find(sender_address) == NULL) {
        syserr("Nie znom jo tego chłopa."); // NOTE nie powinno się wywalać, lecz chyba coś powinno wypisywać
        return; // Abort handling.
    }

    ReceiveInfo *rinfo = rinfo_load(sender_address, msg);
    log_received_message(sender_address, msg, recv_len);

    if (_handle(msg, rinfo) == 0) sync_update_exp_msg(msg);

    free(msg);
    rinfo_free(rinfo);
}

/**
 * Handle -1 being return value of `recvfrom`, meaning either error or timeout.
 */
void handle_recv_fail(const struct sockaddr_in *peer_address) {
    switch (sync_get_exp_msg()) {
        case MSG_SYNC_START:
            timeout_sync_start(peer_address);
            break;
        
        case MSG_DELAY_REQUEST:
        case MSG_DELAY_RESPONSE:
            timeout_delay();
            break;
        
        default:
            assert(false && "Weird value in `exp_msg` field in `sync_man`.");
            break;
    }
}
