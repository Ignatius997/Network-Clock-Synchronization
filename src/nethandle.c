#include <stdio.h>
#include <string.h>

#include "../include/nethandle.h"
#include "../include/netrecv.h"
#include "../include/netsend.h"
#include "../include/netutil.h"
#include "../include/recvinfo.h"
#include "../include/message.h"
#include "../include/peer.h"
#include "../include/err.h" // FIXME Później do wywałki

static void _hello(const HelloReceiveInfo *info) {
    SendInfo send_info;
    send_hello_reply(&info->base.peer_address, &send_info);

    if (!send_info.known) {
        nutil_establish_connection(&info->base.peer_address);
    }
}

static void _hello_reply(const HelloReplyReceiveInfo *info) {
    uint16_t peers_count = ntohs(info->msg->count);

    if (peers_count > 0) {
        Peer *peers = malloc(peers_count * sizeof(Peer));
        if (peers == NULL) syserr("malloc failed");
        memcpy(peers, info->peers, peers_count * sizeof(Peer));

        // FIXME Dać to gdzieś indziej, zrobić to sprytniej.
        fprintf(stderr, "Peers from HELLO_REPLY:\n");
        peer_all_print(peers);

        // Send connect messages.
        for (uint16_t i = 0; i < peers_count; ++i) {
            struct sockaddr_in addr;
            nutil_extract_address(&peers[i], &addr);
            send_connect(&addr);
        }

        free(peers);
    }
}

static void _connect(const ConnectReceiveInfo *info) {
    nutil_establish_connection(&info->base.peer_address);
    send_ack_connect(&info->base.peer_address);
}

static void _ack_connect(const AckConnectReceiveInfo *info) {
    nutil_establish_connection(&info->base.peer_address);
}

static void _sync_start(const SyncStartReceiveInfo *info) {
    (void)info;
    // TODO: Implement this function
}

static void _delay_request(const DelayRequestReceiveInfo *info) {
    (void)info;
    // TODO: Implement this function
}

static void _delay_response(const DelayResponseReceiveInfo *info) {
    (void)info;
    // TODO: Implement this function
}

static void _leader(const LeaderReceiveInfo *info) {
    (void)info;
    // TODO: Implement this function
}

static void _get_time(const GetTimeReceiveInfo *info) {
    (void)info;
    // TODO: Implement this function
}

static void _time(const TimeReceiveInfo *info) {
    (void)info;
    // TODO: Implement this function
}

void nhandle_message(const struct sockaddr_in *peer_address, const uint8_t *buf, const ssize_t recv_len) {
    Message *msg = msg_load(buf); // Interpret data as a Message structure.
    
    if (!msg_allows_unknown_sender(msg) &&
        peer_find(peer_address) == NULL) {
        syserr("Nie znom jo tego chłopa."); // NOTE nie powinno się wywalać, lecz chyba coś powinno wypisywać
    }

    ReceiveInfo *info = rinfo_load(peer_address, msg);
    log_received_message(peer_address, msg, recv_len);

    switch (msg->message) {
        case MSG_HELLO:
            handle_hello((HelloReceiveInfo *)info);
            break;

        case MSG_HELLO_REPLY:
            handle_hello_reply((HelloReplyReceiveInfo *)info);
            break;

        case MSG_CONNECT:
            handle_connect((ConnectReceiveInfo *)info);
            break;

        case MSG_ACK_CONNECT:
            handle_ack_connect((AckConnectReceiveInfo *)info);
            break;

        case MSG_SYNC_START:
            handle_sync_start((SyncStartReceiveInfo *)info);
            break;

        case MSG_DELAY_REQUEST:
            handle_delay_request((DelayRequestReceiveInfo *)info);
            break;

        case MSG_DELAY_RESPONSE:
            handle_delay_response((DelayResponseReceiveInfo *)info);
            break;

        case MSG_LEADER:
            handle_leader((LeaderReceiveInfo *)info);
            break;

        case MSG_GET_TIME:
            handle_get_time((GetTimeReceiveInfo *)info);
            break;

        case MSG_TIME:
            handle_time((TimeReceiveInfo *)info);
            break;

        default:
            fprintf(stderr, "Unknown message type: %u\n", msg->message);
            break;
    }

    free(msg);
    free(info);
}
