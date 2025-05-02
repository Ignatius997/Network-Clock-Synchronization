#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../include/nethandle.h"
#include "../include/netsend.h"
#include "../include/netutil.h"
#include "../include/recvinfo.h"
#include "../include/loglib.h"
#include "../include/message.h"
#include "../include/peer.h"
#include "../include/err.h" // FIXME Później do wywałki

static void _hello(const HelloReceiveInfo *h_rinfo) {
    SendInfo sinfo = {
        .peer_address = h_rinfo->base.peer_address,
    };
    nsend_hello_reply(&sinfo);

    if (!sinfo.known) {
        nutil_establish_connection(&h_rinfo->base.peer_address);
    }
}

static void _hello_reply(const HelloReplyReceiveInfo *hr_rinfo) {
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
            nsend_connect(&sinfo);
        }

        free(peers);
    }
}

static void _connect(const ConnectReceiveInfo *c_rinfo) {
    nutil_establish_connection(&c_rinfo->base.peer_address);

    SendInfo sinfo = {
        .peer_address = c_rinfo->base.peer_address,
        .len = -1,
    };
    nsend_ack_connect(&sinfo);
}

static void _ack_connect(const AckConnectReceiveInfo *ac_rinfo) {
    nutil_establish_connection(&ac_rinfo->base.peer_address);
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

void nhandle_message(const struct sockaddr_in *peer_address, const ssize_t recv_len) {
    Message *msg = msg_load(); // Interpret data as a Message structure.
    
    if (!msg_allows_unknown_sender(msg) &&
        peer_find(peer_address) == NULL) {
        syserr("Nie znom jo tego chłopa."); // NOTE nie powinno się wywalać, lecz chyba coś powinno wypisywać
    }

    ReceiveInfo *rinfo = rinfo_load(peer_address, msg);
    log_received_message(peer_address, msg, recv_len);

    switch (msg->message) {
        case MSG_HELLO:
            _hello((HelloReceiveInfo *)rinfo);
            break;

        case MSG_HELLO_REPLY:
            _hello_reply((HelloReplyReceiveInfo *)rinfo);
            break;

        case MSG_CONNECT:
            _connect((ConnectReceiveInfo *)rinfo);
            break;

        case MSG_ACK_CONNECT:
            _ack_connect((AckConnectReceiveInfo *)rinfo);
            break;

        case MSG_SYNC_START:
            _sync_start((SyncStartReceiveInfo *)rinfo);
            break;

        case MSG_DELAY_REQUEST:
            _delay_request((DelayRequestReceiveInfo *)rinfo);
            break;

        case MSG_DELAY_RESPONSE:
            _delay_response((DelayResponseReceiveInfo *)rinfo);
            break;

        case MSG_LEADER:
            _leader((LeaderReceiveInfo *)rinfo);
            break;

        case MSG_GET_TIME:
            _get_time((GetTimeReceiveInfo *)rinfo);
            break;

        case MSG_TIME:
            _time((TimeReceiveInfo *)rinfo);
            break;

        default:
            fprintf(stderr, "Unknown message type: %u\n", msg->message);
            break;
    }

    free(msg);
    rinfo_free(rinfo);
}
