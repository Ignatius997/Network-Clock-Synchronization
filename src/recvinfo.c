#include <arpa/inet.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../include/recvinfo.h"
#include "../include/message.h"
#include "../include/peer.h"
#include "../include/globals.h"
#include "../include/err.h"

// Tablica przechowująca informacje o ReceiveInfo dla każdego typu wiadomości
static size_t recv_info_size[MSG_MAX_VALUE + 1];

// Funkcja ustawiająca rozmiary struktur ReceiveInfo
static void _set_recv_info_size(void) {
    recv_info_size[MSG_HELLO]          = sizeof(HelloReceiveInfo);
    recv_info_size[MSG_HELLO_REPLY]    = sizeof(HelloReplyReceiveInfo);
    recv_info_size[MSG_CONNECT]        = sizeof(ConnectReceiveInfo);
    recv_info_size[MSG_ACK_CONNECT]    = sizeof(AckConnectReceiveInfo);
    recv_info_size[MSG_SYNC_START]     = sizeof(SyncStartReceiveInfo);
    recv_info_size[MSG_DELAY_REQUEST]  = sizeof(DelayRequestReceiveInfo);
    recv_info_size[MSG_DELAY_RESPONSE] = sizeof(DelayResponseReceiveInfo);
    recv_info_size[MSG_LEADER]         = sizeof(LeaderReceiveInfo);
    recv_info_size[MSG_GET_TIME]       = sizeof(GetTimeReceiveInfo);
    recv_info_size[MSG_TIME]           = sizeof(TimeReceiveInfo);
}

// Konstruktor inicjalizujący tablicę recv_info
__attribute__((constructor)) static void _initialize_recv_info(void) {
    memset(recv_info_size, 0, sizeof(recv_info_size));
    _set_recv_info_size();
}

static void _load_hello_reply(HelloReplyReceiveInfo *hr_rinfo) {
    uint16_t peers_count = ntohs(hr_rinfo->msg.count);

    if (peers_count > 0) {
        hr_rinfo->peers = malloc(peers_count * sizeof(Peer));
        if (hr_rinfo->peers == NULL) syserr("malloc failed");
        memcpy(hr_rinfo->peers, ncs_buf + msg_size((Message *)&hr_rinfo->msg), peers_count * sizeof(Peer));

        fprintf(stderr, "Peers from HELLO_REPLY:\n");
        for (size_t i = 0; i < peers_count; ++i) {
            peer_print(&hr_rinfo->peers[i]);
        }
        fprintf(stderr, "\n");
    } else {
        hr_rinfo->peers = NULL; // To avoid freeing uninitialised memory in `rinfo_free`.
    }
}

static void _basic_load(ReceiveInfo *info, const struct sockaddr_in *peer_address, const Message *msg) {
    info->message = msg->message;
    info->peer_address = *peer_address;
}

static void _specified_load(ReceiveInfo *rinfo, const Message *msg) {
    switch (rinfo->message) {
        /** Cases of MSG_HELLO and others are not included, because
         * size of e.g. HelloReceiveInfo is equal to ReceiveInfo size.
         */

        case MSG_HELLO_REPLY:
            HelloReplyReceiveInfo *hr_rinfo = (HelloReplyReceiveInfo *)rinfo;
            memcpy(&hr_rinfo->msg, msg, msg_size(msg));
            _load_hello_reply(hr_rinfo);
            break;

        case MSG_SYNC_START:
            SyncStartReceiveInfo *ss_rinfo = (SyncStartReceiveInfo *)rinfo;
            memcpy(&ss_rinfo->msg, msg, msg_size(msg));
            break;

        case MSG_DELAY_RESPONSE:
            DelayResponseReceiveInfo *dr_rinfo = (DelayResponseReceiveInfo *)rinfo;
            memcpy(&dr_rinfo->msg, msg, msg_size(msg));
            break;

        case MSG_LEADER:
            LeaderReceiveInfo *l_rinfo = (LeaderReceiveInfo *)rinfo;
            memcpy(&l_rinfo->msg, msg, msg_size(msg));
            break;

        case MSG_TIME:
            TimeReceiveInfo *t_rinfo = (TimeReceiveInfo *)rinfo;
            memcpy(&t_rinfo->msg, msg, msg_size(msg));
            break;

        default:
            syserr("Unknown message type in _specified_load");
    }
}

void rinfo_free(ReceiveInfo *rinfo) {
    switch (rinfo->message) {
        case MSG_HELLO_REPLY:
            HelloReplyReceiveInfo *hr_rinfo = (HelloReplyReceiveInfo *)rinfo;
            free(hr_rinfo->peers);
            break;
        default:
            break;
    }

    free(rinfo);
}

size_t rinfo_size(const ReceiveInfo *rinfo) {
    return recv_info_size[rinfo->message];
}

ReceiveInfo *rinfo_load(const struct sockaddr_in *peer_address, const Message *msg) {
    ReceiveInfo *rinfo = malloc(sizeof(ReceiveInfo));
    if (rinfo == NULL) syserr("malloc nrecv_info_load");

    _basic_load(rinfo, peer_address, msg);
    
    if (rinfo_size(rinfo) > sizeof(ReceiveInfo)) {
        ReceiveInfo *tmp_rinfo = realloc(rinfo, rinfo_size(rinfo));
        if (tmp_rinfo == NULL) {
            free(rinfo);
            syserr("realloc rinfo_load");
        }

        rinfo = tmp_rinfo;
        _specified_load(rinfo, msg);
    }

    return rinfo;
}