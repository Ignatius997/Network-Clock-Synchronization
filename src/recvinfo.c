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
static size_t recv_info_size[MSG_MAX + 1];

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

static void _load_hello_reply(HelloReplyReceiveInfo *info) {
    uint16_t peers_count = ntohs(info->msg.count);

    if (peers_count > 0) {
        info->peers = malloc(peers_count * sizeof(Peer));
        if (info->peers == NULL) syserr("malloc failed");
        memcpy(info->peers, ncs_buf + msg_size((Message *)&info->msg), peers_count * sizeof(Peer));

        fprintf(stderr, "Peers from HELLO_REPLY:\n");
        for (size_t i = 0; i < peers_count; ++i) {
            peer_print(&info->peers[i]);
        }
        fprintf(stderr, "\n");
    }
}

static void _basic_load(ReceiveInfo *info, const struct sockaddr_in *peer_address, const Message *msg) {
    info->message = msg->message;
    info->peer_address = *peer_address;
}

static void _specified_load(ReceiveInfo *info, const Message *msg) {
    switch (info->message) {
        /** Cases of MSG_HELLO and others are not included, because
         * size of e.g. HelloReceiveInfo is equal to ReceiveInfo size.
         */

        case MSG_HELLO_REPLY:
            HelloReplyReceiveInfo *hello_reply_info = (HelloReplyReceiveInfo *)info;
            memcpy(&hello_reply_info->msg, msg, msg_size(msg));
            _load_hello_reply(hello_reply_info);
            break;

        case MSG_SYNC_START:
            SyncStartReceiveInfo *sync_start_info = (SyncStartReceiveInfo *)info;
            memcpy(&sync_start_info->msg, msg, msg_size(msg));
            break;

        case MSG_DELAY_RESPONSE:
            DelayResponseReceiveInfo *delay_response_info = (DelayResponseReceiveInfo *)info;
            memcpy(&delay_response_info->msg, msg, msg_size(msg));
            break;

        case MSG_LEADER:
            LeaderReceiveInfo *leader_info = (LeaderReceiveInfo *)info;
            memcpy(&leader_info->msg, msg, msg_size(msg));
            break;

        case MSG_TIME:
            TimeReceiveInfo *time_info = (TimeReceiveInfo *)info;
            memcpy(&time_info->msg, msg, msg_size(msg));
            break;

        default:
            syserr("Unknown message type in _specified_load");
    }
}

size_t rinfo_size(const ReceiveInfo *info) {
    return recv_info_size[info->message];
}

ReceiveInfo *rinfo_load(const struct sockaddr_in *peer_address, const Message *msg) {
    ReceiveInfo *info = malloc(sizeof(ReceiveInfo));
    if (info == NULL) syserr("malloc nrecv_info_load");

    _basic_load(info, peer_address, msg);
    
    if (rinfo_size(info) > sizeof(ReceiveInfo)) {
        ReceiveInfo *tmp_info = realloc(info, rinfo_size(info));
        if (tmp_info == NULL) {
            free(info);
            syserr("realloc rinfo_load");
        }

        info = tmp_info;
        _specified_load(info, msg);
    }

    return info;
}