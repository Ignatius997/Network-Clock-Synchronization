#include <arpa/inet.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "../include/recvinfo.h"
#include "../include/message.h"
#include "../include/peer.h"
#include "../err.h"

// Tablica przechowująca informacje o ReceiveInfo dla każdego typu wiadomości
static ReceiveInfoInfo recv_info[MSG_MAX + 1];

// Funkcja ustawiająca rozmiary struktur ReceiveInfo
static void _set_recv_info_size(void) {
    recv_info[MSG_HELLO].size          = sizeof(HelloReceiveInfo);
    recv_info[MSG_HELLO_REPLY].size    = sizeof(HelloReplyReceiveInfo);
    recv_info[MSG_CONNECT].size        = sizeof(ConnectReceiveInfo);
    recv_info[MSG_ACK_CONNECT].size    = sizeof(AckConnectReceiveInfo);
    recv_info[MSG_SYNC_START].size     = sizeof(SyncStartReceiveInfo);
    recv_info[MSG_DELAY_REQUEST].size  = sizeof(DelayRequestReceiveInfo);
    recv_info[MSG_DELAY_RESPONSE].size = sizeof(DelayResponseReceiveInfo);
    recv_info[MSG_LEADER].size         = sizeof(LeaderReceiveInfo);
    recv_info[MSG_GET_TIME].size       = sizeof(GetTimeReceiveInfo);
    recv_info[MSG_TIME].size           = sizeof(TimeReceiveInfo);
}

// Funkcja ustawiająca, czy wiadomość może pochodzić od nieznanego nadawcy
static void _set_recv_info_allow_unknown_sender(void) {
    recv_info[MSG_HELLO].allow_unknown_sender          = true;
    recv_info[MSG_HELLO_REPLY].allow_unknown_sender    = true;
    recv_info[MSG_CONNECT].allow_unknown_sender        = true;
    recv_info[MSG_ACK_CONNECT].allow_unknown_sender    = true;
    recv_info[MSG_SYNC_START].allow_unknown_sender     = false;
    recv_info[MSG_DELAY_REQUEST].allow_unknown_sender  = false;
    recv_info[MSG_DELAY_RESPONSE].allow_unknown_sender = false;
    recv_info[MSG_LEADER].allow_unknown_sender         = true;
    recv_info[MSG_GET_TIME].allow_unknown_sender       = true;
    recv_info[MSG_TIME].allow_unknown_sender           = true;
}

// Konstruktor inicjalizujący tablicę recv_info
__attribute__((constructor)) static void _initialize_recv_info(void) {
    memset(recv_info, 0, sizeof(recv_info));
    _set_recv_info_size();
    _set_recv_info_allow_unknown_sender();
}

// NOTE To jest trochę shady i jakbyśmy chcieli coś więcej z tym robić, to trzeba by miec w ReceiveInfo pole type/message.
// NOTE Ale na razie jest ok, jako że nigdzie indziej niż w rinfo_load nie potrzebujemy rozmiaru.
// TODO A co tam zróbmy to pole.
static size_t rinfo_size(const ReceiveInfo *msg) {
    return recv_info;
}

ReceiveInfo *rinfo_load(const struct sockaddr_in *peer_address, const uint8_t *buf, const ssize_t recv_len) {
    ReceiveInfo *info = malloc(sizeof(ReceiveInfo));
    if (info == NULL) syserr("malloc nrecv_info_load");

    memcpy(info, peer_address, sizeof(peer_address));
    
    Message *msg = (Message *)buf;
    size_t info_size = _size(msg);

    switch

    // ==============================
    
    Message *msg = malloc(sizeof(Message));
    if (msg == NULL) syserr("malloc msg_load");
    
    memcpy(msg, buf, sizeof(Message));
    size_t message_size = msg_size(msg);

    if (message_size > sizeof(Message)) {
        Message *tmp_msg = realloc(msg, message_size);
        if (tmp_msg == NULL) {
            free(msg);
            syserr("realloc msg_load");
        }

        msg = tmp_msg;
        memcpy((uint8_t *)msg + sizeof(Message), buf + sizeof(Message), message_size - sizeof(Message));
    }

    return msg;
}