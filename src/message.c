#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <stdlib.h>

#include "../include/message.h"
#include "../include/globals.h"
#include "../include/err.h"

static MessageInfo msg_info[MSG_MAX+1];

static void _set_info_size(void) {
    msg_info[MSG_HELLO].size          = sizeof(HelloMessage);
    msg_info[MSG_HELLO_REPLY].size    = sizeof(HelloReplyMessage);
    msg_info[MSG_CONNECT].size        = sizeof(ConnectMessage);
    msg_info[MSG_ACK_CONNECT].size    = sizeof(AckConnectMessage);
    msg_info[MSG_SYNC_START].size     = sizeof(SyncStartMessage);
    msg_info[MSG_DELAY_REQUEST].size  = sizeof(DelayRequestMessage);
    msg_info[MSG_DELAY_RESPONSE].size = sizeof(DelayResponseMessage);
    msg_info[MSG_LEADER].size         = sizeof(LeaderMessage);
    msg_info[MSG_GET_TIME].size       = sizeof(GetTimeMessage);
    msg_info[MSG_TIME].size           = sizeof(TimeMessage);
}

static void _set_info_allow_unknown_sender(void) {
    msg_info[MSG_HELLO].allow_unknown_sender          = true;
    msg_info[MSG_HELLO_REPLY].allow_unknown_sender    = true;
    msg_info[MSG_CONNECT].allow_unknown_sender        = true;
    msg_info[MSG_ACK_CONNECT].allow_unknown_sender    = true;
    msg_info[MSG_SYNC_START].allow_unknown_sender     = false;
    msg_info[MSG_DELAY_REQUEST].allow_unknown_sender  = false;
    msg_info[MSG_DELAY_RESPONSE].allow_unknown_sender = false;
    msg_info[MSG_LEADER].allow_unknown_sender         = true;
    msg_info[MSG_GET_TIME].allow_unknown_sender       = true;
    msg_info[MSG_TIME].allow_unknown_sender           = true;
}

/** Must have GCC for this. */
__attribute__((constructor)) static void _initialize_msg_info(void) {
    memset(msg_info, 0, sizeof(msg_info));
    _set_info_size();
    _set_info_allow_unknown_sender();
}

Message *msg_load() {
    Message *msg = malloc(sizeof(Message));
    if (msg == NULL) syserr("malloc msg_load");
    
    memcpy(msg, ncs_buf, sizeof(Message));
    size_t message_size = msg_size(msg);

    if (message_size > sizeof(Message)) {
        Message *tmp_msg = realloc(msg, message_size);
        if (tmp_msg == NULL) {
            free(msg);
            syserr("realloc msg_load");
        }

        msg = tmp_msg;
        memcpy((uint8_t *)msg + sizeof(Message), ncs_buf + sizeof(Message), message_size - sizeof(Message));
    }

    return msg;
}

size_t msg_size(const Message *msg) {
    return msg_info[msg->message].size;
}

bool msg_allows_unknown_sender(const Message *msg) {
    return msg_info[msg->message].allow_unknown_sender;
}

const char *msg_name(const Message *msg) {
    switch (msg->message) {
        case MSG_HELLO:
            return "MSG_HELLO";

        case MSG_HELLO_REPLY:
            return "MSG_HELLO_REPLY";

        case MSG_CONNECT:
            return "MSG_CONNECT";

        case MSG_ACK_CONNECT:
            return "MSG_ACK_CONNECT";

        case MSG_SYNC_START:
            return "MSG_SYNC_START";

        case MSG_DELAY_REQUEST:
            return "MSG_DELAY_REQUEST";

        case MSG_DELAY_RESPONSE:
            return "MSG_DELAY_RESPONSE";

        case MSG_LEADER:
            return "MSG_LEADER";

        case MSG_GET_TIME:
            return "MSG_GET_TIME";

        case MSG_TIME:
            return "MSG_TIME";

        default:
            return "UNKNOWN";
    }
}

// TODO można skrócić
void msg_print(const Message *msg) {
    fprintf(stderr, "Message %p:\n", (void*) msg);
    switch (msg->message) {
        case MSG_HELLO:
            fprintf(stderr, "  Type: HELLO\n");
            break;

        case MSG_HELLO_REPLY:
            HelloReplyMessage *hello_reply = (HelloReplyMessage *) msg;
            fprintf(stderr, "  Type: HELLO_REPLY\n");
            fprintf(stderr, "  Count: %u\n", ntohs(hello_reply->count));
            break;

        case MSG_CONNECT:
            fprintf(stderr, "  Type: CONNECT\n");
            break;

        case MSG_ACK_CONNECT:
            fprintf(stderr, "  Type: ACK_CONNECT\n");
            break;

        case MSG_SYNC_START:
            SyncStartMessage *sync_start = (SyncStartMessage *) msg;
            fprintf(stderr, "  Type: SYNC_START\n");
            fprintf(stderr, "  Timestamp: %" PRIu64 "\n", be64toh(sync_start->timestamp));
            fprintf(stderr, "  Synchronized: %u\n", sync_start->synchronized);
            break;

        case MSG_DELAY_REQUEST:
            fprintf(stderr, "  Type: DELAY_REQUEST\n");
            break;

        case MSG_DELAY_RESPONSE:
            DelayResponseMessage *delay_response = (DelayResponseMessage *) msg;
            fprintf(stderr, "  Type: DELAY_RESPONSE\n");
            fprintf(stderr, "  Synchronized: %u\n", delay_response->synchronized);
            fprintf(stderr, "  Timestamp: %" PRIu64 "\n", be64toh(delay_response->timestamp));
            break;

        case MSG_LEADER:
            LeaderMessage *leader = (LeaderMessage *) msg;
            fprintf(stderr, "  Type: LEADER\n");
            fprintf(stderr, "  Synchronized: %u\n", leader->synchronized);
            break;

        case MSG_GET_TIME:
            fprintf(stderr, "  Type: GET_TIME\n");
            break;

        case MSG_TIME:
            TimeMessage *time_msg = (TimeMessage *) msg;
            fprintf(stderr, "  Type: TIME\n");
            fprintf(stderr, "  Synchronized: %u\n", time_msg->synchronized);
            fprintf(stderr, "  Timestamp: %" PRIu64 "\n", be64toh(time_msg->timestamp));
            break;

        default:
            fprintf(stderr, "  Unknown message type: %u\n", msg->message);
            break;
    }
}

// ==== Additional functions ====

Message *msg_copy(const Message *msg_src) {
    // NOTE możemy opakować tego malloca
    Message *msg_cp = malloc(msg_size(msg_src));
    if (msg_cp == NULL) {
        syserr("malloc failed in msg_copy");
    }

    memcpy(msg_cp, msg_src, msg_size(msg_src));
    return msg_cp;
}

void msg_hton(Message *msg) {
    switch (msg->message) {
        case MSG_HELLO_REPLY:
            HelloReplyMessage *hello_reply = (HelloReplyMessage *)(void *)msg;
            hello_reply->count = htons(hello_reply->count);
            break;

        case MSG_SYNC_START:
            SyncStartMessage *sync_start = (SyncStartMessage *)(void *)msg;
            sync_start->timestamp = htobe64(sync_start->timestamp);
            break;

        case MSG_DELAY_RESPONSE:
            DelayResponseMessage *delay_response = (DelayResponseMessage *)(void *)msg;
            delay_response->timestamp = htobe64(delay_response->timestamp);
            break;

        case MSG_TIME:
            TimeMessage *time_msg = (TimeMessage *)(void *)msg;
            time_msg->timestamp = htobe64(time_msg->timestamp);
            break;

        default:
            break;
    }
}

void msg_ntoh(Message *msg) {
    switch (msg->message) {
        case MSG_HELLO_REPLY:
            HelloReplyMessage *hello_reply = (HelloReplyMessage *)(void *)msg;
            hello_reply->count = ntohs(hello_reply->count);
            break;

        case MSG_SYNC_START:
            SyncStartMessage *sync_start = (SyncStartMessage *)(void *)msg;
            sync_start->timestamp = be64toh(sync_start->timestamp);
            break;

        case MSG_DELAY_RESPONSE:
            DelayResponseMessage *delay_response = (DelayResponseMessage *)(void *)msg;
            delay_response->timestamp = be64toh(delay_response->timestamp);
            break;

        case MSG_TIME:
            TimeMessage *time_msg = (TimeMessage *)(void *)msg;
            time_msg->timestamp = be64toh(time_msg->timestamp);
            break;

        default:
            break;
    }
}