#ifndef NCS_SEND_H
#define NCS_SEND_H

#include <arpa/inet.h>
#include <inttypes.h>

#include "../include/message.h"

/** Information about send operation. Packed to save memory. */
typedef struct {
    struct sockaddr_in peer_address;
    ssize_t len; // wejscie i wyjscie
    bool    known; // Used in sending hello-reply message
    // NOTE Szczerze to pole `known` nie powinno się tu znajdować.
} SendInfo;

void send_hello(SendInfo *sinfo);
void send_hello_reply(SendInfo *sinfo);
void send_connect(SendInfo *sinfo);
void send_ack_connect(SendInfo *sinfo);

#endif // NCS_SEND_H