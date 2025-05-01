#ifndef RECVINFO_H
#define RECVINFO_H

#include <arpa/inet.h>
#include <inttypes.h>

#include "message.h"
#include "peer.h"

// Packed ze względu na proste ladowanie rinfo w _specified_load
// Żeby specified load działał fajnie,

typedef struct __attribute__((__packed__)) {
    uint8_t message; // NOTE raczej tylko type, nie cały message
    struct sockaddr_in peer_address; // Wartosci w tym trzymane sa w porzadku sieciowym
} ReceiveInfo;

typedef struct __attribute__((__packed__)) {
    ReceiveInfo base;
} HelloReceiveInfo;

typedef struct __attribute__((__packed__)) {
    ReceiveInfo       base;
    HelloReplyMessage msg;
    Peer              *peers;
} HelloReplyReceiveInfo;

typedef struct __attribute__((__packed__)) {
    ReceiveInfo    base;
} ConnectReceiveInfo;

typedef struct __attribute__((__packed__)) {
    ReceiveInfo       base;
} AckConnectReceiveInfo;

typedef struct __attribute__((__packed__)) {
    ReceiveInfo      base;
    SyncStartMessage msg; // Wiadomość bazowa
} SyncStartReceiveInfo;

typedef struct __attribute__((__packed__)) {
    ReceiveInfo         base;
} DelayRequestReceiveInfo;

typedef struct __attribute__((__packed__)) {
    ReceiveInfo          base;
    DelayResponseMessage msg; // Wiadomość bazowa
} DelayResponseReceiveInfo;

typedef struct __attribute__((__packed__)) {
    ReceiveInfo   base;
    LeaderMessage msg; // Wiadomość bazowa
} LeaderReceiveInfo;

typedef struct __attribute__((__packed__)) {
    ReceiveInfo    base;
} GetTimeReceiveInfo;

typedef struct __attribute__((__packed__)) {
    ReceiveInfo base;
    TimeMessage msg; // Wiadomość bazowa
} TimeReceiveInfo;

size_t       rinfo_size(const ReceiveInfo *info);
ReceiveInfo *rinfo_load(const struct sockaddr_in *peer_address, const uint8_t *buf, const ssize_t recv_len);

#endif // RECVINFO_H