#ifndef RECVINFO_H
#define RECVINFO_H

#include <arpa/inet.h>
#include <inttypes.h>

#include "message.h"
#include "peer.h"

// Packed ze względu na proste ladowanie rinfo w _specified_load
// Żeby specified load działał fajnie,

typedef struct {
    uint8_t message; // NOTE raczej tylko type, nie cały message
    struct sockaddr_in peer_address; // Wartosci w tym trzymane sa w porzadku sieciowym
} ReceiveInfo;

typedef struct {
    ReceiveInfo base;
} HelloReceiveInfo;

typedef struct {
    ReceiveInfo       base;
    HelloReplyMessage msg;
    Peer              *peers;
} HelloReplyReceiveInfo;

typedef struct {
    ReceiveInfo    base;
} ConnectReceiveInfo;

typedef struct {
    ReceiveInfo       base;
} AckConnectReceiveInfo;

typedef struct {
    ReceiveInfo      base;
    SyncStartMessage msg; // Wiadomość bazowa
} SyncStartReceiveInfo;

typedef struct {
    ReceiveInfo         base;
} DelayRequestReceiveInfo;

typedef struct {
    ReceiveInfo          base;
    DelayResponseMessage msg; // Wiadomość bazowa
} DelayResponseReceiveInfo;

typedef struct {
    ReceiveInfo   base;
    LeaderMessage msg; // Wiadomość bazowa
} LeaderReceiveInfo;

typedef struct {
    ReceiveInfo    base;
} GetTimeReceiveInfo;

typedef struct  {
    ReceiveInfo base;
    TimeMessage msg; // Wiadomość bazowa
} TimeReceiveInfo;

size_t       rinfo_size(const ReceiveInfo *info);
ReceiveInfo *rinfo_load(const struct sockaddr_in *peer_address, const Message *msg);

#endif // RECVINFO_H