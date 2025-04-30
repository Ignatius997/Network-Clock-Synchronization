#ifndef RECVINFO_H
#define RECVINFO_H

#include <arpa/inet.h>
#include <inttypes.h>

#include "message.h"
#include "peer.h"

// TODO czy robić to z atrybutem packed? Sprawdzić rozmiar bez i z

typedef struct {
    uint8_t type;
    struct sockaddr_in peer_address;
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
    ConnectMessage msg; // Wiadomość bazowa
} ConnectReceiveInfo;

typedef struct {
    ReceiveInfo       base;
    AckConnectMessage msg; // Wiadomość bazowa
} AckConnectReceiveInfo;

typedef struct {
    ReceiveInfo      base;
    SyncStartMessage msg; // Wiadomość bazowa
} SyncStartReceiveInfo;

typedef struct {
    ReceiveInfo         base;
    DelayRequestMessage msg; // Wiadomość bazowa
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
    GetTimeMessage msg; // Wiadomość bazowa
} GetTimeReceiveInfo;

typedef struct {
    ReceiveInfo base;
    TimeMessage msg; // Wiadomość bazowa
} TimeReceiveInfo;

size_t       rinfo_size(const ReceiveInfo *info);
ReceiveInfo *rinfo_load(const struct sockaddr_in *peer_address, const uint8_t *buf, const ssize_t recv_len);

#endif // RECVINFO_H