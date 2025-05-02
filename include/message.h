#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define MSG_HELLO           1
#define MSG_HELLO_REPLY     2
#define MSG_CONNECT         3
#define MSG_ACK_CONNECT     4
#define MSG_SYNC_START      11
#define MSG_DELAY_REQUEST   12
#define MSG_DELAY_RESPONSE  13
#define MSG_LEADER          21
#define MSG_GET_TIME        31
#define MSG_TIME            32

#define MSG_MAX       255

// NOTE Trzymamy wszystko w big endianess.
typedef struct __attribute__((__packed__)) {
    uint8_t  message; // message type
} Message;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
} HelloMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
    uint16_t count; // count of known nodes
} HelloReplyMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
} ConnectMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
} AckConnectMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
    uint8_t  synchronized;
    uint64_t timestamp;
} SyncStartMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
} DelayRequestMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
    uint8_t  synchronized;
    uint64_t timestamp;
} DelayResponseMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
    uint8_t  synchronized;
} LeaderMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
} GetTimeMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
    uint8_t  synchronized;
    uint64_t timestamp;
} TimeMessage;

/** Packed to reduce the structure size by half. */
typedef struct __attribute__((__packed__)) {
    uint8_t message;
    size_t  size;
    bool    allow_unknown_sender;
} MessageInfo;

Message *msg_load();

size_t      msg_size(const Message *msg);
bool        msg_allows_unknown_sender(const Message *msg);
const char *msg_name(const Message *msg);

void msg_print(const Message *msg);

// Additional functions
Message *msg_copy(const Message *msg_src);
void     msg_hton(Message *msg);
void     msg_ntoh(Message *msg);

#endif // MESSAGE_H