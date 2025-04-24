#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Message type definitions
#define MSG_HELLO           0x01
#define MSG_HELLO_REPLY     0x02
#define MSG_CONNECT         0x03
#define MSG_ACK_CONNECT     0x04
#define MSG_SYNC_START      0x05
#define MSG_DELAY_REQUEST   0x06
#define MSG_DELAY_RESPONSE  0x07
#define MSG_LEADER          0x08
#define MSG_GET_TIME        0x09
#define MSG_TIME            0x0A

#define BUF_SIZE 100

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
    uint64_t timestamp;
    uint8_t  synchronized;
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

// Function to initialize a message
void init_message(Message *msg, uint8_t type) {
    if (msg) {
        msg->message = type;
    }
}

// Function to serialize a message into a buffer
size_t serialize_message(const Message *msg, void *buffer, size_t buffer_size) {
    if (!msg || !buffer || buffer_size < sizeof(Message)) {
        return 0;
    }
    memcpy(buffer, msg, sizeof(Message));
    return sizeof(Message);
}

// Function to deserialize a message from a buffer
size_t deserialize_message(const void *buffer, size_t buffer_size, Message *msg) {
    if (!buffer || !msg || buffer_size < sizeof(Message)) {
        return 0;
    }
    memcpy(msg, buffer, sizeof(Message));
    return sizeof(Message);
}

uint8_t buf[BUF_SIZE];

void print(const size_t n) {
    for (size_t i = 0; i < n; i++) {
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

void size(void *msg) {
    printf("Size of message: %zu bytes\n", sizeof(*msg));
}

void zr() {
    memset(buf, 0, BUF_SIZE);
}

void cp(const void *msg, size_t n) {
    memcpy(buf, msg, n);
}

int main(void) {
    zr();

    Message msg = {
        .message = 5,
    };
    cp(&msg, sizeof(msg));
    size(&msg);
    print(2*sizeof(msg));
    zr();

    HelloMessage hmsg = (HelloMessage) {
        .base.message = 2,
    };
    printf("Size of hmsg: %zu bytes\n", sizeof(hmsg)); // size(&hmsg);
    cp(&hmsg, sizeof(hmsg));
    print(2*sizeof(hmsg));
    zr();

    HelloReplyMessage hrmsg = {
        .base.message = 3,
        .count = 10,
    };
    printf("Size of hrmsg: %zu bytes\n", sizeof(hrmsg)); // size(&hrmsg);
    cp(&hrmsg, sizeof(hrmsg));
    print(2*sizeof(hrmsg));
    zr();
}