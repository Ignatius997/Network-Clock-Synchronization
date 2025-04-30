#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <regex.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <endian.h>

#include "../include/peer.h"
#include "../include/netutil.h"
#include "../include/err.h"
#include "../include/args.h"
#include "../include/sigman.h"
#include "../include/message.h"

#define IPV4_ADDR_LEN 4

#define BUF_SIZE 65535 // FIXME myślę, że więcej

/** Node attributes shall be accessible via global variables.
 * Naming convention: g_{name}.
 */
int      g_socket_fd; // ofc host order
uint8_t  g_buf[BUF_SIZE]; // Buffer for read operations.

/** Information about send operation. Packed to save memory. */
typedef struct __attribute__((__packed__)) {
    ssize_t send_len;
    bool    known; // Used in sending hello-reply message // NOTE zmienić nazwę
} SendInfo;

// TODO te całe wysyłanie możnaby jakoś ujednolicić.
// TODO dodać to cale oczekiwanie od 5 do 10 sekund

// NOTE nie wiedziałem gdzie to dać
void log_received_message(const struct sockaddr_in *peer_address, const Message *msg, const ssize_t recv_len) {
    char ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &peer_address->sin_addr, ip_str, sizeof(ip_str)) == NULL) {
        syserr("inet_ntop failed");
    }

    const char *log = msg_name(msg);
    fprintf(stderr, "Received %s message (%zd bytes) from %s:%u\n", log, recv_len, ip_str, ntohs(peer_address->sin_port));
    msg_print(msg);
    fprintf(stderr, "\n");
}

// NOTE nie wiedziałem gdzie to dać
void log_sent_message(const struct sockaddr_in *peer_address, const Message *msg, const ssize_t send_len) {
    char ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &peer_address->sin_addr, ip_str, sizeof(ip_str)) == NULL) {
        syserr("inet_ntop failed");
    }

    const char *log = msg_name(msg);
    fprintf(stderr, "Sent %s message (%zd bytes) to %s:%u\n", log, send_len, ip_str, ntohs(peer_address->sin_port));
    msg_print(msg);
    fprintf(stderr, "\n");
}

void log_sending_peers(const Message *msg) {
    if (msg->message == MSG_HELLO_REPLY) {
        size_t offset = msg_size(msg);
        fprintf(stderr, "Sending peers:\n");
        for (size_t i = 0; i < ntohs(((HelloReplyMessage *)msg)->count); ++i) {
            Peer *p = (Peer *) (g_buf + offset);
            peer_print(p);
            offset += sizeof(Peer);
        }
    }
}

// TODO Usystematyzować wysyłanie

// NOTE za długa nazwa
// NOTE można by to uogólnić, jednak w sumie jakiekolwiek uogólnienie to po prostu memcpy :)
// peer_index to indeks typa, ktorego nie przesyłamy
void prepare_buffer_for_sending(const Message *msg, const ssize_t peer_index) {
    memcpy(g_buf, msg, msg_size(msg)); // Load message to buffer.
    
    if (msg->message == MSG_HELLO_REPLY) {
        size_t full_len = ntohs(((HelloReplyMessage *)msg)->count) * sizeof(Peer);
        void *src1  = peer_get_all();
        void *dest1 = g_buf + msg_size(msg);

        // Load peers to buffer
        if (peer_index == -1) {
            memcpy(dest1, src1, full_len);
        } else {
            // NOTE Czy sprawdzać, czy nie wychodzimy poza bufor?
            size_t len1 = peer_index * sizeof(Peer);
            size_t len2 = full_len - len1;
            void *src2  = src1 + len1 + sizeof(Peer);
            void *dest2 = dest1 + len1;

            memcpy(dest1, src1, len1);
            memcpy(dest2, src2, len2);
        }
            
        log_sending_peers(msg);
    }
}

/**
 * Jeśli nie bierzemy z g_buf: len=-1
 * Jeśli bierzemy z g_buf, to msg nie ma znaczenia
 */
ssize_t sendto_wrap(const struct sockaddr_in *peer_address, const Message *msg, ssize_t len) {
    socklen_t addr_len = (socklen_t) sizeof(*peer_address);
    ssize_t send_len;

    if (len < 0) {
        send_len = sendto(g_socket_fd, msg, msg_size(msg), 0,
            (struct sockaddr *) peer_address, addr_len);
    } else {
        send_len = sendto(g_socket_fd, g_buf, len, 0,
            (struct sockaddr *) peer_address, addr_len);
    }

    if (send_len < 0) syserr("sendto fail"); // NOTE (chyba) Nie powinno się wywalać
    return send_len;
}

// TODO widać powtarzający się schemat, można to ujednolicić

/**
 * Jeśli nie bierzemy z g_buf: len=-1
 */
ssize_t send_message(const struct sockaddr_in *peer_address, const Message *msg, ssize_t len) {
    if (len < 0) {
        
    }

    ssize_t send_len = sendto_wrap(peer_address, msg, len);
    if (send_len > 0 ) log_sent_message(peer_address, msg, send_len);

    return send_len;
}

ssize_t send_hello(const struct sockaddr_in *peer_address) {
    HelloMessage msg = {
        .base.message = MSG_HELLO
    };

    return send_message(peer_address, (Message *)&msg, -1);
}

void send_hello_reply(const struct sockaddr_in *peer_address, SendInfo *sinfo) {
    Peer *p = peer_find(peer_address);
    sinfo->known = p != NULL;
    ssize_t pind = sinfo->known ? peer_index(p) : -1;

    HelloReplyMessage msg = {
        .base.message = MSG_HELLO_REPLY,
        .count        = sinfo->known ? htons(peer_get_count()-1) : htons(peer_get_count()),
    };

    size_t full_len = msg_size((Message *)&msg) + ntohs(msg.count) * sizeof(Peer);
    prepare_buffer_for_sending((Message *)&msg, pind);
    sinfo->send_len = send_message(peer_address, (Message *)&msg, full_len);
}

ssize_t send_connect(struct sockaddr_in *peer_address) {
    ConnectMessage msg = {
        .base.message = MSG_CONNECT
    };

    return send_message(peer_address, (Message *)&msg, -1);
}

ssize_t send_ack_connect(const struct sockaddr_in *peer_address) {
    AckConnectMessage msg = {
        .base.message = MSG_ACK_CONNECT
    };

    return send_message(peer_address, (Message *)&msg, -1);
}

ssize_t receive_message(struct sockaddr_in *peer_address) {
    socklen_t addr_len = (socklen_t) sizeof(*peer_address);
    ssize_t recv_len = recvfrom(g_socket_fd, g_buf, sizeof(g_buf), 0,
                                (struct sockaddr *) peer_address, &addr_len);
    int val = nutil_validate_received_data(peer_address, g_buf,recv_len);
    (void)val; // NOTE nieużyta zmienna

    return recv_len;
}

// TODO ta funkcja jest aczytalna
uint8_t receive_and_handle_hello_reply(struct sockaddr_in *peer_address, Peer **peers) {
    HelloReplyMessage msg;

    ssize_t recv_len = receive_message(peer_address);

    // Deserialize Message structure.
    memcpy(&msg, g_buf, sizeof(HelloReplyMessage));
    log_received_message(peer_address, (Message *)&msg, recv_len);

    // Copy contents of peers
    uint16_t peers_count = ntohs(msg.count);
    if (peers_count > 0) {
        *peers = malloc(peers_count * sizeof(Peer));
        if (*peers == NULL) syserr("malloc failed");
        memcpy(*peers, g_buf + sizeof(msg), peers_count * sizeof(Peer));

        fprintf(stderr, "Peers from HELLO_REPLY:\n");
        for (size_t i = 0; i < peers_count; ++i) {
            peer_print(&(*peers)[i]);
        }
        fprintf(stderr, "\n");
    }

    // FIXME Jeśli jest niepoprawnie, to wynikiem powinno być 255 (czy to poprawne?)
    return peers_count;
}

void join_network(const ProgramArgs *args) {
    if (!args->_ar_provided) return;

    struct sockaddr_in peer_address;
    nutil_set_address(args->peer_address, htons(args->peer_port), &peer_address);
    // struct sockaddr_in peer_address = get_peer_address(args.peer_address, args.peer_port);
    Peer *peers = NULL;

    Peer first;
    first.peer_address_length = 4 /*FIXME IPV4_ADDR_LEN*/;
    if (inet_pton(AF_INET, args->peer_address, first.peer_address) != 1) {
        syserr("inet_pton failed");
    }
    first.peer_port = htons(args->peer_port);
    peer_add(&first);

    send_hello(&peer_address);
}

void listen_for_messages() {
    struct sockaddr_in peer_address;

    while (true) {
        ssize_t recv_len = receive_message(&peer_address);
        handle_message(&peer_address, recv_len);
    }
}

int main(int argc, char* argv[]) {
    memset(g_buf, 0, BUF_SIZE);
    sig_setup_signal_handler(); // Just for debugging I guess.

    ProgramArgs program_args = args_default();
    args_parse(argc, argv, &program_args);
    args_print(&program_args);
    args_validate(&program_args);

    struct sockaddr_in bind_address; // To avoid allocation on the stack.
    nutil_init_socket(&g_socket_fd, &bind_address, program_args.bind_address, program_args.port);
    
    join_network(&program_args);
    listen_for_messages();
    
    cmn_close_socket(g_socket_fd);
    return 0;
}