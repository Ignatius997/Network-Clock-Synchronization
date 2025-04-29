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
#include "../include/common.h"
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

// NOTE Daj w inne miejsce
int validate_received_length(const ssize_t recv_len, const Message *msg) {
    // NOTE Program nie powinien się wywalać przy jednym złym receive, ale początkowo tak zróbmy dla świętego spokoju i debugowania
    
    if (recv_len < 0) {
        syserr("recvfrom failed");
    }

    if (recv_len < (ssize_t) msg_size(msg)) {
        syserr("recvfrom less bytes than message size."); // Można dodać rodzaj msg
        return 1;
    }

    return 0; // NOTE Na przyszłość (patrz linijka wyżej).
}

// NOTE Daj w inne miejsce
void validate_address(const struct sockaddr_in *addr) {
    if (addr->sin_family != AF_INET) {
        syserr("Invalid address family");
    }

    // TODO Should we check it?
    // if (addr->sin_port == 0) {
    //     syserr("Port number is zero");
    // }
    
    // if (addr->sin_addr.s_addr == INADDR_NONE) {
    //     syserr("Invalid IP address");
    // }
}

int validate_peers(const Message *msg) {
    if (msg->message == MSG_HELLO_REPLY) { // For extensibility.
        uint16_t peers_count = ntohs(((HelloReplyMessage *)msg)->count);
        
        if (peers_count > 0) {
            size_t offset = msg_size(msg);
            
            fprintf(stderr, "Validating peers:\n");
            for (size_t i = 0; i < peers_count; ++i) {
                Peer *p = (Peer *) (g_buf + offset);
                peer_validate(p);
                offset += sizeof(Peer);
            }
        }
        fprintf(stderr, "\n");
    }
    
    return 0; // NOTE Success
}

int validate_received_data(const struct sockaddr_in *peer_address, const ssize_t recv_len, const Message *msg) {
    int ret = validate_received_length(recv_len, msg);
    validate_address(peer_address);
    if (msg->message == MSG_HELLO_REPLY) validate_peers(msg);
    return ret; // NOTE Potem, gdy nie będziemy rzucali syserr w przypadku recv_len < msg_size, będziemy mogli jakoś to lepiej obsłużyc
}

// TODO Usystematyzować wysyłanie

// TODO Możnaby to jakoś ujednolicić, żeby dołączający z _ar_provided też mógł użyć takiej funkcji
void establish_connection(const struct sockaddr_in *peer_address) {
    uint8_t ip[16];
    memset(ip, 0, sizeof(ip));
    memcpy(ip, &peer_address->sin_addr, IPV4_ADDR_LEN);

    Peer p;
    p.peer_address_length = IPV4_ADDR_LEN;
    memcpy(p.peer_address, ip, IPV4_ADDR_LEN);
    p.peer_port = peer_address->sin_port; // NOTE bez konwertowania

    peer_add(&p);
}

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

// TODO lepsza nazwa
void _connect(const Peer *p) {
    if (p->peer_address_length != IPV4_ADDR_LEN) syserr("Wrong address");

    struct sockaddr_in peer_address;
    peer_extract_address(p, &peer_address);

    send_connect(&peer_address);
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
    int val = validate_received_data(peer_address, recv_len, (Message *)g_buf);
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

// TODO czy mozna sensownie ujednolicic wysylanie, aby to tez mozna bylo dac do funkcji `msg_send`?
// TODO Posprzątać
void handle_hello(const struct sockaddr_in *peer_address) {
    SendInfo info;
    send_hello_reply(peer_address, &info);

    if (!info.known) {
        establish_connection(peer_address);
    }
}

void handle_connect(const struct sockaddr_in *peer_address) {
    establish_connection(peer_address);
    send_ack_connect(peer_address);
}

void handle_ack_connect(const struct sockaddr_in *peer_address) {
    establish_connection(peer_address);
}

void handle_sync_start(const struct sockaddr_in *peer_address, const Message *msg) {
    (void)peer_address;
    (void)msg;
    // TODO: Implement this function
}

void handle_delay_request(const struct sockaddr_in *peer_address, const Message *msg) {
    (void)peer_address;
    (void)msg;
    // TODO: Implement this function
}

void handle_delay_response(const struct sockaddr_in *peer_address, const Message *msg) {
    (void)peer_address;
    (void)msg;
    // TODO: Implement this function
}

void handle_leader(const struct sockaddr_in *peer_address, const Message *msg) {
    (void)peer_address;
    (void)msg;
    // TODO: Implement this function
}

void handle_get_time(const Message *msg) {
    (void)msg;
    // TODO: Implement this function
}

void handle_time(const struct sockaddr_in *peer_address, const Message *msg) {
    (void)peer_address;
    (void)msg;
    // TODO: Implement this function
}

void handle_message(const struct sockaddr_in *peer_address, const ssize_t recv_len) {
    Message *msg = msg_load(g_buf); // Interpret data as a Message structure.
    log_received_message(peer_address, msg, recv_len);
    
    if (!msg_allows_unknown_sender(msg) &&
        peer_find(peer_address) == NULL) {
        syserr("Nie znom jo tego chłopa."); // NOTE nie powinno się wywalać, lecz chyba coś powinno wypisywać
    }

    // Można napisać coś o tym, czemu nie rozważamy MSG_HELLO_REPLY.
    // FIXME Jednak trzeba tu uwzględnić MSG_HELLO_REPLY, bo co jeśli węzeł ponownie dołącza do sieci i jakiś koleżka wyśle mu np SYNC_START?
    switch (msg->message) {
        case MSG_HELLO:
            handle_hello(peer_address);
            break;

        case MSG_CONNECT:
            handle_connect(peer_address);
            break;

        case MSG_ACK_CONNECT:
            handle_ack_connect(peer_address);
            break;

        case MSG_SYNC_START:
            handle_sync_start(peer_address, msg);
            break;

        case MSG_DELAY_REQUEST:
            handle_delay_request(peer_address, msg);
            break;

        case MSG_DELAY_RESPONSE:
            handle_delay_response(peer_address, msg);
            break;

        case MSG_LEADER:
            handle_leader(peer_address, msg);
            break;

        case MSG_GET_TIME:
            handle_get_time(msg);
            break;

        case MSG_TIME:
            handle_time(peer_address, msg);
            break;

        default:
            fprintf(stderr, "Unknown message type: %u\n", msg->message);
            break;
    }
}

void listen_for_messages() {
    struct sockaddr_in peer_address;

    // TODO czy nie powinniśmy poświęcać większej uwagi addr_len po recvfrom?
    while (true) {
        ssize_t recv_len = receive_message(&peer_address);
        handle_message(&peer_address, recv_len);
    }
}

void join_network(ProgramArgs args) {
    if (!args._ar_provided) return;

    struct sockaddr_in peer_address;
    cmn_set_address(args.peer_address, htons(args.peer_port), &peer_address);
    // struct sockaddr_in peer_address = get_peer_address(args.peer_address, args.peer_port);
    Peer *peers = NULL;

    Peer first;
    first.peer_address_length = IPV4_ADDR_LEN;
    if (inet_pton(AF_INET, args.peer_address, first.peer_address) != 1) {
        syserr("inet_pton failed");
    }
    first.peer_port = htons(args.peer_port);
    peer_add(&first);

    send_hello(&peer_address);
    uint16_t count = receive_and_handle_hello_reply(&peer_address, &peers);

    for (uint16_t i = 0; i < count; ++i) {
        _connect(&peers[i]);
    }
    free(peers);
}

int main(int argc, char* argv[]) {
    memset(g_buf, 0, BUF_SIZE);
    sig_setup_signal_handler(); // Just for debugging I guess.

    ProgramArgs program_args = args_default();
    args_parse(argc, argv, &program_args);
    args_print(&program_args);
    args_validate(&program_args);

    struct sockaddr_in bind_address; // To avoid allocation on the stack.
    cmn_init_socket(&g_socket_fd, &bind_address, program_args.bind_address, program_args.port);
    
    join_network(program_args);
    listen_for_messages();
    
    cmn_close_socket(g_socket_fd);
    return 0;
}