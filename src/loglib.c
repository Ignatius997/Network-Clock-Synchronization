#include <stdio.h>
#include <arpa/inet.h>

#include "../include/loglib.h"
#include "../include/message.h"
#include "../include/peer.h"
#include "../include/globals.h"
#include "../include/err.h"

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
            Peer *p = (Peer *) (ncs_buf + offset);
            peer_print(p);
            offset += sizeof(Peer);
        }
    }
}