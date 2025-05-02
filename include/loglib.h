#ifndef LOGLIB_H
#define LOGLIB_H

#include <arpa/inet.h>
#include <stddef.h>
#include "message.h"
#include "peer.h"

#ifdef NDEBUG
    #define log_received_message(peer_address, msg, recv_len) ((void)0)
    #define log_sent_message(peer_address, msg, send_len) ((void)0)
    #define log_sending_peers(msg) ((void)0)
#else
    void log_received_message(const struct sockaddr_in *peer_address, const Message *msg, const ssize_t recv_len);
    void log_sent_message(const struct sockaddr_in *peer_address, const Message *msg, const ssize_t send_len);
    void log_sending_peers(const Message *msg);
#endif

#endif // LOGLIB_H