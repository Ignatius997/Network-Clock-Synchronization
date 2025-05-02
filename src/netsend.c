#include <string.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include "../include/netsend.h"
#include "../include/message.h"
#include "../include/peer.h"
#include "../include/loglib.h"
#include "../include/err.h"
#include "../include/globals.h"

// peer_index to indeks typa, ktorego nie przesyłamy
static void _prepare_buffer_for_sending(const Message *msg, const ssize_t peer_index) {
    memset(ncs_buf, 0, G_BUF_SIZE);
    memcpy(ncs_buf, msg, msg_size(msg)); // Load message to buffer.
    
    if (msg->message == MSG_HELLO_REPLY) {
        size_t full_len = ntohs(((HelloReplyMessage *)msg)->count) * sizeof(Peer);
        void *src1  = peer_get_all();
        void *dest1 = ncs_buf + msg_size(msg);

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
 * Jeśli nie bierzemy z ncs_buf: sinfo->len=-1
 * Jeśli bierzemy z ncs_buf, to msg nie ma znaczenia
 */
static void _send_message(SendInfo *sinfo, const Message *msg) {
    void *buf  = sinfo->len < 0 ? (void *)msg : (void *)ncs_buf;
    size_t len = sinfo->len < 0 ? msg_size(msg) : (size_t) sinfo->len;
    socklen_t addr_len = (socklen_t) sizeof(sinfo->peer_address);
    
    sinfo->len = sendto(ncs_sockfd, buf, len, 0,
                        (struct sockaddr *) &sinfo->peer_address, addr_len);

    if (sinfo->len < 0) {
        syserr("sendto"); // NOTE ofc nie powinno się wywalać
    } else {
        log_sent_message(&sinfo->peer_address, msg, sinfo->len);
    }
}

// NOTE IMPORTANT BELOW
/**
 * Sinfo should already have all fields (except known (which is only return-field)
 * and len if it is not meant to be -1) set before the function.
 * Field `buf` ofc has no meaning when `len` field is -1.
*/

void nsend_hello(SendInfo *sinfo) {
    HelloMessage msg = {.base.message = MSG_HELLO};

    sinfo->len = -1; // To nawet chyba lepiej zrobić wcześniej

    _send_message(sinfo, (Message *)&msg);
}

void nsend_hello_reply(SendInfo *sinfo) {
    Peer *p = peer_find(&sinfo->peer_address);
    sinfo->known = p != NULL;
    ssize_t pind = sinfo->known ? peer_index(p) : -1;
    
    HelloReplyMessage msg = {
        .base.message = MSG_HELLO_REPLY,
        .count        = sinfo->known ? htons(peer_get_count()-1) : htons(peer_get_count()),
    };

    sinfo->len = msg_size((Message *)&msg) + ntohs(msg.count) * sizeof(Peer);

    _prepare_buffer_for_sending((Message *)&msg, pind);
    _send_message(sinfo, (Message *)&msg);
}

void nsend_connect(SendInfo *sinfo) {
    ConnectMessage msg = {.base.message = MSG_CONNECT};

    _send_message(sinfo, (Message *)&msg);
}

void nsend_ack_connect(SendInfo *sinfo) {
    AckConnectMessage msg = {.base.message = MSG_ACK_CONNECT};

    _send_message(sinfo, (Message *)&msg);
}