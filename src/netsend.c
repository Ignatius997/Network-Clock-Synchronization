#include <string.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include "../include/netsend.h"
#include "../include/message.h"
#include "../include/peer.h"
#include "../include/loglib.h"
#include "../include/err.h"

// TODO Usystematyzować wysyłanie

static int socket_fd;

void nsend_set_socket_fd(const int sockfd) {
    socket_fd = sockfd;
}

// NOTE za długa nazwa
// NOTE można by to uogólnić, jednak w sumie jakiekolwiek uogólnienie to po prostu memcpy :)
// peer_index to indeks typa, ktorego nie przesyłamy
static void _prepare_buffer_for_sending(uint8_t *buf, const Message *msg, const ssize_t peer_index) {
    memcpy(buf, msg, msg_size(msg)); // Load message to buffer.
    
    if (msg->message == MSG_HELLO_REPLY) {
        size_t full_len = ntohs(((HelloReplyMessage *)msg)->count) * sizeof(Peer);
        void *src1  = peer_get_all();
        void *dest1 = buf + msg_size(msg);

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
            
        log_sending_peers(msg, buf);
    }
}

/**
 * Jeśli nie bierzemy z g_buf: sinfo->len=-1
 * Jeśli bierzemy z g_buf, to msg nie ma znaczenia
 */
static void _send_message(SendInfo *sinfo, const Message *msg) {
    void *buf  = sinfo->len < 0 ? msg : sinfo->buf;
    size_t len = sinfo->len < 0 ? msg_size(msg) : sinfo->len;
    socklen_t addr_len = (socklen_t) sizeof(sinfo->peer_address);
    
    sinfo->len = sendto(socket_fd, buf, len, 0, sinfo->peer_address, addr_len);
}

// static ssize_t _sendto_wrap(const struct sockaddr_in *peer_address, const uint8_t *buf,
//                     const Message *msg, const ssize_t len) {
//     socklen_t addr_len = (socklen_t) sizeof(*peer_address);
//     ssize_t send_len;

//     if (len < 0) {
//         send_len = sendto(socket_fd, msg, msg_size(msg), 0,
//             (struct sockaddr *) peer_address, addr_len);
//     } else {
//         send_len = sendto(socket_fd, buf, len, 0,
//             (struct sockaddr *) peer_address, addr_len);
//     }

//     if (send_len < 0) syserr("sendto fail"); // NOTE (chyba) Nie powinno się wywalać
//     return send_len;
// }

// TODO widać powtarzający się schemat, można to ujednolicić

/**
 * Jeśli nie bierzemy z g_buf: sinfo->len=-1
 */

// static ssize_t _send_message(const struct sockaddr_in *peer_address, const uint8_t *buf,
//                             const Message *msg, ssize_t len) {
//     if (len < 0) {
        
//     }

//     ssize_t send_len = sendto_wrap(peer_address, buf, msg, len);
//     if (send_len > 0 ) log_sent_message(peer_address, msg, send_len);

//     return send_len;
// }

// NOTE IMPORTANT BELOW
/**
 * Sinfo should already have all fields (except known (which is only return-field)
 * and len if it is not meant to be -1) set before the function.
 * Field `buf` ofc has no meaning when `len` field is -1.
*/

void nsend_hello(SendInfo *sinfo) {
    HelloMessage msg = {
        .base.message = MSG_HELLO
    };

    sinfo->len = -1; // To nawet chyba lepiej zrobić wcześniej

    _send_message(sinfo, (Message *)&msg);
}

void nsend_hello_reply(SendInfo *sinfo) {
    Peer *p = peer_find(sinfo->peer_address);
    sinfo->known = p != NULL;
    ssize_t pind = sinfo->known ? peer_index(p) : -1;
    
    HelloReplyMessage msg = {
        .base.message = MSG_HELLO_REPLY,
        .count        = sinfo->known ? htons(peer_get_count(p)-1) : htons(peer_get_count(p)),
    };

    sinfo->len = msg_size((Message *)&msg) + ntohs(msg.count) * sizeof(Peer);

    _prepare_buffer_for_sending(sinfo->buf, (Message *)&msg, pind);
    sinfo->len = _send_message(sinfo, (Message *)&msg);
    // sinfo->send_len = send_message(peer_address, (Message *)&msg, full_len);
}

ssize_t nsend_connect(struct sockaddr_in *peer_address) {
    ConnectMessage msg = {
        .base.message = MSG_CONNECT
    };

    return send_message(peer_address, (Message *)&msg, -1);
}

ssize_t nsend_ack_connect(const struct sockaddr_in *peer_address) {
    AckConnectMessage msg = {
        .base.message = MSG_ACK_CONNECT
    };

    return send_message(peer_address, (Message *)&msg, -1);
}