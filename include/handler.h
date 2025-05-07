#ifndef NCS_HANDLER_H
#define NCS_HANDLER_H

#include <arpa/inet.h>

/**
 * @brief Handles a received message from a peer.
 *
 * This function processes a message received from a peer. It assumes that the 
 * received data is valid and correctly formatted. The function performs the 
 * following steps:
 * 
 * 1. Verifies if the sender is valid. If the sender is unknown and the message
 *    type does not allow unknown senders, an error is logged and function is aborted.
 * 2. Handles the received message based on its type (and message correctness,
 *    see point 3.) by modifying node data and/or sending adequate message.
 * 3. If received message meets specified expectations (cf. `_sync_start`
 *    function in `handler.c` file) the expected message in the synchronization
 *    process is updated to ensure proper protocol flow.
 *
 * @param sender_address A pointer to the sockaddr_in structure representing the 
 *                       address of the node that sent the message.
 * @param recv_len The length of the received message.
 */
void handle_message(const struct sockaddr_in *sender_address, const ssize_t recv_len);

void handle_recv_fail(const struct sockaddr_in *peer_address);

#endif // NCS_HANDLER_H