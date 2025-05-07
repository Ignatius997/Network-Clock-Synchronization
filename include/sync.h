#ifndef NCS_SYNC_H
#define NCS_SYNC_H

#include <arpa/inet.h>
#include <stdint.h>

#include "../include/message.h"

#define SYNC_NONE 255

uint8_t sync_get_exp_msg(void);
void    sync_set_exp_msg(const uint8_t msg);

/**
 * @brief Updates the expected message based on the received message.
 *
 * This function updates the expected message after handling a received message.
 * It assumes that the provided message is valid and has already been handled.
 *
 * @param msg A pointer to the received message.
 */
void sync_update_exp_msg(const Message *msg);

void sync_cancel(void);

#endif // NCS_SYNC_H