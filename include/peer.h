#ifndef PEER_H
#define PEER_H

#include <stdint.h>
#include <arpa/inet.h>
#include <stdint.h>

#define PEER_MAX_COUNT UINT16_MAX // Max amount of peers

/** Structure representing peer.
 * `peer_port` field is *always* held in network order.
 */
typedef struct __attribute__((__packed__)) {
    uint8_t     peer_address_length;
    uint8_t     peer_address[16];
    uint16_t    peer_port;
} Peer;

// Funkcje do zarządzania peerami
void peer_add(const Peer *p); // Dodanie nowego peera

/**
 * @brief Finds a peer in the system based on its address.
 *
 * This function searches for a peer in the system using the provided
 * socket address. If a peer with the specified address exists, a pointer
 * to the corresponding Peer structure is returned. Otherwise, NULL is returned.
 *
 * @param peer_address A pointer to a sockaddr_in structure representing
 *                     the address of the peer to find.
 * @return A pointer to the Peer structure if the peer is found, or NULL
 *         if no matching peer exists.
 */
Peer*   peer_find(const struct sockaddr_in *peer_address);
ssize_t peer_index(const Peer *p);

// Funkcje do zarządzania listą peerów

/**
 * @brief Retrieves the count of peers in the current network or system.
 *
 * This function returns the total number of peers currently connected or 
 * available in the network. It can be used to monitor the size of the 
 * peer group or to perform operations based on the peer count.
 *
 * @return The number of peers.
 */
uint16_t peer_get_count(void);
const Peer* peer_get_all(void); // Pobranie wskaźnika do listy peerów

void peer_print(const Peer *p); // Wypisanie informacji o peerze
void peer_all_print(const Peer *peers);

#endif // PEER_H