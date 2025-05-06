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

Peer*   peer_find(const struct sockaddr_in *peer_address); // Znalezienie peera na podstawie adresu
ssize_t peer_index(const Peer *p);

// Funkcje do zarządzania listą peerów
uint16_t peer_get_count(void); // Pobranie liczby znanych peerów
const Peer* peer_get_all(void); // Pobranie wskaźnika do listy peerów

void peer_print(const Peer *p); // Wypisanie informacji o peerze
void peer_all_print(const Peer *peers);

#endif // PEER_H