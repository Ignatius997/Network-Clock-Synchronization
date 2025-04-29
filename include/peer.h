#ifndef PEER_H
#define PEER_H

#include <stdint.h>
#include <netinet/in.h>

/** Structure representing peer.
 * `peer_port` field is *always* held in network order.
 */
typedef struct __attribute__((__packed__)) {
    uint8_t     peer_address_length;
    uint8_t     peer_address[16];
    uint16_t    peer_port;
} Peer;

// Funkcje do zarządzania peerami
void peer_cleanup(void); // Zwolnienie pamięci związanej z peerami
void peer_add(const Peer *p); // Dodanie nowego peera
void peer_extract_address(const Peer *p, struct sockaddr_in *addr);

int peer_validate(const Peer *p);

Peer*   peer_find(const struct sockaddr_in *peer_address); // Znalezienie peera na podstawie adresu
ssize_t peer_index(const Peer *p);

// Funkcje do zarządzania listą peerów
uint16_t peer_get_count(void); // Pobranie liczby znanych peerów
Peer* peer_get_all(void); // Pobranie wskaźnika do listy peerów

void peer_print(const Peer *p); // Wypisanie informacji o peerze

#endif // PEER_H