#ifndef _NET_TCP_AO_H
#define _NET_TCP_AO_H

#include <stdint.h>
#include <netinet/in.h>
#include <stdbool.h>

#define TCP_AO_MAXKEYLEN 80

//Originally defined in lib/sockunion.h
#include <netinet/in.h>  // For sockaddr_in and sockaddr_in6

typedef union {
    struct sockaddr sa;          // Generic socket address
    struct sockaddr_in sin;      // Internet socket address for IPv4
    struct sockaddr_in6 sin6;    // Internet socket address for IPv6
    struct sockaddr_storage ss;  // Large enough for any socket address
} sockunion;

struct tcp_ao_key {
    char key[TCP_AO_MAXKEYLEN];
    int key_id;
    uint8_t family;
    uint8_t keylen;
    union {
        struct in_addr a4;
        struct in6_addr a6;
    } addr;
};

#endif 