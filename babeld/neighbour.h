// SPDX-License-Identifier: MIT
/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek
*/

#ifndef BABEL_NEIGHBOUR_H
#define BABEL_NEIGHBOUR_H

struct neighbour {
    struct neighbour *next;
    /* This is -1 when unknown, so don't make it unsigned */
    int hello_seqno;
    unsigned char address[16];
    unsigned short reach;
    unsigned short txcost;
    struct timeval hello_time;
    struct timeval ihu_time;
    unsigned short hello_interval; /* in centiseconds */
    unsigned short ihu_interval;   /* in centiseconds */
    /* Used for RTT estimation. */
    /* Absolute time (modulo 2^32) at which the Hello was sent,
       according to remote clock. */
    unsigned int hello_send_us;
    struct timeval hello_rtt_receive_time;
    unsigned int rtt;
    struct timeval rtt_time;
    struct interface *ifp;
};

extern struct neighbour *neighs;

#define FOR_ALL_NEIGHBOURS(_neigh) \
    for(_neigh = neighs; _neigh; _neigh = _neigh->next)

int neighbour_valid(struct neighbour *neigh);
void flush_neighbour(struct neighbour *neigh);
struct neighbour *find_neighbour(const unsigned char *address,
                                 struct interface *ifp);
int update_neighbour(struct neighbour *neigh, int hello, int hello_interval);
unsigned check_neighbours(void);
unsigned neighbour_txcost(struct neighbour *neigh);
unsigned neighbour_rxcost(struct neighbour *neigh);
unsigned neighbour_rttcost(struct neighbour *neigh);
unsigned neighbour_cost(struct neighbour *neigh);
int valid_rtt(struct neighbour *neigh);

#endif /* BABEL_NEIGHBOUR_H */
