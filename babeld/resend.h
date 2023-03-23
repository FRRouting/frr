// SPDX-License-Identifier: MIT
/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek
*/
#ifndef BABEL_RESEND_H
#define BABEL_RESEND_H

#define REQUEST_TIMEOUT 65000
#define RESEND_MAX 3

#define RESEND_REQUEST 1
#define RESEND_UPDATE 2

struct resend {
    unsigned char kind;
    unsigned char max;
    unsigned short delay;
    struct timeval time;
    unsigned char prefix[16];
    unsigned char plen;
    unsigned short seqno;
    unsigned char id[8];
    struct interface *ifp;
    struct resend *next;
};

extern struct timeval resend_time;

struct resend *find_request(const unsigned char *prefix, unsigned char plen,
                            struct resend **previous_return);
void flush_resends(struct neighbour *neigh);
int record_resend(int kind, const unsigned char *prefix, unsigned char plen,
                   unsigned short seqno, const unsigned char *id,
                   struct interface *ifp, int delay);
int unsatisfied_request(const unsigned char *prefix, unsigned char plen,
                        unsigned short seqno, const unsigned char *id);
int request_redundant(struct interface *ifp,
                      const unsigned char *prefix, unsigned char plen,
                      unsigned short seqno, const unsigned char *id);
int satisfy_request(const unsigned char *prefix, unsigned char plen,
                    unsigned short seqno, const unsigned char *id,
                    struct interface *ifp);

void expire_resend(void);
void recompute_resend_time(void);
void do_resend(void);

#endif /* BABEL_RESEND_H */
