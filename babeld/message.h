/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef BABEL_MESSAGE_H
#define BABEL_MESSAGE_H

#include "babel_interface.h"

#define MAX_BUFFERED_UPDATES 200

#define BUCKET_TOKENS_MAX 200
#define BUCKET_TOKENS_PER_SEC 40

/* A registry of assigned TLV and sub-TLV types is available at
   http://www.pps.univ-paris-diderot.fr/~jch/software/babel/babel-tlv-registry.text
*/
#define MESSAGE_PAD1 0
#define MESSAGE_PADN 1
#define MESSAGE_ACK_REQ 2
#define MESSAGE_ACK 3
#define MESSAGE_HELLO 4
#define MESSAGE_IHU 5
#define MESSAGE_ROUTER_ID 6
#define MESSAGE_NH 7
#define MESSAGE_UPDATE 8
#define MESSAGE_REQUEST 9
#define MESSAGE_MH_REQUEST 10
#define MESSAGE_MAX 10

/* Protocol extension through sub-TLVs. */
#define SUBTLV_PAD1 0
#define SUBTLV_PADN 1
#define SUBTLV_DIVERSITY 2 /* Also known as babelz. */
#define SUBTLV_TIMESTAMP 3 /* Used to compute RTT. */

extern unsigned short myseqno;

extern int broadcast_ihu;
extern int split_horizon;

extern struct neighbour *unicast_neighbour;
extern struct timeval unicast_flush_timeout;

void parse_packet(const unsigned char *from, struct interface *ifp,
                  const unsigned char *packet, int packetlen);
void flushbuf(struct interface *ifp);
void flushupdates(struct interface *ifp);
void send_ack(struct neighbour *neigh, unsigned short nonce,
              unsigned short interval);
void send_hello_noupdate(struct interface *ifp, unsigned interval);
void send_hello(struct interface *ifp);
void flush_unicast(int dofree);
void send_update(struct interface *ifp, int urgent,
                 const unsigned char *prefix, unsigned char plen);
void send_update_resend(struct interface *ifp,
                        const unsigned char *prefix, unsigned char plen);
void send_wildcard_retraction(struct interface *ifp);
void update_myseqno(void);
void send_self_update(struct interface *ifp);
void send_ihu(struct neighbour *neigh, struct interface *ifp);
void send_marginal_ihu(struct interface *ifp);
void send_request(struct interface *ifp,
                  const unsigned char *prefix, unsigned char plen);
void send_unicast_request(struct neighbour *neigh,
                          const unsigned char *prefix, unsigned char plen);
void send_multihop_request(struct interface *ifp,
                           const unsigned char *prefix, unsigned char plen,
                           unsigned short seqno, const unsigned char *id,
                           unsigned short hop_count);
void
send_unicast_multihop_request(struct neighbour *neigh,
                              const unsigned char *prefix, unsigned char plen,
                              unsigned short seqno, const unsigned char *id,
                              unsigned short hop_count);
void send_request_resend(struct neighbour *neigh,
                         const unsigned char *prefix, unsigned char plen,
                         unsigned short seqno, unsigned char *id);
void handle_request(struct neighbour *neigh, const unsigned char *prefix,
                    unsigned char plen, unsigned char hop_count,
                    unsigned short seqno, const unsigned char *id);

#endif
