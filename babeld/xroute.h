// SPDX-License-Identifier: MIT
/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek
Copyright 2011 by Matthieu Boutier and Juliusz Chroboczek
*/

#ifndef BABEL_XROUTE_H
#define BABEL_XROUTE_H

struct xroute {
    unsigned char prefix[16];
    unsigned char plen;
    unsigned short metric;
    unsigned int ifindex;
    int proto;
};

struct xroute_stream;

struct xroute *find_xroute(const unsigned char *prefix, unsigned char plen);
void flush_xroute(struct xroute *xroute);
int babel_route_add (struct zapi_route *api);
int babel_route_delete (struct zapi_route *api);
int xroutes_estimate(void);
struct xroute_stream *xroute_stream(void);
struct xroute *xroute_stream_next(struct xroute_stream *stream);
void xroute_stream_done(struct xroute_stream *stream);

#endif /* BABEL_XROUTE_H */
