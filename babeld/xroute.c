// SPDX-License-Identifier: MIT
/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek
Copyright 2011 by Matthieu Boutier and Juliusz Chroboczek
*/

#include <zebra.h>
#include "if.h"
#include "log.h"

#include "babeld.h"
#include "kernel.h"
#include "neighbour.h"
#include "message.h"
#include "route.h"
#include "xroute.h"
#include "util.h"
#include "babel_interface.h"

static int xroute_add_new_route(unsigned char prefix[16], unsigned char plen,
                                unsigned short metric, unsigned int ifindex,
                                int proto, int send_updates);

static struct xroute *xroutes;
static int numxroutes = 0, maxxroutes = 0;

/* Add redistributed route to Babel table. */
int
babel_route_add (struct zapi_route *api)
{
    unsigned char uchar_prefix[16];

    switch (api->prefix.family) {
    case AF_INET:
        inaddr_to_uchar(uchar_prefix, &api->prefix.u.prefix4);
        debugf(BABEL_DEBUG_ROUTE, "Adding new ipv4 route coming from Zebra.");
        xroute_add_new_route(uchar_prefix, api->prefix.prefixlen + 96,
                             api->metric, api->nexthops[0].ifindex, 0, 1);
        break;
    case AF_INET6:
        in6addr_to_uchar(uchar_prefix, &api->prefix.u.prefix6);
        debugf(BABEL_DEBUG_ROUTE, "Adding new ipv6 route coming from Zebra.");
        xroute_add_new_route(uchar_prefix, api->prefix.prefixlen,
                             api->metric, api->nexthops[0].ifindex, 0, 1);
        break;
    }

    return 0;
}

/* Remove redistributed route from Babel table. */
int
babel_route_delete (struct zapi_route *api)
{
    unsigned char uchar_prefix[16];
    struct xroute *xroute = NULL;

    switch (api->prefix.family) {
    case AF_INET:
        inaddr_to_uchar(uchar_prefix, &api->prefix.u.prefix4);
        xroute = find_xroute(uchar_prefix, api->prefix.prefixlen + 96);
        if (xroute != NULL) {
            debugf(BABEL_DEBUG_ROUTE, "Removing ipv4 route (from zebra).");
            flush_xroute(xroute);
        }
        break;
    case AF_INET6:
        in6addr_to_uchar(uchar_prefix, &api->prefix.u.prefix6);
        xroute = find_xroute(uchar_prefix, api->prefix.prefixlen);
        if (xroute != NULL) {
            debugf(BABEL_DEBUG_ROUTE, "Removing ipv6 route (from zebra).");
            flush_xroute(xroute);
        }
        break;
    }

    return 0;
}

struct xroute *
find_xroute(const unsigned char *prefix, unsigned char plen)
{
    int i;
    for(i = 0; i < numxroutes; i++) {
        if(xroutes[i].plen == plen &&
           memcmp(xroutes[i].prefix, prefix, 16) == 0)
            return &xroutes[i];
    }
    return NULL;
}

void
flush_xroute(struct xroute *xroute)
{
    int i;

    i = xroute - xroutes;
    assert(i >= 0 && i < numxroutes);

    if(i != numxroutes - 1)
        memcpy(xroutes + i, xroutes + numxroutes - 1, sizeof(struct xroute));
    numxroutes--;
    VALGRIND_MAKE_MEM_UNDEFINED(xroutes + numxroutes, sizeof(struct xroute));

    if(numxroutes == 0) {
        free(xroutes);
        xroutes = NULL;
        maxxroutes = 0;
    } else if(maxxroutes > 8 && numxroutes < maxxroutes / 4) {
        struct xroute *new_xroutes;
        int n = maxxroutes / 2;
        new_xroutes = realloc(xroutes, n * sizeof(struct xroute));
        if(new_xroutes == NULL)
            return;
        xroutes = new_xroutes;
        maxxroutes = n;
    }
}

static int
add_xroute(unsigned char prefix[16], unsigned char plen,
           unsigned short metric, unsigned int ifindex, int proto)
{
    struct xroute *xroute = find_xroute(prefix, plen);
    if(xroute) {
        if(xroute->metric <= metric)
            return 0;
        xroute->metric = metric;
        return 1;
    }

    if(numxroutes >= maxxroutes) {
        struct xroute *new_xroutes;
        int n = maxxroutes < 1 ? 8 : 2 * maxxroutes;
        new_xroutes = xroutes == NULL ?
            malloc(n * sizeof(struct xroute)) :
            realloc(xroutes, n * sizeof(struct xroute));
        if(new_xroutes == NULL)
            return -1;
        maxxroutes = n;
        xroutes = new_xroutes;
    }

    memcpy(xroutes[numxroutes].prefix, prefix, 16);
    xroutes[numxroutes].plen = plen;
    xroutes[numxroutes].metric = metric;
    xroutes[numxroutes].ifindex = ifindex;
    xroutes[numxroutes].proto = proto;
    numxroutes++;
    return 1;
}

/* Returns an overestimate of the number of xroutes. */
int
xroutes_estimate(void)
{
    return numxroutes;
}

struct xroute_stream {
    int index;
};

struct
xroute_stream *
xroute_stream(void)
{
    struct xroute_stream *stream = malloc(sizeof(struct xroute_stream));
    if(stream == NULL)
       return NULL;

    stream->index = 0;
    return stream;
}

struct xroute *
xroute_stream_next(struct xroute_stream *stream)
{
    if(stream->index < numxroutes)
        return &xroutes[stream->index++];
    else
        return NULL;
}

void
xroute_stream_done(struct xroute_stream *stream)
{
    free(stream);
}

/* add an xroute, verifying some conditions; return 0 if there is no changes */
static int
xroute_add_new_route(unsigned char prefix[16], unsigned char plen,
                     unsigned short metric, unsigned int ifindex,
                     int proto, int send_updates)
{
    int rc;
    if(martian_prefix(prefix, plen))
        return 0;
    metric = redistribute_filter(prefix, plen, ifindex, proto);
    if(metric < INFINITY) {
        rc = add_xroute(prefix, plen, metric, ifindex, proto);
        if(rc > 0) {
            struct babel_route *route;
            route = find_installed_route(prefix, plen);
            if(route)
                uninstall_route(route);
            if(send_updates)
                send_update(NULL, 0, prefix, plen);
            return 1;
        }
    }
    return 0;
}
