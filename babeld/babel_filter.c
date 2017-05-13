/*
Copyright 2011 by Matthieu Boutier and Juliusz Chroboczek

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

#include "babel_filter.h"
#include "vty.h"
#include "filter.h"
#include "log.h"
#include "plist.h"
#include "distribute.h"
#include "util.h"

int
babel_filter(int output, const unsigned char *prefix, unsigned short plen,
             unsigned int ifindex)
{
    struct interface *ifp = if_lookup_by_index(ifindex, VRF_DEFAULT);
    babel_interface_nfo *babel_ifp = ifp ? babel_get_if_nfo(ifp) : NULL;
    struct prefix p;
    struct distribute *dist;
    struct access_list *alist;
    struct prefix_list *plist;
    int distribute;

    p.family = v4mapped(prefix) ? AF_INET : AF_INET6;
    p.prefixlen = v4mapped(prefix) ? plen - 96 : plen;
    if (p.family == AF_INET) {
        uchar_to_inaddr(&p.u.prefix4, prefix);
        distribute = output ? DISTRIBUTE_V4_OUT : DISTRIBUTE_V4_IN;
    } else {
        uchar_to_in6addr(&p.u.prefix6, prefix);
        distribute = output ? DISTRIBUTE_V6_OUT : DISTRIBUTE_V6_IN;
    }

    if (babel_ifp != NULL && babel_ifp->list[distribute]) {
        if (access_list_apply (babel_ifp->list[distribute], &p)
            == FILTER_DENY) {
            debugf(BABEL_DEBUG_FILTER,
                   "%s/%d filtered by distribute %s",
                   p.family == AF_INET ?
                   inet_ntoa(p.u.prefix4) :
                   inet6_ntoa (p.u.prefix6),
                   p.prefixlen,
                   output ? "out" : "in");
            return INFINITY;
	}
    }
    if (babel_ifp != NULL && babel_ifp->prefix[distribute]) {
        if (prefix_list_apply (babel_ifp->prefix[distribute], &p)
            == PREFIX_DENY) {
            debugf(BABEL_DEBUG_FILTER, "%s/%d filtered by distribute %s",
                   p.family == AF_INET ?
                   inet_ntoa(p.u.prefix4) :
                   inet6_ntoa (p.u.prefix6),
                   p.prefixlen,
                   output ? "out" : "in");
            return INFINITY;
	}
    }

    /* All interface filter check. */
    dist = distribute_lookup (NULL);
    if (dist) {
        if (dist->list[distribute]) {
            alist = access_list_lookup (p.family, dist->list[distribute]);

            if (alist) {
                if (access_list_apply (alist, &p) == FILTER_DENY) {
                    debugf(BABEL_DEBUG_FILTER,"%s/%d filtered by distribute %s",
                           p.family == AF_INET ?
                           inet_ntoa(p.u.prefix4) :
                           inet6_ntoa (p.u.prefix6),
                           p.prefixlen,
                           output ? "out" : "in");
                    return INFINITY;
		}
	    }
	}
        if (dist->prefix[distribute]) {
            plist = prefix_list_lookup (p.family, dist->prefix[distribute]);
            if (plist) {
                if (prefix_list_apply (plist, &p) == PREFIX_DENY) {
                    debugf(BABEL_DEBUG_FILTER,"%s/%d filtered by distribute %s",
                           p.family == AF_INET ?
                           inet_ntoa(p.u.prefix4) :
                           inet6_ntoa (p.u.prefix6),
                           p.prefixlen,
                           output ? "out" : "in");
                    return INFINITY;
		}
	    }
	}
    }
    return 0;
}
