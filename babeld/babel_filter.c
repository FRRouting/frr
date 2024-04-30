// SPDX-License-Identifier: MIT
/*
Copyright 2011 by Matthieu Boutier and Juliusz Chroboczek
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
    struct distribute *dist = NULL;
    struct access_list *alist;
    struct prefix_list *plist;
    int distribute;
    struct babel *babel;
    afi_t family;

    p.family = v4mapped(prefix) ? AF_INET : AF_INET6;
    p.prefixlen = v4mapped(prefix) ? plen - 96 : plen;
    if (p.family == AF_INET) {
        uchar_to_inaddr(&p.u.prefix4, prefix);
        distribute = output ? DISTRIBUTE_V4_OUT : DISTRIBUTE_V4_IN;
        family = AFI_IP;
    } else {
        uchar_to_in6addr(&p.u.prefix6, prefix);
        distribute = output ? DISTRIBUTE_V6_OUT : DISTRIBUTE_V6_IN;
        family = AFI_IP6;
    }

    if (babel_ifp != NULL && babel_ifp->list[distribute]) {
        if (access_list_apply (babel_ifp->list[distribute], &p)
            == FILTER_DENY) {
            debugf(BABEL_DEBUG_FILTER,
                   "%pFX filtered by distribute %s",
                   &p, output ? "out" : "in");
            return INFINITY;
	}
    }
    if (babel_ifp != NULL && babel_ifp->prefix[distribute]) {
        if (prefix_list_apply (babel_ifp->prefix[distribute], &p)
            == PREFIX_DENY) {
            debugf(BABEL_DEBUG_FILTER, "%pFX filtered by distribute %s",
                   &p, output ? "out" : "in");
            return INFINITY;
	}
    }

    /* All interface filter check. */
    babel = babel_lookup();
    if (babel)
        dist = distribute_lookup (babel->distribute_ctx, NULL);
    if (dist) {
        if (dist->list[distribute]) {
            alist = access_list_lookup (family, dist->list[distribute]);

            if (alist) {
                if (access_list_apply (alist, &p) == FILTER_DENY) {
                    debugf(BABEL_DEBUG_FILTER,"%pFX filtered by distribute %s",
                           &p, output ? "out" : "in");
                    return INFINITY;
		}
	    }
	}
        if (dist->prefix[distribute]) {
            plist = prefix_list_lookup (family, dist->prefix[distribute]);
            if (plist) {
                if (prefix_list_apply (plist, &p) == PREFIX_DENY) {
                    debugf(BABEL_DEBUG_FILTER,"%pFX filtered by distribute %s",
                           &p, output ? "out" : "in");
                    return INFINITY;
		}
	    }
	}
    }
    return 0;
}
