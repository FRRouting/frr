/*  
 *  This file is free software: you may copy, redistribute and/or modify it  
 *  under the terms of the GNU General Public License as published by the  
 *  Free Software Foundation, either version 2 of the License, or (at your  
 *  option) any later version.  
 *  
 *  This file is distributed in the hope that it will be useful, but  
 *  WITHOUT ANY WARRANTY; without even the implied warranty of  
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU  
 *  General Public License for more details.  
 *  
 *  You should have received a copy of the GNU General Public License  
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.  
 *  
 * This file incorporates work covered by the following copyright and  
 * permission notice:  
 *  
Copyright (c) 2007, 2008 by Juliusz Chroboczek
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

#include <zebra.h>
#include "if.h"

#include "babeld.h"
#include "util.h"
#include "kernel.h"
#include "babel_interface.h"
#include "source.h"
#include "neighbour.h"
#include "route.h"
#include "xroute.h"
#include "message.h"
#include "resend.h"

static void consider_route(struct babel_route *route);

struct babel_route *routes = NULL;
int numroutes = 0, maxroutes = 0;
int kernel_metric = 0;
int allow_duplicates = -1;

struct babel_route *
find_route(const unsigned char *prefix, unsigned char plen,
           struct neighbour *neigh, const unsigned char *nexthop)
{
    int i;
    for(i = 0; i < numroutes; i++) {
        if(routes[i].neigh == neigh &&
           memcmp(routes[i].nexthop, nexthop, 16) == 0 &&
           source_match(routes[i].src, prefix, plen))
            return &routes[i];
    }
    return NULL;
}

struct babel_route *
find_installed_route(const unsigned char *prefix, unsigned char plen)
{
    int i;
    for(i = 0; i < numroutes; i++) {
        if(routes[i].installed && source_match(routes[i].src, prefix, plen))
            return &routes[i];
    }
    return NULL;
}

void
flush_route(struct babel_route *route)
{
    int i;
    struct source *src;
    unsigned oldmetric;
    int lost = 0;

    i = route - routes;
    assert(i >= 0 && i < numroutes);

    oldmetric = route_metric(route);

    if(route->installed) {
        uninstall_route(route);
        lost = 1;
    }

    src = route->src;

    if(i != numroutes - 1)
        memcpy(routes + i, routes + numroutes - 1, sizeof(struct babel_route));
    numroutes--;
    VALGRIND_MAKE_MEM_UNDEFINED(routes + numroutes, sizeof(struct babel_route));

    if(numroutes == 0) {
        free(routes);
        routes = NULL;
        maxroutes = 0;
    } else if(maxroutes > 8 && numroutes < maxroutes / 4) {
        struct babel_route *new_routes;
        int n = maxroutes / 2;
        new_routes = realloc(routes, n * sizeof(struct babel_route));
        if(new_routes != NULL) {
            routes = new_routes;
            maxroutes = n;
        }
    }

    if(lost)
        route_lost(src, oldmetric);
}

void
flush_neighbour_routes(struct neighbour *neigh)
{
    int i;

    i = 0;
    while(i < numroutes) {
        if(routes[i].neigh == neigh) {
            flush_route(&routes[i]);
            continue;
        }
        i++;
    }
}

void
flush_interface_routes(struct interface *ifp, int v4only)
{
    int i;

    i = 0;
    while(i < numroutes) {
        if(routes[i].neigh->ifp == ifp &&
           (!v4only || v4mapped(routes[i].nexthop))) {
           flush_route(&routes[i]);
           continue;
        }
        i++;
    }
}

static int
metric_to_kernel(int metric)
{
    return metric < INFINITY ? kernel_metric : KERNEL_INFINITY;
}

void
install_route(struct babel_route *route)
{
    int rc;

    if(route->installed)
        return;

    if(!route_feasible(route))
        fprintf(stderr, "WARNING: installing unfeasible route "
                "(this shouldn't happen).");

    rc = kernel_route(ROUTE_ADD, route->src->prefix, route->src->plen,
                      route->nexthop,
                      route->neigh->ifp->ifindex,
                      metric_to_kernel(route_metric(route)), NULL, 0, 0);
    if(rc < 0) {
        int save = errno;
        zlog_err("kernel_route(ADD): %s", safe_strerror(errno));
        if(save != EEXIST)
            return;
    }
    route->installed = 1;
}

void
uninstall_route(struct babel_route *route)
{
    int rc;

    if(!route->installed)
        return;

    rc = kernel_route(ROUTE_FLUSH, route->src->prefix, route->src->plen,
                      route->nexthop,
                      route->neigh->ifp->ifindex,
                      metric_to_kernel(route_metric(route)), NULL, 0, 0);
    if(rc < 0)
        zlog_err("kernel_route(FLUSH): %s", safe_strerror(errno));

    route->installed = 0;
}

/* This is equivalent to uninstall_route followed with install_route,
   but without the race condition.  The destination of both routes
   must be the same. */

static void
switch_routes(struct babel_route *old, struct babel_route *new)
{
    int rc;

    if(!old) {
        install_route(new);
        return;
    }

    if(!old->installed)
        return;

    if(!route_feasible(new))
        fprintf(stderr, "WARNING: switching to unfeasible route "
                "(this shouldn't happen).");

    rc = kernel_route(ROUTE_MODIFY, old->src->prefix, old->src->plen,
                      old->nexthop, old->neigh->ifp->ifindex,
                      metric_to_kernel(route_metric(old)),
                      new->nexthop, new->neigh->ifp->ifindex,
                      metric_to_kernel(route_metric(new)));
    if(rc < 0) {
        zlog_err("kernel_route(MODIFY): %s", safe_strerror(errno));
        return;
    }

    old->installed = 0;
    new->installed = 1;
}

static void
change_route_metric(struct babel_route *route, unsigned newmetric)
{
    int old, new;

    if(route_metric(route) == newmetric)
        return;

    old = metric_to_kernel(route_metric(route));
    new = metric_to_kernel(newmetric);

    if(route->installed && old != new) {
        int rc;
        rc = kernel_route(ROUTE_MODIFY, route->src->prefix, route->src->plen,
                          route->nexthop, route->neigh->ifp->ifindex,
                          old,
                          route->nexthop, route->neigh->ifp->ifindex,
                          new);
        if(rc < 0) {
            zlog_err("kernel_route(MODIFY metric): %s", safe_strerror(errno));
            return;
        }
    }

    route->metric = newmetric;
}

static void
retract_route(struct babel_route *route)
{
    route->refmetric = INFINITY;
    change_route_metric(route, INFINITY);
}

int
route_feasible(struct babel_route *route)
{
    return update_feasible(route->src, route->seqno, route->refmetric);
}

int
route_old(struct babel_route *route)
{
    return route->time < babel_now.tv_sec - route->hold_time * 7 / 8;
}

int
route_expired(struct babel_route *route)
{
    return route->time < babel_now.tv_sec - route->hold_time;
}

int
update_feasible(struct source *src,
                unsigned short seqno, unsigned short refmetric)
{
    if(src == NULL)
        return 1;

    if(src->time < babel_now.tv_sec - SOURCE_GC_TIME)
        /* Never mind what is probably stale data */
        return 1;

    if(refmetric >= INFINITY)
        /* Retractions are always feasible */
        return 1;

    return (seqno_compare(seqno, src->seqno) > 0 ||
            (src->seqno == seqno && refmetric < src->metric));
}

/* This returns the feasible route with the smallest metric. */
struct babel_route *
find_best_route(const unsigned char *prefix, unsigned char plen, int feasible,
                struct neighbour *exclude)
{
    struct babel_route *route = NULL;
    int i;

    for(i = 0; i < numroutes; i++) {
        if(!source_match(routes[i].src, prefix, plen))
            continue;
        if(route_expired(&routes[i]))
            continue;
        if(feasible && !route_feasible(&routes[i]))
            continue;
        if(exclude && routes[i].neigh == exclude)
            continue;
        if(route && route_metric(route) <= route_metric(&routes[i]))
            continue;
        route = &routes[i];
    }
    return route;
}

void
update_route_metric(struct babel_route *route)
{
    int oldmetric = route_metric(route);

    if(route_expired(route)) {
        if(route->refmetric < INFINITY) {
            route->seqno = seqno_plus(route->src->seqno, 1);
            retract_route(route);
            if(oldmetric < INFINITY)
                route_changed(route, route->src, oldmetric);
        }
    } else {
        struct neighbour *neigh = route->neigh;
        int add_metric = input_filter(route->src->id,
                                      route->src->prefix, route->src->plen,
                                      neigh->address,
                                      neigh->ifp->ifindex);
        int newmetric = MIN(route->refmetric +
                            add_metric +
                            neighbour_cost(route->neigh),
                            INFINITY);

        if(newmetric != oldmetric) {
            change_route_metric(route, newmetric);
            route_changed(route, route->src, oldmetric);
        }
    }
}

/* Called whenever a neighbour's cost changes, to update the metric of
 all routes through that neighbour. */
void
update_neighbour_metric(struct neighbour *neigh, int changed)
{
    if(changed) {
        int i;

        i = 0;
        while(i < numroutes) {
            if(routes[i].neigh == neigh)
                update_route_metric(&routes[i]);
            i++;
        }
    }
}

void
update_interface_metric(struct interface *ifp)
{
    int i;

    i = 0;
    while(i < numroutes) {
        if(routes[i].neigh->ifp == ifp)
            update_route_metric(&routes[i]);
        i++;
    }
}

/* This is called whenever we receive an update. */
struct babel_route *
update_route(const unsigned char *router_id,
             const unsigned char *prefix, unsigned char plen,
             unsigned short seqno, unsigned short refmetric,
             unsigned short interval,
             struct neighbour *neigh, const unsigned char *nexthop)
{
    struct babel_route *route;
    struct source *src;
    int metric, feasible;
    int add_metric;
    int hold_time = MAX((4 * interval) / 100 + interval / 50, 15);

    if(memcmp(router_id, myid, 8) == 0)
        return NULL; /* I have announced the route */

    if(martian_prefix(prefix, plen)) {
        fprintf(stderr, "Rejecting martian route to %s through %s.\n",
                format_prefix(prefix, plen), format_address(router_id));
        return NULL;
    }

    add_metric = input_filter(router_id, prefix, plen,
                              neigh->address, neigh->ifp->ifindex);
    if(add_metric >= INFINITY)
        return NULL;

    src = find_source(router_id, prefix, plen, 1, seqno);
    if(src == NULL)
        return NULL;

    feasible = update_feasible(src, seqno, refmetric);
    route = find_route(prefix, plen, neigh, nexthop);
    metric = MIN((int)refmetric + neighbour_cost(neigh) + add_metric, INFINITY);

    if(route) {
        struct source *oldsrc;
        unsigned short oldmetric;
        int lost = 0;

        oldsrc = route->src;
        oldmetric = route_metric(route);

        /* If a successor switches sources, we must accept his update even
           if it makes a route unfeasible in order to break any routing loops
           in a timely manner.  If the source remains the same, we ignore
           the update. */
        if(!feasible && route->installed) {
            debugf(BABEL_DEBUG_COMMON,"Unfeasible update for installed route to %s "
                   "(%s %d %d -> %s %d %d).",
                   format_prefix(src->prefix, src->plen),
                   format_address(route->src->id),
                   route->seqno, route->refmetric,
                   format_address(src->id), seqno, refmetric);
            if(src != route->src) {
                uninstall_route(route);
                lost = 1;
            }
        }

        route->src = src;
        if(feasible && refmetric < INFINITY)
            route->time = babel_now.tv_sec;
        route->seqno = seqno;
        route->refmetric = refmetric;
        change_route_metric(route, metric);
        route->hold_time = hold_time;

        route_changed(route, oldsrc, oldmetric);
        if(lost)
            route_lost(oldsrc, oldmetric);

        if(!feasible)
            send_unfeasible_request(neigh, route->installed && route_old(route),
                                    seqno, metric, src);
    } else {
        if(refmetric >= INFINITY)
            /* Somebody's retracting a route we never saw. */
            return NULL;
        if(!feasible) {
            send_unfeasible_request(neigh, 0, seqno, metric, src);
            return NULL;
        }
        if(numroutes >= maxroutes) {
            struct babel_route *new_routes;
            int n = maxroutes < 1 ? 8 : 2 * maxroutes;
            new_routes = routes == NULL ?
                malloc(n * sizeof(struct babel_route)) :
                realloc(routes, n * sizeof(struct babel_route));
            if(new_routes == NULL)
                return NULL;
            maxroutes = n;
            routes = new_routes;
        }
        route = &routes[numroutes];
        route->src = src;
        route->refmetric = refmetric;
        route->seqno = seqno;
        route->metric = metric;
        route->neigh = neigh;
        memcpy(route->nexthop, nexthop, 16);
        route->time = babel_now.tv_sec;
        route->hold_time = hold_time;
        route->installed = 0;
        numroutes++;
        consider_route(route);
    }
    return route;
}

/* We just received an unfeasible update.  If it's any good, send
   a request for a new seqno. */
void
send_unfeasible_request(struct neighbour *neigh, int force,
                        unsigned short seqno, unsigned short metric,
                        struct source *src)
{
    struct babel_route *route = find_installed_route(src->prefix, src->plen);

    if(seqno_minus(src->seqno, seqno) > 100) {
        /* Probably a source that lost its seqno.  Let it time-out. */
        return;
    }

    if(force || !route || route_metric(route) >= metric + 512) {
        send_unicast_multihop_request(neigh, src->prefix, src->plen,
                                      src->metric >= INFINITY ?
                                      src->seqno :
                                      seqno_plus(src->seqno, 1),
                                      src->id, 127);
    }
}

/* This takes a feasible route and decides whether to install it. */
static void
consider_route(struct babel_route *route)
{
    struct babel_route *installed;
    struct xroute *xroute;

    if(route->installed)
        return;

    if(!route_feasible(route))
        return;

    xroute = find_xroute(route->src->prefix, route->src->plen);
    if(xroute && (allow_duplicates < 0 || xroute->metric >= allow_duplicates))
        return;

    installed = find_installed_route(route->src->prefix, route->src->plen);

    if(installed == NULL)
        goto install;

    if(route_metric(route) >= INFINITY)
        return;

    if(route_metric(installed) >= INFINITY)
        goto install;

    if(route_metric(installed) >= route_metric(route) + 192)
        goto install;

    /* Avoid switching sources */
    if(installed->src != route->src)
        return;

    if(route_metric(installed) >= route_metric(route) + 64)
        goto install;

    return;

 install:
    switch_routes(installed, route);
    if(installed && route->installed)
        send_triggered_update(route, installed->src, route_metric(installed));
    else
        send_update(NULL, 1, route->src->prefix, route->src->plen);
    return;
}

void
retract_neighbour_routes(struct neighbour *neigh)
{
    int i;

    i = 0;
    while(i < numroutes) {
        if(routes[i].neigh == neigh) {
            if(routes[i].refmetric != INFINITY) {
                unsigned short oldmetric = route_metric(&routes[i]);
                    retract_route(&routes[i]);
                    if(oldmetric != INFINITY)
                        route_changed(&routes[i], routes[i].src, oldmetric);
            }
        }
        i++;
    }
}

void
send_triggered_update(struct babel_route *route, struct source *oldsrc,
                      unsigned oldmetric)
{
    unsigned newmetric, diff;
    /* 1 means send speedily, 2 means resend */
    int urgent;

    if(!route->installed)
        return;

    newmetric = route_metric(route);
    diff =
        newmetric >= oldmetric ? newmetric - oldmetric : oldmetric - newmetric;

    if(route->src != oldsrc || (oldmetric < INFINITY && newmetric >= INFINITY))
        /* Switching sources can cause transient routing loops.
           Retractions can cause blackholes. */
        urgent = 2;
    else if(newmetric > oldmetric && oldmetric < 6 * 256 && diff >= 512)
        /* Route getting significantly worse */
        urgent = 1;
    else if(unsatisfied_request(route->src->prefix, route->src->plen,
                                route->seqno, route->src->id))
        /* Make sure that requests are satisfied speedily */
        urgent = 1;
    else if(oldmetric >= INFINITY && newmetric < INFINITY)
        /* New route */
        urgent = 0;
    else if(newmetric < oldmetric && diff < 1024)
        /* Route getting better.  This may be a transient fluctuation, so
           don't advertise it to avoid making routes unfeasible later on. */
        return;
    else if(diff < 384)
        /* Don't fret about trivialities */
        return;
    else
        urgent = 0;

    if(urgent >= 2)
        send_update_resend(NULL, route->src->prefix, route->src->plen);
    else
        send_update(NULL, urgent, route->src->prefix, route->src->plen);

    if(oldmetric < INFINITY) {
        if(newmetric >= oldmetric + 512) {
            send_request_resend(NULL, route->src->prefix, route->src->plen,
                                route->src->metric >= INFINITY ?
                                route->src->seqno :
                                seqno_plus(route->src->seqno, 1),
                                route->src->id);
        } else if(newmetric >= oldmetric + 288) {
            send_request(NULL, route->src->prefix, route->src->plen);
        }
    }
}

/* A route has just changed.  Decide whether to switch to a different route or
   send an update. */
void
route_changed(struct babel_route *route,
              struct source *oldsrc, unsigned short oldmetric)
{
    if(route->installed) {
        if(route_metric(route) > oldmetric) {
            struct babel_route *better_route;
            better_route =
                find_best_route(route->src->prefix, route->src->plen, 1, NULL);
            if(better_route &&
               route_metric(better_route) <= route_metric(route) - 96)
                consider_route(better_route);
        }

        if(route->installed)
            /* We didn't change routes after all. */
            send_triggered_update(route, oldsrc, oldmetric);
    } else {
        /* Reconsider routes even when their metric didn't decrease,
           they may not have been feasible before. */
        consider_route(route);
    }
}

/* We just lost the installed route to a given destination. */
void
route_lost(struct source *src, unsigned oldmetric)
{
    struct babel_route *new_route;
    new_route = find_best_route(src->prefix, src->plen, 1, NULL);
    if(new_route) {
        consider_route(new_route);
    } else if(oldmetric < INFINITY) {
        /* Complain loudly. */
        send_update_resend(NULL, src->prefix, src->plen);
        send_request_resend(NULL, src->prefix, src->plen,
                            src->metric >= INFINITY ?
                            src->seqno : seqno_plus(src->seqno, 1),
                            src->id);
    }
}

void
expire_routes(void)
{
    int i;

    debugf(BABEL_DEBUG_COMMON,"Expiring old routes.");

    i = 0;
    while(i < numroutes) {
        struct babel_route *route = &routes[i];

        if(route->time > babel_now.tv_sec || /* clock stepped */
           route_old(route)) {
            flush_route(route);
            continue;
        }

        update_route_metric(route);

        if(route->installed && route->refmetric < INFINITY) {
            if(route_old(route))
                send_unicast_request(route->neigh,
                                     route->src->prefix, route->src->plen);
        }
        i++;
    }
}

void
babel_uninstall_all_routes(void)
{
    while(numroutes > 0) {
        uninstall_route(&routes[0]);
        /* We need to flush the route so network_up won't reinstall it */
        flush_route(&routes[0]);
    }
}

struct babel_route *
babel_route_get_by_source(struct source *src)
{
    int i;
    for(i = 0; i < numroutes; i++) {
        if(routes[i].src == src)
            return &routes[i];
    }
    return NULL;
}
