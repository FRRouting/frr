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

#ifndef BABEL_ROUTE_H
#define BABEL_ROUTE_H

#include "babel_interface.h"
#include "source.h"

struct babel_route {
    struct source *src;
    unsigned short metric;
    unsigned short refmetric;
    unsigned short seqno;
    struct neighbour *neigh;
    unsigned char nexthop[16];
    time_t time;
    unsigned short hold_time;    /* in seconds */
    short installed;
};

static inline unsigned short
route_metric(const struct babel_route *route)
{
    return route->metric;
}

extern struct babel_route *routes;
extern int numroutes, maxroutes;
extern int kernel_metric, allow_duplicates;

struct babel_route *find_route(const unsigned char *prefix, unsigned char plen,
                         struct neighbour *neigh, const unsigned char *nexthop);
struct babel_route *find_installed_route(const unsigned char *prefix,
                                   unsigned char plen);
void flush_route(struct babel_route *route);
void flush_neighbour_routes(struct neighbour *neigh);
void flush_interface_routes(struct interface *ifp, int v4only);
void install_route(struct babel_route *route);
void uninstall_route(struct babel_route *route);
void switch_route(struct babel_route *old, struct babel_route *new);
int route_feasible(struct babel_route *route);
int route_old(struct babel_route *route);
int route_expired(struct babel_route *route);
int update_feasible(struct source *src,
                    unsigned short seqno, unsigned short refmetric);
struct babel_route *find_best_route(const unsigned char *prefix, unsigned char plen,
                              int feasible, struct neighbour *exclude);
struct babel_route *install_best_route(const unsigned char prefix[16],
                                 unsigned char plen);
void update_neighbour_metric(struct neighbour *neigh, int change);
void update_interface_metric(struct interface *ifp);
void update_route_metric(struct babel_route *route);
struct babel_route *update_route(const unsigned char *a,
                           const unsigned char *p, unsigned char plen,
                           unsigned short seqno, unsigned short refmetric,
                           unsigned short interval, struct neighbour *neigh,
                           const unsigned char *nexthop);
void retract_neighbour_routes(struct neighbour *neigh);
void send_unfeasible_request(struct neighbour *neigh, int force,
                             unsigned short seqno, unsigned short metric,
                             struct source *src);
void send_triggered_update(struct babel_route *route,
                           struct source *oldsrc, unsigned oldmetric);
void route_changed(struct babel_route *route,
                   struct source *oldsrc, unsigned short oldmetric);
void route_lost(struct source *src, unsigned oldmetric);
void expire_routes(void);

void babel_uninstall_all_routes(void);
struct babel_route *babel_route_get_by_source(struct source *src);

#endif
