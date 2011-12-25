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
babel_filter_in (struct prefix *p, babel_interface_nfo *babel_ifp)
{
    struct distribute *dist;
    struct access_list *alist;
    struct prefix_list *plist;

    /* Input distribute-list filtering. */
    if (babel_ifp != NULL && babel_ifp->list[BABEL_FILTER_IN]) {
        if (access_list_apply (babel_ifp->list[BABEL_FILTER_IN], p)
            == FILTER_DENY) {
            debugf(BABEL_DEBUG_FILTER,
                   "%s/%d filtered by distribute in",
                   p->family == AF_INET ?
                   inet_ntoa(p->u.prefix4) :
                   inet6_ntoa (p->u.prefix6),
                   p->prefixlen);
            return -1;
	}
    }
    if (babel_ifp != NULL && babel_ifp->prefix[BABEL_FILTER_IN]) {
        if (prefix_list_apply (babel_ifp->prefix[BABEL_FILTER_IN], p)
            == PREFIX_DENY) {
            debugf(BABEL_DEBUG_FILTER, "%s/%d filtered by distribute in",
                        p->family == AF_INET ?
                        inet_ntoa(p->u.prefix4) :
                        inet6_ntoa (p->u.prefix6),
                        p->prefixlen);
            return -1;
	}
    }

    /* All interface filter check. */
    dist = distribute_lookup (NULL);
    if (dist) {
        if (dist->list[DISTRIBUTE_IN]) {
            alist = access_list_lookup (AFI_IP6, dist->list[DISTRIBUTE_IN]);

            if (alist) {
                if (access_list_apply (alist, p) == FILTER_DENY) {
                    debugf(BABEL_DEBUG_FILTER, "%s/%d filtered by distribute in",
                                p->family == AF_INET ?
                                inet_ntoa(p->u.prefix4) :
                                inet6_ntoa (p->u.prefix6),
                                p->prefixlen);
                    return -1;
		}
	    }
	}
        if (dist->prefix[DISTRIBUTE_IN]) {
            plist = prefix_list_lookup (AFI_IP6, dist->prefix[DISTRIBUTE_IN]);
            if (plist) {
                if (prefix_list_apply (plist, p) == PREFIX_DENY) {
                    debugf(BABEL_DEBUG_FILTER, "%s/%d filtered by distribute in",
                                p->family == AF_INET ?
                                inet_ntoa(p->u.prefix4) :
                                inet6_ntoa (p->u.prefix6),
                                p->prefixlen);
                    return -1;
		}
	    }
	}
    }
    return 0;
}

int
babel_filter_out (struct prefix *p, babel_interface_nfo *babel_ifp)
{
    struct distribute *dist;
    struct access_list *alist;
    struct prefix_list *plist;

    if (babel_ifp != NULL && babel_ifp->list[BABEL_FILTER_OUT]) {
        if (access_list_apply (babel_ifp->list[BABEL_FILTER_OUT], p)
            == FILTER_DENY) {
            debugf(BABEL_DEBUG_FILTER, "%s/%d filtered by distribute out",
                        p->family == AF_INET ?
                        inet_ntoa(p->u.prefix4) :
                        inet6_ntoa (p->u.prefix6),
                        p->prefixlen);
            return -1;
	}
    }
    if (babel_ifp != NULL && babel_ifp->prefix[BABEL_FILTER_OUT]) {
        if (prefix_list_apply (babel_ifp->prefix[BABEL_FILTER_OUT], p)
            == PREFIX_DENY) {
            debugf(BABEL_DEBUG_FILTER, "%s/%d filtered by distribute out",
                        p->family == AF_INET ?
                        inet_ntoa(p->u.prefix4) :
                        inet6_ntoa (p->u.prefix6),
                        p->prefixlen);
            return -1;
	}
    }

    /* All interface filter check. */
    dist = distribute_lookup (NULL);
    if (dist) {
        if (dist->list[DISTRIBUTE_OUT]) {
            alist = access_list_lookup (AFI_IP6, dist->list[DISTRIBUTE_OUT]);
            if (alist) {
                if (access_list_apply (alist, p) == FILTER_DENY) {
                    debugf(BABEL_DEBUG_FILTER, "%s/%d filtered by distribute out",
                                p->family == AF_INET ?
                                inet_ntoa(p->u.prefix4) :
                                inet6_ntoa (p->u.prefix6),
                                p->prefixlen);
                    return -1;
		}
	    }
	}
        if (dist->prefix[DISTRIBUTE_OUT]) {
            plist = prefix_list_lookup (AFI_IP6, dist->prefix[DISTRIBUTE_OUT]);
            if (plist) {
                if (prefix_list_apply (plist, p) == PREFIX_DENY) {
                    debugf(BABEL_DEBUG_FILTER, "%s/%d filtered by distribute out",
                                p->family == AF_INET ?
                                inet_ntoa(p->u.prefix4) :
                                inet6_ntoa (p->u.prefix6),
                                p->prefixlen);
                    return -1;
		}
	    }
	}
    }
    return 0;
}

int
babel_filter_redistribute (struct prefix *p,
                           babel_interface_nfo *babel_ifp)
{
    debugf(BABEL_DEBUG_FILTER, "%s/%d WARNING: no redistribute filter implemented !!!!",
                p->family == AF_INET ?
                inet_ntoa(p->u.prefix4) :
                inet6_ntoa (p->u.prefix6),
                p->prefixlen);
    return 0; /* TODO: it redistributes always */
}
