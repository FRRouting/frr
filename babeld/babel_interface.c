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

#include <zebra.h>
#include "memory.h"
#include "log.h"
#include "command.h"
#include "prefix.h"
#include "vector.h"

#include "babel_main.h"
#include "util.h"
#include "kernel.h"
#include "babel_interface.h"
#include "message.h"
#include "route.h"
#include "babel_zebra.h"


static int babel_enable_if_lookup (const char *ifname);
static int babel_enable_if_add (const char *ifname);
static int babel_enable_if_delete (const char *ifname);
static int interface_recalculate(struct interface *ifp);
static int interface_reset(struct interface *ifp);
static int babel_if_new_hook    (struct interface *ifp);
static int babel_if_delete_hook (struct interface *ifp);
static int interface_config_write (struct vty *vty);
static babel_interface_nfo * babel_interface_allocate (void);
static void babel_interface_free (babel_interface_nfo *bi);


static vector babel_enable_if;                 /* enable interfaces (by cmd). */
static struct cmd_node babel_interface_node =  /* babeld's interface node.    */
{
    INTERFACE_NODE,
    "%s(config-if)# ",
    1 /* VTYSH */
};


int
babel_interface_up (int cmd, struct zclient *client, zebra_size_t length)
{
    struct stream *s = NULL;
    struct interface *ifp = NULL;

    debugf(BABEL_DEBUG_IF, "receive a 'interface up'");

    s = zclient->ibuf;
    ifp = zebra_interface_state_read(s);

    if (ifp == NULL) {
        return 0;
    }

    interface_recalculate(ifp);
    return 0;
}

int
babel_interface_down (int cmd, struct zclient *client, zebra_size_t length)
{
    struct stream *s = NULL;
    struct interface *ifp = NULL;

    debugf(BABEL_DEBUG_IF, "receive a 'interface down'");

    s = zclient->ibuf;
    ifp = zebra_interface_state_read(s);

    if (ifp == NULL) {
        return 0;
    }

    interface_reset(ifp);
    return 0;
}

int
babel_interface_add (int cmd, struct zclient *client, zebra_size_t length)
{
    struct interface *ifp = NULL;

    debugf(BABEL_DEBUG_IF, "receive a 'interface add'");

    /* read and add the interface in the iflist. */
    ifp = zebra_interface_add_read (zclient->ibuf);

    if (ifp == NULL) {
        return 0;
    }

    interface_recalculate(ifp);

    return 0;
}

int
babel_interface_delete (int cmd, struct zclient *client, zebra_size_t length)
{
    debugf(BABEL_DEBUG_IF, "receive a 'interface delete'");
    return 0;
}

int
babel_interface_address_add (int cmd, struct zclient *client,
                             zebra_size_t length)
{
    babel_interface_nfo *babel_ifp;
    struct connected *ifc;
    struct prefix *prefix;

    debugf(BABEL_DEBUG_IF, "receive a 'interface address add'");

    ifc = zebra_interface_address_read (ZEBRA_INTERFACE_ADDRESS_ADD,
                                        zclient->ibuf);

    if (ifc == NULL)
        return 0;

    prefix = ifc->address;

    if (prefix->family == AF_INET) {
        flush_interface_routes(ifc->ifp, 0);
        babel_ifp = babel_get_if_nfo(ifc->ifp);
        if (babel_ifp->ipv4 == NULL) {
            babel_ifp->ipv4 = malloc(4);
            if (babel_ifp->ipv4 == NULL) {
                zlog_err("not einough memory");
            } else {
                memcpy(babel_ifp->ipv4, &prefix->u.prefix4, 4);
            }
        }
    }

    send_request(ifc->ifp, NULL, 0);
    send_update(ifc->ifp, 0, NULL, 0);

    return 0;
}

int
babel_interface_address_delete (int cmd, struct zclient *client,
                                zebra_size_t length)
{
    babel_interface_nfo *babel_ifp;
    struct connected *ifc;
    struct prefix *prefix;

    debugf(BABEL_DEBUG_IF, "receive a 'interface address add'");

    ifc = zebra_interface_address_read (ZEBRA_INTERFACE_ADDRESS_ADD,
                                        zclient->ibuf);

    if (ifc == NULL)
        return 0;

    prefix = ifc->address;

    if (prefix->family == AF_INET) {
        flush_interface_routes(ifc->ifp, 0);
        babel_ifp = babel_get_if_nfo(ifc->ifp);
        if (babel_ifp->ipv4 != NULL
            && memcmp(babel_ifp->ipv4, &prefix->u.prefix4, 4) == 0) {
            free(babel_ifp->ipv4);
            babel_ifp->ipv4 = NULL;
        }
    }

    send_request(ifc->ifp, NULL, 0);
    send_update(ifc->ifp, 0, NULL, 0);

    return 0;
}

/* Lookup function. */
static int
babel_enable_if_lookup (const char *ifname)
{
    unsigned int i;
    char *str;

    for (i = 0; i < vector_active (babel_enable_if); i++)
        if ((str = vector_slot (babel_enable_if, i)) != NULL)
            if (strcmp (str, ifname) == 0)
                return i;
    return -1;
}

/* Add interface to babel_enable_if. */
static int
babel_enable_if_add (const char *ifname)
{
    int ret;
    struct interface *ifp = NULL;

    ret = babel_enable_if_lookup (ifname);
    if (ret >= 0)
        return -1;

    vector_set (babel_enable_if, strdup (ifname));

    ifp = if_lookup_by_name(ifname);
    if (ifp != NULL)
        babel_get_if_nfo(ifp)->flags |= BABEL_IF_IS_ENABLE;

    return 1;
}

/* Delete interface from babel_enable_if. */
static int
babel_enable_if_delete (const char *ifname)
{
    int babel_enable_if_index;
    char *str;
    struct interface *ifp = NULL;

    babel_enable_if_index = babel_enable_if_lookup (ifname);
    if (babel_enable_if_index < 0)
        return -1;

    str = vector_slot (babel_enable_if, babel_enable_if_index);
    free (str);
    vector_unset (babel_enable_if, babel_enable_if_index);

    ifp = if_lookup_by_name(ifname);
    if (ifp != NULL)
        babel_get_if_nfo(ifp)->flags &= ~BABEL_IF_IS_ENABLE;

    return 1;
}


/* [Babel Command] Babel enable on specified interface or matched network. */
DEFUN (babel_network,
       babel_network_cmd,
       "network IF_OR_ADDR",
       "Babel enable on specified interface or network.\n"
       "Interface or address")
{
    int ret;
    struct prefix p;

    ret = str2prefix (argv[0], &p);

    /* Given string is:               */
    if (ret) /* an IPv4 or v6 network */
        return CMD_ERR_NO_MATCH; /* not implemented yet */
    else     /* an interface name     */
        ret = babel_enable_if_add (argv[0]);

    if (ret < 0) {
        vty_out (vty, "There is same network configuration %s%s", argv[0],
                 VTY_NEWLINE);
        return CMD_WARNING;
    }

    return CMD_SUCCESS;
}

/* [Babel Command] Babel enable on specified interface or matched network. */
DEFUN (no_babel_network,
       no_babel_network_cmd,
       "no network IF_OR_ADDR",
       NO_STR
       "Babel enable on specified interface or network.\n"
       "Interface or address")
{
    int ret;
    struct prefix p;

    ret = str2prefix (argv[0], &p);

    /* Given string is:               */
    if (ret) /* an IPv4 or v6 network */
        return CMD_ERR_NO_MATCH; /* not implemented yet */
    else     /* an interface name     */
        ret = babel_enable_if_delete (argv[0]);

    if (ret < 0) {
        vty_out (vty, "can't find network %s%s", argv[0],
                 VTY_NEWLINE);
        return CMD_WARNING;
    }

    return CMD_SUCCESS;
}

/* [Interface Command] Tell the interface is wire. */
DEFUN (babel_set_wired,
       babel_set_wired_cmd,
       "wired",
       "Set this interface as wired (default: wireless).\n"
       "No attributes")
{
    struct interface *ifp;
    babel_interface_nfo *babel_ifp;

    ifp = vty->index;
    babel_ifp = babel_get_if_nfo(ifp);

    assert (babel_ifp != NULL);
    babel_ifp->flags |= BABEL_IF_WIRED;
    return CMD_SUCCESS;
}

/* [Interface Command] Tell the interface is wireless (default). */
DEFUN (babel_set_wireless,
       babel_set_wireless_cmd,
       "wireless",
       NO_STR
       "Set this interface as wireless (is default).\n"
       "No attributes")
{
    struct interface *ifp;
    babel_interface_nfo *babel_ifp;

    ifp = vty->index;
    babel_ifp = babel_get_if_nfo(ifp);

    assert (babel_ifp != NULL);
    babel_ifp->flags &= ~BABEL_IF_WIRED;
    return CMD_SUCCESS;
}

/* [Interface Command] Enable split horizon. */
DEFUN (babel_split_horizon,
       babel_split_horizon_cmd,
       "babel split-horizon",
       IPV6_STR
       "Routing Information Protocol\n"
       "Perform split horizon\n")
{
    struct interface *ifp;
    babel_interface_nfo *babel_ifp;

    ifp = vty->index;
    babel_ifp = babel_get_if_nfo(ifp);

    assert (babel_ifp != NULL);
    babel_ifp->flags |= BABEL_IF_SPLIT_HORIZON;
    return CMD_SUCCESS;
}

/* [Interface Command] Disable split horizon (default). */
DEFUN (no_babel_split_horizon,
       no_babel_split_horizon_cmd,
       "no babel split-horizon",
       NO_STR
       IPV6_STR
       "Routing Information Protocol\n"
       "Perform split horizon\n")
{
    struct interface *ifp;
    babel_interface_nfo *babel_ifp;

    ifp = vty->index;
    babel_ifp = babel_get_if_nfo(ifp);

    assert (babel_ifp != NULL);
    babel_ifp->flags &= ~BABEL_IF_SPLIT_HORIZON;
    return CMD_SUCCESS;
}

/* [Interface Command]. */
DEFUN (babel_set_hello_interval,
       babel_set_hello_interval_cmd,
       "hello interval <5-1000000>",
       "Set interface's hello interval (default: 4000).\n"
       "Value in miliseconds\n")
{
    struct interface *ifp;
    babel_interface_nfo *babel_ifp;

    int interval = atoi(argv[1]);

    ifp = vty->index;
    babel_ifp = babel_get_if_nfo(ifp);

    assert (babel_ifp != NULL);
    babel_ifp->hello_interval = interval;
    return CMD_SUCCESS;
}

/* [Interface Command]. */
DEFUN (babel_passive_interface,
       babel_passive_interface_cmd,
       "passive-interface",
       "The daemon will only announce redistributed routes\n"
       "Interface name\n")
{
    if (allow_duplicates) {
        return CMD_WARNING;
    }
    parasitic = -1;
    return CMD_SUCCESS;
}

/* [Interface Command]. */
DEFUN (no_babel_passive_interface,
       no_babel_passive_interface_cmd,
       "no passive-interface",
       NO_STR
       "The daemon will announce all (filtred) routes\n"
       "Interface name\n")
{
    parasitic = 0;
    return CMD_SUCCESS;
}


int
interface_idle(babel_interface_nfo *babel_ifp)
{
    return (idle_hello_interval > 0 &&
            babel_ifp->activity_time < babel_now.tv_sec - idle_time);
}

/* This should be no more than half the hello interval, so that hellos
   aren't sent late.  The result is in milliseconds. */
unsigned
jitter(babel_interface_nfo *babel_ifp, int urgent)
{
    unsigned interval = babel_ifp->hello_interval;
    if(urgent)
        interval = MIN(interval, 100);
    else
        interval = MIN(interval, 4000);
    return roughly(interval) / 4;
}

unsigned
update_jitter(babel_interface_nfo *babel_ifp, int urgent)
{
    unsigned interval = babel_ifp->hello_interval;
    if(urgent)
        interval = MIN(interval, 100);
    else
        interval = MIN(interval, 4000);
    return roughly(interval);
}

/* calculate babeld's specific datas of an interface (change when the interface
 change) */
static int
interface_recalculate(struct interface *ifp)
{
    babel_interface_nfo *babel_ifp = babel_get_if_nfo(ifp);
    unsigned char *tmp = NULL;
    int mtu, rc;
    struct ipv6_mreq mreq;

    mtu = MIN(ifp->mtu, ifp->mtu6);

    /* We need to be able to fit at least two messages into a packet,
     so MTUs below 116 require lower layer fragmentation. */
    /* In IPv6, the minimum MTU is 1280, and every host must be able
     to reassemble up to 1500 bytes, but I'd rather not rely on this. */
    if(mtu < 128) {
        debugf(BABEL_DEBUG_IF, "Suspiciously low MTU %d on interface %s (%d).",
               mtu, ifp->name, ifp->ifindex);
        mtu = 128;
    }

    /* 40 for IPv6 header, 8 for UDP header, 12 for good luck. */
    babel_ifp->bufsize = mtu - sizeof(packet_header) - 60;
    tmp = babel_ifp->sendbuf;
    babel_ifp->sendbuf = realloc(babel_ifp->sendbuf, babel_ifp->bufsize);
    if(babel_ifp->sendbuf == NULL) {
        fprintf(stderr, "Couldn't reallocate sendbuf.\n");
        free(tmp);
        babel_ifp->bufsize = 0;
        return -1;
    }
    tmp = NULL;

    resize_receive_buffer(mtu);

    if(!(babel_ifp->flags & BABEL_IF_WIRED)) { /* if (wired) */
        babel_ifp->cost = 96;
        babel_ifp->flags &= ~BABEL_IF_LQ;
    } else {
        babel_ifp->cost = 256;
        babel_ifp->flags |= BABEL_IF_LQ;
    }

    babel_ifp->activity_time = babel_now.tv_sec;
    /* Since the interface was marked as active above, the
     idle_hello_interval cannot be the one being used here. */
    babel_ifp->update_interval = babel_ifp->hello_interval * 4;

    memset(&mreq, 0, sizeof(mreq));
    memcpy(&mreq.ipv6mr_multiaddr, protocol_group, 16);
    mreq.ipv6mr_interface = ifp->ifindex;

    rc = setsockopt(protocol_socket, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                    (char*)&mreq, sizeof(mreq));
    if(rc < 0) {
        zlog_err("setsockopt(IPV6_JOIN_GROUP) on interface '%s': %s",
                 ifp->name, safe_strerror(errno));
        /* This is probably due to a missing link-local address,
         so down this interface, and wait until the main loop
         tries to up it again. */
        interface_reset(ifp);
        return -1;
    }

    set_timeout(&babel_ifp->hello_timeout, babel_ifp->hello_interval);
    set_timeout(&babel_ifp->update_timeout, babel_ifp->update_interval);
    send_hello(ifp);
    send_request(ifp, NULL, 0);

    update_interface_metric(ifp);

    debugf(BABEL_DEBUG_COMMON,
           "Upped network %s (%s, cost=%d%s).",
           ifp->name,
           (babel_ifp->flags & BABEL_IF_WIRED) ? "wired" : "wireless",
           babel_ifp->cost,
           babel_ifp->ipv4 ? ", IPv4" : "");

    if(rc > 0)
        send_update(ifp, 0, NULL, 0);

    /* Check and set if interface is enable. */
    if (babel_enable_if_lookup(ifp->name) >= 0) {
        babel_ifp->flags |= BABEL_IF_IS_ENABLE;
    } else {
        babel_ifp->flags &= ~BABEL_IF_IS_ENABLE;
    }

    return 1;
}

/* Reset the interface as it was new: it's not removed from the interface list,
 and may be considered as a upped interface. */
static int
interface_reset(struct interface *ifp)
{
    int rc;
    struct ipv6_mreq mreq;
    babel_interface_nfo *babel_ifp = babel_get_if_nfo(ifp);

    flush_interface_routes(ifp, 0);
    babel_ifp->buffered = 0;
    babel_ifp->bufsize = 0;
    free(babel_ifp->sendbuf);
    babel_ifp->num_buffered_updates = 0;
    babel_ifp->update_bufsize = 0;
    if(babel_ifp->buffered_updates)
        free(babel_ifp->buffered_updates);
    babel_ifp->buffered_updates = NULL;
    babel_ifp->sendbuf = NULL;

    if(ifp->ifindex > 0) {
        memset(&mreq, 0, sizeof(mreq));
        memcpy(&mreq.ipv6mr_multiaddr, protocol_group, 16);
        mreq.ipv6mr_interface = ifp->ifindex;
        rc = setsockopt(protocol_socket, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
                        (char*)&mreq, sizeof(mreq));
        if(rc < 0)
            zlog_err("setsockopt(IPV6_LEAVE_GROUP) on interface '%s': %s",
                     ifp->name, safe_strerror(errno));
    }

    update_interface_metric(ifp);

    debugf(BABEL_DEBUG_COMMON,"Upped network %s (%s, cost=%d%s).",
           ifp->name,
           (babel_ifp->flags & BABEL_IF_WIRED) ? "wired" : "wireless",
           babel_ifp->cost,
           babel_ifp->ipv4 ? ", IPv4" : "");

    return 1;
}

/* Send retraction to all, and reset all interfaces statistics. */
void
babel_interface_close_all(void)
{
    struct interface *ifp = NULL;
    struct listnode *linklist_node = NULL;

    FOR_ALL_INTERFACES(ifp, linklist_node) {
        if(!if_up(ifp))
            continue;
        send_wildcard_retraction(ifp);
        /* Make sure that we expire quickly from our neighbours'
         association caches. */
        send_hello_noupdate(ifp, 10);
        flushbuf(ifp);
        usleep(roughly(1000));
        gettime(&babel_now);
    }
    FOR_ALL_INTERFACES(ifp, linklist_node) {
        if(!if_up(ifp))
            continue;
        /* Make sure they got it. */
        send_wildcard_retraction(ifp);
        send_hello_noupdate(ifp, 1);
        flushbuf(ifp);
        usleep(roughly(10000));
        gettime(&babel_now);
        interface_reset(ifp);
    }
}

/* return "true" if address is one of our ipv6 addresses */
int
is_interface_ll_address(struct interface *ifp, const unsigned char *address)
{
    struct connected *connected;
    struct listnode *node;

    if(!if_up(ifp))
        return 0;

    FOR_ALL_INTERFACES_ADDRESSES(ifp, connected, node) {
        if(connected->address->family == AF_INET6 &&
           memcmp(&connected->address->u.prefix6, address, 16) == 0)
            return 1;
    }

    return 0;
}


void
babel_if_init ()
{
    /* initialize interface list */
    if_init();
    if_add_hook (IF_NEW_HOOK,    babel_if_new_hook);
    if_add_hook (IF_DELETE_HOOK, babel_if_delete_hook);

    babel_enable_if = vector_init (1);

    /* install interface node and commands */
    install_element (CONFIG_NODE, &interface_cmd);
    install_element (CONFIG_NODE, &no_interface_cmd);
    install_node (&babel_interface_node, interface_config_write);
    install_default(INTERFACE_NODE);
    install_element(INTERFACE_NODE, &interface_cmd);
    install_element(INTERFACE_NODE, &no_interface_cmd);

    install_element(BABEL_NODE, &babel_network_cmd);
    install_element(BABEL_NODE, &no_babel_network_cmd);
    install_element(INTERFACE_NODE, &babel_split_horizon_cmd);
    install_element(INTERFACE_NODE, &no_babel_split_horizon_cmd);
    install_element(INTERFACE_NODE, &babel_set_wired_cmd);
    install_element(INTERFACE_NODE, &babel_set_wireless_cmd);
    install_element(INTERFACE_NODE, &babel_set_hello_interval_cmd);
    install_element(INTERFACE_NODE, &babel_passive_interface_cmd);
    install_element(INTERFACE_NODE, &no_babel_passive_interface_cmd);
}

/* hooks: functions called respectively when struct interface is
 created or deleted. */
static int
babel_if_new_hook (struct interface *ifp)
{
    ifp->info = babel_interface_allocate();
    return 0;
}

static int
babel_if_delete_hook (struct interface *ifp)
{
    babel_interface_free(ifp->info);
    ifp->info = NULL;
    return 0;
}

/* Configuration write function for babeld. */
static int
interface_config_write (struct vty *vty)
{
    struct listnode *node;
    struct interface *ifp;
    int write = 0;

    for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp)) {
        /* Do not display the interface if there is no configuration about it */
        if (ifp->desc == NULL)
            continue;

        vty_out (vty, "interface %s%s", ifp->name,
                 VTY_NEWLINE);
        if (ifp->desc)
            vty_out (vty, " description %s%s", ifp->desc,
                     VTY_NEWLINE);

        /* TODO: to be completed... */

        vty_out (vty, "!%s", VTY_NEWLINE);

        write++;
    }
    return write;
}

/* functions to allocate or free memory for a babel_interface_nfo, filling
 needed fields */
static babel_interface_nfo *
babel_interface_allocate (void)
{
    babel_interface_nfo *babel_ifp;
    babel_ifp = XMALLOC(MTYPE_BABEL_IF, sizeof(babel_interface_nfo));
    if(babel_ifp == NULL)
        return NULL;

    /* Here are set the default values for an interface. */
    memset(babel_ifp, 0, sizeof(babel_interface_nfo));
    /* All flags are unset */
    babel_ifp->activity_time = babel_now.tv_sec;
    babel_ifp->bucket_time = babel_now.tv_sec;
    babel_ifp->bucket = BUCKET_TOKENS_MAX;
    babel_ifp->hello_seqno = (random() & 0xFFFF);
    babel_ifp->hello_interval = BABELD_DEFAULT_HELLO_INTERVAL;

    return babel_ifp;
}

static void
babel_interface_free (babel_interface_nfo *babel_ifp)
{
    XFREE(MTYPE_BABEL_IF, babel_ifp);
}
