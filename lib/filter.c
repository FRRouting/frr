/* Route filtering function.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "prefix.h"
#include "filter.h"
#include "memory.h"
#include "command.h"
#include "sockunion.h"
#include "buffer.h"
#include "log.h"
#include "routemap.h"
#include "libfrr.h"
#include "northbound_cli.h"

DEFINE_MTYPE_STATIC(LIB, ACCESS_LIST, "Access List")
DEFINE_MTYPE_STATIC(LIB, ACCESS_LIST_STR, "Access List Str")
DEFINE_MTYPE_STATIC(LIB, ACCESS_FILTER, "Access Filter")

/* Static structure for mac access_list's master. */
static struct access_master access_master_mac = {
	{NULL, NULL},
	{NULL, NULL},
	NULL,
	NULL,
};

/* Static structure for IPv4 access_list's master. */
static struct access_master access_master_ipv4 = {
	{NULL, NULL},
	{NULL, NULL},
	NULL,
	NULL,
};

/* Static structure for IPv6 access_list's master. */
static struct access_master access_master_ipv6 = {
	{NULL, NULL},
	{NULL, NULL},
	NULL,
	NULL,
};

static struct access_master *access_master_get(afi_t afi)
{
	if (afi == AFI_IP)
		return &access_master_ipv4;
	else if (afi == AFI_IP6)
		return &access_master_ipv6;
	else if (afi == AFI_L2VPN)
		return &access_master_mac;
	return NULL;
}

/* Allocate new filter structure. */
struct filter *filter_new(void)
{
	return XCALLOC(MTYPE_ACCESS_FILTER, sizeof(struct filter));
}

static void filter_free(struct filter *filter)
{
	XFREE(MTYPE_ACCESS_FILTER, filter);
}

/* Return string of filter_type. */
static const char *filter_type_str(struct filter *filter)
{
	switch (filter->type) {
	case FILTER_PERMIT:
		return "permit";
	case FILTER_DENY:
		return "deny";
	case FILTER_DYNAMIC:
		return "dynamic";
	default:
		return "";
	}
}

/* If filter match to the prefix then return 1. */
static int filter_match_cisco(struct filter *mfilter, const struct prefix *p)
{
	struct filter_cisco *filter;
	struct in_addr mask;
	uint32_t check_addr;
	uint32_t check_mask;

	filter = &mfilter->u.cfilter;
	check_addr = p->u.prefix4.s_addr & ~filter->addr_mask.s_addr;

	if (filter->extended) {
		masklen2ip(p->prefixlen, &mask);
		check_mask = mask.s_addr & ~filter->mask_mask.s_addr;

		if (memcmp(&check_addr, &filter->addr.s_addr, 4) == 0
		    && memcmp(&check_mask, &filter->mask.s_addr, 4) == 0)
			return 1;
	} else if (memcmp(&check_addr, &filter->addr.s_addr, 4) == 0)
		return 1;

	return 0;
}

/* If filter match to the prefix then return 1. */
static int filter_match_zebra(struct filter *mfilter, const struct prefix *p)
{
	struct filter_zebra *filter = NULL;

	filter = &mfilter->u.zfilter;

	if (filter->prefix.family == p->family) {
		if (filter->exact) {
			if (filter->prefix.prefixlen == p->prefixlen)
				return prefix_match(&filter->prefix, p);
			else
				return 0;
		} else
			return prefix_match(&filter->prefix, p);
	} else
		return 0;
}

/* Allocate new access list structure. */
static struct access_list *access_list_new(void)
{
	return XCALLOC(MTYPE_ACCESS_LIST, sizeof(struct access_list));
}

/* Free allocated access_list. */
static void access_list_free(struct access_list *access)
{
	XFREE(MTYPE_ACCESS_LIST, access);
}

/* Delete access_list from access_master and free it. */
void access_list_delete(struct access_list *access)
{
	struct filter *filter;
	struct filter *next;
	struct access_list_list *list;
	struct access_master *master;

	for (filter = access->head; filter; filter = next) {
		next = filter->next;
		filter_free(filter);
	}

	master = access->master;

	if (access->type == ACCESS_TYPE_NUMBER)
		list = &master->num;
	else
		list = &master->str;

	if (access->next)
		access->next->prev = access->prev;
	else
		list->tail = access->prev;

	if (access->prev)
		access->prev->next = access->next;
	else
		list->head = access->next;

	XFREE(MTYPE_ACCESS_LIST_STR, access->name);

	XFREE(MTYPE_TMP, access->remark);

	access_list_free(access);
}

/* Insert new access list to list of access_list.  Each acceess_list
   is sorted by the name. */
static struct access_list *access_list_insert(afi_t afi, const char *name)
{
	unsigned int i;
	long number;
	struct access_list *access;
	struct access_list *point;
	struct access_list_list *alist;
	struct access_master *master;

	master = access_master_get(afi);
	if (master == NULL)
		return NULL;

	/* Allocate new access_list and copy given name. */
	access = access_list_new();
	access->name = XSTRDUP(MTYPE_ACCESS_LIST_STR, name);
	access->master = master;

	/* If name is made by all digit character.  We treat it as
	   number. */
	for (number = 0, i = 0; i < strlen(name); i++) {
		if (isdigit((unsigned char)name[i]))
			number = (number * 10) + (name[i] - '0');
		else
			break;
	}

	/* In case of name is all digit character */
	if (i == strlen(name)) {
		access->type = ACCESS_TYPE_NUMBER;

		/* Set access_list to number list. */
		alist = &master->num;

		for (point = alist->head; point; point = point->next)
			if (atol(point->name) >= number)
				break;
	} else {
		access->type = ACCESS_TYPE_STRING;

		/* Set access_list to string list. */
		alist = &master->str;

		/* Set point to insertion point. */
		for (point = alist->head; point; point = point->next)
			if (strcmp(point->name, name) >= 0)
				break;
	}

	/* In case of this is the first element of master. */
	if (alist->head == NULL) {
		alist->head = alist->tail = access;
		return access;
	}

	/* In case of insertion is made at the tail of access_list. */
	if (point == NULL) {
		access->prev = alist->tail;
		alist->tail->next = access;
		alist->tail = access;
		return access;
	}

	/* In case of insertion is made at the head of access_list. */
	if (point == alist->head) {
		access->next = alist->head;
		alist->head->prev = access;
		alist->head = access;
		return access;
	}

	/* Insertion is made at middle of the access_list. */
	access->next = point;
	access->prev = point->prev;

	if (point->prev)
		point->prev->next = access;
	point->prev = access;

	return access;
}

/* Lookup access_list from list of access_list by name. */
struct access_list *access_list_lookup(afi_t afi, const char *name)
{
	struct access_list *access;
	struct access_master *master;

	if (name == NULL)
		return NULL;

	master = access_master_get(afi);
	if (master == NULL)
		return NULL;

	for (access = master->num.head; access; access = access->next)
		if (strcmp(access->name, name) == 0)
			return access;

	for (access = master->str.head; access; access = access->next)
		if (strcmp(access->name, name) == 0)
			return access;

	return NULL;
}

/* Get access list from list of access_list.  If there isn't matched
   access_list create new one and return it. */
struct access_list *access_list_get(afi_t afi, const char *name)
{
	struct access_list *access;

	access = access_list_lookup(afi, name);
	if (access == NULL)
		access = access_list_insert(afi, name);
	return access;
}

/* Apply access list to object (which should be struct prefix *). */
enum filter_type access_list_apply(struct access_list *access,
				   const void *object)
{
	struct filter *filter;
	const struct prefix *p = (const struct prefix *)object;

	if (access == NULL)
		return FILTER_DENY;

	for (filter = access->head; filter; filter = filter->next) {
		if (filter->cisco) {
			if (filter_match_cisco(filter, p))
				return filter->type;
		} else {
			if (filter_match_zebra(filter, p))
				return filter->type;
		}
	}

	return FILTER_DENY;
}

/* Add hook function. */
void access_list_add_hook(void (*func)(struct access_list *access))
{
	access_master_ipv4.add_hook = func;
	access_master_ipv6.add_hook = func;
	access_master_mac.add_hook = func;
}

/* Delete hook function. */
void access_list_delete_hook(void (*func)(struct access_list *access))
{
	access_master_ipv4.delete_hook = func;
	access_master_ipv6.delete_hook = func;
	access_master_mac.delete_hook = func;
}

/* Calculate new sequential number. */
int64_t filter_new_seq_get(struct access_list *access)
{
	int64_t maxseq;
	int64_t newseq;
	struct filter *filter;

	maxseq = 0;

	for (filter = access->head; filter; filter = filter->next) {
		if (maxseq < filter->seq)
			maxseq = filter->seq;
	}

	newseq = ((maxseq / 5) * 5) + 5;

	return (newseq > UINT_MAX) ? UINT_MAX : newseq;
}

/* Return access list entry which has same seq number. */
static struct filter *filter_seq_check(struct access_list *access,
						  int64_t seq)
{
	struct filter *filter;

	for (filter = access->head; filter; filter = filter->next)
		if (filter->seq == seq)
			return filter;
	return NULL;
}

/* Delete filter from specified access_list.  If there is hook
   function execute it. */
void access_list_filter_delete(struct access_list *access,
			       struct filter *filter)
{
	struct access_master *master;

	master = access->master;

	if (filter->next)
		filter->next->prev = filter->prev;
	else
		access->tail = filter->prev;

	if (filter->prev)
		filter->prev->next = filter->next;
	else
		access->head = filter->next;

	filter_free(filter);

	route_map_notify_dependencies(access->name, RMAP_EVENT_FILTER_DELETED);
	/* Run hook function. */
	if (master->delete_hook)
		(*master->delete_hook)(access);
}

/* Add new filter to the end of specified access_list. */
void access_list_filter_add(struct access_list *access,
			    struct filter *filter)
{
	struct filter *replace;
	struct filter *point;

	/* Automatic asignment of seq no. */
	if (filter->seq == -1)
		filter->seq = filter_new_seq_get(access);

	if (access->tail && filter->seq > access->tail->seq)
		point = NULL;
	else {
		/* Is there any same seq access list filter? */
		replace = filter_seq_check(access, filter->seq);
		if (replace)
			access_list_filter_delete(access, replace);

		/* Check insert point. */
		for (point = access->head; point; point = point->next)
			if (point->seq >= filter->seq)
				break;
	}

	/* In case of this is the first element of the list. */
	filter->next = point;

	if (point) {
		if (point->prev)
			point->prev->next = filter;
		else
			access->head = filter;

		filter->prev = point->prev;
		point->prev = filter;
	} else {
		if (access->tail)
			access->tail->next = filter;
		else
			access->head = filter;

		filter->prev = access->tail;
		access->tail = filter;
	}

	/* Run hook function. */
	if (access->master->add_hook)
		(*access->master->add_hook)(access);
	route_map_notify_dependencies(access->name, RMAP_EVENT_FILTER_ADDED);
}

/*
  deny    Specify packets to reject
  permit  Specify packets to forward
  dynamic ?
*/

/*
  Hostname or A.B.C.D  Address to match
  any                  Any source host
  host                 A single host address
*/

struct filter *filter_lookup_cisco(struct access_list *access,
				   struct filter *mnew)
{
	struct filter *mfilter;
	struct filter_cisco *filter;
	struct filter_cisco *new;

	new = &mnew->u.cfilter;

	for (mfilter = access->head; mfilter; mfilter = mfilter->next) {
		filter = &mfilter->u.cfilter;

		if (filter->extended) {
			if (mfilter->type == mnew->type
			    && filter->addr.s_addr == new->addr.s_addr
			    && filter->addr_mask.s_addr == new->addr_mask.s_addr
			    && filter->mask.s_addr == new->mask.s_addr
			    && filter->mask_mask.s_addr
				       == new->mask_mask.s_addr)
				return mfilter;
		} else {
			if (mfilter->type == mnew->type
			    && filter->addr.s_addr == new->addr.s_addr
			    && filter->addr_mask.s_addr
				       == new->addr_mask.s_addr)
				return mfilter;
		}
	}

	return NULL;
}

struct filter *filter_lookup_zebra(struct access_list *access,
				   struct filter *mnew)
{
	struct filter *mfilter;
	struct filter_zebra *filter;
	struct filter_zebra *new;

	new = &mnew->u.zfilter;

	for (mfilter = access->head; mfilter; mfilter = mfilter->next) {
		filter = &mfilter->u.zfilter;

		if (filter->exact == new->exact
		    && mfilter->type == mnew->type) {
			if (prefix_same(&filter->prefix, &new->prefix))
				return mfilter;
		}
	}
	return NULL;
}

static void config_write_access_zebra(struct vty *, struct filter *);
static void config_write_access_cisco(struct vty *, struct filter *);

/* show access-list command. */
static int filter_show(struct vty *vty, const char *name, afi_t afi)
{
	struct access_list *access;
	struct access_master *master;
	struct filter *mfilter;
	struct filter_cisco *filter;
	int write = 0;

	master = access_master_get(afi);
	if (master == NULL)
		return 0;

	/* Print the name of the protocol */
	vty_out(vty, "%s:\n", frr_protoname);

	for (access = master->num.head; access; access = access->next) {
		if (name && strcmp(access->name, name) != 0)
			continue;

		write = 1;

		for (mfilter = access->head; mfilter; mfilter = mfilter->next) {
			filter = &mfilter->u.cfilter;

			if (write) {
				vty_out(vty, "%s %s access list %s\n",
					mfilter->cisco ? (filter->extended
								  ? "Extended"
								  : "Standard")
						       : "Zebra",
					(afi == AFI_IP)
						? ("IP")
						: ((afi == AFI_IP6) ? ("IPv6 ")
								    : ("MAC ")),
					access->name);
				write = 0;
			}

			vty_out(vty, "    seq %" PRId64, mfilter->seq);
			vty_out(vty, " %s%s", filter_type_str(mfilter),
				mfilter->type == FILTER_DENY ? "  " : "");

			if (!mfilter->cisco)
				config_write_access_zebra(vty, mfilter);
			else if (filter->extended)
				config_write_access_cisco(vty, mfilter);
			else {
				if (filter->addr_mask.s_addr == 0xffffffff)
					vty_out(vty, " any\n");
				else {
					vty_out(vty, " %pI4",
						&filter->addr);
					if (filter->addr_mask.s_addr
					    != INADDR_ANY)
						vty_out(vty,
							", wildcard bits %pI4",
							&filter->addr_mask);
					vty_out(vty, "\n");
				}
			}
		}
	}

	for (access = master->str.head; access; access = access->next) {
		if (name && strcmp(access->name, name) != 0)
			continue;

		write = 1;

		for (mfilter = access->head; mfilter; mfilter = mfilter->next) {
			filter = &mfilter->u.cfilter;

			if (write) {
				vty_out(vty, "%s %s access list %s\n",
					mfilter->cisco ? (filter->extended
								  ? "Extended"
								  : "Standard")
						       : "Zebra",
					(afi == AFI_IP)
						? ("IP")
						: ((afi == AFI_IP6) ? ("IPv6 ")
								    : ("MAC ")),
					access->name);
				write = 0;
			}

			vty_out(vty, "    seq %" PRId64, mfilter->seq);
			vty_out(vty, " %s%s", filter_type_str(mfilter),
				mfilter->type == FILTER_DENY ? "  " : "");

			if (!mfilter->cisco)
				config_write_access_zebra(vty, mfilter);
			else if (filter->extended)
				config_write_access_cisco(vty, mfilter);
			else {
				if (filter->addr_mask.s_addr == 0xffffffff)
					vty_out(vty, " any\n");
				else {
					vty_out(vty, " %pI4",
						&filter->addr);
					if (filter->addr_mask.s_addr
					    != INADDR_ANY)
						vty_out(vty,
							", wildcard bits %pI4",
							&filter->addr_mask);
					vty_out(vty, "\n");
				}
			}
		}
	}
	return CMD_SUCCESS;
}

/* show MAC access list - this only has MAC filters for now*/
DEFUN (show_mac_access_list,
       show_mac_access_list_cmd,
       "show mac access-list",
       SHOW_STR
       "mac access lists\n"
       "List mac access lists\n")
{
	return filter_show(vty, NULL, AFI_L2VPN);
}

DEFUN (show_mac_access_list_name,
       show_mac_access_list_name_cmd,
       "show mac access-list WORD",
       SHOW_STR
       "mac access lists\n"
       "List mac access lists\n"
       "mac address\n")
{
	return filter_show(vty, argv[3]->arg, AFI_L2VPN);
}

DEFUN (show_ip_access_list,
       show_ip_access_list_cmd,
       "show ip access-list",
       SHOW_STR
       IP_STR
       "List IP access lists\n")
{
	return filter_show(vty, NULL, AFI_IP);
}

DEFUN (show_ip_access_list_name,
       show_ip_access_list_name_cmd,
       "show ip access-list <(1-99)|(100-199)|(1300-1999)|(2000-2699)|WORD>",
       SHOW_STR
       IP_STR
       "List IP access lists\n"
       "IP standard access list\n"
       "IP extended access list\n"
       "IP standard access list (expanded range)\n"
       "IP extended access list (expanded range)\n"
       "IP zebra access-list\n")
{
	int idx_acl = 3;
	return filter_show(vty, argv[idx_acl]->arg, AFI_IP);
}

DEFUN (show_ipv6_access_list,
       show_ipv6_access_list_cmd,
       "show ipv6 access-list",
       SHOW_STR
       IPV6_STR
       "List IPv6 access lists\n")
{
	return filter_show(vty, NULL, AFI_IP6);
}

DEFUN (show_ipv6_access_list_name,
       show_ipv6_access_list_name_cmd,
       "show ipv6 access-list WORD",
       SHOW_STR
       IPV6_STR
       "List IPv6 access lists\n"
       "IPv6 zebra access-list\n")
{
	int idx_word = 3;
	return filter_show(vty, argv[idx_word]->arg, AFI_IP6);
}

static void config_write_access_cisco(struct vty *vty, struct filter *mfilter)
{
	struct filter_cisco *filter;

	filter = &mfilter->u.cfilter;

	if (filter->extended) {
		vty_out(vty, " ip");
		if (filter->addr_mask.s_addr == 0xffffffff)
			vty_out(vty, " any");
		else if (filter->addr_mask.s_addr == INADDR_ANY)
			vty_out(vty, " host %pI4", &filter->addr);
		else {
			vty_out(vty, " %pI4", &filter->addr);
			vty_out(vty, " %pI4", &filter->addr_mask);
		}

		if (filter->mask_mask.s_addr == 0xffffffff)
			vty_out(vty, " any");
		else if (filter->mask_mask.s_addr == INADDR_ANY)
			vty_out(vty, " host %pI4", &filter->mask);
		else {
			vty_out(vty, " %pI4", &filter->mask);
			vty_out(vty, " %pI4", &filter->mask_mask);
		}
		vty_out(vty, "\n");
	} else {
		if (filter->addr_mask.s_addr == 0xffffffff)
			vty_out(vty, " any\n");
		else {
			vty_out(vty, " %pI4", &filter->addr);
			if (filter->addr_mask.s_addr != INADDR_ANY)
				vty_out(vty, " %pI4",
					&filter->addr_mask);
			vty_out(vty, "\n");
		}
	}
}

static void config_write_access_zebra(struct vty *vty, struct filter *mfilter)
{
	struct filter_zebra *filter;
	struct prefix *p;

	filter = &mfilter->u.zfilter;
	p = &filter->prefix;

	if (p->prefixlen == 0 && !filter->exact)
		vty_out(vty, " any");
	else if (p->family == AF_INET6 || p->family == AF_INET)
		vty_out(vty, " %pFX%s",
			p, filter->exact ? " exact-match" : "");
	else if (p->family == AF_ETHERNET) {
		if (p->prefixlen == 0)
			vty_out(vty, " any");
		else
			vty_out(vty, " %pEA", &(p->u.prefix_eth));
	}

	vty_out(vty, "\n");
}

static struct cmd_node access_mac_node = {
	.name = "MAC access list",
	.node = ACCESS_MAC_NODE,
	.prompt = "",
};

static void access_list_reset_mac(void)
{
	struct access_list *access;
	struct access_list *next;
	struct access_master *master;

	master = access_master_get(AFI_L2VPN);
	if (master == NULL)
		return;

	for (access = master->num.head; access; access = next) {
		next = access->next;
		access_list_delete(access);
	}
	for (access = master->str.head; access; access = next) {
		next = access->next;
		access_list_delete(access);
	}

	assert(master->num.head == NULL);
	assert(master->num.tail == NULL);

	assert(master->str.head == NULL);
	assert(master->str.tail == NULL);
}

/* Install vty related command. */
static void access_list_init_mac(void)
{
	install_node(&access_mac_node);

	install_element(ENABLE_NODE, &show_mac_access_list_cmd);
	install_element(ENABLE_NODE, &show_mac_access_list_name_cmd);
}

/* Access-list node. */
static int config_write_access(struct vty *vty);
static struct cmd_node access_node = {
	.name = "ipv4 access list",
	.node = ACCESS_NODE,
	.prompt = "",
	.config_write = config_write_access,
};

static int config_write_access(struct vty *vty)
{
	struct lyd_node *dnode;
	int written = 0;

	dnode = yang_dnode_get(running_config->dnode, "/frr-filter:lib");
	if (dnode) {
		nb_cli_show_dnode_cmds(vty, dnode, false);
		written = 1;
	}

	return written;
}

static void access_list_reset_ipv4(void)
{
	struct access_list *access;
	struct access_list *next;
	struct access_master *master;

	master = access_master_get(AFI_IP);
	if (master == NULL)
		return;

	for (access = master->num.head; access; access = next) {
		next = access->next;
		access_list_delete(access);
	}
	for (access = master->str.head; access; access = next) {
		next = access->next;
		access_list_delete(access);
	}

	assert(master->num.head == NULL);
	assert(master->num.tail == NULL);

	assert(master->str.head == NULL);
	assert(master->str.tail == NULL);
}

/* Install vty related command. */
static void access_list_init_ipv4(void)
{
	install_node(&access_node);

	install_element(ENABLE_NODE, &show_ip_access_list_cmd);
	install_element(ENABLE_NODE, &show_ip_access_list_name_cmd);
}

static struct cmd_node access_ipv6_node = {
	.name = "ipv6 access list",
	.node = ACCESS_IPV6_NODE,
	.prompt = "",
};

static void access_list_reset_ipv6(void)
{
	struct access_list *access;
	struct access_list *next;
	struct access_master *master;

	master = access_master_get(AFI_IP6);
	if (master == NULL)
		return;

	for (access = master->num.head; access; access = next) {
		next = access->next;
		access_list_delete(access);
	}
	for (access = master->str.head; access; access = next) {
		next = access->next;
		access_list_delete(access);
	}

	assert(master->num.head == NULL);
	assert(master->num.tail == NULL);

	assert(master->str.head == NULL);
	assert(master->str.tail == NULL);
}

static void access_list_init_ipv6(void)
{
	install_node(&access_ipv6_node);

	install_element(ENABLE_NODE, &show_ipv6_access_list_cmd);
	install_element(ENABLE_NODE, &show_ipv6_access_list_name_cmd);
}

void access_list_init(void)
{
	access_list_init_ipv4();
	access_list_init_ipv6();
	access_list_init_mac();

	filter_cli_init();
}

void access_list_reset(void)
{
	access_list_reset_ipv4();
	access_list_reset_ipv6();
	access_list_reset_mac();
}
