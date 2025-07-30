// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DHCP gateway related functions
 * Copyright (C) 2025 VyOS Inc.
 * Kyrylo Yatsenko
 */

#include <zebra.h>

#include <sys/stat.h>
#include <time.h>

#include "lib/command.h"
#include "lib/debug.h"
#include "lib/bfd.h"

#include "static_dhcpgw.h"

DEFINE_MGROUP(STATIC_DHCPGW, "staticd-dhcp-gateway");

DEFINE_MTYPE_STATIC(STATIC_DHCPGW, STATIC_DHCPGW_NEXTHOP, "Static DHCP Gateway Nexthop");
DEFINE_MTYPE_STATIC(STATIC_DHCPGW, STATIC_DHCPGW_INTERFACE, "Static DHCP Gateway Interface");

/* Default values */
#define DHCLIENT_DEFAULT_LEASE_PATH_PREFIX "/var/run/dhclient/dhclient_"
#define DHCLIENT_DEFAULT_LEASE_PATH_SUFFIX ".lease"
#define DHCLIENT_DEFAULT_UPDATE_PERIOD_S   0L

/* Options */
static unsigned long poll_period_seconds = DHCLIENT_DEFAULT_UPDATE_PERIOD_S;
static char lease_path_prefix[MAXPATHLEN] = DHCLIENT_DEFAULT_LEASE_PATH_PREFIX;
static char lease_path_suffix[MAXPATHLEN] = DHCLIENT_DEFAULT_LEASE_PATH_SUFFIX;

/* Master event loop, used to create events */
static struct event_loop *master;


/*
 * List of nexthops to watch
 */
PREDECL_SORTLIST_UNIQ(static_dhcpgw_nexthop_list);

struct static_dhcpgw_nexthop {
	/* For linked list. */
	struct static_dhcpgw_nexthop_list_item list;

	struct static_nexthop *nh;
};

static int cmp_static_dhcpgw_nexthop(const struct static_dhcpgw_nexthop *a,
				     const struct static_dhcpgw_nexthop *b)
{
	return (int)(a->nh - b->nh);
}

DECLARE_SORTLIST_UNIQ(static_dhcpgw_nexthop_list, struct static_dhcpgw_nexthop, list,
		      cmp_static_dhcpgw_nexthop);


/*
 * List of interface lease files with cached data to watch
 */
PREDECL_SORTLIST_UNIQ(static_dhcpgw_interface_list);

struct static_dhcpgw_interface {
	/* For linked list. */
	struct static_dhcpgw_interface_list_item list;

	char ifname[IFNAMSIZ + 1];    /* Main key of item - which interface is watched */
	char lease_path[MAXPATHLEN];  /* Cached path to lease file */
	struct timespec last_st_mtim; /* Last seen modification time of lease file */
	bool last_valid;	      /* Last cached is interface valid */
	struct in_addr last_addr;     /* Last cached address for interface */
	int nh_count;		      /* Counter of nexthops that use this interface */
};

static int cmp_static_dhcpgw_interface(const struct static_dhcpgw_interface *a,
				       const struct static_dhcpgw_interface *b)
{
	return strcmp(a->ifname, b->ifname);
}

DECLARE_SORTLIST_UNIQ(static_dhcpgw_interface_list, struct static_dhcpgw_interface, list,
		      cmp_static_dhcpgw_interface);


/*
 * Basic functionality section
 */

/* List of watched nexthops */
static struct static_dhcpgw_nexthop_list_head nexthops_list_head;

/* Helper when lease path prefix or suffix updated */
static void static_dhcpgw_update_lease_path_helper(void);

/* Update all watched nexthops */
static void static_dhcpgw_update_nexthops(void);

/*
 * Updates one static_nexthop IP and nh_valid values
 *
 * Uses cached values from interfaces_list_head
 *
 * nh
 *      Nexthop to update
 *
 * install
 *      If true, make call of static_install_path to install nexthop, if any
 *      change took place
 *
 * force_update
 *      Ignore interfaces_list_head `has_updates` field - compare
 *      address/valid anyway
 */
static void static_dhcpgw_update_nexthop(struct static_nexthop *nh, bool install,
					 bool force_update);

/*
 * Dhclient specific - reads lease data from lease file
 */

/*
 * Get DHCP gateway ipv4 address by lease path
 * Reads dhclient lease file
 *
 * out_addr
 *    Parsed IP address. 0.0.0.0 if no DHCP gateway
 *
 * out_valid
 *    Is there gateway for this lease file
 *
 * leasepath
 *    Path to dhclient lease file
 */
static void get_dhcpgw_dhclient_ipv4_address(struct in_addr *out_addr, bool *out_valid,
					     const char *lease_path);

/*
 * Lease files cache functions
 *
 * Store list of static_dhcpgw_interface, one per each interface
 * that is used in any of watched nexthops.
 *
 * Each list item stores path, last modification date, last address
 * and last validness. Also it stores counter of nexthops with the interface
 * to remove item from list when there are none.
 */

/* List of interfaces */
static struct static_dhcpgw_interface_list_head interfaces_list_head;

/* Initialize interface after allocation */
static void static_dhcpgw_interface_init(struct static_dhcpgw_interface *pif,
					 struct static_nexthop *nh);
/* Update interface lease path using prefix and suffix, call static_dhcpgw_interface_update */
static void static_dhcpgw_interface_update_path(struct static_dhcpgw_interface *pif);
/* Update interface data - reread lease file if it is modified */
static void static_dhcpgw_interface_update(struct static_dhcpgw_interface *pif);
/* Helper - return interface from list by ifname as key */
static struct static_dhcpgw_interface *get_dhcpgw_interface_by_ifname(const char *ifname);
/* Create interface item if needed, increment counter */
static void static_dhcpgw_interfaces_on_add_nexthop(struct static_nexthop *nh);
/* Delete interface item if needed, decrement counter */
static void static_dhcpgw_interfaces_on_del_nexthop(struct static_nexthop *nh);


/*
 * Polling timer section
 */
struct event *dhcpgw_timer;

static void static_dhcpgw_start_timer_if_needed(void);
static void static_dhcpgw_timer_event_cb(struct event *ev);


/*
 * IMPLEMENTATION
 */

extern void static_dhcpgw_init(struct event_loop *m)
{
	master = m;
	static_dhcpgw_nexthop_list_init(&nexthops_list_head);
	static_dhcpgw_interface_list_init(&interfaces_list_head);
}

extern void static_dhcpgw_close(void)
{
	static_dhcpgw_set_poll_period_seconds(0);
	/* lists should be emptied by calls of static_dhcpgw_del_nexthop_watch for
	 * each nexthop
	 */
}

extern void static_dhcpgw_add_nexthop_watch(struct static_nexthop *nh)
{
	struct static_dhcpgw_nexthop dgnh;

	dgnh.nh = nh;
	/* Check if this nexthop is already watched */
	if (!static_dhcpgw_nexthop_list_find(&nexthops_list_head, &dgnh)) {
		struct static_dhcpgw_nexthop *p = XCALLOC(MTYPE_STATIC_DHCPGW_NEXTHOP,
							  sizeof(struct static_dhcpgw_nexthop));
		p->nh = nh;
		static_dhcpgw_nexthop_list_add(&nexthops_list_head, p);
		static_dhcpgw_interfaces_on_add_nexthop(nh);
		static_dhcpgw_update_nexthop(nh, false, true);
		static_dhcpgw_start_timer_if_needed();
	}
}

extern void static_dhcpgw_del_nexthop_watch(struct static_nexthop *nh)
{
	struct static_dhcpgw_nexthop dgnh;
	struct static_dhcpgw_nexthop *p;

	dgnh.nh = nh;
	p = static_dhcpgw_nexthop_list_find(&nexthops_list_head, &dgnh);
	if (!p)
		return;
	static_dhcpgw_nexthop_list_del(&nexthops_list_head, &dgnh);
	static_dhcpgw_interfaces_on_del_nexthop(nh);
	XFREE(MTYPE_STATIC_DHCPGW_NEXTHOP, p);
}

extern void static_dhcpgw_set_poll_period_seconds(unsigned long seconds)
{
	poll_period_seconds = seconds;

	/* If previous poll period was bigger than current and time left till
	 * event is bigger than new poll period, cancel previous event
	 * Also cancels event if poll_period_seconds == 0 with meaning that polling is disabled
	 */
	if (dhcpgw_timer && event_timer_remain_second(dhcpgw_timer) > poll_period_seconds)
		event_cancel(&dhcpgw_timer);

	static_dhcpgw_start_timer_if_needed();
}

extern void static_dhcpgw_set_lease_path_prefix(const char *prefix)
{
	strlcpy(lease_path_prefix, prefix, sizeof(lease_path_prefix));

	static_dhcpgw_update_lease_path_helper();
}

extern void static_dhcpgw_set_lease_path_suffix(const char *suffix)
{
	strlcpy(lease_path_suffix, suffix, sizeof(lease_path_suffix));

	static_dhcpgw_update_lease_path_helper();
}

extern void static_dhcpgw_update(void)
{
	static_dhcpgw_update_nexthops();
}

void static_dhcpgw_update_lease_path_helper(void)
{
	struct static_dhcpgw_interface *dgif;

	frr_each (static_dhcpgw_interface_list, &interfaces_list_head, dgif) {
		static_dhcpgw_interface_update_path(dgif);
	}
	static_dhcpgw_update();
}

static void static_dhcpgw_update_nexthops(void)
{
	struct static_dhcpgw_interface *dgif;
	struct static_dhcpgw_nexthop *dgnh;

	frr_each (static_dhcpgw_interface_list, &interfaces_list_head, dgif) {
		static_dhcpgw_interface_update(dgif);
	}

	frr_each (static_dhcpgw_nexthop_list, &nexthops_list_head, dgnh) {
		static_dhcpgw_update_nexthop(dgnh->nh, true, false);
	}
}

static void static_dhcpgw_update_nexthop(struct static_nexthop *nh, bool install, bool force_update)
{
	struct static_dhcpgw_interface dgif;
	struct static_dhcpgw_interface *pif;

	strlcpy(dgif.ifname, nh->ifname, sizeof(dgif.ifname));

	pif = get_dhcpgw_interface_by_ifname(nh->ifname);
	if (!pif) {
		zlog_warn("%s: couldn't get interface data for interface %s", __func__, nh->ifname);
		return;
	}

	if (force_update)
		static_dhcpgw_interface_update(pif);

	/* TODO some better comparison?.. */
	/* Is update needed? */
	if (nh->nh_valid == pif->last_valid && nh->addr.ipv4.s_addr == pif->last_addr.s_addr) {
		/* No */
		return;
	}

	/* Yes */
	nh->nh_valid = pif->last_valid;
	nh->addr.ipv4 = pif->last_addr;
	if (install)
		static_install_path(nh->pn);
}

static void get_dhcpgw_dhclient_ipv4_address(struct in_addr *out_addr, bool *out_valid,
					     const char *leasepath)
{
#define DHCLIENT_LEASE_NEW_ROUTERS_PREFIX "new_routers='"

	out_addr->s_addr = 0;
	*out_valid = false;

	char buf[BUFSIZ];
	char *ip = NULL;
	char *ipend = NULL;

	FILE *fp = fopen(leasepath, "r");

	if (!fp) {
		zlog_warn("%s: couldn't open lease file %s", __func__, leasepath);
		return;
	}

	while (fgets(buf, BUFSIZ, fp)) {
		/*
		 * Line format in case of available gateway IP:
		 *     new_routers='10.1.1.1'
		 * In case of no working DHCP:
		 *     new_routers=''
		 */
		if (strncmp(buf, DHCLIENT_LEASE_NEW_ROUTERS_PREFIX,
			    sizeof(DHCLIENT_LEASE_NEW_ROUTERS_PREFIX) - 1)) {
			continue;
		}


		ip = buf + sizeof(DHCLIENT_LEASE_NEW_ROUTERS_PREFIX) - 1;

		ipend = strchr(ip, '\'');
		if (!ipend)
			continue;

		*ipend = '\0';

		break;
	}
	fclose(fp);

	if (!ip) {
		zlog_warn("%s: couldn't find ip in lease file %s", __func__, leasepath);
		return;
	}

	if (strlen(ip) == 0) {
		// no lease, normal situation
		return;
	}

	if (inet_pton(AF_INET, ip, out_addr) != 1) {
		zlog_warn("%s: couldn't parse ip '%s' with inet_pton, from lease file '%s'",
			  __func__, ip, leasepath);
		return;
	}

	*out_valid = true;
}

static void static_dhcpgw_interface_init(struct static_dhcpgw_interface *pif,
					 struct static_nexthop *nh)
{
	strlcpy(pif->ifname, nh->ifname, sizeof(pif->ifname));
	static_dhcpgw_interface_update_path(pif);
	pif->nh_count = 0;
}

static void static_dhcpgw_interface_update_path(struct static_dhcpgw_interface *pif)
{
	strlcpy(pif->lease_path, lease_path_prefix, sizeof(pif->lease_path));
	strlcat(pif->lease_path, pif->ifname, sizeof(pif->lease_path));
	strlcat(pif->lease_path, lease_path_suffix, sizeof(pif->lease_path));
	pif->last_st_mtim.tv_sec = 0;
	pif->last_st_mtim.tv_nsec = 0;
	static_dhcpgw_interface_update(pif);
}

static void static_dhcpgw_interface_update(struct static_dhcpgw_interface *pif)
{
	struct stat statbuf;

	if (stat(pif->lease_path, &statbuf)) {
		zlog_warn("%s: calling stat for %s failed", __func__, pif->lease_path);
		return;
	}

	/* Compare modification time. No standard function seems to exist for this */
	if (statbuf.st_mtim.tv_sec < pif->last_st_mtim.tv_sec)
		return;
	if (statbuf.st_mtim.tv_sec == pif->last_st_mtim.tv_sec)
		if (statbuf.st_mtim.tv_nsec <= pif->last_st_mtim.tv_nsec)
			return;

	pif->last_st_mtim = statbuf.st_mtim;

	get_dhcpgw_dhclient_ipv4_address(&pif->last_addr, &pif->last_valid, pif->lease_path);
}

static struct static_dhcpgw_interface *get_dhcpgw_interface_by_ifname(const char *ifname)
{
	struct static_dhcpgw_interface dgif;

	strlcpy(dgif.ifname, ifname, sizeof(dgif.ifname));

	return static_dhcpgw_interface_list_find(&interfaces_list_head, &dgif);
}

static void static_dhcpgw_interfaces_on_add_nexthop(struct static_nexthop *nh)
{
	struct static_dhcpgw_interface *pif = get_dhcpgw_interface_by_ifname(nh->ifname);

	if (!pif) {
		pif = XCALLOC(MTYPE_STATIC_DHCPGW_INTERFACE,
			      sizeof(struct static_dhcpgw_interface));

		static_dhcpgw_interface_init(pif, nh);

		static_dhcpgw_interface_list_add(&interfaces_list_head, pif);
	}
	pif->nh_count++;
}

static void static_dhcpgw_interfaces_on_del_nexthop(struct static_nexthop *nh)
{
	struct static_dhcpgw_interface *pif = get_dhcpgw_interface_by_ifname(nh->ifname);

	if (!pif) {
		zlog_warn("%s: couldn't get interface data for interface %s", __func__, nh->ifname);
		return;
	}
	pif->nh_count--;
	if (!pif->nh_count) {
		static_dhcpgw_interface_list_del(&interfaces_list_head, pif);
		XFREE(MTYPE_STATIC_DHCPGW_INTERFACE, pif);
	}
}

static void static_dhcpgw_start_timer_if_needed(void)
{
	if (poll_period_seconds && !dhcpgw_timer &&
	    static_dhcpgw_nexthop_list_first(&nexthops_list_head)) {
		event_add_timer(master, static_dhcpgw_timer_event_cb, NULL, poll_period_seconds,
				&dhcpgw_timer);
	}
}

static void static_dhcpgw_timer_event_cb(struct event *ev)
{
	static_dhcpgw_update_nexthops();
	static_dhcpgw_start_timer_if_needed();
}
