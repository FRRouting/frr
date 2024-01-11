// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra NS collector and notifier for Network NameSpaces
 * Copyright (C) 2017 6WIND
 */

#include <zebra.h>
#include <fcntl.h>

#ifdef HAVE_NETLINK
#ifdef HAVE_NETNS
#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <sched.h>
#endif
#include <dirent.h>
#include <sys/inotify.h>
#include <sys/stat.h>

#include "frrevent.h"
#include "ns.h"
#include "command.h"
#include "memory.h"
#include "lib_errors.h"

#include "zebra_router.h"
#endif /* defined(HAVE_NETLINK) */

#include "zebra_netns_notify.h"
#include "zebra_netns_id.h"
#include "zebra_errors.h"
#include "interface.h"

#ifdef HAVE_NETLINK

/* upon creation of folder under /var/run/netns,
 * wait that netns context is bound to
 * that folder 10 seconds
 */
#define ZEBRA_NS_POLLING_INTERVAL_MSEC     1000
#define ZEBRA_NS_POLLING_MAX_RETRIES  200

DEFINE_MTYPE_STATIC(ZEBRA, NETNS_MISC, "ZebraNetNSInfo");
static struct event *zebra_netns_notify_current;

struct zebra_netns_info {
	const char *netnspath;
	unsigned int retries;
};

static void zebra_ns_ready_read(struct event *t);
static void zebra_ns_notify_create_context_from_entry_name(const char *name);
static int zebra_ns_continue_read(struct zebra_netns_info *zns_info,
				  int stop_retry);
static void zebra_ns_notify_read(struct event *t);

static struct vrf *vrf_handler_create(struct vty *vty, const char *vrfname)
{
	if (strlen(vrfname) > VRF_NAMSIZ) {
		flog_warn(EC_LIB_VRF_LENGTH,
			  "%% VRF name %s invalid: length exceeds %d bytes",
			  vrfname, VRF_NAMSIZ);
		return NULL;
	}

	return vrf_get(VRF_UNKNOWN, vrfname);
}

static void zebra_ns_notify_create_context_from_entry_name(const char *name)
{
	char *netnspath = ns_netns_pathname(NULL, name);
	struct vrf *vrf;
	int ret;
	ns_id_t ns_id, ns_id_external, ns_id_relative = NS_UNKNOWN;
	struct ns *default_ns;

	if (netnspath == NULL)
		return;

	frr_with_privs(&zserv_privs) {
		ns_id = zebra_ns_id_get(netnspath, -1);
	}
	if (ns_id == NS_UNKNOWN)
		return;
	ns_id_external = ns_map_nsid_with_external(ns_id, true);
	/* if VRF with NS ID already present */
	vrf = vrf_lookup_by_id((vrf_id_t)ns_id_external);
	if (vrf) {
		zlog_debug(
			"NS notify : same NSID used by VRF %s. Ignore NS %s creation",
			vrf->name, netnspath);
		return;
	}
	vrf = vrf_handler_create(NULL, name);
	if (!vrf) {
		flog_warn(EC_ZEBRA_NS_VRF_CREATION_FAILED,
			  "NS notify : failed to create VRF %s", name);
		ns_map_nsid_with_external(ns_id, false);
		return;
	}

	default_ns = ns_get_default();

	/* force kernel ns_id creation in that new vrf */
	frr_with_privs(&zserv_privs) {
		ns_switch_to_netns(netnspath);
		ns_id_relative = zebra_ns_id_get(NULL, default_ns->fd);
		ns_switchback_to_initial();
	}

	frr_with_privs(&zserv_privs) {
		ret = zebra_vrf_netns_handler_create(NULL, vrf, netnspath,
						     ns_id_external, ns_id,
						     ns_id_relative);
	}
	if (ret != CMD_SUCCESS) {
		flog_warn(EC_ZEBRA_NS_VRF_CREATION_FAILED,
			  "NS notify : failed to create NS %s", netnspath);
		ns_map_nsid_with_external(ns_id, false);
		vrf_delete(vrf);
		return;
	}
	zlog_info("NS notify : created VRF %s NS %s", name, netnspath);
}

static int zebra_ns_continue_read(struct zebra_netns_info *zns_info,
				  int stop_retry)
{
	void *ns_path_ptr = (void *)zns_info->netnspath;

	if (stop_retry) {
		XFREE(MTYPE_NETNS_MISC, ns_path_ptr);
		XFREE(MTYPE_NETNS_MISC, zns_info);
		return 0;
	}
	event_add_timer_msec(zrouter.master, zebra_ns_ready_read,
			     (void *)zns_info, ZEBRA_NS_POLLING_INTERVAL_MSEC,
			     NULL);
	return 0;
}

static int zebra_ns_delete(char *name)
{
	struct vrf *vrf = vrf_lookup_by_name(name);
	struct interface *ifp, *tmp;
	struct ns *ns;

	if (!vrf) {
		flog_warn(EC_ZEBRA_NS_DELETION_FAILED_NO_VRF,
			  "NS notify : no VRF found using NS %s", name);
		return 0;
	}

	/*
	 * We don't receive interface down/delete notifications from kernel
	 * when a netns is deleted. Therefore we have to manually replicate
	 * the necessary actions here.
	 */
	RB_FOREACH_SAFE (ifp, if_name_head, &vrf->ifaces_by_name, tmp) {
		if (!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE))
			continue;

		if (if_is_no_ptm_operative(ifp)) {
			UNSET_FLAG(ifp->flags, IFF_RUNNING);
			if_down(ifp);
		}

		if (IS_ZEBRA_IF_BOND(ifp))
			zebra_l2if_update_bond(ifp, false);
		if (IS_ZEBRA_IF_BOND_SLAVE(ifp))
			zebra_l2if_update_bond_slave(ifp, IFINDEX_INTERNAL,
						     false);
		/* Special handling for bridge or VxLAN interfaces. */
		if (IS_ZEBRA_IF_BRIDGE(ifp))
			zebra_l2_bridge_del(ifp);
		else if (IS_ZEBRA_IF_VXLAN(ifp))
			zebra_l2_vxlanif_del(ifp);

		UNSET_FLAG(ifp->flags, IFF_UP);
		if_delete_update(&ifp);
	}

	ns = (struct ns *)vrf->ns_ctxt;
	/* the deletion order is the same
	 * as the one used when siging signal is received
	 */
	vrf->ns_ctxt = NULL;
	vrf_delete(vrf);
	if (ns)
		ns_delete(ns);

	zlog_info("NS notify : deleted VRF %s", name);
	return 0;
}

static int zebra_ns_notify_self_identify(struct stat *netst)
{
	char net_path[PATH_MAX];
	int netns;

	snprintf(net_path, sizeof(net_path), "/proc/self/ns/net");
	netns = open(net_path, O_RDONLY);
	if (netns < 0)
		return -1;
	if (fstat(netns, netst) < 0) {
		close(netns);
		return -1;
	}
	close(netns);
	return 0;
}

static bool zebra_ns_notify_is_default_netns(const char *name)
{
	struct stat default_netns_stat;
	struct stat st;
	char netnspath[PATH_MAX];

	if (zebra_ns_notify_self_identify(&default_netns_stat))
		return false;

	memset(&st, 0, sizeof(st));
	snprintf(netnspath, sizeof(netnspath), "%s/%s", NS_RUN_DIR, name);
	/* compare with local stat */
	if (stat(netnspath, &st) == 0 &&
	    (st.st_dev == default_netns_stat.st_dev) &&
	    (st.st_ino == default_netns_stat.st_ino))
		return true;
	return false;
}

static void zebra_ns_ready_read(struct event *t)
{
	struct zebra_netns_info *zns_info = EVENT_ARG(t);
	const char *netnspath;
	int err, stop_retry = 0;

	if (!zns_info)
		return;
	if (!zns_info->netnspath) {
		XFREE(MTYPE_NETNS_MISC, zns_info);
		return;
	}
	netnspath = zns_info->netnspath;
	if (--zns_info->retries == 0)
		stop_retry = 1;
	frr_with_privs(&zserv_privs) {
		err = ns_switch_to_netns(netnspath);
	}
	if (err < 0) {
		zebra_ns_continue_read(zns_info, stop_retry);
		return;
	}

	/* go back to default ns */
	frr_with_privs(&zserv_privs) {
		err = ns_switchback_to_initial();
	}
	if (err < 0) {
		zebra_ns_continue_read(zns_info, stop_retry);
		return;
	}

	/* check default name is not already set */
	if (strmatch(VRF_DEFAULT_NAME, basename(netnspath))) {
		zlog_warn("NS notify : NS %s is already default VRF.Cancel VRF Creation", basename(netnspath));
		zebra_ns_continue_read(zns_info, 1);
		return;
	}
	if (zebra_ns_notify_is_default_netns(basename(netnspath))) {
		zlog_warn(
			"NS notify : NS %s is default VRF. Ignore VRF creation",
			basename(netnspath));
		zebra_ns_continue_read(zns_info, 1);
		return;
	}

	/* success : close fd and create zns context */
	zebra_ns_notify_create_context_from_entry_name(basename(netnspath));
	zebra_ns_continue_read(zns_info, 1);
}

static void zebra_ns_notify_read(struct event *t)
{
	int fd_monitor = EVENT_FD(t);
	struct inotify_event *event;
	char buf[BUFSIZ];
	ssize_t len;
	char event_name[NAME_MAX + 1];

	event_add_read(zrouter.master, zebra_ns_notify_read, NULL, fd_monitor,
		       &zebra_netns_notify_current);
	len = read(fd_monitor, buf, sizeof(buf));
	if (len < 0) {
		flog_err_sys(EC_ZEBRA_NS_NOTIFY_READ,
			     "NS notify read: failed to read (%s)",
			     safe_strerror(errno));
		return;
	}
	for (event = (struct inotify_event *)buf; (char *)event < &buf[len];
	     event = (struct inotify_event *)((char *)event + sizeof(*event)
					      + event->len)) {
		char *netnspath;
		struct zebra_netns_info *netnsinfo;

		if (!(event->mask & (IN_CREATE | IN_DELETE)))
			continue;

		if (offsetof(struct inotify_event, name) + event->len
		    >= sizeof(buf)) {
			flog_err(EC_ZEBRA_NS_NOTIFY_READ,
				 "NS notify read: buffer underflow");
			break;
		}

		if (strnlen(event->name, event->len) == event->len) {
			flog_err(EC_ZEBRA_NS_NOTIFY_READ,
				 "NS notify error: bad event name");
			break;
		}

		/*
		 * Coverity Scan extra steps to satisfy `STRING_NULL` warning:
		 * - Make sure event name is present by checking `len != 0`
		 * - Event name length must be at most `NAME_MAX + 1`
		 *   (null byte inclusive)
		 * - Copy event name to a stack buffer to make sure it
		 *   includes the null byte. `event->name` includes at least
		 *   one null byte and `event->len` accounts the null bytes,
		 *   so the operation after `memcpy` will look like a
		 *   truncation to satisfy Coverity Scan null byte ending.
		 *
		 *   Example:
		 *   if `event->name` is `abc\0` and `event->len` is 4,
		 *   `memcpy` will copy the 4 bytes and then we set the
		 *   null byte again at the position 4.
		 *
		 * For more information please read inotify(7) man page.
		 */
		if (event->len == 0)
			continue;

		if (event->len > sizeof(event_name)) {
			flog_err(EC_ZEBRA_NS_NOTIFY_READ,
				 "NS notify error: unexpected big event name");
			break;
		}

		memcpy(event_name, event->name, event->len);
		event_name[event->len - 1] = 0;

		if (event->mask & IN_DELETE) {
			zebra_ns_delete(event_name);
			continue;
		}
		netnspath = ns_netns_pathname(NULL, event_name);
		if (!netnspath)
			continue;
		netnspath = XSTRDUP(MTYPE_NETNS_MISC, netnspath);
		netnsinfo = XCALLOC(MTYPE_NETNS_MISC,
				    sizeof(struct zebra_netns_info));
		netnsinfo->retries = ZEBRA_NS_POLLING_MAX_RETRIES;
		netnsinfo->netnspath = netnspath;
		event_add_timer_msec(zrouter.master, zebra_ns_ready_read,
				     (void *)netnsinfo, 0, NULL);
	}
}

void zebra_ns_notify_parse(void)
{
	struct dirent *dent;
	DIR *srcdir = opendir(NS_RUN_DIR);

	if (srcdir == NULL) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "NS parsing init: failed to parse %s", NS_RUN_DIR);
		return;
	}
	while ((dent = readdir(srcdir)) != NULL) {
		struct stat st;

		if (strcmp(dent->d_name, ".") == 0
		    || strcmp(dent->d_name, "..") == 0)
			continue;
		if (fstatat(dirfd(srcdir), dent->d_name, &st, 0) < 0) {
			flog_err_sys(
				EC_LIB_SYSTEM_CALL,
				"NS parsing init: failed to parse entry %s",
				dent->d_name);
			continue;
		}
		if (S_ISDIR(st.st_mode)) {
			zlog_debug("NS parsing init: %s is not a NS",
				   dent->d_name);
			continue;
		}
		/* check default name is not already set */
		if (strmatch(VRF_DEFAULT_NAME, basename(dent->d_name))) {
			zlog_warn("NS notify : NS %s is already default VRF.Cancel VRF Creation", dent->d_name);
			continue;
		}
		if (zebra_ns_notify_is_default_netns(dent->d_name)) {
			zlog_warn(
				"NS notify : NS %s is default VRF. Ignore VRF creation",
				dent->d_name);
			continue;
		}
		zebra_ns_notify_create_context_from_entry_name(dent->d_name);
	}
	closedir(srcdir);
}

void zebra_ns_notify_init(void)
{
	int fd_monitor;

	fd_monitor = inotify_init();
	if (fd_monitor < 0) {
		flog_err_sys(
			EC_LIB_SYSTEM_CALL,
			"NS notify init: failed to initialize inotify (%s)",
			safe_strerror(errno));
	}
	if (inotify_add_watch(fd_monitor, NS_RUN_DIR,
			      IN_CREATE | IN_DELETE) < 0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "NS notify watch: failed to add watch (%s)",
			     safe_strerror(errno));
	}
	event_add_read(zrouter.master, zebra_ns_notify_read, NULL, fd_monitor,
		       &zebra_netns_notify_current);
}

void zebra_ns_notify_close(void)
{
	if (zebra_netns_notify_current == NULL)
		return;

	int fd = 0;

	if (zebra_netns_notify_current->u.fd > 0)
		fd = zebra_netns_notify_current->u.fd;

	if (zebra_netns_notify_current->master != NULL)
		EVENT_OFF(zebra_netns_notify_current);

	/* auto-removal of notify items */
	if (fd > 0)
		close(fd);
}

#else
void zebra_ns_notify_parse(void)
{
}

void zebra_ns_notify_init(void)
{
}

void zebra_ns_notify_close(void)
{
}
#endif /* !HAVE_NETLINK */
