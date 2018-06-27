/*
 * Zebra NS collector and notifier for Network NameSpaces
 * Copyright (C) 2017 6WIND
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#ifdef HAVE_NETLINK
#ifdef HAVE_NETNS
#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <sched.h>
#endif
#include <dirent.h>
#include <sys/inotify.h>
#include <sys/stat.h>

#include "thread.h"
#include "ns.h"
#include "command.h"
#include "memory.h"

#include "zserv.h"
#include "zebra_memory.h"
#endif /* defined(HAVE_NETLINK) */

#include "zebra_netns_notify.h"
#include "zebra_netns_id.h"

#ifdef HAVE_NETLINK

/* upon creation of folder under /var/run/netns,
 * wait that netns context is bound to
 * that folder 10 seconds
 */
#define ZEBRA_NS_POLLING_INTERVAL_MSEC     1000
#define ZEBRA_NS_POLLING_MAX_RETRIES  200

DEFINE_MTYPE_STATIC(ZEBRA, NETNS_MISC, "ZebraNetNSInfo")
static struct thread *zebra_netns_notify_current;

struct zebra_netns_info {
	const char *netnspath;
	unsigned int retries;
};

static int zebra_ns_ready_read(struct thread *t);
static void zebra_ns_notify_create_context_from_entry_name(const char *name);
static int zebra_ns_continue_read(struct zebra_netns_info *zns_info,
				  int stop_retry);
static int zebra_ns_notify_read(struct thread *t);

static void zebra_ns_notify_create_context_from_entry_name(const char *name)
{
	char *netnspath = ns_netns_pathname(NULL, name);
	struct vrf *vrf;
	int ret;
	ns_id_t ns_id, ns_id_external;

	if (netnspath == NULL)
		return;

	if (zserv_privs.change(ZPRIVS_RAISE))
		zlog_err("Can't raise privileges");
	ns_id = zebra_ns_id_get(netnspath);
	if (zserv_privs.change(ZPRIVS_LOWER))
		zlog_err("Can't lower privileges");
	ns_id_external = ns_map_nsid_with_external(ns_id, true);
	/* if VRF with NS ID already present */
	vrf = vrf_lookup_by_id((vrf_id_t)ns_id_external);
	if (vrf) {
		zlog_warn(
			"NS notify : same NSID used by VRF %s. Ignore NS %s creation",
			vrf->name, netnspath);
		return;
	}
	if (vrf_handler_create(NULL, name, &vrf) != CMD_SUCCESS) {
		zlog_warn("NS notify : failed to create VRF %s", name);
		ns_map_nsid_with_external(ns_id, false);
		return;
	}
	if (zserv_privs.change(ZPRIVS_RAISE))
		zlog_err("Can't raise privileges");
	ret = vrf_netns_handler_create(NULL, vrf, netnspath,
				       ns_id_external, ns_id);
	if (zserv_privs.change(ZPRIVS_LOWER))
		zlog_err("Can't lower privileges");
	if (ret != CMD_SUCCESS) {
		zlog_warn("NS notify : failed to create NS %s", netnspath);
		ns_map_nsid_with_external(ns_id, false);
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
	thread_add_timer_msec(zebrad.master, zebra_ns_ready_read,
			      (void *)zns_info, ZEBRA_NS_POLLING_INTERVAL_MSEC,
			      NULL);
	return 0;
}

static int zebra_ns_delete(char *name)
{
	struct vrf *vrf = vrf_lookup_by_name(name);
	struct ns *ns;

	if (!vrf) {
		zlog_warn(
			"NS notify : no VRF found using NS %s",
			name);
		return 0;
	}
	/* Clear configured flag and invoke delete. */
	UNSET_FLAG(vrf->status, VRF_CONFIGURED);
	ns = (struct ns *)vrf->ns_ctxt;
	/* the deletion order is the same
	 * as the one used when siging signal is received
	 */
	vrf_delete(vrf);
	if (ns)
		ns_delete(ns);

	zlog_info("NS notify : deleted VRF %s", name);
	return 0;
}


static int zebra_ns_ready_read(struct thread *t)
{
	struct zebra_netns_info *zns_info = THREAD_ARG(t);
	const char *netnspath;
	int err, stop_retry = 0;

	if (!zns_info)
		return 0;
	if (!zns_info->netnspath) {
		XFREE(MTYPE_NETNS_MISC, zns_info);
		return 0;
	}
	netnspath = zns_info->netnspath;
	if (--zns_info->retries == 0)
		stop_retry = 1;
	if (zserv_privs.change(ZPRIVS_RAISE))
		zlog_err("Can't raise privileges");
	err = ns_switch_to_netns(netnspath);
	if (zserv_privs.change(ZPRIVS_LOWER))
		zlog_err("Can't lower privileges");
	if (err < 0)
		return zebra_ns_continue_read(zns_info, stop_retry);

	/* go back to default ns */
	if (zserv_privs.change(ZPRIVS_RAISE))
		zlog_err("Can't raise privileges");
	err = ns_switchback_to_initial();
	if (zserv_privs.change(ZPRIVS_LOWER))
		zlog_err("Can't lower privileges");
	if (err < 0)
		return zebra_ns_continue_read(zns_info, stop_retry);

	/* success : close fd and create zns context */
	zebra_ns_notify_create_context_from_entry_name(basename(netnspath));
	return zebra_ns_continue_read(zns_info, 1);
}

static int zebra_ns_notify_read(struct thread *t)
{
	int fd_monitor = THREAD_FD(t);
	struct inotify_event *event;
	char buf[BUFSIZ];
	ssize_t len;

	zebra_netns_notify_current = thread_add_read(
		zebrad.master, zebra_ns_notify_read, NULL, fd_monitor, NULL);
	len = read(fd_monitor, buf, sizeof(buf));
	if (len < 0) {
		zlog_warn("NS notify read: failed to read (%s)",
			  safe_strerror(errno));
		return 0;
	}
	for (event = (struct inotify_event *)buf; (char *)event < &buf[len];
	     event = (struct inotify_event *)((char *)event + sizeof(*event)
					      + event->len)) {
		char *netnspath;
		struct zebra_netns_info *netnsinfo;

		if (!(event->mask & (IN_CREATE | IN_DELETE)))
			continue;
		if (event->mask & IN_DELETE)
			return zebra_ns_delete(event->name);

		if (offsetof(struct inotify_event, name) + event->len
		    >= sizeof(buf)) {
			zlog_err("NS notify read: buffer underflow");
			break;
		}

		if (strnlen(event->name, event->len) == event->len) {
			zlog_err("NS notify error: bad event name");
			break;
		}

		netnspath = ns_netns_pathname(NULL, event->name);
		if (!netnspath)
			continue;
		netnspath = XSTRDUP(MTYPE_NETNS_MISC, netnspath);
		netnsinfo = XCALLOC(MTYPE_NETNS_MISC,
				    sizeof(struct zebra_netns_info));
		netnsinfo->retries = ZEBRA_NS_POLLING_MAX_RETRIES;
		netnsinfo->netnspath = netnspath;
		thread_add_timer_msec(zebrad.master, zebra_ns_ready_read,
				      (void *)netnsinfo, 0, NULL);
	}
	return 0;
}

void zebra_ns_notify_parse(void)
{
	struct dirent *dent;
	DIR *srcdir = opendir(NS_RUN_DIR);

	if (srcdir == NULL) {
		zlog_warn("NS parsing init: failed to parse %s", NS_RUN_DIR);
		return;
	}
	while ((dent = readdir(srcdir)) != NULL) {
		struct stat st;

		if (strcmp(dent->d_name, ".") == 0
		    || strcmp(dent->d_name, "..") == 0)
			continue;
		if (fstatat(dirfd(srcdir), dent->d_name, &st, 0) < 0) {
			zlog_warn("NS parsing init: failed to parse entry %s",
				  dent->d_name);
			continue;
		}
		if (S_ISDIR(st.st_mode)) {
			zlog_warn("NS parsing init: %s is not a NS",
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

	zebra_netns_notify_current = NULL;
	fd_monitor = inotify_init();
	if (fd_monitor < 0) {
		zlog_warn("NS notify init: failed to initialize inotify (%s)",
			  safe_strerror(errno));
	}
	if (inotify_add_watch(fd_monitor, NS_RUN_DIR,
			      IN_CREATE | IN_DELETE) < 0) {
		zlog_warn("NS notify watch: failed to add watch (%s)",
			  safe_strerror(errno));
	}
	zebra_netns_notify_current = thread_add_read(
		zebrad.master, zebra_ns_notify_read, NULL, fd_monitor, NULL);
}

void zebra_ns_notify_close(void)
{
	if (zebra_netns_notify_current == NULL)
		return;

	int fd = 0;

	if (zebra_netns_notify_current->u.fd > 0)
		fd = zebra_netns_notify_current->u.fd;
	thread_cancel(zebra_netns_notify_current);
	/* auto-removal of inotify items */
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
