/*
 * NS functions.
 * Copyright (C) 2014 6WIND S.A.
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

#ifdef HAVE_NETNS
#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <sched.h>
#endif

/* for basename */
#include <libgen.h>

#include "if.h"
#include "ns.h"
#include "log.h"
#include "memory.h"

#include "command.h"
#include "vty.h"
#include "vrf.h"

DEFINE_MTYPE_STATIC(LIB, NS, "NetNS Context")
DEFINE_MTYPE_STATIC(LIB, NS_NAME, "NetNS Name")

/* default NS ID value used when VRF backend is not NETNS */
#define NS_DEFAULT_INTERNAL 0

static inline int ns_compare(const struct ns *ns, const struct ns *ns2);
static struct ns *ns_lookup_name_internal(const char *name);

RB_GENERATE(ns_head, ns, entry, ns_compare)

struct ns_head ns_tree = RB_INITIALIZER(&ns_tree);

static struct ns *default_ns;
static int ns_current_ns_fd;
static int ns_default_ns_fd;

static int ns_debug;

struct ns_map_nsid {
	RB_ENTRY(ns_map_nsid) id_entry;
	ns_id_t ns_id_external;
	ns_id_t ns_id;
};

static inline int ns_map_compare(const struct ns_map_nsid *a,
				   const struct ns_map_nsid *b)
{
	return (a->ns_id - b->ns_id);
}

RB_HEAD(ns_map_nsid_head, ns_map_nsid);
RB_PROTOTYPE(ns_map_nsid_head, ns_map_nsid, id_entry, ns_map_compare);
RB_GENERATE(ns_map_nsid_head, ns_map_nsid, id_entry, ns_map_compare);
struct ns_map_nsid_head ns_map_nsid_list = RB_INITIALIZER(&ns_map_nsid_list);

static ns_id_t ns_id_external_numbering;


#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
/* New network namespace (lo, device, names sockets, etc) */
#endif

#ifndef HAVE_SETNS
static inline int setns(int fd, int nstype)
{
#ifdef __NR_setns
	return syscall(__NR_setns, fd, nstype);
#else
	errno = EINVAL;
	return -1;
#endif
}
#endif /* !HAVE_SETNS */

#ifdef HAVE_NETNS
static int have_netns_enabled = -1;
#endif /* HAVE_NETNS */

/* default NS ID value used when VRF backend is not NETNS */
#define NS_DEFAULT_INTERNAL 0

static int have_netns(void)
{
#ifdef HAVE_NETNS
	if (have_netns_enabled < 0) {
		int fd = open(NS_DEFAULT_NAME, O_RDONLY);

		if (fd < 0)
			have_netns_enabled = 0;
		else {
			have_netns_enabled = 1;
			close(fd);
		}
	}
	return have_netns_enabled;
#else
	return 0;
#endif
}

/* Holding NS hooks  */
struct ns_master {
	int (*ns_new_hook)(struct ns *ns);
	int (*ns_delete_hook)(struct ns *ns);
	int (*ns_enable_hook)(struct ns *ns);
	int (*ns_disable_hook)(struct ns *ns);
} ns_master = {
	0,
};

static int ns_is_enabled(struct ns *ns);

static inline int ns_compare(const struct ns *a, const struct ns *b)
{
	return (a->ns_id - b->ns_id);
}

/* Look up a NS by identifier. */
static struct ns *ns_lookup_internal(ns_id_t ns_id)
{
	struct ns ns;

	ns.ns_id = ns_id;
	return RB_FIND(ns_head, &ns_tree, &ns);
}

/* Look up a NS by name */
static struct ns *ns_lookup_name_internal(const char *name)
{
	struct ns *ns = NULL;

	RB_FOREACH (ns, ns_head, &ns_tree) {
		if (ns->name != NULL) {
			if (strcmp(name, ns->name) == 0)
				return ns;
		}
	}
	return NULL;
}

static struct ns *ns_get_created_internal(struct ns *ns, char *name,
					  ns_id_t ns_id)
{
	int created = 0;
	/*
	 * Initialize interfaces.
	 */
	if (!ns && !name && ns_id != NS_UNKNOWN)
		ns = ns_lookup_internal(ns_id);
	if (!ns && name)
		ns = ns_lookup_name_internal(name);
	if (!ns) {
		ns = XCALLOC(MTYPE_NS, sizeof(struct ns));
		ns->ns_id = ns_id;
		if (name)
			ns->name = XSTRDUP(MTYPE_NS_NAME, name);
		ns->fd = -1;
		RB_INSERT(ns_head, &ns_tree, ns);
		created = 1;
	}
	if (ns_id != ns->ns_id) {
		RB_REMOVE(ns_head, &ns_tree, ns);
		ns->ns_id = ns_id;
		RB_INSERT(ns_head, &ns_tree, ns);
	}
	if (!created)
		return ns;
	if (ns_debug) {
		if (ns->ns_id != NS_UNKNOWN)
			zlog_info("NS %u is created.", ns->ns_id);
		else
			zlog_info("NS %s is created.", ns->name);
	}
	if (ns_master.ns_new_hook)
		(*ns_master.ns_new_hook)(ns);
	return ns;
}

/*
 * Enable a NS - that is, let the NS be ready to use.
 * The NS_ENABLE_HOOK callback will be called to inform
 * that they can allocate resources in this NS.
 *
 * RETURN: 1 - enabled successfully; otherwise, 0.
 */
static int ns_enable_internal(struct ns *ns, void (*func)(ns_id_t, void *))
{
	if (!ns_is_enabled(ns)) {
		if (have_netns()) {
			ns->fd = open(ns->name, O_RDONLY);
		} else {
			ns->fd = -2;
			/* Remember ns_enable_hook has been called */
			errno = -ENOTSUP;
		}

		if (!ns_is_enabled(ns)) {
			zlog_err("Can not enable NS %u: %s!", ns->ns_id,
				 safe_strerror(errno));
			return 0;
		}

		/* Non default NS. leave */
		if (ns->ns_id == NS_UNKNOWN) {
			zlog_err("Can not enable NS %s %u: Invalid NSID",
				 ns->name, ns->ns_id);
			return 0;
		}
		if (func)
			func(ns->ns_id, (void *)ns->vrf_ctxt);
		if (ns_debug) {
			if (have_netns())
				zlog_info("NS %u is associated with NETNS %s.",
					  ns->ns_id, ns->name);
			zlog_info("NS %u is enabled.", ns->ns_id);
		}
		/* zebra first receives NS enable event,
		 * then VRF enable event
		 */
		if (ns_master.ns_enable_hook)
			(*ns_master.ns_enable_hook)(ns);
	}

	return 1;
}

/*
 * Check whether the NS is enabled - that is, whether the NS
 * is ready to allocate resources. Currently there's only one
 * type of resource: socket.
 */
static int ns_is_enabled(struct ns *ns)
{
	if (have_netns())
		return ns && ns->fd >= 0;
	else
		return ns && ns->fd == -2 && ns->ns_id == NS_DEFAULT;
}

/*
 * Disable a NS - that is, let the NS be unusable.
 * The NS_DELETE_HOOK callback will be called to inform
 * that they must release the resources in the NS.
 */
static void ns_disable_internal(struct ns *ns)
{
	if (ns_is_enabled(ns)) {
		if (ns_debug)
			zlog_info("NS %u is to be disabled.", ns->ns_id);

		if (ns_master.ns_disable_hook)
			(*ns_master.ns_disable_hook)(ns);

		if (have_netns())
			close(ns->fd);

		ns->fd = -1;
	}
}

/* VRF list existance check by name. */
static struct ns_map_nsid *ns_map_nsid_lookup_by_nsid(ns_id_t ns_id)
{
	struct ns_map_nsid ns_map;

	ns_map.ns_id = ns_id;
	return RB_FIND(ns_map_nsid_head, &ns_map_nsid_list, &ns_map);
}

ns_id_t ns_map_nsid_with_external(ns_id_t ns_id, bool map)
{
	struct ns_map_nsid *ns_map;
	vrf_id_t ns_id_external;

	ns_map = ns_map_nsid_lookup_by_nsid(ns_id);
	if (ns_map && !map) {
		ns_id_external = ns_map->ns_id_external;
		RB_REMOVE(ns_map_nsid_head, &ns_map_nsid_list, ns_map);
		return ns_id_external;
	}
	if (ns_map)
		return ns_map->ns_id_external;
	ns_map = XCALLOC(MTYPE_NS, sizeof(struct ns_map_nsid));
	/* increase vrf_id
	 * default vrf is the first one : 0
	 */
	ns_map->ns_id_external = ns_id_external_numbering++;
	ns_map->ns_id = ns_id;
	RB_INSERT(ns_map_nsid_head, &ns_map_nsid_list, ns_map);
	return ns_map->ns_id_external;
}

struct ns *ns_get_created(struct ns *ns, char *name, ns_id_t ns_id)
{
	return ns_get_created_internal(ns, name, ns_id);
}

int ns_have_netns(void)
{
	return have_netns();
}

/* Delete a NS. This is called in ns_terminate(). */
void ns_delete(struct ns *ns)
{
	if (ns_debug)
		zlog_info("NS %u is to be deleted.", ns->ns_id);

	ns_disable(ns);

	if (ns_master.ns_delete_hook)
		(*ns_master.ns_delete_hook)(ns);

	/*
	 * I'm not entirely sure if the vrf->iflist
	 * needs to be moved into here or not.
	 */
	// if_terminate (&ns->iflist);

	RB_REMOVE(ns_head, &ns_tree, ns);
	if (ns->name)
		XFREE(MTYPE_NS_NAME, ns->name);

	XFREE(MTYPE_NS, ns);
}

/* Look up the data pointer of the specified VRF. */
void *ns_info_lookup(ns_id_t ns_id)
{
	struct ns *ns = ns_lookup_internal(ns_id);

	return ns ? ns->info : NULL;
}

/* Look up a NS by name */
struct ns *ns_lookup_name(const char *name)
{
	return ns_lookup_name_internal(name);
}

int ns_enable(struct ns *ns, void (*func)(ns_id_t, void *))
{
	return ns_enable_internal(ns, func);
}

void ns_disable(struct ns *ns)
{
	return ns_disable_internal(ns);
}

struct ns *ns_lookup(ns_id_t ns_id)
{
	return ns_lookup_internal(ns_id);
}

void ns_walk_func(int (*func)(struct ns *))
{
	struct ns *ns = NULL;

	RB_FOREACH (ns, ns_head, &ns_tree)
		func(ns);
}

const char *ns_get_name(struct ns *ns)
{
	if (!ns)
		return NULL;
	return ns->name;
}

/* Add a NS hook. Please add hooks before calling ns_init(). */
void ns_add_hook(int type, int (*func)(struct ns *))
{
	switch (type) {
	case NS_NEW_HOOK:
		ns_master.ns_new_hook = func;
		break;
	case NS_DELETE_HOOK:
		ns_master.ns_delete_hook = func;
		break;
	case NS_ENABLE_HOOK:
		ns_master.ns_enable_hook = func;
		break;
	case NS_DISABLE_HOOK:
		ns_master.ns_disable_hook = func;
		break;
	default:
		break;
	}
}

/*
 * NS realization with NETNS
 */

char *ns_netns_pathname(struct vty *vty, const char *name)
{
	static char pathname[PATH_MAX];
	char *result;
	char *check_base;

	if (name[0] == '/') /* absolute pathname */
		result = realpath(name, pathname);
	else {
		/* relevant pathname */
		char tmp_name[PATH_MAX];

		snprintf(tmp_name, PATH_MAX, "%s/%s", NS_RUN_DIR, name);
		result = realpath(tmp_name, pathname);
	}

	if (!result) {
		if (vty)
			vty_out(vty, "Invalid pathname for %s: %s\n",
				pathname,
				safe_strerror(errno));
		else
			zlog_warn("Invalid pathname for %s: %s",
				  pathname,
				  safe_strerror(errno));
		return NULL;
	}
	check_base = basename(pathname);
	if (check_base != NULL && strlen(check_base) + 1 > NS_NAMSIZ) {
		if (vty)
			vty_out(vty, "NS name (%s) invalid: too long (>%d)\n",
				check_base, NS_NAMSIZ - 1);
		else
			zlog_warn("NS name (%s) invalid: too long (>%d)",
				  check_base, NS_NAMSIZ - 1);
		return NULL;
	}
	return pathname;
}

void ns_init(void)
{
	static int ns_initialised;

	ns_debug = 0;
	/* silently return as initialisation done */
	if (ns_initialised == 1)
		return;
	errno = 0;
#ifdef HAVE_NETNS
	if (have_netns_enabled < 0) {
		ns_default_ns_fd = open(NS_DEFAULT_NAME, O_RDONLY);
		if (ns_default_ns_fd == -1)
			zlog_err("NS initialization failure %d(%s)",
				 errno, safe_strerror(errno));
	} else {
		ns_default_ns_fd = -1;
		default_ns = NULL;
	}
#else
	ns_default_ns_fd = -1;
	default_ns = NULL;
#endif /* HAVE_NETNS */
	ns_current_ns_fd = -1;
	ns_initialised = 1;
}

/* Initialize NS module. */
void ns_init_management(ns_id_t default_ns_id, ns_id_t internal_ns)
{
	int fd;

	ns_init();
	default_ns = ns_get_created_internal(NULL, NULL, default_ns_id);
	if (!default_ns) {
		zlog_err("%s: failed to create the default NS!", __func__);
		exit(1);
	}
	if (have_netns()) {
		fd = open(NS_DEFAULT_NAME, O_RDONLY);
		default_ns->fd = fd;
	}
	default_ns->internal_ns_id = internal_ns;

	/* Set the default NS name. */
	default_ns->name = XSTRDUP(MTYPE_NS_NAME, NS_DEFAULT_NAME);
	if (ns_debug)
		zlog_info("%s: default NSID is %u", __func__,
			  default_ns->ns_id);

	/* Enable the default NS. */
	if (!ns_enable(default_ns, NULL)) {
		zlog_err("%s: failed to enable the default NS!", __func__);
		exit(1);
	}
}

/* Terminate NS module. */
void ns_terminate(void)
{
	struct ns *ns;

	while (!RB_EMPTY(ns_head, &ns_tree)) {
		ns = RB_ROOT(ns_head, &ns_tree);

		ns_delete(ns);
	}
}

int ns_switch_to_netns(const char *name)
{
	int ret;
	int fd;

	if (name == NULL)
		return -1;
	if (ns_default_ns_fd == -1)
		return -1;
	fd = open(name, O_RDONLY);
	if (fd == -1) {
		errno = EINVAL;
		return -1;
	}
	ret = setns(fd, CLONE_NEWNET);
	ns_current_ns_fd = fd;
	close(fd);
	return ret;
}

/* returns 1 if switch() was not called before
 * return status of setns() otherwise
 */
int ns_switchback_to_initial(void)
{
	if (ns_current_ns_fd != -1 && ns_default_ns_fd != -1) {
		int ret;

		ret = setns(ns_default_ns_fd, CLONE_NEWNET);
		ns_current_ns_fd = -1;
		return ret;
	}
	/* silently ignore if setns() is not called */
	return 1;
}

/* Create a socket for the NS. */
int ns_socket(int domain, int type, int protocol, ns_id_t ns_id)
{
	struct ns *ns = ns_lookup(ns_id);
	int ret;

	if (!ns || !ns_is_enabled(ns)) {
		errno = EINVAL;
		return -1;
	}
	if (have_netns()) {
		ret = (ns_id != NS_DEFAULT) ? setns(ns->fd, CLONE_NEWNET) : 0;
		if (ret >= 0) {
			ret = socket(domain, type, protocol);
			if (ns_id != NS_DEFAULT) {
				setns(ns_lookup(NS_DEFAULT)->fd, CLONE_NEWNET);
				ns_current_ns_fd = ns_id;
			}
		}
	} else
		ret = socket(domain, type, protocol);

	return ret;
}

ns_id_t ns_get_default_id(void)
{
	if (default_ns)
		return default_ns->ns_id;
	return NS_DEFAULT_INTERNAL;
}
