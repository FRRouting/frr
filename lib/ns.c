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

#include "if.h"
#include "ns.h"
#include "log.h"
#include "memory.h"

#include "command.h"
#include "vty.h"

DEFINE_MTYPE_STATIC(LIB, NS, "Logical-Router")
DEFINE_MTYPE_STATIC(LIB, NS_NAME, "Logical-Router Name")

static __inline int ns_compare(const struct ns *, const struct ns *);
static struct ns *ns_lookup(ns_id_t);

RB_GENERATE(ns_head, ns, entry, ns_compare)

struct ns_head ns_tree = RB_INITIALIZER(&ns_tree);

#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000 /* New network namespace (lo, device, names sockets, etc) */
#endif

#ifndef HAVE_SETNS
static inline int setns(int fd, int nstype)
{
#ifdef __NR_setns
	return syscall(__NR_setns, fd, nstype);
#else
	errno = ENOSYS;
	return -1;
#endif
}
#endif /* HAVE_SETNS */

#ifdef HAVE_NETNS

#define NS_DEFAULT_NAME    "/proc/self/ns/net"
static int have_netns_enabled = -1;

#else  /* !HAVE_NETNS */

#define NS_DEFAULT_NAME    "Default-logical-router"

#endif /* HAVE_NETNS */

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
	int (*ns_new_hook)(ns_id_t, void **);
	int (*ns_delete_hook)(ns_id_t, void **);
	int (*ns_enable_hook)(ns_id_t, void **);
	int (*ns_disable_hook)(ns_id_t, void **);
} ns_master = {
	0,
};

static int ns_is_enabled(struct ns *ns);
static int ns_enable(struct ns *ns);
static void ns_disable(struct ns *ns);

static __inline int ns_compare(const struct ns *a, const struct ns *b)
{
	return (a->ns_id - b->ns_id);
}

/* Get a NS. If not found, create one. */
static struct ns *ns_get(ns_id_t ns_id)
{
	struct ns *ns;

	ns = ns_lookup(ns_id);
	if (ns)
		return (ns);

	ns = XCALLOC(MTYPE_NS, sizeof(struct ns));
	ns->ns_id = ns_id;
	ns->fd = -1;
	RB_INSERT(ns_head, &ns_tree, ns);

	/*
	 * Initialize interfaces.
	 *
	 * I'm not sure if this belongs here or in
	 * the vrf code.
	 */
	// if_init (&ns->iflist);

	zlog_info("NS %u is created.", ns_id);

	if (ns_master.ns_new_hook)
		(*ns_master.ns_new_hook)(ns_id, &ns->info);

	return ns;
}

/* Delete a NS. This is called in ns_terminate(). */
static void ns_delete(struct ns *ns)
{
	zlog_info("NS %u is to be deleted.", ns->ns_id);

	ns_disable(ns);

	if (ns_master.ns_delete_hook)
		(*ns_master.ns_delete_hook)(ns->ns_id, &ns->info);

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

/* Look up a NS by identifier. */
static struct ns *ns_lookup(ns_id_t ns_id)
{
	struct ns ns;
	ns.ns_id = ns_id;
	return (RB_FIND(ns_head, &ns_tree, &ns));
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
 * Enable a NS - that is, let the NS be ready to use.
 * The NS_ENABLE_HOOK callback will be called to inform
 * that they can allocate resources in this NS.
 *
 * RETURN: 1 - enabled successfully; otherwise, 0.
 */
static int ns_enable(struct ns *ns)
{

	if (!ns_is_enabled(ns)) {
		if (have_netns()) {
			ns->fd = open(ns->name, O_RDONLY);
		} else {
			ns->fd = -2; /* Remember that ns_enable_hook has been
					called */
			errno = -ENOTSUP;
		}

		if (!ns_is_enabled(ns)) {
			zlog_err("Can not enable NS %u: %s!", ns->ns_id,
				 safe_strerror(errno));
			return 0;
		}

		if (have_netns())
			zlog_info("NS %u is associated with NETNS %s.",
				  ns->ns_id, ns->name);

		zlog_info("NS %u is enabled.", ns->ns_id);
		if (ns_master.ns_enable_hook)
			(*ns_master.ns_enable_hook)(ns->ns_id, &ns->info);
	}

	return 1;
}

/*
 * Disable a NS - that is, let the NS be unusable.
 * The NS_DELETE_HOOK callback will be called to inform
 * that they must release the resources in the NS.
 */
static void ns_disable(struct ns *ns)
{
	if (ns_is_enabled(ns)) {
		zlog_info("NS %u is to be disabled.", ns->ns_id);

		if (ns_master.ns_disable_hook)
			(*ns_master.ns_disable_hook)(ns->ns_id, &ns->info);

		if (have_netns())
			close(ns->fd);

		ns->fd = -1;
	}
}


/* Add a NS hook. Please add hooks before calling ns_init(). */
void ns_add_hook(int type, int (*func)(ns_id_t, void **))
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

static char *ns_netns_pathname(struct vty *vty, const char *name)
{
	static char pathname[PATH_MAX];
	char *result;

	if (name[0] == '/') /* absolute pathname */
		result = realpath(name, pathname);
	else /* relevant pathname */
	{
		char tmp_name[PATH_MAX];
		snprintf(tmp_name, PATH_MAX, "%s/%s", NS_RUN_DIR, name);
		result = realpath(tmp_name, pathname);
	}

	if (!result) {
		vty_out(vty, "Invalid pathname: %s\n", safe_strerror(errno));
		return NULL;
	}
	return pathname;
}

DEFUN_NOSH (ns_netns,
       ns_netns_cmd,
       "logical-router (1-65535) ns NAME",
       "Enable a logical-router\n"
       "Specify the logical-router indentifier\n"
       "The Name Space\n"
       "The file name in " NS_RUN_DIR ", or a full pathname\n")
{
	int idx_number = 1;
	int idx_name = 3;
	ns_id_t ns_id = NS_DEFAULT;
	struct ns *ns = NULL;
	char *pathname = ns_netns_pathname(vty, argv[idx_name]->arg);

	if (!pathname)
		return CMD_WARNING_CONFIG_FAILED;

	ns_id = strtoul(argv[idx_number]->arg, NULL, 10);
	ns = ns_get(ns_id);

	if (ns->name && strcmp(ns->name, pathname) != 0) {
		vty_out(vty, "NS %u is already configured with NETNS %s\n",
			ns->ns_id, ns->name);
		return CMD_WARNING;
	}

	if (!ns->name)
		ns->name = XSTRDUP(MTYPE_NS_NAME, pathname);

	if (!ns_enable(ns)) {
		vty_out(vty, "Can not associate NS %u with NETNS %s\n",
			ns->ns_id, ns->name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_ns_netns,
       no_ns_netns_cmd,
       "no logical-router (1-65535) ns NAME",
       NO_STR
       "Enable a Logical-Router\n"
       "Specify the Logical-Router identifier\n"
       "The Name Space\n"
       "The file name in " NS_RUN_DIR ", or a full pathname\n")
{
	int idx_number = 2;
	int idx_name = 4;
	ns_id_t ns_id = NS_DEFAULT;
	struct ns *ns = NULL;
	char *pathname = ns_netns_pathname(vty, argv[idx_name]->arg);

	if (!pathname)
		return CMD_WARNING_CONFIG_FAILED;

	ns_id = strtoul(argv[idx_number]->arg, NULL, 10);
	ns = ns_lookup(ns_id);

	if (!ns) {
		vty_out(vty, "NS %u is not found\n", ns_id);
		return CMD_SUCCESS;
	}

	if (ns->name && strcmp(ns->name, pathname) != 0) {
		vty_out(vty, "Incorrect NETNS file name\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ns_disable(ns);

	if (ns->name) {
		XFREE(MTYPE_NS_NAME, ns->name);
		ns->name = NULL;
	}

	return CMD_SUCCESS;
}

/* NS node. */
static struct cmd_node ns_node = {NS_NODE, "", /* NS node has no interface. */
				  1};

/* NS configuration write function. */
static int ns_config_write(struct vty *vty)
{
	struct ns *ns;
	int write = 0;

	RB_FOREACH (ns, ns_head, &ns_tree) {
		if (ns->ns_id == NS_DEFAULT || ns->name == NULL)
			continue;

		vty_out(vty, "logical-router %u netns %s\n", ns->ns_id,
			ns->name);
		write = 1;
	}

	return write;
}

/* Initialize NS module. */
void ns_init(void)
{
	struct ns *default_ns;

	/* The default NS always exists. */
	default_ns = ns_get(NS_DEFAULT);
	if (!default_ns) {
		zlog_err("ns_init: failed to create the default NS!");
		exit(1);
	}

	/* Set the default NS name. */
	default_ns->name = XSTRDUP(MTYPE_NS_NAME, NS_DEFAULT_NAME);

	/* Enable the default NS. */
	if (!ns_enable(default_ns)) {
		zlog_err("ns_init: failed to enable the default NS!");
		exit(1);
	}

	if (have_netns()) {
		/* Install NS commands. */
		install_node(&ns_node, ns_config_write);
		install_element(CONFIG_NODE, &ns_netns_cmd);
		install_element(CONFIG_NODE, &no_ns_netns_cmd);
	}
}

/* Terminate NS module. */
void ns_terminate(void)
{
	struct ns *ns;

	while ((ns = RB_ROOT(ns_head, &ns_tree)) != NULL)
		ns_delete(ns);
}

/* Create a socket for the NS. */
int ns_socket(int domain, int type, int protocol, ns_id_t ns_id)
{
	struct ns *ns = ns_lookup(ns_id);
	int ret = -1;

	if (!ns_is_enabled(ns)) {
		errno = ENOSYS;
		return -1;
	}

	if (have_netns()) {
		ret = (ns_id != NS_DEFAULT) ? setns(ns->fd, CLONE_NEWNET) : 0;
		if (ret >= 0) {
			ret = socket(domain, type, protocol);
			if (ns_id != NS_DEFAULT)
				setns(ns_lookup(NS_DEFAULT)->fd, CLONE_NEWNET);
		}
	} else
		ret = socket(domain, type, protocol);

	return ret;
}
