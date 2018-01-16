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

static __inline int ns_compare(const struct ns *, const struct ns *);
static struct ns *ns_lookup(ns_id_t);
static struct ns *ns_lookup_name(const char *);

RB_GENERATE(ns_head, ns, entry, ns_compare)

struct ns_head ns_tree = RB_INITIALIZER(&ns_tree);

static struct ns *default_ns;
static int ns_current_ns_fd;
static int ns_default_ns_fd;

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
static int ns_enable(struct ns *ns);
static void ns_disable(struct ns *ns);
static void ns_get_created(struct ns *ns);

static __inline int ns_compare(const struct ns *a, const struct ns *b)
{
	return (a->ns_id - b->ns_id);
}

static void ns_get_created(struct ns *ns)
{
	/*
	 * Initialize interfaces.
	 *
	 * I'm not sure if this belongs here or in
	 * the vrf code.
	 */
	// if_init (&ns->iflist);

	if (ns->ns_id != NS_UNKNOWN)
		zlog_info("NS %u is created.", ns->ns_id);
	else
		zlog_info("NS %s is created.", ns->name);
	if (ns_master.ns_new_hook)
		(*ns_master.ns_new_hook) (ns);
	return;
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
	ns_get_created(ns);
	return ns;
}

/* Get a NS. If not found, create one. */
static struct ns *ns_get_by_name(char *ns_name)
{
	struct ns *ns;

	ns = ns_lookup_name(ns_name);
	if (ns)
		return (ns);

	ns = XCALLOC(MTYPE_NS, sizeof(struct ns));
	ns->ns_id = NS_UNKNOWN;
	ns->name = XSTRDUP(MTYPE_NS_NAME, ns_name);
	ns->fd = -1;
	RB_INSERT(ns_head, &ns_tree, ns);

	/* ns_id not initialised */
	ns_get_created(ns);
	return ns;
}

/* Delete a NS. This is called in ns_terminate(). */
static void ns_delete(struct ns *ns)
{
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

/* Look up a NS by identifier. */
static struct ns *ns_lookup(ns_id_t ns_id)
{
	struct ns ns;
	ns.ns_id = ns_id;
	return (RB_FIND(ns_head, &ns_tree, &ns));
}

/* Look up the data pointer of the specified VRF. */
void *
ns_info_lookup(ns_id_t ns_id)
{
	struct ns *ns = ns_lookup(ns_id);

	return ns ? ns->info : NULL;
}

void ns_walk_func(int (*func)(struct ns *))
{
	struct ns *ns = NULL;

	RB_FOREACH(ns, ns_head, &ns_tree)
		func(ns);
}

const char *ns_get_name(struct ns *ns)
{
	if (!ns)
		return NULL;
	return ns->name;
}

/* Look up a NS by name */
static struct ns *ns_lookup_name(const char *name)
{
	struct ns *ns = NULL;

	RB_FOREACH(ns, ns_head, &ns_tree) {
		if (ns->name != NULL) {
			if (strcmp(name, ns->name) == 0)
				return ns;
		}
	}
	return NULL;
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
	int vrf_on = 0;

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

		/* Non default NS. leave */
		if (ns->ns_id == NS_UNKNOWN) {
			zlog_err("Can not enable NS %s %u: Invalid NSID",
				 ns->name, ns->ns_id);
			return 0;
		}
		vrf_on = vrf_update_vrf_id((vrf_id_t)ns->ns_id,
					   (struct vrf *)ns->vrf_ctxt);
		if (have_netns())
			zlog_info("NS %u is associated with NETNS %s.",
				  ns->ns_id, ns->name);

		zlog_info("NS %u is enabled.", ns->ns_id);
		/* zebra first receives NS enable event,
		 * then VRF enable event
		 */
		if (ns_master.ns_enable_hook)
			(*ns_master.ns_enable_hook)(ns);
		if (vrf_on == 1)
			vrf_enable((struct vrf *)ns->vrf_ctxt);
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
			(*ns_master.ns_disable_hook)(ns);

		if (have_netns())
			close(ns->fd);

		ns->fd = -1;
	}
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
	else /* relevant pathname */
	{
		char tmp_name[PATH_MAX];
		snprintf(tmp_name, PATH_MAX, "%s/%s", NS_RUN_DIR, name);
		result = realpath(tmp_name, pathname);
	}

	if (!result) {
		if (vty)
			vty_out(vty, "Invalid pathname: %s\n",
				safe_strerror(errno));
		else
			zlog_warn("Invalid pathname: %s",
				  safe_strerror(errno));
		return NULL;
	}
	check_base = basename(pathname);
	if (check_base != NULL && strlen(check_base) + 1 > NS_NAMSIZ) {
		if (vty)
			vty_out(vty, "NS name (%s) invalid:"
				" too long( %d needed)\n",
				check_base, NS_NAMSIZ-1);
		else
			zlog_warn("NS name (%s) invalid:"
				  " too long ( %d needed)",
				  check_base, NS_NAMSIZ-1);
		return NULL;
	}
	return pathname;
}

DEFUN_NOSH (ns_logicalrouter,
       ns_logicalrouter_cmd,
       "logical-router (1-65535) ns NAME",
       "Enable a logical-router\n"
       "Specify the logical-router indentifier\n"
       "The Name Space\n"
       "The file name in " NS_RUN_DIR ", or a full pathname\n")
{
	int idx_number = 1;
	int idx_name = 3;
	ns_id_t ns_id;
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

static struct cmd_node logicalrouter_node = {NS_NODE, "", /* NS node has no interface. */
					     1};

DEFUN (no_ns_logicalrouter,
       no_ns_logicalrouter_cmd,
       "no logical-router (1-65535) ns NAME",
       NO_STR
       "Enable a Logical-Router\n"
       "Specify the Logical-Router identifier\n"
       "The Name Space\n"
       "The file name in " NS_RUN_DIR ", or a full pathname\n")
{
	int idx_number = 2;
	int idx_name = 4;
	ns_id_t ns_id;
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

int ns_handler_create(struct vty *vty, struct vrf *vrf,
		      char *pathname, ns_id_t ns_id)
{
	struct ns *ns = NULL;

	if (!vrf)
		return CMD_WARNING_CONFIG_FAILED;
	if (vrf->vrf_id != VRF_UNKNOWN && vrf->ns_ctxt == NULL) {
		if (vty)
			vty_out(vty,
				"VRF %u is already configured with VRF %s\n",
				vrf->vrf_id, vrf->name);
		else
			zlog_warn("VRF %u is already configured with VRF %s\n",
				  vrf->vrf_id, vrf->name);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (vrf->ns_ctxt != NULL) {
		ns = (struct ns *) vrf->ns_ctxt;
		if (ns && 0 != strcmp(ns->name, pathname)) {
			if (vty)
				vty_out(vty,
					"VRF %u is already configured"
					" with NETNS %s\n",
					vrf->vrf_id, ns->name);
			else
				zlog_warn("VRF %u is already configured with NETNS %s",
					  vrf->vrf_id, ns->name);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}
	ns = ns_lookup_name(pathname);
	if (ns && ns->vrf_ctxt) {
		struct vrf *vrf2 = (struct vrf *)ns->vrf_ctxt;

		if (vrf2 == vrf)
			return CMD_SUCCESS;
		if (vty)
			vty_out(vty, "NS %s is already configured"
				" with VRF %u(%s)\n",
			    ns->name, vrf2->vrf_id, vrf2->name);
		else
			zlog_warn("NS %s is already configured with VRF %u(%s)",
				  ns->name, vrf2->vrf_id, vrf2->name);
		return CMD_WARNING_CONFIG_FAILED;
	} else if (!ns)
		ns = ns_get_by_name(pathname);

	if (ns_id != ns->ns_id) {
		RB_REMOVE(ns_head, &ns_tree, ns);
		ns->ns_id = ns_id;
		RB_INSERT(ns_head, &ns_tree, ns);
	}
	ns->vrf_ctxt = (void *)vrf;
	vrf->ns_ctxt = (void *)ns;
	/* update VRF netns NAME */
	if (vrf)
		strlcpy(vrf->data.l.netns_name, basename(pathname), NS_NAMSIZ);

	if (!ns_enable(ns)) {
		if (vty)
			vty_out(vty, "Can not associate NS %u with NETNS %s\n",
			    ns->ns_id, ns->name);
		else
			zlog_warn("Can not associate NS %u with NETNS %s",
				  ns->ns_id, ns->name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}


static int ns_logicalrouter_config_write(struct vty *vty)
{
	struct ns *ns;
	int write = 0;

	RB_FOREACH(ns, ns_head, &ns_tree) {
		if (ns->ns_id == NS_DEFAULT || ns->name == NULL)
			continue;
		vty_out(vty, "logical-router %u netns %s\n", ns->ns_id,
			ns->name);
		write = 1;
	}
	return write;
}

DEFUN_NOSH (ns_netns,
	    ns_netns_cmd,
	    "netns NAME",
	    "Attach VRF to a Namespace\n"
	    "The file name in " NS_RUN_DIR ", or a full pathname\n")
{
	int idx_name = 1;
	char *pathname = ns_netns_pathname(vty, argv[idx_name]->arg);

	VTY_DECLVAR_CONTEXT(vrf, vrf);

	if (!pathname)
		return CMD_WARNING_CONFIG_FAILED;
	return ns_handler_create(vty, vrf, pathname, NS_UNKNOWN);
}

DEFUN (no_ns_netns,
	no_ns_netns_cmd,
	"no netns [NAME]",
	NO_STR
	"Detach VRF from a Namespace\n"
	"The file name in " NS_RUN_DIR ", or a full pathname\n")
{
	struct ns *ns = NULL;

	VTY_DECLVAR_CONTEXT(vrf, vrf);

	if (!vrf_is_backend_netns()) {
		vty_out(vty, "VRF backend is not Netns. Aborting\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (!vrf->ns_ctxt) {
		vty_out(vty, "VRF %s(%u) is not configured with NetNS\n",
			vrf->name, vrf->vrf_id);
		return CMD_WARNING_CONFIG_FAILED;
	}

	ns = (struct ns *)vrf->ns_ctxt;

	ns->vrf_ctxt = NULL;
	vrf_disable(vrf);
	/* vrf ID from VRF is necessary for Zebra
	 * so that propagate to other clients is done
	 */
	RB_REMOVE(ns_head, &ns_tree, ns);
	ns->ns_id = NS_UNKNOWN;
	RB_INSERT(ns_head, &ns_tree, ns);
	ns_delete(ns);
	vrf->ns_ctxt = NULL;
	return CMD_SUCCESS;
}

void ns_init(void)
{
#ifdef HAVE_NETNS
	if (have_netns_enabled < 0) {
		ns_default_ns_fd = open(NS_DEFAULT_NAME, O_RDONLY);
		return;
	}
#endif /* HAVE_NETNS */
	ns_default_ns_fd = -1;
	default_ns = NULL;
}

/* Initialize NS module. */
void ns_init_zebra(ns_id_t default_ns_id)
{
	int fd;

	ns_init();
	default_ns = ns_get(default_ns_id);
	if (!default_ns) {
		zlog_err("ns_init: failed to create the default NS!");
		exit(1);
	}
	if (have_netns()) {
		fd = open(NS_DEFAULT_NAME, O_RDONLY);
		default_ns->fd = fd;
	}
	ns_current_ns_fd = -1;
	/* Set the default NS name. */
	default_ns->name = XSTRDUP(MTYPE_NS_NAME, NS_DEFAULT_NAME);
	zlog_info("ns_init: default NSID is %u", default_ns->ns_id);

	/* Enable the default NS. */
	if (!ns_enable(default_ns)) {
		zlog_err("ns_init: failed to enable the default NS!");
		exit(1);
	}

	if (have_netns() && !vrf_is_backend_netns()) {
		/* Install NS commands. */
		install_node(&logicalrouter_node,
			     ns_logicalrouter_config_write);
		install_element(CONFIG_NODE, &ns_logicalrouter_cmd);
		install_element(CONFIG_NODE, &no_ns_logicalrouter_cmd);
	}
}

void ns_cmd_init(void)
{
	if (have_netns() && vrf_is_backend_netns()) {
		/* Install NS commands. */
		install_element(VRF_NODE, &ns_netns_cmd);
		install_element(VRF_NODE, &no_ns_netns_cmd);
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
	fd = open(name, O_RDONLY);
	if (fd == -1) {
		errno = ENOSYS;
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
	if (ns_current_ns_fd != -1) {
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
		errno = ENOSYS;
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
	return NS_UNKNOWN;
}

