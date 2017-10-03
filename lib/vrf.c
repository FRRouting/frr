/*
 * VRF functions.
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

#include "if.h"
#include "vrf.h"
#include "vrf_int.h"
#include "prefix.h"
#include "table.h"
#include "log.h"
#include "memory.h"
#include "command.h"

DEFINE_MTYPE_STATIC(LIB, VRF, "VRF")
DEFINE_MTYPE_STATIC(LIB, VRF_BITMAP, "VRF bit-map")

DEFINE_QOBJ_TYPE(vrf)

static __inline int vrf_id_compare(const struct vrf *, const struct vrf *);
static __inline int vrf_name_compare(const struct vrf *, const struct vrf *);

RB_GENERATE(vrf_id_head, vrf, id_entry, vrf_id_compare);
RB_GENERATE(vrf_name_head, vrf, name_entry, vrf_name_compare);

struct vrf_id_head vrfs_by_id = RB_INITIALIZER(&vrfs_by_id);
struct vrf_name_head vrfs_by_name = RB_INITIALIZER(&vrfs_by_name);

/*
 * Turn on/off debug code
 * for vrf.
 */
int debug_vrf = 0;

/* Holding VRF hooks  */
struct vrf_master {
	int (*vrf_new_hook)(struct vrf *);
	int (*vrf_delete_hook)(struct vrf *);
	int (*vrf_enable_hook)(struct vrf *);
	int (*vrf_disable_hook)(struct vrf *);
} vrf_master = {
	0,
};

static int vrf_is_enabled(struct vrf *vrf);
static void vrf_disable(struct vrf *vrf);

/* VRF list existance check by name. */
struct vrf *vrf_lookup_by_name(const char *name)
{
	struct vrf vrf;
	strlcpy(vrf.name, name, sizeof(vrf.name));
	return (RB_FIND(vrf_name_head, &vrfs_by_name, &vrf));
}

static __inline int vrf_id_compare(const struct vrf *a, const struct vrf *b)
{
	return (a->vrf_id - b->vrf_id);
}

static int vrf_name_compare(const struct vrf *a, const struct vrf *b)
{
	return strcmp(a->name, b->name);
}

/* Get a VRF. If not found, create one.
 * Arg:
 *   name   - The name of the vrf.  May be NULL if unknown.
 *   vrf_id - The vrf_id of the vrf.  May be VRF_UNKNOWN if unknown
 * Description: Please note that this routine can be called with just the name
 * and 0 vrf-id
 */
struct vrf *vrf_get(vrf_id_t vrf_id, const char *name)
{
	struct vrf *vrf = NULL;
	int new = 0;

	if (debug_vrf)
		zlog_debug("VRF_GET: %s(%d)", name, vrf_id);

	/* Nothing to see, move along here */
	if (!name && vrf_id == VRF_UNKNOWN)
		return NULL;

	/* Try to find VRF both by ID and name */
	if (vrf_id != VRF_UNKNOWN)
		vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf && name)
		vrf = vrf_lookup_by_name(name);

	if (vrf == NULL) {
		vrf = XCALLOC(MTYPE_VRF, sizeof(struct vrf));
		vrf->vrf_id = VRF_UNKNOWN;
		RB_INIT(if_name_head, &vrf->ifaces_by_name);
		QOBJ_REG(vrf, vrf);
		new = 1;

		if (debug_vrf)
			zlog_debug("VRF(%u) %s is created.", vrf_id,
				   (name) ? name : "(NULL)");
	}

	/* Set identifier */
	if (vrf_id != VRF_UNKNOWN && vrf->vrf_id == VRF_UNKNOWN) {
		vrf->vrf_id = vrf_id;
		RB_INSERT(vrf_id_head, &vrfs_by_id, vrf);
	}

	/* Set name */
	if (name && vrf->name[0] != '\0' && strcmp(name, vrf->name)) {
		RB_REMOVE(vrf_name_head, &vrfs_by_name, vrf);
		strlcpy(vrf->name, name, sizeof(vrf->name));
		RB_INSERT(vrf_name_head, &vrfs_by_name, vrf);
	} else if (name && vrf->name[0] == '\0') {
		strlcpy(vrf->name, name, sizeof(vrf->name));
		RB_INSERT(vrf_name_head, &vrfs_by_name, vrf);
	}

	if (new &&vrf_master.vrf_new_hook)
		(*vrf_master.vrf_new_hook)(vrf);

	return vrf;
}

/* Delete a VRF. This is called in vrf_terminate(). */
void vrf_delete(struct vrf *vrf)
{
	if (debug_vrf)
		zlog_debug("VRF %u is to be deleted.", vrf->vrf_id);

	if (vrf_is_enabled(vrf))
		vrf_disable(vrf);

	if (vrf_master.vrf_delete_hook)
		(*vrf_master.vrf_delete_hook)(vrf);

	QOBJ_UNREG(vrf);
	if_terminate(vrf);

	if (vrf->vrf_id != VRF_UNKNOWN)
		RB_REMOVE(vrf_id_head, &vrfs_by_id, vrf);
	if (vrf->name[0] != '\0')
		RB_REMOVE(vrf_name_head, &vrfs_by_name, vrf);

	XFREE(MTYPE_VRF, vrf);
}

/* Look up a VRF by identifier. */
struct vrf *vrf_lookup_by_id(vrf_id_t vrf_id)
{
	struct vrf vrf;
	vrf.vrf_id = vrf_id;
	return (RB_FIND(vrf_id_head, &vrfs_by_id, &vrf));
}

/*
 * Check whether the VRF is enabled.
 */
static int vrf_is_enabled(struct vrf *vrf)
{
	return vrf && CHECK_FLAG(vrf->status, VRF_ACTIVE);
}

/*
 * Enable a VRF - that is, let the VRF be ready to use.
 * The VRF_ENABLE_HOOK callback will be called to inform
 * that they can allocate resources in this VRF.
 *
 * RETURN: 1 - enabled successfully; otherwise, 0.
 */
int vrf_enable(struct vrf *vrf)
{
	if (vrf_is_enabled(vrf))
		return 1;

	if (debug_vrf)
		zlog_debug("VRF %u is enabled.", vrf->vrf_id);

	SET_FLAG(vrf->status, VRF_ACTIVE);

	if (vrf_master.vrf_enable_hook)
		(*vrf_master.vrf_enable_hook)(vrf);

	return 1;
}

/*
 * Disable a VRF - that is, let the VRF be unusable.
 * The VRF_DELETE_HOOK callback will be called to inform
 * that they must release the resources in the VRF.
 */
static void vrf_disable(struct vrf *vrf)
{
	if (!vrf_is_enabled(vrf))
		return;

	UNSET_FLAG(vrf->status, VRF_ACTIVE);

	if (debug_vrf)
		zlog_debug("VRF %u is to be disabled.", vrf->vrf_id);

	/* Till now, nothing to be done for the default VRF. */
	// Pending: see why this statement.

	if (vrf_master.vrf_disable_hook)
		(*vrf_master.vrf_disable_hook)(vrf);
}

vrf_id_t vrf_name_to_id(const char *name)
{
	struct vrf *vrf;
	vrf_id_t vrf_id = VRF_DEFAULT; // Pending: need a way to return invalid
				       // id/ routine not used.

	vrf = vrf_lookup_by_name(name);
	if (vrf)
		vrf_id = vrf->vrf_id;

	return vrf_id;
}

/* Get the data pointer of the specified VRF. If not found, create one. */
void *vrf_info_get(vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_get(vrf_id, NULL);
	return vrf->info;
}

/* Look up the data pointer of the specified VRF. */
void *vrf_info_lookup(vrf_id_t vrf_id)
{
	struct vrf *vrf = vrf_lookup_by_id(vrf_id);
	return vrf ? vrf->info : NULL;
}

/*
 * VRF bit-map
 */

#define VRF_BITMAP_NUM_OF_GROUPS            8
#define VRF_BITMAP_NUM_OF_BITS_IN_GROUP (UINT16_MAX / VRF_BITMAP_NUM_OF_GROUPS)
#define VRF_BITMAP_NUM_OF_BYTES_IN_GROUP                                       \
	(VRF_BITMAP_NUM_OF_BITS_IN_GROUP / CHAR_BIT + 1) /* +1 for ensure */

#define VRF_BITMAP_GROUP(_id) ((_id) / VRF_BITMAP_NUM_OF_BITS_IN_GROUP)
#define VRF_BITMAP_BIT_OFFSET(_id) ((_id) % VRF_BITMAP_NUM_OF_BITS_IN_GROUP)

#define VRF_BITMAP_INDEX_IN_GROUP(_bit_offset) ((_bit_offset) / CHAR_BIT)
#define VRF_BITMAP_FLAG(_bit_offset) (((u_char)1) << ((_bit_offset) % CHAR_BIT))

struct vrf_bitmap {
	u_char *groups[VRF_BITMAP_NUM_OF_GROUPS];
};

vrf_bitmap_t vrf_bitmap_init(void)
{
	return (vrf_bitmap_t)XCALLOC(MTYPE_VRF_BITMAP,
				     sizeof(struct vrf_bitmap));
}

void vrf_bitmap_free(vrf_bitmap_t bmap)
{
	struct vrf_bitmap *bm = (struct vrf_bitmap *)bmap;
	int i;

	if (bmap == VRF_BITMAP_NULL)
		return;

	for (i = 0; i < VRF_BITMAP_NUM_OF_GROUPS; i++)
		if (bm->groups[i])
			XFREE(MTYPE_VRF_BITMAP, bm->groups[i]);

	XFREE(MTYPE_VRF_BITMAP, bm);
}

void vrf_bitmap_set(vrf_bitmap_t bmap, vrf_id_t vrf_id)
{
	struct vrf_bitmap *bm = (struct vrf_bitmap *)bmap;
	u_char group = VRF_BITMAP_GROUP(vrf_id);
	u_char offset = VRF_BITMAP_BIT_OFFSET(vrf_id);

	if (bmap == VRF_BITMAP_NULL || vrf_id == VRF_UNKNOWN)
		return;

	if (bm->groups[group] == NULL)
		bm->groups[group] = XCALLOC(MTYPE_VRF_BITMAP,
					    VRF_BITMAP_NUM_OF_BYTES_IN_GROUP);

	SET_FLAG(bm->groups[group][VRF_BITMAP_INDEX_IN_GROUP(offset)],
		 VRF_BITMAP_FLAG(offset));
}

void vrf_bitmap_unset(vrf_bitmap_t bmap, vrf_id_t vrf_id)
{
	struct vrf_bitmap *bm = (struct vrf_bitmap *)bmap;
	u_char group = VRF_BITMAP_GROUP(vrf_id);
	u_char offset = VRF_BITMAP_BIT_OFFSET(vrf_id);

	if (bmap == VRF_BITMAP_NULL || vrf_id == VRF_UNKNOWN
	    || bm->groups[group] == NULL)
		return;

	UNSET_FLAG(bm->groups[group][VRF_BITMAP_INDEX_IN_GROUP(offset)],
		   VRF_BITMAP_FLAG(offset));
}

int vrf_bitmap_check(vrf_bitmap_t bmap, vrf_id_t vrf_id)
{
	struct vrf_bitmap *bm = (struct vrf_bitmap *)bmap;
	u_char group = VRF_BITMAP_GROUP(vrf_id);
	u_char offset = VRF_BITMAP_BIT_OFFSET(vrf_id);

	if (bmap == VRF_BITMAP_NULL || vrf_id == VRF_UNKNOWN
	    || bm->groups[group] == NULL)
		return 0;

	return CHECK_FLAG(bm->groups[group][VRF_BITMAP_INDEX_IN_GROUP(offset)],
			  VRF_BITMAP_FLAG(offset))
		       ? 1
		       : 0;
}

static void vrf_autocomplete(vector comps, struct cmd_token *token)
{
	struct vrf *vrf = NULL;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (vrf->vrf_id != 0)
			vector_set(comps, XSTRDUP(MTYPE_COMPLETION, vrf->name));
	}
}

static const struct cmd_variable_handler vrf_var_handlers[] = {
	{
		.varname = "vrf",
		.completions = vrf_autocomplete,
	},
	{.completions = NULL},
};

/* Initialize VRF module. */
void vrf_init(int (*create)(struct vrf *), int (*enable)(struct vrf *),
	      int (*disable)(struct vrf *), int (*delete)(struct vrf *))
{
	struct vrf *default_vrf;

	if (debug_vrf)
		zlog_debug("%s: Initializing VRF subsystem",
			   __PRETTY_FUNCTION__);

	vrf_master.vrf_new_hook = create;
	vrf_master.vrf_enable_hook = enable;
	vrf_master.vrf_disable_hook = disable;
	vrf_master.vrf_delete_hook = delete;

	/* The default VRF always exists. */
	default_vrf = vrf_get(VRF_DEFAULT, VRF_DEFAULT_NAME);
	if (!default_vrf) {
		zlog_err("vrf_init: failed to create the default VRF!");
		exit(1);
	}

	/* Enable the default VRF. */
	if (!vrf_enable(default_vrf)) {
		zlog_err("vrf_init: failed to enable the default VRF!");
		exit(1);
	}

	cmd_variable_handler_register(vrf_var_handlers);
}

/* Terminate VRF module. */
void vrf_terminate(void)
{
	struct vrf *vrf;

	if (debug_vrf)
		zlog_debug("%s: Shutting down vrf subsystem",
			   __PRETTY_FUNCTION__);

	while ((vrf = RB_ROOT(vrf_id_head, &vrfs_by_id)) != NULL)
		vrf_delete(vrf);
	while ((vrf = RB_ROOT(vrf_name_head, &vrfs_by_name)) != NULL)
		vrf_delete(vrf);
}

/* Create a socket for the VRF. */
int vrf_socket(int domain, int type, int protocol, vrf_id_t vrf_id)
{
	int ret = -1;

	ret = socket(domain, type, protocol);

	return ret;
}

/* vrf CLI commands */
DEFUN_NOSH (vrf,
       vrf_cmd,
       "vrf NAME",
       "Select a VRF to configure\n"
       "VRF's name\n")
{
	int idx_name = 1;
	const char *vrfname = argv[idx_name]->arg;
	struct vrf *vrfp;

	if (strlen(vrfname) > VRF_NAMSIZ) {
		vty_out(vty,
			"%% VRF name %s is invalid: length exceeds "
			"%d characters\n",
			vrfname, VRF_NAMSIZ);
		return CMD_WARNING_CONFIG_FAILED;
	}

	vrfp = vrf_get(VRF_UNKNOWN, vrfname);

	VTY_PUSH_CONTEXT(VRF_NODE, vrfp);

	return CMD_SUCCESS;
}

DEFUN_NOSH (no_vrf,
           no_vrf_cmd,
           "no vrf NAME",
           NO_STR
           "Delete a pseudo VRF's configuration\n"
           "VRF's name\n")
{
	const char *vrfname = argv[2]->arg;

	struct vrf *vrfp;

	vrfp = vrf_lookup_by_name(vrfname);

	if (vrfp == NULL) {
		vty_out(vty, "%% VRF %s does not exist\n", vrfname);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (CHECK_FLAG(vrfp->status, VRF_ACTIVE)) {
		vty_out(vty, "%% Only inactive VRFs can be deleted\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	vrf_delete(vrfp);

	return CMD_SUCCESS;
}


struct cmd_node vrf_node = {VRF_NODE, "%s(config-vrf)# ", 1};

/*
 * Debug CLI for vrf's
 */
DEFUN (vrf_debug,
      vrf_debug_cmd,
      "debug vrf",
      DEBUG_STR
      "VRF Debugging\n")
{
	debug_vrf = 1;

	return CMD_SUCCESS;
}

DEFUN (no_vrf_debug,
      no_vrf_debug_cmd,
      "no debug vrf",
      NO_STR
      DEBUG_STR
      "VRF Debugging\n")
{
	debug_vrf = 0;

	return CMD_SUCCESS;
}

static int vrf_write_host(struct vty *vty)
{
	if (debug_vrf)
		vty_out(vty, "debug vrf\n");

	return 1;
}

static struct cmd_node vrf_debug_node = {VRF_DEBUG_NODE, "", 1};

void vrf_install_commands(void)
{
	install_node(&vrf_debug_node, vrf_write_host);

	install_element(CONFIG_NODE, &vrf_debug_cmd);
	install_element(ENABLE_NODE, &vrf_debug_cmd);
	install_element(CONFIG_NODE, &no_vrf_debug_cmd);
	install_element(ENABLE_NODE, &no_vrf_debug_cmd);
}

void vrf_cmd_init(int (*writefunc)(struct vty *vty))
{
	install_element(CONFIG_NODE, &vrf_cmd);
	install_element(CONFIG_NODE, &no_vrf_cmd);
	install_node(&vrf_node, writefunc);
	install_default(VRF_NODE);
}
