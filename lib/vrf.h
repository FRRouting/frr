/*
 * VRF related header.
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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef _ZEBRA_VRF_H
#define _ZEBRA_VRF_H

#include "openbsd-tree.h"
#include "linklist.h"
#include "qobj.h"
#include "vty.h"

/* The default NS ID */
#define NS_DEFAULT 0

/* The default VRF ID */
#define VRF_DEFAULT 0
#define VRF_UNKNOWN UINT16_MAX
#define VRF_ALL UINT16_MAX - 1

/* Pending: May need to refine this. */
#ifndef IFLA_VRF_MAX
enum {
        IFLA_VRF_UNSPEC,
        IFLA_VRF_TABLE,
        __IFLA_VRF_MAX
};

#define IFLA_VRF_MAX (__IFLA_VRF_MAX - 1)
#endif

#define VRF_NAMSIZ      36

#define VRF_DEFAULT_NAME    "Default-IP-Routing-Table"

/*
 * The command strings
 */
#define VRF_CMD_HELP_STR    "Specify the VRF\nThe VRF name\n"
#define VRF_ALL_CMD_HELP_STR    "Specify the VRF\nAll VRFs\n"

/*
 * VRF hooks
 */

#define VRF_NEW_HOOK        0   /* a new VRF is just created */
#define VRF_DELETE_HOOK     1   /* a VRF is to be deleted */
#define VRF_ENABLE_HOOK     2   /* a VRF is ready to use */
#define VRF_DISABLE_HOOK    3   /* a VRF is to be unusable */

struct vrf
{
  RB_ENTRY(vrf) id_entry, name_entry;

  /* Identifier, same as the vector index */
  vrf_id_t vrf_id;

  /* Name */
  char name[VRF_NAMSIZ + 1];

  /* Zebra internal VRF status */
  u_char status;
#define VRF_ACTIVE     (1 << 0)

  /* Master list of interfaces belonging to this VRF */
  struct list *iflist;

  /* User data */
  void *info;

  QOBJ_FIELDS
};
RB_HEAD (vrf_id_head, vrf);
RB_PROTOTYPE (vrf_id_head, vrf, id_entry, vrf_id_compare)
RB_HEAD (vrf_name_head, vrf);
RB_PROTOTYPE (vrf_name_head, vrf, name_entry, vrf_name_compare)
DECLARE_QOBJ_TYPE(vrf)


extern struct vrf_id_head vrfs_by_id;
extern struct vrf_name_head vrfs_by_name;

/*
 * Add a specific hook to VRF module.
 * @param1: hook type
 * @param2: the callback function
 *          - param 1: the VRF ID
 *          - param 2: the address of the user data pointer (the user data
 *                     can be stored in or freed from there)
 */
extern void vrf_add_hook (int, int (*)(struct vrf *));

extern struct vrf *vrf_lookup_by_id (vrf_id_t);
extern struct vrf *vrf_lookup_by_name (const char *);
extern struct vrf *vrf_get (vrf_id_t, const char *);
extern void vrf_delete (struct vrf *);
extern int vrf_enable (struct vrf *);
extern vrf_id_t vrf_name_to_id (const char *);

#define VRF_GET_ID(V,NAME)      \
  do {                          \
      struct vrf *vrf; \
      if (!(vrf = vrf_lookup_by_name(NAME))) \
        {                                                           \
          vty_out (vty, "%% VRF %s not found%s", NAME, VTY_NEWLINE);\
          return CMD_WARNING;                                       \
        }                                               \
      if (vrf->vrf_id == VRF_UNKNOWN) \
        { \
          vty_out (vty, "%% VRF %s not active%s", NAME, VTY_NEWLINE);\
          return CMD_WARNING;                                       \
        } \
      (V) = vrf->vrf_id; \
  } while (0)

/*
 * Utilities to obtain the user data
 */

/* Get the data pointer of the specified VRF. If not found, create one. */
extern void *vrf_info_get (vrf_id_t);
/* Look up the data pointer of the specified VRF. */
extern void *vrf_info_lookup (vrf_id_t);

/*
 * Utilities to obtain the interface list
 */

/* Look up the interface list of the specified VRF. */
extern struct list *vrf_iflist (vrf_id_t);
/* Get the interface list of the specified VRF. Create one if not find. */
extern struct list *vrf_iflist_get (vrf_id_t);
/* Create the interface list for the specified VRF, if needed. */
extern void vrf_iflist_create (vrf_id_t vrf_id);
/* Free the interface list of the specified VRF. */
extern void vrf_iflist_terminate (vrf_id_t vrf_id);

/*
 * VRF bit-map: maintaining flags, one bit per VRF ID
 */

typedef void *              vrf_bitmap_t;
#define VRF_BITMAP_NULL     NULL

extern vrf_bitmap_t vrf_bitmap_init (void);
extern void vrf_bitmap_free (vrf_bitmap_t);
extern void vrf_bitmap_set (vrf_bitmap_t, vrf_id_t);
extern void vrf_bitmap_unset (vrf_bitmap_t, vrf_id_t);
extern int vrf_bitmap_check (vrf_bitmap_t, vrf_id_t);

/*
 * VRF initializer/destructor
 */
/* Please add hooks before calling vrf_init(). */
extern void vrf_init (void);
extern void vrf_terminate (void);

extern void vrf_cmd_init (int (*writefunc)(struct vty *vty));

/*
 * VRF utilities
 */

/* Create a socket serving for the given VRF */
extern int vrf_socket (int, int, int, vrf_id_t);

/*
 * VRF Debugging
 */
extern void vrf_install_commands (void);
#endif /*_ZEBRA_VRF_H*/

