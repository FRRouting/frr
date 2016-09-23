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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <zebra.h>

#ifdef HAVE_NETNS
#undef  _GNU_SOURCE
#define _GNU_SOURCE

#include <sched.h>
#endif

#include "if.h"
#include "ns.h"
#include "prefix.h"
#include "table.h"
#include "log.h"
#include "memory.h"

#include "command.h"
#include "vty.h"

DEFINE_MTYPE_STATIC(LIB, NS,        "Logical-Router")
DEFINE_MTYPE_STATIC(LIB, NS_NAME,   "Logical-Router Name")
DEFINE_MTYPE_STATIC(LIB, NS_BITMAP, "Logical-Router bit-map")

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

#else /* !HAVE_NETNS */

#define NS_DEFAULT_NAME    "Default-logical-router"

#endif /* HAVE_NETNS */

static int have_netns(void)
{
#ifdef HAVE_NETNS
  if (have_netns_enabled < 0)
    {
        int fd = open (NS_DEFAULT_NAME, O_RDONLY);

        if (fd < 0)
          have_netns_enabled = 0;
        else
          {
            have_netns_enabled = 1;
            close(fd);
          }
    }
  return have_netns_enabled;
#else
  return 0;
#endif
}

struct ns
{
  /* Identifier, same as the vector index */
  ns_id_t ns_id;
  /* Name */
  char *name;
  /* File descriptor */
  int fd;

  /* Master list of interfaces belonging to this NS */
  struct list *iflist;

  /* User data */
  void *info;
};

/* Holding NS hooks  */
struct ns_master
{
  int (*ns_new_hook) (ns_id_t, void **);
  int (*ns_delete_hook) (ns_id_t, void **);
  int (*ns_enable_hook) (ns_id_t, void **);
  int (*ns_disable_hook) (ns_id_t, void **);
} ns_master = {0,};

/* NS table */
struct route_table *ns_table = NULL;

static int ns_is_enabled (struct ns *ns);
static int ns_enable (struct ns *ns);
static void ns_disable (struct ns *ns);


/* Build the table key */
static void
ns_build_key (ns_id_t ns_id, struct prefix *p)
{
  p->family = AF_INET;
  p->prefixlen = IPV4_MAX_BITLEN;
  p->u.prefix4.s_addr = ns_id;
}

/* Get a NS. If not found, create one. */
static struct ns *
ns_get (ns_id_t ns_id)
{
  struct prefix p;
  struct route_node *rn;
  struct ns *ns;

  ns_build_key (ns_id, &p);
  rn = route_node_get (ns_table, &p);
  if (rn->info)
    {
      ns = (struct ns *)rn->info;
      route_unlock_node (rn); /* get */
      return ns;
    }

  ns = XCALLOC (MTYPE_NS, sizeof (struct ns));
  ns->ns_id = ns_id;
  ns->fd = -1;
  rn->info = ns;

  /*
   * Initialize interfaces.
   *
   * I'm not sure if this belongs here or in
   * the vrf code.
   */
  // if_init (&ns->iflist);

  zlog_info ("NS %u is created.", ns_id);

  if (ns_master.ns_new_hook)
    (*ns_master.ns_new_hook) (ns_id, &ns->info);

  return ns;
}

/* Delete a NS. This is called in ns_terminate(). */
static void
ns_delete (struct ns *ns)
{
  zlog_info ("NS %u is to be deleted.", ns->ns_id);

  ns_disable (ns);

  if (ns_master.ns_delete_hook)
    (*ns_master.ns_delete_hook) (ns->ns_id, &ns->info);

  /*
   * I'm not entirely sure if the vrf->iflist
   * needs to be moved into here or not.
   */
  //if_terminate (&ns->iflist);

  if (ns->name)
    XFREE (MTYPE_NS_NAME, ns->name);

  XFREE (MTYPE_NS, ns);
}

/* Look up a NS by identifier. */
static struct ns *
ns_lookup (ns_id_t ns_id)
{
  struct prefix p;
  struct route_node *rn;
  struct ns *ns = NULL;

  ns_build_key (ns_id, &p);
  rn = route_node_lookup (ns_table, &p);
  if (rn)
    {
      ns = (struct ns *)rn->info;
      route_unlock_node (rn); /* lookup */
    }
  return ns;
}

/*
 * Check whether the NS is enabled - that is, whether the NS
 * is ready to allocate resources. Currently there's only one
 * type of resource: socket.
 */
static int
ns_is_enabled (struct ns *ns)
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
static int
ns_enable (struct ns *ns)
{

  if (!ns_is_enabled (ns))
    {
      if (have_netns()) {
        ns->fd = open (ns->name, O_RDONLY);
      } else {
        ns->fd = -2; /* Remember that ns_enable_hook has been called */
        errno = -ENOTSUP;
      }

      if (!ns_is_enabled (ns))
        {
          zlog_err ("Can not enable NS %u: %s!",
                    ns->ns_id, safe_strerror (errno));
          return 0;
        }

      if (have_netns())
        zlog_info ("NS %u is associated with NETNS %s.",
                   ns->ns_id, ns->name);

      zlog_info ("NS %u is enabled.", ns->ns_id);
      if (ns_master.ns_enable_hook)
        (*ns_master.ns_enable_hook) (ns->ns_id, &ns->info);
    }

  return 1;
}

/*
 * Disable a NS - that is, let the NS be unusable.
 * The NS_DELETE_HOOK callback will be called to inform
 * that they must release the resources in the NS.
 */
static void
ns_disable (struct ns *ns)
{
  if (ns_is_enabled (ns))
    {
      zlog_info ("NS %u is to be disabled.", ns->ns_id);

      if (ns_master.ns_disable_hook)
        (*ns_master.ns_disable_hook) (ns->ns_id, &ns->info);

      if (have_netns())
        close (ns->fd);

      ns->fd = -1;
    }
}


/* Add a NS hook. Please add hooks before calling ns_init(). */
void
ns_add_hook (int type, int (*func)(ns_id_t, void **))
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

/* Return the iterator of the first NS. */
ns_iter_t
ns_first (void)
{
  struct route_node *rn;

  for (rn = route_top (ns_table); rn; rn = route_next (rn))
    if (rn->info)
      {
        route_unlock_node (rn); /* top/next */
        return (ns_iter_t)rn;
      }
  return NS_ITER_INVALID;
}

/* Return the next NS iterator to the given iterator. */
ns_iter_t
ns_next (ns_iter_t iter)
{
  struct route_node *rn = NULL;

  /* Lock it first because route_next() will unlock it. */
  if (iter != NS_ITER_INVALID)
    rn = route_next (route_lock_node ((struct route_node *)iter));

  for (; rn; rn = route_next (rn))
    if (rn->info)
      {
        route_unlock_node (rn); /* next */
        return (ns_iter_t)rn;
      }
  return NS_ITER_INVALID;
}

/* Return the NS iterator of the given NS ID. If it does not exist,
 * the iterator of the next existing NS is returned. */
ns_iter_t
ns_iterator (ns_id_t ns_id)
{
  struct prefix p;
  struct route_node *rn;

  ns_build_key (ns_id, &p);
  rn = route_node_get (ns_table, &p);
  if (rn->info)
    {
      /* OK, the NS exists. */
      route_unlock_node (rn); /* get */
      return (ns_iter_t)rn;
    }

  /* Find the next NS. */
  for (rn = route_next (rn); rn; rn = route_next (rn))
    if (rn->info)
      {
        route_unlock_node (rn); /* next */
        return (ns_iter_t)rn;
      }

  return NS_ITER_INVALID;
}

/* Obtain the NS ID from the given NS iterator. */
ns_id_t
ns_iter2id (ns_iter_t iter)
{
  struct route_node *rn = (struct route_node *) iter;
  return (rn && rn->info) ? ((struct ns *)rn->info)->ns_id : NS_DEFAULT;
}

/* Obtain the data pointer from the given NS iterator. */
void *
ns_iter2info (ns_iter_t iter)
{
  struct route_node *rn = (struct route_node *) iter;
  return (rn && rn->info) ? ((struct ns *)rn->info)->info : NULL;
}

/* Obtain the interface list from the given NS iterator. */
struct list *
ns_iter2iflist (ns_iter_t iter)
{
  struct route_node *rn = (struct route_node *) iter;
  return (rn && rn->info) ? ((struct ns *)rn->info)->iflist : NULL;
}

/* Get the data pointer of the specified NS. If not found, create one. */
void *
ns_info_get (ns_id_t ns_id)
{
  struct ns *ns = ns_get (ns_id);
  return ns->info;
}

/* Look up the data pointer of the specified NS. */
void *
ns_info_lookup (ns_id_t ns_id)
{
  struct ns *ns = ns_lookup (ns_id);
  return ns ? ns->info : NULL;
}

/* Look up the interface list in a NS. */
struct list *
ns_iflist (ns_id_t ns_id)
{
   struct ns * ns = ns_lookup (ns_id);
   return ns ? ns->iflist : NULL;
}

/* Get the interface list of the specified NS. Create one if not find. */
struct list *
ns_iflist_get (ns_id_t ns_id)
{
   struct ns * ns = ns_get (ns_id);
   return ns->iflist;
}

/*
 * NS bit-map
 */

#define NS_BITMAP_NUM_OF_GROUPS            8
#define NS_BITMAP_NUM_OF_BITS_IN_GROUP \
    (UINT16_MAX / NS_BITMAP_NUM_OF_GROUPS)
#define NS_BITMAP_NUM_OF_BYTES_IN_GROUP \
    (NS_BITMAP_NUM_OF_BITS_IN_GROUP / CHAR_BIT + 1) /* +1 for ensure */

#define NS_BITMAP_GROUP(_id) \
    ((_id) / NS_BITMAP_NUM_OF_BITS_IN_GROUP)
#define NS_BITMAP_BIT_OFFSET(_id) \
    ((_id) % NS_BITMAP_NUM_OF_BITS_IN_GROUP)

#define NS_BITMAP_INDEX_IN_GROUP(_bit_offset) \
    ((_bit_offset) / CHAR_BIT)
#define NS_BITMAP_FLAG(_bit_offset) \
    (((u_char)1) << ((_bit_offset) % CHAR_BIT))

struct ns_bitmap
{
  u_char *groups[NS_BITMAP_NUM_OF_GROUPS];
};

ns_bitmap_t
ns_bitmap_init (void)
{
  return (ns_bitmap_t) XCALLOC (MTYPE_NS_BITMAP, sizeof (struct ns_bitmap));
}

void
ns_bitmap_free (ns_bitmap_t bmap)
{
  struct ns_bitmap *bm = (struct ns_bitmap *) bmap;
  int i;

  if (bmap == NS_BITMAP_NULL)
    return;

  for (i = 0; i < NS_BITMAP_NUM_OF_GROUPS; i++)
    if (bm->groups[i])
      XFREE (MTYPE_NS_BITMAP, bm->groups[i]);

  XFREE (MTYPE_NS_BITMAP, bm);
}

void
ns_bitmap_set (ns_bitmap_t bmap, ns_id_t ns_id)
{
  struct ns_bitmap *bm = (struct ns_bitmap *) bmap;
  u_char group = NS_BITMAP_GROUP (ns_id);
  u_char offset = NS_BITMAP_BIT_OFFSET (ns_id);

  if (bmap == NS_BITMAP_NULL)
    return;

  if (bm->groups[group] == NULL)
    bm->groups[group] = XCALLOC (MTYPE_NS_BITMAP,
                                 NS_BITMAP_NUM_OF_BYTES_IN_GROUP);

  SET_FLAG (bm->groups[group][NS_BITMAP_INDEX_IN_GROUP (offset)],
            NS_BITMAP_FLAG (offset));
}

void
ns_bitmap_unset (ns_bitmap_t bmap, ns_id_t ns_id)
{
  struct ns_bitmap *bm = (struct ns_bitmap *) bmap;
  u_char group = NS_BITMAP_GROUP (ns_id);
  u_char offset = NS_BITMAP_BIT_OFFSET (ns_id);

  if (bmap == NS_BITMAP_NULL || bm->groups[group] == NULL)
    return;

  UNSET_FLAG (bm->groups[group][NS_BITMAP_INDEX_IN_GROUP (offset)],
              NS_BITMAP_FLAG (offset));
}

int
ns_bitmap_check (ns_bitmap_t bmap, ns_id_t ns_id)
{
  struct ns_bitmap *bm = (struct ns_bitmap *) bmap;
  u_char group = NS_BITMAP_GROUP (ns_id);
  u_char offset = NS_BITMAP_BIT_OFFSET (ns_id);

  if (bmap == NS_BITMAP_NULL || bm->groups[group] == NULL)
    return 0;

  return CHECK_FLAG (bm->groups[group][NS_BITMAP_INDEX_IN_GROUP (offset)],
                     NS_BITMAP_FLAG (offset)) ? 1 : 0;
}

/*
 * NS realization with NETNS
 */

static char *
ns_netns_pathname (struct vty *vty, const char *name)
{
  static char pathname[PATH_MAX];
  char *result;

  if (name[0] == '/') /* absolute pathname */
    result = realpath (name, pathname);
  else /* relevant pathname */
    {
      char tmp_name[PATH_MAX];
      snprintf (tmp_name, PATH_MAX, "%s/%s", NS_RUN_DIR, name);
      result = realpath (tmp_name, pathname);
    }

  if (! result)
    {
      vty_out (vty, "Invalid pathname: %s%s", safe_strerror (errno),
               VTY_NEWLINE);
      return NULL;
    }
  return pathname;
}

DEFUN (ns_netns,
       ns_netns_cmd,
       "logical-router (1-65535) ns NAME",
       "Enable a logical-router\n"
       "Specify the logical-router indentifier\n"
       "The Name Space\n"
       "The file name in " NS_RUN_DIR ", or a full pathname\n")
{
  ns_id_t ns_id = NS_DEFAULT;
  struct ns *ns = NULL;
  char *pathname = ns_netns_pathname (vty, argv[3]->arg);

  if (!pathname)
    return CMD_WARNING;

  VTY_GET_INTEGER ("NS ID", ns_id, argv[1]->arg);
  ns = ns_get (ns_id);

  if (ns->name && strcmp (ns->name, pathname) != 0)
    {
      vty_out (vty, "NS %u is already configured with NETNS %s%s",
               ns->ns_id, ns->name, VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (!ns->name)
    ns->name = XSTRDUP (MTYPE_NS_NAME, pathname);

  if (!ns_enable (ns))
    {
      vty_out (vty, "Can not associate NS %u with NETNS %s%s",
               ns->ns_id, ns->name, VTY_NEWLINE);
      return CMD_WARNING;
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
  ns_id_t ns_id = NS_DEFAULT;
  struct ns *ns = NULL;
  char *pathname = ns_netns_pathname (vty, argv[4]->arg);

  if (!pathname)
    return CMD_WARNING;

  VTY_GET_INTEGER ("NS ID", ns_id, argv[2]->arg);
  ns = ns_lookup (ns_id);

  if (!ns)
    {
      vty_out (vty, "NS %u is not found%s", ns_id, VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  if (ns->name && strcmp (ns->name, pathname) != 0)
    {
      vty_out (vty, "Incorrect NETNS file name%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ns_disable (ns);

  if (ns->name)
    {
      XFREE (MTYPE_NS_NAME, ns->name);
      ns->name = NULL;
    }

  return CMD_SUCCESS;
}

/* NS node. */
static struct cmd_node ns_node =
{
  NS_NODE,
  "",       /* NS node has no interface. */
  1
};

/* NS configuration write function. */
static int
ns_config_write (struct vty *vty)
{
  struct route_node *rn;
  struct ns *ns;
  int write = 0;

  for (rn = route_top (ns_table); rn; rn = route_next (rn))
    if ((ns = rn->info) != NULL &&
        ns->ns_id != NS_DEFAULT && ns->name)
      {
        vty_out (vty, "logical-router %u netns %s%s", ns->ns_id, ns->name, VTY_NEWLINE);
        write++;
      }

  return write;
}

/* Initialize NS module. */
void
ns_init (void)
{
  struct ns *default_ns;

  /* Allocate NS table.  */
  ns_table = route_table_init ();

  /* The default NS always exists. */
  default_ns = ns_get (NS_DEFAULT);
  if (!default_ns)
    {
      zlog_err ("ns_init: failed to create the default NS!");
      exit (1);
    }

  /* Set the default NS name. */
  default_ns->name = XSTRDUP (MTYPE_NS_NAME, NS_DEFAULT_NAME);

  /* Enable the default NS. */
  if (!ns_enable (default_ns))
    {
      zlog_err ("ns_init: failed to enable the default NS!");
      exit (1);
    }

  if (have_netns())
    {
      /* Install NS commands. */
      install_node (&ns_node, ns_config_write);
      install_element (CONFIG_NODE, &ns_netns_cmd);
      install_element (CONFIG_NODE, &no_ns_netns_cmd);
    }
}

/* Terminate NS module. */
void
ns_terminate (void)
{
  struct route_node *rn;
  struct ns *ns;

  for (rn = route_top (ns_table); rn; rn = route_next (rn))
    if ((ns = rn->info) != NULL)
      ns_delete (ns);

  route_table_finish (ns_table);
  ns_table = NULL;
}

/* Create a socket for the NS. */
int
ns_socket (int domain, int type, int protocol, ns_id_t ns_id)
{
  struct ns *ns = ns_lookup (ns_id);
  int ret = -1;

  if (!ns_is_enabled (ns))
    {
      errno = ENOSYS;
      return -1;
    }

  if (have_netns())
    {
      ret = (ns_id != NS_DEFAULT) ? setns (ns->fd, CLONE_NEWNET) : 0;
      if (ret >= 0)
        {
          ret = socket (domain, type, protocol);
          if (ns_id != NS_DEFAULT)
            setns (ns_lookup (NS_DEFAULT)->fd, CLONE_NEWNET);
        }
    }
  else
    ret = socket (domain, type, protocol);

  return ret;
}
