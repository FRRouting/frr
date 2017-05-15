/* Zebra PW code
 * Copyright (C) 2016 Volta Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "workqueue.h"
#include "zserv.h"

#include "zebra_pw.h"

DEFINE_MTYPE_STATIC(LIB, PW, "Pseudowire")

DEFINE_HOOK(pw_change, (struct zebra_pw_t *pw), (pw))

extern struct zebra_t zebrad;

struct zebra_pw_t *
pw_add (void)
{
  return XCALLOC (MTYPE_PW, sizeof (struct zebra_pw_t));
}

void
pw_del (struct zebra_pw_t *pw)
{
  XFREE (MTYPE_PW, pw);
}

/**
 * Add PW to work queue
 *
 * @param pw Pseudowire to enqueue
 */
void
pw_queue_add (struct zebra_pw_t *pw)
{
  assert (pw);

  /* If already scheduled, exit. */
  if (CHECK_FLAG (pw->queue_flags, PW_FLAG_SCHEDULED))
    return;

  work_queue_add (zebrad.pwq, pw);
  SET_FLAG (pw->queue_flags, PW_FLAG_SCHEDULED);

}
/**
 * Call on completion of a PseudWire processing.
 *
 * @param wq Workqueue
 * @param data The pseudowire to be removed
 */
static void
pw_queue_del (struct work_queue *wq, void *data)
{
  struct zebra_pw_t *pw;

  pw = (struct zebra_pw_t *)data;
  XFREE (MTYPE_PW, pw);

}
/**
 * Remove PWs from workqueue.
 *
 * It actually sets the ran counter over the max, so it will be
 * deleted on next iteration
 *
 * @param pw Pseudowire to be removed from queue
 */
void
unqueue_pw (struct zebra_pw_t *pw)
{
  struct work_queue *wq;
  struct work_queue_item *item;
  struct listnode *node, *nnode;
  struct zebra_pw_t *item_pw;

  wq = zebrad.pwq;

  for (ALL_LIST_ELEMENTS (wq->items, node, nnode, item))
    {
      item_pw = (struct zebra_pw_t *)item->data;
      if (item_pw->cmd != pw->cmd)
        continue;
      if (strncmp (item_pw->ifname, pw->ifname, IF_NAMESIZE) != 0)
        continue;
      if (item_pw->pwid != pw->pwid)
        continue;
      if (strncmp(item_pw->vpn_name, pw->vpn_name, L2VPN_NAME_LEN) != 0)
        continue;
      item->ran = PW_MAX_RETRIES + 1;
    }

}

static int
check_lsp (struct zebra_pw_t *pw)
{
  struct rib *rib;
  afi_t afi = 0;
  struct nexthop *nexthop, *tnexthop;
  int recursing;

  switch (pw->af)
    {
    case AF_INET:
      afi = AFI_IP;
      break;
    case AF_INET6:
      afi = AFI_IP6;
      break;
    default:
      zlog_warn ("Wrong AF for PW %u at VPN %s!", pw->pwid, pw->vpn_name);
      return 1;
    }

  /* find route for PW */
  rib = rib_match (afi, SAFI_UNICAST, VRF_DEFAULT,
                   (union g_addr *)&pw->nexthop, NULL);
  if (!rib)
    {
      zlog_warn ("No rib found for PW %u at VPN %s", pw->pwid, pw->vpn_name);
      return 1;
    }
  /* check labels for each nexthop in Route */
  /*
   * Need to ensure that there's a label binding for all nexthops.
   * Otherwise, ECMP for this route could render the pseudowire unusable.
   */
  for (ALL_NEXTHOPS_RO(rib->nexthop, nexthop, tnexthop, recursing))
    if (!nexthop->nh_label || nexthop->nh_label->num_labels == 0)
      {
        zlog_warn ("No label found in rib for PW %u at VPN %s", pw->pwid,
                   pw->vpn_name);
        return 1;
      }

  return 0;
}
/**
 * Process a PsuedoWire that is in the queue
 * Send it to External Manager
 *
 * @param wq PW work queue
 * @param data The PW itself
 */
static wq_item_status
pw_process (struct work_queue *wq, void *data)
{
  struct zebra_pw_t *pw;
  int ret;

  pw = (struct zebra_pw_t *) data;

  ret = check_lsp (pw);
  /* install in kernel */
  if (ret == 0)
    ret = hook_call (pw_change, pw);

  if (ret != 0)
    return WQ_RETRY_LATER;

  return WQ_SUCCESS;

}
static void
pw_queue_init (struct zebra_t *zebra)
{
  assert (zebra);

  if (! (zebra->pwq = work_queue_new (zebra->master,
                                      "Pseudowire processing")))
    {
      zlog_err ("%s: could not initialize work queue!", __func__);
      return;
    }

  /* fill in the work queue spec */
  zebra->pwq->spec.workfunc = &pw_process;
  zebra->pwq->spec.del_item_data = &pw_queue_del;
  zebra->pwq->spec.errorfunc = NULL;
  zebra->pwq->spec.max_retries = PW_MAX_RETRIES;
  zebra->pwq->spec.hold = PW_PROCESS_HOLD_TIME;

  return;
}

void
zebra_pw_init (void)
{
  pw_queue_init (&zebrad);
}
