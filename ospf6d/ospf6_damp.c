/*
 * OSPF flap dampening by Manav Bhatia
 * Copyright (C) 2002 
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
#include <math.h>

#include "log.h"
#include "prefix.h"
#include "thread.h"
#include "table.h"
#include "command.h"
#include "vty.h"

extern struct thread_master *master;

#include "ospf6_damp.h"

#ifdef HAVE_OSPF6_DAMP

#define DELTA_REUSE         10 /* Time granularity for reuse lists */
#define DELTA_T              5 /* Time granularity for decay arrays */
#define DEFAULT_HALF_LIFE   60 /* (sec)     1 min */

#define DEFAULT_PENALTY   1000
#define DEFAULT_REUSE      750
#define DEFAULT_SUPPRESS  2000

#define REUSE_LIST_SIZE    256
#define REUSE_ARRAY_SIZE  1024

/* Global variable to access damping configuration */
struct ospf6_damp_config damp_config;
struct ospf6_damp_config *dc = &damp_config;
u_int reuse_array_offset = 0;
struct route_table *damp_info_table[OSPF6_DAMP_TYPE_MAX];
struct thread *ospf6_reuse_thread = NULL;

int ospf6_damp_debug = 0;
#define IS_OSPF6_DEBUG_DAMP (ospf6_damp_debug)

static struct ospf6_damp_info *
ospf6_damp_lookup (u_short type, struct prefix *name)
{
  struct route_node *node;

  node = route_node_lookup (damp_info_table[type], name);
  if (node && node->info)
    return (struct ospf6_damp_info *) node->info;
  return NULL;
}

static struct ospf6_damp_info *
ospf6_damp_create (u_short type, struct prefix *name)
{
  struct route_node *node;
  struct ospf6_damp_info *di;
  char namebuf[64];

  di = ospf6_damp_lookup (type, name);
  if (di)
    return di;

  if (IS_OSPF6_DEBUG_DAMP)
    {
      prefix2str (name, namebuf, sizeof (namebuf));
      zlog_info ("DAMP: create: type: %d, name: %s", type, namebuf);
    }

  di = (struct ospf6_damp_info *)
    malloc (sizeof (struct ospf6_damp_info));
  memset (di, 0, sizeof (struct ospf6_damp_info));
  di->type = type;
  prefix_copy (&di->name, name);

  node = route_node_get (damp_info_table[type], name);
  node->info = di;

  return di;
}

static void
ospf6_damp_delete (u_short type, struct prefix *name)
{
  struct route_node *node;
  struct ospf6_damp_info *di;
  char namebuf[64];

  node = route_node_lookup (damp_info_table[type], name);
  if (! node || ! node->info)
    return;

  di = node->info;

  if (IS_OSPF6_DEBUG_DAMP)
    {
      prefix2str (&di->name, namebuf, sizeof (namebuf));
      zlog_info ("DAMP: delete: type: %d, name: %s",
                 di->type, namebuf);
    }

  node->info = NULL;
  free (di);
}

/* compute and fill the configuration parameter */
void
ospf6_damp_init_config (u_int half_life, u_int reuse,
                        u_int suppress, u_int t_hold)
{
  int i;
  double max_ratio, max_ratio1, max_ratio2;

  dc->half_life = half_life ? half_life : DEFAULT_HALF_LIFE;
  dc->reuse     = reuse     ? reuse     : DEFAULT_REUSE;
  dc->suppress  = suppress  ? suppress  : DEFAULT_SUPPRESS;
  dc->t_hold    = t_hold    ? t_hold    : 4 * dc->half_life;

  /* Initialize system-wide params */
  dc->delta_t = DELTA_T;
  dc->delta_reuse = DELTA_REUSE;
  dc->default_penalty = DEFAULT_PENALTY;
  dc->reuse_index_array_size = REUSE_ARRAY_SIZE;

  /* ceiling is the maximum penalty a route may attain */
  /* ceiling = reuse * 2^(T-hold/half-life) */
  dc->ceiling = (int)
    (dc->reuse * (pow (2, (double) dc->t_hold / dc->half_life)));

  /* Decay-array computations */
  /* decay_array_size = decay memory/time granularity */
  dc->decay_array_size = ceil ((double) dc->t_hold / dc->delta_t);
  dc->decay_array = malloc (sizeof (double) * (dc->decay_array_size));

  /* Each i-th element is per tick delay raised to the i-th power */
  dc->decay_array[0] = 1.0;
  dc->decay_array[1] = exp ((1.0 / (dc->half_life / dc->delta_t)) * log (0.5));
  for (i = 2; i < dc->decay_array_size; i++)
    dc->decay_array[i] = dc->decay_array[i - 1] * dc->decay_array[1];

  /* Reuse-list computations (reuse queue head array ?) */
  dc->reuse_list_size = ceil ((double) dc->t_hold / dc->delta_reuse) + 1;
  if (dc->reuse_list_size == 0 || dc->reuse_list_size > REUSE_LIST_SIZE)
    dc->reuse_list_size = REUSE_LIST_SIZE;
  dc->reuse_list_array = (struct ospf6_damp_info **)
    malloc (dc->reuse_list_size * sizeof (struct ospf6_reuse_list *));
  memset (dc->reuse_list_array, 0x00,
          dc->reuse_list_size * sizeof (struct ospf6_reuse_list *));

  /* Reuse-array computations */
  dc->reuse_index_array = malloc (sizeof (int) * dc->reuse_index_array_size);

  /*
   * This is the maximum ratio between the current value of the penalty and
   * the reuse value which can be indexed by the reuse array. It will be 
   * limited by the ceiling or by the amount of time that the reuse list 
   * covers 
   */
  max_ratio1 = (double) dc->ceiling / dc->reuse;
  max_ratio2 = exp ((double) dc->t_hold / dc->half_life) * log10 (2.0);
  max_ratio = (max_ratio2 != 0 && max_ratio2 < max_ratio1 ?
               max_ratio2 : max_ratio1);

  /*
   * reuse array is just an estimator and we need something
   * to use the full array 
   */
  dc->scale_factor = (double) dc->reuse_index_array_size / (max_ratio - 1);

  for (i = 0; i < dc->reuse_index_array_size; i++)
    {
      dc->reuse_index_array[i] = (int)
        (((double) dc->half_life / dc->delta_reuse) *
         log10 (1.0 / (dc->reuse * (1.0 + ((double) i / dc->scale_factor))))
         / log10 (0.5));
    }

  dc->enabled = ON;
}

static double
ospf6_damp_decay (time_t tdiff)
{
  int index = tdiff / dc->delta_t;

  if (index >= dc->decay_array_size)
    return 0;

  return dc->decay_array[index];
}

static int
ospf6_damp_reuse_index (int penalty)
{
  int index;

  index = (int) (((double) penalty / dc->reuse - 1.0) * dc->scale_factor);

  if (index >= dc->reuse_index_array_size)
    index = dc->reuse_index_array_size - 1;

  return (dc->reuse_index_array[index] - dc->reuse_index_array[0]);
}

static int
ospf6_reuse_list_lookup (struct ospf6_damp_info *di)
{
  struct ospf6_damp_info *info;

  for (info = dc->reuse_list_array[di->index]; info; info = info->next)
    {
      if (info == di)
        return 1;
    }
  return 0;
}

static void
ospf6_reuse_list_remove (struct ospf6_damp_info *di)
{
  if (di->prev)
    di->prev->next = di->next;
  else
    dc->reuse_list_array[di->index] = di->next;
  if (di->next)
    di->next->prev = di->prev;

  di->index = -1;
  di->prev = NULL;
  di->next = NULL;
}

static void
ospf6_reuse_list_add (struct ospf6_damp_info *di)
{
  /* set the index of reuse-array */
  di->index = (reuse_array_offset + (ospf6_damp_reuse_index (di->penalty)))
              % dc->reuse_list_size;

  /* insert to the head of the reuse list */
  di->next = dc->reuse_list_array[di->index];
  if (di->next)
    di->next->prev = di;
  di->prev = NULL;
  dc->reuse_list_array[di->index] = di;
}

/* When we quit damping for a target, we should execute proper event
   which have been postponed during damping */
static void
ospf6_damp_stop (struct ospf6_damp_info *di)
{
  time_t t_now;
  char namebuf[64];
  struct timeval now;

  if (IS_OSPF6_DEBUG_DAMP)
    {
      t_now = time (NULL);
      prefix2str (&di->name, namebuf, sizeof (namebuf));
      gettimeofday (&now, NULL);
      zlog_info ("DAMP: %lu.%06lu stop damping: %ld: type: %d, name: %s",
                 now.tv_sec, now.tv_usec,
                 t_now, di->type, namebuf);
    }

  /* set flag indicates that we're damping this target */
  di->damping = OFF;

  /* if the target's current status differ from that it should be,
     execute the proper event to repair his status */
  if (di->target_status != di->event_type)
    {
      (*(di->event)) (di->target);
      di->target_status = di->event_type;

      di->event = NULL;
      di->event_type = event_none;
    }
}

/* ospf6_reuse_timer is called every DELTA_REUSE seconds.
   Each route in the current reuse-list is evaluated
   and is used or requeued */
int
ospf6_damp_reuse_timer (struct thread *t)
{
  struct ospf6_damp_info *di, *next;
  time_t t_now, t_diff;
  char namebuf[64];
  struct timeval now;

  /* Restart the reuse timer */
  ospf6_reuse_thread =
    thread_add_timer (master, ospf6_damp_reuse_timer, NULL, dc->delta_reuse);

  t_now = time (NULL);

  /* get the damp info list head */
  di = dc->reuse_list_array[reuse_array_offset];
  dc->reuse_list_array[reuse_array_offset] = NULL;

  /* rotate the circular reuse list head array */
  reuse_array_offset = (reuse_array_offset + 1) % dc->reuse_list_size;

  /* for each damp info */
  while (di)
    {
      next = di->next;
      di->next = NULL;

      /* Update penalty */
      t_diff = t_now - di->t_updated;
      di->t_updated = t_now;
      di->penalty = (int)
        ((double) di->penalty * ospf6_damp_decay (t_diff));
      /* configration of ceiling may be just changed */
      if (di->penalty > dc->ceiling)
        di->penalty = dc->ceiling;

      if (IS_OSPF6_DEBUG_DAMP)
        {
          prefix2str (&di->name, namebuf, sizeof (namebuf));
          gettimeofday (&now, NULL);
          zlog_info ("DAMP: %lu.%06lu update penalty: type: %d, name: %s, penalty: %d",
                     now.tv_sec, now.tv_usec,
                     di->type, namebuf, di->penalty);
        }

      /* If the penalty becomes under reuse,
         call real event that we have been postponed. */
      if (di->penalty < dc->reuse && di->damping == ON)
        ospf6_damp_stop (di);

      /* If the penalty becomes less than the half of the
         reuse value, this damp info will be freed from reuse-list,
         by assuming that it is considered to be stable enough already,
         and there's no need to maintain flapping history for this. */
      if (di->penalty <= dc->reuse / 2)
        {
          ospf6_damp_delete (di->type, &di->name);
          di = next;
          continue;
        }

      /* re-insert to the reuse-list */
      ospf6_reuse_list_add (di);

      di = next;
    }

  return 0;
}

static void
ospf6_damp_event (damp_event_t event_type,
                  u_short type, struct prefix *name,
                  int (*event) (void *), void *target)
{
  time_t t_now, t_diff;
  struct ospf6_damp_info *di;
  char namebuf[64];
  struct timeval now;

  if (dc->enabled == OFF)
    {
      (*event) (target);
      return;
    }

  di = ospf6_damp_lookup (type, name);
  if (! di)
    di = ospf6_damp_create (type, name);

  t_now = time (NULL);

  di->event = event;
  di->target = target;
  di->event_type = event_type;

  if (! ospf6_reuse_list_lookup (di))
    di->t_start = t_now;
  else
    {
      ospf6_reuse_list_remove (di);

      t_diff = t_now - di->t_updated;
      di->penalty = (int) (di->penalty * ospf6_damp_decay (t_diff));
    }

  /* penalty only on down event */
  if (event_type == event_down)
    {
      di->flap++;
      di->penalty += dc->default_penalty;
    }

  /* limit penalty up to ceiling */
  if (di->penalty > dc->ceiling)
    di->penalty = dc->ceiling;

  if (IS_OSPF6_DEBUG_DAMP)
    {
      prefix2str (&di->name, namebuf, sizeof (namebuf));
      gettimeofday (&now, NULL);
      zlog_info ("DAMP: %lu.%06lu update penalty: type: %d, name: %s, penalty: %d",
                 now.tv_sec, now.tv_usec,
                 di->type, namebuf, di->penalty);
    }

  /* if penalty < reuse, stop damping here */
  if (di->penalty < dc->reuse && di->damping == ON)
    {
      if (IS_OSPF6_DEBUG_DAMP)
        {
          prefix2str (&di->name, namebuf, sizeof (namebuf));
          gettimeofday (&now, NULL);
          zlog_info ("DAMP: %lu.%06lu stop damping: %ld: type: %d, name: %s",
                     now.tv_sec, now.tv_usec,
                     t_now, di->type, namebuf);
        }
      di->damping = OFF;
    }

  /* if event == up and if penalty >= suppress , start damping here */
  if (di->event_type == event_up && di->penalty >= dc->suppress &&
      di->damping == OFF)
    {
      if (IS_OSPF6_DEBUG_DAMP)
        {
          prefix2str (&di->name, namebuf, sizeof (namebuf));
          gettimeofday (&now, NULL);
          zlog_info ("DAMP: %lu.%06lu start damping: %ld: type: %d, name: %s",
                     now.tv_sec, now.tv_usec,
                     t_now, type, namebuf);
        }
      di->damping = ON;
    }

  /* execute event if we're not damping */
  if (di->damping == OFF)
    {
      (*(di->event)) (di->target);
      di->target_status = di->event_type;
    }

  /* if the penalty goes beyond suppress value, start damping */
  if (di->penalty >= dc->suppress && di->damping == OFF)
    {
      if (IS_OSPF6_DEBUG_DAMP)
        {
          prefix2str (name, namebuf, sizeof (namebuf));
          gettimeofday (&now, NULL);
          zlog_info ("DAMP: %lu.%06lu start damping: %ld: type: %d, name: %s",
                     now.tv_sec, now.tv_usec,
                     t_now, type, namebuf);
        }
      di->damping = ON;
    }

  /* update last-updated-time field */
  di->t_updated = t_now;

  /* Insert it into the reuse list */
  ospf6_reuse_list_add (di);
}

void
ospf6_damp_event_up (u_short type, struct prefix *name,
                     int (*event) (void *), void *target)
{
  struct timeval now;

  gettimeofday (&now, NULL);
  if (IS_OSPF6_DEBUG_DAMP)
    zlog_info ("DAMP: Up   Event at %lu.%06lu", now.tv_sec, now.tv_usec);

  ospf6_damp_event (event_up, type, name, event, target);
}

void
ospf6_damp_event_down (u_short type, struct prefix *name,
                       int (*event) (void *), void *target)
{
  struct timeval now;

  gettimeofday (&now, NULL);
  if (IS_OSPF6_DEBUG_DAMP)
    zlog_info ("DAMP: Down Event at %lu.%06lu", now.tv_sec, now.tv_usec);

  ospf6_damp_event (event_down, type, name, event, target);
}

int
ospf6_damp_debug_thread (struct thread *thread)
{
  int i;
  struct ospf6_damp_info *di;
  char buf[256];
  time_t t_now;
  struct timeval now;

  for (i = 0; i < dc->reuse_list_size; i++)
    {
      for (di = dc->reuse_list_array[i]; di; di = di->next)
        {
          t_now = time (NULL);
          gettimeofday (&now, NULL);
          prefix2str (&di->name, buf, sizeof (buf));
          zlog_info ("DAMP: %lu.%06lu %c %-32s penalty %7u",
                     now.tv_sec, now.tv_usec,
                     (di->damping == ON ? 'D' : 'A'), buf,
                     (u_int) (di->penalty *
                              ospf6_damp_decay (t_now - di->t_updated)));
        }
    }
  thread_add_timer (master, ospf6_damp_debug_thread, NULL, 1);
  return 0;
}

DEFUN (show_ipv6_ospf6_route_flapping,
       show_ipv6_ospf6_route_flapping_cmd,
       "show ipv6 ospf6 route flapping",
       SHOW_STR
       IP6_STR
       OSPF6_STR)
{
  int i;
  struct ospf6_damp_info *di;
  char buf[256];
  time_t t_now;

  t_now = time (NULL);
  vty_out (vty, "%c %-32s %7s%s", ' ', "Prefix", "penalty", VTY_NEWLINE);

  for (i = 0; i < dc->reuse_list_size; i++)
    {
      for (di = dc->reuse_list_array[i]; di; di = di->next)
        {
          prefix2str (&di->name, buf, sizeof (buf));
          vty_out (vty, "%c %-32s %7u%s",
                   (di->damping == ON ? 'D' : ' '), buf,
                   (u_int) (di->penalty *
                            ospf6_damp_decay (t_now - di->t_updated)),
                   VTY_NEWLINE);
        }
    }

  return CMD_SUCCESS;
}

DEFUN (flap_damping_route,
       flap_damping_route_cmd,
       "flap-damping route <0-4294967295> <0-4294967295> "
                          "<0-4294967295> <0-4294967295>",
       "enable flap dampening\n"
       "enable route flap dampening\n"
       "half-life in second\n"
       "reuse value\n"
       "suppress value\n"
       "t-hold in second (maximum time that the target can be damped)\n"
      )
{
  u_int half_life, reuse, suppress, t_hold;

  if (argc)
    {
      half_life = (u_int) strtoul (argv[0], NULL, 10);
      reuse     = (u_int) strtoul (argv[1], NULL, 10);
      suppress  = (u_int) strtoul (argv[2], NULL, 10);
      t_hold    = (u_int) strtoul (argv[3], NULL, 10);
    }
  else
    {
      half_life = (u_int) DEFAULT_HALF_LIFE;
      reuse     = (u_int) DEFAULT_REUSE;
      suppress  = (u_int) DEFAULT_SUPPRESS;
      t_hold    = (u_int) DEFAULT_HALF_LIFE * 4;
    }

  if (reuse && suppress && reuse >= suppress)
    {
      vty_out (vty, "reuse value exceeded suppress value, failed%s\n",
               VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  if (half_life && t_hold && half_life >= t_hold)
    {
      vty_out (vty, "half-life exceeded t-hold, failed%s\n", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  ospf6_damp_init_config (half_life, reuse, suppress, t_hold);

  if (ospf6_reuse_thread == NULL)
    ospf6_reuse_thread =
      thread_add_timer (master, ospf6_damp_reuse_timer, NULL, dc->delta_reuse);

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_damp_config,
       show_ipv6_ospf6_camp_config_cmd,
       "show ipv6 ospf6 damp config",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Flap-dampening information\n"
       "shows dampening configuration\n"
      )
{
  int i;

  vty_out (vty, "%10s %10s %10s %10s%s",
           "Half life", "Suppress", "Reuse", "T-hold",
           VTY_NEWLINE);
  vty_out (vty, "%10u %10u %10u %10u%s",
           dc->half_life, dc->suppress, dc->reuse, dc->t_hold,
           VTY_NEWLINE);
  vty_out (vty, "%s", VTY_NEWLINE);

  vty_out (vty, "Delta-t = %u%s", dc->delta_t, VTY_NEWLINE);
  vty_out (vty, "Delta-Reuse = %u%s", dc->delta_reuse, VTY_NEWLINE);
  vty_out (vty, "Default-Penalty = %u%s", dc->default_penalty, VTY_NEWLINE);
  vty_out (vty, "Ceiling = %u%s", dc->ceiling, VTY_NEWLINE);
  vty_out (vty, "ScaleFactor = %f%s", dc->scale_factor, VTY_NEWLINE);

  vty_out (vty, "DecayArray(%d) =%s", dc->decay_array_size, VTY_NEWLINE);
  for (i = 0; i < dc->decay_array_size; i++)
    {
      if (i % 10 == 0)
        vty_out (vty, "  ");
      vty_out (vty, " %f", dc->decay_array[i]);
      if (i % 10 == 0)
        vty_out (vty, "%s", VTY_NEWLINE);
    }
  vty_out (vty, "%s", VTY_NEWLINE);

  vty_out (vty, "ReuseIndexArray(%d) =%s",
           dc->reuse_index_array_size, VTY_NEWLINE);
  for (i = 0; i < dc->reuse_index_array_size; i++)
    {
      if (i % 10 == 0)
        vty_out (vty, "  ");
      vty_out (vty, " %d", dc->reuse_index_array[i]);
      if (i % 10 == 0)
        vty_out (vty, "%s", VTY_NEWLINE);
    }
  vty_out (vty, "%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

void
ospf6_damp_config_write (struct vty *vty)
{
  if (dc->enabled == ON)
    {
      vty_out (vty, " flap-damping route %u %u %u %u%s",
               dc->half_life, dc->reuse, dc->suppress, dc->t_hold,
               VTY_NEWLINE);
    }
}

DEFUN (debug_ospf6_damp,
       debug_ospf6_damp_cmd,
       "debug ospf6 damp",
       DEBUG_STR
       OSPF6_STR
       "Flap-dampening information\n"
      )
{
  ospf6_damp_debug = 1;
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_damp,
       no_debug_ospf6_damp_cmd,
       "no debug ospf6 damp",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Flap-dampening information\n"
      )
{
  ospf6_damp_debug = 0;
  return CMD_SUCCESS;
}

DEFUN (show_debug_ospf6_damp,
       show_debug_ospf6_damp_cmd,
       "show debugging ospf6 damp",
       SHOW_STR
       DEBUG_STR
       OSPF6_STR
       "Flap-dampening information\n"
      )
{
  vty_out (vty, "debugging ospf6 damp is ");
  if (IS_OSPF6_DEBUG_DAMP)
    vty_out (vty, "enabled.");
  else
    vty_out (vty, "disabled.");
  vty_out (vty, "%s", VTY_NEWLINE);
  return CMD_SUCCESS;
}

void
ospf6_damp_init ()
{
  int i;
  for (i = 0; i < OSPF6_DAMP_TYPE_MAX; i++)
    damp_info_table[i] = route_table_init ();

  install_element (VIEW_NODE, &show_ipv6_ospf6_route_flapping_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_route_flapping_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_camp_config_cmd);
  install_element (OSPF6_NODE, &flap_damping_route_cmd);

  install_element (ENABLE_NODE, &show_debug_ospf6_damp_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_damp_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_damp_cmd);

  thread_add_event (master, ospf6_damp_debug_thread, NULL, 0);
}

#endif /* HAVE_OSPF6_DAMP */


