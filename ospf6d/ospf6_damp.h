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

/*
 * Flap Damping (target e.g. link/route)
 */

#define HAVE_OSPF6_DAMP

typedef enum
{
  OFF,
  ON,
} onoff_t;

typedef enum
{
  event_none,
  event_up,
  event_down,
} damp_event_t;

/* Structure maintained per target basis */
struct ospf6_damp_info
{
  /* identifier to decide which target */
  u_short type;
  struct prefix name;

  /* do we damping this info */
  onoff_t damping;

  u_int penalty;
  u_int flap;
  time_t t_start;   /* First flap (down event) time */
  time_t t_updated; /* Last time the penalty was updated */

  /* index and double-link for reuse list */
  int                    index;
  struct ospf6_damp_info *next;
  struct ospf6_damp_info *prev;

  /* the last event that we are avoiding */
  int (*event) (void *target);
  void *target;
  damp_event_t event_type;
  damp_event_t target_status;
};

#define OSPF6_DAMP_TYPE_ROUTE      0
#define OSPF6_DAMP_TYPE_MAX        1

/* Global Configuration Parameters */
struct ospf6_damp_config
{
  /* is damping enabled ? */
  onoff_t enabled;

  /* configurable parameters */
  u_int half_life;
  u_int suppress;
  u_int reuse;
  u_int t_hold;                 /* Maximum hold down time */

  /* Non configurable parameters */
  u_int   delta_t;
  u_int   delta_reuse;
  u_int   default_penalty;
  u_int   ceiling;              /* Max value a penalty can attain */
  double  scale_factor;

  int     decay_array_size;     /* Calculated using config parameters */
  double *decay_array;          /* Storage for decay values */

  int  reuse_index_array_size;  /* Size of reuse index array */
  int *reuse_index_array;

  int  reuse_list_size;         /* Number of reuse lists */
  struct ospf6_damp_info **reuse_list_array;
};

int ospf6_damp_reuse_timer (struct thread *);
void ospf6_damp_event_up   (u_short type, struct prefix *name,
                           int (*exec_up)   (void *), void *target);
void ospf6_damp_event_down (u_short type, struct prefix *name,
                           int (*exec_down) (void *), void *target);

void ospf6_damp_config_write (struct vty *);
void ospf6_damp_init ();

