/*
 * IS-IS Rout(e)ing protocol - isis_dynhn.c
 *                             Dynamic hostname cache
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <time.h>
#include <zebra.h>

#include "vty.h"
#include "linklist.h"
#include "memory.h"
#include "log.h"
#include "stream.h"
#include "command.h"
#include "if.h"

#include "isisd/dict.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_constants.h"

extern struct isis *isis;
extern struct host host;

struct list *dyn_cache = NULL;

void
dyn_cache_init (void)
{
  dyn_cache = list_new ();

  return;
}

struct isis_dynhn *
dynhn_find_by_id (u_char * id)
{
  struct listnode *node = NULL;
  struct isis_dynhn *dyn = NULL;

  for (node = listhead (dyn_cache); node; nextnode (node))
    {
      dyn = getdata (node);
      if (memcmp (dyn->id, id, ISIS_SYS_ID_LEN) == 0)
	return dyn;
    }

  return NULL;
}

void
isis_dynhn_insert (u_char * id, struct hostname *hostname, int level)
{
  struct isis_dynhn *dyn;

  dyn = dynhn_find_by_id (id);
  if (dyn)
    {
      memcpy (&dyn->name, hostname, hostname->namelen + 1);
      memcpy (dyn->id, id, ISIS_SYS_ID_LEN);
      dyn->refresh = time (NULL);
      return;
    }
  dyn = XMALLOC (MTYPE_ISIS_DYNHN, sizeof (struct isis_dynhn));
  if (!dyn)
    {
      zlog_warn ("isis_dynhn_insert(): out of memory!");
      return;
    }
  memset (dyn, 0, sizeof (struct isis_dynhn));
  /* we also copy the length */
  memcpy (&dyn->name, hostname, hostname->namelen + 1);
  memcpy (dyn->id, id, ISIS_SYS_ID_LEN);
  dyn->refresh = time (NULL);
  dyn->level = level;

  listnode_add (dyn_cache, dyn);

  return;
}

/*
 * Level  System ID      Dynamic Hostname  (notag)
 *  2     0000.0000.0001 foo-gw
 *  2     0000.0000.0002 bar-gw
 *      * 0000.0000.0004 this-gw
 */
void
dynhn_print_all (struct vty *vty)
{
  struct listnode *node;
  struct isis_dynhn *dyn;

  vty_out (vty, "Level  System ID      Dynamic Hostname%s", VTY_NEWLINE);
  for (node = listhead (dyn_cache); node; nextnode (node))
    {
      dyn = getdata (node);
      vty_out (vty, "%-7d", dyn->level);
      vty_out (vty, "%-15s%-15s%s", sysid_print (dyn->id), dyn->name.name,
	       VTY_NEWLINE);
    }

  vty_out (vty, "     * %s %s%s", sysid_print (isis->sysid), unix_hostname (),
	   VTY_NEWLINE);
  return;
}
