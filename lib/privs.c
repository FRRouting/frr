/* 
 * Zebra privileges.
 *
 * Copyright (C) 2003 Paul Jakma.
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
#include "privs.h"
#include "memory.h"
       

/* internal privileges state */
static struct _zprivs_t
{
#ifdef HAVE_LCAPS
  cap_t caps;                 /* caps storage             */
  cap_value_t *syscaps_p;     /* system permitted caps    */
  cap_value_t *syscaps_i;     /* system inheritable caps  */
  int sys_num_p;              /* number of syscaps_p      */
  int sys_num_i;              /* number of syscaps_i      */
#endif /* HAVE_LCAPS */
  uid_t zuid,                 /* uid to run as            */
        zsuid;                /* saved uid                */
  gid_t zgid;                 /* gid to run as            */
} zprivs_state;

/* externally exported but not directly accessed functions */
#ifdef HAVE_LCAPS
int zprivs_change_caps (zebra_privs_ops_t);
zebra_privs_current_t zprivs_state_caps (void);
#endif /* HAVE_LCAPS */
int zprivs_change_uid (zebra_privs_ops_t);
zebra_privs_current_t zprivs_state_uid (void);
int zprivs_change_null (zebra_privs_ops_t);
zebra_privs_current_t zprivs_state_null (void);
void zprivs_terminate (void);

#ifdef HAVE_LCAPS
static int 
cap_map [ZCAP_MAX] =
{
  [ZCAP_SETGID] = CAP_SETGID,
  [ZCAP_SETUID] = CAP_SETUID,
  [ZCAP_BIND] = CAP_NET_BIND_SERVICE,
  [ZCAP_BROADCAST] = CAP_NET_BROADCAST,
  [ZCAP_ADMIN] = CAP_NET_ADMIN,
  [ZCAP_RAW] = CAP_NET_RAW,
  [ZCAP_CHROOT] = CAP_SYS_CHROOT,
  [ZCAP_NICE] = CAP_SYS_NICE,
  [ZCAP_PTRACE] =  CAP_SYS_PTRACE
};

static cap_value_t cap_setuid_value [] = { CAP_SETUID };

/* convert zebras privileges to system capabilities */
static cap_value_t *
zcaps2sys (zebra_capabilities_t *zcaps, int num)
{
  cap_value_t *syscaps;
  int i;
  
  if (!num)
    return NULL;

  syscaps = (cap_value_t *) XCALLOC ( MTYPE_PRIVS, 
                                       (sizeof(cap_value_t) * num) );
  if (!syscaps)
    {
      zlog_err ("zcap2sys: could not XCALLOC!");
      return NULL;
    }
  
  for (i=0; i < num; i++)
    {
      syscaps[i] = cap_map[zcaps[i]];
    }
    
  return syscaps;
}

/* set or clear the effective capabilities to/from permitted */
int 
zprivs_change_caps (zebra_privs_ops_t op)
{
  cap_flag_value_t cflag;
  
  if (op == ZPRIVS_RAISE)
    cflag = CAP_SET;
  else if (op == ZPRIVS_LOWER)
    cflag = CAP_CLEAR;
  else
    return -1;

  if ( !cap_set_flag (zprivs_state.caps, CAP_EFFECTIVE,
                       zprivs_state.sys_num_p, zprivs_state.syscaps_p, cflag))
    return cap_set_proc (zprivs_state.caps);
  return -1;
}

zebra_privs_current_t
zprivs_state_caps (void)
{
  int i;
  cap_flag_value_t val;
  
  for (i=0; i < zprivs_state.sys_num_p; i++)
    {
      if ( cap_get_flag (zprivs_state.caps, zprivs_state.syscaps_p[i], 
                         CAP_EFFECTIVE, &val) )
        zlog_warn ("zprivs_state_caps: could not cap_get_flag, %s",
                    strerror (errno) );
      if (val == CAP_SET)
        return ZPRIVS_RAISED;
    }
  return ZPRIVS_LOWERED;
}

#endif /* HAVE_LCAPS */

int
zprivs_change_uid (zebra_privs_ops_t op)
{
  if (op == ZPRIVS_RAISE)
    return seteuid (zprivs_state.zsuid);
  else if (op == ZPRIVS_LOWER)
    return seteuid (zprivs_state.zuid);
  else
    return -1;
}

zebra_privs_current_t
zprivs_state_uid (void)
{
  return ( (zprivs_state.zuid == geteuid()) ? ZPRIVS_LOWERED : ZPRIVS_RAISED);
}

int
zprivs_change_null (zebra_privs_ops_t op)
{
  return 0;
}

zebra_privs_current_t
zprivs_state_null (void)
{
  return ZPRIVS_RAISED;
}


void
zprivs_init(struct zebra_privs_t *zprivs)
{
  struct passwd *pwentry = NULL;
  struct group *grentry = NULL;

  /* NULL privs */
  if (! (zprivs->user || zprivs->group 
         || zprivs->cap_num_p || zprivs->cap_num_i) )
    {
      zprivs->change = zprivs_change_null;
      zprivs->current_state = zprivs_state_null;
      return;
    }

  if (zprivs->user)
    {
      if ( (pwentry = getpwnam (zprivs->user)) )
        zprivs_state.zuid = pwentry->pw_uid;
      else
        {
          zlog_err ("privs_init: could not lookup supplied user");
          exit (1);
        }
    }
  
  if (zprivs->group)
    {
      if ( (grentry = getgrnam (zprivs->user)) )
        zprivs_state.zgid = pwentry->pw_uid;
      else
        {
          zlog_err ("privs_init: could not lookup supplied user");
          exit (1);
        }
        
      /* change group now, forever. uid we do later */
      if ( setregid (zprivs_state.zgid, zprivs_state.zgid) )
        {
          zlog_err ("privs_init: could not setregid");
          exit (1);
        }
    }
  
#ifdef HAVE_LCAPS
  zprivs_state.syscaps_p = zcaps2sys (zprivs->caps_p, zprivs->cap_num_p);
  zprivs_state.sys_num_p = zprivs->cap_num_p;
  zprivs_state.syscaps_i = zcaps2sys (zprivs->caps_i, zprivs->cap_num_i);
  zprivs_state.sys_num_i = zprivs->cap_num_i;

  /* Tell kernel we want caps maintained across uid changes */
  if ( prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1 )
    {
      zlog_err("privs_init: could not set PR_SET_KEEPCAPS, %s",
                strerror (errno) );
      exit(1);
    }

  if ( !zprivs_state.syscaps_p )
    {
      zlog_warn ("privs_init: capabilities enabled, but no capabilities supplied");
    }

  if ( !(zprivs_state.caps = cap_init()) )
    {
      zlog_err ("privs_init: failed to cap_init, %s", strerror (errno) );
      exit (1);
    }
  
  if ( cap_clear (zprivs_state.caps) )
    {
      zlog_err ("privs_init: failed to cap_clear, %s", strerror (errno));
      exit (1);
    }
  
  /* set permitted caps */
  cap_set_flag(zprivs_state.caps, CAP_PERMITTED, 
               zprivs_state.sys_num_p, zprivs_state.syscaps_p, CAP_SET);
  cap_set_flag(zprivs_state.caps, CAP_EFFECTIVE, 
               zprivs_state.sys_num_p, zprivs_state.syscaps_p, CAP_SET);

  /* still need CAP_SETUID for the moment */
  cap_set_flag(zprivs_state.caps, CAP_PERMITTED,
               1, cap_setuid_value, CAP_SET);
  cap_set_flag(zprivs_state.caps, CAP_EFFECTIVE,
  				1, cap_setuid_value, CAP_SET);

  /* set inheritable caps, if any */
  if (zprivs_state.sys_num_i)
    {
      cap_set_flag(zprivs_state.caps, CAP_INHERITABLE, 
                   zprivs_state.sys_num_i, zprivs_state.syscaps_i, CAP_SET);
    }
  
  /* apply caps. CAP_EFFECTIVE is clear bar cap_setuid_value. 
   * we'll raise the caps as and when, and only when, they are needed.
   */
  if ( cap_set_proc (zprivs_state.caps) ) 
    {
      zlog_err ("privs_init: initial cap_set_proc failed");
      exit (1);
    }
  
  /* we have caps, we have no need to ever change back the original user
  if (zprivs_state.zuid)
    {
      if ( setreuid (zprivs_state.zuid, zprivs_state.zuid) )
        {
          zlog_err ("privs_init (cap): could not setreuid, %s", strerror (errno) );
          exit (1);
        }
     }
   */

  /* No more need for cap_setuid_value */
  cap_set_flag(zprivs_state.caps, CAP_PERMITTED,
               1, cap_setuid_value, CAP_CLEAR);
  cap_set_flag(zprivs_state.caps, CAP_EFFECTIVE,
  				1, cap_setuid_value, CAP_CLEAR);
  if ( cap_set_proc (zprivs_state.caps) ) 
    {
      zlog_err ("privs_init: cap_set_proc failed to clear cap_setuid, %s",
                strerror (errno) );
      exit (1);
    }

  zprivs->change = zprivs_change_caps;
  zprivs->current_state = zprivs_state_caps;

#elif !defined(HAVE_LCAPS)
  /* we dont have caps. we'll need to maintain rid and saved uid
   * and change euid back to saved uid (who we presume has all neccessary
   * privileges) whenever we are asked to raise our privileges.
   */
  zprivs_state.zsuid = geteuid();  
  if ( zprivs_state.zuid )
    {
      if ( setreuid (-1, zprivs_state.zuid) )
        {
          zlog_err ("privs_init (uid): could not setreuid, %s", strerror (errno));
          exit (1);
        }
    }
  
  zprivs->change = zprivs_change_uid;
  zprivs->current_state = zprivs_state_uid;
#endif /* HAVE_LCAPS */
}

void 
zprivs_terminate (void)
{

#ifdef HAVE_LCAPS

  if (zprivs_state.caps)
      cap_clear (zprivs_state.caps);

  if ( cap_set_proc (zprivs_state.caps) ) 
    {
      zlog_err ("privs_terminate: cap_set_proc failed, %s",
                strerror (errno) );
      exit (1);
    }  

  if (zprivs_state.sys_num_p)
    XFREE (MTYPE_PRIVS, zprivs_state.syscaps_p);
  
  if (zprivs_state.sys_num_i)
    XFREE (MTYPE_PRIVS, zprivs_state.syscaps_i);
  
  cap_free (zprivs_state.caps);
#else
  if (zprivs_state.zuid)
    {
      if ( setreuid (zprivs_state.zuid, zprivs_state.zuid) )
        {
          zlog_err ("privs_terminate: could not setreuid, %s", 
                     strerror (errno) );
          exit (1);
        }
     }
#endif /* HAVE_LCAPS */
  return;
}
