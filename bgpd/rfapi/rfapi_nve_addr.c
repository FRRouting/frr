/* 
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */


#include "zebra.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "memory.h"
#include "skiplist.h"


#include "bgpd.h"

#include "bgp_rfapi_cfg.h"
#include "rfapi.h"
#include "rfapi_backend.h"

#include "rfapi_import.h"
#include "rfapi_private.h"
#include "rfapi_nve_addr.h"
#include "rfapi_vty.h"

#define DEBUG_NVE_ADDR 0

void rfapiNveAddr2Str (struct rfapi_nve_addr *, char *, int);


#if DEBUG_NVE_ADDR
static void
logdifferent (const char *tag,
              struct rfapi_nve_addr *a, struct rfapi_nve_addr *b)
{
  char a_str[BUFSIZ];
  char b_str[BUFSIZ];

  rfapiNveAddr2Str (a, a_str, BUFSIZ);
  rfapiNveAddr2Str (b, b_str, BUFSIZ);
  zlog_debug ("%s: [%s] [%s]", tag, a_str, b_str);
}
#endif


int
rfapi_nve_addr_cmp (void *k1, void *k2)
{
  struct rfapi_nve_addr *a = (struct rfapi_nve_addr *) k1;
  struct rfapi_nve_addr *b = (struct rfapi_nve_addr *) k2;
  int ret = 0;

  if (!a || !b)
    {
#if DEBUG_NVE_ADDR
      zlog_debug ("%s: missing address a=%p b=%p", __func__, a, b);
#endif
      return (a - b);
    }
  if (a->un.addr_family != b->un.addr_family)
    {
#if DEBUG_NVE_ADDR
      zlog_debug ("diff: UN addr fam a->un.af=%d, b->un.af=%d",
                  a->un.addr_family, b->un.addr_family);
#endif
      return (a->un.addr_family - b->un.addr_family);
    }
  if (a->un.addr_family == AF_INET)
    {
      ret = IPV4_ADDR_CMP (&a->un.addr.v4, &b->un.addr.v4);
      if (ret != 0)
        {
#if DEBUG_NVE_ADDR
          logdifferent ("diff: UN addr", a, b);
#endif
          return ret;
        }
    }
  else if (a->un.addr_family == AF_INET6)
    {
      ret = IPV6_ADDR_CMP (&a->un.addr.v6, &b->un.addr.v6);
      if (ret == 0)
        {
#if DEBUG_NVE_ADDR
          logdifferent ("diff: UN addr", a, b);
#endif
          return ret;
        }
    }
  else
    {
      assert (0);
    }
  if (a->vn.addr_family != b->vn.addr_family)
    {
#if DEBUG_NVE_ADDR
      zlog_debug ("diff: pT addr fam a->vn.af=%d, b->vn.af=%d",
                  a->vn.addr_family, b->vn.addr_family);
#endif
      return (a->vn.addr_family - b->vn.addr_family);
    }
  if (a->vn.addr_family == AF_INET)
    {
      ret = IPV4_ADDR_CMP (&a->vn.addr.v4, &b->vn.addr.v4);
      if (ret != 0)
        {
#if DEBUG_NVE_ADDR
          logdifferent ("diff: VN addr", a, b);
#endif
          return ret;
        }
    }
  else if (a->vn.addr_family == AF_INET6)
    {
      ret = IPV6_ADDR_CMP (&a->vn.addr.v6, &b->vn.addr.v6);
      if (ret == 0)
        {
#if DEBUG_NVE_ADDR
          logdifferent ("diff: VN addr", a, b);
#endif
          return ret;
        }
    }
  else
    {
      assert (0);
    }
  return 0;
}

void
rfapiNveAddr2Str (struct rfapi_nve_addr *na, char *buf, int bufsize)
{
  char *p = buf;
  int r;

#define REMAIN (bufsize - (p-buf))
#define INCP {p += (r > REMAIN)? REMAIN: r;}

  if (bufsize < 1)
    return;

  r = snprintf (p, REMAIN, "VN=");
  INCP;

  if (!rfapiRfapiIpAddr2Str (&na->vn, p, REMAIN))
    goto done;

  buf[bufsize - 1] = 0;
  p = buf + strlen (buf);

  r = snprintf (p, REMAIN, ", UN=");
  INCP;

  rfapiRfapiIpAddr2Str (&na->un, p, REMAIN);

done:
  buf[bufsize - 1] = 0;
}
