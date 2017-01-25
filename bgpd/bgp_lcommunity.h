/* BGP Large Communities Attribute.

Copyright (C) 2016 Keyur Patel <keyur@arrcus.com>

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#ifndef _QUAGGA_BGP_LCOMMUNITY_H
#define _QUAGGA_BGP_LCOMMUNITY_H

/* Extended communities attribute string format.  */
#define LCOMMUNITY_FORMAT_ROUTE_MAP            0
#define LCOMMUNITY_FORMAT_COMMUNITY_LIST       1
#define LCOMMUNITY_FORMAT_DISPLAY              2

/* Large Communities value is twelve octets long.  */
#define LCOMMUNITY_SIZE                        12

/* Large Communities attribute.  */
struct lcommunity
{
  /* Reference counter.  */
  unsigned long refcnt;

  /* Size of Extended Communities attribute.  */
  int size;

  /* Extended Communities value.  */
  u_int8_t *val;

  /* Human readable format string.  */
  char *str;
};

/* Extended community value is eight octet.  */
struct lcommunity_val
{
  char val[LCOMMUNITY_SIZE];
};

#define lcom_length(X)    ((X)->size * LCOMMUNITY_SIZE)

extern void lcommunity_init (void);
extern void lcommunity_finish (void);
extern void lcommunity_free (struct lcommunity **);
extern struct lcommunity *lcommunity_parse (u_int8_t *, u_short);
extern struct lcommunity *lcommunity_dup (struct lcommunity *);
extern struct lcommunity *lcommunity_merge (struct lcommunity *, struct lcommunity *);
extern struct lcommunity *lcommunity_uniq_sort (struct lcommunity *);
extern struct lcommunity *lcommunity_intern (struct lcommunity *);
extern int lcommunity_cmp (const void *, const void *);
extern void lcommunity_unintern (struct lcommunity **);
extern unsigned int lcommunity_hash_make (void *);
extern struct hash *lcommunity_hash (void);
extern struct lcommunity *lcommunity_str2com (const char *);
extern char *lcommunity_lcom2str (struct lcommunity *, int);
extern int lcommunity_match (const struct lcommunity *, const struct lcommunity *);
extern char *lcommunity_str (struct lcommunity *);
extern int lcommunity_include (struct lcommunity *lcom, u_char *ptr);
extern void lcommunity_del_val (struct lcommunity *lcom, u_char *ptr);
#endif /* _QUAGGA_BGP_LCOMMUNITY_H */
