/* BGP dump to ascii converter
   Copyright (C) 1999 Kunihiro Ishiguro

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

#include <zebra.h>

#include "zebra.h"
#include "stream.h"
#include "log.h"
#include "prefix.h"
#include "command.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"

enum MRT_MSG_TYPES {
   MSG_NULL,
   MSG_START,                   /* sender is starting up */
   MSG_DIE,                     /* receiver should shut down */
   MSG_I_AM_DEAD,               /* sender is shutting down */
   MSG_PEER_DOWN,               /* sender's peer is down */
   MSG_PROTOCOL_BGP,            /* msg is a BGP packet */
   MSG_PROTOCOL_RIP,            /* msg is a RIP packet */
   MSG_PROTOCOL_IDRP,           /* msg is an IDRP packet */
   MSG_PROTOCOL_RIPNG,          /* msg is a RIPNG packet */
   MSG_PROTOCOL_BGP4PLUS,       /* msg is a BGP4+ packet */
   MSG_PROTOCOL_BGP4PLUS_01,    /* msg is a BGP4+ (draft 01) packet */
   MSG_PROTOCOL_OSPF,           /* msg is an OSPF packet */
   MSG_TABLE_DUMP               /* routing table dump */
};

int
attr_parse (struct stream *s, u_int16_t len)
{
  u_int flag;
  u_int type;
  u_int16_t length;
  u_int16_t lim;

  lim = s->getp + len;

  printf ("attr_parse s->getp %d, len %d, lim %d\n", s->getp, len, lim);

  while (s->getp < lim)
    {
      flag = stream_getc (s);
      type = stream_getc (s);

      if (flag & ATTR_FLAG_EXTLEN)
	length = stream_getw (s);
      else
	length = stream_getc (s);

      printf ("FLAG: %d\n", flag);
      printf ("TYPE: %d\n", type);
      printf ("Len: %d\n", length);

      switch (type)
	{
	case BGP_ATTR_ORIGIN:
	  {
	    u_char origin;
	    origin = stream_getc (s);
	    printf ("ORIGIN: %d\n", origin);
	  }
	  break;
	case BGP_ATTR_AS_PATH:
	  {
	    struct aspath aspath;

	    aspath.data = (s->data + s->getp);
	    aspath.length = length;
	    aspath.str = aspath_make_str_count (&aspath);
	    printf ("ASPATH: %s\n", aspath.str);
	    free (aspath.str);
	    
	    stream_forward (s, length);
	  }
	  break;
	case BGP_ATTR_NEXT_HOP:	
	  {
	    struct in_addr nexthop;
	    nexthop.s_addr = stream_get_ipv4 (s);
	    printf ("NEXTHOP: %s\n", inet_ntoa (nexthop));
	    /* stream_forward (s, length); */
	  }
	  break;
	default:
	  stream_forward (s, length);
	  break;
	}
    }

  return 0;
}

int
main (int argc, char **argv)
{
  int ret;
  FILE *fp;
  struct stream *s;
  time_t now;
  int type;
  int subtype;
  int len;
  int source_as;
  int dest_as;
  int ifindex;
  int family;
  struct in_addr sip;
  struct in_addr dip;
  u_int16_t viewno, seq_num;
  struct prefix_ipv4 p;

  s = stream_new (10000);

  if (argc != 2)
    {
      fprintf (stderr, "Usage: %s FILENAME\n", argv[0]);
      exit (1);
    }
  fp = fopen (argv[1], "r");
  if (!fp)
    {
      perror ("fopen");
      exit (1);
    }
  
  while (1)
    {
      stream_reset (s);

      ret = fread (s->data, 12, 1, fp);
      if (feof (fp))
	{
	  printf ("END OF FILE\n");
	  break;
	}
      if (ferror (fp))
	{
	  printf ("ERROR OF FREAD\n");
	  break;
	}

      /* Extract header. */
      now = stream_getl (s);
      type = stream_getw (s);
      subtype = stream_getw (s);
      len = stream_getl (s);

      printf ("TIME: %s", ctime (&now));

      /* printf ("TYPE: %d/%d\n", type, subtype); */

      if (type == MSG_PROTOCOL_BGP4MP)
	printf ("TYPE: BGP4MP");
      else if (type == MSG_TABLE_DUMP)
	printf ("TYPE: MSG_TABLE_DUMP");
      else
	printf ("TYPE: Unknown %d", type);

      if (type == MSG_TABLE_DUMP)
	switch (subtype)
	  {
	  case AFI_IP:
	    printf ("/AFI_IP\n");
	    break;
	  case AFI_IP6:
	    printf ("/AFI_IP6\n");
	    break;
	  default:
	    printf ("/UNKNOWN %d", subtype);
	    break;
	  }
      else
	{
	  switch (subtype)
	    {
	    case BGP4MP_STATE_CHANGE:
	      printf ("/CHANGE\n");
	      break;
	    case BGP4MP_MESSAGE:
	      printf ("/MESSAGE\n");
	      break;
	    case BGP4MP_ENTRY:
	      printf ("/ENTRY\n");
	      break;
	    case BGP4MP_SNAPSHOT:
	      printf ("/SNAPSHOT\n");
	      break;
	    default:
	      printf ("/UNKNOWN %d", subtype);
	      break;
	    }
	}

      printf ("len: %d\n", len);

      ret = fread (s->data + 12, len, 1, fp);
      if (feof (fp))
	{
	  printf ("ENDOF FILE 2\n");
	  break;
	}
      if (ferror (fp))
	{
	  printf ("ERROR OF FREAD 2\n");
	  break;
	}

      /* printf ("now read %d\n", len); */

      if (type == MSG_TABLE_DUMP)
	{
	  u_char status;
	  time_t originated;
	  struct in_addr peer;
	  u_int16_t attrlen;

	  viewno = stream_getw (s);
	  seq_num = stream_getw (s);
	  printf ("VIEW: %d\n", viewno);
	  printf ("SEQUENCE: %d\n", seq_num);

	  /* start */
	  while (s->getp < len - 16)
	    {
	      p.prefix.s_addr = stream_get_ipv4 (s);
	      p.prefixlen = stream_getc (s);
	      printf ("PREFIX: %s/%d\n", inet_ntoa (p.prefix), p.prefixlen);

	      status = stream_getc (s);
	      originated = stream_getl (s);
	      peer.s_addr = stream_get_ipv4 (s);
	      source_as = stream_getw(s);

	      printf ("FROM: %s AS%d\n", inet_ntoa (peer), source_as);
	      printf ("ORIGINATED: %s", ctime (&originated));

	      attrlen = stream_getw (s);
	      printf ("ATTRLEN: %d\n", attrlen);

	      attr_parse (s, attrlen);

	      printf ("STATUS: 0x%x\n", status);
	    }
	}
      else
	{
	  source_as = stream_getw (s);
	  dest_as = stream_getw (s);
	  printf ("source_as: %d\n", source_as);
	  printf ("dest_as: %d\n", dest_as);

	  ifindex = stream_getw (s);
	  family = stream_getw (s);

	  printf ("ifindex: %d\n", ifindex);
	  printf ("family: %d\n", family);

	  sip.s_addr = stream_get_ipv4 (s);
	  dip.s_addr = stream_get_ipv4 (s);
	  
	  printf ("saddr: %s\n", inet_ntoa (sip));
	  printf ("daddr: %s\n", inet_ntoa (dip));

	  printf ("\n");
	}
    }
  fclose (fp);
  return 0;
}
