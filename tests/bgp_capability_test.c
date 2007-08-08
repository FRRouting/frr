#include <zebra.h>

#include "vty.h"
#include "stream.h"
#include "privs.h"
#include "memory.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_debug.h"

#define OPEN	0
#define DYNCAP	1

/* need these to link in libbgp */
struct zebra_privs_t *bgpd_privs = NULL;
struct thread_master *master = NULL;

static int failed = 0;

/* test segments to parse and validate, and use for other tests */
static struct test_segment {
  const char *name;
  const char *desc;
  const u_char data[1024];
  int len;
#define SHOULD_PARSE	0
#define SHOULD_ERR	-1
  int parses; /* whether it should parse or not */
} test_segments [] = 
{
  /* 0 */
  { "caphdr", 
    "capability header, and no more",
    { CAPABILITY_CODE_REFRESH, 0x0 },
    2, SHOULD_PARSE,
  },
  /* 1 */
  { "nodata",
    "header, no data but length says there is",
    { 0x1, 0xa },
    2, SHOULD_ERR,
  },
  /* 2 */
  { "padded",
    "valid, with padding",
    { CAPABILITY_CODE_REFRESH, 0x2, 0x0, 0x0 },
    4, SHOULD_PARSE,
  },
  /* 3 */
  { "minsize",
    "violates minsize requirement",
    { CAPABILITY_CODE_ORF, 0x2, 0x0, 0x0 },
    4, SHOULD_ERR,
  },
  /* 4 */
  { "MP1",
    "MP IP/Uni",
    { 0x1, 0x4, 0x0, 0x1, 0x0, 0x1 },
    6, SHOULD_PARSE,
  },
  /* 5 */
  { "MP2",
    "MP IP/Multicast",
    { CAPABILITY_CODE_MP, 0x4, 0x0, 0x1, 0x0, 0x2 },
    6, SHOULD_PARSE,
  },
  /* 6 */
  { "MP3",
    "MP IP6/VPNv4",
    { CAPABILITY_CODE_MP, 0x4, 0x0, 0x2, 0x0, 0x80 },
    6, SHOULD_PARSE, /* parses, but invalid afi,safi */
  },
  /* 7 */
  { "MP5",
    "MP IP6/MPLS-VPN",
    { CAPABILITY_CODE_MP, 0x4, 0x0, 0x2, 0x0, 0x4 },
    6, SHOULD_PARSE,
  },
  /* 8 */
  { "MP6",
    "MP IP4/VPNv4",
    { CAPABILITY_CODE_MP, 0x4, 0x0, 0x1, 0x0, 0x80 },
    6, SHOULD_PARSE,
  },  
  /* 9 */
  { "MP7",
    "MP IP4/VPNv6",
    { CAPABILITY_CODE_MP, 0x4, 0x0, 0x1, 0x0, 0x81 },
    6, SHOULD_PARSE, /* parses, but invalid afi,safi tuple! - manually inspect */
  },
  /* 10 */
  { "MP8",
    "MP unknown AFI",
    { CAPABILITY_CODE_MP, 0x4, 0x0, 0xa, 0x0, 0x81 },
    6, SHOULD_PARSE, /* parses, but unknown */
  },
  /* 11 */
  { "MP-short",
    "MP IP4/Unicast, length too short (< minimum)",
    { CAPABILITY_CODE_MP, 0x2, 0x0, 0x1, 0x0, 0x1 },
    6, SHOULD_ERR,
  },
  /* 12 */
  { "MP-overflow",
    "MP IP4/Unicast, length too long",
    { CAPABILITY_CODE_MP, 0x6, 0x0, 0x1, 0x0, 0x1 },
    6, SHOULD_ERR,
  },
  /* 13 */
  { "ORF",
    "ORF, simple, single entry, single tuple",
    { /* hdr */		CAPABILITY_CODE_ORF, 0x7, 
      /* mpc */		0x0, 0x1, 0x0, 0x1, 
      /* num */		0x1, 
      /* tuples */	0x40, 0x3
    },
    9, SHOULD_PARSE,
  },
  /* 14 */
  { "ORF-many",
    "ORF, multi entry/tuple",
    { /* hdr */		CAPABILITY_CODE_ORF, 0x21,
      /* mpc */		0x0, 0x1, 0x0, 0x1, 
      /* num */		0x3, 
      /* tuples */	0x40, ORF_MODE_BOTH,
                        0x80, ORF_MODE_RECEIVE,
                        0x80, ORF_MODE_SEND,
      /* mpc */		0x0, 0x2, 0x0, 0x1, 
      /* num */		0x3, 
      /* tuples */	0x40, ORF_MODE_BOTH,
                        0x80, ORF_MODE_RECEIVE,
                        0x80, ORF_MODE_SEND,
      /* mpc */		0x0, 0x2, 0x0, 0x2,
      /* num */		0x3, 
      /* tuples */	0x40, ORF_MODE_RECEIVE,
                        0x80, ORF_MODE_SEND,
                        0x80, ORF_MODE_BOTH,
    },
    35, SHOULD_PARSE,
  },
  /* 15 */
  { "ORFlo",
    "ORF, multi entry/tuple, hdr length too short",
    { /* hdr */		CAPABILITY_CODE_ORF, 0x15,
      /* mpc */		0x0, 0x1, 0x0, 0x1, 
      /* num */		0x3, 
      /* tuples */	0x40, 0x3,
                        0x80, 0x1,
                        0x80, 0x2,
      /* mpc */		0x0, 0x1, 0x0, 0x1, 
      /* num */		0x3, 
      /* tuples */	0x40, 0x3,
                        0x80, 0x1,
                        0x80, 0x2,
      /* mpc */		0x0, 0x2, 0x0, 0x2,
      /* num */		0x3, 
      /* tuples */	0x40, 0x3,
                        0x80, 0x1,
                        0x80, 0x2,
    },
    35, SHOULD_ERR, /* It should error on invalid Route-Refresh.. */
  },
  /* 16 */
  { "ORFlu",
    "ORF, multi entry/tuple, length too long",
    { /* hdr */		0x3, 0x22,
      /* mpc */		0x0, 0x1, 0x0, 0x1, 
      /* num */		0x3, 
      /* tuples */	0x40, 0x3,
                        0x80, 0x1,
                        0x80, 0x2,
      /* mpc */		0x0, 0x2, 0x0, 0x1, 
      /* num */		0x3, 
      /* tuples */	0x40, 0x3,
                        0x80, 0x1,
                        0x80, 0x2,
      /* mpc */		0x0, 0x2, 0x0, 0x2,
      /* num */		0x3, 
      /* tuples */	0x40, 0x3,
                        0x80, 0x1,
                        0x80, 0x2,
    },
    35, SHOULD_ERR
  },
  /* 17 */
  { "ORFnu",
    "ORF, multi entry/tuple, entry number too long",
    { /* hdr */		0x3, 0x21,
      /* mpc */		0x0, 0x1, 0x0, 0x1, 
      /* num */		0x3, 
      /* tuples */	0x40, 0x3,
                        0x80, 0x1,
                        0x80, 0x2,
      /* mpc */		0x0, 0x2, 0x0, 0x1, 
      /* num */		0x4, 
      /* tuples */	0x40, 0x3,
                        0x80, 0x1,
                        0x80, 0x2,
      /* mpc */		0x0, 0x2, 0x0, 0x2,
      /* num */		0x3, 
      /* tuples */	0x40, 0x3,
                        0x80, 0x1,
                        0x80, 0x2,
    },
    35, SHOULD_PARSE, /* parses, but last few tuples should be gibberish */
  },
  /* 18 */
  { "ORFno",
    "ORF, multi entry/tuple, entry number too short",
    { /* hdr */		0x3, 0x21,
      /* mpc */		0x0, 0x1, 0x0, 0x1, 
      /* num */		0x3, 
      /* tuples */	0x40, 0x3,
                        0x80, 0x1,
                        0x80, 0x2,
      /* mpc */		0x0, 0x2, 0x0, 0x1, 
      /* num */		0x1, 
      /* tuples */	0x40, 0x3,
                        0x80, 0x1,
                        0x80, 0x2,
      /* mpc */		0x0, 0x2, 0x0, 0x2,
      /* num */		0x3,
      /* tuples */	0x40, 0x3,
                        0x80, 0x1,
                        0x80, 0x2,
    },
    35, SHOULD_PARSE, /* Parses, but should get gibberish afi/safis */
  },
  /* 17 */
  { "ORFpad",
    "ORF, multi entry/tuple, padded to align",
    { /* hdr */		0x3, 0x22,
      /* mpc */		0x0, 0x1, 0x0, 0x1, 
      /* num */		0x3, 
      /* tuples */	0x40, 0x3,
                        0x80, 0x1,
                        0x80, 0x2,
      /* mpc */		0x0, 0x2, 0x0, 0x1, 
      /* num */		0x3, 
      /* tuples */	0x40, 0x3,
                        0x80, 0x1,
                        0x80, 0x2,
      /* mpc */		0x0, 0x2, 0x0, 0x2,
      /* num */		0x3, 
      /* tuples */	0x40, 0x3,
                        0x80, 0x1,
                        0x80, 0x2,
                        0x00,
    },
    36, SHOULD_PARSE,
  },
  /* 19 */
  { "AS4",
    "AS4 capability",
    { 0x41, 0x4, 0xab, 0xcd, 0xef, 0x12 },
    6, SHOULD_PARSE,
  },
  /* 20 */
  { "GR",
    "GR capability",
    { /* hdr */		CAPABILITY_CODE_RESTART, 0xe,
      /* R-bit, time */	0xf1, 0x12,
      /* afi */		0x0, 0x1,
      /* safi */	0x1,
      /* flags */	0xf,
      /* afi */		0x0, 0x2,
      /* safi */	0x1,
      /* flags */	0x0,
      /* afi */		0x0, 0x2,
      /* safi */	0x2,
      /* flags */	0x1,
    },
    16, SHOULD_PARSE,
  },
  /* 21 */
  { "GR-short",
    "GR capability, but header length too short",
    { /* hdr */		0x40, 0xa,
      /* R-bit, time */	0xf1, 0x12,
      /* afi */		0x0, 0x1,
      /* safi */	0x1,
      /* flags */	0xf,
      /* afi */		0x0, 0x2,
      /* safi */	0x1,
      /* flags */	0x0,
      /* afi */		0x0, 0x2,
      /* safi */	0x2,
      /* flags */	0x1,
    },
    16, SHOULD_PARSE,
  },
  /* 22 */
  { "GR-long",
    "GR capability, but header length too long",
    { /* hdr */		0x40, 0xf,
      /* R-bit, time */	0xf1, 0x12,
      /* afi */		0x0, 0x1,
      /* safi */	0x1,
      /* flags */	0xf,
      /* afi */		0x0, 0x2,
      /* safi */	0x1,
      /* flags */	0x0,
      /* afi */		0x0, 0x2,
      /* safi */	0x2,
    },
    16, SHOULD_ERR,
  },
  { "GR-trunc",
    "GR capability, but truncated",
    { /* hdr */		0x40, 0xf,
      /* R-bit, time */	0xf1, 0x12,
      /* afi */		0x0, 0x1,
      /* safi */	0x1,
      /* flags */	0xf,
      /* afi */		0x0, 0x2,
      /* safi */	0x1,
      /* flags */	0x0,
      /* afi */		0x0, 0x2,
      /* safi */	0x2,
      /* flags */	0x1,
    },
    15, SHOULD_ERR,
  },
  { "dyn-old",
    "Dynamic capability (deprecated version)",
    { CAPABILITY_CODE_DYNAMIC, 0x0 },
    2, SHOULD_PARSE,
  },
  { NULL, NULL, {0}, 0, 0}
};


struct test_segment dynamic_cap_msgs[] = 
{
  { "DynCap",
    "Dynamic Capability Message, IP/Multicast",
    { 0x0, 0x1, 0x4, 0x0, 0x1, 0x0, 0x2 },
      7, SHOULD_PARSE, /* horrible alignment, just as with ORF */
  },
  { "DynCapLong",
    "Dynamic Capability Message, IP/Multicast, truncated",
    { 0x0, 0x1, 0x4, 0x0, 0x1, 0x0, 0x2 },
      5, SHOULD_ERR,
  },
  { "DynCapPadded",
    "Dynamic Capability Message, IP/Multicast, padded",
    { 0x0, 0x1, 0x4, 0x0, 0x1, 0x0, 0x2, 0x0 },
      8, SHOULD_ERR, /* No way to tell padding from data.. */
  },
  { "DynCapMPCpadded",
    "Dynamic Capability Message, IP/Multicast, cap data padded",
    { 0x0, 0x1, 0x5, 0x0, 0x1, 0x0, 0x2, 0x0 },
      8, SHOULD_PARSE, /* You can though add padding to the capability data */
  },
  { "DynCapMPCoverflow",
    "Dynamic Capability Message, IP/Multicast, cap data != length",
    { 0x0, 0x1, 0x3, 0x0, 0x1, 0x0, 0x2, 0x0 },
      8, SHOULD_ERR,
  },
  { NULL, NULL, {0}, 0, 0}
};
/* basic parsing test */
static void
parse_test (struct peer *peer, struct test_segment *t, int type)
{
  int ret;
  int capability = 0;
  
  stream_reset (peer->ibuf);
  switch (type)
    {
      case OPEN:
        stream_putc (peer->ibuf, BGP_OPEN_OPT_CAP);
        stream_putc (peer->ibuf, t->len);
        break;
      case DYNCAP:
/*        for (i = 0; i < BGP_MARKER_SIZE; i++)
          stream_putc (peer->, 0xff);
        stream_putw (s, 0);
        stream_putc (s, BGP_MSG_CAPABILITY);*/
        break;
    }
  stream_write (peer->ibuf, t->data, t->len);
  
  printf ("%s: %s\n", t->name, t->desc);
  
  switch (type)
    {
      case OPEN:
        ret = bgp_open_option_parse (peer, t->len + 2, &capability);
        break;
      case DYNCAP:
        ret = bgp_capability_receive (peer, t->len);
        break;
      default:
        printf ("unknown type %u\n", type);
        exit(1);
    }
  
  printf ("parsed?: %s\n", ret ? "no" : "yes");
  
  if (ret == t->parses)
    printf ("OK\n");
  else
    {
      printf ("failed\n");
      failed++;
    }
  
  printf ("\n");
}

static struct bgp *bgp;
static as_t asn = 100;

int
main (void)
{
  struct peer *peer;
  int i, j;
  
  conf_bgp_debug_fsm = -1UL;
  conf_bgp_debug_events = -1UL;
  conf_bgp_debug_packet = -1UL;
  conf_bgp_debug_normal = -1UL;
  term_bgp_debug_fsm = -1UL;
  term_bgp_debug_events = -1UL;
  term_bgp_debug_packet = -1UL;
  term_bgp_debug_normal = -1UL;
  
  master = thread_master_create ();
  bgp_master_init ();
  
  if (bgp_get (&bgp, &asn, NULL))
    return -1;
  
  peer = peer_create_accept (bgp);
  
  for (i = AFI_IP; i < AFI_MAX; i++)
    for (j = SAFI_UNICAST; j < SAFI_MAX; j++)
      peer->afc_nego[i][j] = 1;
  
  i =0;
  while (test_segments[i].name)   
    parse_test (peer, &test_segments[i++], OPEN);
  
  SET_FLAG (peer->cap, PEER_CAP_DYNAMIC_ADV);
  peer->status = Established;
  
  i = 0;
  while (dynamic_cap_msgs[i].name)
    parse_test (peer, &dynamic_cap_msgs[i++], DYNCAP);
  
  printf ("failures: %d\n", failed);
  return failed;
}
