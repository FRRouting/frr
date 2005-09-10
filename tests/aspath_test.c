#include <zebra.h>

#include "vty.h"
#include "stream.h"
#include "privs.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"

/* need these to link in libbgp */
struct zebra_privs_t *bgpd_privs = NULL;
struct thread_master *master = NULL;

static int failed = 0;

/* specification for a test - what the results should be */
struct test_spec 
{
  const char *shouldbe; /* the string the path should parse to */
  const char *shouldbe_delete_confed; /* ditto, but once confeds are deleted */
  const int hops; /* aspath_count_hops result */
  const int confeds; /* aspath_count_confeds */
  const int private_as; /* whether the private_as check should pass or fail */
#define NOT_ALL_PRIVATE 0
#define ALL_PRIVATE 1
  const as_t does_loop; /* an ASN which should trigger loop-check */
  const as_t doesnt_loop; /* one which should not */
  const as_t first; /* the first ASN, if there is one */
#define NULL_ASN 0
};


/* test segments to parse and validate, and use for other tests */
static struct test_segment {
  const char *name;
  const char *desc;
  const u_char asdata[1024];
  int len;
  struct test_spec sp;
} test_segments [] = 
{
  { /* 0 */ 
    "seq1",
    "seq(8466,3,52737,4096)",
    { 0x2,0x4, 0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00 },
    10,
    { "8466 3 52737 4096",
      "8466 3 52737 4096",
      4, 0, NOT_ALL_PRIVATE, 4096, 4, 8466 },
  },
  { /* 1 */
    "seq2",
    "seq(8722) seq(4)",
    { 0x2,0x1, 0x22,0x12,
      0x2,0x1, 0x00,0x04 },
    8,
    { "8722 4",
      "8722 4",
      2, 0, NOT_ALL_PRIVATE, 4, 5, 8722, },
  },
  { /* 2 */
    "seq3",
    "seq(8466,3,52737,4096,8722,4)",
    { 0x2,0x6, 0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 
               0x22,0x12, 0x00,0x04},
    14,
    { "8466 3 52737 4096 8722 4",
      "8466 3 52737 4096 8722 4",
       6, 0, NOT_ALL_PRIVATE, 3, 5, 8466 },
  },
  { /* 3 */
    "seqset",
    "seq(8482,51457) set(5204)",
    { 0x2,0x2, 0x21,0x22, 0xc9,0x01,
      0x1,0x1, 0x14,0x54 },
    10,
    { "8482 51457 {5204}",
      "8482 51457 {5204}",
      3, 0, NOT_ALL_PRIVATE, 5204, 51457, 8482},
  },
  { /* 4 */
    "seqset2",
    "seq(8467, 59649) set(4196,48658) set(17322,30745)",
    { 0x2,0x2, 0x21,0x13, 0xe9,0x01,
      0x1,0x2, 0x10,0x64, 0xbe,0x12,
      0x1,0x2, 0x43,0xaa, 0x78,0x19 },    
    18,
    { "8467 59649 {4196,48658} {17322,30745}",
      "8467 59649 {4196,48658} {17322,30745}",
      4, 0, NOT_ALL_PRIVATE, 48658, 1, 8467},
  },
  { /* 5 */
    "multi",
    "seq(6435,59408,21665) set(2457,61697,4369), seq(1842,41590,51793)",
    { 0x2,0x3, 0x19,0x23, 0xe8,0x10, 0x54,0xa1,
      0x1,0x3, 0x09,0x99, 0xf1,0x01, 0x11,0x11,
      0x2,0x3, 0x07,0x32, 0xa2,0x76, 0xca,0x51 },
    24,
    { "6435 59408 21665 {2457,4369,61697} 1842 41590 51793",
      "6435 59408 21665 {2457,4369,61697} 1842 41590 51793",
      7, 0, NOT_ALL_PRIVATE, 51793, 1, 6435 },
  },
  { /* 6 */
    "confed",
    "confseq(123,456,789)",
    { 0x3,0x3, 0x00,0x7b, 0x01,0xc8, 0x03,0x15 },
    8,
    { "(123 456 789)",
      "",
      0, 3, NOT_ALL_PRIVATE, 789, 1, NULL_ASN },
  },
  { /* 7 */
    "confed2",
    "confseq(123,456,789) confseq(111,222)",
    { 0x3,0x3, 0x00,0x7b, 0x01,0xc8, 0x03,0x15,
      0x3,0x2, 0x00,0x6f, 0x00,0xde },
    14,
    { "(123 456 789) (111 222)",
      "",
      0, 5, NOT_ALL_PRIVATE, 111, 1, NULL_ASN },
  },
  { /* 8 */
    "confset",
    "confset(456,123,789)",
    { 0x4,0x3, 0x01,0xc8, 0x00,0x7b, 0x03,0x15 },
    8,
    { "[123,456,789]",
      "[123,456,789]",
      0, 1, NOT_ALL_PRIVATE, 123, 1, NULL_ASN },
  },
  { /* 9 */
    "confmulti",
    "confseq(123,456,789) confset(222,111) seq(8722) set(4196,48658)",
    { 0x3,0x3, 0x00,0x7b, 0x01,0xc8, 0x03,0x15,
      0x4,0x2, 0x00,0xde, 0x00,0x6f,
      0x2,0x1, 0x22,0x12,
      0x1,0x2, 0x10,0x64, 0xbe,0x12 },
    24,
    { "(123 456 789) [111,222] 8722 {4196,48658}",
      "8722 {4196,48658}",
      2, 4, NOT_ALL_PRIVATE, 123, 1, NULL_ASN },
  },
  { /* 10 */
    "seq4",
    "seq(8466,2,52737,4096,8722,4)",
    { 0x2,0x6, 0x21,0x12, 0x00,0x02, 0xce,0x01, 0x10,0x00, 
               0x22,0x12, 0x00,0x04},
    14,
    { "8466 2 52737 4096 8722 4",
      "8466 2 52737 4096 8722 4",
      6, 0, NOT_ALL_PRIVATE, 4096, 1, 8466 },
  },
  { /* 11 */
    "tripleseq1",
    "seq(8466,2,52737) seq(4096,8722,4) seq(8722)",
    { 0x2,0x3, 0x21,0x12, 0x00,0x02, 0xce,0x01, 
      0x2,0x3, 0x10,0x00, 0x22,0x12, 0x00,0x04,
      0x2,0x1, 0x22,0x12},
    20,
    { "8466 2 52737 4096 8722 4 8722",
      "8466 2 52737 4096 8722 4 8722",
      7, 0, NOT_ALL_PRIVATE, 4096, 1, 8466 },
  },
  { /* 12 */ 
    "someprivate",
    "seq(8466,64512,52737,65535)",
    { 0x2,0x4, 0x21,0x12, 0xfc,0x00, 0xce,0x01, 0xff,0xff },
    10,
    { "8466 64512 52737 65535",
      "8466 64512 52737 65535",
      4, 0, NOT_ALL_PRIVATE, 65535, 4, 8466 },
  },
  { /* 13 */ 
    "allprivate",
    "seq(65534,64512,64513,65535)",
    { 0x2,0x4, 0xff,0xfe, 0xfc,0x00, 0xfc,0x01, 0xff,0xff },
    10,
    { "65534 64512 64513 65535",
      "65534 64512 64513 65535",
      4, 0, ALL_PRIVATE, 65534, 4, 65534 },
  },
  { /* 14 */ 
    "long",
    "seq(8466,3,52737,4096,34285,<repeated 49 more times>)",
    { 0x2,0xfa, 0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed,
                0x21,0x12, 0x00,0x03, 0xce,0x01, 0x10,0x00, 0x85,0xed, },
    502,
    { "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285",
      
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285",
      250, 0, NOT_ALL_PRIVATE, 4096, 4, 8466 },
  },
  { NULL, NULL, {0}, 0, { NULL, 0, 0 } }
};

/* prepending tests */
static struct tests {
  const struct test_segment *test1;
  const struct test_segment *test2;
  struct test_spec sp;
} prepend_tests[] = 
{
  { &test_segments[0], &test_segments[1],
    { "8466 3 52737 4096 8722 4",
      "8466 3 52737 4096 8722 4",
      6, 0, NOT_ALL_PRIVATE, 4096, 1, 8466 },
  },
  { &test_segments[1], &test_segments[3],
    { "8722 4 8482 51457 {5204}",
      "8722 4 8482 51457 {5204}",
      5, 0, NOT_ALL_PRIVATE, 5204, 1, 8722 }
  },
  { &test_segments[3], &test_segments[4],
    { "8482 51457 {5204} 8467 59649 {4196,48658} {17322,30745}",
      "8482 51457 {5204} 8467 59649 {4196,48658} {17322,30745}",
      7, 0, NOT_ALL_PRIVATE, 5204, 1, 8482 },
  },
  { &test_segments[4], &test_segments[5],
    { "8467 59649 {4196,48658} {17322,30745} 6435 59408 21665"
      " {2457,4369,61697} 1842 41590 51793",
      "8467 59649 {4196,48658} {17322,30745} 6435 59408 21665"
      " {2457,4369,61697} 1842 41590 51793",
      11, 0, NOT_ALL_PRIVATE, 61697, 1, 8467 }
  },
  { &test_segments[5], &test_segments[6],
    { "6435 59408 21665 {2457,4369,61697} 1842 41590 51793 (123 456 789)",
      "6435 59408 21665 {2457,4369,61697} 1842 41590 51793 (123 456 789)",
      7, 3, NOT_ALL_PRIVATE, 123, 1, 6435 },
  },
  { &test_segments[6], &test_segments[7],
    { "(123 456 789) (123 456 789) (111 222)",
      "",
      0, 8, NOT_ALL_PRIVATE, 111, 1, 0 }
  },
  { &test_segments[7], &test_segments[8],
    { "(123 456 789) (111 222) [123,456,789]",
      "",
      0, 6, NOT_ALL_PRIVATE, 111, 1, 0 }
  },
  { &test_segments[8], &test_segments[9],
    { "[123,456,789] (123 456 789) [111,222] 8722 {4196,48658}",
      "[123,456,789] (123 456 789) [111,222] 8722 {4196,48658}",
      2, 5, NOT_ALL_PRIVATE, 456, 1, NULL_ASN },
  },
  { &test_segments[9], &test_segments[8],
    { "(123 456 789) [111,222] 8722 {4196,48658} [123,456,789]",
      "8722 {4196,48658} [123,456,789]",
      2, 5, NOT_ALL_PRIVATE, 48658, 1, NULL_ASN },
  },
  { &test_segments[14], &test_segments[11],
    { "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 2 52737 4096 8722 4 8722",
      
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 3 52737 4096 34285 8466 3 52737 4096 34285 "
      "8466 2 52737 4096 8722 4 8722",
      257, 0, NOT_ALL_PRIVATE, 4096, 1000, 8466 },
  },
  { NULL, NULL, { NULL, 0, 0, 0, 0, 0, 0, } },
};

struct tests aggregate_tests[] =
{
  { &test_segments[0], &test_segments[1],
    { "{3,4,4096,8466,8722,52737}",
      "{3,4,4096,8466,8722,52737}",
      1, 0, NOT_ALL_PRIVATE, 52737, 1, NULL_ASN },
  },
  { &test_segments[0], &test_segments[2],
    { "8466 3 52737 4096 {4,8722}",
      "8466 3 52737 4096 {4,8722}",
      5, 0, NOT_ALL_PRIVATE, 4, 1, 8466 },
  },
  { &test_segments[2], &test_segments[0],
    { "8466 3 52737 4096 {4,8722}",
      "8466 3 52737 4096 {4,8722}",
      5, 0, NOT_ALL_PRIVATE, 8722, 1, 8466 },
  },
  { &test_segments[2], &test_segments[10],
    { "8466 {2,3,4,4096,8722,52737}",
      "8466 {2,3,4,4096,8722,52737}",
      2, 0, NOT_ALL_PRIVATE, 8722, 5, 8466 },
  },
  { &test_segments[10], &test_segments[2],
    { "8466 {2,3,4,4096,8722,52737}",
      "8466 {2,3,4,4096,8722,52737}",
      2, 0, NOT_ALL_PRIVATE, 2, 20000, 8466 },
  },
  { NULL, NULL, { NULL, 0, 0}  },
};

struct compare_tests 
{
  int test_index1;
  int test_index2;
#define CMP_RES_YES 1
#define CMP_RES_NO 0
  char shouldbe_cmp;
  char shouldbe_confed;
} left_compare [] =
{
  { 0, 1, CMP_RES_NO, CMP_RES_NO },
  { 0, 2, CMP_RES_YES, CMP_RES_NO },
  { 0, 11, CMP_RES_YES, CMP_RES_NO },
  { 1, 11, CMP_RES_NO, CMP_RES_NO },
  { 6, 7, CMP_RES_NO, CMP_RES_YES },
  { 6, 8, CMP_RES_NO, CMP_RES_NO },
  { 7, 8, CMP_RES_NO, CMP_RES_NO },
  { 1, 9, CMP_RES_YES, CMP_RES_NO },
  { 0, 9, CMP_RES_NO, CMP_RES_NO },
  { 3, 9, CMP_RES_NO, CMP_RES_NO },
  { 0, 6, CMP_RES_NO, CMP_RES_NO },
  { 1, 6, CMP_RES_NO, CMP_RES_NO },
  { 0, 8, CMP_RES_NO, CMP_RES_NO },
  { 1, 8, CMP_RES_NO, CMP_RES_NO },
  { 11, 6, CMP_RES_NO, CMP_RES_NO },
  { 11, 7, CMP_RES_NO, CMP_RES_NO },
  { 11, 8, CMP_RES_NO, CMP_RES_NO },
  { 9, 6, CMP_RES_NO, CMP_RES_YES },
  { 9, 7, CMP_RES_NO, CMP_RES_YES },
  { 9, 8, CMP_RES_NO, CMP_RES_NO },
};

/* make an aspath from a data stream */
static struct aspath *
make_aspath (const u_char *data, size_t len)
{
  struct stream *s = NULL;
  struct aspath *as;
  
  if (len)
    {
      s = stream_new (len);
      stream_put (s, data, len);
    }
  as = aspath_parse (s, len);
  stream_free (s);
  
  return as;
}

static void
printbytes (const u_char *bytes, int len)
{
  int i = 0;
  while (i < len)
    {
      if (i % 2)
        printf ("%02hhx%s", bytes[i], " ");
      else
        printf ("0x%02hhx", bytes[i]);
      i++;
    }
  printf ("\n");
}  

/* validate the given aspath */
static int
validate (struct aspath *as, const struct test_spec *sp)
{
  size_t bytes;
  int fails = 0;
  const u_char *out;
  struct aspath *asinout, *asconfeddel, *asstr;
  
  out = aspath_snmp_pathseg (as, &bytes);
  asinout = make_aspath (out, bytes);
  
  asstr = aspath_str2aspath (sp->shouldbe);
  
  asconfeddel = aspath_delete_confed_seq (aspath_dup (asinout));
  
  /* the parsed path should match the specified 'shouldbe' string.
   * We should pass the "eat our own dog food" test, be able to output
   * this path and then input it again. Ie the path resulting from:
   *
   *   aspath_parse(aspath_put(as)) 
   *
   * should:
   *
   * - also match the specified 'shouldbe' value
   * - hash to same value as original path
   * - have same hops and confed counts as original, and as the
   *   the specified counts
   *
   * aspath_str2aspath() and shouldbe should match
   *
   * Confederation related tests: 
   * - aspath_delete_confed_seq(aspath) should match shouldbe_confed
   * - aspath_delete_confed_seq should be idempotent.
   */
  if (strcmp(aspath_print (as), sp->shouldbe)
         /* hash validation */
      || (aspath_key_make (as) != aspath_key_make (asinout))
         /* by string */
      || strcmp(aspath_print (asinout), sp->shouldbe)
         /* by various path counts */
      || (aspath_count_hops (as) != sp->hops)
      || (aspath_count_confeds (as) != sp->confeds)
      || (aspath_count_hops (asinout) != sp->hops)
      || (aspath_count_confeds (asinout) != sp->confeds))
    {
      failed++;
      fails++;
      printf ("shouldbe:\n%s\n", sp->shouldbe);
      printf ("got:\n%s\n", aspath_print(as));
      printf ("hash keys: in: %d out->in: %d\n", 
              aspath_key_make (as), aspath_key_make (asinout));
      printf ("hops: %d, counted %d %d\n", sp->hops, 
              aspath_count_hops (as),
              aspath_count_hops (asinout) );
      printf ("confeds: %d, counted %d %d\n", sp->confeds,
              aspath_count_confeds (as),
              aspath_count_confeds (asinout));
      printf ("out->in:\n%s\nbytes: ", aspath_print(asinout));
      printbytes (out, bytes);
    }
         /* basic confed related tests */
  if ((aspath_print (asconfeddel) == NULL 
          && sp->shouldbe_delete_confed != NULL)
      || (aspath_print (asconfeddel) != NULL 
          && sp->shouldbe_delete_confed == NULL)
      || strcmp(aspath_print (asconfeddel), sp->shouldbe_delete_confed)
         /* delete_confed_seq should be idempotent */
      || (aspath_key_make (asconfeddel) 
          != aspath_key_make (aspath_delete_confed_seq (asconfeddel))))
    {
      failed++;
      fails++;
      printf ("confed_del: %s\n", aspath_print (asconfeddel));
      printf ("should be: %s\n", sp->shouldbe_delete_confed);
    }
      /* aspath_str2aspath test */
  if ((aspath_print (asstr) == NULL && sp->shouldbe != NULL)
      || (aspath_print (asstr) != NULL && sp->shouldbe == NULL)
      || strcmp(aspath_print (asstr), sp->shouldbe))
    {
      failed++;
      fails++;
      printf ("asstr: %s\n", aspath_print (asstr));
    }
  
    /* loop, private and first as checks */
  if (aspath_loop_check (as, sp->does_loop)
      || aspath_loop_check (as, sp->doesnt_loop)
      || (aspath_private_as_check (as) != sp->private_as)
      || (aspath_firstas_check (as,sp->first)
          && sp->first == 0))
    {
      failed++;
      fails++;
      printf ("firstas: %d,  got %d\n", sp->first,
              aspath_firstas_check (as,sp->first));
      printf ("loop does: %d %d, doesnt: %d %d\n",
              sp->does_loop, aspath_loop_check (as, sp->does_loop),
              sp->doesnt_loop, aspath_loop_check (as, sp->doesnt_loop));
      printf ("private check: %d %d\n", sp->private_as,
              aspath_private_as_check (as));
    }
  aspath_unintern (asinout);
 /* aspath_unintern (asconfeddel);*/
  return fails;
  
}

static void
empty_get_test ()
{
  struct aspath *as = aspath_empty_get ();
  struct test_spec sp = { "", "", 0, 0, 0, 0, 0, 0 };

  printf ("empty_get_test, as: %s\n",aspath_print (as));
  if (!validate (as, &sp))
    printf ("OK\n");
  else
    printf ("failed!\n");
  
  printf ("\n");
}

/* basic parsing test */
static void
parse_test (struct test_segment *t)
{
  struct aspath *asp;
  
  printf ("%s: %s\n", t->name, t->desc);

  asp = make_aspath (t->asdata, t->len);

  printf ("aspath: %s\nvalidating...:\n", aspath_print (asp));

  if (!validate (asp, &t->sp))
    printf ("OK\n");
  else
    printf ("failed\n");
  
  printf ("\n");
  aspath_unintern (asp);
}

/* prepend testing */
void
prepend_test (struct tests *t)
{
  struct aspath *asp1, *asp2, *ascratch;
  
  printf ("prepend %s: %s\n", t->test1->name, t->test1->desc);
  printf ("to %s: %s\n", t->test2->name, t->test2->desc);
  
  asp1 = make_aspath (t->test1->asdata, t->test1->len);
  asp2 = make_aspath (t->test2->asdata, t->test2->len);
  
  ascratch = aspath_dup (asp2);
  aspath_unintern (asp2);
  
  asp2 = aspath_prepend (asp1, ascratch);
  
  printf ("aspath: %s\n", aspath_print (asp2));
  
  if (!validate (asp2, &t->sp))
    printf ("OK\n");
  else
    printf ("failed!\n");
  
  printf ("\n");
  aspath_unintern (asp1);
  aspath_free (asp2);
}

/* empty-prepend testing */
void
empty_prepend_test (struct test_segment *t)
{
  struct aspath *asp1, *asp2, *ascratch;
  
  printf ("empty prepend %s: %s\n", t->name, t->desc);
  
  asp1 = make_aspath (t->asdata, t->len);
  asp2 = aspath_empty ();
  
  ascratch = aspath_dup (asp2);
  aspath_unintern (asp2);
  
  asp2 = aspath_prepend (asp1, ascratch);
  
  printf ("aspath: %s\n", aspath_print (asp2));
  
  if (!validate (asp2, &t->sp))
    printf ("OK\n");
  else
    printf ("failed!\n");
  
  printf ("\n");
  aspath_unintern (asp1);
  aspath_free (asp2);
}

/* aggregation testing */
void
aggregate_test (struct tests *t)
{
  struct aspath *asp1, *asp2, *ascratch;
  
  printf ("aggregate %s: %s\n", t->test1->name, t->test1->desc);
  printf ("with %s: %s\n", t->test2->name, t->test2->desc);
  
  asp1 = make_aspath (t->test1->asdata, t->test1->len);
  asp2 = make_aspath (t->test2->asdata, t->test2->len);
  
  ascratch = aspath_aggregate (asp1, asp2);
  
  printf ("aspath: %s\n", aspath_print (ascratch));
  
  if (!validate (ascratch, &t->sp))
    printf ("OK\n");
  else
    printf ("failed!\n");
  
  printf ("\n");
  aspath_unintern (asp1);
  aspath_unintern (asp2);
  aspath_free (ascratch);
/*  aspath_unintern (ascratch);*/
}

/* cmp_left tests  */
static void
cmp_test ()
{
  int i;
#define CMP_TESTS_MAX \
  (sizeof(left_compare) / sizeof (struct compare_tests))

  for (i = 0; i < CMP_TESTS_MAX; i++)
    {
      struct test_segment *t1 = &test_segments[left_compare[i].test_index1];
      struct test_segment *t2 = &test_segments[left_compare[i].test_index2];
      struct aspath *asp1, *asp2;
      
      printf ("left cmp %s: %s\n", t1->name, t1->desc);
      printf ("and %s: %s\n", t2->name, t2->desc);
      
      asp1 = make_aspath (t1->asdata, t1->len);
      asp2 = make_aspath (t2->asdata, t2->len);
      
      if (aspath_cmp_left (asp1, asp2) != left_compare[i].shouldbe_cmp
          || aspath_cmp_left (asp2, asp1) != left_compare[i].shouldbe_cmp
          || aspath_cmp_left_confed (asp1, asp2) 
               != left_compare[i].shouldbe_confed
          || aspath_cmp_left_confed (asp2, asp1) 
               != left_compare[i].shouldbe_confed)
        {
          printf ("failed\n");
          printf ("result should be: cmp: %d, confed: %d\n", 
                  left_compare[i].shouldbe_cmp,
                  left_compare[i].shouldbe_confed);
          printf ("got: cmp %d, cmp_confed: %d\n",
                  aspath_cmp_left (asp1, asp2),
                  aspath_cmp_left_confed (asp1, asp2));
          printf("path1: %s\npath2: %s\n", aspath_print (asp1),
                 aspath_print (asp2));
          failed++;
        }
      else
        printf ("OK\n");
      
      printf ("\n");
      aspath_unintern (asp1);
      aspath_unintern (asp2);
    }
}
     
int
main (void)
{
  int i = 0;
  aspath_init();
  while (test_segments[i].name)
    {
      parse_test (&test_segments[i]);
      empty_prepend_test (&test_segments[i++]);
    }
  
  i = 0;
  while (prepend_tests[i].test1)
    prepend_test (&prepend_tests[i++]);
  
  i = 0;
  while (aggregate_tests[i].test1)
    aggregate_test (&aggregate_tests[i++]);
  
  cmp_test();
  
  i = 0;
  
  empty_get_test();
  
  printf ("failures: %d\n", failed);
  printf ("aspath count: %ld\n", aspath_count());
  
  return (failed + aspath_count());
}
