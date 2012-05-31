/* OSPFv3 SNMP support
 * Copyright (C) 2004 Yasuhiro Ohara
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#include <zebra.h>

#ifdef HAVE_SNMP

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "log.h"
#include "vty.h"
#include "linklist.h"
#include "smux.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_route.h"
#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_message.h"
#include "ospf6_neighbor.h"
#include "ospf6d.h"
#include "ospf6_snmp.h"

/* OSPFv3-MIB */
#define OSPFv3MIB 1,3,6,1,2,1,191

/* OSPFv3 MIB General Group values. */
#define OSPFv3ROUTERID                   1
#define OSPFv3ADMINSTAT                  2
#define OSPFv3VERSIONNUMBER              3
#define OSPFv3AREABDRRTRSTATUS           4
#define OSPFv3ASBDRRTRSTATUS             5
#define OSPFv3ASSCOPELSACOUNT            6
#define OSPFv3ASSCOPELSACHECKSUMSUM      7
#define OSPFv3ORIGINATENEWLSAS           8
#define OSPFv3RXNEWLSAS                  9
#define OSPFv3EXTLSACOUNT               10
#define OSPFv3EXTAREALSDBLIMIT          11
#define OSPFv3EXITOVERFLOWINTERVAL      12
#define OSPFv3DEMANDEXTENSIONS          13
#define OSPFv3REFERENCEBANDWIDTH        14
#define OSPFv3RESTARTSUPPORT            15
#define OSPFv3RESTARTINTERVAL           16
#define OSPFv3RESTARTSTRICTLSACHECKING  17
#define OSPFv3RESTARTSTATUS             18
#define OSPFv3RESTARTAGE                19
#define OSPFv3RESTARTEXITREASON         20
#define OSPFv3NOTIFICATIONENABLE        21
#define OSPFv3STUBROUTERSUPPORT         22
#define OSPFv3STUBROUTERADVERTISEMENT   23
#define OSPFv3DISCONTINUITYTIME         24
#define OSPFv3RESTARTTIME               25

/* OSPFv3 MIB Area Table values: ospfv3AreaTable */
#define OSPFv3IMPORTASEXTERN             2
#define OSPFv3AREASPFRUNS                3
#define OSPFv3AREABDRRTRCOUNT            4
#define OSPFv3AREAASBDRRTRCOUNT          5
#define OSPFv3AREASCOPELSACOUNT          6
#define OSPFv3AREASCOPELSACKSUMSUM       7
#define OSPFv3AREASUMMARY                8
#define OSPFv3AREAROWSTATUS              9
#define OSPFv3AREASTUBMETRIC            10
#define OSPFv3AREANSSATRANSLATORROLE    11
#define OSPFv3AREANSSATRANSLATORSTATE   12
#define OSPFv3AREANSSATRANSLATORSTABINTERVAL    13
#define OSPFv3AREANSSATRANSLATOREVENTS  14
#define OSPFv3AREASTUBMETRICTYPE        15
#define OSPFv3AREATEENABLED             16

/* OSPFv3 MIB AS Lsdb Table values: ospfv3AsLsdbTable */
#define OSPFv3ASLSDBSEQUENCE             4
#define OSPFv3ASLSDBAGE                  5
#define OSPFv3ASLSDBCHECKSUM             6
#define OSPFv3ASLSDBADVERTISEMENT        7
#define OSPFv3ASLSDBTYPEKNOWN            8

/* OSPFv3 MIB Area Lsdb Table values: ospfv3AreaLsdbTable */
#define OSPFv3AREALSDBSEQUENCE           5
#define OSPFv3AREALSDBAGE                6
#define OSPFv3AREALSDBCHECKSUM           7
#define OSPFv3AREALSDBADVERTISEMENT      8
#define OSPFv3AREALSDBTYPEKNOWN          9

/* OSPFv3 MIB Link Lsdb Table values: ospfv3LinkLsdbTable */
#define OSPFv3LINKLSDBSEQUENCE           6
#define OSPFv3LINKLSDBAGE                7
#define OSPFv3LINKLSDBCHECKSUM           8
#define OSPFv3LINKLSDBADVERTISEMENT      9
#define OSPFv3LINKLSDBTYPEKNOWN         10

/* OSPFv3 MIB Host Table values: ospfv3HostTable */
#define OSPFv3HOSTMETRIC                 3
#define OSPFv3HOSTROWSTATUS              4
#define OSPFv3HOSTAREAID                 5

/* OSPFv3 MIB Interface Table values: ospfv3IfTable */
#define OSPFv3IFAREAID                   3
#define OSPFv3IFTYPE                     4
#define OSPFv3IFADMINSTATUS              5
#define OSPFv3IFRTRPRIORITY              6
#define OSPFv3IFTRANSITDELAY             7
#define OSPFv3IFRETRANSINTERVAL          8
#define OSPFv3IFHELLOINTERVAL            9
#define OSPFv3IFRTRDEADINTERVAL         10
#define OSPFv3IFPOLLINTERVAL            11
#define OSPFv3IFSTATE                   12
#define OSPFv3IFDESIGNATEDROUTER        13
#define OSPFv3IFBACKUPDESIGNATEDROUTER  14
#define OSPFv3IFEVENTS                  15
#define OSPFv3IFROWSTATUS               16
#define OSPFv3IFDEMAND                  17
#define OSPFv3IFMETRICVALUE             18
#define OSPFv3IFLINKSCOPELSACOUNT       19
#define OSPFv3IFLINKLSACKSUMSUM         20
#define OSPFv3IFDEMANDNBRPROBE          21
#define OSPFv3IFDEMANDNBRPROBERETRANSLIMIT 22
#define OSPFv3IFDEMANDNBRPROBEINTERVAL  23
#define OSPFv3IFTEDISABLED              24
#define OSPFv3IFLINKLSASUPPRESSION      25

/* OSPFv3 MIB Virtual Interface Table values: ospfv3VirtIfTable */
#define OSPFv3VIRTIFINDEX           3
#define OSPFv3VIRTIFINSTID          4
#define OSPFv3VIRTIFTRANSITDELAY    5
#define OSPFv3VIRTIFRETRANSINTERVAL 6
#define OSPFv3VIRTIFHELLOINTERVAL   7
#define OSPFv3VIRTIFRTRDEADINTERVAL 8
#define OSPFv3VIRTIFSTATE           9
#define OSPFv3VIRTIFEVENTS         10
#define OSPFv3VIRTIFROWSTATUS      11
#define OSPFv3VIRTIFLINKSCOPELSACOUNT 12
#define OSPFv3VIRTIFLINKLSACKSUMSUM   13

/* OSPFv3 MIB Neighbors Table values: ospfv3NbrTable */
#define OSPFv3NBRADDRESSTYPE      4
#define OSPFv3NBRADDRESS          5
#define OSPFv3NBROPTIONS          6
#define OSPFv3NBRPRIORITY         7
#define OSPFv3NBRSTATE            8
#define OSPFv3NBREVENTS           9
#define OSPFv3NBRLSRETRANSQLEN   10
#define OSPFv3NBRHELLOSUPPRESSED 11
#define OSPFv3NBRIFID            12
#define OSPFv3NBRRESTARTHELPERSTATUS     13
#define OSPFv3NBRRESTARTHELPERAGE        14
#define OSPFv3NBRRESTARTHELPEREXITREASON 15

/* OSPFv3 MIB Configured Neighbors Table values: ospfv3CfgNbrTable */
#define OSPFv3CFGNBRPRIORITY  5
#define OSPFv3CFGNBRROWSTATUS 6

/* OSPFv3 MIB Virtual Neighbors Table values: ospfv3VirtNbrTable */
#define OSPFv3VIRTNBRIFINDEX          3
#define OSPFv3VIRTNBRIFINSTID         4
#define OSPFv3VIRTNBRADDRESSTYPE      5
#define OSPFv3VIRTNBRADDRESS          6
#define OSPFv3VIRTNBROPTIONS          7
#define OSPFv3VIRTNBRSTATE            8
#define OSPFv3VIRTNBREVENTS           9
#define OSPFv3VIRTNBRLSRETRANSQLEN   10
#define OSPFv3VIRTNBRHELLOSUPPRESSED 11
#define OSPFv3VIRTNBRIFID            12
#define OSPFv3VIRTNBRRESTARTHELPERSTATUS     13
#define OSPFv3VIRTNBRRESTARTHELPERAGE        14
#define OSPFv3VIRTNBRRESTARTHELPEREXITREASON 15

/* OSPFv3 MIB Area Aggregate Table values: ospfv3AreaAggregateTable */
#define OSPFv3AREAAGGREGATEROWSTATUS  6
#define OSPFv3AREAAGGREGATEEFFECT     7
#define OSPFv3AREAAGGREGATEROUTETAG   8

/* OSPFv3 MIB Virtual Link Lsdb Table values: ospfv3VirtLinkLsdbTable */
#define OSPFv3VIRTLINKLSDBSEQUENCE       6
#define OSPFv3VIRTLINKLSDBAGE            7
#define OSPFv3VIRTLINKLSDBCHECKSUM       8
#define OSPFv3VIRTLINKLSDBADVERTISEMENT  9
#define OSPFv3VIRTLINKLSDBTYPEKNOWN     10

/* SYNTAX Status from OSPF-MIB. */
#define OSPF_STATUS_ENABLED  1
#define OSPF_STATUS_DISABLED 2

/* SNMP value hack. */
#define COUNTER     ASN_COUNTER
#define INTEGER     ASN_INTEGER
#define GAUGE       ASN_GAUGE
#define UNSIGNED    ASN_UNSIGNED
#define TIMETICKS   ASN_TIMETICKS
#define IPADDRESS   ASN_IPADDRESS
#define STRING      ASN_OCTET_STR

/* For return values e.g. SNMP_INTEGER macro */
SNMP_LOCAL_VARIABLES

/* OSPFv3-MIB instances. */
oid ospfv3_oid [] = { OSPFv3MIB };

/* Hook functions. */
static u_char *ospfv3GeneralGroup (struct variable *, oid *, size_t *,
				   int, size_t *, WriteMethod **);
static u_char *ospfv3AreaEntry (struct variable *, oid *, size_t *,
				int, size_t *, WriteMethod **);
static u_char *ospfv3AreaLsdbEntry (struct variable *, oid *, size_t *,
				    int, size_t *, WriteMethod **);
static u_char *ospfv3NbrEntry (struct variable *, oid *, size_t *,
			       int, size_t *, WriteMethod **);

struct variable ospfv3_variables[] =
{
  /* OSPF general variables */
  {OSPFv3ROUTERID,             UNSIGNED,   RWRITE, ospfv3GeneralGroup,
   3, {1, 1, 1}},
  {OSPFv3ADMINSTAT,             INTEGER,   RWRITE, ospfv3GeneralGroup,
   3, {1, 1, 2}},
  {OSPFv3VERSIONNUMBER,         INTEGER,   RONLY,  ospfv3GeneralGroup,
   3, {1, 1, 3}},
  {OSPFv3AREABDRRTRSTATUS,      INTEGER,   RONLY,  ospfv3GeneralGroup,
   3, {1, 1, 4}},
  {OSPFv3ASBDRRTRSTATUS,        INTEGER,   RWRITE, ospfv3GeneralGroup,
   3, {1, 1, 5}},
  {OSPFv3ASSCOPELSACOUNT,       GAUGE,     RONLY,  ospfv3GeneralGroup,
   3, {1, 1, 6}},
  {OSPFv3ASSCOPELSACHECKSUMSUM,UNSIGNED,   RONLY,  ospfv3GeneralGroup,
   3, {1, 1, 7}},
  {OSPFv3ORIGINATENEWLSAS,      COUNTER,   RONLY,  ospfv3GeneralGroup,
   3, {1, 1, 8}},
  {OSPFv3RXNEWLSAS,             COUNTER,   RONLY,  ospfv3GeneralGroup,
   3, {1, 1, 9}},
  {OSPFv3EXTLSACOUNT,           GAUGE,     RONLY,  ospfv3GeneralGroup,
   3, {1, 1, 10}},
  {OSPFv3EXTAREALSDBLIMIT,      INTEGER,   RWRITE, ospfv3GeneralGroup,
   3, {1, 1, 11}},
  {OSPFv3EXITOVERFLOWINTERVAL, UNSIGNED,   RWRITE, ospfv3GeneralGroup,
   3, {1, 1, 12}},
  {OSPFv3DEMANDEXTENSIONS,      INTEGER,   RWRITE, ospfv3GeneralGroup,
   3, {1, 1, 13}},
  {OSPFv3REFERENCEBANDWIDTH,   UNSIGNED, RWRITE, ospfv3GeneralGroup,
   3, {1, 1, 14}},
  {OSPFv3RESTARTSUPPORT,        INTEGER, RWRITE, ospfv3GeneralGroup,
   3, {1, 1, 15}},
  {OSPFv3RESTARTINTERVAL,      UNSIGNED, RWRITE, ospfv3GeneralGroup,
   3, {1, 1, 16}},
  {OSPFv3RESTARTSTRICTLSACHECKING, INTEGER, RWRITE, ospfv3GeneralGroup,
   3, {1, 1, 17}},
  {OSPFv3RESTARTSTATUS,         INTEGER, RONLY,  ospfv3GeneralGroup,
   3, {1, 1, 18}},
  {OSPFv3RESTARTAGE,           UNSIGNED, RONLY,  ospfv3GeneralGroup,
   3, {1, 1, 19}},
  {OSPFv3RESTARTEXITREASON,     INTEGER, RONLY,  ospfv3GeneralGroup,
   3, {1, 1, 20}},
  {OSPFv3NOTIFICATIONENABLE,    INTEGER, RWRITE, ospfv3GeneralGroup,
   3, {1, 1, 21}},
  {OSPFv3STUBROUTERSUPPORT,     INTEGER, RONLY,  ospfv3GeneralGroup,
   3, {1, 1, 22}},
  {OSPFv3STUBROUTERADVERTISEMENT, INTEGER, RWRITE, ospfv3GeneralGroup,
   3, {1, 1, 23}},
  {OSPFv3DISCONTINUITYTIME,     TIMETICKS, RONLY,  ospfv3GeneralGroup,
   3, {1, 1, 24}},
  {OSPFv3RESTARTTIME,           TIMETICKS, RONLY,  ospfv3GeneralGroup,
   3, {1, 1, 25}},

  /* OSPFv3 Area Data Structure */
  {OSPFv3IMPORTASEXTERN,        INTEGER,   RWRITE, ospfv3AreaEntry,
   4, {1, 2, 1, 2}},
  {OSPFv3AREASPFRUNS,           COUNTER,   RONLY,  ospfv3AreaEntry,
   4, {1, 2, 1, 3}},
  {OSPFv3AREABDRRTRCOUNT,       GAUGE,     RONLY,  ospfv3AreaEntry,
   4, {1, 2, 1, 4}},
  {OSPFv3AREAASBDRRTRCOUNT,     GAUGE,     RONLY,  ospfv3AreaEntry,
   4, {1, 2, 1, 5}},
  {OSPFv3AREASCOPELSACOUNT,     GAUGE,     RONLY,  ospfv3AreaEntry,
   4, {1, 2, 1, 6}},
  {OSPFv3AREASCOPELSACKSUMSUM, UNSIGNED,   RONLY,  ospfv3AreaEntry,
   4, {1, 2, 1, 7}},
  {OSPFv3AREASUMMARY,           INTEGER,   RWRITE, ospfv3AreaEntry,
   4, {1, 2, 1, 8}},
  {OSPFv3AREAROWSTATUS,         INTEGER,   RWRITE, ospfv3AreaEntry,
   4, {1, 2, 1, 9}},
  {OSPFv3AREASTUBMETRIC,        INTEGER,   RWRITE, ospfv3AreaEntry,
   4, {1, 2, 1, 10}},
  {OSPFv3AREANSSATRANSLATORROLE, INTEGER,  RWRITE, ospfv3AreaEntry,
   4, {1, 2, 1, 11}},
  {OSPFv3AREANSSATRANSLATORSTATE, INTEGER, RONLY,  ospfv3AreaEntry,
   4, {1, 2, 1, 12}},
  {OSPFv3AREANSSATRANSLATORSTABINTERVAL, UNSIGNED, RWRITE, ospfv3AreaEntry,
   4, {1, 2, 1, 13}},
  {OSPFv3AREANSSATRANSLATOREVENTS, COUNTER, RONLY, ospfv3AreaEntry,
   4, {1, 2, 1, 14}},
  {OSPFv3AREASTUBMETRICTYPE,    INTEGER, RWRITE, ospfv3AreaEntry,
   4, {1, 2, 1, 15}},
  {OSPFv3AREATEENABLED,         INTEGER, RWRITE, ospfv3AreaEntry,
   4, {1, 2, 1, 16}},

  /* OSPFv3 Area LSDB */
  {OSPFv3AREALSDBSEQUENCE,      INTEGER,   RONLY,  ospfv3AreaLsdbEntry,
   4, {1, 4, 1, 5}},
  {OSPFv3AREALSDBAGE,          UNSIGNED,   RONLY,  ospfv3AreaLsdbEntry,
   4, {1, 4, 1, 6}},
  {OSPFv3AREALSDBCHECKSUM,      INTEGER,   RONLY,  ospfv3AreaLsdbEntry,
   4, {1, 4, 1, 7}},
  {OSPFv3AREALSDBADVERTISEMENT, STRING,    RONLY,  ospfv3AreaLsdbEntry,
   4, {1, 4, 1, 8}},
  {OSPFv3AREALSDBTYPEKNOWN,     INTEGER,   RONLY,  ospfv3AreaLsdbEntry,
   4, {1, 4, 1, 9}},

  /* OSPFv3 neighbors */
  {OSPFv3NBRADDRESSTYPE,        INTEGER,   RONLY,  ospfv3NbrEntry,
   4, {1, 9, 1, 4}},
  {OSPFv3NBRADDRESS,            STRING,    RONLY,  ospfv3NbrEntry,
   4, {1, 9, 1, 5}},
  {OSPFv3NBROPTIONS,            INTEGER,   RONLY,  ospfv3NbrEntry,
   4, {1, 9, 1, 6}},
  {OSPFv3NBRPRIORITY,           INTEGER,   RONLY,  ospfv3NbrEntry,
   4, {1, 9, 1, 7}},
  {OSPFv3NBRSTATE,              INTEGER,   RONLY,  ospfv3NbrEntry,
   4, {1, 9, 1, 8}},
  {OSPFv3NBREVENTS,             COUNTER,   RONLY,  ospfv3NbrEntry,
   4, {1, 9, 1, 9}},
  {OSPFv3NBRLSRETRANSQLEN,        GAUGE,   RONLY,  ospfv3NbrEntry,
   4, {1, 9, 1, 10}},
  {OSPFv3NBRHELLOSUPPRESSED,    INTEGER,   RONLY,  ospfv3NbrEntry,
   4, {1, 9, 1, 11}},
  {OSPFv3NBRIFID,               INTEGER,   RONLY,  ospfv3NbrEntry,
   4, {1, 9, 1, 12}},
  {OSPFv3NBRRESTARTHELPERSTATUS, INTEGER,  RONLY,  ospfv3NbrEntry,
   4, {1, 9, 1, 13}},
  {OSPFv3NBRRESTARTHELPERAGE,  UNSIGNED,   RONLY,  ospfv3NbrEntry,
   4, {1, 9, 1, 14}},
  {OSPFv3NBRRESTARTHELPEREXITREASON, INTEGER, RONLY, ospfv3NbrEntry,
   4, {1, 9, 1, 15}},
};

static u_char *
ospfv3GeneralGroup (struct variable *v, oid *name, size_t *length,
                    int exact, size_t *var_len, WriteMethod **write_method)
{
  /* Check whether the instance identifier is valid */
  if (smux_header_generic (v, name, length, exact, var_len, write_method)
      == MATCH_FAILED)
    return NULL;

  /* Return the current value of the variable */
  switch (v->magic)
    {
    case OSPFv3ROUTERID:
      /* Router-ID of this OSPF instance. */
      if (ospf6)
	return SNMP_INTEGER (ntohl (ospf6->router_id));
      return SNMP_INTEGER (0);
    case OSPFv3ADMINSTAT:
    case OSPFv3VERSIONNUMBER:
    case OSPFv3AREABDRRTRSTATUS:
    case OSPFv3ASBDRRTRSTATUS:
    case OSPFv3ASSCOPELSACOUNT:
    case OSPFv3ASSCOPELSACHECKSUMSUM:
    case OSPFv3ORIGINATENEWLSAS:
    case OSPFv3RXNEWLSAS:
    case OSPFv3EXTLSACOUNT:
    case OSPFv3EXTAREALSDBLIMIT:
    case OSPFv3EXITOVERFLOWINTERVAL:
    case OSPFv3DEMANDEXTENSIONS:
    case OSPFv3REFERENCEBANDWIDTH:
    case OSPFv3RESTARTSUPPORT:
    case OSPFv3RESTARTINTERVAL:
    case OSPFv3RESTARTSTRICTLSACHECKING:
    case OSPFv3RESTARTSTATUS:
    case OSPFv3RESTARTAGE:
    case OSPFv3RESTARTEXITREASON:
    case OSPFv3NOTIFICATIONENABLE:
    case OSPFv3STUBROUTERSUPPORT:
    case OSPFv3STUBROUTERADVERTISEMENT:
    case OSPFv3DISCONTINUITYTIME:
    case OSPFv3RESTARTTIME:
      /* TODO: Not implemented */
      return NULL;
    }
  return NULL;
}

static u_char *
ospfv3AreaEntry (struct variable *v, oid *name, size_t *length,
                 int exact, size_t *var_len, WriteMethod **write_method)
{
  struct ospf6_area *oa, *area = NULL;
  u_int32_t area_id = 0;
  struct listnode *node;
  unsigned int len;
  char a[16];

  if (ospf6 == NULL)
    return NULL;

  if (smux_header_table(v, name, length, exact, var_len, write_method)
      == MATCH_FAILED)
    return NULL;

  len = *length - v->namelen;
  len = (len >= 1 ? sizeof 1 : 0);
  if (exact && len != 1)
    return NULL;
  if (len)
    area_id  = htonl (name[v->namelen]);

  inet_ntop (AF_INET, &area_id, a, sizeof (a));
  zlog_debug ("SNMP access by area: %s, exact=%d len=%d length=%lu",
	      a, exact, len, (u_long)*length);

  for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, node, oa))
    {
      if (area == NULL)
        {
          if (len == 0) /* return first area entry */
            area = oa;
          else if (exact && ntohl (oa->area_id) == ntohl (area_id))
            area = oa;
          else if (ntohl (oa->area_id) > ntohl (area_id))
            area = oa;
        }
    }

  if (area == NULL)
    return NULL;

  *length = v->namelen + 1;
  name[v->namelen] = ntohl (area->area_id);

  inet_ntop (AF_INET, &area->area_id, a, sizeof (a));
  zlog_debug ("SNMP found area: %s, exact=%d len=%d length=%lu",
	      a, exact, len, (u_long)*length);

  switch (v->magic)
    {
    case OSPFv3IMPORTASEXTERN:
      return SNMP_INTEGER (ospf6->external_table->count);
      break;
    case OSPFv3AREASPFRUNS:
    case OSPFv3AREABDRRTRCOUNT:
    case OSPFv3AREAASBDRRTRCOUNT:
    case OSPFv3AREASCOPELSACOUNT:
    case OSPFv3AREASCOPELSACKSUMSUM:
    case OSPFv3AREASUMMARY:
    case OSPFv3AREAROWSTATUS:
    case OSPFv3AREASTUBMETRIC:
    case OSPFv3AREANSSATRANSLATORROLE:
    case OSPFv3AREANSSATRANSLATORSTATE:
    case OSPFv3AREANSSATRANSLATORSTABINTERVAL:
    case OSPFv3AREANSSATRANSLATOREVENTS:
    case OSPFv3AREASTUBMETRICTYPE:
    case OSPFv3AREATEENABLED:
      /* Not implemented. */
      return NULL;
    }
  return NULL;
}

static u_char *
ospfv3AreaLsdbEntry (struct variable *v, oid *name, size_t *length,
                     int exact, size_t *var_len, WriteMethod **write_method)
{
  struct ospf6_lsa *lsa = NULL;
  u_int32_t area_id, id, adv_router;
  u_int16_t type;
  int len;
  oid *offset;
  int offsetlen;
  char a[16], b[16], c[16];
  struct ospf6_area *oa;
  struct listnode *node;

  if (smux_header_table(v, name, length, exact, var_len, write_method)
      == MATCH_FAILED)
    return NULL;

  area_id = type = id = adv_router = 0;

  /* Check OSPFv3 instance. */
  if (ospf6 == NULL)
    return NULL;

  /* Get variable length. */
  offset = name + v->namelen;
  offsetlen = *length - v->namelen;

#define OSPFV3_AREA_LSDB_ENTRY_EXACT_OFFSET 4

  if (exact && offsetlen != OSPFV3_AREA_LSDB_ENTRY_EXACT_OFFSET)
    return NULL;

  /* Parse area-id */
  len = (offsetlen < 1 ? 0 : 1);
  if (len)
    area_id = htonl (*offset);
  offset += len;
  offsetlen -= len;

  /* Parse type */
  len = (offsetlen < 1 ? 0 : 1);
  if (len)
    type = htons (*offset);
  offset += len;
  offsetlen -= len;

  /* Parse Router-ID */
  len = (offsetlen < 1 ? 0 : 1);
  if (len)
    adv_router = htonl (*offset);
  offset += len;
  offsetlen -= len;

  /* Parse LS-ID */
  len = (offsetlen < 1 ? 0 : 1);
  if (len)
    id = htonl (*offset);
  offset += len;
  offsetlen -= len;

  inet_ntop (AF_INET, &area_id, a, sizeof (a));
  inet_ntop (AF_INET, &adv_router, b, sizeof (b));
  inet_ntop (AF_INET, &id, c, sizeof (c));
  zlog_debug ("SNMP access by lsdb: area=%s exact=%d length=%lu magic=%d"
	      " type=%#x adv_router=%s id=%s",
	      a, exact, (u_long)*length, v->magic, ntohs (type), b, c);

  if (exact)
    {
      oa = ospf6_area_lookup (area_id, ospf6);
      lsa = ospf6_lsdb_lookup (type, id, adv_router, oa->lsdb);
    }
  else
    {
      for (ALL_LIST_ELEMENTS_RO (ospf6->area_list, node, oa))
        {
          if (lsa)
            continue;
          if (oa->area_id < area_id)
            continue;

          lsa = ospf6_lsdb_lookup_next (type, id, adv_router,
                                        oa->lsdb);
          if (! lsa)
            {
              type = 0;
	      id = 0;
	      adv_router = 0;
            }
        }
    }

  if (! lsa)
    {
      zlog_debug ("SNMP respond: No LSA to return");
      return NULL;
    }
  oa = OSPF6_AREA (lsa->lsdb->data);

  zlog_debug ("SNMP respond: area: %s lsa: %s", oa->name, lsa->name);

  /* Add Index (AreaId, Type, RouterId, Lsid) */
  *length = v->namelen + OSPFV3_AREA_LSDB_ENTRY_EXACT_OFFSET;
  offset = name + v->namelen;
  *offset = ntohl (oa->area_id);
  offset++;
  *offset = ntohs (lsa->header->type);
  offset++;
  *offset = ntohl (lsa->header->adv_router);
  offset++;
  *offset = ntohl (lsa->header->id);
  offset++;

  /* Return the current value of the variable */
  switch (v->magic)
    {
    case OSPFv3AREALSDBSEQUENCE:
      return SNMP_INTEGER (ntohl (lsa->header->seqnum));
      break;
    case OSPFv3AREALSDBAGE:
      ospf6_lsa_age_current (lsa);
      return SNMP_INTEGER (ntohs (lsa->header->age));
      break;
    case OSPFv3AREALSDBCHECKSUM:
      return SNMP_INTEGER (ntohs (lsa->header->checksum));
      break;
    case OSPFv3AREALSDBADVERTISEMENT:
      *var_len = ntohs (lsa->header->length);
      return (u_char *) lsa->header;
      break;
    case OSPFv3AREALSDBTYPEKNOWN:
      return SNMP_INTEGER (OSPF6_LSA_IS_KNOWN (lsa->header->type) ?
                           SNMP_TRUE : SNMP_FALSE);
      break;
    }
  return NULL;
}

static int
if_icmp_func (struct interface *ifp1, struct interface *ifp2)
{
  return (ifp1->ifindex - ifp2->ifindex);
}

static u_char *
ospfv3NbrEntry (struct variable *v, oid *name, size_t *length,
		int exact, size_t *var_len, WriteMethod **write_method)
{
  unsigned int ifindex, instid, rtrid;
  struct ospf6_interface *oi = NULL;
  struct ospf6_neighbor  *on = NULL;
  struct interface      *iif;
  struct listnode *i, *j;
  struct list *ifslist;
  oid *offset;
  int offsetlen, len;

  if (smux_header_table (v, name, length, exact, var_len, write_method)
      == MATCH_FAILED)
    return NULL;

  ifindex = instid = rtrid = 0;

  /* Check OSPFv3 instance. */
  if (ospf6 == NULL)
    return NULL;

  /* Get variable length. */
  offset = name + v->namelen;
  offsetlen = *length - v->namelen;

  if (exact && offsetlen != 3)
    return NULL;

  /* Parse if index */
  len = (offsetlen < 1 ? 0 : 1);
  if (len)
    ifindex = *offset;
  offset += len;
  offsetlen -= len;

  /* Parse instance ID */
  len = (offsetlen < 1 ? 0 : 1);
  if (len)
    instid = *offset;
  offset += len;
  offsetlen -= len;

  /* Parse router ID */
  len = (offsetlen < 1 ? 0 : 1);
  if (len)
    rtrid = htonl (*offset);
  offset += len;
  offsetlen -= len;

  if (exact)
    {
      oi = ospf6_interface_lookup_by_ifindex (ifindex);
      on = ospf6_neighbor_lookup (rtrid, oi);
      if (oi->instance_id != instid) return NULL;
    }
  else
    {
      /* We build a sorted list of interfaces */
      ifslist = list_new ();
      if (!ifslist) return NULL;
      ifslist->cmp = (int (*)(void *, void *))if_icmp_func;
      for (ALL_LIST_ELEMENTS_RO (iflist, i, iif))
	listnode_add_sort (ifslist, iif);

      for (ALL_LIST_ELEMENTS_RO (ifslist, i, iif))
        {
          if (!iif->ifindex) continue;
          oi = ospf6_interface_lookup_by_ifindex (iif->ifindex);
          if (!oi) continue;
          for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, j, on)) {
            if (iif->ifindex > ifindex ||
                (iif->ifindex == ifindex &&
                 (oi->instance_id > instid ||
                  (oi->instance_id == instid &&
                   ntohl (on->router_id) > ntohl (rtrid)))))
              break;
          }
          if (on) break;
          oi = on = NULL;
        }

      list_delete_all_node (ifslist);
    }

  if (!oi || !on) return NULL;

  /* Add Index (IfIndex, IfInstId, RtrId) */
  *length = v->namelen + 3;
  offset = name + v->namelen;
  *offset = oi->interface->ifindex;
  offset++;
  *offset = oi->instance_id;
  offset++;
  *offset = ntohl (on->router_id);
  offset++;

  /* Return the current value of the variable */
  switch (v->magic)
    {
    case OSPFv3NBRADDRESSTYPE:
      return SNMP_INTEGER (2);	/* IPv6 only */
    case OSPFv3NBRADDRESS:
      *var_len = sizeof (struct in6_addr);
      return (u_char *) &on->linklocal_addr;
    case OSPFv3NBROPTIONS:
      return SNMP_INTEGER (on->options[2]);
    case OSPFv3NBRPRIORITY:
      return SNMP_INTEGER (on->priority);
    case OSPFv3NBRSTATE:
      return SNMP_INTEGER (on->state);
    case OSPFv3NBREVENTS:
      return SNMP_INTEGER (on->state_change);
    case OSPFv3NBRLSRETRANSQLEN:
      return SNMP_INTEGER (on->retrans_list->count);
    case OSPFv3NBRHELLOSUPPRESSED:
      return SNMP_INTEGER (SNMP_FALSE);
    case OSPFv3NBRIFID:
      return SNMP_INTEGER (on->ifindex);
    case OSPFv3NBRRESTARTHELPERSTATUS:
    case OSPFv3NBRRESTARTHELPERAGE:
    case OSPFv3NBRRESTARTHELPEREXITREASON:
      /* Not implemented. Only works if all the last ones are not
	 implemented! */
      return NULL;
    }

  return NULL;
}


/* Register OSPFv3-MIB. */
void
ospf6_snmp_init (struct thread_master *master)
{
  smux_init (master);
  REGISTER_MIB ("OSPFv3MIB", ospfv3_variables, variable, ospfv3_oid);
}

#endif /* HAVE_SNMP */

