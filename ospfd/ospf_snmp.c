// SPDX-License-Identifier: GPL-2.0-or-later
/* OSPFv2 SNMP support
 * Copyright (C) 2005 6WIND <alain.ritoux@6wind.com>
 * Copyright (C) 2000 IP Infusion Inc.
 *
 * Written by Kunihiro Ishiguro <kunihiro@zebra.org>
 */

#include <zebra.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "if.h"
#include "log.h"
#include "prefix.h"
#include "table.h"
#include "command.h"
#include "memory.h"
#include "smux.h"
#include "libfrr.h"
#include "lib/version.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"

DEFINE_MTYPE_STATIC(OSPFD, SNMP, "OSPF SNMP");

/* OSPF2-MIB. */
#define OSPF2MIB 1,3,6,1,2,1,14

/* OSPF MIB General Group values. */
#define OSPFROUTERID                     1
#define OSPFADMINSTAT                    2
#define OSPFVERSIONNUMBER                3
#define OSPFAREABDRRTRSTATUS             4
#define OSPFASBDRRTRSTATUS               5
#define OSPFEXTERNLSACOUNT               6
#define OSPFEXTERNLSACKSUMSUM            7
#define OSPFTOSSUPPORT                   8
#define OSPFORIGINATENEWLSAS             9
#define OSPFRXNEWLSAS                    10
#define OSPFEXTLSDBLIMIT                 11
#define OSPFMULTICASTEXTENSIONS          12
#define OSPFEXITOVERFLOWINTERVAL         13
#define OSPFDEMANDEXTENSIONS             14

/* OSPF MIB ospfAreaTable. */
#define OSPFAREAID                       1
#define OSPFAUTHTYPE                     2
#define OSPFIMPORTASEXTERN               3
#define OSPFSPFRUNS                      4
#define OSPFAREABDRRTRCOUNT              5
#define OSPFASBDRRTRCOUNT                6
#define OSPFAREALSACOUNT                 7
#define OSPFAREALSACKSUMSUM              8
#define OSPFAREASUMMARY                  9
#define OSPFAREASTATUS                   10

/* OSPF MIB ospfStubAreaTable. */
#define OSPFSTUBAREAID                   1
#define OSPFSTUBTOS                      2
#define OSPFSTUBMETRIC                   3
#define OSPFSTUBSTATUS                   4
#define OSPFSTUBMETRICTYPE               5

/* OSPF MIB ospfLsdbTable. */
#define OSPFLSDBAREAID                   1
#define OSPFLSDBTYPE                     2
#define OSPFLSDBLSID                     3
#define OSPFLSDBROUTERID                 4
#define OSPFLSDBSEQUENCE                 5
#define OSPFLSDBAGE                      6
#define OSPFLSDBCHECKSUM                 7
#define OSPFLSDBADVERTISEMENT            8

/* OSPF MIB ospfAreaRangeTable. */
#define OSPFAREARANGEAREAID              1
#define OSPFAREARANGENET                 2
#define OSPFAREARANGEMASK                3
#define OSPFAREARANGESTATUS              4
#define OSPFAREARANGEEFFECT              5

/* OSPF MIB ospfHostTable. */
#define OSPFHOSTIPADDRESS                1
#define OSPFHOSTTOS                      2
#define OSPFHOSTMETRIC                   3
#define OSPFHOSTSTATUS                   4
#define OSPFHOSTAREAID                   5

/* OSPF MIB ospfIfTable. */
#define OSPFIFIPADDRESS                  1
#define OSPFADDRESSLESSIF                2
#define OSPFIFAREAID                     3
#define OSPFIFTYPE                       4
#define OSPFIFADMINSTAT                  5
#define OSPFIFRTRPRIORITY                6
#define OSPFIFTRANSITDELAY               7
#define OSPFIFRETRANSINTERVAL            8
#define OSPFIFHELLOINTERVAL              9
#define OSPFIFRTRDEADINTERVAL            10
#define OSPFIFPOLLINTERVAL               11
#define OSPFIFSTATE                      12
#define OSPFIFDESIGNATEDROUTER           13
#define OSPFIFBACKUPDESIGNATEDROUTER     14
#define OSPFIFEVENTS                     15
#define OSPFIFAUTHKEY                    16
#define OSPFIFSTATUS                     17
#define OSPFIFMULTICASTFORWARDING        18
#define OSPFIFDEMAND                     19
#define OSPFIFAUTHTYPE                   20

/* OSPF MIB ospfIfMetricTable. */
#define OSPFIFMETRICIPADDRESS            1
#define OSPFIFMETRICADDRESSLESSIF        2
#define OSPFIFMETRICTOS                  3
#define OSPFIFMETRICVALUE                4
#define OSPFIFMETRICSTATUS               5

/* OSPF MIB ospfVirtIfTable. */
#define OSPFVIRTIFAREAID                 1
#define OSPFVIRTIFNEIGHBOR               2
#define OSPFVIRTIFTRANSITDELAY           3
#define OSPFVIRTIFRETRANSINTERVAL        4
#define OSPFVIRTIFHELLOINTERVAL          5
#define OSPFVIRTIFRTRDEADINTERVAL        6
#define OSPFVIRTIFSTATE                  7
#define OSPFVIRTIFEVENTS                 8
#define OSPFVIRTIFAUTHKEY                9
#define OSPFVIRTIFSTATUS                 10
#define OSPFVIRTIFAUTHTYPE               11

/* OSPF MIB ospfNbrTable. */
#define OSPFNBRIPADDR                    1
#define OSPFNBRADDRESSLESSINDEX          2
#define OSPFNBRRTRID                     3
#define OSPFNBROPTIONS                   4
#define OSPFNBRPRIORITY                  5
#define OSPFNBRSTATE                     6
#define OSPFNBREVENTS                    7
#define OSPFNBRLSRETRANSQLEN             8
#define OSPFNBMANBRSTATUS                9
#define OSPFNBMANBRPERMANENCE            10
#define OSPFNBRHELLOSUPPRESSED           11

/* OSPF MIB ospfVirtNbrTable. */
#define OSPFVIRTNBRAREA                  1
#define OSPFVIRTNBRRTRID                 2
#define OSPFVIRTNBRIPADDR                3
#define OSPFVIRTNBROPTIONS               4
#define OSPFVIRTNBRSTATE                 5
#define OSPFVIRTNBREVENTS                6
#define OSPFVIRTNBRLSRETRANSQLEN         7
#define OSPFVIRTNBRHELLOSUPPRESSED       8

/* OSPF MIB ospfExtLsdbTable. */
#define OSPFEXTLSDBTYPE                  1
#define OSPFEXTLSDBLSID                  2
#define OSPFEXTLSDBROUTERID              3
#define OSPFEXTLSDBSEQUENCE              4
#define OSPFEXTLSDBAGE                   5
#define OSPFEXTLSDBCHECKSUM              6
#define OSPFEXTLSDBADVERTISEMENT         7

/* OSPF MIB ospfAreaAggregateTable. */
#define OSPFAREAAGGREGATEAREAID          1
#define OSPFAREAAGGREGATELSDBTYPE        2
#define OSPFAREAAGGREGATENET             3
#define OSPFAREAAGGREGATEMASK            4
#define OSPFAREAAGGREGATESTATUS          5
#define OSPFAREAAGGREGATEEFFECT          6

/* SYNTAX Status from OSPF-MIB. */
#define OSPF_STATUS_ENABLED  1
#define OSPF_STATUS_DISABLED 2

/* SNMP value hack. */
#define COUNTER     ASN_COUNTER
#define INTEGER     ASN_INTEGER
#define GAUGE       ASN_GAUGE
#define TIMETICKS   ASN_TIMETICKS
#define IPADDRESS   ASN_IPADDRESS
#define STRING      ASN_OCTET_STR

/* Because DR/DROther values are exhanged wrt RFC */
#define ISM_SNMP(x)                                                            \
	(((x) == ISM_DROther) ? ISM_DR : ((x) == ISM_DR) ? ISM_DROther : (x))

/* Declare static local variables for convenience. */
SNMP_LOCAL_VARIABLES

/* OSPF-MIB instances. */
static oid ospf_oid[] = {OSPF2MIB};
static oid ospf_trap_oid[] = {OSPF2MIB, 16, 2}; /* Not reverse mappable! */

/* IP address 0.0.0.0. */
static struct in_addr ospf_empty_addr = {.s_addr = 0};

/* Hook functions. */
static uint8_t *ospfGeneralGroup(struct variable *, oid *, size_t *, int,
				 size_t *, WriteMethod **);
static uint8_t *ospfAreaEntry(struct variable *, oid *, size_t *, int, size_t *,
			      WriteMethod **);
static uint8_t *ospfStubAreaEntry(struct variable *, oid *, size_t *, int,
				  size_t *, WriteMethod **);
static uint8_t *ospfLsdbEntry(struct variable *, oid *, size_t *, int, size_t *,
			      WriteMethod **);
static uint8_t *ospfAreaRangeEntry(struct variable *, oid *, size_t *, int,
				   size_t *, WriteMethod **);
static uint8_t *ospfHostEntry(struct variable *, oid *, size_t *, int, size_t *,
			      WriteMethod **);
static uint8_t *ospfIfEntry(struct variable *, oid *, size_t *, int, size_t *,
			    WriteMethod **);
static uint8_t *ospfIfMetricEntry(struct variable *, oid *, size_t *, int,
				  size_t *, WriteMethod **);
static uint8_t *ospfVirtIfEntry(struct variable *, oid *, size_t *, int,
				size_t *, WriteMethod **);
static uint8_t *ospfNbrEntry(struct variable *, oid *, size_t *, int, size_t *,
			     WriteMethod **);
static uint8_t *ospfVirtNbrEntry(struct variable *, oid *, size_t *, int,
				 size_t *, WriteMethod **);
static uint8_t *ospfExtLsdbEntry(struct variable *, oid *, size_t *, int,
				 size_t *, WriteMethod **);
static uint8_t *ospfAreaAggregateEntry(struct variable *, oid *, size_t *, int,
				       size_t *, WriteMethod **);

static struct variable ospf_variables[] = {
	/* OSPF general variables */
	{OSPFROUTERID, IPADDRESS, RWRITE, ospfGeneralGroup, 2, {1, 1}},
	{OSPFADMINSTAT, INTEGER, RWRITE, ospfGeneralGroup, 2, {1, 2}},
	{OSPFVERSIONNUMBER, INTEGER, RONLY, ospfGeneralGroup, 2, {1, 3}},
	{OSPFAREABDRRTRSTATUS, INTEGER, RONLY, ospfGeneralGroup, 2, {1, 4}},
	{OSPFASBDRRTRSTATUS, INTEGER, RWRITE, ospfGeneralGroup, 2, {1, 5}},
	{OSPFEXTERNLSACOUNT, GAUGE, RONLY, ospfGeneralGroup, 2, {1, 6}},
	{OSPFEXTERNLSACKSUMSUM, INTEGER, RONLY, ospfGeneralGroup, 2, {1, 7}},
	{OSPFTOSSUPPORT, INTEGER, RWRITE, ospfGeneralGroup, 2, {1, 8}},
	{OSPFORIGINATENEWLSAS, COUNTER, RONLY, ospfGeneralGroup, 2, {1, 9}},
	{OSPFRXNEWLSAS, COUNTER, RONLY, ospfGeneralGroup, 2, {1, 10}},
	{OSPFEXTLSDBLIMIT, INTEGER, RWRITE, ospfGeneralGroup, 2, {1, 11}},
	{OSPFMULTICASTEXTENSIONS,
	 INTEGER,
	 RWRITE,
	 ospfGeneralGroup,
	 2,
	 {1, 12}},
	{OSPFEXITOVERFLOWINTERVAL,
	 INTEGER,
	 RWRITE,
	 ospfGeneralGroup,
	 2,
	 {1, 13}},
	{OSPFDEMANDEXTENSIONS, INTEGER, RWRITE, ospfGeneralGroup, 2, {1, 14}},

	/* OSPF area data structure. */
	{OSPFAREAID, IPADDRESS, RONLY, ospfAreaEntry, 3, {2, 1, 1}},
	{OSPFAUTHTYPE, INTEGER, RWRITE, ospfAreaEntry, 3, {2, 1, 2}},
	{OSPFIMPORTASEXTERN, INTEGER, RWRITE, ospfAreaEntry, 3, {2, 1, 3}},
	{OSPFSPFRUNS, COUNTER, RONLY, ospfAreaEntry, 3, {2, 1, 4}},
	{OSPFAREABDRRTRCOUNT, GAUGE, RONLY, ospfAreaEntry, 3, {2, 1, 5}},
	{OSPFASBDRRTRCOUNT, GAUGE, RONLY, ospfAreaEntry, 3, {2, 1, 6}},
	{OSPFAREALSACOUNT, GAUGE, RONLY, ospfAreaEntry, 3, {2, 1, 7}},
	{OSPFAREALSACKSUMSUM, INTEGER, RONLY, ospfAreaEntry, 3, {2, 1, 8}},
	{OSPFAREASUMMARY, INTEGER, RWRITE, ospfAreaEntry, 3, {2, 1, 9}},
	{OSPFAREASTATUS, INTEGER, RWRITE, ospfAreaEntry, 3, {2, 1, 10}},

	/* OSPF stub area information. */
	{OSPFSTUBAREAID, IPADDRESS, RONLY, ospfStubAreaEntry, 3, {3, 1, 1}},
	{OSPFSTUBTOS, INTEGER, RONLY, ospfStubAreaEntry, 3, {3, 1, 2}},
	{OSPFSTUBMETRIC, INTEGER, RWRITE, ospfStubAreaEntry, 3, {3, 1, 3}},
	{OSPFSTUBSTATUS, INTEGER, RWRITE, ospfStubAreaEntry, 3, {3, 1, 4}},
	{OSPFSTUBMETRICTYPE, INTEGER, RWRITE, ospfStubAreaEntry, 3, {3, 1, 5}},

	/* OSPF link state database. */
	{OSPFLSDBAREAID, IPADDRESS, RONLY, ospfLsdbEntry, 3, {4, 1, 1}},
	{OSPFLSDBTYPE, INTEGER, RONLY, ospfLsdbEntry, 3, {4, 1, 2}},
	{OSPFLSDBLSID, IPADDRESS, RONLY, ospfLsdbEntry, 3, {4, 1, 3}},
	{OSPFLSDBROUTERID, IPADDRESS, RONLY, ospfLsdbEntry, 3, {4, 1, 4}},
	{OSPFLSDBSEQUENCE, INTEGER, RONLY, ospfLsdbEntry, 3, {4, 1, 5}},
	{OSPFLSDBAGE, INTEGER, RONLY, ospfLsdbEntry, 3, {4, 1, 6}},
	{OSPFLSDBCHECKSUM, INTEGER, RONLY, ospfLsdbEntry, 3, {4, 1, 7}},
	{OSPFLSDBADVERTISEMENT, STRING, RONLY, ospfLsdbEntry, 3, {4, 1, 8}},

	/* Area range table. */
	{OSPFAREARANGEAREAID,
	 IPADDRESS,
	 RONLY,
	 ospfAreaRangeEntry,
	 3,
	 {5, 1, 1}},
	{OSPFAREARANGENET, IPADDRESS, RONLY, ospfAreaRangeEntry, 3, {5, 1, 2}},
	{OSPFAREARANGEMASK,
	 IPADDRESS,
	 RWRITE,
	 ospfAreaRangeEntry,
	 3,
	 {5, 1, 3}},
	{OSPFAREARANGESTATUS,
	 INTEGER,
	 RWRITE,
	 ospfAreaRangeEntry,
	 3,
	 {5, 1, 4}},
	{OSPFAREARANGEEFFECT,
	 INTEGER,
	 RWRITE,
	 ospfAreaRangeEntry,
	 3,
	 {5, 1, 5}},

	/* OSPF host table. */
	{OSPFHOSTIPADDRESS, IPADDRESS, RONLY, ospfHostEntry, 3, {6, 1, 1}},
	{OSPFHOSTTOS, INTEGER, RONLY, ospfHostEntry, 3, {6, 1, 2}},
	{OSPFHOSTMETRIC, INTEGER, RWRITE, ospfHostEntry, 3, {6, 1, 3}},
	{OSPFHOSTSTATUS, INTEGER, RWRITE, ospfHostEntry, 3, {6, 1, 4}},
	{OSPFHOSTAREAID, IPADDRESS, RONLY, ospfHostEntry, 3, {6, 1, 5}},

	/* OSPF interface table. */
	{OSPFIFIPADDRESS, IPADDRESS, RONLY, ospfIfEntry, 3, {7, 1, 1}},
	{OSPFADDRESSLESSIF, INTEGER, RONLY, ospfIfEntry, 3, {7, 1, 2}},
	{OSPFIFAREAID, IPADDRESS, RWRITE, ospfIfEntry, 3, {7, 1, 3}},
	{OSPFIFTYPE, INTEGER, RWRITE, ospfIfEntry, 3, {7, 1, 4}},
	{OSPFIFADMINSTAT, INTEGER, RWRITE, ospfIfEntry, 3, {7, 1, 5}},
	{OSPFIFRTRPRIORITY, INTEGER, RWRITE, ospfIfEntry, 3, {7, 1, 6}},
	{OSPFIFTRANSITDELAY, INTEGER, RWRITE, ospfIfEntry, 3, {7, 1, 7}},
	{OSPFIFRETRANSINTERVAL, INTEGER, RWRITE, ospfIfEntry, 3, {7, 1, 8}},
	{OSPFIFHELLOINTERVAL, INTEGER, RWRITE, ospfIfEntry, 3, {7, 1, 9}},
	{OSPFIFRTRDEADINTERVAL, INTEGER, RWRITE, ospfIfEntry, 3, {7, 1, 10}},
	{OSPFIFPOLLINTERVAL, INTEGER, RWRITE, ospfIfEntry, 3, {7, 1, 11}},
	{OSPFIFSTATE, INTEGER, RONLY, ospfIfEntry, 3, {7, 1, 12}},
	{OSPFIFDESIGNATEDROUTER, IPADDRESS, RONLY, ospfIfEntry, 3, {7, 1, 13}},
	{OSPFIFBACKUPDESIGNATEDROUTER,
	 IPADDRESS,
	 RONLY,
	 ospfIfEntry,
	 3,
	 {7, 1, 14}},
	{OSPFIFEVENTS, COUNTER, RONLY, ospfIfEntry, 3, {7, 1, 15}},
	{OSPFIFAUTHKEY, STRING, RWRITE, ospfIfEntry, 3, {7, 1, 16}},
	{OSPFIFSTATUS, INTEGER, RWRITE, ospfIfEntry, 3, {7, 1, 17}},
	{OSPFIFMULTICASTFORWARDING,
	 INTEGER,
	 RWRITE,
	 ospfIfEntry,
	 3,
	 {7, 1, 18}},
	{OSPFIFDEMAND, INTEGER, RWRITE, ospfIfEntry, 3, {7, 1, 19}},
	{OSPFIFAUTHTYPE, INTEGER, RWRITE, ospfIfEntry, 3, {7, 1, 20}},

	/* OSPF interface metric table. */
	{OSPFIFMETRICIPADDRESS,
	 IPADDRESS,
	 RONLY,
	 ospfIfMetricEntry,
	 3,
	 {8, 1, 1}},
	{OSPFIFMETRICADDRESSLESSIF,
	 INTEGER,
	 RONLY,
	 ospfIfMetricEntry,
	 3,
	 {8, 1, 2}},
	{OSPFIFMETRICTOS, INTEGER, RONLY, ospfIfMetricEntry, 3, {8, 1, 3}},
	{OSPFIFMETRICVALUE, INTEGER, RWRITE, ospfIfMetricEntry, 3, {8, 1, 4}},
	{OSPFIFMETRICSTATUS, INTEGER, RWRITE, ospfIfMetricEntry, 3, {8, 1, 5}},

	/* OSPF virtual interface table. */
	{OSPFVIRTIFAREAID, IPADDRESS, RONLY, ospfVirtIfEntry, 3, {9, 1, 1}},
	{OSPFVIRTIFNEIGHBOR, IPADDRESS, RONLY, ospfVirtIfEntry, 3, {9, 1, 2}},
	{OSPFVIRTIFTRANSITDELAY,
	 INTEGER,
	 RWRITE,
	 ospfVirtIfEntry,
	 3,
	 {9, 1, 3}},
	{OSPFVIRTIFRETRANSINTERVAL,
	 INTEGER,
	 RWRITE,
	 ospfVirtIfEntry,
	 3,
	 {9, 1, 4}},
	{OSPFVIRTIFHELLOINTERVAL,
	 INTEGER,
	 RWRITE,
	 ospfVirtIfEntry,
	 3,
	 {9, 1, 5}},
	{OSPFVIRTIFRTRDEADINTERVAL,
	 INTEGER,
	 RWRITE,
	 ospfVirtIfEntry,
	 3,
	 {9, 1, 6}},
	{OSPFVIRTIFSTATE, INTEGER, RONLY, ospfVirtIfEntry, 3, {9, 1, 7}},
	{OSPFVIRTIFEVENTS, COUNTER, RONLY, ospfVirtIfEntry, 3, {9, 1, 8}},
	{OSPFVIRTIFAUTHKEY, STRING, RWRITE, ospfVirtIfEntry, 3, {9, 1, 9}},
	{OSPFVIRTIFSTATUS, INTEGER, RWRITE, ospfVirtIfEntry, 3, {9, 1, 10}},
	{OSPFVIRTIFAUTHTYPE, INTEGER, RWRITE, ospfVirtIfEntry, 3, {9, 1, 11}},

	/* OSPF neighbor table. */
	{OSPFNBRIPADDR, IPADDRESS, RONLY, ospfNbrEntry, 3, {10, 1, 1}},
	{OSPFNBRADDRESSLESSINDEX, INTEGER, RONLY, ospfNbrEntry, 3, {10, 1, 2}},
	{OSPFNBRRTRID, IPADDRESS, RONLY, ospfNbrEntry, 3, {10, 1, 3}},
	{OSPFNBROPTIONS, INTEGER, RONLY, ospfNbrEntry, 3, {10, 1, 4}},
	{OSPFNBRPRIORITY, INTEGER, RWRITE, ospfNbrEntry, 3, {10, 1, 5}},
	{OSPFNBRSTATE, INTEGER, RONLY, ospfNbrEntry, 3, {10, 1, 6}},
	{OSPFNBREVENTS, COUNTER, RONLY, ospfNbrEntry, 3, {10, 1, 7}},
	{OSPFNBRLSRETRANSQLEN, GAUGE, RONLY, ospfNbrEntry, 3, {10, 1, 8}},
	{OSPFNBMANBRSTATUS, INTEGER, RWRITE, ospfNbrEntry, 3, {10, 1, 9}},
	{OSPFNBMANBRPERMANENCE, INTEGER, RONLY, ospfNbrEntry, 3, {10, 1, 10}},
	{OSPFNBRHELLOSUPPRESSED, INTEGER, RONLY, ospfNbrEntry, 3, {10, 1, 11}},

	/* OSPF virtual neighbor table. */
	{OSPFVIRTNBRAREA, IPADDRESS, RONLY, ospfVirtNbrEntry, 3, {11, 1, 1}},
	{OSPFVIRTNBRRTRID, IPADDRESS, RONLY, ospfVirtNbrEntry, 3, {11, 1, 2}},
	{OSPFVIRTNBRIPADDR, IPADDRESS, RONLY, ospfVirtNbrEntry, 3, {11, 1, 3}},
	{OSPFVIRTNBROPTIONS, INTEGER, RONLY, ospfVirtNbrEntry, 3, {11, 1, 4}},
	{OSPFVIRTNBRSTATE, INTEGER, RONLY, ospfVirtNbrEntry, 3, {11, 1, 5}},
	{OSPFVIRTNBREVENTS, COUNTER, RONLY, ospfVirtNbrEntry, 3, {11, 1, 6}},
	{OSPFVIRTNBRLSRETRANSQLEN,
	 INTEGER,
	 RONLY,
	 ospfVirtNbrEntry,
	 3,
	 {11, 1, 7}},
	{OSPFVIRTNBRHELLOSUPPRESSED,
	 INTEGER,
	 RONLY,
	 ospfVirtNbrEntry,
	 3,
	 {11, 1, 8}},

	/* OSPF link state database, external. */
	{OSPFEXTLSDBTYPE, INTEGER, RONLY, ospfExtLsdbEntry, 3, {12, 1, 1}},
	{OSPFEXTLSDBLSID, IPADDRESS, RONLY, ospfExtLsdbEntry, 3, {12, 1, 2}},
	{OSPFEXTLSDBROUTERID,
	 IPADDRESS,
	 RONLY,
	 ospfExtLsdbEntry,
	 3,
	 {12, 1, 3}},
	{OSPFEXTLSDBSEQUENCE, INTEGER, RONLY, ospfExtLsdbEntry, 3, {12, 1, 4}},
	{OSPFEXTLSDBAGE, INTEGER, RONLY, ospfExtLsdbEntry, 3, {12, 1, 5}},
	{OSPFEXTLSDBCHECKSUM, INTEGER, RONLY, ospfExtLsdbEntry, 3, {12, 1, 6}},
	{OSPFEXTLSDBADVERTISEMENT,
	 STRING,
	 RONLY,
	 ospfExtLsdbEntry,
	 3,
	 {12, 1, 7}},

	/* OSPF area aggregate table. */
	{OSPFAREAAGGREGATEAREAID,
	 IPADDRESS,
	 RONLY,
	 ospfAreaAggregateEntry,
	 3,
	 {14, 1, 1}},
	{OSPFAREAAGGREGATELSDBTYPE,
	 INTEGER,
	 RONLY,
	 ospfAreaAggregateEntry,
	 3,
	 {14, 1, 2}},
	{OSPFAREAAGGREGATENET,
	 IPADDRESS,
	 RONLY,
	 ospfAreaAggregateEntry,
	 3,
	 {14, 1, 3}},
	{OSPFAREAAGGREGATEMASK,
	 IPADDRESS,
	 RONLY,
	 ospfAreaAggregateEntry,
	 3,
	 {14, 1, 4}},
	{OSPFAREAAGGREGATESTATUS,
	 INTEGER,
	 RWRITE,
	 ospfAreaAggregateEntry,
	 3,
	 {14, 1, 5}},
	{OSPFAREAAGGREGATEEFFECT,
	 INTEGER,
	 RWRITE,
	 ospfAreaAggregateEntry,
	 3,
	 {14, 1, 6}}};

/* The administrative status of OSPF.  When OSPF is enbled on at least
   one interface return 1. */
static int ospf_admin_stat(struct ospf *ospf)
{
	struct listnode *node;
	struct ospf_interface *oi;

	if (ospf == NULL)
		return 0;

	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi))
		if (oi && oi->address)
			return 1;

	return 0;
}

static uint8_t *ospfGeneralGroup(struct variable *v, oid *name, size_t *length,
				 int exact, size_t *var_len,
				 WriteMethod **write_method)
{
	struct ospf *ospf;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	/* Check whether the instance identifier is valid */
	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	/* Return the current value of the variable */
	switch (v->magic) {
	case OSPFROUTERID: /* 1 */
		/* Router-ID of this OSPF instance. */
		if (ospf)
			return SNMP_IPADDRESS(ospf->router_id);
		else
			return SNMP_IPADDRESS(ospf_empty_addr);
	case OSPFADMINSTAT: /* 2 */
		/* The administrative status of OSPF in the router. */
		if (ospf_admin_stat(ospf))
			return SNMP_INTEGER(OSPF_STATUS_ENABLED);
		else
			return SNMP_INTEGER(OSPF_STATUS_DISABLED);
	case OSPFVERSIONNUMBER: /* 3 */
		/* OSPF version 2. */
		return SNMP_INTEGER(OSPF_VERSION);
	case OSPFAREABDRRTRSTATUS: /* 4 */
		/* Area Border router status. */
		if (ospf && CHECK_FLAG(ospf->flags, OSPF_FLAG_ABR))
			return SNMP_INTEGER(SNMP_TRUE);
		else
			return SNMP_INTEGER(SNMP_FALSE);
	case OSPFASBDRRTRSTATUS: /* 5 */
		/* AS Border router status. */
		if (ospf && CHECK_FLAG(ospf->flags, OSPF_FLAG_ASBR))
			return SNMP_INTEGER(SNMP_TRUE);
		else
			return SNMP_INTEGER(SNMP_FALSE);
	case OSPFEXTERNLSACOUNT: /* 6 */
		/* External LSA counts. */
		if (ospf)
			return SNMP_INTEGER(ospf_lsdb_count_all(ospf->lsdb));
		else
			return SNMP_INTEGER(0);
	case OSPFEXTERNLSACKSUMSUM: /* 7 */
		/* External LSA checksum. */
		return SNMP_INTEGER(0);
	case OSPFTOSSUPPORT: /* 8 */
		/* TOS is not supported. */
		return SNMP_INTEGER(SNMP_FALSE);
	case OSPFORIGINATENEWLSAS: /* 9 */
		/* The number of new link-state advertisements. */
		if (ospf)
			return SNMP_INTEGER(ospf->lsa_originate_count);
		else
			return SNMP_INTEGER(0);
	case OSPFRXNEWLSAS: /* 10 */
		/* The number of link-state advertisements received determined
		   to be new instantiations. */
		if (ospf)
			return SNMP_INTEGER(ospf->rx_lsa_count);
		else
			return SNMP_INTEGER(0);
	case OSPFEXTLSDBLIMIT: /* 11 */
		/* There is no limit for the number of non-default
		   AS-external-LSAs. */
		return SNMP_INTEGER(-1);
	case OSPFMULTICASTEXTENSIONS: /* 12 */
		/* Multicast Extensions to OSPF is not supported. */
		return SNMP_INTEGER(0);
	case OSPFEXITOVERFLOWINTERVAL: /* 13 */
		/* Overflow is not supported. */
		return SNMP_INTEGER(0);
	case OSPFDEMANDEXTENSIONS: /* 14 */
		/* Demand routing is not supported. */
		return SNMP_INTEGER(SNMP_FALSE);
	default:
		return NULL;
	}
	return NULL;
}

static struct ospf_area *
ospf_area_lookup_next(struct ospf *ospf, struct in_addr *area_id, int first)
{
	struct ospf_area *area;
	struct listnode *node;

	if (ospf == NULL)
		return NULL;

	if (first) {
		node = listhead(ospf->areas);
		if (node) {
			area = listgetdata(node);
			*area_id = area->area_id;
			return area;
		}
		return NULL;
	}
	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		if (ntohl(area->area_id.s_addr) > ntohl(area_id->s_addr)) {
			*area_id = area->area_id;
			return area;
		}
	}
	return NULL;
}

static struct ospf_area *ospfAreaLookup(struct variable *v, oid name[],
					size_t *length, struct in_addr *addr,
					int exact)
{
	struct ospf *ospf;
	struct ospf_area *area;
	int len;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL)
		return NULL;

	if (exact) {
		/* Length is insufficient to lookup OSPF area. */
		if (*length - v->namelen != sizeof(struct in_addr))
			return NULL;

		oid2in_addr(name + v->namelen, sizeof(struct in_addr), addr);

		area = ospf_area_lookup_by_area_id(ospf, *addr);

		return area;
	} else {
		len = *length - v->namelen;
		if (len > 4)
			len = 4;

		oid2in_addr(name + v->namelen, len, addr);

		area = ospf_area_lookup_next(ospf, addr, len == 0 ? 1 : 0);

		if (area == NULL)
			return NULL;

		oid_copy_in_addr(name + v->namelen, addr);
		*length = sizeof(struct in_addr) + v->namelen;

		return area;
	}
	return NULL;
}

static uint8_t *ospfAreaEntry(struct variable *v, oid *name, size_t *length,
			      int exact, size_t *var_len,
			      WriteMethod **write_method)
{
	struct ospf_area *area;
	struct in_addr addr;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	memset(&addr, 0, sizeof(addr));

	area = ospfAreaLookup(v, name, length, &addr, exact);
	if (!area)
		return NULL;

	/* Return the current value of the variable */
	switch (v->magic) {
	case OSPFAREAID: /* 1 */
		return SNMP_IPADDRESS(area->area_id);
	case OSPFAUTHTYPE: /* 2 */
		return SNMP_INTEGER(area->auth_type);
	case OSPFIMPORTASEXTERN: /* 3 */
		return SNMP_INTEGER(area->external_routing + 1);
	case OSPFSPFRUNS: /* 4 */
		return SNMP_INTEGER(area->spf_calculation);
	case OSPFAREABDRRTRCOUNT: /* 5 */
		return SNMP_INTEGER(area->abr_count);
	case OSPFASBDRRTRCOUNT: /* 6 */
		return SNMP_INTEGER(area->asbr_count);
	case OSPFAREALSACOUNT: /* 7 */
		return SNMP_INTEGER(area->lsdb->total);
	case OSPFAREALSACKSUMSUM: /* 8 */
		return SNMP_INTEGER(0);
	case OSPFAREASUMMARY: /* 9 */
#define OSPF_noAreaSummary   1
#define OSPF_sendAreaSummary 2
		if (area->no_summary)
			return SNMP_INTEGER(OSPF_noAreaSummary);
		else
			return SNMP_INTEGER(OSPF_sendAreaSummary);
	case OSPFAREASTATUS: /* 10 */
		return SNMP_INTEGER(SNMP_VALID);
	default:
		return NULL;
	}
	return NULL;
}

static struct ospf_area *ospf_stub_area_lookup_next(struct in_addr *area_id,
						    int first)
{
	struct ospf_area *area;
	struct listnode *node;
	struct ospf *ospf;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		if (area->external_routing == OSPF_AREA_STUB) {
			if (first) {
				*area_id = area->area_id;
				return area;
			} else if (ntohl(area->area_id.s_addr)
				   > ntohl(area_id->s_addr)) {
				*area_id = area->area_id;
				return area;
			}
		}
	}
	return NULL;
}

static struct ospf_area *ospfStubAreaLookup(struct variable *v, oid name[],
					    size_t *length,
					    struct in_addr *addr, int exact)
{
	struct ospf *ospf;
	struct ospf_area *area;
	int len;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL)
		return NULL;

	/* Exact lookup. */
	if (exact) {
		/* ospfStubAreaID + ospfStubTOS. */
		if (*length != v->namelen + sizeof(struct in_addr) + 1)
			return NULL;

		/* Check ospfStubTOS is zero. */
		if (name[*length - 1] != 0)
			return NULL;

		oid2in_addr(name + v->namelen, sizeof(struct in_addr), addr);

		area = ospf_area_lookup_by_area_id(ospf, *addr);

		if (area && area->external_routing == OSPF_AREA_STUB)
			return area;
		else
			return NULL;
	} else {
		len = *length - v->namelen;
		if (len > 4)
			len = 4;

		oid2in_addr(name + v->namelen, len, addr);

		area = ospf_stub_area_lookup_next(addr, len == 0 ? 1 : 0);

		if (area == NULL)
			return NULL;

		oid_copy_in_addr(name + v->namelen, addr);
		/* Set TOS 0. */
		name[v->namelen + sizeof(struct in_addr)] = 0;
		*length = v->namelen + sizeof(struct in_addr) + 1;

		return area;
	}
	return NULL;
}

static uint8_t *ospfStubAreaEntry(struct variable *v, oid *name, size_t *length,
				  int exact, size_t *var_len,
				  WriteMethod **write_method)
{
	struct ospf_area *area;
	struct in_addr addr;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	memset(&addr, 0, sizeof(addr));

	area = ospfStubAreaLookup(v, name, length, &addr, exact);
	if (!area)
		return NULL;

	/* Return the current value of the variable */
	switch (v->magic) {
	case OSPFSTUBAREAID: /* 1 */
		/* OSPF stub area id. */
		return SNMP_IPADDRESS(area->area_id);
	case OSPFSTUBTOS: /* 2 */
		/* TOS value is not supported. */
		return SNMP_INTEGER(0);
	case OSPFSTUBMETRIC: /* 3 */
		/* Default cost to stub area. */
		return SNMP_INTEGER(area->default_cost);
	case OSPFSTUBSTATUS: /* 4 */
		/* Status of the stub area. */
		return SNMP_INTEGER(SNMP_VALID);
	case OSPFSTUBMETRICTYPE: /* 5 */
				 /* OSPF Metric type. */
#define OSPF_ospfMetric     1
#define OSPF_comparableCost 2
#define OSPF_nonComparable  3
		return SNMP_INTEGER(OSPF_ospfMetric);
	default:
		return NULL;
	}
	return NULL;
}

static struct ospf_lsa *lsdb_lookup_next(struct ospf_area *area, uint8_t *type,
					 int type_next, struct in_addr *ls_id,
					 int ls_id_next,
					 struct in_addr *router_id,
					 int router_id_next)
{
	struct ospf_lsa *lsa;
	int i;

	if (type_next)
		i = OSPF_MIN_LSA;
	else
		i = *type;

	/* Sanity check, if LSA type unknwon
	   merley skip any LSA */
	if ((i < OSPF_MIN_LSA) || (i >= OSPF_MAX_LSA)) {
		zlog_debug("Strange request with LSA type %d", i);
		return NULL;
	}

	for (; i < OSPF_MAX_LSA; i++) {
		*type = i;

		lsa = ospf_lsdb_lookup_by_id_next(area->lsdb, *type, *ls_id,
						  *router_id, ls_id_next);
		if (lsa)
			return lsa;

		ls_id_next = 1;
	}
	return NULL;
}

static struct ospf_lsa *ospfLsdbLookup(struct variable *v, oid *name,
				       size_t *length, struct in_addr *area_id,
				       uint8_t *type, struct in_addr *ls_id,
				       struct in_addr *router_id, int exact)
{
	struct ospf *ospf;
	struct ospf_area *area;
	struct ospf_lsa *lsa;
	int len;
	int type_next;
	int ls_id_next;
	int router_id_next;
	oid *offset;
	int offsetlen;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);

#define OSPF_LSDB_ENTRY_OFFSET (IN_ADDR_SIZE + 1 + IN_ADDR_SIZE + IN_ADDR_SIZE)

	if (exact) {
		/* Area ID + Type + LS ID + Router ID. */
		if (*length - v->namelen != OSPF_LSDB_ENTRY_OFFSET)
			return NULL;

		/* Set OID offset for Area ID. */
		offset = name + v->namelen;

		/* Lookup area first. */
		oid2in_addr(offset, IN_ADDR_SIZE, area_id);
		area = ospf_area_lookup_by_area_id(ospf, *area_id);
		if (!area)
			return NULL;
		offset += IN_ADDR_SIZE;

		/* Type. */
		*type = *offset;
		offset++;

		/* LS ID. */
		oid2in_addr(offset, IN_ADDR_SIZE, ls_id);
		offset += IN_ADDR_SIZE;

		/* Router ID. */
		oid2in_addr(offset, IN_ADDR_SIZE, router_id);

		/* Lookup LSDB. */
		return ospf_lsdb_lookup_by_id(area->lsdb, *type, *ls_id,
					      *router_id);
	} else {
		/* Get variable length. */
		offset = name + v->namelen;
		offsetlen = *length - v->namelen;
		len = offsetlen;

		if (len > (int)IN_ADDR_SIZE)
			len = IN_ADDR_SIZE;

		oid2in_addr(offset, len, area_id);

		/* First we search area. */
		if (len == IN_ADDR_SIZE)
			area = ospf_area_lookup_by_area_id(ospf, *area_id);
		else
			area = ospf_area_lookup_next(ospf, area_id, 1);

		if (area == NULL)
			return NULL;

		do {
			/* Next we lookup type. */
			offset += len;
			offsetlen -= len;
			len = offsetlen;

			if (len <= 0)
				type_next = 1;
			else {
				type_next = 0;
				*type = *offset;
			}

			/* LS ID. */
			offset++;
			offsetlen--;
			len = offsetlen;

			if (len <= 0)
				ls_id_next = 1;
			else {
				ls_id_next = 0;
				if (len > (int)IN_ADDR_SIZE)
					len = IN_ADDR_SIZE;

				oid2in_addr(offset, len, ls_id);
			}

			/* Router ID. */
			offset += IN_ADDR_SIZE;
			offsetlen -= IN_ADDR_SIZE;
			len = offsetlen;

			if (len <= 0)
				router_id_next = 1;
			else {
				router_id_next = 0;
				if (len > (int)IN_ADDR_SIZE)
					len = IN_ADDR_SIZE;

				oid2in_addr(offset, len, router_id);
			}

			lsa = lsdb_lookup_next(area, type, type_next, ls_id,
					       ls_id_next, router_id,
					       router_id_next);

			if (lsa) {
				/* Fill in length. */
				*length = v->namelen + OSPF_LSDB_ENTRY_OFFSET;

				/* Fill in value. */
				offset = name + v->namelen;
				oid_copy_in_addr(offset, area_id);
				offset += IN_ADDR_SIZE;
				*offset = lsa->data->type;
				offset++;
				oid_copy_in_addr(offset, &lsa->data->id);
				offset += IN_ADDR_SIZE;
				oid_copy_in_addr(offset,
						 &lsa->data->adv_router);

				return lsa;
			}
		} while ((area = ospf_area_lookup_next(ospf, area_id, 0))
			 != NULL);
	}
	return NULL;
}

static uint8_t *ospfLsdbEntry(struct variable *v, oid *name, size_t *length,
			      int exact, size_t *var_len,
			      WriteMethod **write_method)
{
	struct ospf_lsa *lsa;
	struct lsa_header *lsah;
	struct in_addr area_id;
	uint8_t type;
	struct in_addr ls_id;
	struct in_addr router_id;
	struct ospf *ospf;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	/* INDEX { ospfLsdbAreaId, ospfLsdbType,
	   ospfLsdbLsid, ospfLsdbRouterId } */

	memset(&area_id, 0, sizeof(area_id));
	type = 0;
	memset(&ls_id, 0, sizeof(ls_id));
	memset(&router_id, 0, sizeof(router_id));

	/* Check OSPF instance. */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL)
		return NULL;

	lsa = ospfLsdbLookup(v, name, length, &area_id, &type, &ls_id,
			     &router_id, exact);
	if (!lsa)
		return NULL;

	lsah = lsa->data;

	/* Return the current value of the variable */
	switch (v->magic) {
	case OSPFLSDBAREAID: /* 1 */
		return SNMP_IPADDRESS(lsa->area->area_id);
	case OSPFLSDBTYPE: /* 2 */
		return SNMP_INTEGER(lsah->type);
	case OSPFLSDBLSID: /* 3 */
		return SNMP_IPADDRESS(lsah->id);
	case OSPFLSDBROUTERID: /* 4 */
		return SNMP_IPADDRESS(lsah->adv_router);
	case OSPFLSDBSEQUENCE: /* 5 */
		return SNMP_INTEGER(lsah->ls_seqnum);
	case OSPFLSDBAGE: /* 6 */
		return SNMP_INTEGER(lsah->ls_age);
	case OSPFLSDBCHECKSUM: /* 7 */
		return SNMP_INTEGER(lsah->checksum);
	case OSPFLSDBADVERTISEMENT: /* 8 */
		*var_len = ntohs(lsah->length);
		return (uint8_t *)lsah;
	default:
		return NULL;
	}
	return NULL;
}

static struct ospf_area_range *ospfAreaRangeLookup(struct variable *v,
						   oid *name, size_t *length,
						   struct in_addr *area_id,
						   struct in_addr *range_net,
						   int exact)
{
	oid *offset;
	int offsetlen;
	int len;
	struct ospf *ospf;
	struct ospf_area *area;
	struct ospf_area_range *range;
	struct prefix_ipv4 p;
	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	if (exact) {
		/* Area ID + Range Network. */
		if (v->namelen + IN_ADDR_SIZE + IN_ADDR_SIZE != *length)
			return NULL;

		/* Set OID offset for Area ID. */
		offset = name + v->namelen;

		/* Lookup area first. */
		oid2in_addr(offset, IN_ADDR_SIZE, area_id);

		area = ospf_area_lookup_by_area_id(ospf, *area_id);
		if (!area)
			return NULL;

		offset += IN_ADDR_SIZE;

		/* Lookup area range. */
		oid2in_addr(offset, IN_ADDR_SIZE, range_net);
		p.prefix = *range_net;

		return ospf_area_range_lookup(area, area->ranges, &p);
	} else {
		/* Set OID offset for Area ID. */
		offset = name + v->namelen;
		offsetlen = *length - v->namelen;

		len = offsetlen;
		if (len > (int)IN_ADDR_SIZE)
			len = IN_ADDR_SIZE;

		oid2in_addr(offset, len, area_id);

		/* First we search area. */
		if (len == IN_ADDR_SIZE)
			area = ospf_area_lookup_by_area_id(ospf, *area_id);
		else
			area = ospf_area_lookup_next(ospf, area_id,
						     len == 0 ? 1 : 0);

		if (area == NULL)
			return NULL;

		do {
			offset += IN_ADDR_SIZE;
			offsetlen -= IN_ADDR_SIZE;
			len = offsetlen;

			if (len < 0)
				len = 0;
			if (len > (int)IN_ADDR_SIZE)
				len = IN_ADDR_SIZE;

			oid2in_addr(offset, len, range_net);

			range = ospf_area_range_lookup_next(area, range_net,
							    len == 0 ? 1 : 0);

			if (range) {
				/* Fill in length. */
				*length = v->namelen + IN_ADDR_SIZE
					  + IN_ADDR_SIZE;

				/* Fill in value. */
				offset = name + v->namelen;
				oid_copy_in_addr(offset, area_id);
				offset += IN_ADDR_SIZE;
				oid_copy_in_addr(offset, range_net);

				return range;
			}
		} while ((area = ospf_area_lookup_next(ospf, area_id, 0))
			 != NULL);
	}
	return NULL;
}

static uint8_t *ospfAreaRangeEntry(struct variable *v, oid *name,
				   size_t *length, int exact, size_t *var_len,
				   WriteMethod **write_method)
{
	struct ospf_area_range *range;
	struct in_addr area_id;
	struct in_addr range_net;
	struct in_addr mask;
	struct ospf *ospf;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	/* Check OSPF instance. */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL)
		return NULL;

	memset(&area_id, 0, IN_ADDR_SIZE);
	memset(&range_net, 0, IN_ADDR_SIZE);

	range = ospfAreaRangeLookup(v, name, length, &area_id, &range_net,
				    exact);
	if (!range)
		return NULL;

	/* Convert prefixlen to network mask format. */
	masklen2ip(range->subst_masklen, &mask);

	/* Return the current value of the variable */
	switch (v->magic) {
	case OSPFAREARANGEAREAID: /* 1 */
		return SNMP_IPADDRESS(area_id);
	case OSPFAREARANGENET: /* 2 */
		return SNMP_IPADDRESS(range_net);
	case OSPFAREARANGEMASK: /* 3 */
		return SNMP_IPADDRESS(mask);
	case OSPFAREARANGESTATUS: /* 4 */
		return SNMP_INTEGER(SNMP_VALID);
	case OSPFAREARANGEEFFECT: /* 5 */
#define OSPF_advertiseMatching      1
#define OSPF_doNotAdvertiseMatching 2
		return SNMP_INTEGER(OSPF_advertiseMatching);
	default:
		return NULL;
	}
	return NULL;
}

static struct ospf_nbr_nbma *ospfHostLookup(struct variable *v, oid *name,
					    size_t *length,
					    struct in_addr *addr, int exact)
{
	struct ospf_nbr_nbma *nbr_nbma;
	struct ospf *ospf;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL)
		return NULL;

	if (exact) {
		/* INDEX { ospfHostIpAddress, ospfHostTOS } */
		if (*length != v->namelen + IN_ADDR_SIZE + 1)
			return NULL;

		/* Check ospfHostTOS. */
		if (name[*length - 1] != 0)
			return NULL;

		oid2in_addr(name + v->namelen, IN_ADDR_SIZE, addr);

		nbr_nbma = ospf_nbr_nbma_lookup(ospf, *addr);

		return nbr_nbma;
	}

	return NULL;
}

static uint8_t *ospfHostEntry(struct variable *v, oid *name, size_t *length,
			      int exact, size_t *var_len,
			      WriteMethod **write_method)
{
	struct ospf_nbr_nbma *nbr_nbma;
	struct ospf_interface *oi;
	struct in_addr addr;
	struct ospf *ospf;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	/* Check OSPF instance. */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL)
		return NULL;

	memset(&addr, 0, sizeof(addr));

	nbr_nbma = ospfHostLookup(v, name, length, &addr, exact);
	if (nbr_nbma == NULL)
		return NULL;

	oi = nbr_nbma->oi;

	/* Return the current value of the variable */
	switch (v->magic) {
	case OSPFHOSTIPADDRESS: /* 1 */
		return SNMP_IPADDRESS(nbr_nbma->addr);
	case OSPFHOSTTOS: /* 2 */
		return SNMP_INTEGER(0);
	case OSPFHOSTMETRIC: /* 3 */
		if (oi)
			return SNMP_INTEGER(oi->output_cost);
		else
			return SNMP_INTEGER(1);
	case OSPFHOSTSTATUS: /* 4 */
		return SNMP_INTEGER(SNMP_VALID);
	case OSPFHOSTAREAID: /* 5 */
		if (oi && oi->area)
			return SNMP_IPADDRESS(oi->area->area_id);
		else
			return SNMP_IPADDRESS(ospf_empty_addr);
	default:
		return NULL;
	}
	return NULL;
}

static struct list *ospf_snmp_iflist;

struct ospf_snmp_if {
	struct in_addr addr;
	ifindex_t ifindex;
	struct interface *ifp;
};

static struct ospf_snmp_if *ospf_snmp_if_new(void)
{
	return XCALLOC(MTYPE_SNMP, sizeof(struct ospf_snmp_if));
}

static void ospf_snmp_if_free(struct ospf_snmp_if *osif)
{
	XFREE(MTYPE_SNMP, osif);
}

static int ospf_snmp_if_delete(struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct ospf_snmp_if *osif;

	for (ALL_LIST_ELEMENTS(ospf_snmp_iflist, node, nnode, osif)) {
		if (osif->ifp == ifp) {
			list_delete_node(ospf_snmp_iflist, node);
			ospf_snmp_if_free(osif);
			break;
		}
	}
	return 0;
}

static int ospf_snmp_if_update(struct interface *ifp)
{
	struct listnode *node;
	struct listnode *pn;
	struct connected *ifc;
	struct prefix *p;
	struct ospf_snmp_if *osif;
	struct in_addr *addr;
	ifindex_t ifindex;

	ospf_snmp_if_delete(ifp);

	p = NULL;
	addr = NULL;
	ifindex = 0;

	/* Lookup first IPv4 address entry. */
	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc)) {
		p = CONNECTED_ID(ifc);

		if (p->family == AF_INET) {
			addr = &p->u.prefix4;
			break;
		}
	}
	if (!addr)
		ifindex = ifp->ifindex;

	/* Add interface to the list. */
	pn = NULL;
	for (ALL_LIST_ELEMENTS_RO(ospf_snmp_iflist, node, osif)) {
		if (addr) {
			/* Usual interfaces --> Sort them based on interface
			 * IPv4 addresses */
			if (ntohl(osif->addr.s_addr) > ntohl(addr->s_addr))
				break;
		} else {
			/* Unnumbered interfaces --> Sort them based on
			 * interface indexes */
			if (osif->addr.s_addr != INADDR_ANY
			    || osif->ifindex > ifindex)
				break;
		}
		pn = node;
	}

	osif = ospf_snmp_if_new();
	if (addr) /* Usual interface */
	{
		osif->addr = *addr;

		/* This field is used for storing ospfAddressLessIf OID value,
		 * conform to RFC1850 OSPF-MIB specification, it must be 0 for
		 * usual interface */
		osif->ifindex = 0;
	} else /* Unnumbered interface */
		osif->ifindex = ifindex;
	osif->ifp = ifp;

	listnode_add_after(ospf_snmp_iflist, pn, osif);
	return 0;
}

static int ospf_snmp_is_if_have_addr(struct interface *ifp)
{
	struct listnode *nn;
	struct connected *ifc;

	/* Is this interface having any connected IPv4 address ? */
	for (ALL_LIST_ELEMENTS_RO(ifp->connected, nn, ifc)) {
		if (CONNECTED_PREFIX(ifc)->family == AF_INET)
			return 1;
	}

	return 0;
}

static struct ospf_interface *ospf_snmp_if_lookup(struct in_addr *ifaddr,
						  ifindex_t *ifindex)
{
	struct listnode *node;
	struct ospf_snmp_if *osif;
	struct ospf_interface *oi = NULL;
	struct ospf *ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	for (ALL_LIST_ELEMENTS_RO(ospf_snmp_iflist, node, osif)) {
		if (ifaddr->s_addr) {
			if (IPV4_ADDR_SAME(&osif->addr, ifaddr))
				oi = ospf_if_lookup_by_local_addr(
					ospf, osif->ifp, *ifaddr);
		} else {
			if (osif->ifindex == *ifindex)
				oi = ospf_if_lookup_by_local_addr(
					ospf, osif->ifp, *ifaddr);
		}
	}
	return oi;
}

static struct ospf_interface *ospf_snmp_if_lookup_next(struct in_addr *ifaddr,
						       ifindex_t *ifindex,
						       int ifaddr_next,
						       ifindex_t ifindex_next)
{
	struct ospf_snmp_if *osif;
	struct listnode *nn;
	struct ospf *ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	struct ospf_interface *oi = NULL;

	if (ospf == NULL)
		return NULL;

	/* No instance is specified --> Return the first OSPF interface */
	if (ifaddr_next) {
		for (ALL_LIST_ELEMENTS_RO(ospf_snmp_iflist, nn, osif)) {
			osif = listgetdata(nn);
			*ifaddr = osif->addr;
			*ifindex = osif->ifindex;
			/* Because no instance is specified, we don't care about
			 * the kind of
			 * interface (usual or unnumbered), just returning the
			 * first valid
			 * OSPF interface */
			oi = ospf_if_lookup_by_local_addr(ospf, osif->ifp,
							  *ifaddr);
			if (oi)
				return (oi);
		}
		return NULL;
	}

	/* An instance is specified --> Return the next OSPF interface */
	for (ALL_LIST_ELEMENTS_RO(ospf_snmp_iflist, nn, osif)) {
		/* Usual interface */
		if (ifaddr->s_addr) {
			/* The interface must have valid AF_INET connected
			 * address */
			/* it must have lager IPv4 address value than the lookup
			 * entry */
			if ((ospf_snmp_is_if_have_addr(osif->ifp))
			    && (ntohl(osif->addr.s_addr)
				> ntohl(ifaddr->s_addr))) {
				*ifaddr = osif->addr;
				*ifindex = osif->ifindex;

				/* and it must be an OSPF interface */
				oi = ospf_if_lookup_by_local_addr(
					ospf, osif->ifp, *ifaddr);
				if (oi)
					return oi;
			}
		}
		/* Unnumbered interface */
		else
			/* The interface must NOT have valid AF_INET connected
			   address */
			/* it must have lager interface index than the lookup
			   entry */
			if ((!ospf_snmp_is_if_have_addr(osif->ifp))
			    && (osif->ifindex > *ifindex)) {
			*ifaddr = osif->addr;
			*ifindex = osif->ifindex;

			/* and it must be an OSPF interface */
			oi = ospf_if_lookup_by_local_addr(ospf, osif->ifp,
							  *ifaddr);
			if (oi)
				return oi;
		}
	}
	return NULL;
}

static int ospf_snmp_iftype(struct interface *ifp)
{
#define ospf_snmp_iftype_broadcast         1
#define ospf_snmp_iftype_nbma              2
#define ospf_snmp_iftype_pointToPoint      3
#define ospf_snmp_iftype_pointToMultipoint 5
	if (if_is_broadcast(ifp))
		return ospf_snmp_iftype_broadcast;
	if (if_is_pointopoint(ifp))
		return ospf_snmp_iftype_pointToPoint;
	return ospf_snmp_iftype_broadcast;
}

static struct ospf_interface *ospfIfLookup(struct variable *v, oid *name,
					   size_t *length,
					   struct in_addr *ifaddr,
					   ifindex_t *ifindex, int exact)
{
	unsigned int len;
	int ifaddr_next = 0;
	ifindex_t ifindex_next = 0;
	struct ospf_interface *oi;
	oid *offset;

	if (exact) {
		if (*length != v->namelen + IN_ADDR_SIZE + 1)
			return NULL;

		oid2in_addr(name + v->namelen, IN_ADDR_SIZE, ifaddr);
		*ifindex = name[v->namelen + IN_ADDR_SIZE];

		return ospf_snmp_if_lookup(ifaddr, ifindex);
	} else {
		len = *length - v->namelen;
		if (len >= IN_ADDR_SIZE)
			len = IN_ADDR_SIZE;
		if (len == 0)
			ifaddr_next = 1;

		oid2in_addr(name + v->namelen, len, ifaddr);

		len = *length - v->namelen - IN_ADDR_SIZE;
		if (len >= 1)
			len = 1;
		else
			ifindex_next = 1;

		if (len == 1)
			*ifindex = name[v->namelen + IN_ADDR_SIZE];

		oi = ospf_snmp_if_lookup_next(ifaddr, ifindex, ifaddr_next,
					      ifindex_next);
		if (oi) {
			*length = v->namelen + IN_ADDR_SIZE + 1;
			offset = name + v->namelen;
			oid_copy_in_addr(offset, ifaddr);
			offset += IN_ADDR_SIZE;
			*offset = *ifindex;
			return oi;
		}
	}
	return NULL;
}

static uint8_t *ospfIfEntry(struct variable *v, oid *name, size_t *length,
			    int exact, size_t *var_len,
			    WriteMethod **write_method)
{
	ifindex_t ifindex;
	struct in_addr ifaddr;
	struct ospf_interface *oi;
	struct ospf *ospf;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	ifindex = 0;
	memset(&ifaddr, 0, sizeof(ifaddr));

	/* Check OSPF instance. */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL)
		return NULL;

	oi = ospfIfLookup(v, name, length, &ifaddr, &ifindex, exact);
	if (oi == NULL)
		return NULL;

	/* Return the current value of the variable */
	switch (v->magic) {
	case OSPFIFIPADDRESS: /* 1 */
		return SNMP_IPADDRESS(ifaddr);
	case OSPFADDRESSLESSIF: /* 2 */
		return SNMP_INTEGER(ifindex);
	case OSPFIFAREAID: /* 3 */
		if (oi->area)
			return SNMP_IPADDRESS(oi->area->area_id);
		else
			return SNMP_IPADDRESS(ospf_empty_addr);
	case OSPFIFTYPE: /* 4 */
		return SNMP_INTEGER(ospf_snmp_iftype(oi->ifp));
	case OSPFIFADMINSTAT: /* 5 */
		if (oi)
			return SNMP_INTEGER(OSPF_STATUS_ENABLED);
		else
			return SNMP_INTEGER(OSPF_STATUS_DISABLED);
	case OSPFIFRTRPRIORITY: /* 6 */
		return SNMP_INTEGER(PRIORITY(oi));
	case OSPFIFTRANSITDELAY: /* 7 */
		return SNMP_INTEGER(OSPF_IF_PARAM(oi, transmit_delay));
	case OSPFIFRETRANSINTERVAL: /* 8 */
		return SNMP_INTEGER(OSPF_IF_PARAM(oi, retransmit_interval));
	case OSPFIFHELLOINTERVAL: /* 9 */
		return SNMP_INTEGER(OSPF_IF_PARAM(oi, v_hello));
	case OSPFIFRTRDEADINTERVAL: /* 10 */
		return SNMP_INTEGER(OSPF_IF_PARAM(oi, v_wait));
	case OSPFIFPOLLINTERVAL: /* 11 */
		return SNMP_INTEGER(OSPF_POLL_INTERVAL_DEFAULT);
	case OSPFIFSTATE: /* 12 */
		return SNMP_INTEGER(ISM_SNMP(oi->state));
	case OSPFIFDESIGNATEDROUTER: /* 13 */
		return SNMP_IPADDRESS(DR(oi));
	case OSPFIFBACKUPDESIGNATEDROUTER: /* 14 */
		return SNMP_IPADDRESS(BDR(oi));
	case OSPFIFEVENTS: /* 15 */
		return SNMP_INTEGER(oi->state_change);
	case OSPFIFAUTHKEY: /* 16 */
		*var_len = 0;
		return (uint8_t *)OSPF_IF_PARAM(oi, auth_simple);
	case OSPFIFSTATUS: /* 17 */
		return SNMP_INTEGER(SNMP_VALID);
	case OSPFIFMULTICASTFORWARDING: /* 18 */
#define ospf_snmp_multiforward_blocked    1
#define ospf_snmp_multiforward_multicast  2
#define ospf_snmp_multiforward_unicast    3
		return SNMP_INTEGER(ospf_snmp_multiforward_blocked);
	case OSPFIFDEMAND: /* 19 */
		return SNMP_INTEGER(SNMP_FALSE);
	case OSPFIFAUTHTYPE: /* 20 */
		if (oi->area)
			return SNMP_INTEGER(oi->area->auth_type);
		else
			return SNMP_INTEGER(0);
	default:
		return NULL;
	}
	return NULL;
}

#define OSPF_SNMP_METRIC_VALUE 1

static struct ospf_interface *ospfIfMetricLookup(struct variable *v, oid *name,
						 size_t *length,
						 struct in_addr *ifaddr,
						 ifindex_t *ifindex, int exact)
{
	unsigned int len;
	int ifaddr_next = 0;
	ifindex_t ifindex_next = 0;
	struct ospf_interface *oi;
	oid *offset;
	int metric;

	if (exact) {
		if (*length != v->namelen + IN_ADDR_SIZE + 1 + 1)
			return NULL;

		oid2in_addr(name + v->namelen, IN_ADDR_SIZE, ifaddr);
		*ifindex = name[v->namelen + IN_ADDR_SIZE];
		metric = name[v->namelen + IN_ADDR_SIZE + 1];

		if (metric != OSPF_SNMP_METRIC_VALUE)
			return NULL;

		return ospf_snmp_if_lookup(ifaddr, ifindex);
	} else {
		len = *length - v->namelen;
		if (len >= IN_ADDR_SIZE)
			len = IN_ADDR_SIZE;
		else
			ifaddr_next = 1;

		oid2in_addr(name + v->namelen, len, ifaddr);

		len = *length - v->namelen - IN_ADDR_SIZE;
		if (len >= 1)
			len = 1;
		else
			ifindex_next = 1;

		if (len == 1)
			*ifindex = name[v->namelen + IN_ADDR_SIZE];

		oi = ospf_snmp_if_lookup_next(ifaddr, ifindex, ifaddr_next,
					      ifindex_next);
		if (oi) {
			*length = v->namelen + IN_ADDR_SIZE + 1 + 1;
			offset = name + v->namelen;
			oid_copy_in_addr(offset, ifaddr);
			offset += IN_ADDR_SIZE;
			*offset = *ifindex;
			offset++;
			*offset = OSPF_SNMP_METRIC_VALUE;
			return oi;
		}
	}
	return NULL;
}

static uint8_t *ospfIfMetricEntry(struct variable *v, oid *name, size_t *length,
				  int exact, size_t *var_len,
				  WriteMethod **write_method)
{
	/* Currently we support metric 1 only. */
	ifindex_t ifindex;
	struct in_addr ifaddr;
	struct ospf_interface *oi;
	struct ospf *ospf;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	ifindex = 0;
	memset(&ifaddr, 0, sizeof(ifaddr));

	/* Check OSPF instance. */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL)
		return NULL;

	oi = ospfIfMetricLookup(v, name, length, &ifaddr, &ifindex, exact);
	if (oi == NULL)
		return NULL;

	/* Return the current value of the variable */
	switch (v->magic) {
	case OSPFIFMETRICIPADDRESS:
		return SNMP_IPADDRESS(ifaddr);
	case OSPFIFMETRICADDRESSLESSIF:
		return SNMP_INTEGER(ifindex);
	case OSPFIFMETRICTOS:
		return SNMP_INTEGER(0);
	case OSPFIFMETRICVALUE:
		return SNMP_INTEGER(OSPF_SNMP_METRIC_VALUE);
	case OSPFIFMETRICSTATUS:
		return SNMP_INTEGER(1);
	default:
		return NULL;
	}
	return NULL;
}

static struct route_table *ospf_snmp_vl_table;

static int ospf_snmp_vl_add(struct ospf_vl_data *vl_data)
{
	struct prefix_ls lp;
	struct route_node *rn;

	memset(&lp, 0, sizeof(lp));
	lp.family = AF_UNSPEC;
	lp.prefixlen = 64;
	lp.id = vl_data->vl_area_id;
	lp.adv_router = vl_data->vl_peer;

	rn = route_node_get(ospf_snmp_vl_table, (struct prefix *)&lp);
	if (rn->info)
		route_unlock_node(rn);

	rn->info = vl_data;
	return 0;
}

static int ospf_snmp_vl_delete(struct ospf_vl_data *vl_data)
{
	struct prefix_ls lp;
	struct route_node *rn;

	memset(&lp, 0, sizeof(lp));
	lp.family = AF_UNSPEC;
	lp.prefixlen = 64;
	lp.id = vl_data->vl_area_id;
	lp.adv_router = vl_data->vl_peer;

	rn = route_node_lookup(ospf_snmp_vl_table, (struct prefix *)&lp);
	if (!rn)
		return 0;
	rn->info = NULL;
	route_unlock_node(rn);
	route_unlock_node(rn);
	return 0;
}

static struct ospf_vl_data *ospf_snmp_vl_lookup(struct in_addr *area_id,
						struct in_addr *neighbor)
{
	struct prefix_ls lp;
	struct route_node *rn;
	struct ospf_vl_data *vl_data;

	memset(&lp, 0, sizeof(lp));
	lp.family = AF_UNSPEC;
	lp.prefixlen = 64;
	lp.id = *area_id;
	lp.adv_router = *neighbor;

	rn = route_node_lookup(ospf_snmp_vl_table, (struct prefix *)&lp);
	if (rn) {
		vl_data = rn->info;
		route_unlock_node(rn);
		return vl_data;
	}
	return NULL;
}

static struct ospf_vl_data *ospf_snmp_vl_lookup_next(struct in_addr *area_id,
						     struct in_addr *neighbor,
						     int first)
{
	struct prefix_ls lp;
	struct route_node *rn;
	struct ospf_vl_data *vl_data;

	memset(&lp, 0, sizeof(lp));
	lp.family = AF_UNSPEC;
	lp.prefixlen = 64;
	lp.id = *area_id;
	lp.adv_router = *neighbor;

	if (first)
		rn = route_top(ospf_snmp_vl_table);
	else {
		rn = route_node_get(ospf_snmp_vl_table, (struct prefix *)&lp);
		rn = route_next(rn);
	}

	for (; rn; rn = route_next(rn))
		if (rn->info)
			break;

	if (rn && rn->info) {
		vl_data = rn->info;
		*area_id = vl_data->vl_area_id;
		*neighbor = vl_data->vl_peer;
		route_unlock_node(rn);
		return vl_data;
	}
	return NULL;
}

static struct ospf_vl_data *
ospfVirtIfLookup(struct variable *v, oid *name, size_t *length,
		 struct in_addr *area_id, struct in_addr *neighbor, int exact)
{
	int first;
	unsigned int len;
	struct ospf_vl_data *vl_data;

	if (exact) {
		if (*length != v->namelen + IN_ADDR_SIZE + IN_ADDR_SIZE)
			return NULL;

		oid2in_addr(name + v->namelen, IN_ADDR_SIZE, area_id);
		oid2in_addr(name + v->namelen + IN_ADDR_SIZE, IN_ADDR_SIZE,
			    neighbor);

		return ospf_snmp_vl_lookup(area_id, neighbor);
	} else {
		first = 0;

		len = *length - v->namelen;
		if (len == 0)
			first = 1;
		if (len > IN_ADDR_SIZE)
			len = IN_ADDR_SIZE;
		oid2in_addr(name + v->namelen, len, area_id);

		len = *length - v->namelen - IN_ADDR_SIZE;
		if (len > IN_ADDR_SIZE)
			len = IN_ADDR_SIZE;
		oid2in_addr(name + v->namelen + IN_ADDR_SIZE, len, neighbor);

		vl_data = ospf_snmp_vl_lookup_next(area_id, neighbor, first);

		if (vl_data) {
			*length = v->namelen + IN_ADDR_SIZE + IN_ADDR_SIZE;
			oid_copy_in_addr(name + v->namelen, area_id);
			oid_copy_in_addr(name + v->namelen + IN_ADDR_SIZE,
					 neighbor);
			return vl_data;
		}
	}
	return NULL;
}

static uint8_t *ospfVirtIfEntry(struct variable *v, oid *name, size_t *length,
				int exact, size_t *var_len,
				WriteMethod **write_method)
{
	struct ospf_vl_data *vl_data;
	struct ospf_interface *oi;
	struct in_addr area_id;
	struct in_addr neighbor;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	memset(&area_id, 0, sizeof(area_id));
	memset(&neighbor, 0, sizeof(neighbor));

	vl_data = ospfVirtIfLookup(v, name, length, &area_id, &neighbor, exact);
	if (!vl_data)
		return NULL;
	oi = vl_data->vl_oi;
	if (!oi)
		return NULL;

	/* Return the current value of the variable */
	switch (v->magic) {
	case OSPFVIRTIFAREAID:
		return SNMP_IPADDRESS(area_id);
	case OSPFVIRTIFNEIGHBOR:
		return SNMP_IPADDRESS(neighbor);
	case OSPFVIRTIFTRANSITDELAY:
		return SNMP_INTEGER(OSPF_IF_PARAM(oi, transmit_delay));
	case OSPFVIRTIFRETRANSINTERVAL:
		return SNMP_INTEGER(OSPF_IF_PARAM(oi, retransmit_interval));
	case OSPFVIRTIFHELLOINTERVAL:
		return SNMP_INTEGER(OSPF_IF_PARAM(oi, v_hello));
	case OSPFVIRTIFRTRDEADINTERVAL:
		return SNMP_INTEGER(OSPF_IF_PARAM(oi, v_wait));
	case OSPFVIRTIFSTATE:
		return SNMP_INTEGER(oi->state);
	case OSPFVIRTIFEVENTS:
		return SNMP_INTEGER(oi->state_change);
	case OSPFVIRTIFAUTHKEY:
		*var_len = 0;
		return (uint8_t *)OSPF_IF_PARAM(oi, auth_simple);
	case OSPFVIRTIFSTATUS:
		return SNMP_INTEGER(SNMP_VALID);
	case OSPFVIRTIFAUTHTYPE:
		if (oi->area)
			return SNMP_INTEGER(oi->area->auth_type);
		else
			return SNMP_INTEGER(0);
	default:
		return NULL;
	}
	return NULL;
}

static struct ospf_neighbor *ospf_snmp_nbr_lookup(struct ospf *ospf,
						  struct in_addr *nbr_addr,
						  ifindex_t *ifindex)
{
	struct listnode *node, *nnode;
	struct ospf_interface *oi;
	struct ospf_neighbor *nbr;
	struct route_node *rn;

	for (ALL_LIST_ELEMENTS(ospf->oiflist, node, nnode, oi)) {
		for (rn = route_top(oi->nbrs); rn; rn = route_next(rn))
			if ((nbr = rn->info) != NULL
			    && nbr != oi->nbr_self
			    /* If EXACT match is needed, provide ALL entry found
					&& nbr->state != NSM_Down
			     */
			    && nbr->src.s_addr != INADDR_ANY) {
				if (IPV4_ADDR_SAME(&nbr->src, nbr_addr)) {
					route_unlock_node(rn);
					return nbr;
				}
			}
	}
	return NULL;
}

static struct ospf_neighbor *ospf_snmp_nbr_lookup_next(struct in_addr *nbr_addr,
						       ifindex_t *ifindex,
						       int first)
{
	struct listnode *nn;
	struct ospf_interface *oi;
	struct ospf_neighbor *nbr;
	struct route_node *rn;
	struct ospf_neighbor *min = NULL;
	struct ospf *ospf;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, nn, oi)) {
		for (rn = route_top(oi->nbrs); rn; rn = route_next(rn))
			if ((nbr = rn->info) != NULL && nbr != oi->nbr_self
			    && nbr->state != NSM_Down
			    && nbr->src.s_addr != INADDR_ANY) {
				if (first) {
					if (!min)
						min = nbr;
					else if (ntohl(nbr->src.s_addr)
						 < ntohl(min->src.s_addr))
						min = nbr;
				} else if (ntohl(nbr->src.s_addr)
					   > ntohl(nbr_addr->s_addr)) {
					if (!min)
						min = nbr;
					else if (ntohl(nbr->src.s_addr)
						 < ntohl(min->src.s_addr))
						min = nbr;
				}
			}
	}
	if (min) {
		*nbr_addr = min->src;
		*ifindex = 0;
		return min;
	}
	return NULL;
}

static struct ospf_neighbor *ospfNbrLookup(struct variable *v, oid *name,
					   size_t *length,
					   struct in_addr *nbr_addr,
					   ifindex_t *ifindex, int exact)
{
	unsigned int len;
	int first;
	struct ospf_neighbor *nbr;
	struct ospf *ospf;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	if (!ospf)
		return NULL;

	if (exact) {
		if (*length != v->namelen + IN_ADDR_SIZE + 1)
			return NULL;

		oid2in_addr(name + v->namelen, IN_ADDR_SIZE, nbr_addr);
		*ifindex = name[v->namelen + IN_ADDR_SIZE];

		return ospf_snmp_nbr_lookup(ospf, nbr_addr, ifindex);
	} else {
		first = 0;
		len = *length - v->namelen;

		if (len == 0)
			first = 1;

		if (len > IN_ADDR_SIZE)
			len = IN_ADDR_SIZE;

		oid2in_addr(name + v->namelen, len, nbr_addr);

		len = *length - v->namelen - IN_ADDR_SIZE;
		if (len >= 1)
			*ifindex = name[v->namelen + IN_ADDR_SIZE];

		nbr = ospf_snmp_nbr_lookup_next(nbr_addr, ifindex, first);

		if (nbr) {
			*length = v->namelen + IN_ADDR_SIZE + 1;
			oid_copy_in_addr(name + v->namelen, nbr_addr);
			name[v->namelen + IN_ADDR_SIZE] = *ifindex;
			return nbr;
		}
	}
	return NULL;
}

/* map internal frr neighbor states to official MIB values:

ospfNbrState OBJECT-TYPE
	SYNTAX   INTEGER    {
		    down (1),
		    attempt (2),
		    init (3),
		    twoWay (4),
		    exchangeStart (5),
		    exchange (6),
		    loading (7),
		    full (8)
		  }
*/
static int32_t ospf_snmp_neighbor_state(uint8_t nst)
{
	switch (nst) {
	case NSM_Attempt:
		return 2;
	case NSM_Init:
		return 3;
	case NSM_TwoWay:
		return 4;
	case NSM_ExStart:
		return 5;
	case NSM_Exchange:
		return 6;
	case NSM_Loading:
		return 7;
	case NSM_Full:
		return 8;
	default:
		return 1; /* down */
	}
}

static uint8_t *ospfNbrEntry(struct variable *v, oid *name, size_t *length,
			     int exact, size_t *var_len,
			     WriteMethod **write_method)
{
	struct in_addr nbr_addr;
	ifindex_t ifindex;
	struct ospf_neighbor *nbr;
	struct ospf_interface *oi;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	memset(&nbr_addr, 0, sizeof(nbr_addr));
	ifindex = 0;

	nbr = ospfNbrLookup(v, name, length, &nbr_addr, &ifindex, exact);
	if (!nbr)
		return NULL;
	oi = nbr->oi;

	/* Return the current value of the variable */
	switch (v->magic) {
	case OSPFNBRIPADDR:
		return SNMP_IPADDRESS(nbr_addr);
	case OSPFNBRADDRESSLESSINDEX:
		return SNMP_INTEGER(ifindex);
	case OSPFNBRRTRID:
		return SNMP_IPADDRESS(nbr->router_id);
	case OSPFNBROPTIONS:
		return SNMP_INTEGER(oi->nbr_self->options);
	case OSPFNBRPRIORITY:
		return SNMP_INTEGER(nbr->priority);
	case OSPFNBRSTATE:
		return SNMP_INTEGER(ospf_snmp_neighbor_state(nbr->state));
	case OSPFNBREVENTS:
		return SNMP_INTEGER(nbr->state_change);
	case OSPFNBRLSRETRANSQLEN:
		return SNMP_INTEGER(ospf_ls_retransmit_count(nbr));
	case OSPFNBMANBRSTATUS:
		return SNMP_INTEGER(SNMP_VALID);
	case OSPFNBMANBRPERMANENCE:
		return SNMP_INTEGER(2);
	case OSPFNBRHELLOSUPPRESSED:
		return SNMP_INTEGER(SNMP_FALSE);
	default:
		return NULL;
	}
	return NULL;
}

static uint8_t *ospfVirtNbrEntry(struct variable *v, oid *name, size_t *length,
				 int exact, size_t *var_len,
				 WriteMethod **write_method)
{
	struct ospf_vl_data *vl_data;
	struct in_addr area_id;
	struct in_addr neighbor;
	struct ospf *ospf;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	memset(&area_id, 0, sizeof(area_id));
	memset(&neighbor, 0, sizeof(neighbor));

	/* Check OSPF instance. */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL)
		return NULL;

	vl_data = ospfVirtIfLookup(v, name, length, &area_id, &neighbor, exact);
	if (!vl_data)
		return NULL;

	/* Return the current value of the variable */
	switch (v->magic) {
	case OSPFVIRTNBRAREA:
		return (uint8_t *)NULL;
	case OSPFVIRTNBRRTRID:
		return (uint8_t *)NULL;
	case OSPFVIRTNBRIPADDR:
		return (uint8_t *)NULL;
	case OSPFVIRTNBROPTIONS:
		return (uint8_t *)NULL;
	case OSPFVIRTNBRSTATE:
		return (uint8_t *)NULL;
	case OSPFVIRTNBREVENTS:
		return (uint8_t *)NULL;
	case OSPFVIRTNBRLSRETRANSQLEN:
		return (uint8_t *)NULL;
	case OSPFVIRTNBRHELLOSUPPRESSED:
		return (uint8_t *)NULL;
	default:
		return NULL;
	}
	return NULL;
}

static struct ospf_lsa *ospfExtLsdbLookup(struct variable *v, oid *name,
					  size_t *length, uint8_t *type,
					  struct in_addr *ls_id,
					  struct in_addr *router_id, int exact)
{
	int first;
	oid *offset;
	int offsetlen;
	uint8_t lsa_type;
	unsigned int len;
	struct ospf_lsa *lsa;
	struct ospf *ospf;

	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (exact) {
		if (*length != v->namelen + 1 + IN_ADDR_SIZE + IN_ADDR_SIZE)
			return NULL;

		offset = name + v->namelen;

		/* Make it sure given value match to type. */
		lsa_type = *offset;
		offset++;

		if (lsa_type != *type)
			return NULL;

		/* LS ID. */
		oid2in_addr(offset, IN_ADDR_SIZE, ls_id);
		offset += IN_ADDR_SIZE;

		/* Router ID. */
		oid2in_addr(offset, IN_ADDR_SIZE, router_id);

		return ospf_lsdb_lookup_by_id(ospf->lsdb, *type, *ls_id,
					      *router_id);
	} else {
		/* Get variable length. */
		first = 0;
		offset = name + v->namelen;
		offsetlen = *length - v->namelen;

		/* LSA type value. */
		lsa_type = *offset;
		offset++;
		offsetlen--;

		if (offsetlen <= 0 || lsa_type < OSPF_AS_EXTERNAL_LSA)
			first = 1;

		/* LS ID. */
		len = offsetlen;
		if (len > IN_ADDR_SIZE)
			len = IN_ADDR_SIZE;

		oid2in_addr(offset, len, ls_id);

		offset += IN_ADDR_SIZE;
		offsetlen -= IN_ADDR_SIZE;

		/* Router ID. */
		len = offsetlen;
		if (len > IN_ADDR_SIZE)
			len = IN_ADDR_SIZE;

		oid2in_addr(offset, len, router_id);

		lsa = ospf_lsdb_lookup_by_id_next(ospf->lsdb, *type, *ls_id,
						  *router_id, first);

		if (lsa) {
			/* Fill in length. */
			*length = v->namelen + 1 + IN_ADDR_SIZE + IN_ADDR_SIZE;

			/* Fill in value. */
			offset = name + v->namelen;

			*offset = OSPF_AS_EXTERNAL_LSA;
			offset++;
			oid_copy_in_addr(offset, &lsa->data->id);
			offset += IN_ADDR_SIZE;
			oid_copy_in_addr(offset, &lsa->data->adv_router);

			return lsa;
		}
	}
	return NULL;
}

static uint8_t *ospfExtLsdbEntry(struct variable *v, oid *name, size_t *length,
				 int exact, size_t *var_len,
				 WriteMethod **write_method)
{
	struct ospf_lsa *lsa;
	struct lsa_header *lsah;
	uint8_t type;
	struct in_addr ls_id;
	struct in_addr router_id;
	struct ospf *ospf;

	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	type = OSPF_AS_EXTERNAL_LSA;
	memset(&ls_id, 0, sizeof(ls_id));
	memset(&router_id, 0, sizeof(router_id));

	/* Check OSPF instance. */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL)
		return NULL;

	lsa = ospfExtLsdbLookup(v, name, length, &type, &ls_id, &router_id,
				exact);
	if (!lsa)
		return NULL;

	lsah = lsa->data;

	/* Return the current value of the variable */
	switch (v->magic) {
	case OSPFEXTLSDBTYPE:
		return SNMP_INTEGER(OSPF_AS_EXTERNAL_LSA);
	case OSPFEXTLSDBLSID:
		return SNMP_IPADDRESS(lsah->id);
	case OSPFEXTLSDBROUTERID:
		return SNMP_IPADDRESS(lsah->adv_router);
	case OSPFEXTLSDBSEQUENCE:
		return SNMP_INTEGER(lsah->ls_seqnum);
	case OSPFEXTLSDBAGE:
		return SNMP_INTEGER(lsah->ls_age);
	case OSPFEXTLSDBCHECKSUM:
		return SNMP_INTEGER(lsah->checksum);
	case OSPFEXTLSDBADVERTISEMENT:
		*var_len = ntohs(lsah->length);
		return (uint8_t *)lsah;
	default:
		return NULL;
	}
	return NULL;
}

static uint8_t *ospfAreaAggregateEntry(struct variable *v, oid *name,
				       size_t *length, int exact,
				       size_t *var_len,
				       WriteMethod **write_method)
{
	if (smux_header_table(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	/* Return the current value of the variable */
	switch (v->magic) {
	case OSPFAREAAGGREGATEAREAID:
		return (uint8_t *)NULL;
	case OSPFAREAAGGREGATELSDBTYPE:
		return (uint8_t *)NULL;
	case OSPFAREAAGGREGATENET:
		return (uint8_t *)NULL;
	case OSPFAREAAGGREGATEMASK:
		return (uint8_t *)NULL;
	case OSPFAREAAGGREGATESTATUS:
		return (uint8_t *)NULL;
	case OSPFAREAAGGREGATEEFFECT:
		return (uint8_t *)NULL;
	default:
		return NULL;
	}
	return NULL;
}

/* OSPF Traps. */
#define IFSTATECHANGE      16
#define VIRTIFSTATECHANGE   1
#define NBRSTATECHANGE      2
#define VIRTNBRSTATECHANGE  3

static struct trap_object ospfNbrTrapList[] = {{-2, {1, OSPFROUTERID}},
					       {3, {10, 1, OSPFNBRIPADDR}},
					       {3, {10, 1, OSPFNBRRTRID}},
					       {3, {10, 1, OSPFNBRSTATE}}};


static struct trap_object ospfVirtNbrTrapList[] = {
	{-2, {1, 1}},
	{3, {11, 1, OSPFVIRTNBRAREA}},
	{3, {11, 1, OSPFVIRTNBRRTRID}},
	{3, {11, 1, OSPFVIRTNBRSTATE}}};

static struct trap_object ospfIfTrapList[] = {{-2, {1, OSPFROUTERID}},
					      {3, {7, 1, OSPFIFIPADDRESS}},
					      {3, {7, 1, OSPFADDRESSLESSIF}},
					      {3, {7, 1, OSPFIFSTATE}}};

static struct trap_object ospfVirtIfTrapList[] = {
	{-2, {1, OSPFROUTERID}},
	{3, {9, 1, OSPFVIRTIFAREAID}},
	{3, {9, 1, OSPFVIRTIFNEIGHBOR}},
	{3, {9, 1, OSPFVIRTIFSTATE}}};

static void ospfTrapNbrStateChange(struct ospf_neighbor *on)
{
	oid index[sizeof(oid) * (IN_ADDR_SIZE + 1)];
	char msgbuf[16];

	ospf_nbr_ism_state_message(on, msgbuf, sizeof(msgbuf));
	if (IS_DEBUG_OSPF_EVENT)
		zlog_info("%s: trap sent: %pI4 now %s", __func__,
			  &on->address.u.prefix4, msgbuf);

	oid_copy_in_addr(index, &(on->address.u.prefix4));
	index[IN_ADDR_SIZE] = 0;

	smux_trap(ospf_variables, array_size(ospf_variables), ospf_trap_oid,
		  array_size(ospf_trap_oid), ospf_oid,
		  sizeof(ospf_oid) / sizeof(oid), index, IN_ADDR_SIZE + 1,
		  ospfNbrTrapList, array_size(ospfNbrTrapList), NBRSTATECHANGE);
}

static void ospfTrapVirtNbrStateChange(struct ospf_neighbor *on)
{
	oid index[sizeof(oid) * (IN_ADDR_SIZE + 1)];

	zlog_info("ospfTrapVirtNbrStateChange trap sent");

	oid_copy_in_addr(index, &(on->address.u.prefix4));
	index[IN_ADDR_SIZE] = 0;

	smux_trap(ospf_variables, array_size(ospf_variables), ospf_trap_oid,
		  array_size(ospf_trap_oid), ospf_oid,
		  sizeof(ospf_oid) / sizeof(oid), index, IN_ADDR_SIZE + 1,
		  ospfVirtNbrTrapList, array_size(ospfVirtNbrTrapList),
		  VIRTNBRSTATECHANGE);
}

static int ospf_snmp_nsm_change(struct ospf_neighbor *nbr, int next_state,
				int old_state)
{
	/* Transition to/from state Full should be handled only by
	 * DR when in Broadcast or Non-Brodcast Multi-Access networks
	 */
	if ((next_state == NSM_Full || old_state == NSM_Full)
	    && (nbr->oi->state != ISM_DR)
	    && (nbr->oi->type == OSPF_IFTYPE_BROADCAST
		|| nbr->oi->type == OSPF_IFTYPE_NBMA))
		return 0;

	/* State progression to non-terminal state */
	if (next_state > old_state && next_state != NSM_Full
	    && next_state != NSM_TwoWay)
		return 0;

	if (nbr->oi->type == OSPF_IFTYPE_VIRTUALLINK)
		ospfTrapVirtNbrStateChange(nbr);
	else
		ospfTrapNbrStateChange(nbr);

	return 0;
}

static void ospfTrapIfStateChange(struct ospf_interface *oi)
{
	oid index[sizeof(oid) * (IN_ADDR_SIZE + 1)];

	if (IS_DEBUG_OSPF_EVENT)
		zlog_info("%s: trap sent: %pI4 now %s", __func__,
			  &oi->address->u.prefix4,
			  lookup_msg(ospf_ism_state_msg, oi->state, NULL));

	oid_copy_in_addr(index, &(oi->address->u.prefix4));
	index[IN_ADDR_SIZE] = 0;

	smux_trap(ospf_variables, array_size(ospf_variables), ospf_trap_oid,
		  array_size(ospf_trap_oid), ospf_oid,
		  sizeof(ospf_oid) / sizeof(oid), index, IN_ADDR_SIZE + 1,
		  ospfIfTrapList, array_size(ospfIfTrapList), IFSTATECHANGE);
}

static void ospfTrapVirtIfStateChange(struct ospf_interface *oi)
{
	oid index[sizeof(oid) * (IN_ADDR_SIZE + 1)];

	zlog_info("ospfTrapVirtIfStateChange trap sent");

	oid_copy_in_addr(index, &(oi->address->u.prefix4));
	index[IN_ADDR_SIZE] = 0;

	smux_trap(ospf_variables, array_size(ospf_variables), ospf_trap_oid,
		  array_size(ospf_trap_oid), ospf_oid,
		  sizeof(ospf_oid) / sizeof(oid), index, IN_ADDR_SIZE + 1,
		  ospfVirtIfTrapList, array_size(ospfVirtIfTrapList),
		  VIRTIFSTATECHANGE);
}

static int ospf_snmp_ism_change(struct ospf_interface *oi, int state,
				int old_state)
{
	/* Terminal state or regression */
	if ((state == ISM_DR) || (state == ISM_Backup) || (state == ISM_DROther)
	    || (state == ISM_PointToPoint) || (state < old_state)) {
		/* ospfVirtIfStateChange */
		if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
			ospfTrapVirtIfStateChange(oi);
		/* ospfIfStateChange */
		else
			ospfTrapIfStateChange(oi);
	}
	return 0;
}

/* Register OSPF2-MIB. */
static int ospf_snmp_init(struct event_loop *tm)
{
	ospf_snmp_iflist = list_new();
	ospf_snmp_vl_table = route_table_init();
	smux_init(tm);
	REGISTER_MIB("mibII/ospf", ospf_variables, variable, ospf_oid);
	return 0;
}

static int ospf_snmp_module_init(void)
{
	hook_register(ospf_if_update, ospf_snmp_if_update);
	hook_register(ospf_if_delete, ospf_snmp_if_delete);
	hook_register(ospf_vl_add, ospf_snmp_vl_add);
	hook_register(ospf_vl_delete, ospf_snmp_vl_delete);
	hook_register(ospf_ism_change, ospf_snmp_ism_change);
	hook_register(ospf_nsm_change, ospf_snmp_nsm_change);

	hook_register(frr_late_init, ospf_snmp_init);
	return 0;
}

FRR_MODULE_SETUP(.name = "ospfd_snmp", .version = FRR_VERSION,
		 .description = "ospfd AgentX SNMP module",
		 .init = ospf_snmp_module_init,
);
