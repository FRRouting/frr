// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ISIS SNMP support
 * Copyright (C) 2020 Volta Networks, Inc.
 *                    Aleksey Romanov
 */

/*
 * This is minimal read-only implementations providing isisReadOnlyCompliance
 */

#include <zebra.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "vrf.h"
#include "if.h"
#include "log.h"
#include "prefix.h"
#include "table.h"
#include "command.h"
#include "memory.h"
#include "smux.h"
#include "libfrr.h"
#include "lib/version.h"
#include "lib/zclient.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_network.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_te.h"
#include "isisd/isis_dr.h"
#include "isisd/isis_nb.h"
#include "isisd/isisd.h"

/* ISIS-MIB. */
#define ISIS_MIB 1, 3, 6, 1, 2, 1, 138

#define ISIS_OBJECTS 1
#define ISIS_SYSTEM 1, 1
#define ISIS_SYSLEVEL 1, 2
#define ISIS_CIRC 1, 3
#define ISIS_CIRC_LEVEL_VALUES 1, 4
#define ISIS_COUNTERS 1, 5
#define ISIS_ISADJ 1, 6

/************************ isisSystemGroup ************************/

/* isisSysObject  */
#define ISIS_SYS_OBJECT 1, 1, 1
#define ISIS_SYS_VERSION 1
#define ISIS_SYS_LEVELTYPE 2
#define ISIS_SYS_ID 3
#define ISIS_SYS_MAXPATHSPLITS 4
#define ISIS_SYS_MAXLSPGENINT 5
#define ISIS_SYS_POLLESHELLORATE 6
#define ISIS_SYS_WAITTIME 7
#define ISIS_SYS_ADMINSTATE 8
#define ISIS_SYS_L2TOL1LEAKING 9
#define ISIS_SYS_MAXAGE 10
#define ISIS_SYS_RECEIVELSPBUFFERSIZE 11
#define ISIS_SYS_PROTSUPPORTED 12
#define ISIS_SYS_NOTIFICATIONENABLE 13

/* isisManAreaAddrEntry */
#define ISIS_MANAREA_ADDRENTRY 1, 1, 2, 1
#define ISIS_MANAREA_ADDREXISTSTATE 2

/* isisAreaAddrEntry */
#define ISIS_AREA_ADDRENTRY 1, 1, 3, 1
#define ISIS_AREA_ADDR 1

/* isisSummAddrEntry */
#define ISIS_SUMM_ADDRENTRY 1, 1, 4, 1
#define ISIS_SUMM_ADDREXISTSTATE 4
#define ISIS_SUMM_ADDRMETRIC 5
#define ISIS_SUMM_ADDRFULLMETRIC 6

/* isisRedistributeAddrEntry */
#define ISIS_REDISTRIBUTE_ADDRENTRY 1, 1, 5, 1
#define ISIS_REDISTRIBUTE_ADDREXISTSTATE 3

/* isisRouterEntry */
#define ISIS_ROUTER_ENTRY 1, 1, 6, 1
#define ISIS_ROUTER_HOSTNAME 3
#define ISIS_ROUTER_ID 4

/* isisSysLevelTable */
#define ISIS_SYSLEVEL_ENTRY 1, 2, 1, 1
#define ISIS_SYSLEVEL_ORIGLSPBUFFSIZE 2
#define ISIS_SYSLEVEL_MINLSPGENINT 3
#define ISIS_SYSLEVEL_STATE 4
#define ISIS_SYSLEVEL_SETOVERLOAD 5
#define ISIS_SYSLEVEL_SETOVERLOADUNTIL 6
#define ISIS_SYSLEVEL_METRICSTYLE 7
#define ISIS_SYSLEVEL_SPFCONSIDERS 8
#define ISIS_SYSLEVEL_TEENABLED 9


/* isisSystemCounterEntry */
#define ISIS_SYSTEM_COUNTER_ENTRY 1, 5, 1, 1
#define ISIS_SYSSTAT_CORRLSPS 2
#define ISIS_SYSSTAT_AUTHTYPEFAILS 3
#define ISIS_SYSSTAT_AUTHFAILS 4
#define ISIS_SYSSTAT_LSPDBASEOLOADS 5
#define ISIS_SYSSTAT_MANADDRDROPFROMAREAS 6
#define ISIS_SYSSTAT_ATTMPTTOEXMAXSEQNUMS 7
#define ISIS_SYSSTAT_SEQNUMSKIPS 8
#define ISIS_SYSSTAT_OWNLSPPURGES 9
#define ISIS_SYSSTAT_IDFIELDLENMISMATCHES 10
#define ISIS_SYSSTAT_PARTCHANGES 11
#define ISIS_SYSSTAT_SPFRUNS 12
#define ISIS_SYSSTAT_LSPERRORS 13


/************************ isisCircuitGroup ************************/

/* Scalar directly under isisCirc */
#define ISIS_NEXTCIRC_INDEX 1

/* isisCircEntry */
#define ISIS_CIRC_ENTRY 1, 3, 2, 1
#define ISIS_CIRC_IFINDEX 2
#define ISIS_CIRC_ADMINSTATE 3
#define ISIS_CIRC_EXISTSTATE 4
#define ISIS_CIRC_TYPE 5
#define ISIS_CIRC_EXTDOMAIN 6
#define ISIS_CIRC_LEVELTYPE 7
#define ISIS_CIRC_PASSIVECIRCUIT 8
#define ISIS_CIRC_MESHGROUPENABLED 9
#define ISIS_CIRC_MESHGROUP 10
#define ISIS_CIRC_SMALLHELLOS 11
#define ISIS_CIRC_LASTUPTIME 12
#define ISIS_CIRC_3WAYENABLED 13
#define ISIS_CIRC_EXTENDEDCIRCID 14

/* isisCircLevelEntry */
#define ISIS_CIRCLEVEL_ENTRY 1, 4, 1, 1
#define ISIS_CIRCLEVEL_METRIC 2
#define ISIS_CIRCLEVEL_WIDEMETRIC 3
#define ISIS_CIRCLEVEL_ISPRIORITY 4
#define ISIS_CIRCLEVEL_IDOCTET 5
#define ISIS_CIRCLEVEL_ID 6
#define ISIS_CIRCLEVEL_DESIS 7
#define ISIS_CIRCLEVEL_HELLOMULTIPLIER 8
#define ISIS_CIRCLEVEL_HELLOTIMER 9
#define ISIS_CIRCLEVEL_DRHELLOTIMER 10
#define ISIS_CIRCLEVEL_LSPTHROTTLE 11
#define ISIS_CIRCLEVEL_MINLSPRETRANSINT 12
#define ISIS_CIRCLEVEL_CSNPINTERVAL 13
#define ISIS_CIRCLEVEL_PARTSNPINTERVAL 14

/* isisCircuitCounterEntry */
#define ISIS_CIRC_COUNTER_ENTRY 1, 5, 2, 1
#define ISIS_CIRC_ADJCHANGES 2
#define ISIS_CIRC_NUMADJ 3
#define ISIS_CIRC_INITFAILS 4
#define ISIS_CIRC_REJADJS 5
#define ISIS_CIRC_IDFIELDLENMISMATCHES 6
#define ISIS_CIRC_MAXAREAADDRMISMATCHES 7
#define ISIS_CIRC_AUTHTYPEFAILS 8
#define ISIS_CIRC_AUTHFAILS 9
#define ISIS_CIRC_LANDESISCHANGES 10


/************************ isisISAdjGroup ************************/

/* isisISAdjEntry */
#define ISIS_ISADJ_ENTRY 1, 6, 1, 1
#define ISIS_ISADJ_STATE 2
#define ISIS_ISADJ_3WAYSTATE 3
#define ISIS_ISADJ_NEIGHSNPAADDRESS 4
#define ISIS_ISADJ_NEIGHSYSTYPE 5
#define ISIS_ISADJ_NEIGHSYSID 6
#define ISIS_ISADJ_NBREXTENDEDCIRCID 7
#define ISIS_ISADJ_USAGE 8
#define ISIS_ISADJ_HOLDTIMER 9
#define ISIS_ISADJ_NEIGHPRIORITY 10
#define ISIS_ISADJ_LASTUPTIME 11

/* isisISAdjAreadAddrEntry */
#define ISIS_ISADJAREA_ADDRENTRY 1, 6, 2, 1
#define ISIS_ISADJAREA_ADDRESS 2

/* isisISAdjIPAddrEntry*/
#define ISIS_ISADJIPADDR_ENTRY 1, 6, 3, 1
#define ISIS_ISADJIPADDR_TYPE 2
#define ISIS_ISADJIPADDR_ADDRESS 3


/* isisISAdjProtSuppEntty */

#define ISIS_ISADJPROTSUPP_ENTRY 1, 6, 4, 1
#define ISIS_ISADJPROTSUPP_PROTOCOL 1


/************************ Trap data variables ************************/
#define ISIS_NOTIFICATION_ENTRY 1, 10, 1
#define ISIS_NOTIF_SYLELVELINDEX 1
#define ISIS_NOTIF_CIRCIFINDEX 2
#define ISIS_PDU_LSPID 3
#define ISIS_PDU_FRAGMENT 4
#define ISIS_PDU_FIELDLEN 5
#define ISIS_PDU_MAXAREAADDR 6
#define ISIS_PDU_PROTOVER 7
#define ISIS_PDU_LSPSIZE 8
#define ISIS_PDU_ORIGBUFFERSIZE 9
#define ISIS_PDU_BUFFERSIZE 10
#define ISIS_PDU_PROTSUPP 11
#define ISIS_ADJ_STATE 12
#define ISIS_ERROR_OFFSET 13
#define ISIS_ERROR_TLVTYPE 14
#define ISIS_NOTIF_AREAADDR 15

/************************ Traps ************************/
#define ISIS_NOTIFICATIONS ISIS_MIB, 0
#define ISIS_TRAP_DB_OVERLOAD 1
#define ISIS_TRAP_MAN_ADDR_DROP 2
#define ISIS_TRAP_CORRUPTED_LSP 3
#define ISIS_TRAP_LSP_EXCEED_MAX 4
#define ISIS_TRAP_ID_LEN_MISMATCH 5
#define ISIS_TRAP_MAX_AREA_ADDR_MISMATCH 6
#define ISIS_TRAP_OWN_LSP_PURGE 7
#define ISIS_TRAP_SEQNO_SKIPPED 8
#define ISIS_TRAP_AUTHEN_TYPE_FAILURE 9
#define ISIS_TRAP_AUTHEN_FAILURE 10
#define ISIS_TRAP_VERSION_SKEW 11
#define ISIS_TRAP_AREA_MISMATCH 12
#define ISIS_TRAP_REJ_ADJACENCY 13
#define ISIS_TRAP_LSP_TOO_LARGE 14
#define ISIS_TRAP_LSP_BUFFSIZE_MISMATCH 15
#define ISIS_TRAP_PROTSUPP_MISMATCH 16
#define ISIS_TRAP_ADJ_STATE_CHANGE 17
#define ISIS_TRAP_LSP_ERROR 18

/* Change this definition if number of traps changes */
#define ISIS_TRAP_LAST_TRAP ISIS_TRAP_LSP_ERROR + 1

#define ISIS_SNMP_TRAP_VAR 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0


/* SNMP value hack. */
#define COUNTER32 ASN_COUNTER
#define INTEGER ASN_INTEGER
#define UNSIGNED32 ASN_GAUGE
#define TIMESTAMP ASN_TIMETICKS
#define TIMETICKS ASN_TIMETICKS
#define STRING ASN_OCTET_STR

/* Declare static local variables for convenience. */
SNMP_LOCAL_VARIABLES

/*
 * Define time function, it serves two purposes
 * 1. Uses unint32_t for unix time and encapsulates
 *    sing extension issues in conversion from time_t
 *
 * 2. I could be replaced in unit test environment
 */

/* ISIS-MIB instances. */
static oid isis_oid[] = {ISIS_MIB};

/* SNMP trap variable */
static oid isis_snmp_trap_var[] = {ISIS_SNMP_TRAP_VAR};

/* SNMP trap values (others are calculated on the fly */
static oid isis_snmp_notifications[] = {ISIS_NOTIFICATIONS};
static oid isis_snmp_trap_val_db_overload[] = {ISIS_NOTIFICATIONS,
					       ISIS_TRAP_DB_OVERLOAD};
static oid isis_snmp_trap_val_lsp_exceed_max[] = {ISIS_NOTIFICATIONS,
						  ISIS_TRAP_LSP_EXCEED_MAX};
static oid isis_snmp_trap_val_area_mismatch[] = {ISIS_NOTIFICATIONS,
						 ISIS_TRAP_AREA_MISMATCH};
static oid isis_snmp_trap_val_lsp_error[] = {ISIS_NOTIFICATIONS,
					     ISIS_TRAP_LSP_ERROR};

/*
 * Trap vars under 'isisNotifications': note: we use full names of variables
 * scalar index
 */
static oid isis_snmp_trap_data_var_sys_level_index[] = {
	ISIS_MIB, ISIS_NOTIFICATION_ENTRY, ISIS_NOTIF_SYLELVELINDEX, 0};
static oid isis_snmp_trap_data_var_circ_if_index[] = {
	ISIS_MIB, ISIS_NOTIFICATION_ENTRY, ISIS_NOTIF_CIRCIFINDEX, 0};
static oid isis_snmp_trap_data_var_pdu_lsp_id[] = {
	ISIS_MIB, ISIS_NOTIFICATION_ENTRY, ISIS_PDU_LSPID, 0};
static oid isis_snmp_trap_data_var_pdu_fragment[] = {
	ISIS_MIB, ISIS_NOTIFICATION_ENTRY, ISIS_PDU_FRAGMENT, 0};
static oid isis_snmp_trap_data_var_pdu_field_len[] = {
	ISIS_MIB, ISIS_NOTIFICATION_ENTRY, ISIS_PDU_FIELDLEN, 0};
static oid isis_snmp_trap_data_var_pdu_max_area_addr[] = {
	ISIS_MIB, ISIS_NOTIFICATION_ENTRY, ISIS_PDU_MAXAREAADDR, 0};
static oid isis_snmp_trap_data_var_pdu_proto_ver[] = {
	ISIS_MIB, ISIS_NOTIFICATION_ENTRY, ISIS_PDU_PROTOVER, 0};
static oid isis_snmp_trap_data_var_pdu_lsp_size[] = {
	ISIS_MIB, ISIS_NOTIFICATION_ENTRY, ISIS_PDU_LSPSIZE, 0};
static oid isis_snmp_trap_data_var_adj_state[] = {
	ISIS_MIB, ISIS_NOTIFICATION_ENTRY, ISIS_ADJ_STATE, 0};
static oid isis_snmp_trap_data_var_error_offset[] = {
	ISIS_MIB, ISIS_NOTIFICATION_ENTRY, ISIS_ERROR_OFFSET, 0};
static oid isis_snmp_trap_data_var_error_tlv_type[] = {
	ISIS_MIB, ISIS_NOTIFICATION_ENTRY, ISIS_ERROR_TLVTYPE, 0};

/*
 * Other variables used by traps: note we use full names of variables and
 * reserve space for index
 */
static oid isis_snmp_trap_data_var_sys_level_state[] = {
	ISIS_MIB, ISIS_SYSLEVEL_ENTRY, ISIS_SYSLEVEL_STATE, 0};

/* Throttle time values for traps */
static time_t isis_snmp_trap_timestamp[ISIS_TRAP_LAST_TRAP]; /* ?? 1 */

/* Max len of raw-pdu in traps */
#define ISIS_SNMP_TRAP_PDU_FRAGMENT_MAX_LEN (64)

/*
 * Just to save on typing we have a shortcut structure
 * to specify mib layout as prefix/leaf combination
 */
#define ISIS_SNMP_PREF_LEN_MAX 10
struct isis_var_prefix {
	FindVarMethod *findVar;
	uint8_t ivd_pref_len;
	oid ivd_pref[ISIS_SNMP_PREF_LEN_MAX];
};


/* Find-val functions */
static uint8_t *isis_snmp_find_sys_object(struct variable *, oid *, size_t *,
					  int, size_t *, WriteMethod **);

static uint8_t *isis_snmp_find_man_area(struct variable *, oid *, size_t *, int,
					size_t *, WriteMethod **);

static uint8_t *isis_snmp_find_area_addr(struct variable *, oid *, size_t *,
					 int, size_t *, WriteMethod **);

static uint8_t *isis_snmp_find_summ_addr(struct variable *, oid *, size_t *,
					 int, size_t *, WriteMethod **);

static uint8_t *isis_snmp_find_redistribute_addr(struct variable *, oid *,
						 size_t *, int, size_t *,
						 WriteMethod **);

static uint8_t *isis_snmp_find_router(struct variable *, oid *, size_t *, int,
				      size_t *, WriteMethod **);

static uint8_t *isis_snmp_find_sys_level(struct variable *, oid *, size_t *,
					 int, size_t *, WriteMethod **);

static uint8_t *isis_snmp_find_system_counter(struct variable *, oid *,
					      size_t *, int, size_t *,
					      WriteMethod **);

static uint8_t *isis_snmp_find_next_circ_index(struct variable *, oid *,
					       size_t *, int, size_t *,
					       WriteMethod **);

static uint8_t *isis_snmp_find_circ(struct variable *, oid *, size_t *, int,
				    size_t *, WriteMethod **);

static uint8_t *isis_snmp_find_circ_level(struct variable *, oid *, size_t *,
					  int, size_t *, WriteMethod **);

static uint8_t *isis_snmp_find_circ_counter(struct variable *, oid *, size_t *,
					    int, size_t *, WriteMethod **);

static uint8_t *isis_snmp_find_isadj(struct variable *, oid *, size_t *, int,
				     size_t *, WriteMethod **);

static uint8_t *isis_snmp_find_isadj_area(struct variable *, oid *, size_t *,
					  int, size_t *, WriteMethod **);

static uint8_t *isis_snmp_find_isadj_ipaddr(struct variable *, oid *, size_t *,
					    int, size_t *, WriteMethod **);

static uint8_t *isis_snmp_find_isadj_prot_supp(struct variable *, oid *,
					       size_t *, int, size_t *,
					       WriteMethod **);

/*
 * Just to save on typing we have a shortcut structure
 * to specify mib layout, we populate the rest of the data
 * during initialization
 */
#define ISIS_PREF_LEN_MAX (6)

struct isis_func_to_prefix {
	FindVarMethod *ihtp_func;
	oid ihtp_pref_oid[ISIS_PREF_LEN_MAX];
	uint8_t ihtp_pref_len;
};

static struct isis_func_to_prefix isis_func_to_prefix_arr[] = {
	{isis_snmp_find_sys_object, {ISIS_SYS_OBJECT}, 3},
	{isis_snmp_find_man_area, {ISIS_MANAREA_ADDRENTRY}, 4},
	{isis_snmp_find_area_addr, {ISIS_AREA_ADDRENTRY}, 4},
	{isis_snmp_find_summ_addr, {ISIS_SUMM_ADDRENTRY}, 4},
	{isis_snmp_find_redistribute_addr, {ISIS_REDISTRIBUTE_ADDRENTRY}, 4},
	{isis_snmp_find_router, {ISIS_ROUTER_ENTRY}, 4},
	{isis_snmp_find_sys_level, {ISIS_SYSLEVEL_ENTRY}, 4},
	{isis_snmp_find_system_counter, {ISIS_SYSTEM_COUNTER_ENTRY}, 4},
	{isis_snmp_find_next_circ_index, {ISIS_CIRC}, 2},
	{isis_snmp_find_circ, {ISIS_CIRC_ENTRY}, 4},
	{isis_snmp_find_circ_level, {ISIS_CIRCLEVEL_ENTRY}, 4},
	{isis_snmp_find_circ_counter, {ISIS_CIRC_COUNTER_ENTRY}, 4},
	{isis_snmp_find_isadj, {ISIS_ISADJ_ENTRY}, 4},
	{isis_snmp_find_isadj_area, {ISIS_ISADJAREA_ADDRENTRY}, 4},
	{isis_snmp_find_isadj_ipaddr, {ISIS_ISADJIPADDR_ENTRY}, 4},
	{isis_snmp_find_isadj_prot_supp, {ISIS_ISADJPROTSUPP_ENTRY}, 4},
};
static size_t isis_func_to_prefix_count = array_size(isis_func_to_prefix_arr);

static struct variable isis_var_arr[] = {
	{ISIS_SYS_VERSION, INTEGER, RONLY, isis_snmp_find_sys_object},
	{ISIS_SYS_LEVELTYPE, INTEGER, RONLY, isis_snmp_find_sys_object},
	{ISIS_SYS_ID, STRING, RONLY, isis_snmp_find_sys_object},
	{ISIS_SYS_MAXPATHSPLITS, UNSIGNED32, RONLY, isis_snmp_find_sys_object},
	{ISIS_SYS_MAXLSPGENINT, UNSIGNED32, RONLY, isis_snmp_find_sys_object},
	{ISIS_SYS_POLLESHELLORATE, UNSIGNED32, RONLY,
	 isis_snmp_find_sys_object},
	{ISIS_SYS_WAITTIME, UNSIGNED32, RONLY, isis_snmp_find_sys_object},
	{ISIS_SYS_ADMINSTATE, INTEGER, RONLY, isis_snmp_find_sys_object},
	{ISIS_SYS_L2TOL1LEAKING, INTEGER, RONLY, isis_snmp_find_sys_object},
	{ISIS_SYS_MAXAGE, UNSIGNED32, RONLY, isis_snmp_find_sys_object},
	{ISIS_SYS_RECEIVELSPBUFFERSIZE, UNSIGNED32, RONLY,
	 isis_snmp_find_sys_object},
	{ISIS_SYS_PROTSUPPORTED, STRING, RONLY, isis_snmp_find_sys_object},
	{ISIS_SYS_NOTIFICATIONENABLE, INTEGER, RONLY,
	 isis_snmp_find_sys_object},
	{ISIS_MANAREA_ADDREXISTSTATE, INTEGER, RONLY, isis_snmp_find_man_area},
	{ISIS_AREA_ADDR, STRING, RONLY, isis_snmp_find_area_addr},
	{ISIS_SUMM_ADDREXISTSTATE, INTEGER, RONLY, isis_snmp_find_summ_addr},
	{ISIS_SUMM_ADDRMETRIC, UNSIGNED32, RONLY, isis_snmp_find_summ_addr},
	{ISIS_SUMM_ADDRFULLMETRIC, UNSIGNED32, RONLY, isis_snmp_find_summ_addr},
	{ISIS_REDISTRIBUTE_ADDREXISTSTATE, INTEGER, RONLY,
	 isis_snmp_find_redistribute_addr},
	{ISIS_ROUTER_HOSTNAME, STRING, RONLY, isis_snmp_find_router},
	{ISIS_ROUTER_ID, UNSIGNED32, RONLY, isis_snmp_find_router},
	{ISIS_SYSLEVEL_ORIGLSPBUFFSIZE, UNSIGNED32, RONLY,
	 isis_snmp_find_sys_level},
	{ISIS_SYSLEVEL_MINLSPGENINT, UNSIGNED32, RONLY,
	 isis_snmp_find_sys_level},
	{ISIS_SYSLEVEL_STATE, INTEGER, RONLY, isis_snmp_find_sys_level},
	{ISIS_SYSLEVEL_SETOVERLOAD, INTEGER, RONLY, isis_snmp_find_sys_level},
	{ISIS_SYSLEVEL_SETOVERLOADUNTIL, UNSIGNED32, RONLY,
	 isis_snmp_find_sys_level},
	{ISIS_SYSLEVEL_METRICSTYLE, INTEGER, RONLY, isis_snmp_find_sys_level},
	{ISIS_SYSLEVEL_SPFCONSIDERS, INTEGER, RONLY, isis_snmp_find_sys_level},
	{ISIS_SYSLEVEL_TEENABLED, INTEGER, RONLY, isis_snmp_find_sys_level},
	{ISIS_SYSSTAT_CORRLSPS, COUNTER32, RONLY,
	 isis_snmp_find_system_counter},
	{ISIS_SYSSTAT_AUTHTYPEFAILS, COUNTER32, RONLY,
	 isis_snmp_find_system_counter},
	{ISIS_SYSSTAT_AUTHFAILS, COUNTER32, RONLY,
	 isis_snmp_find_system_counter},
	{ISIS_SYSSTAT_LSPDBASEOLOADS, COUNTER32, RONLY,
	 isis_snmp_find_system_counter},
	{ISIS_SYSSTAT_MANADDRDROPFROMAREAS, COUNTER32, RONLY,
	 isis_snmp_find_system_counter},
	{ISIS_SYSSTAT_ATTMPTTOEXMAXSEQNUMS, COUNTER32, RONLY,
	 isis_snmp_find_system_counter},
	{ISIS_SYSSTAT_SEQNUMSKIPS, COUNTER32, RONLY,
	 isis_snmp_find_system_counter},
	{ISIS_SYSSTAT_OWNLSPPURGES, COUNTER32, RONLY,
	 isis_snmp_find_system_counter},
	{ISIS_SYSSTAT_IDFIELDLENMISMATCHES, COUNTER32, RONLY,
	 isis_snmp_find_system_counter},
	{ISIS_SYSSTAT_PARTCHANGES, COUNTER32, RONLY,
	 isis_snmp_find_system_counter},
	{ISIS_SYSSTAT_SPFRUNS, COUNTER32, RONLY, isis_snmp_find_system_counter},
	{ISIS_SYSSTAT_LSPERRORS, COUNTER32, RONLY,
	 isis_snmp_find_system_counter},
	{ISIS_NEXTCIRC_INDEX, UNSIGNED32, RONLY,
	 isis_snmp_find_next_circ_index},
	{ISIS_CIRC_IFINDEX, INTEGER, RONLY, isis_snmp_find_circ},
	{ISIS_CIRC_ADMINSTATE, INTEGER, RONLY, isis_snmp_find_circ},
	{ISIS_CIRC_EXISTSTATE, INTEGER, RONLY, isis_snmp_find_circ},
	{ISIS_CIRC_TYPE, INTEGER, RONLY, isis_snmp_find_circ},
	{ISIS_CIRC_EXTDOMAIN, INTEGER, RONLY, isis_snmp_find_circ},
	{ISIS_CIRC_LEVELTYPE, INTEGER, RONLY, isis_snmp_find_circ},
	{ISIS_CIRC_PASSIVECIRCUIT, INTEGER, RONLY, isis_snmp_find_circ},
	{ISIS_CIRC_MESHGROUPENABLED, INTEGER, RONLY, isis_snmp_find_circ},
	{ISIS_CIRC_MESHGROUP, UNSIGNED32, RONLY, isis_snmp_find_circ},
	{ISIS_CIRC_SMALLHELLOS, INTEGER, RONLY, isis_snmp_find_circ},
	{ISIS_CIRC_LASTUPTIME, TIMESTAMP, RONLY, isis_snmp_find_circ},
	{ISIS_CIRC_3WAYENABLED, INTEGER, RONLY, isis_snmp_find_circ},
	{ISIS_CIRC_EXTENDEDCIRCID, UNSIGNED32, RONLY, isis_snmp_find_circ},
	{ISIS_CIRCLEVEL_METRIC, UNSIGNED32, RONLY, isis_snmp_find_circ_level},
	{ISIS_CIRCLEVEL_WIDEMETRIC, UNSIGNED32, RONLY,
	 isis_snmp_find_circ_level},
	{ISIS_CIRCLEVEL_ISPRIORITY, UNSIGNED32, RONLY,
	 isis_snmp_find_circ_level},
	{ISIS_CIRCLEVEL_IDOCTET, UNSIGNED32, RONLY, isis_snmp_find_circ_level},
	{ISIS_CIRCLEVEL_ID, STRING, RONLY, isis_snmp_find_circ_level},
	{ISIS_CIRCLEVEL_DESIS, STRING, RONLY, isis_snmp_find_circ_level},
	{ISIS_CIRCLEVEL_HELLOMULTIPLIER, UNSIGNED32, RONLY,
	 isis_snmp_find_circ_level},
	{ISIS_CIRCLEVEL_HELLOTIMER, UNSIGNED32, RONLY,
	 isis_snmp_find_circ_level},
	{ISIS_CIRCLEVEL_DRHELLOTIMER, UNSIGNED32, RONLY,
	 isis_snmp_find_circ_level},
	{ISIS_CIRCLEVEL_LSPTHROTTLE, UNSIGNED32, RONLY,
	 isis_snmp_find_circ_level},
	{ISIS_CIRCLEVEL_MINLSPRETRANSINT, UNSIGNED32, RONLY,
	 isis_snmp_find_circ_level},
	{ISIS_CIRCLEVEL_CSNPINTERVAL, UNSIGNED32, RONLY,
	 isis_snmp_find_circ_level},
	{ISIS_CIRCLEVEL_PARTSNPINTERVAL, UNSIGNED32, RONLY,
	 isis_snmp_find_circ_level},
	{ISIS_CIRC_ADJCHANGES, COUNTER32, RONLY, isis_snmp_find_circ_counter},
	{ISIS_CIRC_NUMADJ, UNSIGNED32, RONLY, isis_snmp_find_circ_counter},
	{ISIS_CIRC_INITFAILS, COUNTER32, RONLY, isis_snmp_find_circ_counter},
	{ISIS_CIRC_REJADJS, COUNTER32, RONLY, isis_snmp_find_circ_counter},
	{ISIS_CIRC_IDFIELDLENMISMATCHES, COUNTER32, RONLY,
	 isis_snmp_find_circ_counter},
	{ISIS_CIRC_MAXAREAADDRMISMATCHES, COUNTER32, RONLY,
	 isis_snmp_find_circ_counter},
	{ISIS_CIRC_AUTHTYPEFAILS, COUNTER32, RONLY,
	 isis_snmp_find_circ_counter},
	{ISIS_CIRC_AUTHFAILS, COUNTER32, RONLY, isis_snmp_find_circ_counter},
	{ISIS_CIRC_LANDESISCHANGES, COUNTER32, RONLY,
	 isis_snmp_find_circ_counter},
	{ISIS_ISADJ_STATE, INTEGER, RONLY, isis_snmp_find_isadj},
	{ISIS_ISADJ_3WAYSTATE, INTEGER, RONLY, isis_snmp_find_isadj},
	{ISIS_ISADJ_NEIGHSNPAADDRESS, STRING, RONLY, isis_snmp_find_isadj},
	{ISIS_ISADJ_NEIGHSYSTYPE, INTEGER, RONLY, isis_snmp_find_isadj},
	{ISIS_ISADJ_NEIGHSYSID, STRING, RONLY, isis_snmp_find_isadj},
	{ISIS_ISADJ_NBREXTENDEDCIRCID, UNSIGNED32, RONLY, isis_snmp_find_isadj},
	{ISIS_ISADJ_USAGE, INTEGER, RONLY, isis_snmp_find_isadj},
	{ISIS_ISADJ_HOLDTIMER, UNSIGNED32, RONLY, isis_snmp_find_isadj},
	{ISIS_ISADJ_NEIGHPRIORITY, UNSIGNED32, RONLY, isis_snmp_find_isadj},
	{ISIS_ISADJ_LASTUPTIME, TIMESTAMP, RONLY, isis_snmp_find_isadj},
	{ISIS_ISADJAREA_ADDRESS, STRING, RONLY, isis_snmp_find_isadj_area},
	{ISIS_ISADJIPADDR_TYPE, INTEGER, RONLY, isis_snmp_find_isadj_ipaddr},
	{ISIS_ISADJIPADDR_ADDRESS, STRING, RONLY, isis_snmp_find_isadj_ipaddr},
	{ISIS_ISADJPROTSUPP_PROTOCOL, INTEGER, RONLY,
	 isis_snmp_find_isadj_prot_supp},
};

static const size_t isis_var_count = array_size(isis_var_arr);

/* Minimal set of hard-coded data */
#define ISIS_VERSION (1)

/* If sys-id is not set use this value */
static uint8_t isis_null_sysid[ISIS_SYS_ID_LEN];

/* OSI addr-len */
#define ISIS_SNMP_OSI_ADDR_LEN_MAX (20)

/*
 * The implementation has a fixed max-path splits value
 * of 64 (see ISIS_MAX_PATH_SPLITS), the max mib value
 * is 32.
 *
 * FIXME(aromanov): should we return 32 or 64?
 */
#define ISIS_SNMP_MAX_PATH_SPLITS (32)

#define ISIS_SNMP_ADMIN_STATE_ON (1)

#define ISIS_SNMP_ROW_STATUS_ACTIVE (1)

#define ISIS_SNMP_LEVEL_STATE_OFF (1)
#define ISIS_SNMP_LEVEL_STATE_ON (2)
#define ISIS_SNMP_LEVEL_STATE_WAITING (3)
#define ISIS_SNMP_LEVEL_STATE_OVERLOADED (4)

#define ISIS_SNMP_TRUTH_VALUE_TRUE (1)
#define ISIS_SNMP_TRUTH_VALUE_FALSE (2)

#define ISIS_SNMP_METRIC_STYLE_NARROW (1)
#define ISIS_SNMP_METRIC_STYLE_WIDE (2)
#define ISIS_SNMP_METRIC_STYLE_BOTH (3)

#define ISIS_SNMP_MESH_GROUP_INACTIVE (1)

#define ISIS_SNMP_ADJ_STATE_DOWN (1)
#define ISIS_SNMP_ADJ_STATE_INITIALIZING (2)
#define ISIS_SNMP_ADJ_STATE_UP (3)
#define ISIS_SNMP_ADJ_STATE_FAILED (4)

static inline uint32_t isis_snmp_adj_state(enum isis_adj_state state)
{
	switch (state) {
	case ISIS_ADJ_UNKNOWN:
		return ISIS_SNMP_ADJ_STATE_DOWN;
	case ISIS_ADJ_INITIALIZING:
		return ISIS_SNMP_ADJ_STATE_INITIALIZING;
	case ISIS_ADJ_UP:
		return ISIS_SNMP_ADJ_STATE_UP;
	case ISIS_ADJ_DOWN:
		return ISIS_SNMP_ADJ_STATE_FAILED;
	}

	return 0; /* not reached */
}

#define ISIS_SNMP_ADJ_NEIGHTYPE_IS_L1 (1)
#define ISIS_SNMP_ADJ_NEIGHTYPE_IS_L2 (2)
#define ISIS_SNMP_ADJ_NEIGHTYPE_IS_L1_L2 (3)
#define ISIS_SNMP_ADJ_NEIGHTYPE_UNKNOWN (4)

static inline uint32_t isis_snmp_adj_neightype(enum isis_system_type type)
{
	switch (type) {
	case ISIS_SYSTYPE_UNKNOWN:
	case ISIS_SYSTYPE_ES:
		return ISIS_SNMP_ADJ_NEIGHTYPE_UNKNOWN;
	case ISIS_SYSTYPE_IS:
		return ISIS_SNMP_ADJ_NEIGHTYPE_IS_L1_L2;
	case ISIS_SYSTYPE_L1_IS:
		return ISIS_SNMP_ADJ_NEIGHTYPE_IS_L1;
	case ISIS_SYSTYPE_L2_IS:
		return ISIS_SNMP_ADJ_NEIGHTYPE_IS_L2;
	}

	return 0; /* not reached */
}

#define ISIS_SNMP_INET_TYPE_V4 (1)
#define ISIS_SNMP_INET_TYPE_V6 (2)

#define ISIS_SNMP_P2P_CIRCUIT (3)

/* Protocols supported value */
static uint8_t isis_snmp_protocols_supported = 0x7; /* All: iso, ipv4, ipv6 */

#define SNMP_CIRCUITS_MAX (512)

static struct isis_circuit *snmp_circuits[SNMP_CIRCUITS_MAX];
static uint32_t snmp_circuit_id_last;

static int isis_circuit_snmp_id_gen(struct isis_circuit *circuit)
{
	uint32_t id;
	uint32_t i;

	id = snmp_circuit_id_last;
	id++;

	/* find next unused entry */
	for (i = 0; i < SNMP_CIRCUITS_MAX; i++) {
		if (id >= SNMP_CIRCUITS_MAX) {
			id = 0;
			continue;
		}

		if (id == 0)
			continue;

		if (snmp_circuits[id] == NULL)
			break;

		id++;
	}

	if (i == SNMP_CIRCUITS_MAX) {
		zlog_warn("Could not allocate a smmp-circuit-id");
		return 0;
	}

	snmp_circuits[id] = circuit;
	snmp_circuit_id_last = id;
	circuit->snmp_id = id;

	return 0;
}

static int isis_circuit_snmp_id_free(struct isis_circuit *circuit)
{
	snmp_circuits[circuit->snmp_id] = NULL;
	circuit->snmp_id = 0;
	return 0;
}

/*
 * Convenience function to move to the next circuit,
 */
static struct isis_circuit *isis_snmp_circuit_next(struct isis_circuit *circuit)
{
	uint32_t start;
	uint32_t off;

	start = 1;

	if (circuit != NULL)
		start = circuit->snmp_id + 1;

	for (off = start; off < SNMP_CIRCUITS_MAX; off++) {
		circuit = snmp_circuits[off];

		if (circuit != NULL)
			return circuit;
	}

	return NULL;
}

/*
 * Convenience function to get the first matching level
 */
static int isis_snmp_circuit_get_level_lo(struct isis_circuit *circuit)
{
	if (circuit->is_type == IS_LEVEL_2)
		return IS_LEVEL_2;

	return IS_LEVEL_1;
}

/* Check level match */
static int isis_snmp_get_level_match(int is_type, int level)
{
	if (is_type != IS_LEVEL_1 && is_type != IS_LEVEL_2
	    && is_type != IS_LEVEL_1_AND_2)
		return 0;

	if (level != IS_LEVEL_1 && level != IS_LEVEL_2)
		return 0;


	if (is_type == IS_LEVEL_1) {
		if (level == IS_LEVEL_1)
			return 1;

		return 0;
	}

	if (is_type == IS_LEVEL_2) {
		if (level == IS_LEVEL_2)
			return 1;

		return 0;
	}

	return 1;
}
/*
 * Helper function to convert oid index representing
 * octet-string index (e.g. isis-sys-id) to byte string
 * representing the same index.
 *
 * Also we do not fail if idx is longer than max_len,
 * so we can use the same function to check compound
 * indexes.
 */
static int isis_snmp_conv_exact(uint8_t *buf, size_t max_len, size_t *out_len,
				const oid *idx, size_t idx_len)
{
	size_t off;
	size_t len;

	/* Oid representation: length followed by bytes */
	if (idx == NULL || idx_len == 0)
		return 0;

	len = idx[0];

	if (len > max_len)
		return 0;

	if (idx_len < len + 1)
		return 0;

	for (off = 0; off < len; off++) {
		if (idx[off + 1] > 0xff)
			return 0;

		buf[off] = (uint8_t)(idx[off + 1] & 0xff);
	}

	*out_len = len;

	return 1;
}

static int isis_snmp_conv_next(uint8_t *buf, size_t max_len, size_t *out_len,
			       int *try_exact, const oid *idx, size_t idx_len)
{
	size_t off;
	size_t len;
	size_t cmp_len;

	if (idx == NULL || idx_len == 0) {
		*out_len = 0;
		*try_exact = 1;
		return 1;
	}

	len = idx[0];

	if (len > max_len)
		return 0;

	cmp_len = len;

	if ((idx_len - 1) < cmp_len)
		cmp_len = idx_len - 1;

	for (off = 0; off < cmp_len; off++) {
		if (idx[off + 1] > 0xff) {
			memset(buf + off, 0xff, len - off);
			*out_len = len;
			*try_exact = 1;
			return 1;
		}

		buf[off] = (uint8_t)(idx[off + 1] & 0xff);
	}

	if (cmp_len < len)
		memset(buf + cmp_len, 0, len - cmp_len);

	*out_len = len;
	*try_exact = cmp_len < len ? 1 : 0;
	return 1;
}

/*
 * Helper functions to find area address from snmp index
 */
static int isis_snmp_area_addr_lookup_exact(oid *oid_idx, size_t oid_idx_len,
					    struct isis_area **ret_area,
					    struct iso_address **ret_addr)
{
	uint8_t cmp_buf[ISIS_SNMP_OSI_ADDR_LEN_MAX];
	size_t addr_len;
	struct isis_area *area = NULL;
	struct iso_address *addr = NULL;
	struct listnode *addr_node;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	if (isis == NULL)
		return 0;

	if (list_isempty(isis->area_list)) {
		/* Area is not configured yet */
		return 0;
	}

	area = listgetdata(listhead(isis->area_list));

	int res = isis_snmp_conv_exact(cmp_buf, sizeof(cmp_buf), &addr_len,
				       oid_idx, oid_idx_len);


	if (!res || addr_len == 0 || oid_idx_len != (addr_len + 1)) {
		/* Bad conversion, empty address or extra oids at the end */
		return 0;
	}

	for (ALL_LIST_ELEMENTS_RO(area->area_addrs, addr_node, addr)) {
		if (addr->addr_len != addr_len)
			continue;

		if (memcmp(addr->area_addr, cmp_buf, addr_len) == 0) {
			if (ret_area != 0)
				*ret_area = area;

			if (ret_addr != 0)
				*ret_addr = addr;

			return 1;
		}
	}
	return 0;
}

static int isis_snmp_area_addr_lookup_next(oid *oid_idx, size_t oid_idx_len,
					   struct isis_area **ret_area,
					   struct iso_address **ret_addr)
{
	uint8_t cmp_buf[ISIS_SNMP_OSI_ADDR_LEN_MAX];
	size_t addr_len;
	int try_exact = 0;
	struct isis_area *found_area = NULL;
	struct isis_area *area = NULL;
	struct iso_address *found_addr = NULL;
	struct iso_address *addr = NULL;
	struct listnode *addr_node;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	if (isis == NULL)
		return 0;

	if (list_isempty(isis->area_list)) {
		/* Area is not configured yet */
		return 0;
	}

	area = listgetdata(listhead(isis->area_list));

	int res = isis_snmp_conv_next(cmp_buf, sizeof(cmp_buf), &addr_len,
				      &try_exact, oid_idx, oid_idx_len);

	if (!res)
		return 0;

	for (ALL_LIST_ELEMENTS_RO(area->area_addrs, addr_node, addr)) {
		if (addr->addr_len < addr_len)
			continue;

		if (addr->addr_len == addr_len) {
			if (addr_len == 0)
				continue;

			res = memcmp(addr->area_addr, cmp_buf, addr_len);

			if (res < 0)
				continue;

			if (res == 0 && addr->addr_len == addr_len) {
				if (try_exact) {
					/*
					 * This is the best match no point
					 * to look further
					 */
					found_area = area;
					found_addr = addr;
					break;
				}
				continue;
			}
		}

		if (found_addr == NULL || addr->addr_len < found_addr->addr_len
		    || (addr->addr_len == found_addr->addr_len
			&& memcmp(addr->area_addr, found_addr->area_addr,
				  addr->addr_len)
				   < 0)) {
			found_area = area;
			found_addr = addr;
		}
	}

	if (found_area == NULL)
		return 0;

	if (ret_area != 0)
		*ret_area = found_area;

	if (ret_addr != 0)
		*ret_addr = found_addr;

	return 1;
}

/*
 * Helper functions to find circuit from
 * snmp index
 */
static int isis_snmp_circuit_lookup_exact(oid *oid_idx, size_t oid_idx_len,
					  struct isis_circuit **ret_circuit)
{
	struct isis_circuit *circuit;

	if (oid_idx == NULL || oid_idx_len < 1
	    || oid_idx[0] > SNMP_CIRCUITS_MAX)
		return 0;

	circuit = snmp_circuits[oid_idx[0]];
	if (circuit == NULL)
		return 0;

	if (ret_circuit != NULL)
		*ret_circuit = circuit;

	return 1;
}

static int isis_snmp_circuit_lookup_next(oid *oid_idx, size_t oid_idx_len,
					 struct isis_circuit **ret_circuit)
{
	oid off;
	oid start;
	struct isis_circuit *circuit;

	start = 0;

	if (oid_idx != NULL && oid_idx_len != 0) {
		if (oid_idx[0] > SNMP_CIRCUITS_MAX)
			return 0;

		start = oid_idx[0];
	}

	for (off = start; off < SNMP_CIRCUITS_MAX; ++off) {
		circuit = snmp_circuits[off];

		if (circuit != NULL && off > start) {
			if (ret_circuit != NULL)
				*ret_circuit = circuit;

			return 1;
		}
	}

	return 0;
}

/*
 * Helper functions to find circuit level
 * combination from snmp index
 */
static int isis_snmp_circuit_level_lookup_exact(
	oid *oid_idx, size_t oid_idx_len, int check_match,
	struct isis_circuit **ret_circuit, int *ret_level)
{
	int level;
	int res;
	struct isis_circuit *circuit;

	/* Minor optimization: check level first */
	if (oid_idx == NULL || oid_idx_len < 2)
		return 0;

	if (oid_idx[1] < IS_LEVEL_1 || oid_idx[1] > IS_LEVEL_2)
		return 0;

	level = (int)oid_idx[1];

	res = isis_snmp_circuit_lookup_exact(oid_idx, oid_idx_len, &circuit);

	if (!res)
		return 0;

	if (check_match && !isis_snmp_get_level_match(circuit->is_type, level))
		return 0;

	if (ret_circuit != NULL)
		*ret_circuit = circuit;

	if (ret_level != NULL)
		*ret_level = level;

	return 1;
}

static int isis_snmp_circuit_level_lookup_next(
	oid *oid_idx, size_t oid_idx_len, int check_match,
	struct isis_circuit **ret_circuit, int *ret_level)
{
	oid off;
	oid start;
	struct isis_circuit *circuit = NULL;
	int level;

	start = 0;

	if (oid_idx != NULL && oid_idx_len != 0) {
		if (oid_idx[0] > SNMP_CIRCUITS_MAX)
			return 0;

		start = oid_idx[0];
	}

	for (off = start; off < SNMP_CIRCUITS_MAX; off++) {
		circuit = snmp_circuits[off];

		if (circuit == NULL)
			continue;

		if (off > start || oid_idx_len < 2) {
			/* Found and can use level 1 */
			level = IS_LEVEL_1;
			break;
		}

		assert(oid_idx != NULL);

		/* We have to check level specified by index */
		if (oid_idx[1] < IS_LEVEL_1) {
			level = IS_LEVEL_1;
			break;
		}

		if (oid_idx[1] < IS_LEVEL_2) {
			level = IS_LEVEL_2;
			break;
		}

		/* Try next */
		circuit = NULL;
	}

	if (circuit == NULL)
		return 0;

	if (check_match
	    && !isis_snmp_get_level_match(circuit->is_type, level)) {
		if (level == IS_LEVEL_1) {
			/*
			 * We can simply advance level because
			 * at least one level should match
			 */
			level = IS_LEVEL_2;
		} else {
			/* We have to move to the next circuit */
			circuit = isis_snmp_circuit_next(circuit);
			if (circuit == NULL)
				return 0;

			level = isis_snmp_circuit_get_level_lo(circuit);
		}
	}

	if (ret_circuit != NULL)
		*ret_circuit = circuit;

	if (ret_level != NULL)
		*ret_level = level;

	return 1;
}

/*
 * Helper functions to find adjacency
 * from snmp index.
 *
 * We have 4 tables related to adjacency
 * looking up adjacency is quite expensive
 * in case of bcast interfaces.
 *
 * It is pain to have 4 very similar functions
 * hence we pass in and out additional data
 * we are looking for.
 *
 * Note: we  use data-len value to distinguish
 * between ipv4 and ipv6 addresses
 */
#define ISIS_SNMP_ADJ_DATA_NONE (1)
#define ISIS_SNMP_ADJ_DATA_AREA_ADDR (2)
#define ISIS_SNMP_ADJ_DATA_IP_ADDR (3)
#define ISIS_SNMP_ADJ_DATA_PROTO (4)

/*
 * Helper function to process data associated
 * with adjacency
 */
static int isis_snmp_adj_helper(struct isis_adjacency *adj, int data_id,
				oid data_off, uint8_t **ret_data,
				size_t *ret_data_len)
{
	uint8_t *data = NULL;
	size_t data_len = 0;

	switch (data_id) {
	case ISIS_SNMP_ADJ_DATA_NONE:
		break;

	case ISIS_SNMP_ADJ_DATA_AREA_ADDR:
		if (data_off >= adj->area_address_count)
			return 0;

		data = adj->area_addresses[data_off].area_addr;
		data_len = adj->area_addresses[data_off].addr_len;
		break;

	case ISIS_SNMP_ADJ_DATA_IP_ADDR:
		if (data_off >= (adj->ipv4_address_count + adj->ll_ipv6_count))
			return 0;

		if (data_off >= adj->ipv4_address_count) {
			data = (uint8_t *)&adj->ll_ipv6_addrs
				       [data_off - adj->ipv4_address_count];
			data_len = sizeof(adj->ll_ipv6_addrs[0]);
		} else {
			data = (uint8_t *)&adj->ipv4_addresses[data_off];
			data_len = sizeof(adj->ipv4_addresses[0]);
		}

		break;


	case ISIS_SNMP_ADJ_DATA_PROTO:
		if (data_off >= adj->nlpids.count)
			return 0;

		data = &adj->nlpids.nlpids[data_off];
		data_len = sizeof(adj->nlpids.nlpids[0]);
		break;

	default:
		assert(0);
		return 0;
	}

	if (ret_data != NULL)
		*ret_data = data;

	if (ret_data_len != NULL)
		*ret_data_len = data_len;

	return 1;
}

static int isis_snmp_adj_lookup_exact(oid *oid_idx, size_t oid_idx_len,
				      int data_id,
				      struct isis_adjacency **ret_adj,
				      oid *ret_data_idx, uint8_t **ret_data,
				      size_t *ret_data_len)
{
	int res;
	struct listnode *node;
	struct isis_circuit *circuit;
	struct isis_adjacency *adj;
	struct isis_adjacency *tmp_adj;
	oid adj_idx;
	oid data_off;
	uint8_t *data;
	size_t data_len;

	res = isis_snmp_circuit_lookup_exact(oid_idx, oid_idx_len, &circuit);

	if (!res)
		return 0;

	if (oid_idx == NULL || oid_idx_len < 2
	    || (data_id != ISIS_SNMP_ADJ_DATA_NONE && oid_idx_len < 3))
		return 0;

	adj_idx = oid_idx[1];

	if (data_id != ISIS_SNMP_ADJ_DATA_NONE) {
		if (oid_idx[2] == 0)
			return 0;

		data_off = oid_idx[2] - 1;
	} else {
		/*
		 * Data-off is not used if data-id is none
		 * but we set it just for consistency
		 */
		data_off = 0;
	}

	adj = NULL;
	data = NULL;
	data_len = 0;

	for (ALL_LIST_ELEMENTS_RO(circuit->snmp_adj_list, node, tmp_adj)) {
		if (tmp_adj->snmp_idx > adj_idx) {
			/*
			 * Adjacencies are ordered in the list
			 * no point to look further
			 */
			break;
		}

		if (tmp_adj->snmp_idx == adj_idx) {
			res = isis_snmp_adj_helper(tmp_adj, data_id, data_off,
						   &data, &data_len);
			if (res)
				adj = tmp_adj;

			break;
		}
	}

	if (adj == NULL)
		return 0;

	if (ret_adj != NULL)
		*ret_adj = adj;

	if (ret_data_idx != NULL)
		*ret_data_idx = data_off + 1;

	if (ret_data)
		*ret_data = data;

	if (ret_data_len)
		*ret_data_len = data_len;

	return 1;
}

static int isis_snmp_adj_lookup_next(oid *oid_idx, size_t oid_idx_len,
				     int data_id,
				     struct isis_adjacency **ret_adj,
				     oid *ret_data_idx, uint8_t **ret_data,
				     size_t *ret_data_len)
{
	struct listnode *node;
	struct isis_circuit *circuit;
	struct isis_adjacency *adj;
	struct isis_adjacency *tmp_adj;
	oid circ_idx;
	oid adj_idx;
	oid data_idx;
	uint8_t *data;
	size_t data_len;

	adj = NULL;
	data = NULL;
	data_len = 0;

	/*
	 * Note: we rely on the fact that data indexes are consequtive
	 * starting from 1
	 */

	if (oid_idx == 0 || oid_idx_len == 0) {
		circ_idx = 0;
		adj_idx = 0;
		data_idx = 0;
	} else if (oid_idx_len == 1) {
		circ_idx = oid_idx[0];
		adj_idx = 0;
		data_idx = 0;
	} else if (oid_idx_len == 2) {
		circ_idx = oid_idx[0];
		adj_idx = oid_idx[1];
		data_idx = 0;
	} else {
		circ_idx = oid_idx[0];
		adj_idx = oid_idx[1];

		if (data_id == ISIS_SNMP_ADJ_DATA_NONE)
			data_idx = 0;
		else
			data_idx = oid_idx[2];
	}

	if (!isis_snmp_circuit_lookup_exact(&circ_idx, 1, &circuit)
	    && !isis_snmp_circuit_lookup_next(&circ_idx, 1, &circuit))
		/* No circuit */
		return 0;

	if (circuit->snmp_id != circ_idx) {
		/* Match is not exact */
		circ_idx = 0;
		adj_idx = 0;
		data_idx = 0;
	}

	/*
	 * Note: the simple loop  below will work in all cases
	 */
	while (circuit != NULL) {
		for (ALL_LIST_ELEMENTS_RO(circuit->snmp_adj_list, node,
					  tmp_adj)) {
			if (tmp_adj->snmp_idx < adj_idx)
				continue;

			if (tmp_adj->snmp_idx == adj_idx
			    && data_id == ISIS_SNMP_ADJ_DATA_NONE)
				continue;

			if (adj_idx != 0 && tmp_adj->snmp_idx > adj_idx)
				data_idx = 0;

			if (isis_snmp_adj_helper(tmp_adj, data_id, data_idx,
						 &data, &data_len)) {
				adj = tmp_adj;
				break;
			}
		}

		if (adj != NULL)
			break;

		circuit = isis_snmp_circuit_next(circuit);
		circ_idx = 0;
		adj_idx = 0;
		data_idx = 0;
	}

	if (adj == NULL)
		return 0;

	if (ret_adj != NULL)
		*ret_adj = adj;

	if (ret_data_idx != 0) {
		if (data_id == ISIS_SNMP_ADJ_DATA_NONE)
			/*
			 * Value does not matter but let us set
			 * it to zero for consistency
			 */
			*ret_data_idx = 0;
		else
			*ret_data_idx = data_idx + 1;
	}

	if (ret_data != 0)
		*ret_data = data;

	if (ret_data_len != 0)
		*ret_data_len = data_len;

	return 1;
}

static uint8_t *isis_snmp_find_sys_object(struct variable *v, oid *name,
					  size_t *length, int exact,
					  size_t *var_len,
					  WriteMethod **write_method)
{
	struct isis_area *area = NULL;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	if (isis == NULL)
		return NULL;

	if (!list_isempty(isis->area_list))
		area = listgetdata(listhead(isis->area_list));

	/* Check whether the instance identifier is valid */
	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	switch (v->magic) {
	case ISIS_SYS_VERSION:
		return SNMP_INTEGER(ISIS_VERSION);

	case ISIS_SYS_LEVELTYPE:
		/*
		 * If we do not have areas use 1&2 otherwise use settings
		 * from the first area in the list
		 */
		if (area == NULL)
			return SNMP_INTEGER(IS_LEVEL_1_AND_2);

		return SNMP_INTEGER(area->is_type);

	case ISIS_SYS_ID:
		if (!isis->sysid_set) {
			*var_len = ISIS_SYS_ID_LEN;
			return isis_null_sysid;
		}

		*var_len = ISIS_SYS_ID_LEN;
		return isis->sysid;

	case ISIS_SYS_MAXPATHSPLITS:
		return SNMP_INTEGER(ISIS_SNMP_MAX_PATH_SPLITS);

	case ISIS_SYS_MAXLSPGENINT:
		return SNMP_INTEGER(DEFAULT_MAX_LSP_GEN_INTERVAL);

	case ISIS_SYS_POLLESHELLORATE:
		return SNMP_INTEGER(DEFAULT_HELLO_INTERVAL);

	case ISIS_SYS_WAITTIME:
		/* Note: it seems that we have same fixed delay time */
		return SNMP_INTEGER(DEFAULT_MIN_LSP_GEN_INTERVAL);

	case ISIS_SYS_ADMINSTATE:
		/* If daemon is running it admin state is on */
		return SNMP_INTEGER(ISIS_SNMP_ADMIN_STATE_ON);


	case ISIS_SYS_L2TOL1LEAKING:
		/* We do not allow l2-to-l1 leaking */
		return SNMP_INTEGER(ISIS_SNMP_TRUTH_VALUE_FALSE);

	case ISIS_SYS_MAXAGE:
		return SNMP_INTEGER(MAX_AGE);

	case ISIS_SYS_RECEIVELSPBUFFERSIZE:
		if (area == NULL)
			return SNMP_INTEGER(DEFAULT_LSP_MTU);

		return SNMP_INTEGER(area->lsp_mtu);

	case ISIS_SYS_PROTSUPPORTED:
		*var_len = 1;
		return &isis_snmp_protocols_supported;

	case ISIS_SYS_NOTIFICATIONENABLE:
		if (isis->snmp_notifications)
			return SNMP_INTEGER(ISIS_SNMP_TRUTH_VALUE_TRUE);

		return SNMP_INTEGER(ISIS_SNMP_TRUTH_VALUE_FALSE);

	default:
		break;
	}

	return NULL;
}


static uint8_t *isis_snmp_find_man_area(struct variable *v, oid *name,
					size_t *length, int exact,
					size_t *var_len,
					WriteMethod **write_method)
{
	int res;
	struct iso_address *area_addr = NULL;
	oid *oid_idx;
	size_t oid_idx_len;
	size_t off = 0;

	*write_method = NULL;

	if (*length <= v->namelen) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else if (memcmp(name, v->name, v->namelen * sizeof(oid)) != 0) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else {
		oid_idx = name + v->namelen;
		oid_idx_len = *length - v->namelen;
	}

	if (exact) {
		res = isis_snmp_area_addr_lookup_exact(oid_idx, oid_idx_len,
						       NULL, &area_addr);

		if (!res)
			return NULL;

	} else {
		res = isis_snmp_area_addr_lookup_next(oid_idx, oid_idx_len,
						      NULL, &area_addr);

		if (!res)
			return NULL;

		/* Copy the name out */
		memcpy(name, v->name, v->namelen * sizeof(oid));

		/* Append index */
		name[v->namelen] = area_addr->addr_len;

		for (off = 0; off < area_addr->addr_len; off++)
			name[v->namelen + 1 + off] = area_addr->area_addr[off];

		*length = v->namelen + 1 + area_addr->addr_len;
	}

	switch (v->magic) {
	case ISIS_MANAREA_ADDREXISTSTATE:
		return SNMP_INTEGER(ISIS_SNMP_ROW_STATUS_ACTIVE);

	default:
		break;
	}

	return NULL;
}

static uint8_t *isis_snmp_find_area_addr(struct variable *v, oid *name,
					 size_t *length, int exact,
					 size_t *var_len,
					 WriteMethod **write_method)
{
	/*
	 * Area addresses in sense of addresses reported by L1 lsps
	 * are not supported yet.
	 */
	(void)v;
	(void)name;
	(void)length;
	(void)exact;
	(void)var_len;


	*write_method = NULL;

	return NULL;
}

static uint8_t *isis_snmp_find_summ_addr(struct variable *v, oid *name,
					 size_t *length, int exact,
					 size_t *var_len,
					 WriteMethod **write_method)
{
	/*
	 * So far there is no way to set summary table values through cli
	 * and snmp operations are read-only, hence there are no entries
	 */
	(void)v;
	(void)name;
	(void)length;
	(void)exact;
	(void)var_len;
	*write_method = NULL;

	return NULL;
}

static uint8_t *isis_snmp_find_redistribute_addr(struct variable *v, oid *name,
						 size_t *length, int exact,
						 size_t *var_len,
						 WriteMethod **write_method)
{
	/*
	 * It is not clear at the point whether redist code in isis is actually
	 * used for now we will consider that entries are not present
	 */
	(void)v;
	(void)name;
	(void)length;
	(void)exact;
	(void)var_len;
	*write_method = NULL;

	return NULL;
}

static uint8_t *isis_snmp_find_router(struct variable *v, oid *name,
				      size_t *length, int exact,
				      size_t *var_len,
				      WriteMethod **write_method)
{
	uint8_t cmp_buf[ISIS_SYS_ID_LEN];
	size_t cmp_len;
	int try_exact;
	int cmp_level;
	int res;
	struct isis_dynhn *dyn = NULL;
	oid *oid_idx;
	size_t oid_idx_len;
	size_t off = 0;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	if (isis == NULL)
		return NULL;

	*write_method = NULL;

	if (*length <= v->namelen) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else if (memcmp(name, v->name, v->namelen * sizeof(oid)) != 0) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else {
		oid_idx = name + v->namelen;
		oid_idx_len = *length - v->namelen;
	}

	if (exact) {
		res = isis_snmp_conv_exact(cmp_buf, sizeof(cmp_buf), &cmp_len,
					   oid_idx, oid_idx_len);

		if (!res || cmp_len != ISIS_SYS_ID_LEN
		    || oid_idx_len != (cmp_len + 2))
			/*
			 * Bad conversion, or bad length,
			 * or extra oids at the end
			 */
			return NULL;

		if (oid_idx[ISIS_SYS_ID_LEN + 1] < IS_LEVEL_1
		    || oid_idx[ISIS_SYS_ID_LEN + 1] > IS_LEVEL_2)
			/* Level part of the index is out of range */
			return NULL;

		cmp_level = (int)oid_idx[ISIS_SYS_ID_LEN + 1];

		dyn = dynhn_find_by_id(isis, cmp_buf);

		if (dyn == NULL || dyn->level != cmp_level)
			return NULL;

		switch (v->magic) {
		case ISIS_ROUTER_HOSTNAME:
			*var_len = strlen(dyn->hostname);
			return (uint8_t *)dyn->hostname;

		case ISIS_ROUTER_ID:
			/* It seems that we do no know router-id in lsps */
			return SNMP_INTEGER(0);

		default:
			break;
		}

		return NULL;
	}

	res = isis_snmp_conv_next(cmp_buf, sizeof(cmp_buf), &cmp_len,
				  &try_exact, oid_idx, oid_idx_len);


	if (!res)
		/* Bad conversion */
		return NULL;

	if (cmp_len != ISIS_SYS_ID_LEN) {
		/* We do not have valid index oids */
		memset(cmp_buf, 0, sizeof(cmp_buf));
		cmp_level = 0;
	} else if (try_exact)
		/*
		 * We have no valid level index.
		 * Let start from non-existing level 0 and
		 * hence not need to do exact match
		 */
		cmp_level = 0;
	else if (oid_idx_len < (ISIS_SYS_ID_LEN + 2))
		cmp_level = 0;
	else if (oid_idx[ISIS_SYS_ID_LEN + 1] <= IS_LEVEL_2)
		cmp_level = (int)oid_idx[ISIS_SYS_ID_LEN + 1];
	else
		/*
		 * Any value greater than 2 will have the same result
		 * but we can have integer overflows, hence 3 is a reasonable
		 * choice
		 */
		cmp_level = (int)(IS_LEVEL_2 + 1);

	dyn = dynhn_snmp_next(isis, cmp_buf, cmp_level);

	if (dyn == NULL)
		return NULL;

	/* Copy the name out */
	memcpy(name, v->name, v->namelen * sizeof(oid));

	/* Append index */
	name[v->namelen] = ISIS_SYS_ID_LEN;

	for (off = 0; off < ISIS_SYS_ID_LEN; off++)
		name[v->namelen + 1 + off] = dyn->id[off];

	name[v->namelen + 1 + ISIS_SYS_ID_LEN] = (oid)dyn->level;

	/* Set length */
	*length = v->namelen + 1 + ISIS_SYS_ID_LEN + 1;

	switch (v->magic) {
	case ISIS_ROUTER_HOSTNAME:
		*var_len = strlen(dyn->hostname);
		return (uint8_t *)dyn->hostname;

	case ISIS_ROUTER_ID:
		/* It seems that we do no know router-id in lsps */
		return SNMP_INTEGER(0);

	default:
		break;
	}

	return NULL;
}

static uint8_t *isis_snmp_find_sys_level(struct variable *v, oid *name,
					 size_t *length, int exact,
					 size_t *var_len,
					 WriteMethod **write_method)
{
	oid *oid_idx;
	size_t oid_idx_len;
	int level;
	int level_match;
	struct isis_area *area = NULL;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	if (isis == NULL)
		return NULL;

	*write_method = NULL;

	if (*length <= v->namelen) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else if (memcmp(name, v->name, v->namelen * sizeof(oid)) != 0) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else {
		oid_idx = name + v->namelen;
		oid_idx_len = *length - v->namelen;
	}

	if (exact) {
		if (oid_idx == NULL || oid_idx_len != 1)
			return NULL;

		if (oid_idx[0] == IS_LEVEL_1)
			level = IS_LEVEL_1;
		else if (oid_idx[0] == IS_LEVEL_2)
			level = IS_LEVEL_2;
		else
			return NULL;

	} else {
		if (oid_idx == NULL)
			level = IS_LEVEL_1;
		else if (oid_idx_len == 0)
			level = IS_LEVEL_1;
		else if (oid_idx[0] < IS_LEVEL_1)
			level = IS_LEVEL_1;
		else if (oid_idx[0] < IS_LEVEL_2)
			level = IS_LEVEL_2;
		else
			return NULL;

		/* Copy the name out */
		memcpy(name, v->name, v->namelen * sizeof(oid));

		/* Append index */
		name[v->namelen] = level;

		/* Set length */
		*length = v->namelen + 1;
	}

	area = NULL;

	if (!list_isempty(isis->area_list))
		area = listgetdata(listhead(isis->area_list));

	level_match = 0;

	if (area != NULL)
		level_match = isis_snmp_get_level_match(area->is_type, level);

	switch (v->magic) {
	case ISIS_SYSLEVEL_ORIGLSPBUFFSIZE:
		if (level_match)
			return SNMP_INTEGER(area->lsp_mtu);

		return SNMP_INTEGER(DEFAULT_LSP_MTU);

	case ISIS_SYSLEVEL_MINLSPGENINT:
		if (level_match)
			return SNMP_INTEGER(area->lsp_gen_interval[level - 1]);
		else
			return SNMP_INTEGER(DEFAULT_MIN_LSP_GEN_INTERVAL);

	case ISIS_SYSLEVEL_STATE:
		if (level_match) {
			if (area->overload_bit)
				return SNMP_INTEGER(
					ISIS_SNMP_LEVEL_STATE_OVERLOADED);

			return SNMP_INTEGER(ISIS_SNMP_LEVEL_STATE_ON);
		}
		return SNMP_INTEGER(ISIS_SNMP_LEVEL_STATE_OFF);

	case ISIS_SYSLEVEL_SETOVERLOAD:
		if (level_match && area->overload_bit)
			return SNMP_INTEGER(ISIS_SNMP_TRUTH_VALUE_TRUE);

		return SNMP_INTEGER(ISIS_SNMP_TRUTH_VALUE_FALSE);

	case ISIS_SYSLEVEL_SETOVERLOADUNTIL:
		/* We do not have automatic cleanup of overload bit */
		return SNMP_INTEGER(0);

	case ISIS_SYSLEVEL_METRICSTYLE:
		if (level_match) {
			if (area->newmetric && area->oldmetric)
				return SNMP_INTEGER(
					ISIS_SNMP_METRIC_STYLE_BOTH);

			if (area->newmetric)
				return SNMP_INTEGER(
					ISIS_SNMP_METRIC_STYLE_WIDE);

			return SNMP_INTEGER(ISIS_SNMP_METRIC_STYLE_NARROW);
		}
		return SNMP_INTEGER(ISIS_SNMP_METRIC_STYLE_NARROW);

	case ISIS_SYSLEVEL_SPFCONSIDERS:
		return SNMP_INTEGER(ISIS_SNMP_METRIC_STYLE_BOTH);

	case ISIS_SYSLEVEL_TEENABLED:
		if (level_match && IS_MPLS_TE(area->mta))
			return SNMP_INTEGER(ISIS_SNMP_TRUTH_VALUE_TRUE);

		return SNMP_INTEGER(ISIS_SNMP_TRUTH_VALUE_FALSE);

	default:
		break;
	}

	return NULL;
}

static uint8_t *isis_snmp_find_system_counter(struct variable *v, oid *name,
					      size_t *length, int exact,
					      size_t *var_len,
					      WriteMethod **write_method)
{
	oid *oid_idx;
	size_t oid_idx_len;
	int level;
	int level_match;
	struct isis_area *area = NULL;
	uint32_t val;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	if (isis == NULL)
		return NULL;

	*write_method = NULL;

	if (*length <= v->namelen) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else if (memcmp(name, v->name, v->namelen * sizeof(oid)) != 0) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else {
		oid_idx = name + v->namelen;
		oid_idx_len = *length - v->namelen;
	}

	if (exact) {
		if (oid_idx == NULL || oid_idx_len != 1)
			return 0;

		if (oid_idx[0] == IS_LEVEL_1)
			level = IS_LEVEL_1;
		else if (oid_idx[0] == IS_LEVEL_2)
			level = IS_LEVEL_2;
		else
			return NULL;

	} else {
		if (oid_idx == NULL)
			level = IS_LEVEL_1;
		else if (oid_idx_len == 0)
			level = IS_LEVEL_1;
		else if (oid_idx[0] < IS_LEVEL_1)
			level = IS_LEVEL_1;
		else if (oid_idx[0] < IS_LEVEL_2)
			level = IS_LEVEL_2;
		else
			return NULL;

		/* Copy the name out */
		memcpy(name, v->name, v->namelen * sizeof(oid));

		/* Append index */
		name[v->namelen] = level;

		/* Set length */
		*length = v->namelen + 1;
	}

	area = NULL;

	if (!list_isempty(isis->area_list))
		area = listgetdata(listhead(isis->area_list));

	level_match = 0;

	if (area != NULL)
		level_match = isis_snmp_get_level_match(area->is_type, level);

	if (!level_match)
		/* If level does not match all counters are zeros */
		return SNMP_INTEGER(0);

	switch (v->magic) {
	case ISIS_SYSSTAT_CORRLSPS:
		val = 0;
		break;

	case ISIS_SYSSTAT_AUTHTYPEFAILS:
		val = (uint32_t)area->auth_type_failures[level - 1];
		break;

	case ISIS_SYSSTAT_AUTHFAILS:
		val = (uint32_t)area->auth_failures[level - 1];
		break;

	case ISIS_SYSSTAT_LSPDBASEOLOADS:
		val = area->overload_counter;
		break;

	case ISIS_SYSSTAT_MANADDRDROPFROMAREAS:
		/* We do not support manual addresses */
		val = 0;
		break;

	case ISIS_SYSSTAT_ATTMPTTOEXMAXSEQNUMS:
		val = area->lsp_exceeded_max_counter;
		break;

	case ISIS_SYSSTAT_SEQNUMSKIPS:
		val = area->lsp_seqno_skipped_counter;
		break;

	case ISIS_SYSSTAT_OWNLSPPURGES:
		if (!area->purge_originator)
			val = 0;
		else
			val = area->lsp_purge_count[level - 1];
		break;

	case ISIS_SYSSTAT_IDFIELDLENMISMATCHES:
		val = (uint32_t)area->id_len_mismatches[level - 1];
		break;

	case ISIS_SYSSTAT_PARTCHANGES:
		/* Not supported */
		val = 0;
		break;

	case ISIS_SYSSTAT_SPFRUNS:
		val = (uint32_t)area->spf_run_count[level - 1];
		break;

	case ISIS_SYSSTAT_LSPERRORS:
		val = (uint32_t)area->lsp_error_counter[level - 1];
		break;

	default:
		return NULL;
	}

	return SNMP_INTEGER(val);
}

static uint8_t *isis_snmp_find_next_circ_index(struct variable *v, oid *name,
					       size_t *length, int exact,
					       size_t *var_len,
					       WriteMethod **write_method)
{
	/* Check whether the instance identifier is valid */
	if (smux_header_generic(v, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	switch (v->magic) {
	case ISIS_NEXTCIRC_INDEX:
		/*
		 * We do not support circuit creation through snmp
		 */
		return SNMP_INTEGER(0);

	default:
		break;
	}

	return 0;
}

static uint8_t *isis_snmp_find_circ(struct variable *v, oid *name,
				    size_t *length, int exact, size_t *var_len,
				    WriteMethod **write_method)
{
	/* Index is circuit-id: 1-255 */
	oid *oid_idx;
	size_t oid_idx_len;
	struct isis_circuit *circuit;
	uint32_t up_ticks;
	uint32_t delta_ticks;
	time_t now_time;
	int res;

	*write_method = NULL;

	if (*length <= v->namelen) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else if (memcmp(name, v->name, v->namelen * sizeof(oid)) != 0) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else {
		oid_idx = name + v->namelen;
		oid_idx_len = *length - v->namelen;
	}
	if (exact) {
		res = isis_snmp_circuit_lookup_exact(oid_idx, oid_idx_len,
						     &circuit);

		if (!res || oid_idx_len != 1)
			return NULL;

	} else {
		res = isis_snmp_circuit_lookup_next(oid_idx, oid_idx_len,
						    &circuit);

		if (!res)
			return NULL;

		/* Copy the name out */
		memcpy(name, v->name, v->namelen * sizeof(oid));

		/* Append index */
		name[v->namelen] = circuit->snmp_id;

		/* Set length */
		*length = v->namelen + 1;
	}

	switch (v->magic) {
	case ISIS_CIRC_IFINDEX:
		if (circuit->interface == NULL)
			return SNMP_INTEGER(0);

		return SNMP_INTEGER(circuit->interface->ifindex);

	case ISIS_CIRC_ADMINSTATE:
		return SNMP_INTEGER(ISIS_SNMP_ADMIN_STATE_ON);

	case ISIS_CIRC_EXISTSTATE:
		return SNMP_INTEGER(ISIS_SNMP_ROW_STATUS_ACTIVE);

	case ISIS_CIRC_TYPE:
		/*
		 * Note: values do not match 100%:
		 *
		 * 1. From isis_circuit.h:
		 *        CIRCUIT_T_UNKNOWN    0
		 *        CIRCUIT_T_BROADCAST  1
		 *        CIRCUIT_T_P2P        2
		 *        CIRCUIT_T_LOOPBACK   3
		 *
		 * 2. From rfc:
		 *        broadcast(1),
		 *        ptToPt(2),
		 *        staticIn(3),
		 *        staticOut(4),
		 */

		return SNMP_INTEGER(circuit->circ_type);

	case ISIS_CIRC_EXTDOMAIN:
		if (circuit->ext_domain)
			return SNMP_INTEGER(ISIS_SNMP_TRUTH_VALUE_TRUE);

		return SNMP_INTEGER(ISIS_SNMP_TRUTH_VALUE_FALSE);

	case ISIS_CIRC_LEVELTYPE:
		return SNMP_INTEGER(circuit->is_type);

	case ISIS_CIRC_PASSIVECIRCUIT:
		if (circuit->is_passive)
			return SNMP_INTEGER(ISIS_SNMP_TRUTH_VALUE_TRUE);

		return SNMP_INTEGER(ISIS_SNMP_TRUTH_VALUE_FALSE);

	case ISIS_CIRC_MESHGROUPENABLED:
		/* Not supported */
		return SNMP_INTEGER(ISIS_SNMP_MESH_GROUP_INACTIVE);

	case ISIS_CIRC_MESHGROUP:
		/* Not supported */
		return SNMP_INTEGER(0);

	case ISIS_CIRC_SMALLHELLOS:
		/*
		 * return false if lan hellos must be padded
		 */
		if (circuit->pad_hellos == ISIS_HELLO_PADDING_ALWAYS ||
		    (circuit->pad_hellos ==
			     ISIS_HELLO_PADDING_DURING_ADJACENCY_FORMATION &&
		     circuit->upadjcount[0] + circuit->upadjcount[1] == 0))
			return SNMP_INTEGER(ISIS_SNMP_TRUTH_VALUE_FALSE);

		return SNMP_INTEGER(ISIS_SNMP_TRUTH_VALUE_TRUE);

	case ISIS_CIRC_LASTUPTIME:
		if (circuit->last_uptime == 0)
			return SNMP_INTEGER(0);

		up_ticks = (uint32_t)netsnmp_get_agent_uptime();
		now_time = time(NULL);

		if (circuit->last_uptime >= now_time)
			return SNMP_INTEGER(up_ticks);

		delta_ticks = (now_time - circuit->last_uptime) * 10;

		if (up_ticks < delta_ticks)
			return SNMP_INTEGER(up_ticks);

		return SNMP_INTEGER(up_ticks - delta_ticks);

	case ISIS_CIRC_3WAYENABLED:
		/* Not supported */
		return SNMP_INTEGER(ISIS_SNMP_TRUTH_VALUE_FALSE);

	case ISIS_CIRC_EXTENDEDCIRCID:
		/* Used for 3-way hand shake only */
		return SNMP_INTEGER(0);

	default:
		break;
	}

	return NULL;
}

static uint8_t *isis_snmp_find_circ_level(struct variable *v, oid *name,
					  size_t *length, int exact,
					  size_t *var_len,
					  WriteMethod **write_method)
{
	static uint8_t circuit_id_val[ISIS_SYS_ID_LEN + 1];
	/* Index is circuit-id: 1-255 + level: 1-2 */
	oid *oid_idx;
	size_t oid_idx_len;
	int res;
	struct isis_circuit *circuit;
	int level;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	if (isis == NULL)
		return NULL;

	*write_method = NULL;

	if (*length <= v->namelen) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else if (memcmp(name, v->name, v->namelen * sizeof(oid)) != 0) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else {
		oid_idx = name + v->namelen;
		oid_idx_len = *length - v->namelen;
	}
	if (exact) {
		res = isis_snmp_circuit_level_lookup_exact(oid_idx, oid_idx_len,
							   1, &circuit, &level);

		if (!res || oid_idx_len != 2)
			return NULL;

	} else {
		res = isis_snmp_circuit_level_lookup_next(oid_idx, oid_idx_len,
							  1, &circuit, &level);

		if (!res)
			return NULL;

		/* Copy the name out */
		memcpy(name, v->name, v->namelen * sizeof(oid));

		/* Append index */
		name[v->namelen] = circuit->snmp_id;
		name[v->namelen + 1] = level;

		/* Set length */
		*length = v->namelen + 2;
	}

	switch (v->magic) {
	case ISIS_CIRCLEVEL_METRIC:
		return SNMP_INTEGER(circuit->metric[level - 1]);

	case ISIS_CIRCLEVEL_WIDEMETRIC:
		if (circuit->area == NULL || !circuit->area->newmetric) {
			/* What should we do if wide metric is not supported? */
			return SNMP_INTEGER(0);
		}
		return SNMP_INTEGER(circuit->te_metric[level - 1]);

	case ISIS_CIRCLEVEL_ISPRIORITY:
		return SNMP_INTEGER(circuit->priority[level - 1]);

	case ISIS_CIRCLEVEL_IDOCTET:
		return SNMP_INTEGER(circuit->circuit_id);

	case ISIS_CIRCLEVEL_ID:
		if (circuit->circ_type != CIRCUIT_T_P2P) {
			/*
			 * Unless it is point-to-point circuit, the value is and
			 * empty octet string
			 */
			*var_len = 0;
			return circuit_id_val;
		}

		/* !!!!!! Circuit-id is zero for p2p links */
		if (circuit->u.p2p.neighbor == NULL
		    || circuit->u.p2p.neighbor->adj_state != ISIS_ADJ_UP) {
			/* No adjacency or adjacency not fully up yet */
			memcpy(circuit_id_val, isis->sysid, ISIS_SYS_ID_LEN);
			circuit_id_val[ISIS_SYS_ID_LEN] = circuit->circuit_id;
			*var_len = ISIS_SYS_ID_LEN + 1;
			return circuit_id_val;
		}

		/* Adjacency fully-up */
		memcpy(circuit_id_val, circuit->u.p2p.neighbor->sysid,
		       ISIS_SYS_ID_LEN);
		circuit_id_val[ISIS_SYS_ID_LEN] = 0;
		*var_len = ISIS_SYS_ID_LEN + 1;
		return circuit_id_val;

	case ISIS_CIRCLEVEL_DESIS:
		if (circuit->circ_type != CIRCUIT_T_BROADCAST
		    || !circuit->u.bc.is_dr[level - 1]) {
			/*
			 * Unless it is lan circuit participating in dis process
			 * the value is an empty octet string
			 */
			*var_len = 0;
			return circuit_id_val;
		}

		*var_len = ISIS_SYS_ID_LEN + 1;

		if (level == IS_LEVEL_1)
			return circuit->u.bc.l1_desig_is;

		return circuit->u.bc.l2_desig_is;

	case ISIS_CIRCLEVEL_HELLOMULTIPLIER:
		return SNMP_INTEGER(circuit->hello_multiplier[level - 1]);

	case ISIS_CIRCLEVEL_HELLOTIMER:
		return SNMP_INTEGER(circuit->hello_interval[level - 1] * 1000);

	case ISIS_CIRCLEVEL_DRHELLOTIMER:
		return SNMP_INTEGER(circuit->hello_interval[level - 1] * 1000);

	case ISIS_CIRCLEVEL_LSPTHROTTLE:
		if (circuit->area)
			return SNMP_INTEGER(
				circuit->area->min_spf_interval[level - 1]
				* 1000);
		else
			return SNMP_INTEGER(0);

	case ISIS_CIRCLEVEL_MINLSPRETRANSINT:
		if (circuit->area)
			return SNMP_INTEGER(
				circuit->area->min_spf_interval[level - 1]);
		else
			return SNMP_INTEGER(0);

	case ISIS_CIRCLEVEL_CSNPINTERVAL:
		return SNMP_INTEGER(circuit->csnp_interval[level - 1]);

	case ISIS_CIRCLEVEL_PARTSNPINTERVAL:
		return SNMP_INTEGER(circuit->psnp_interval[level - 1]);

	default:
		break;
	}

	return NULL;
}

static uint8_t *isis_snmp_find_circ_counter(struct variable *v, oid *name,
					    size_t *length, int exact,
					    size_t *var_len,
					    WriteMethod **write_method)
{
	/* Index circuit-id 1-255 + level */
	oid *oid_idx;
	size_t oid_idx_len;
	int res;
	struct isis_circuit *circuit;
	int level;
	uint32_t val = 0;

	*write_method = NULL;

	if (*length <= v->namelen) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else if (memcmp(name, v->name, v->namelen * sizeof(oid)) != 0) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else {
		oid_idx = name + v->namelen;
		oid_idx_len = *length - v->namelen;
	}
	if (exact) {
		res = isis_snmp_circuit_level_lookup_exact(oid_idx, oid_idx_len,
							   1, &circuit, &level);

		if (!res || oid_idx_len != 2)
			return NULL;

	} else {
		res = isis_snmp_circuit_level_lookup_next(oid_idx, oid_idx_len,
							  1, &circuit, &level);

		if (!res)
			return NULL;

		/* Copy the name out */
		memcpy(name, v->name, v->namelen * sizeof(oid));

		/* Append index */
		name[v->namelen] = circuit->snmp_id;
		if (circuit->circ_type == CIRCUIT_T_P2P)
			name[v->namelen + 1] = ISIS_SNMP_P2P_CIRCUIT;
		else
			name[v->namelen + 1] = level;

		/* Set length */
		*length = v->namelen + 2;
	}

	switch (v->magic) {
	case ISIS_CIRC_ADJCHANGES:
		val = circuit->adj_state_changes;
		break;

	case ISIS_CIRC_NUMADJ:
		if (circuit->circ_type == CIRCUIT_T_P2P) {
			val = circuit->u.p2p.neighbor == NULL ? 0 : 1;
			break;
		}

		if (circuit->circ_type != CIRCUIT_T_BROADCAST) {
			val = 0;
			break;
		}

		if (level == IS_LEVEL_1) {
			if (circuit->u.bc.adjdb[0] == NULL)
				val = 0;
			else
				val = listcount(circuit->u.bc.adjdb[0]);
			break;
		}

		if (circuit->u.bc.adjdb[1] == NULL)
			val = 0;
		else
			val = listcount(circuit->u.bc.adjdb[1]);

		break;

	case ISIS_CIRC_INITFAILS:
		val = circuit->init_failures; /* counter never incremented */
		break;

	case ISIS_CIRC_REJADJS:
		val = circuit->rej_adjacencies;
		break;

	case ISIS_CIRC_IDFIELDLENMISMATCHES:
		val = circuit->id_len_mismatches;
		break;

	case ISIS_CIRC_MAXAREAADDRMISMATCHES:
		val = circuit->max_area_addr_mismatches;
		break;

	case ISIS_CIRC_AUTHTYPEFAILS:
		val = circuit->auth_type_failures;
		break;

	case ISIS_CIRC_AUTHFAILS:
		val = circuit->auth_failures;
		break;

	case ISIS_CIRC_LANDESISCHANGES:
		if (circuit->circ_type == CIRCUIT_T_P2P)
			val = 0;
		else
			val = circuit->desig_changes[level - 1];
		break;

	default:
		return NULL;
	}

	return SNMP_INTEGER(val);
}

static uint8_t *isis_snmp_find_isadj(struct variable *v, oid *name,
				     size_t *length, int exact, size_t *var_len,
				     WriteMethod **write_method)
{
	/* Index is circuit-id: 1-255 + adj-id: 1-... */
	oid *oid_idx;
	size_t oid_idx_len;
	int res;
	time_t val;
	struct isis_adjacency *adj;
	uint32_t up_ticks;
	uint32_t delta_ticks;
	time_t now_time;

	/* Ring buffer to print SNPA */
#define FORMAT_BUF_COUNT 4
	static char snpa[FORMAT_BUF_COUNT][ISO_SYSID_STRLEN];
	static size_t cur_buf = 0;

	*write_method = NULL;

	if (*length <= v->namelen) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else if (memcmp(name, v->name, v->namelen * sizeof(oid)) != 0) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else {
		oid_idx = name + v->namelen;
		oid_idx_len = *length - v->namelen;
	}
	if (exact) {
		res = isis_snmp_adj_lookup_exact(oid_idx, oid_idx_len,
						 ISIS_SNMP_ADJ_DATA_NONE, &adj,
						 NULL, NULL, NULL);

		if (!res || oid_idx_len != 2)
			return NULL;

	} else {
		res = isis_snmp_adj_lookup_next(oid_idx, oid_idx_len,
						ISIS_SNMP_ADJ_DATA_NONE, &adj,
						NULL, NULL, NULL);
		if (!res)
			return NULL;

		/* Copy the name out */
		memcpy(name, v->name, v->namelen * sizeof(oid));

		/* Append index */
		name[v->namelen] = adj->circuit->snmp_id;
		name[v->namelen + 1] = adj->snmp_idx;

		/* Set length */
		*length = v->namelen + 2;
	}

	switch (v->magic) {
	case ISIS_ISADJ_STATE:
		return SNMP_INTEGER(isis_snmp_adj_state(adj->adj_state));

	case ISIS_ISADJ_3WAYSTATE:
		return SNMP_INTEGER(adj->threeway_state);

	case ISIS_ISADJ_NEIGHSNPAADDRESS: {
		cur_buf = (cur_buf + 1) % FORMAT_BUF_COUNT;
		snprintfrr(snpa[cur_buf], ISO_SYSID_STRLEN, "%pSY", adj->snpa);
		*var_len = strlen(snpa[cur_buf]);
		return (uint8_t *)snpa[cur_buf];
	}

	case ISIS_ISADJ_NEIGHSYSTYPE:
		return SNMP_INTEGER(isis_snmp_adj_neightype(adj->sys_type));

	case ISIS_ISADJ_NEIGHSYSID:
		*var_len = sizeof(adj->sysid);
		return adj->sysid;

	case ISIS_ISADJ_NBREXTENDEDCIRCID:
		return SNMP_INTEGER(adj->ext_circuit_id != 0 ? 1 : 0);

	case ISIS_ISADJ_USAGE:
		/* It seems that no value conversion is required */
		return SNMP_INTEGER(adj->adj_usage);

	case ISIS_ISADJ_HOLDTIMER:
		/*
		 * It seems that we want remaining timer
		 */
		if (adj->last_upd != 0) {
			val = time(NULL);
			if (val < (adj->last_upd + adj->hold_time))
				return SNMP_INTEGER(adj->last_upd
						    + adj->hold_time - val);
		}
		/* Not running or just expired */
		return SNMP_INTEGER(0);

	case ISIS_ISADJ_NEIGHPRIORITY:
		return SNMP_INTEGER(adj->prio[adj->level - 1]);

	case ISIS_ISADJ_LASTUPTIME:
		if (adj->flaps == 0)
			return SNMP_INTEGER(0);

		up_ticks = (uint32_t)netsnmp_get_agent_uptime();

		now_time = time(NULL);

		if (adj->last_flap >= now_time)
			return SNMP_INTEGER(up_ticks);

		delta_ticks = (now_time - adj->last_flap) * 10;

		if (up_ticks < delta_ticks)
			return SNMP_INTEGER(up_ticks);

		return SNMP_INTEGER(up_ticks - delta_ticks);

	default:
		break;
	}

	return NULL;
}

static uint8_t *isis_snmp_find_isadj_area(struct variable *v, oid *name,
					  size_t *length, int exact,
					  size_t *var_len,
					  WriteMethod **write_method)
{
	/* Index circuit-id: 1-255 + adj-id: 1-... */
	oid *oid_idx;
	size_t oid_idx_len;
	int res;
	struct isis_adjacency *adj;
	oid data_idx;
	uint8_t *data;
	size_t data_len;

	*write_method = NULL;

	if (*length <= v->namelen) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else if (memcmp(name, v->name, v->namelen * sizeof(oid)) != 0) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else {
		oid_idx = name + v->namelen;
		oid_idx_len = *length - v->namelen;
	}
	if (exact) {
		res = isis_snmp_adj_lookup_exact(oid_idx, oid_idx_len,
						 ISIS_SNMP_ADJ_DATA_AREA_ADDR,
						 &adj, NULL, &data, &data_len);

		if (!res || oid_idx_len != 3)
			return NULL;

	} else {
		res = isis_snmp_adj_lookup_next(
			oid_idx, oid_idx_len, ISIS_SNMP_ADJ_DATA_AREA_ADDR,
			&adj, &data_idx, &data, &data_len);
		if (!res)
			return NULL;

		/* Copy the name out */
		memcpy(name, v->name, v->namelen * sizeof(oid));

		/* Append index */
		name[v->namelen] = adj->circuit->snmp_id;
		name[v->namelen + 1] = adj->snmp_idx;
		name[v->namelen + 2] = data_idx;

		/* Set length */
		*length = v->namelen + 3;
	}

	switch (v->magic) {
	case ISIS_ISADJAREA_ADDRESS:
		*var_len = data_len;
		return data;

	default:
		break;
	}

	return NULL;
}

static uint8_t *isis_snmp_find_isadj_ipaddr(struct variable *v, oid *name,
					    size_t *length, int exact,
					    size_t *var_len,
					    WriteMethod **write_method)
{
	/* Index circuit-id 1-255 + adj-id 1-... */
	oid *oid_idx;
	size_t oid_idx_len;
	int res;
	struct isis_adjacency *adj;
	oid data_idx;
	uint8_t *data;
	size_t data_len;

	*write_method = NULL;

	if (*length <= v->namelen) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else if (memcmp(name, v->name, v->namelen * sizeof(oid)) != 0) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else {
		oid_idx = name + v->namelen;
		oid_idx_len = *length - v->namelen;
	}
	if (exact) {
		res = isis_snmp_adj_lookup_exact(oid_idx, oid_idx_len,
						 ISIS_SNMP_ADJ_DATA_IP_ADDR,
						 &adj, NULL, &data, &data_len);

		if (!res || oid_idx_len != 3)
			return NULL;
	} else {
		res = isis_snmp_adj_lookup_next(
			oid_idx, oid_idx_len, ISIS_SNMP_ADJ_DATA_IP_ADDR, &adj,
			&data_idx, &data, &data_len);
		if (!res)
			return NULL;

		/* Copy the name out */
		memcpy(name, v->name, v->namelen * sizeof(oid));

		/* Append index */
		name[v->namelen] = adj->circuit->snmp_id;
		name[v->namelen + 1] = adj->snmp_idx;
		name[v->namelen + 2] = data_idx;

		/* Set length */
		*length = v->namelen + 3;
	}

	switch (v->magic) {
	case ISIS_ISADJIPADDR_TYPE:
		if (data_len == 4)
			return SNMP_INTEGER(ISIS_SNMP_INET_TYPE_V4);

		return SNMP_INTEGER(ISIS_SNMP_INET_TYPE_V6);

	case ISIS_ISADJIPADDR_ADDRESS:
		*var_len = data_len;
		return data;

	default:
		break;
	}

	return NULL;
}

static uint8_t *isis_snmp_find_isadj_prot_supp(struct variable *v, oid *name,
					       size_t *length, int exact,
					       size_t *var_len,
					       WriteMethod **write_method)
{
	/* Index circuit-id 1-255 + adj-id 1-... */
	oid *oid_idx;
	size_t oid_idx_len;
	int res;
	struct isis_adjacency *adj;
	oid data_idx;
	uint8_t *data;
	size_t data_len;

	*write_method = NULL;

	if (*length <= v->namelen) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else if (memcmp(name, v->name, v->namelen * sizeof(oid)) != 0) {
		oid_idx = NULL;
		oid_idx_len = 0;
	} else {
		oid_idx = name + v->namelen;
		oid_idx_len = *length - v->namelen;
	}
	if (exact) {
		res = isis_snmp_adj_lookup_exact(oid_idx, oid_idx_len,
						 ISIS_SNMP_ADJ_DATA_PROTO, &adj,
						 NULL, &data, &data_len);

		if (!res || oid_idx_len != 3)
			return NULL;

	} else {
		res = isis_snmp_adj_lookup_next(oid_idx, oid_idx_len,
						ISIS_SNMP_ADJ_DATA_PROTO, &adj,
						&data_idx, &data, &data_len);
		if (!res)
			return NULL;

		/* Copy the name out */
		memcpy(name, v->name, v->namelen * sizeof(oid));

		/* Append index */
		name[v->namelen] = adj->circuit->snmp_id;
		name[v->namelen + 1] = adj->snmp_idx;
		name[v->namelen + 2] = data_idx;

		/* Set length */
		*length = v->namelen + 3;
	}

	switch (v->magic) {
	case ISIS_ISADJPROTSUPP_PROTOCOL:
		return SNMP_INTEGER(*data);

	default:
		break;
	}

	return NULL;
}


/* Register ISIS-MIB. */
static int isis_snmp_init(struct event_loop *tm)
{
	struct isis_func_to_prefix *h2f = isis_func_to_prefix_arr;
	struct variable *v;

	for (size_t off = 0; off < isis_var_count; off++) {
		v = &isis_var_arr[off];

		if (v->findVar != h2f->ihtp_func) {
			/* Next table */
			h2f++;
			assert(h2f < (isis_func_to_prefix_arr
				      + isis_func_to_prefix_count));
			assert(v->findVar == h2f->ihtp_func);
		}

		v->namelen = h2f->ihtp_pref_len + 1;
		memcpy(v->name, h2f->ihtp_pref_oid,
		       h2f->ihtp_pref_len * sizeof(oid));
		v->name[h2f->ihtp_pref_len] = v->magic;
	}


	smux_init(tm);
	REGISTER_MIB("mibII/isis", isis_var_arr, variable, isis_oid);
	return 0;
}

static int isis_snmp_terminate(void)
{
	smux_terminate();

	return 0;
}

/*
 * ISIS notification functions: we have one function per notification
 */
static int isis_snmp_trap_throttle(oid trap_id)
{
	time_t time_now;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	if (isis == NULL || !isis->snmp_notifications || !smux_enabled())
		return 0;

	time_now = time(NULL);

	if ((isis_snmp_trap_timestamp[trap_id] + 5) > time_now)
		/* Throttle trap rate at 1 in 5 secs */
		return 0;

	isis_snmp_trap_timestamp[trap_id] = time_now;
	return 1;
}

static int isis_snmp_db_overload_update(const struct isis_area *area)
{
	netsnmp_variable_list *notification_vars;
	long val;
	uint32_t off;

	if (!isis_snmp_trap_throttle(ISIS_TRAP_DB_OVERLOAD))
		return 0;

	notification_vars = NULL;

	/* Put in trap value */
	snmp_varlist_add_variable(&notification_vars, isis_snmp_trap_var,
				  array_size(isis_snmp_trap_var), ASN_OBJECT_ID,
				  (uint8_t *)&isis_snmp_trap_val_db_overload,
				  sizeof(isis_snmp_trap_val_db_overload));

	/* Prepare data */
	val = area->is_type;

	snmp_varlist_add_variable(
		&notification_vars, isis_snmp_trap_data_var_sys_level_index,
		array_size(isis_snmp_trap_data_var_sys_level_index), INTEGER,
		(uint8_t *)&val, sizeof(val));

	/* Patch sys_level_state with proper index */
	off = array_size(isis_snmp_trap_data_var_sys_level_state) - 1;
	isis_snmp_trap_data_var_sys_level_state[off] = val;

	/* Prepare data */
	if (area->overload_bit)
		val = ISIS_SNMP_LEVEL_STATE_OVERLOADED;
	else
		val = ISIS_SNMP_LEVEL_STATE_ON;

	snmp_varlist_add_variable(
		&notification_vars, isis_snmp_trap_data_var_sys_level_state,
		array_size(isis_snmp_trap_data_var_sys_level_state), INTEGER,
		(uint8_t *)&val, sizeof(val));

	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
	smux_events_update();
	return 0;
}

static int isis_snmp_lsp_exceed_max_update(const struct isis_area *area,
					   const uint8_t *lsp_id)
{
	netsnmp_variable_list *notification_vars;
	long val;

	if (!isis_snmp_trap_throttle(ISIS_TRAP_LSP_EXCEED_MAX))
		return 0;

	notification_vars = NULL;

	/* Put in trap value */
	snmp_varlist_add_variable(&notification_vars, isis_snmp_trap_var,
				  array_size(isis_snmp_trap_var), ASN_OBJECT_ID,
				  (uint8_t *)&isis_snmp_trap_val_lsp_exceed_max,
				  sizeof(isis_snmp_trap_val_lsp_exceed_max));

	/* Prepare data */
	val = area->is_type;

	snmp_varlist_add_variable(
		&notification_vars, isis_snmp_trap_data_var_sys_level_index,
		array_size(isis_snmp_trap_data_var_sys_level_index), INTEGER,
		(uint8_t *)&val, sizeof(val));

	snmp_varlist_add_variable(
		&notification_vars, isis_snmp_trap_data_var_pdu_lsp_id,
		array_size(isis_snmp_trap_data_var_pdu_lsp_id), STRING, lsp_id,
		ISIS_SYS_ID_LEN + 2);

	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
	smux_events_update();
	return 0;
}


/*
 * A common function to handle popular combination of trap objects
 * isisNotificationSysLevelIndex,
 * optional-object-a
 * isisNotificationCircIfIndex,
 * optional-object-b
 */
static void isis_snmp_update_worker_a(const struct isis_circuit *circuit,
				      oid trap_id, const oid *oid_a,
				      size_t oid_a_len, uint8_t type_a,
				      const void *data_a, size_t data_a_len,
				      const oid *oid_b, size_t oid_b_len,
				      uint8_t type_b, const void *data_b,
				      size_t data_b_len)
{
	netsnmp_variable_list *notification_vars = NULL;
	oid var_name[MAX_OID_LEN];
	size_t var_count;
	long val;

	/* Sanity */
	if (trap_id != ISIS_TRAP_ID_LEN_MISMATCH
	    && trap_id != ISIS_TRAP_MAX_AREA_ADDR_MISMATCH
	    && trap_id != ISIS_TRAP_OWN_LSP_PURGE
	    && trap_id != ISIS_TRAP_SEQNO_SKIPPED
	    && trap_id != ISIS_TRAP_AUTHEN_TYPE_FAILURE
	    && trap_id != ISIS_TRAP_AUTHEN_FAILURE
	    && trap_id != ISIS_TRAP_REJ_ADJACENCY)
		return;

	/* Put in trap value */
	memcpy(var_name, isis_snmp_notifications,
	       sizeof(isis_snmp_notifications));
	var_count = array_size(isis_snmp_notifications);
	var_name[var_count++] = trap_id;

	/* Put in trap value */
	snmp_varlist_add_variable(&notification_vars, isis_snmp_trap_var,
				  array_size(isis_snmp_trap_var), ASN_OBJECT_ID,
				  (uint8_t *)var_name, var_count * sizeof(oid));

	val = circuit->is_type;
	snmp_varlist_add_variable(
		&notification_vars, isis_snmp_trap_data_var_sys_level_index,
		array_size(isis_snmp_trap_data_var_sys_level_index), INTEGER,
		(uint8_t *)&val, sizeof(val));

	if (oid_a_len != 0) {
		if (oid_a == NULL || data_a == NULL || data_a_len == 0)
			return;

		snmp_varlist_add_variable(&notification_vars, oid_a, oid_a_len,
					  type_a, (uint8_t *)data_a,
					  data_a_len);
	}

	if (circuit->interface == NULL)
		val = 0;
	else
		val = circuit->interface->ifindex;

	snmp_varlist_add_variable(
		&notification_vars, isis_snmp_trap_data_var_circ_if_index,
		array_size(isis_snmp_trap_data_var_circ_if_index), UNSIGNED32,
		(uint8_t *)&val, sizeof(val));


	if (oid_b_len != 0) {
		if (oid_b == NULL || data_b == NULL || data_b_len == 0)
			return;

		snmp_varlist_add_variable(&notification_vars, oid_b, oid_b_len,
					  type_b, (uint8_t *)data_b,
					  data_b_len);
	}

	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
	smux_events_update();
}

/*
 * A common function to handle popular combination of trap objects
 * isisNotificationSysLevelIndex,
 * isisNotificationCircIfIndex,
 * optional-var-a
 * optional-var-b
 *
 * Note: the only difference with worker_a is order of circ-if-index vs
 * optional-var-a
 */
static void isis_snmp_update_worker_b(const struct isis_circuit *circuit,
				      oid trap_id, const oid *oid_a,
				      size_t oid_a_len, uint8_t type_a,
				      const void *data_a, size_t data_a_len,
				      const oid *oid_b, size_t oid_b_len,
				      uint8_t type_b, const void *data_b,
				      size_t data_b_len)
{
	netsnmp_variable_list *notification_vars = NULL;
	oid var_name[MAX_OID_LEN];
	size_t var_count;
	long val;

	/* Sanity */
	if (trap_id != ISIS_TRAP_VERSION_SKEW
	    && trap_id != ISIS_TRAP_LSP_TOO_LARGE
	    && trap_id != ISIS_TRAP_ADJ_STATE_CHANGE)
		return;

	/* Put in trap value */
	memcpy(var_name, isis_snmp_notifications,
	       sizeof(isis_snmp_notifications));
	var_count = array_size(isis_snmp_notifications);
	var_name[var_count++] = trap_id;

	/* Put in trap value */
	snmp_varlist_add_variable(&notification_vars, isis_snmp_trap_var,
				  array_size(isis_snmp_trap_var), ASN_OBJECT_ID,
				  (uint8_t *)var_name, var_count * sizeof(oid));

	val = circuit->is_type;
	snmp_varlist_add_variable(
		&notification_vars, isis_snmp_trap_data_var_sys_level_index,
		array_size(isis_snmp_trap_data_var_sys_level_index), INTEGER,
		(uint8_t *)&val, sizeof(val));

	if (circuit->interface == NULL)
		val = 0;
	else
		val = circuit->interface->ifindex;

	snmp_varlist_add_variable(
		&notification_vars, isis_snmp_trap_data_var_circ_if_index,
		array_size(isis_snmp_trap_data_var_circ_if_index), UNSIGNED32,
		(uint8_t *)&val, sizeof(val));


	if (oid_a_len != 0) {
		if (oid_a == NULL || data_a == NULL || data_a_len == 0)
			return;

		snmp_varlist_add_variable(&notification_vars, oid_a, oid_a_len,
					  type_a, (uint8_t *)data_a,
					  data_a_len);
	}

	if (oid_b_len != 0) {
		if (oid_b == NULL || data_b == NULL || data_b_len == 0)
			return;

		snmp_varlist_add_variable(&notification_vars, oid_b, oid_b_len,
					  type_b, (uint8_t *)data_b,
					  data_b_len);
	}

	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
	smux_events_update();
}


static int isis_snmp_id_len_mismatch_update(const struct isis_circuit *circuit,
					    uint8_t rcv_id, const char *raw_pdu,
					    size_t raw_pdu_len)
{
	long val;

	if (!isis_snmp_trap_throttle(ISIS_TRAP_ID_LEN_MISMATCH))
		return 0;

	val = rcv_id;

	if (raw_pdu_len > ISIS_SNMP_TRAP_PDU_FRAGMENT_MAX_LEN)
		raw_pdu_len = ISIS_SNMP_TRAP_PDU_FRAGMENT_MAX_LEN;

	isis_snmp_update_worker_a(
		circuit, ISIS_TRAP_ID_LEN_MISMATCH,
		isis_snmp_trap_data_var_pdu_field_len,
		array_size(isis_snmp_trap_data_var_pdu_field_len), UNSIGNED32,
		&val, sizeof(val), isis_snmp_trap_data_var_pdu_fragment,
		array_size(isis_snmp_trap_data_var_pdu_fragment), STRING,
		raw_pdu, raw_pdu_len);
	return 0;
}

static int
isis_snmp_max_area_addr_mismatch_update(const struct isis_circuit *circuit,
					uint8_t max_addrs, const char *raw_pdu,
					size_t raw_pdu_len)
{
	long val;

	if (!isis_snmp_trap_throttle(ISIS_TRAP_MAX_AREA_ADDR_MISMATCH))
		return 0;

	val = max_addrs;

	if (raw_pdu_len > ISIS_SNMP_TRAP_PDU_FRAGMENT_MAX_LEN)
		raw_pdu_len = ISIS_SNMP_TRAP_PDU_FRAGMENT_MAX_LEN;

	isis_snmp_update_worker_a(
		circuit, ISIS_TRAP_MAX_AREA_ADDR_MISMATCH,
		isis_snmp_trap_data_var_pdu_max_area_addr,
		array_size(isis_snmp_trap_data_var_pdu_max_area_addr),
		UNSIGNED32, &val, sizeof(val),
		isis_snmp_trap_data_var_pdu_fragment,
		array_size(isis_snmp_trap_data_var_pdu_fragment), STRING,
		raw_pdu, raw_pdu_len);
	return 0;
}

static int isis_snmp_own_lsp_purge_update(const struct isis_circuit *circuit,
					  const uint8_t *lsp_id)
{
	if (!isis_snmp_trap_throttle(ISIS_TRAP_OWN_LSP_PURGE))
		return 0;

	isis_snmp_update_worker_a(
		circuit, ISIS_TRAP_OWN_LSP_PURGE, NULL, 0, STRING, NULL, 0,
		isis_snmp_trap_data_var_pdu_lsp_id,
		array_size(isis_snmp_trap_data_var_pdu_lsp_id), STRING, lsp_id,
		ISIS_SYS_ID_LEN + 2);
	return 0;
}

static int isis_snmp_seqno_skipped_update(const struct isis_circuit *circuit,
					  const uint8_t *lsp_id)
{
	if (!isis_snmp_trap_throttle(ISIS_TRAP_SEQNO_SKIPPED))
		return 0;

	isis_snmp_update_worker_a(
		circuit, ISIS_TRAP_SEQNO_SKIPPED, NULL, 0, STRING, NULL, 0,
		isis_snmp_trap_data_var_pdu_lsp_id,
		array_size(isis_snmp_trap_data_var_pdu_lsp_id), STRING, lsp_id,
		ISIS_SYS_ID_LEN + 2);
	return 0;
}

static int
isis_snmp_authentication_type_failure_update(const struct isis_circuit *circuit,
					     const char *raw_pdu,
					     size_t raw_pdu_len)
{
	if (!isis_snmp_trap_throttle(ISIS_TRAP_AUTHEN_TYPE_FAILURE))
		return 0;

	if (raw_pdu_len > ISIS_SNMP_TRAP_PDU_FRAGMENT_MAX_LEN)
		raw_pdu_len = ISIS_SNMP_TRAP_PDU_FRAGMENT_MAX_LEN;

	isis_snmp_update_worker_a(
		circuit, ISIS_TRAP_AUTHEN_TYPE_FAILURE, NULL, 0, STRING, NULL,
		0, isis_snmp_trap_data_var_pdu_fragment,
		array_size(isis_snmp_trap_data_var_pdu_fragment), STRING,
		raw_pdu, raw_pdu_len);
	return 0;
}

static int
isis_snmp_authentication_failure_update(const struct isis_circuit *circuit,
					char const *raw_pdu, size_t raw_pdu_len)
{
	if (!isis_snmp_trap_throttle(ISIS_TRAP_AUTHEN_FAILURE))
		return 0;

	if (raw_pdu_len > ISIS_SNMP_TRAP_PDU_FRAGMENT_MAX_LEN)
		raw_pdu_len = ISIS_SNMP_TRAP_PDU_FRAGMENT_MAX_LEN;

	isis_snmp_update_worker_a(
		circuit, ISIS_TRAP_AUTHEN_FAILURE, NULL, 0, STRING, NULL, 0,
		isis_snmp_trap_data_var_pdu_fragment,
		array_size(isis_snmp_trap_data_var_pdu_fragment), STRING,
		raw_pdu, raw_pdu_len);
	return 0;
}

static int isis_snmp_version_skew_update(const struct isis_circuit *circuit,
					 uint8_t version, const char *raw_pdu,
					 size_t raw_pdu_len)
{
	long val;

	if (!isis_snmp_trap_throttle(ISIS_TRAP_VERSION_SKEW))
		return 0;

	val = version;

	if (raw_pdu_len > ISIS_SNMP_TRAP_PDU_FRAGMENT_MAX_LEN)
		raw_pdu_len = ISIS_SNMP_TRAP_PDU_FRAGMENT_MAX_LEN;

	isis_snmp_update_worker_b(
		circuit, ISIS_TRAP_VERSION_SKEW,
		isis_snmp_trap_data_var_pdu_proto_ver,
		array_size(isis_snmp_trap_data_var_pdu_proto_ver), UNSIGNED32,
		&val, sizeof(val), isis_snmp_trap_data_var_pdu_fragment,
		array_size(isis_snmp_trap_data_var_pdu_fragment), STRING,
		raw_pdu, raw_pdu_len);
	return 0;
}

static int isis_snmp_area_mismatch_update(const struct isis_circuit *circuit,
					  const char *raw_pdu,
					  size_t raw_pdu_len)
{
	/*
	 * This is a special case because
	 * it does not include isisNotificationSysLevelIndex
	 */
	netsnmp_variable_list *notification_vars;
	long val;

	if (!isis_snmp_trap_throttle(ISIS_TRAP_AREA_MISMATCH))
		return 0;

	notification_vars = NULL;

	/* Put in trap value */
	snmp_varlist_add_variable(&notification_vars, isis_snmp_trap_var,
				  array_size(isis_snmp_trap_var), ASN_OBJECT_ID,
				  (uint8_t *)&isis_snmp_trap_val_area_mismatch,
				  sizeof(isis_snmp_trap_val_area_mismatch));


	if (circuit->interface == NULL)
		val = 0;
	else
		val = circuit->interface->ifindex;

	snmp_varlist_add_variable(
		&notification_vars, isis_snmp_trap_data_var_circ_if_index,
		array_size(isis_snmp_trap_data_var_circ_if_index), UNSIGNED32,
		(uint8_t *)&val, sizeof(val));


	if (raw_pdu_len > ISIS_SNMP_TRAP_PDU_FRAGMENT_MAX_LEN)
		raw_pdu_len = ISIS_SNMP_TRAP_PDU_FRAGMENT_MAX_LEN;

	snmp_varlist_add_variable(
		&notification_vars, isis_snmp_trap_data_var_pdu_fragment,
		array_size(isis_snmp_trap_data_var_pdu_fragment), STRING,
		raw_pdu, raw_pdu_len);

	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
	smux_events_update();

	return 0;
}

static int isis_snmp_reject_adjacency_update(const struct isis_circuit *circuit,
					     const char *raw_pdu,
					     size_t raw_pdu_len)
{
	if (!isis_snmp_trap_throttle(ISIS_TRAP_REJ_ADJACENCY))
		return 0;

	if (raw_pdu_len > ISIS_SNMP_TRAP_PDU_FRAGMENT_MAX_LEN)
		raw_pdu_len = ISIS_SNMP_TRAP_PDU_FRAGMENT_MAX_LEN;

	isis_snmp_update_worker_a(
		circuit, ISIS_TRAP_REJ_ADJACENCY, NULL, 0, STRING, NULL, 0,
		isis_snmp_trap_data_var_pdu_fragment,
		array_size(isis_snmp_trap_data_var_pdu_fragment), STRING,
		raw_pdu, raw_pdu_len);
	return 0;
}

static int isis_snmp_lsp_too_large_update(const struct isis_circuit *circuit,
					  uint32_t pdu_size,
					  const uint8_t *lsp_id)
{
	if (!isis_snmp_trap_throttle(ISIS_TRAP_LSP_TOO_LARGE))
		return 0;

	isis_snmp_update_worker_b(
		circuit, ISIS_TRAP_LSP_TOO_LARGE,
		isis_snmp_trap_data_var_pdu_lsp_size,
		array_size(isis_snmp_trap_data_var_pdu_lsp_size), UNSIGNED32,
		&pdu_size, sizeof(pdu_size), isis_snmp_trap_data_var_pdu_lsp_id,
		array_size(isis_snmp_trap_data_var_pdu_lsp_id), STRING, lsp_id,
		ISIS_SYS_ID_LEN + 2);
	return 0;
}


static int isis_snmp_adj_state_change_update(const struct isis_adjacency *adj)
{
	uint8_t lsp_id[ISIS_SYS_ID_LEN + 2];
	long val;
	struct isis *isis = isis_lookup_by_vrfid(VRF_DEFAULT);

	if (isis == NULL || !isis->snmp_notifications || !smux_enabled())
		return 0;

	/* Prepare data */
	memcpy(lsp_id, adj->sysid, ISIS_SYS_ID_LEN);
	lsp_id[ISIS_SYS_ID_LEN] = 0;
	lsp_id[ISIS_SYS_ID_LEN + 1] = 0;

	val = isis_snmp_adj_state(adj->adj_state);

	isis_snmp_update_worker_b(
		adj->circuit, ISIS_TRAP_ADJ_STATE_CHANGE,
		isis_snmp_trap_data_var_pdu_lsp_id,
		array_size(isis_snmp_trap_data_var_pdu_lsp_id), STRING, lsp_id,
		ISIS_SYS_ID_LEN + 2, isis_snmp_trap_data_var_adj_state,
		array_size(isis_snmp_trap_data_var_adj_state), INTEGER, &val,
		sizeof(val));
	return 0;
}

static int isis_snmp_lsp_error_update(const struct isis_circuit *circuit,
				      const uint8_t *lsp_id,
				      char const *raw_pdu, size_t raw_pdu_len)
{
	/*
	 * This is a special case because
	 * it have more variables
	 */
	netsnmp_variable_list *notification_vars;
	long val;

	if (!isis_snmp_trap_throttle(ISIS_TRAP_LSP_ERROR))
		return 0;

	notification_vars = NULL;

	/* Put in trap value */
	snmp_varlist_add_variable(&notification_vars, isis_snmp_trap_var,
				  array_size(isis_snmp_trap_var), ASN_OBJECT_ID,
				  (uint8_t *)&isis_snmp_trap_val_lsp_error,
				  sizeof(isis_snmp_trap_val_lsp_error));

	/* Prepare data */
	val = circuit->is_type;

	snmp_varlist_add_variable(
		&notification_vars, isis_snmp_trap_data_var_sys_level_index,
		array_size(isis_snmp_trap_data_var_sys_level_index), INTEGER,
		(uint8_t *)&val, sizeof(val));


	snmp_varlist_add_variable(
		&notification_vars, isis_snmp_trap_data_var_pdu_lsp_id,
		array_size(isis_snmp_trap_data_var_pdu_lsp_id), STRING, lsp_id,
		ISIS_SYS_ID_LEN + 2);

	/* Prepare data */
	if (circuit->interface == NULL)
		val = 0;
	else
		val = circuit->interface->ifindex;

	snmp_varlist_add_variable(
		&notification_vars, isis_snmp_trap_data_var_circ_if_index,
		array_size(isis_snmp_trap_data_var_circ_if_index), UNSIGNED32,
		(uint8_t *)&val, sizeof(val));

	/* Prepare data */
	if (raw_pdu_len > ISIS_SNMP_TRAP_PDU_FRAGMENT_MAX_LEN)
		raw_pdu_len = ISIS_SNMP_TRAP_PDU_FRAGMENT_MAX_LEN;

	snmp_varlist_add_variable(
		&notification_vars, isis_snmp_trap_data_var_pdu_fragment,
		array_size(isis_snmp_trap_data_var_pdu_fragment), STRING,
		raw_pdu, raw_pdu_len);

	/* Prepare data */
	val = 0;

	snmp_varlist_add_variable(
		&notification_vars, isis_snmp_trap_data_var_error_offset,
		array_size(isis_snmp_trap_data_var_error_offset), UNSIGNED32,
		(uint8_t *)&val, sizeof(val));

	/* Prepare data */
	val = 0;

	snmp_varlist_add_variable(
		&notification_vars, isis_snmp_trap_data_var_error_tlv_type,
		array_size(isis_snmp_trap_data_var_error_tlv_type), UNSIGNED32,
		(uint8_t *)&val, sizeof(val));

	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
	smux_events_update();
	return 0;
}


static int isis_snmp_module_init(void)
{
	hook_register(isis_hook_db_overload, isis_snmp_db_overload_update);
	hook_register(isis_hook_lsp_exceed_max,
		      isis_snmp_lsp_exceed_max_update);
	hook_register(isis_hook_id_len_mismatch,
		      isis_snmp_id_len_mismatch_update);
	hook_register(isis_hook_max_area_addr_mismatch,
		      isis_snmp_max_area_addr_mismatch_update);
	hook_register(isis_hook_own_lsp_purge, isis_snmp_own_lsp_purge_update);
	hook_register(isis_hook_seqno_skipped, isis_snmp_seqno_skipped_update);
	hook_register(isis_hook_authentication_type_failure,
		      isis_snmp_authentication_type_failure_update);
	hook_register(isis_hook_authentication_failure,
		      isis_snmp_authentication_failure_update);
	hook_register(isis_hook_version_skew, isis_snmp_version_skew_update);
	hook_register(isis_hook_area_mismatch, isis_snmp_area_mismatch_update);
	hook_register(isis_hook_reject_adjacency,
		      isis_snmp_reject_adjacency_update);
	hook_register(isis_hook_lsp_too_large, isis_snmp_lsp_too_large_update);
	hook_register(isis_hook_adj_state_change,
		      isis_snmp_adj_state_change_update);
	hook_register(isis_hook_lsp_error, isis_snmp_lsp_error_update);
	hook_register(isis_circuit_new_hook, isis_circuit_snmp_id_gen);
	hook_register(isis_circuit_del_hook, isis_circuit_snmp_id_free);

	hook_register(frr_late_init, isis_snmp_init);
	hook_register(frr_fini, isis_snmp_terminate);
	return 0;
}

FRR_MODULE_SETUP(
	.name = "isis_snmp",
	.version = FRR_VERSION,
	.description = "isis AgentX SNMP module",
	.init = isis_snmp_module_init,
);
