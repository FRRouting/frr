/* SNMP support
 * Copyright (C) 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_SNMP_H
#define _ZEBRA_SNMP_H

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_vars.h>

#include "thread.h"
#include "hook.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Structures here are mostly compatible with UCD SNMP 4.1.1 */
#define MATCH_FAILED     (-1)
#define MATCH_SUCCEEDED  0

/* SYNTAX TruthValue from SNMPv2-TC. */
#define SNMP_TRUE  1
#define SNMP_FALSE 2

/* SYNTAX RowStatus from SNMPv2-TC. */
#define SNMP_VALID  1
#define SNMP_INVALID 2

#define IN_ADDR_SIZE sizeof(struct in_addr)

/* IANAipRouteProtocol */
#define IANAIPROUTEPROTOCOLOTHER 1
#define IANAIPROUTEPROTOCOLLOCAL 2
#define IANAIPROUTEPROTOCOLNETMGMT 3
#define IANAIPROUTEPROTOCOLICMP 4
#define IANAIPROUTEPROTOCOLEGP 5
#define IANAIPROUTEPROTOCOLGGP 6
#define IANAIPROUTEPROTOCOLHELLO 7
#define IANAIPROUTEPROTOCOLRIP 8
#define IANAIPROUTEPROTOCOLISIS 9
#define IANAIPROUTEPROTOCOLESIS 10
#define IANAIPROUTEPROTOCOLCISCOIGRP 11
#define IANAIPROUTEPROTOCOLBBNSPFIGP 12
#define IANAIPROUTEPROTOCOLOSPF 13
#define IANAIPROUTEPROTOCOLBGP 14
#define IANAIPROUTEPROTOCOLIDPR 15
#define IANAIPROUTEPROTOCOLCISCOEIGRP 16
#define IANAIPROUTEPROTOCOLDVMRP 17

#define INETADDRESSTYPEUNKNOWN 0
#define INETADDRESSTYPEIPV4 1
#define INETADDRESSTYPEIPV6 2

#undef REGISTER_MIB
#define REGISTER_MIB(descr, var, vartype, theoid)                              \
	smux_register_mib(descr, (struct variable *)var,                       \
			  sizeof(struct vartype),                              \
			  sizeof(var) / sizeof(struct vartype), theoid,        \
			  sizeof(theoid) / sizeof(oid))

struct trap_object {
	int namelen; /* Negative if the object is not indexed */
	oid name[MAX_OID_LEN];
};

struct index_oid {
	int indexlen;
	oid indexname[MAX_OID_LEN];
};
/* Declare SMUX return value. */
#define SNMP_LOCAL_VARIABLES                                                   \
	static long snmp_int_val __attribute__((unused));                      \
	static struct in_addr snmp_in_addr_val __attribute__((unused));
	static uint8_t snmp_octet_val __attribute__((unused));
#define SNMP_INTEGER(V)                                                        \
	(*var_len = sizeof(snmp_int_val), snmp_int_val = V,                    \
	 (uint8_t *)&snmp_int_val)

#define SNMP_OCTET(V)							\
	(*var_len = sizeof(snmp_octet_val), snmp_octet_val = V,                    \
	 (uint8_t *)&snmp_octet_val)

#define SNMP_IPADDRESS(V)                                                      \
	(*var_len = sizeof(struct in_addr), snmp_in_addr_val = V,              \
	 (uint8_t *)&snmp_in_addr_val)

#define SNMP_IP6ADDRESS(V) (*var_len = sizeof(struct in6_addr), (uint8_t *)&V)

extern int smux_enabled(void);

extern void smux_init(struct thread_master *tm);
extern void smux_agentx_enable(void);
extern void smux_register_mib(const char *, struct variable *, size_t, int,
			      oid[], size_t);
extern int smux_header_generic(struct variable *, oid[], size_t *, int,
			       size_t *, WriteMethod **);
extern int smux_header_table(struct variable *, oid *, size_t *, int, size_t *,
			     WriteMethod **);

/* For traps, three OID are provided:

 1. The enterprise OID to use (the last argument will be appended to
    it to form the SNMP trap OID)

 2. The base OID for objects to be sent in traps.

 3. The index OID for objects to be sent in traps. This index is used
    to designate a particular instance of a column.

 The provided trap object contains the bindings to be sent with the
 trap. The base OID will be prefixed to the provided OID and, if the
 length is positive, the requested OID is assumed to be a columnar
 object and the index OID will be appended.

 The two first arguments are the MIB registry used to locate the trap
 objects.

 The use of the arguments may differ depending on the implementation
 used.
*/
extern void smux_trap(struct variable *, size_t, const oid *, size_t,
		      const oid *, size_t, const oid *, size_t,
		      const struct trap_object *, size_t, uint8_t);

extern int smux_trap_multi_index(struct variable *vp, size_t vp_len,
				 const oid *ename, size_t enamelen,
				 const oid *name, size_t namelen,
				 struct index_oid *iname, size_t index_len,
				 const struct trap_object *trapobj,
				 size_t trapobjlen, uint8_t sptrap);

extern void smux_events_update(void);
extern int oid_compare(const oid *, int, const oid *, int);
extern void oid2in_addr(oid[], int, struct in_addr *);
extern void oid2in6_addr(oid oid[], struct in6_addr *addr);
extern void oid2int(oid oid[], int *dest);
extern void *oid_copy(void *, const void *, size_t);
extern void oid_copy_in_addr(oid[], const struct in_addr *);
extern void oid_copy_in6_addr(oid[], const struct in6_addr *);
extern void oid_copy_int(oid oid[], int *val);
extern void oid2string(oid oid[], int len, char *string);
extern void oid_copy_str(oid oid[], const char *string, int len);

DECLARE_HOOK(agentx_enabled, (), ());

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_SNMP_H */
