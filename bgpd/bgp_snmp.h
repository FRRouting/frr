// SPDX-License-Identifier: GPL-2.0-or-later
/* Common header file for BGP SNMP implementation.
 *
 * Copyright (C) 2022 Donatas Abraitis <donatas@opensourcerouting.org>
 */

#ifndef _FRR_BGP_SNMP_H_
#define _FRR_BGP_SNMP_H_

/* SNMP value hack. */
#define INTEGER ASN_INTEGER
#define INTEGER32 ASN_INTEGER
#define COUNTER32 ASN_COUNTER
#define OCTET_STRING ASN_OCTET_STR
#define IPADDRESS ASN_IPADDRESS
#define GAUGE32 ASN_UNSIGNED

<<<<<<< HEAD
=======
extern int bgpTrapEstablished(struct peer *peer);
extern int bgpTrapBackwardTransition(struct peer *peer);

>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
#endif /* _FRR_BGP_SNMP_H_ */
