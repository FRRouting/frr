// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2015-2016, LabN Consulting, L.L.C.
 */

#ifndef _QUAGGA_BGP_RFAPI_ENCAP_TLV_H
#define _QUAGGA_BGP_RFAPI_ENCAP_TLV_H

#define RFAPI_BGP_ENCAP_TYPE_DEFAULT BGP_ENCAP_TYPE_IP_IN_IP

extern bgp_encap_types
rfapi_tunneltype_option_to_tlv(struct bgp *bgp, struct rfapi_ip_addr *ea,
			       struct rfapi_tunneltype_option *tto,
			       struct attr *attr, int always_add);

extern struct rfapi_un_option *rfapi_encap_tlv_to_un_option(struct attr *attr);

extern void rfapi_print_tunneltype_option(void *stream, int column_offset,
					  struct rfapi_tunneltype_option *tto);


#endif /* _QUAGGA_BGP_RFAPI_ENCAP_TLV_H */
