// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2026, Donatas Abraitis <donatas@opensourcerouting.org>
 *
 * BGP RPKI - rtrlib API compatibility
 *
 * rtrlib gained ASPA support and, in the same unreleased window, prefixed its
 * entire public API with "rtr_" (upstream commit f3d1cfa, "rtrlib: Make API
 * consistent"). There are no compatibility aliases upstream, and rtrlib did
 * not bump its version for either change, so configure detects the new API by
 * probing for ASPA support.
 */
#ifndef __BGP_RPKI_COMPAT_H__
#define __BGP_RPKI_COMPAT_H__

#ifndef FOUND_ASPA

#define rtr_pfx_record			   pfx_record
#define rtr_pfx_table			   pfx_table
#define rtr_pfx_rtvals			   pfx_rtvals
#define rtr_pfx_update_fp		   pfx_update_fp
#define RTR_PFX_SUCCESS			   PFX_SUCCESS
#define rtr_pfxv_state			   pfxv_state
#define RTR_BGP_PFXV_STATE_VALID	   BGP_PFXV_STATE_VALID
#define RTR_BGP_PFXV_STATE_NOT_FOUND	   BGP_PFXV_STATE_NOT_FOUND
#define RTR_BGP_PFXV_STATE_INVALID	   BGP_PFXV_STATE_INVALID
#define rtr_pfx_table_validate_r	   pfx_table_validate_r
#define rtr_pfx_table_for_each_ipv4_record pfx_table_for_each_ipv4_record
#define rtr_pfx_table_for_each_ipv6_record pfx_table_for_each_ipv6_record
#define rtr_mgr_roa_validate		   rtr_mgr_validate

#define rtr_ip_addr		lrtr_ip_addr
#define RTR_IPV4		LRTR_IPV4
#define RTR_IPV6		LRTR_IPV6
#define rtr_ip_addr_to_str	lrtr_ip_addr_to_str
#define rtr_ip_str_to_addr	lrtr_ip_str_to_addr
#define rtr_set_alloc_functions lrtr_set_alloc_functions

#define rtr_tr_socket	  tr_socket
#define rtr_tr_tcp_config tr_tcp_config
#define rtr_tr_ssh_config tr_ssh_config
#define rtr_tr_tcp_init	  tr_tcp_init
#define rtr_tr_ssh_init	  tr_ssh_init

/*
 * The ROA update callback's last parameter changed from a plain "added"
 * boolean to an operation-type enum.  bgpd ignores it either way, but the
 * function pointer type still has to match.
 */
#define RPKI_PFX_UPDATE_OP_T const bool

#else /* FOUND_ASPA */

#define RPKI_PFX_UPDATE_OP_T const enum rtr_pfx_operation_type

#endif /* !FOUND_ASPA */

#endif /* __BGP_RPKI_COMPAT_H__ */
