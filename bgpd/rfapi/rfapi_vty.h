/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef RFAPI_VTY_H
#define RFAPI_VTY_H

#include "lib/vty.h"

typedef enum {
	SHOW_NVE_SUMMARY_ACTIVE_NVES,
	SHOW_NVE_SUMMARY_UNKNOWN_NVES, /* legacy */
	SHOW_NVE_SUMMARY_REGISTERED,
	SHOW_NVE_SUMMARY_QUERIES,
	SHOW_NVE_SUMMARY_RESPONSES,
	SHOW_NVE_SUMMARY_MAX
} show_nve_summary_t;

#define VNC_SHOW_STR "VNC information\n"

extern char *rfapiFormatSeconds(uint32_t seconds, char *buf, size_t len);

extern char *rfapiFormatAge(time_t age, char *buf, size_t len);

extern void rfapiRprefixApplyMask(struct rfapi_ip_prefix *rprefix);

extern int rfapiQprefix2Raddr(struct prefix *qprefix,
			      struct rfapi_ip_addr *raddr);

extern void rfapiQprefix2Rprefix(struct prefix *qprefix,
				 struct rfapi_ip_prefix *rprefix);

extern int rfapiRprefix2Qprefix(struct rfapi_ip_prefix *rprefix,
				struct prefix *qprefix);

extern int rfapiRaddr2Qprefix(struct rfapi_ip_addr *hia, struct prefix *pfx);

extern int rfapiRprefixSame(struct rfapi_ip_prefix *hp1,
			    struct rfapi_ip_prefix *hp2);

extern void rfapiL2o2Qprefix(struct rfapi_l2address_option *l2o,
			     struct prefix *pfx);

extern int rfapiStr2EthAddr(const char *str, struct ethaddr *ea);

extern const char *rfapi_ntop(int af, const void *src, char *buf,
			      socklen_t size);

extern int rfapiDebugPrintf(void *dummy, const char *format, ...);

extern int rfapiStream2Vty(void *stream,			  /* input */
			   int (**fp)(void *, const char *, ...), /* output */
			   struct vty **vty,			  /* output */
			   void **outstream,			  /* output */
			   const char **vty_newline);		  /* output */

/*------------------------------------------
 * rfapiRfapiIpAddr2Str
 *
 * UI helper: generate string from rfapi_ip_addr
 *
 * input:
 *	a			IP v4/v6 address
 *
 * output
 *	buf			put string here
 *	bufsize			max space to write
 *
 * return value:
 *	NULL			conversion failed
 *	non-NULL		pointer to buf
 --------------------------------------------*/
extern const char *rfapiRfapiIpAddr2Str(struct rfapi_ip_addr *a, char *buf,
					int bufsize);

extern void rfapiPrintRfapiIpAddr(void *stream, struct rfapi_ip_addr *a);

extern void rfapiPrintRfapiIpPrefix(void *stream, struct rfapi_ip_prefix *p);

void rfapiPrintRd(struct vty *vty, struct prefix_rd *prd);

extern void rfapiPrintAdvertisedInfo(struct vty *vty,
				     struct rfapi_descriptor *rfd, safi_t safi,
				     struct prefix *p);

extern void rfapiPrintDescriptor(struct vty *vty, struct rfapi_descriptor *rfd);

extern void rfapiPrintMatchingDescriptors(struct vty *vty,
					  struct prefix *vn_prefix,
					  struct prefix *un_prefix);

extern void rfapiPrintAttrPtrs(void *stream, struct attr *attr);

/*
 * Parse an address and put into a struct prefix
 */
extern int rfapiCliGetPrefixAddr(struct vty *vty, const char *str,
				 struct prefix *p);

extern int rfapiCliGetRfapiIpAddr(struct vty *vty, const char *str,
				  struct rfapi_ip_addr *hai);

extern void rfapiPrintNhl(void *stream, struct rfapi_next_hop_entry *next_hops);

extern char *rfapiMonitorVpn2Str(struct rfapi_monitor_vpn *m, char *buf,
				 int size);

extern const char *rfapiRfapiIpPrefix2Str(struct rfapi_ip_prefix *p, char *buf,
					  int bufsize);

extern void rfapiShowItNode(void *stream, struct route_node *rn);

extern char *rfapiEthAddr2Str(const struct ethaddr *ea, char *buf, int bufsize);

/* install vty commands */
extern void rfapi_vty_init(void);

/*------------------------------------------
 * rfapiShowRemoteRegistrations
 *
 * UI helper: produces the "remote" portion of the output
 * of "show vnc registrations".
 *
 * input:
 *	stream		pointer to output stream
 *	prefix_only	pointer to prefix. If non-NULL, print only registrations
 *			matching the specified prefix
 *	show_expiring	if non-zero, show expiring registrations
 *	show_local	if non-zero, show local registrations
 *	show_imported	if non-zero, show imported registrations
 *
 * return value:
 *	0		nothing printed
 *	>0		something printed
 --------------------------------------------*/
extern int rfapiShowRemoteRegistrations(void *stream,
					struct prefix *prefix_only,
					int show_expiring, int show_local,
					int show_remote, int show_imported);

/*------------------------------------------
 * rfapi_monitor_count
 *
 * UI helper: count number of active monitors
 *
 * input:
 *	handle			rfapi handle (NULL to count across
 *				all open handles)
 *
 * output
 *
 * return value:
 *	count of monitors
 --------------------------------------------*/
extern uint32_t rfapi_monitor_count(rfapi_handle);

extern int rfapiShowVncQueries(void *stream, struct prefix *pfx_match);


#endif
