/*
 * IS-IS Rout(e)ing protocol - isis_tlv.h
 *                             IS-IS TLV related routines
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _ZEBRA_ISIS_TLV_H
#define _ZEBRA_ISIS_TLV_H

/*
 * Structures found in TLV's.
 * this header is fully complient with
 * RFC 3359
 1.  TLV Codepoints reserved
     ____________________________________________________
     Name                 Value   IIH   LSP  SNP   Status
     ____________________________________________________

     Area Addresses            1  y     y    n  ISO 10589
     IIS Neighbors             2  n     y    n  ISO 10589
     ES Neighbors              3  n     y    n  ISO 10589
     Part. DIS                 4  n     y    n  ISO 10589
     Prefix Neighbors          5  n     y    n  ISO 10589
     IIS Neighbors             6  y     n    n  ISO 10589
     Padding                   8  y     n    n  ISO 10589
     LSP Entries               9  n     n    y  ISO 10589
     Authentication           10  y     y    y  ISO 10589
     Opt. Checksum            12  y     n    y  RFC 3358
     LSPBufferSize            14  n     y    n  ISO 10589 Rev 2 Draft
     TE IIS Neigh.            22  n     y    n  RFC 3784
     IS Alias ID              24  n     y    n  RFC 3786
     DECnet Phase IV          42  y     n    n  DEC (ancient)
     Lucent Proprietary       66  n     y    n
     IP Int. Reach           128  n     y    n  RFC 1195
     Prot. Supported         129  y     y    n  RFC 1195
     IP Ext. Address         130  n     y    n  RFC 1195
     IDRPI                   131  n     y    y  RFC 1195
     IP Intf. Address        132  y     y    n  RFC 1195
     Illegal                 133  n     n    n  RFC 1195 (not used)
     Router ID               134  n     y    n  RFC 3784
     TE IP. Reach            135  n     y    n  RFC 3784
     Dynamic Name            137  n     y    n  RFC 2763
     Nortel Proprietary      176  n     y    n
     Nortel Proprietary      177  n     y    n
     Restart TLV             211  y     n    n  RFC 3847
     MT-ISN                  222  n     y    n  IETF-draft
     M-Topologies            229  y     y    n  IETF-draft
     IPv6 Intf. Addr.        232  y     y    n  IETF-draft
     MT IP. Reach            235  n     y    n  IETF-draft
     IPv6 IP. Reach          236  n     y    n  IETF-draft
     MT IPv6 IP. Reach       237  n     y    n  IETF-draft
     P2P Adjacency State     240  y     n    n  RFC 3373

 */

#define AREA_ADDRESSES            1
#define IS_NEIGHBOURS             2
#define ES_NEIGHBOURS             3
#define PARTITION_DESIG_LEVEL2_IS 4
#define PREFIX_NEIGHBOURS         5
#define LAN_NEIGHBOURS            6
#define PADDING                   8
#define LSP_ENTRIES               9
#define AUTH_INFO                 10
#define CHECKSUM                  12
#define TE_IS_NEIGHBOURS          22
#define IPV4_INT_REACHABILITY     128
#define IPV4_EXT_REACHABILITY     130
#define PROTOCOLS_SUPPORTED       129
#define IDRP_INFO                 131
#define IPV4_ADDR                 132
#define TE_ROUTER_ID              134
#define TE_IPV4_REACHABILITY      135
#define DYNAMIC_HOSTNAME          137
#define GRACEFUL_RESTART          211
#define IPV6_REACHABILITY         236
#define IPV6_ADDR                 232
#define WAY3_HELLO                240

#define IS_NEIGHBOURS_LEN (ISIS_SYS_ID_LEN + 5)
#define LAN_NEIGHBOURS_LEN 6
#define LSP_ENTRIES_LEN (10 + ISIS_SYS_ID_LEN)	/* FIXME: should be entry */
#define IPV4_REACH_LEN 12
#define IPV6_REACH_LEN 22

/* struct for neighbor */
struct is_neigh
{
  struct metric metrics;
  u_char neigh_id[ISIS_SYS_ID_LEN + 1];
};

/* struct for te is neighbor */
struct te_is_neigh
{
  u_char neigh_id[ISIS_SYS_ID_LEN + 1];
  u_char te_metric[3];
  u_char sub_tlvs_length;
};

/* struct for es neighbors */
struct es_neigh
{
  struct metric metrics;
  /* approximate position of first, we use the
   * length ((uchar*)metric-1) to know all     */
  u_char first_es_neigh[ISIS_SYS_ID_LEN];

};

struct partition_desig_level2_is
{
  struct list *isis_system_ids;
};

/* struct for lan neighbors */
struct lan_neigh
{
  u_char LAN_addr[6];
};

/* struct for LSP entry */
struct lsp_entry
{
  u_int16_t rem_lifetime;
  u_char lsp_id[ISIS_SYS_ID_LEN + 2];
  u_int32_t seq_num;
  u_int16_t checksum;
} __attribute__ ((packed));

/* struct for checksum */
struct checksum
{
  u_int16_t checksum;
};

/* ipv4 reachability */
struct ipv4_reachability
{
  struct metric metrics;
  struct in_addr prefix;
  struct in_addr mask;
};

/* te router id */
struct te_router_id
{
  struct in_addr id;
};

/* te ipv4 reachability */
struct te_ipv4_reachability
{
  u_int32_t te_metric;
  u_char control;
  u_char prefix_start;		/* since this is variable length by nature it only */
};				/* points to an approximate location */



struct idrp_info
{
  u_char len;
  u_char *value;
};

#ifdef HAVE_IPV6
struct ipv6_reachability
{
  u_int32_t metric;
  u_char control_info;
  u_char prefix_len;
  u_char prefix[16];
};
#endif /* HAVE_IPV6 */

/* bits in control_info */
#define CTRL_INFO_DIRECTION    0x80
#define DIRECTION_UP           0
#define DIRECTION_DOWN         1
#define CTRL_INFO_DISTRIBUTION 0x40
#define DISTRIBUTION_INTERNAL  0
#define DISTRIBUTION_EXTERNAL  1
#define CTRL_INFO_SUBTLVS      0x20

/*
 * Pointer to each tlv type, filled by parse_tlvs()
 */
struct tlvs
{
  struct list *area_addrs;
  struct list *is_neighs;
  struct list *te_is_neighs;
  struct list *es_neighs;
  struct list *lsp_entries;
  struct list *prefix_neighs;
  struct list *lan_neighs;
  struct checksum *checksum;
  struct nlpids *nlpids;
  struct list *ipv4_addrs;
  struct list *ipv4_int_reachs;
  struct list *ipv4_ext_reachs;
  struct list *te_ipv4_reachs;
  struct hostname *hostname;
  struct te_router_id *router_id;
#ifdef HAVE_IPV6
  struct list *ipv6_addrs;
  struct list *ipv6_reachs;
#endif
  struct isis_passwd auth_info;
};

/*
 * Own definitions - used to bitmask found and expected
 */

#define TLVFLAG_AREA_ADDRS                (1<<0)
#define TLVFLAG_IS_NEIGHS                 (1<<1)
#define TLVFLAG_ES_NEIGHS                 (1<<2)
#define TLVFLAG_PARTITION_DESIG_LEVEL2_IS (1<<3)
#define TLVFLAG_PREFIX_NEIGHS             (1<<4)
#define TLVFLAG_LAN_NEIGHS                (1<<5)
#define TLVFLAG_LSP_ENTRIES               (1<<6)
#define TLVFLAG_PADDING                   (1<<7)
#define TLVFLAG_AUTH_INFO                 (1<<8)
#define TLVFLAG_IPV4_INT_REACHABILITY     (1<<9)
#define TLVFLAG_NLPID                     (1<<10)
#define TLVFLAG_IPV4_EXT_REACHABILITY     (1<<11)
#define TLVFLAG_IPV4_ADDR                 (1<<12)
#define TLVFLAG_DYN_HOSTNAME              (1<<13)
#define TLVFLAG_IPV6_ADDR                 (1<<14)
#define TLVFLAG_IPV6_REACHABILITY         (1<<15)
#define TLVFLAG_TE_IS_NEIGHS              (1<<16)
#define TLVFLAG_TE_IPV4_REACHABILITY      (1<<17)
#define TLVFLAG_3WAY_HELLO                (1<<18)
#define TLVFLAG_TE_ROUTER_ID              (1<<19)
#define TLVFLAG_CHECKSUM                  (1<<20)
#define TLVFLAG_GRACEFUL_RESTART          (1<<21)

void init_tlvs (struct tlvs *tlvs, uint32_t expected);
void free_tlvs (struct tlvs *tlvs);
int parse_tlvs (char *areatag, u_char * stream, int size,
		u_int32_t * expected, u_int32_t * found, struct tlvs *tlvs);
void free_tlv (void *val);

int add_tlv (u_char, u_char, u_char *, struct stream *);
int tlv_add_area_addrs (struct list *area_addrs, struct stream *stream);
int tlv_add_is_neighs (struct list *is_neighs, struct stream *stream);
int tlv_add_lan_neighs (struct list *lan_neighs, struct stream *stream);
int tlv_add_nlpid (struct nlpids *nlpids, struct stream *stream);
int tlv_add_checksum (struct checksum *checksum, struct stream *stream);
int tlv_add_authinfo (char auth_type, char authlen, u_char *auth_value,
		      struct stream *stream);
int tlv_add_ip_addrs (struct list *ip_addrs, struct stream *stream);
int tlv_add_dynamic_hostname (struct hostname *hostname,
			      struct stream *stream);
int tlv_add_lsp_entries (struct list *lsps, struct stream *stream);
int tlv_add_ipv4_reachs (struct list *ipv4_reachs, struct stream *stream);
#ifdef HAVE_IPV6
int tlv_add_ipv6_addrs (struct list *ipv6_addrs, struct stream *stream);
int tlv_add_ipv6_reachs (struct list *ipv6_reachs, struct stream *stream);
#endif /* HAVE_IPV6 */

int tlv_add_padding (struct stream *stream);

#endif /* _ZEBRA_ISIS_TLV_H */
