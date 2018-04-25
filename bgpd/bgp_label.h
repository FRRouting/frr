/* BGP carrying Label information
 * Copyright (C) 2013 Cumulus Networks, Inc.
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

#ifndef _BGP_LABEL_H
#define _BGP_LABEL_H

#define BGP_LABEL_BYTES 3
#define BGP_LABEL_BITS 24
#define BGP_WITHDRAW_LABEL 0x800000
#define BGP_PREVENT_VRF_2_VRF_LEAK 0xFFFFFFFE

struct bgp_node;
struct bgp_info;
struct peer;

extern void bgp_reg_dereg_for_label(struct bgp_node *rn, struct bgp_info *ri,
				    int reg);
extern int bgp_parse_fec_update(void);
extern mpls_label_t bgp_adv_label(struct bgp_node *rn, struct bgp_info *ri,
				  struct peer *to, afi_t afi, safi_t safi);

extern int bgp_nlri_parse_label(struct peer *peer, struct attr *attr,
				struct bgp_nlri *packet);

static inline int bgp_labeled_safi(safi_t safi)
{
	/* NOTE: This API really says a label (tag) MAY be present. Not all EVPN
	 * routes will have a label.
	 */
	if ((safi == SAFI_LABELED_UNICAST) || (safi == SAFI_MPLS_VPN)
	    || (safi == SAFI_EVPN))
		return 1;
	return 0;
}

static inline int bgp_is_withdraw_label(mpls_label_t *label)
{
	uint8_t *pkt = (uint8_t *)label;

	/* The check on pkt[2] for 0x00 or 0x02 is in case bgp_set_valid_label()
	 * was called on the withdraw label */
	if ((pkt[0] == 0x80) && (pkt[1] == 0x00)
	    && ((pkt[2] == 0x00) || (pkt[2] == 0x02)))
		return 1;
	return 0;
}

static inline int bgp_is_valid_label(mpls_label_t *label)
{
	uint8_t *t = (uint8_t *)label;
	if (!t)
		return 0;
	return (t[2] & 0x02);
}

static inline void bgp_set_valid_label(mpls_label_t *label)
{
	uint8_t *t = (uint8_t *)label;
	if (t)
		t[2] |= 0x02;
}

static inline void bgp_unset_valid_label(mpls_label_t *label)
{
	uint8_t *t = (uint8_t *)label;
	if (t)
		t[2] &= ~0x02;
}

static inline void bgp_register_for_label(struct bgp_node *rn,
					  struct bgp_info *ri)
{
	bgp_reg_dereg_for_label(rn, ri, 1);
}

static inline void bgp_unregister_for_label(struct bgp_node *rn)
{
	bgp_reg_dereg_for_label(rn, NULL, 0);
}

/* Label stream to value */
static inline uint32_t label_pton(mpls_label_t *label)
{
	uint8_t *t = (uint8_t *)label;
	return ((((unsigned int)t[0]) << 12) | (((unsigned int)t[1]) << 4)
		| ((unsigned int)((t[2] & 0xF0) >> 4)));
}

/* Encode label values */
static inline void label_ntop(uint32_t l, int bos, mpls_label_t *label)
{
	uint8_t *t = (uint8_t *)label;
	t[0] = ((l & 0x000FF000) >> 12);
	t[1] = ((l & 0x00000FF0) >> 4);
	t[2] = ((l & 0x0000000F) << 4);
	if (bos)
		t[2] |= 0x01;
}

/* Return BOS value of label stream */
static inline uint8_t label_bos(mpls_label_t *label)
{
	uint8_t *t = (uint8_t *)label;
	return (t[2] & 0x01);
};

#endif /* _BGP_LABEL_H */
