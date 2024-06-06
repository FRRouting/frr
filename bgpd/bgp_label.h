// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP carrying Label information
 * Copyright (C) 2013 Cumulus Networks, Inc.
 */

#ifndef _BGP_LABEL_H
#define _BGP_LABEL_H

#define BGP_LABEL_BYTES 3
#define BGP_LABEL_BITS 24
#define BGP_WITHDRAW_LABEL 0x800000
#define BGP_PREVENT_VRF_2_VRF_LEAK 0xFFFFFFFE

struct bgp_dest;
struct bgp_path_info;
struct peer;

/* Maximum number of labels we can process or send with a prefix. We
 * really do only 1 for MPLS (BGP-LU) but we can do 2 for EVPN-VxLAN.
 */
#define BGP_MAX_LABELS 2

/* MPLS label(s) - VNI(s) for EVPN-VxLAN  */
struct bgp_labels {
	mpls_label_t label[BGP_MAX_LABELS];
	uint8_t num_labels;

	unsigned long refcnt;
};

extern void bgp_labels_init(void);
extern void bgp_labels_finish(void);
extern struct bgp_labels *bgp_labels_intern(struct bgp_labels *labels);
extern void bgp_labels_unintern(struct bgp_labels **plabels);
extern bool bgp_labels_cmp(const struct bgp_labels *labels1,
			   const struct bgp_labels *labels2);

extern int bgp_reg_for_label_callback(mpls_label_t new_label, void *labelid,
				    bool allocated);
extern void bgp_reg_dereg_for_label(struct bgp_dest *dest,
				    struct bgp_path_info *pi, bool reg);
extern int bgp_parse_fec_update(void);
extern mpls_label_t bgp_adv_label(struct bgp_dest *dest,
				  struct bgp_path_info *pi, struct peer *to,
				  afi_t afi, safi_t safi);

extern int bgp_nlri_parse_label(struct peer *peer, struct attr *attr,
				struct bgp_nlri *packet);
extern bool bgp_labels_same(const mpls_label_t *tbl_a,
			    const uint8_t num_labels_a,
			    const mpls_label_t *tbl_b,
			    const uint8_t num_labels_b);

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
	if (((pkt[0] == 0x80) || (pkt[0] == 0x00)) && (pkt[1] == 0x00)
	    && ((pkt[2] == 0x00) || (pkt[2] == 0x02)))
		return 1;
	return 0;
}

static inline int bgp_is_valid_label(const mpls_label_t *label)
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

static inline void bgp_register_for_label(struct bgp_dest *dest,
					  struct bgp_path_info *pi)
{
	bgp_reg_dereg_for_label(dest, pi, true);
}

static inline void bgp_unregister_for_label(struct bgp_dest *dest)
{
	bgp_reg_dereg_for_label(dest, NULL, false);
}

/* Return BOS value of label stream */
static inline uint8_t label_bos(mpls_label_t *label)
{
	uint8_t *t = (uint8_t *)label;
	return (t[2] & 0x01);
};

#endif /* _BGP_LABEL_H */
