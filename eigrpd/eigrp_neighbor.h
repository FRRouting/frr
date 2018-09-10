/*
 * EIGRP Neighbor Handling.
 * Copyright (C) 2013-2016
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
 *   Frantisek Gazo
 *   Tomas Hvorkovy
 *   Martin Kontsek
 *   Lukas Koribsky
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

#ifndef _ZEBRA_EIGRP_NEIGHBOR_H
#define _ZEBRA_EIGRP_NEIGHBOR_H

/* Neighbor Data Structure */
struct eigrp_neighbor {

    uint8_t os_rel_major;  // system version - just for show
    uint8_t os_rel_minor;  // system version - just for show

    /* TLV decoders for this peer - version dependent */
    uint8_t tlv_rel_major; // eigrp version - tells us what TLV format to use
    uint8_t tlv_rel_minor; // eigrp version - tells us what TLV format to use
    
    eigrp_tlv_decoder_t	tlv_decoder;
    eigrp_tlv_encoder_t	tlv_encoder;

    uint8_t K1;
    uint8_t K2;
    uint8_t K3;
    uint8_t K4;
    uint8_t K5;
    uint8_t K6;

    /* This neighbor's parent eigrp interface. */
    eigrp_interface_t *ei;

    /* EIGRP neighbor Information */
    uint8_t state; /* neigbor status. */

    uint32_t recv_sequence_number; /* Last received sequence Number. */
    uint32_t init_sequence_number;

    /*If packet is unacknowledged, we try to send it again 16 times*/
    uint8_t retrans_counter;

    struct in_addr src; /* Neighbor Src address. */

    /* Timer values. */
    uint16_t v_holddown;

    /* Threads. */
    struct thread *t_holddown;
    struct thread *t_nbr_send_gr; /* thread for sending multiple GR packet
				     chunks */

    struct eigrp_fifo *retrans_queue;
    struct eigrp_fifo *multicast_queue;

    uint32_t crypt_seqnum; /* Cryptographic Sequence Number. */

    /* prefixes not received from neighbor during Graceful restart */
    struct list *nbr_gr_prefixes;
    /* prefixes not yet send to neighbor during Graceful restart */
    struct list *nbr_gr_prefixes_send;
    /* if packet is first or last during Graceful restart */
    enum Packet_part_type nbr_gr_packet_type;

};


/* Prototypes */
extern eigrp_neighbor_t *eigrp_nbr_get(eigrp_interface_t *,
				       struct eigrp_header *, struct ip *);
extern eigrp_neighbor_t *eigrp_nbr_new(eigrp_interface_t *);
extern void eigrp_nbr_delete(eigrp_neighbor_t *);

extern int holddown_timer_expired(struct thread *);

extern int eigrp_neighborship_check(eigrp_neighbor_t *,
				    struct TLV_Parameter_Type *);
extern void eigrp_nbr_state_update(eigrp_neighbor_t *);
extern void eigrp_nbr_state_set(eigrp_neighbor_t *, uint8_t state);
extern uint8_t eigrp_nbr_state_get(eigrp_neighbor_t *);
extern int eigrp_nbr_count_get(eigrp_t *);
extern const char *eigrp_nbr_state_str(eigrp_neighbor_t *);
extern eigrp_neighbor_t *eigrp_nbr_lookup_by_addr(eigrp_interface_t *,
						       struct in_addr *);
extern eigrp_neighbor_t *eigrp_nbr_lookup_by_addr_process(eigrp_t *, struct in_addr);
extern void eigrp_nbr_hard_restart(eigrp_t *, eigrp_neighbor_t *nbr, struct vty *);

extern int eigrp_nbr_split_horizon_check(eigrp_route_descriptor_t *,
					 eigrp_interface_t *);

/**
 * Found in eigrp-tlv*.c for peer versioning of TLV decoding
 */
extern void eigrp_tlv1_init(eigrp_neighbor_t *);
extern void eigrp_tlv2_init(eigrp_neighbor_t *);

#endif /* _ZEBRA_EIGRP_NEIGHBOR_H */
