// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - BFD support
 * Copyright (C) 2018 Christian Franke
 */
#ifndef ISIS_BFD_H
#define ISIS_BFD_H

/* RFC6213 MTID/NLPID supported pair */
#define ISIS_BFD_MT_NLP_UNDEFINED	  0x0
#define ISIS_BFD_MT_STANDARD_NLP_IPV4	  0x1
#define ISIS_BFD_MT_STANDARD_NLP_IPV6	  0x2
#define ISIS_BFD_MT_IPV6_UNICAST_NLP_IPV6 0x4

struct isis_circuit;
struct isis_bfd_enabled;
struct event_loop;
struct isis_adjacency;
struct bfd_conf;

/* Locally supported MTID/NLPID pair */
struct bfd_local_mtnlpid {
	uint16_t mtid;
	uint8_t nlpid;

	/* RFC6213 variables have been inited.
	 * Display debug log if false.
	 */
	bool inited;

	/* RFC6213 variables */
	/* ISIS_TOPO_NLPID_BFD_REQUIRED */
	bool topo_nlpid_bfd_required;
	/* ISIS_TOPO_NLPID_STATE */
	bool topo_nlpid_state;
};

/* Locally supported topologies (MTID) */
struct bfd_local_mtid {
	uint16_t mtid;

	/* RFC6213 variables have been inited.
	 * Display debug log if false.
	 */
	bool inited;

	/* RFC6213 variables */
	/* ISIS_TOPO_BFD_REQUIRED */
	bool topo_bfd_required;
	/* ISIS_TOPO_USEABLE */
	bool topo_useable;
};

struct bfd_rfc6213_params {
	/* Neighbor enabled RFC6213 MTID/NLPID pairs */
	uint8_t neighbor_mtid_nlpid;

	/* list of locally supported MTID/NLPID pairs */
	struct list *local_mtnlpid_lst;
	/* list of locally supported MTID*/
	struct list *local_mtid_lst;

	/* RFC6213 and internal variables have been inited.
	 * Display debug log if false.
	 */
	bool inited;

	/* RFC6213 variables */
	/* ISIS_BFD_REQUIRED */
	bool bfd_required;
	/* previous ISIS_BFD_REQUIRED */
	bool bfd_required_last;
	/* ISIS_NEIGHBOR_USEABLE */
	bool neighbor_useable;

	/* internal variables */
	/* BFD IPv4 local config is required and can be used */
	bool bfd_ipv4_required;
	/* BFD IPv6 local config is required and can be used */
	bool bfd_ipv6_required;

	/* previous BFD configuration value */
	bool config_enabled_last;
	/* previous BFD IPv4 configuration value */
	bool config_rfc6213_ipv4_last;
	/* previous BFD IPv6 configuration value */
	bool config_rfc6213_ipv6_last;

#define BFD_ADJ_STOP_IPV4 0x1
#define BFD_ADJ_STOP_IPV6 0x2
	uint8_t flags;

	bool bfd_required_is_transition_up;
};

void isis_bfd_circuit_cmd(struct isis_circuit *circuit);
void isis_bfd_circuit_update_rfc6213(struct isis_circuit *circuit);
bool isis_bfd_circuit_rfc6213_enabled(struct isis_circuit *circuit);
void isis_bfd_update_rfc6213(struct isis_adjacency *adj);
void isis_bfd_init_adjacency(struct isis_adjacency *adj);
void isis_bfd_show_adjacency(struct vty *vty, struct isis_adjacency *adj);
void isis_bfd_update_adj_bfd(struct isis_bfd_enabled *head,
			     struct isis_adjacency *adj, bool *changed);
void bfd_handle_adj_down(struct isis_adjacency *adj, uint8_t family,
			 const char *reason);
bool isis_bfd_dont_update_adjacency_holdtime(struct isis_adjacency *adj);
bool isis_bfd_is_bfd_state_up(struct isis_adjacency *adj);

void isis_bfd_init(struct event_loop *tm);

#endif

