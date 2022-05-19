// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - BFD support
 * Copyright (C) 2018 Christian Franke
 */
#ifndef ISIS_BFD_H
#define ISIS_BFD_H

/* RFC6213 MTID/NLPID supported pair */
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
};

/* Locally supported topologies (MTID) */
struct bfd_local_mtid {
	uint16_t mtid;
};

struct bfd_rfc6213_params {
	/* Neighbor enabled RFC6213 MTID/NLPID pairs */
	uint8_t neighbor_mtid_nlpid;

	/* list of locally supported MTID/NLPID pairs */
	struct list *local_mtnlpid_lst;
	/* list of locally supported MTID*/
	struct list *local_mtid_lst;
};

void isis_bfd_adjacency_update_rfc6213_local_params(struct isis_adjacency *adj);

void isis_bfd_circuit_cmd(struct isis_circuit *circuit);
void isis_bfd_circuit_update_rfc6213(struct isis_circuit *circuit);
bool isis_bfd_config_rfc6213_enabled(struct bfd_conf *config);
void isis_bfd_init_adjacency(struct isis_adjacency *adj);
void isis_bfd_show_adjacency(struct vty *vty, struct isis_adjacency *adj);
void isis_bfd_update_adj_bfd(struct isis_bfd_enabled *head,
			     struct isis_adjacency *adj, bool *changed);

void isis_bfd_init(struct event_loop *tm);

#endif

