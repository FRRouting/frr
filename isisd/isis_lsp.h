// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_lsp.h
 *                             LSP processing
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */

#ifndef _ZEBRA_ISIS_LSP_H
#define _ZEBRA_ISIS_LSP_H

#include "lib/typesafe.h"
#include "isisd/isis_pdu.h"

PREDECL_RBTREE_UNIQ(lspdb);

struct isis;
/* Structure for isis_lsp, this structure will only support the fixed
 * System ID (Currently 6) (atleast for now). In order to support more
 * We will have to split the header into two parts, and for readability
 * sake it should better be avoided */
struct isis_lsp {
	struct lspdb_item dbe;

	struct isis_lsp_hdr hdr;
	struct stream *pdu; /* full pdu lsp */
	union {
		struct list *frags;
		struct isis_lsp *zero_lsp;
	} lspu;
	uint32_t SSNflags[ISIS_MAX_CIRCUITS];
	int level;     /* L1 or L2? */
	int scheduled; /* scheduled for sending */
	time_t installed;
	time_t last_generated;
	int own_lsp;
	/* used for 60 second counting when rem_lifetime is zero */
	int age_out;
	struct isis_area *area;
	struct isis_tlvs *tlvs;

	time_t flooding_time;
	struct list *flooding_neighbors[TX_LSP_CIRCUIT_SCOPED + 1];
	char *flooding_interface;
	bool flooding_circuit_scoped;
};

extern int lspdb_compare(const struct isis_lsp *a, const struct isis_lsp *b);
DECLARE_RBTREE_UNIQ(lspdb, struct isis_lsp, dbe, lspdb_compare);

void lsp_db_init(struct lspdb_head *head);
void lsp_db_fini(struct lspdb_head *head);
void lsp_tick(struct event *thread);
void set_overload_on_start_timer(struct event *thread);

int lsp_generate(struct isis_area *area, int level);
#define lsp_regenerate_schedule(area, level, all_pseudo) \
	_lsp_regenerate_schedule((area), (level), (all_pseudo), true, \
				 __func__, __FILE__, __LINE__)
int _lsp_regenerate_schedule(struct isis_area *area, int level,
			     int all_pseudo, bool postpone,
			     const char *func, const char *file, int line);
int lsp_generate_pseudo(struct isis_circuit *circuit, int level);
int lsp_regenerate_schedule_pseudo(struct isis_circuit *circuit, int level);

bool isis_level2_adj_up(struct isis_area *area);

struct isis_lsp *lsp_new(struct isis_area *area, uint8_t *lsp_id,
			 uint16_t rem_lifetime, uint32_t seq_num,
			 uint8_t lsp_bits, uint16_t checksum,
			 struct isis_lsp *lsp0, int level);
struct isis_lsp *lsp_new_from_recv(struct isis_lsp_hdr *hdr,
				   struct isis_tlvs *tlvs,
				   struct stream *stream, struct isis_lsp *lsp0,
				   struct isis_area *area, int level);
void lsp_insert(struct lspdb_head *head, struct isis_lsp *lsp);
struct isis_lsp *lsp_search(struct lspdb_head *head, const uint8_t *id);

void lsp_build_list(struct lspdb_head *head, const uint8_t *start_id,
		    const uint8_t *stop_id, uint8_t num_lsps,
		    struct list *list);
void lsp_build_list_nonzero_ht(struct lspdb_head *head,
			       const uint8_t *start_id,
			       const uint8_t *stop_id, struct list *list);
void lsp_search_and_destroy(struct lspdb_head *head, const uint8_t *id);
void lsp_purge_pseudo(uint8_t *id, struct isis_circuit *circuit, int level);
void lsp_purge_non_exist(int level, struct isis_lsp_hdr *hdr,
			 struct isis_area *area);

#define LSP_EQUAL 1
#define LSP_NEWER 2
#define LSP_OLDER 3

#define LSP_PSEUDO_ID(I) ((I)[ISIS_SYS_ID_LEN])
#define LSP_FRAGMENT(I) ((I)[ISIS_SYS_ID_LEN + 1])
#define OWNLSPID(I)                                                            \
	memcpy((I), isis->sysid, ISIS_SYS_ID_LEN);                             \
	(I)[ISIS_SYS_ID_LEN] = 0;                                              \
	(I)[ISIS_SYS_ID_LEN + 1] = 0
int lsp_id_cmp(uint8_t *id1, uint8_t *id2);
int lsp_compare(char *areatag, struct isis_lsp *lsp, uint32_t seqno,
		uint16_t checksum, uint16_t rem_lifetime);
void lsp_update(struct isis_lsp *lsp, struct isis_lsp_hdr *hdr,
		struct isis_tlvs *tlvs, struct stream *stream,
		struct isis_area *area, int level, bool confusion);
void lsp_inc_seqno(struct isis_lsp *lsp, uint32_t seqno);
void lspid_print(uint8_t *lsp_id, char *dest, size_t dest_len, char dynhost,
		 char frag, struct isis *isis);
void lsp_print_common(struct isis_lsp *lsp, struct vty *vty,
		      struct json_object *json, char dynhost,
		      struct isis *isis);
void lsp_print_vty(struct isis_lsp *lsp, struct vty *vty, char dynhost,
		   struct isis *isis);
void lsp_print_json(struct isis_lsp *lsp, struct json_object *json,
		    char dynhost, struct isis *isis);
void lsp_print_detail(struct isis_lsp *lsp, struct vty *vty,
		      struct json_object *json, char dynhost,
		      struct isis *isis);
int lsp_print_all(struct vty *vty, struct json_object *json,
		  struct lspdb_head *head, char detail, char dynhost,
		  struct isis *isis);
/* sets SRMflags for all active circuits of an lsp */
void lsp_set_all_srmflags(struct isis_lsp *lsp, bool set);

#define LSP_ITER_CONTINUE 0
#define LSP_ITER_STOP -1

/* Callback used by isis_lsp_iterate_ip_reach() function. */
struct isis_subtlvs;
typedef int (*lsp_ip_reach_iter_cb)(const struct prefix *prefix,
				    uint32_t metric, bool external,
				    struct isis_subtlvs *subtlvs, void *arg);

/* Callback used by isis_lsp_iterate_is_reach() function. */
typedef int (*lsp_is_reach_iter_cb)(const uint8_t *id, uint32_t metric,
				    bool oldmetric,
				    struct isis_ext_subtlvs *subtlvs,
				    void *arg);

int isis_lsp_iterate_ip_reach(struct isis_lsp *lsp, int family, uint16_t mtid,
			      lsp_ip_reach_iter_cb cb, void *arg);
int isis_lsp_iterate_is_reach(struct isis_lsp *lsp, uint16_t mtid,
			      lsp_is_reach_iter_cb cb, void *arg);
int isis_lsp_iterate_srv6_locator(struct isis_lsp *lsp, uint16_t mtid,
				  lsp_ip_reach_iter_cb cb, void *arg);

#define lsp_flood(lsp, circuit) \
	_lsp_flood((lsp), (circuit), __func__, __FILE__, __LINE__)
void _lsp_flood(struct isis_lsp *lsp, struct isis_circuit *circuit,
		const char *func, const char *file, int line);
void lsp_init(void);

#endif /* ISIS_LSP */
