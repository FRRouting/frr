/*
 * IS-IS Rout(e)ing protocol - isis_lsp.h   
 *                             LSP processing
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

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _ZEBRA_ISIS_LSP_H
#define _ZEBRA_ISIS_LSP_H

/* The grand plan is to support 1024 circuits so we have 32*32 bit flags
 * the support will be achived using the newest drafts */
#define ISIS_MAX_CIRCUITS 32 /* = 1024 - FIXME:defined in flags.h as well */

/* Structure for isis_lsp, this structure will only support the fixed
 * System ID (Currently 6) (atleast for now). In order to support more
 * We will have to split the header into two parts, and for readability
 * sake it should better be avoided */
struct isis_lsp
{
  struct isis_fixed_hdr *isis_header;		/* normally equals pdu */
  struct isis_link_state_hdr *lsp_header;	/* pdu + isis_header_len */
  struct stream *pdu;				/* full pdu lsp */
  union
  {
    struct list *frags;
    struct isis_lsp *zero_lsp;
  } lspu;
  u_int32_t SRMflags[ISIS_MAX_CIRCUITS];
  u_int32_t SSNflags[ISIS_MAX_CIRCUITS];
  u_int32_t rexmit_queue[ISIS_MAX_CIRCUITS];
  int level;			/* L1 or L2? */
  int purged;			/* have purged this one */
  int scheduled;		/* scheduled for sending */
  time_t installed;
  time_t last_generated;
  time_t last_sent;
  int own_lsp;
#ifdef TOPOLOGY_GENERATE
  int from_topology;
  struct thread *t_lsp_top_ref;
#endif
  /* used for 60 second counting when rem_lifetime is zero */
  int age_out;
  struct isis_adjacency *adj;
  /* FIXME: For now only topology LSP's use this. Is it helpful for others? */
  struct isis_area *area;
  struct tlvs tlv_data;		/* Simplifies TLV access */
};

dict_t *lsp_db_init (void);
void lsp_db_destroy (dict_t * lspdb);
int lsp_tick (struct thread *thread);

int lsp_l1_generate (struct isis_area *area);
int lsp_l2_generate (struct isis_area *area);
int lsp_refresh_l1 (struct thread *thread);
int lsp_refresh_l2 (struct thread *thread);
int lsp_regenerate_schedule (struct isis_area *area);

int lsp_l1_pseudo_generate (struct isis_circuit *circuit);
int lsp_l2_pseudo_generate (struct isis_circuit *circuit);
int lsp_l1_refresh_pseudo (struct thread *thread);
int lsp_l2_refresh_pseudo (struct thread *thread);
int isis_lsp_authinfo_check (struct stream *stream, struct isis_area *area,
			     int pdulen, struct isis_passwd *passwd);
struct isis_lsp *lsp_new (u_char * lsp_id, u_int16_t rem_lifetime,
			  u_int32_t seq_num, u_int8_t lsp_bits,
			  u_int16_t checksum, int level);
struct isis_lsp *lsp_new_from_stream_ptr (struct stream *stream,
					  u_int16_t pdu_len,
					  struct isis_lsp *lsp0,
					  struct isis_area *area);
void lsp_insert (struct isis_lsp *lsp, dict_t * lspdb);
struct isis_lsp *lsp_search (u_char * id, dict_t * lspdb);

void lsp_build_list (u_char * start_id, u_char * stop_id,
		     struct list *list, dict_t * lspdb);
void lsp_build_list_nonzero_ht (u_char * start_id, u_char * stop_id,
				struct list *list, dict_t * lspdb);
void lsp_build_list_ssn (struct isis_circuit *circuit, struct list *list,
			 dict_t * lspdb);

void lsp_search_and_destroy (u_char * id, dict_t * lspdb);
void lsp_purge_dr (u_char * id, struct isis_circuit *circuit, int level);
void lsp_purge_non_exist (struct isis_link_state_hdr *lsp_hdr,
			  struct isis_area *area);

#define LSP_EQUAL 1
#define LSP_NEWER 2
#define LSP_OLDER 3

#define LSP_PSEUDO_ID(I) ((I)[ISIS_SYS_ID_LEN])
#define LSP_FRAGMENT(I) ((I)[ISIS_SYS_ID_LEN + 1])
#define OWNLSPID(I) \
        memcpy ((I), isis->sysid, ISIS_SYS_ID_LEN);\
        (I)[ISIS_SYS_ID_LEN] = 0;\
        (I)[ISIS_SYS_ID_LEN + 1] = 0
int lsp_id_cmp (u_char * id1, u_char * id2);
int lsp_compare (char *areatag, struct isis_lsp *lsp, u_int32_t seq_num,
		 u_int16_t checksum, u_int16_t rem_lifetime);
void lsp_update (struct isis_lsp *lsp, struct isis_link_state_hdr *lsp_hdr,
		 struct stream *stream, struct isis_area *area, int level);
void lsp_inc_seqnum (struct isis_lsp *lsp, u_int32_t seq_num);
int lsp_print_all (struct vty *vty, dict_t * lspdb, char detail,
		   char dynhost);
const char *lsp_bits2string (u_char *);

#ifdef TOPOLOGY_GENERATE
void generate_topology_lsps (struct isis_area *area);
void remove_topology_lsps (struct isis_area *area);
void build_topology_lsp_data (struct isis_lsp *lsp,
			      struct isis_area *area, int lsp_top_num);
#endif /* TOPOLOGY_GENERATE */

#endif /* ISIS_LSP */
