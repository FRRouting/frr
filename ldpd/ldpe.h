// SPDX-License-Identifier: ISC
/*	$OpenBSD$ */

/*
 * Copyright (c) 2013, 2016 Renato Westphal <renato@openbsd.org>
 * Copyright (c) 2009 Michele Marchetto <michele@openbsd.org>
 * Copyright (c) 2004, 2005, 2008 Esben Norby <norby@openbsd.org>
 */

#ifndef _LDPE_H_
#define _LDPE_H_

#include "queue.h"
#include "openbsd-tree.h"
#ifdef __OpenBSD__
#include <net/pfkeyv2.h>
#endif

#include "ldpd.h"
#include "lib/ldp_sync.h"

/* forward declarations */
TAILQ_HEAD(mapping_head, mapping_entry);

struct hello_source {
	enum hello_type		 type;
	struct {
		struct iface_af	*ia;
		union g_addr src_addr;
	} link;
	struct tnbr		*target;
};

struct adj {
	RB_ENTRY(adj)		 global_entry, nbr_entry, ia_entry;
	struct in_addr		 lsr_id;
	struct nbr		*nbr;
	int			 ds_tlv;
	struct hello_source	 source;
	struct event *inactivity_timer;
	uint16_t		 holdtime;
	union g_addr trans_addr;
};
RB_PROTOTYPE(global_adj_head, adj, global_entry, adj_compare)
RB_PROTOTYPE(nbr_adj_head, adj, nbr_entry, adj_compare)
RB_PROTOTYPE(ia_adj_head, adj, ia_entry, adj_compare)

struct tcp_conn {
	struct nbr		*nbr;
	int			 fd;
	struct ibuf_read	*rbuf;
	struct evbuf		 wbuf;
	struct event *rev;
	in_port_t		 lport;
	in_port_t		 rport;
};

struct nbr {
	RB_ENTRY(nbr)		 id_tree, addr_tree, pid_tree;
	struct tcp_conn		*tcp;
	struct nbr_adj_head	 adj_tree;	/* adjacencies */
	struct event *ev_connect;
	struct event *keepalive_timer;
	struct event *keepalive_timeout;
	struct event *init_timeout;
	struct event *initdelay_timer;

	struct mapping_head	 mapping_list;
	struct mapping_head	 withdraw_list;
	struct mapping_head	 request_list;
	struct mapping_head	 release_list;
	struct mapping_head	 abortreq_list;

	uint32_t		 peerid;	/* unique ID in DB */
	int			 af;
	int			 ds_tlv;
	int			 v4_enabled;	/* announce/process v4 msgs */
	int			 v6_enabled;	/* announce/process v6 msgs */
	struct in_addr		 id;		/* lsr id */
	union g_addr laddr;			/* local address */
	union g_addr raddr;			/* remote address */
	ifindex_t		 raddr_scope;	/* remote address scope (v6) */
	time_t			 uptime;
	int			 fd;
	int			 state;
	uint32_t		 conf_seqnum;
	int			 idtimer_cnt;
	uint16_t		 keepalive;
	uint16_t		 max_pdu_len;
	struct ldp_stats	 stats;

	struct {
		uint8_t			established;
		uint32_t		spi_in;
		uint32_t		spi_out;
		enum auth_method	method;
		char			md5key[TCP_MD5_KEY_LEN];
	} auth;
	int			 flags;
};
#define F_NBR_GTSM_NEGOTIATED	 0x01
#define F_NBR_CAP_DYNAMIC	 0x02
#define F_NBR_CAP_TWCARD	 0x04
#define F_NBR_CAP_UNOTIF	 0x08

RB_HEAD(nbr_id_head, nbr);
RB_PROTOTYPE(nbr_id_head, nbr, id_tree, nbr_id_compare)
RB_HEAD(nbr_addr_head, nbr);
RB_PROTOTYPE(nbr_addr_head, nbr, addr_tree, nbr_addr_compare)
RB_HEAD(nbr_pid_head, nbr);
RB_PROTOTYPE(nbr_pid_head, nbr, pid_tree, nbr_pid_compare)

struct pending_conn {
	TAILQ_ENTRY(pending_conn)	 entry;
	int				 fd;
	int				 af;
	union g_addr addr;
	struct event *ev_timeout;
};
#define PENDING_CONN_TIMEOUT	5

struct mapping_entry {
	TAILQ_ENTRY(mapping_entry)	entry;
	struct map			map;
};

struct ldpd_sysdep {
	uint8_t		no_pfkey;
	uint8_t		no_md5sig;
};

extern struct ldpd_conf		*leconf;
extern struct ldpd_sysdep	 sysdep;
extern struct nbr_id_head	 nbrs_by_id;
extern struct nbr_addr_head	 nbrs_by_addr;
extern struct nbr_pid_head	 nbrs_by_pid;

/* accept.c */
void	accept_init(void);
int accept_add(int fd, void (*cb)(struct event *), void *arg);
void accept_del(int fd);
void	accept_pause(void);
void	accept_unpause(void);

/* hello.c */
int send_hello(enum hello_type type, struct iface_af *ia, struct tnbr *tnbr);
void recv_hello(struct in_addr lsr_id, struct ldp_msg *msg, int af, union g_addr *src,
		struct iface *iface, int source_addr, char *pdu_buf, uint16_t tlvs_len);

/* init.c */
void send_init(struct nbr *nbr);
int recv_init(struct nbr *nbr, char *buf, uint16_t len);
void send_capability(struct nbr *nbr, uint16_t capability, int enable);
int recv_capability(struct nbr *nbr, char *buf, uint16_t len);

/* keepalive.c */
void send_keepalive(struct nbr *nbr);
int recv_keepalive(struct nbr *nbr, char *buf, uint16_t len);

/* notification.c */
void send_notification_full(struct tcp_conn *tcp, struct notify_msg *nm);
void send_notification(struct tcp_conn *tcp, uint32_t status_code, uint32_t msg_id,
		       uint16_t msg_type);
void send_notification_rtlvs(struct nbr *nbr, uint32_t status_code, uint32_t msg_id,
			     uint16_t msg_type, uint16_t fec_type, uint16_t fec_len,
			     char *fec_value);
int recv_notification(struct nbr *nbr, char *buf, uint16_t len);
int gen_status_tlv(struct ibuf *buf, uint32_t status_code, uint32_t msg_id, uint16_t msg_type);

/* address.c */
void send_address_single(struct nbr *nbr, struct if_addr *if_addr, int withdraw);
void send_address_all(struct nbr *nbr, int af);
void send_mac_withdrawal(struct nbr *nbr, struct map *fec, uint8_t *mac);
int recv_address(struct nbr *nbr, char *buf, uint16_t len);

/* labelmapping.c */
#define PREFIX_SIZE(x)	(((x) + 7) / 8)
void send_labelmessage(struct nbr *nbr, uint16_t type, struct mapping_head *mh);
int recv_labelmessage(struct nbr *nbr, char *buf, uint16_t len, uint16_t type);
int gen_pw_status_tlv(struct ibuf *buf, uint32_t status);
uint16_t len_fec_tlv(struct map *map);
int gen_fec_tlv(struct ibuf *buf, struct map *map);
int tlv_decode_fec_elm(struct nbr *nbr, struct ldp_msg *msg, char *buf, uint16_t len,
		       struct map *map);

/* ldpe.c */
void		 ldpe(void);
void ldpe_init(struct ldpd_init *init);
int ldpe_imsg_compose_parent(int type, pid_t pid, void *data, uint16_t datalen);
void ldpe_imsg_compose_parent_sync(int type, pid_t pid, void *data, uint16_t datalen);
int ldpe_imsg_compose_lde(int type, uint32_t peerid, pid_t pid, void *data, uint16_t datalen);
int ldpe_acl_check(char *acl_name, int af, union g_addr *addr, uint8_t prefixlen);
void ldpe_reset_nbrs(int af);
void		 ldpe_reset_ds_nbrs(void);
void ldpe_remove_dynamic_tnbrs(int af);
void ldpe_stop_init_backoff(int af);
struct ctl_conn;
void		 ldpe_iface_ctl(struct ctl_conn *c, ifindex_t ifidx);
void ldpe_adj_ctl(struct ctl_conn *c);
void ldpe_adj_detail_ctl(struct ctl_conn *c);
void ldpe_nbr_ctl(struct ctl_conn *c);
void ldpe_ldp_sync_ctl(struct ctl_conn *c);
void mapping_list_add(struct mapping_head *mh, struct map *map);
void mapping_list_clr(struct mapping_head *mh);
void		 ldpe_set_config_change_time(void);

/* interface.c */
struct iface	*if_new(const char *);
void ldpe_if_init(struct iface *iface);
void ldpe_if_exit(struct iface *iface);
struct iface	*if_lookup(struct ldpd_conf *c, ifindex_t ifidx);
struct iface	*if_lookup_name(struct ldpd_conf *, const char *);
void if_update_info(struct iface *iface, struct kif *kif);
struct iface_af *iface_af_get(struct iface *, int);
void if_addr_add(struct kaddr *ka);
void if_addr_del(struct kaddr *ka);
void ldp_if_update(struct iface *iface, int af);
void if_update_all(int af);
uint16_t if_get_hello_holdtime(struct iface_af *ia);
uint16_t if_get_hello_interval(struct iface_af *ia);
uint16_t	 if_get_wait_for_sync_interval(void);
struct ctl_iface *if_to_ctl(struct iface_af *);
in_addr_t if_get_ipv4_addr(struct iface *iface);
int ldp_sync_fsm_adj_event(struct adj *adj, enum ldp_sync_event event);
int ldp_sync_fsm_nbr_event(struct nbr *nbr, enum ldp_sync_event event);
int ldp_sync_fsm_state_req(struct ldp_igp_sync_if_state_req *state_req);
int ldp_sync_fsm(struct iface *iface, enum ldp_sync_event event);
void		 ldp_sync_fsm_reset_all(void);
const char      *ldp_sync_state_name(int);
const char      *ldp_sync_event_name(int);
struct ctl_ldp_sync *ldp_sync_to_ctl(struct iface *);

/* adjacency.c */
struct adj *adj_new(struct in_addr, struct hello_source *, union g_addr *);
void adj_del(struct adj *adj, uint32_t notif_status);
struct adj	*adj_find(struct in_addr, struct hello_source *);
int		 adj_get_af(const struct adj *adj);
void adj_start_itimer(struct adj *adj);
void adj_stop_itimer(struct adj *adj);
struct tnbr *tnbr_new(int, union g_addr *);
struct tnbr *tnbr_find(struct ldpd_conf *, int, union g_addr *);
struct tnbr	*tnbr_check(struct ldpd_conf *, struct tnbr *);
void tnbr_update(struct tnbr *tnbr);
void tnbr_update_all(int af);
uint16_t tnbr_get_hello_holdtime(struct tnbr *tnbr);
uint16_t tnbr_get_hello_interval(struct tnbr *tnbr);
struct ctl_adj	*adj_to_ctl(struct adj *);

/* neighbor.c */
int nbr_fsm(struct nbr *nbr, enum nbr_event event);
struct nbr *nbr_new(struct in_addr, int, int, union g_addr *, uint32_t);
void nbr_del(struct nbr *nbr);
struct nbr		*nbr_find_ldpid(uint32_t);
struct nbr		*nbr_get_first_ldpid(void);
struct nbr		*nbr_get_next_ldpid(uint32_t);
struct nbr *nbr_find_addr(int, union g_addr *);
struct nbr		*nbr_find_peerid(uint32_t);
int nbr_adj_count(struct nbr *nbr, int af);
int nbr_session_active_role(struct nbr *nbr);
void nbr_stop_ktimer(struct nbr *nbr);
void nbr_stop_ktimeout(struct nbr *nbr);
void nbr_stop_itimeout(struct nbr *nbr);
void nbr_start_idtimer(struct nbr *nbr);
void nbr_stop_idtimer(struct nbr *nbr);
int nbr_pending_idtimer(struct nbr *nbr);
int nbr_pending_connect(struct nbr *nbr);
int nbr_establish_connection(struct nbr *nbr);
int nbr_gtsm_enabled(struct nbr *nbr, struct nbr_params *nbrp);
int nbr_gtsm_setup(int fd, int af, struct nbr_params *nbrp);
int nbr_gtsm_check(int fd, struct nbr *nbr, struct nbr_params *nbrp);
struct nbr_params	*nbr_params_new(struct in_addr);
struct nbr_params	*nbr_params_find(struct ldpd_conf *, struct in_addr);
uint16_t nbr_get_keepalive(int af, struct in_addr lsr_id);
struct ctl_nbr		*nbr_to_ctl(struct nbr *);
void nbr_clear_ctl(struct ctl_nbr *nctl);

/* packet.c */
int gen_ldp_hdr(struct ibuf *buf, uint16_t size);
int gen_msg_hdr(struct ibuf *buf, uint16_t type, uint16_t size);
int send_packet(int fd, int af, union g_addr *dst, struct iface_af *ia, void *pkt, size_t pkt_len);
void disc_recv_packet(struct event *event);
void session_accept(struct event *event);
void session_accept_nbr(struct nbr *nbr, int fd);
void session_shutdown(struct nbr *nbr, uint32_t status_code, uint32_t msg_id, uint32_t msg_type);
void session_close(struct nbr *nbr);
struct tcp_conn		*tcp_new(int, struct nbr *);
void pending_conn_del(struct pending_conn *pconn);
struct pending_conn *pending_conn_find(int, union g_addr *);

extern char *pkt_ptr; /* packet buffer */

/* pfkey.c */
#ifdef __OpenBSD__
int pfkey_read(int sd, struct sadb_msg *h);
int pfkey_establish(struct nbr *nbr, struct nbr_params *nbrp);
int pfkey_remove(struct nbr *nbr);
int	pfkey_init(void);
#endif

/* l2vpn.c */
void ldpe_l2vpn_init(struct l2vpn *l2vpn);
void ldpe_l2vpn_exit(struct l2vpn *l2vpn);
void ldpe_l2vpn_pw_init(struct l2vpn_pw *pw);
void ldpe_l2vpn_pw_exit(struct l2vpn_pw *pw);

DECLARE_HOOK(ldp_nbr_state_change, (struct nbr * nbr, int old_state),
	     (nbr, old_state));

#endif	/* _LDPE_H_ */
