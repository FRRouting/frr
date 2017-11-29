/*	$OpenBSD$ */

/*
 * Copyright (c) 2013, 2016 Renato Westphal <renato@openbsd.org>
 * Copyright (c) 2009 Michele Marchetto <michele@openbsd.org>
 * Copyright (c) 2004 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _LDPD_H_
#define _LDPD_H_

#include "queue.h"
#include "openbsd-tree.h"
#include "imsg.h"
#include "thread.h"
#include "qobj.h"
#include "prefix.h"
#include "filter.h"
#include "vty.h"
#include "pw.h"
#include "zclient.h"

#include "ldp.h"

#define CONF_FILE		"/etc/ldpd.conf"
#define LDPD_USER		"_ldpd"

#define LDPD_FD_ASYNC		3
#define LDPD_FD_SYNC		4

#define LDPD_OPT_VERBOSE	0x00000001
#define LDPD_OPT_VERBOSE2	0x00000002
#define LDPD_OPT_NOACTION	0x00000004

#define TCP_MD5_KEY_LEN		80

#define	RT_BUF_SIZE		16384
#define	MAX_RTSOCK_BUF		128 * 1024
#define	LDP_BACKLOG		128

#define	F_LDPD_INSERTED		0x0001
#define	F_CONNECTED		0x0002
#define	F_STATIC		0x0004
#define	F_DYNAMIC		0x0008
#define	F_REJECT		0x0010
#define	F_BLACKHOLE		0x0020
#define	F_REDISTRIBUTED		0x0040

struct evbuf {
	struct msgbuf		 wbuf;
	struct thread		*ev;
	int			 (*handler)(struct thread *);
	void			*arg;
};

struct imsgev {
	struct imsgbuf		 ibuf;
	int			(*handler_write)(struct thread *);
	struct thread		*ev_write;
	int			(*handler_read)(struct thread *);
	struct thread		*ev_read;
};

enum imsg_type {
	IMSG_NONE,
	IMSG_CTL_RELOAD,
	IMSG_CTL_SHOW_INTERFACE,
	IMSG_CTL_SHOW_DISCOVERY,
	IMSG_CTL_SHOW_DISCOVERY_DTL,
	IMSG_CTL_SHOW_DISC_IFACE,
	IMSG_CTL_SHOW_DISC_TNBR,
	IMSG_CTL_SHOW_DISC_ADJ,
	IMSG_CTL_SHOW_NBR,
	IMSG_CTL_SHOW_NBR_DISC,
	IMSG_CTL_SHOW_NBR_END,
	IMSG_CTL_SHOW_LIB,
	IMSG_CTL_SHOW_LIB_BEGIN,
	IMSG_CTL_SHOW_LIB_SENT,
	IMSG_CTL_SHOW_LIB_RCVD,
	IMSG_CTL_SHOW_LIB_END,
	IMSG_CTL_SHOW_L2VPN_PW,
	IMSG_CTL_SHOW_L2VPN_BINDING,
	IMSG_CTL_CLEAR_NBR,
	IMSG_CTL_FIB_COUPLE,
	IMSG_CTL_FIB_DECOUPLE,
	IMSG_CTL_KROUTE,
	IMSG_CTL_KROUTE_ADDR,
	IMSG_CTL_IFINFO,
	IMSG_CTL_END,
	IMSG_CTL_LOG_VERBOSE,
	IMSG_KLABEL_CHANGE,
	IMSG_KLABEL_DELETE,
	IMSG_KPW_ADD,
	IMSG_KPW_DELETE,
	IMSG_KPW_SET,
	IMSG_KPW_UNSET,
	IMSG_IFSTATUS,
	IMSG_NEWADDR,
	IMSG_DELADDR,
	IMSG_RTRID_UPDATE,
	IMSG_LABEL_MAPPING,
	IMSG_LABEL_MAPPING_FULL,
	IMSG_LABEL_REQUEST,
	IMSG_LABEL_RELEASE,
	IMSG_LABEL_WITHDRAW,
	IMSG_LABEL_ABORT,
	IMSG_REQUEST_ADD,
	IMSG_REQUEST_ADD_END,
	IMSG_MAPPING_ADD,
	IMSG_MAPPING_ADD_END,
	IMSG_RELEASE_ADD,
	IMSG_RELEASE_ADD_END,
	IMSG_WITHDRAW_ADD,
	IMSG_WITHDRAW_ADD_END,
	IMSG_ADDRESS_ADD,
	IMSG_ADDRESS_DEL,
	IMSG_NOTIFICATION,
	IMSG_NOTIFICATION_SEND,
	IMSG_NEIGHBOR_UP,
	IMSG_NEIGHBOR_DOWN,
	IMSG_NETWORK_ADD,
	IMSG_NETWORK_UPDATE,
	IMSG_SOCKET_IPC,
	IMSG_SOCKET_NET,
	IMSG_CLOSE_SOCKETS,
	IMSG_REQUEST_SOCKETS,
	IMSG_SETUP_SOCKETS,
	IMSG_RECONF_CONF,
	IMSG_RECONF_IFACE,
	IMSG_RECONF_TNBR,
	IMSG_RECONF_NBRP,
	IMSG_RECONF_L2VPN,
	IMSG_RECONF_L2VPN_IF,
	IMSG_RECONF_L2VPN_PW,
	IMSG_RECONF_L2VPN_IPW,
	IMSG_RECONF_END,
	IMSG_DEBUG_UPDATE,
	IMSG_LOG,
	IMSG_ACL_CHECK,
	IMSG_INIT,
	IMSG_PW_UPDATE
};

struct ldpd_init {
	char		 user[256];
	char		 group[256];
	char		 ctl_sock_path[MAXPATHLEN];
	char		 zclient_serv_path[MAXPATHLEN];
	u_short		 instance;
};

union ldpd_addr {
	struct in_addr	v4;
	struct in6_addr	v6;
};

#define IN6_IS_SCOPE_EMBED(a)   \
	((IN6_IS_ADDR_LINKLOCAL(a)) ||  \
	 (IN6_IS_ADDR_MC_LINKLOCAL(a)) || \
	 (IN6_IS_ADDR_MC_INTFACELOCAL(a)))

/* interface states */
#define	IF_STA_DOWN		0x01
#define	IF_STA_ACTIVE		0x02

/* targeted neighbor states */
#define	TNBR_STA_DOWN		0x01
#define	TNBR_STA_ACTIVE		0x02

/* interface types */
enum iface_type {
	IF_TYPE_POINTOPOINT,
	IF_TYPE_BROADCAST
};

/* neighbor states */
#define	NBR_STA_PRESENT		0x0001
#define	NBR_STA_INITIAL		0x0002
#define	NBR_STA_OPENREC		0x0004
#define	NBR_STA_OPENSENT	0x0008
#define	NBR_STA_OPER		0x0010
#define	NBR_STA_SESSION		(NBR_STA_INITIAL | NBR_STA_OPENREC | \
				NBR_STA_OPENSENT | NBR_STA_OPER)

/* neighbor events */
enum nbr_event {
	NBR_EVT_NOTHING,
	NBR_EVT_MATCH_ADJ,
	NBR_EVT_CONNECT_UP,
	NBR_EVT_CLOSE_SESSION,
	NBR_EVT_INIT_RCVD,
	NBR_EVT_KEEPALIVE_RCVD,
	NBR_EVT_PDU_RCVD,
	NBR_EVT_PDU_SENT,
	NBR_EVT_INIT_SENT
};

/* neighbor actions */
enum nbr_action {
	NBR_ACT_NOTHING,
	NBR_ACT_RST_KTIMEOUT,
	NBR_ACT_SESSION_EST,
	NBR_ACT_RST_KTIMER,
	NBR_ACT_CONNECT_SETUP,
	NBR_ACT_PASSIVE_INIT,
	NBR_ACT_KEEPALIVE_SEND,
	NBR_ACT_CLOSE_SESSION
};

/* forward declarations */
RB_HEAD(global_adj_head, adj);
RB_HEAD(nbr_adj_head, adj);
RB_HEAD(ia_adj_head, adj);

struct map {
	uint8_t		type;
	uint32_t	msg_id;
	union {
		struct {
			uint16_t	af;
			union ldpd_addr	prefix;
			uint8_t		prefixlen;
		} prefix;
		struct {
			uint16_t	type;
			uint32_t	pwid;
			uint32_t	group_id;
			uint16_t	ifmtu;
		} pwid;
		struct {
			uint8_t		type;
			union {
				uint16_t	prefix_af;
				uint16_t	pw_type;
			} u;
		} twcard;
	} fec;
	struct {
		uint32_t	status_code;
		uint32_t	msg_id;
		uint16_t	msg_type;
	} st;
	uint32_t	label;
	uint32_t	requestid;
	uint32_t	pw_status;
	uint8_t		flags;
};
#define F_MAP_REQ_ID	0x01	/* optional request message id present */
#define F_MAP_STATUS	0x02	/* status */
#define F_MAP_PW_CWORD	0x04	/* pseudowire control word */
#define F_MAP_PW_ID	0x08	/* pseudowire connection id */
#define F_MAP_PW_IFMTU	0x10	/* pseudowire interface parameter */
#define F_MAP_PW_STATUS	0x20	/* pseudowire status */

struct notify_msg {
	uint32_t	status_code;
	uint32_t	msg_id;		/* network byte order */
	uint16_t	msg_type;	/* network byte order */
	uint32_t	pw_status;
	struct map	fec;
	struct {
		uint16_t	 type;
		uint16_t	 length;
		char		*data;
	} rtlvs;
	uint8_t		flags;
};
#define F_NOTIF_PW_STATUS	0x01	/* pseudowire status tlv present */
#define F_NOTIF_FEC		0x02	/* fec tlv present */
#define F_NOTIF_RETURNED_TLVS	0x04	/* returned tlvs present */

struct if_addr {
	LIST_ENTRY(if_addr)	 entry;
	int			 af;
	union ldpd_addr		 addr;
	uint8_t			 prefixlen;
	union ldpd_addr		 dstbrd;
};
LIST_HEAD(if_addr_head, if_addr);

struct iface_af {
	struct iface		*iface;
	int			 af;
	int			 enabled;
	int			 state;
	struct ia_adj_head	 adj_tree;
	time_t			 uptime;
	struct thread		*hello_timer;
	uint16_t		 hello_holdtime;
	uint16_t		 hello_interval;
};

struct iface {
	RB_ENTRY(iface)		 entry;
	char			 name[IF_NAMESIZE];
	unsigned int		 ifindex;
	struct if_addr_head	 addr_list;
	struct in6_addr		 linklocal;
	enum iface_type		 type;
	int			 operative;
	struct iface_af		 ipv4;
	struct iface_af		 ipv6;
	QOBJ_FIELDS
};
RB_HEAD(iface_head, iface);
RB_PROTOTYPE(iface_head, iface, entry, iface_compare);
DECLARE_QOBJ_TYPE(iface)

/* source of targeted hellos */
struct tnbr {
	RB_ENTRY(tnbr)		 entry;
	struct thread		*hello_timer;
	struct adj		*adj;
	int			 af;
	union ldpd_addr		 addr;
	int			 state;
	uint16_t		 pw_count;
	uint8_t			 flags;
	QOBJ_FIELDS
};
RB_HEAD(tnbr_head, tnbr);
RB_PROTOTYPE(tnbr_head, tnbr, entry, tnbr_compare);
DECLARE_QOBJ_TYPE(tnbr)
#define F_TNBR_CONFIGURED	 0x01
#define F_TNBR_DYNAMIC		 0x02

enum auth_method {
	AUTH_NONE,
	AUTH_MD5SIG
};

/* neighbor specific parameters */
struct nbr_params {
	RB_ENTRY(nbr_params)	 entry;
	struct in_addr		 lsr_id;
	uint16_t		 keepalive;
	int			 gtsm_enabled;
	uint8_t			 gtsm_hops;
	struct {
		enum auth_method	 method;
		char			 md5key[TCP_MD5_KEY_LEN];
		uint8_t			 md5key_len;
	} auth;
	uint8_t			 flags;
	QOBJ_FIELDS
};
RB_HEAD(nbrp_head, nbr_params);
RB_PROTOTYPE(nbrp_head, nbr_params, entry, nbr_params_compare);
DECLARE_QOBJ_TYPE(nbr_params)
#define F_NBRP_KEEPALIVE	 0x01
#define F_NBRP_GTSM		 0x02
#define F_NBRP_GTSM_HOPS	 0x04

struct ldp_stats {
	uint32_t		 kalive_sent;
	uint32_t		 kalive_rcvd;
	uint32_t		 addr_sent;
	uint32_t		 addr_rcvd;
	uint32_t		 addrwdraw_sent;
	uint32_t		 addrwdraw_rcvd;
	uint32_t		 notif_sent;
	uint32_t		 notif_rcvd;
	uint32_t		 capability_sent;
	uint32_t		 capability_rcvd;
	uint32_t		 labelmap_sent;
	uint32_t		 labelmap_rcvd;
	uint32_t		 labelreq_sent;
	uint32_t		 labelreq_rcvd;
	uint32_t		 labelwdraw_sent;
	uint32_t		 labelwdraw_rcvd;
	uint32_t		 labelrel_sent;
	uint32_t		 labelrel_rcvd;
	uint32_t		 labelabreq_sent;
	uint32_t		 labelabreq_rcvd;
};

struct l2vpn_if {
	RB_ENTRY(l2vpn_if)	 entry;
	struct l2vpn		*l2vpn;
	char			 ifname[IF_NAMESIZE];
	unsigned int		 ifindex;
	int			 operative;
	uint8_t			 mac[ETH_ALEN];
	QOBJ_FIELDS
};
RB_HEAD(l2vpn_if_head, l2vpn_if);
RB_PROTOTYPE(l2vpn_if_head, l2vpn_if, entry, l2vpn_if_compare);
DECLARE_QOBJ_TYPE(l2vpn_if)

struct l2vpn_pw {
	RB_ENTRY(l2vpn_pw)	 entry;
	struct l2vpn		*l2vpn;
	struct in_addr		 lsr_id;
	int			 af;
	union ldpd_addr		 addr;
	uint32_t		 pwid;
	char			 ifname[IF_NAMESIZE];
	unsigned int		 ifindex;
	bool			 enabled;
	uint32_t		 remote_group;
	uint16_t		 remote_mtu;
	uint32_t		 local_status;
	uint32_t		 remote_status;
	uint8_t			 flags;
	QOBJ_FIELDS
};
RB_HEAD(l2vpn_pw_head, l2vpn_pw);
RB_PROTOTYPE(l2vpn_pw_head, l2vpn_pw, entry, l2vpn_pw_compare);
DECLARE_QOBJ_TYPE(l2vpn_pw)
#define F_PW_STATUSTLV_CONF	0x01	/* status tlv configured */
#define F_PW_STATUSTLV		0x02	/* status tlv negotiated */
#define F_PW_CWORD_CONF		0x04	/* control word configured */
#define F_PW_CWORD		0x08	/* control word negotiated */
#define F_PW_STATIC_NBR_ADDR	0x10	/* static neighbor address configured */

struct l2vpn {
	RB_ENTRY(l2vpn)		 entry;
	char			 name[L2VPN_NAME_LEN];
	int			 type;
	int			 pw_type;
	int			 mtu;
	char			 br_ifname[IF_NAMESIZE];
	unsigned int		 br_ifindex;
	struct l2vpn_if_head	 if_tree;
	struct l2vpn_pw_head	 pw_tree;
	struct l2vpn_pw_head	 pw_inactive_tree;
	QOBJ_FIELDS
};
RB_HEAD(l2vpn_head, l2vpn);
RB_PROTOTYPE(l2vpn_head, l2vpn, entry, l2vpn_compare);
DECLARE_QOBJ_TYPE(l2vpn)
#define L2VPN_TYPE_VPWS		1
#define L2VPN_TYPE_VPLS		2

/* ldp_conf */
enum ldpd_process {
	PROC_MAIN,
	PROC_LDP_ENGINE,
	PROC_LDE_ENGINE
} ldpd_process;

static const char * const log_procnames[] = {
	"parent",
	"ldpe",
	"lde"
};

enum socket_type {
	LDP_SOCKET_DISC,
	LDP_SOCKET_EDISC,
	LDP_SOCKET_SESSION
};

enum hello_type {
	HELLO_LINK,
	HELLO_TARGETED
};

struct ldpd_af_conf {
	uint16_t		 keepalive;
	uint16_t		 lhello_holdtime;
	uint16_t		 lhello_interval;
	uint16_t		 thello_holdtime;
	uint16_t		 thello_interval;
	union ldpd_addr		 trans_addr;
	char			 acl_thello_accept_from[ACL_NAMSIZ];
	char			 acl_label_allocate_for[ACL_NAMSIZ];
	char			 acl_label_advertise_to[ACL_NAMSIZ];
	char			 acl_label_advertise_for[ACL_NAMSIZ];
	char			 acl_label_expnull_for[ACL_NAMSIZ];
	char			 acl_label_accept_from[ACL_NAMSIZ];
	char			 acl_label_accept_for[ACL_NAMSIZ];
	int			 flags;
};
#define	F_LDPD_AF_ENABLED	0x0001
#define	F_LDPD_AF_THELLO_ACCEPT	0x0002
#define	F_LDPD_AF_EXPNULL	0x0004
#define	F_LDPD_AF_NO_GTSM	0x0008
#define	F_LDPD_AF_ALLOCHOSTONLY	0x0010

struct ldpd_conf {
	struct in_addr		 rtr_id;
	struct ldpd_af_conf	 ipv4;
	struct ldpd_af_conf	 ipv6;
	struct iface_head	 iface_tree;
	struct tnbr_head	 tnbr_tree;
	struct nbrp_head	 nbrp_tree;
	struct l2vpn_head	 l2vpn_tree;
	uint16_t		 lhello_holdtime;
	uint16_t		 lhello_interval;
	uint16_t		 thello_holdtime;
	uint16_t		 thello_interval;
	uint16_t		 trans_pref;
	int			 flags;
	QOBJ_FIELDS
};
DECLARE_QOBJ_TYPE(ldpd_conf)
#define	F_LDPD_NO_FIB_UPDATE	0x0001
#define	F_LDPD_DS_CISCO_INTEROP	0x0002
#define	F_LDPD_ENABLED		0x0004

struct ldpd_af_global {
	struct thread		*disc_ev;
	struct thread		*edisc_ev;
	int			 ldp_disc_socket;
	int			 ldp_edisc_socket;
	int			 ldp_session_socket;
};

struct ldpd_global {
	int			 cmd_opts;
	struct in_addr		 rtr_id;
	struct ldpd_af_global	 ipv4;
	struct ldpd_af_global	 ipv6;
	uint32_t		 conf_seqnum;
	int			 pfkeysock;
	struct if_addr_head	 addr_list;
	struct global_adj_head	 adj_tree;
	struct in_addr		 mcast_addr_v4;
	struct in6_addr		 mcast_addr_v6;
	TAILQ_HEAD(, pending_conn) pending_conns;
};

/* kroute */
struct kroute {
	int			 af;
	union ldpd_addr		 prefix;
	uint8_t			 prefixlen;
	union ldpd_addr		 nexthop;
	uint32_t		 local_label;
	uint32_t		 remote_label;
	unsigned short		 ifindex;
	uint8_t			 priority;
	uint16_t		 flags;
};

struct kaddr {
	char			 ifname[IF_NAMESIZE];
	unsigned short		 ifindex;
	int			 af;
	union ldpd_addr		 addr;
	uint8_t			 prefixlen;
	union ldpd_addr	 	 dstbrd;
};

struct kif {
	char			 ifname[IF_NAMESIZE];
	unsigned short		 ifindex;
	int			 flags;
	int			 operative;
	uint8_t			 mac[ETH_ALEN];
	int			 mtu;
};

struct acl_check {
	char			 acl[ACL_NAMSIZ];
	int			 af;
	union ldpd_addr		 addr;
	uint8_t			 prefixlen;
};

/* control data structures */
struct ctl_iface {
	int			 af;
	char			 name[IF_NAMESIZE];
	unsigned int		 ifindex;
	int			 state;
	enum iface_type		 type;
	uint16_t		 hello_holdtime;
	uint16_t		 hello_interval;
	time_t			 uptime;
	uint16_t		 adj_cnt;
};

struct ctl_disc_if {
	char			 name[IF_NAMESIZE];
	int			 active_v4;
	int			 active_v6;
	int			 no_adj;
};

struct ctl_disc_tnbr {
	int			 af;
	union ldpd_addr		 addr;
	int			 no_adj;
};

struct ctl_adj {
	int			 af;
	struct in_addr		 id;
	enum hello_type		 type;
	char			 ifname[IF_NAMESIZE];
	union ldpd_addr		 src_addr;
	uint16_t		 holdtime;
	uint16_t		 holdtime_remaining;
	union ldpd_addr		 trans_addr;
	int			 ds_tlv;
};

struct ctl_nbr {
	int			 af;
	struct in_addr		 id;
	union ldpd_addr		 laddr;
	in_port_t		 lport;
	union ldpd_addr		 raddr;
	in_port_t		 rport;
	enum auth_method	 auth_method;
	uint16_t		 holdtime;
	time_t			 uptime;
	int			 nbr_state;
	struct ldp_stats	 stats;
	int			 flags;
};

struct ctl_rt {
	int			 af;
	union ldpd_addr		 prefix;
	uint8_t			 prefixlen;
	struct in_addr		 nexthop;	/* lsr-id */
	uint32_t		 local_label;
	uint32_t		 remote_label;
	uint8_t			 flags;
	uint8_t			 in_use;
	int			 no_downstream;
};

struct ctl_pw {
	uint16_t		 type;
	char			 l2vpn_name[L2VPN_NAME_LEN];
	char			 ifname[IF_NAMESIZE];
	uint32_t		 pwid;
	struct in_addr		 lsr_id;
	uint32_t		 local_label;
	uint32_t		 local_gid;
	uint16_t		 local_ifmtu;
	uint8_t			 local_cword;
	uint32_t		 remote_label;
	uint32_t		 remote_gid;
	uint16_t		 remote_ifmtu;
	uint8_t			 remote_cword;
	uint32_t		 status;
};

extern struct ldpd_conf		*ldpd_conf, *vty_conf;
extern struct ldpd_global	 global;
extern struct ldpd_init		 init;

/* parse.y */
struct ldpd_conf	*parse_config(char *);
int			 cmdline_symset(char *);

/* kroute.c */
void		 pw2zpw(struct l2vpn_pw *, struct zapi_pw *);
void		 kif_redistribute(const char *);
int		 kr_change(struct kroute *);
int		 kr_delete(struct kroute *);
int		 kmpw_add(struct zapi_pw *);
int		 kmpw_del(struct zapi_pw *);
int		 kmpw_set(struct zapi_pw *);
int		 kmpw_unset(struct zapi_pw *);

/* util.c */
uint8_t		 mask2prefixlen(in_addr_t);
uint8_t		 mask2prefixlen6(struct sockaddr_in6 *);
in_addr_t	 prefixlen2mask(uint8_t);
struct in6_addr	*prefixlen2mask6(uint8_t);
void		 ldp_applymask(int, union ldpd_addr *,
		    const union ldpd_addr *, int);
int		 ldp_addrcmp(int, const union ldpd_addr *,
		    const union ldpd_addr *);
int		 ldp_addrisset(int, const union ldpd_addr *);
int		 ldp_prefixcmp(int, const union ldpd_addr *,
		    const union ldpd_addr *, uint8_t);
int		 bad_addr_v4(struct in_addr);
int		 bad_addr_v6(struct in6_addr *);
int		 bad_addr(int, union ldpd_addr *);
void		 embedscope(struct sockaddr_in6 *);
void		 recoverscope(struct sockaddr_in6 *);
void		 addscope(struct sockaddr_in6 *, uint32_t);
void		 clearscope(struct in6_addr *);
struct sockaddr	*addr2sa(int af, union ldpd_addr *, uint16_t);
void		 sa2addr(struct sockaddr *, int *, union ldpd_addr *,
		    in_port_t *);
socklen_t	 sockaddr_len(struct sockaddr *);

/* ldpd.c */
int			 ldp_write_handler(struct thread *);
void			 main_imsg_compose_ldpe(int, pid_t, void *, uint16_t);
void			 main_imsg_compose_lde(int, pid_t, void *, uint16_t);
int			 main_imsg_compose_both(enum imsg_type, void *,
			    uint16_t);
void			 imsg_event_add(struct imsgev *);
int			 imsg_compose_event(struct imsgev *, uint16_t, uint32_t,
			    pid_t, int, void *, uint16_t);
void			 evbuf_enqueue(struct evbuf *, struct ibuf *);
void			 evbuf_event_add(struct evbuf *);
void			 evbuf_init(struct evbuf *, int,
			    int (*)(struct thread *), void *);
void			 evbuf_clear(struct evbuf *);
int			 ldp_acl_request(struct imsgev *, char *, int,
			    union ldpd_addr *, uint8_t);
void			 ldp_acl_reply(struct imsgev *, struct acl_check *);
struct ldpd_af_conf	*ldp_af_conf_get(struct ldpd_conf *, int);
struct ldpd_af_global	*ldp_af_global_get(struct ldpd_global *, int);
int			 ldp_is_dual_stack(struct ldpd_conf *);
in_addr_t		 ldp_rtr_id_get(struct ldpd_conf *);
int			 ldp_config_apply(struct vty *, struct ldpd_conf *);
void			 ldp_clear_config(struct ldpd_conf *);
void			 merge_config(struct ldpd_conf *, struct ldpd_conf *);
struct ldpd_conf	*config_new_empty(void);
void			 config_clear(struct ldpd_conf *);

/* ldp_vty_conf.c */
/* NOTE: the parameters' names should be preserved because of codegen */
struct iface		*iface_new_api(struct ldpd_conf *conf,
			    const char *name);
void			 iface_del_api(struct ldpd_conf *conf,
			    struct iface *iface);
struct tnbr		*tnbr_new_api(struct ldpd_conf *conf, int af,
			    union ldpd_addr *addr);
void			 tnbr_del_api(struct ldpd_conf *conf, struct tnbr *tnbr);
struct nbr_params	*nbrp_new_api(struct ldpd_conf *conf,
			    struct in_addr lsr_id);
void			 nbrp_del_api(struct ldpd_conf *conf,
			    struct nbr_params *nbrp);
struct l2vpn		*l2vpn_new_api(struct ldpd_conf *conf, const char *name);
void			 l2vpn_del_api(struct ldpd_conf *conf,
			    struct l2vpn *l2vpn);
struct l2vpn_if		*l2vpn_if_new_api(struct ldpd_conf *conf,
			    struct l2vpn *l2vpn, const char *ifname);
void			 l2vpn_if_del_api(struct l2vpn *l2vpn,
			   struct l2vpn_if *lif);
struct l2vpn_pw		*l2vpn_pw_new_api(struct ldpd_conf *conf,
			    struct l2vpn *l2vpn, const char *ifname);
void			 l2vpn_pw_del_api(struct l2vpn *l2vpn,
			    struct l2vpn_pw *pw);

/* socket.c */
int		 ldp_create_socket(int, enum socket_type);
void		 sock_set_nonblock(int);
void		 sock_set_cloexec(int);
void		 sock_set_recvbuf(int);
int		 sock_set_reuse(int, int);
int		 sock_set_bindany(int, int);
int		 sock_set_md5sig(int, int, union ldpd_addr *, const char *);
int		 sock_set_ipv4_tos(int, int);
int		 sock_set_ipv4_pktinfo(int, int);
int		 sock_set_ipv4_recvdstaddr(int, int);
int		 sock_set_ipv4_recvif(int, int);
int		 sock_set_ipv4_minttl(int, int);
int		 sock_set_ipv4_ucast_ttl(int fd, int);
int		 sock_set_ipv4_mcast_ttl(int, uint8_t);
int		 sock_set_ipv4_mcast(struct iface *);
int		 sock_set_ipv4_mcast_loop(int);
int		 sock_set_ipv6_dscp(int, int);
int		 sock_set_ipv6_pktinfo(int, int);
int		 sock_set_ipv6_minhopcount(int, int);
int		 sock_set_ipv6_ucast_hops(int, int);
int		 sock_set_ipv6_mcast_hops(int, int);
int		 sock_set_ipv6_mcast(struct iface *);
int		 sock_set_ipv6_mcast_loop(int);

/* logmsg.h */
struct in6_addr;
union ldpd_addr;
struct hello_source;
struct fec;

const char	*log_sockaddr(void *);
const char	*log_in6addr(const struct in6_addr *);
const char	*log_in6addr_scope(const struct in6_addr *, unsigned int);
const char	*log_addr(int, const union ldpd_addr *);
char		*log_label(uint32_t);
const char	*log_time(time_t);
char		*log_hello_src(const struct hello_source *);
const char	*log_map(const struct map *);
const char	*log_fec(const struct fec *);
const char	*af_name(int);
const char	*socket_name(int);
const char	*nbr_state_name(int);
const char	*if_state_name(int);
const char	*if_type_name(enum iface_type);
const char	*msg_name(uint16_t);
const char	*status_code_name(uint32_t);
const char	*pw_type_name(uint16_t);

/* quagga */
extern struct thread_master	*master;
extern char			 ctl_sock_path[MAXPATHLEN];

/* ldp_zebra.c */
void		 ldp_zebra_init(struct thread_master *);
void		 ldp_zebra_destroy(void);

/* compatibility */
#ifndef __OpenBSD__
#define __IPV6_ADDR_MC_SCOPE(a)		((a)->s6_addr[1] & 0x0f)
#define __IPV6_ADDR_SCOPE_INTFACELOCAL	0x01
#define	IN6_IS_ADDR_MC_INTFACELOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	(__IPV6_ADDR_MC_SCOPE(a) == __IPV6_ADDR_SCOPE_INTFACELOCAL))
#endif

#endif	/* _LDPD_H_ */
