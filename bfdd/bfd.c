/*********************************************************************
 * Copyright 2013 Cumulus Networks, LLC.  All rights reserved.
 * Copyright 2014,2015,2016,2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * bfd.c: implements the BFD protocol.
 *
 * Authors
 * -------
 * Shrijeet Mukherjee [shm@cumulusnetworks.com]
 * Kanna Rajagopal [kanna@cumulusnetworks.com]
 * Radhika Mahankali [Radhika@cumulusnetworks.com]
 */

#include <zebra.h>

#include "lib/jhash.h"

#include "bfd.h"

DEFINE_QOBJ_TYPE(bfd_session);

/*
 * Prototypes
 */
static uint32_t ptm_bfd_gen_ID(void);
static void ptm_bfd_echo_xmt_TO(struct bfd_session *bfd);
static void bfd_session_free(struct bfd_session *bs);
static struct bfd_session *bfd_session_new(int sd);
static struct bfd_session *bfd_find_disc(struct sockaddr_any *sa,
					 uint32_t ldisc);
static int bfd_session_update(struct bfd_session *bs, struct bfd_peer_cfg *bpc);
static const char *get_diag_str(int diag);


/*
 * Functions
 */
struct bfd_session *bs_peer_find(struct bfd_peer_cfg *bpc)
{
	struct bfd_session *bs;
	struct peer_label *pl;
	struct bfd_mhop_key mhop;
	struct bfd_shop_key shop;

	/* Try to find label first. */
	if (bpc->bpc_has_label) {
		pl = pl_find(bpc->bpc_label);
		if (pl != NULL) {
			bs = pl->pl_bs;
			return bs;
		}
	}

	/* Otherwise fallback to peer/local hash lookup. */
	if (bpc->bpc_mhop) {
		memset(&mhop, 0, sizeof(mhop));
		mhop.peer = bpc->bpc_peer;
		mhop.local = bpc->bpc_local;
		if (bpc->bpc_has_vrfname)
			strlcpy(mhop.vrf_name, bpc->bpc_vrfname,
				sizeof(mhop.vrf_name));

		bs = bfd_mhop_lookup(mhop);
	} else {
		memset(&shop, 0, sizeof(shop));
		shop.peer = bpc->bpc_peer;
		if (!bpc->bpc_has_vxlan && bpc->bpc_has_localif)
			strlcpy(shop.port_name, bpc->bpc_localif,
				sizeof(shop.port_name));

		bs = bfd_shop_lookup(shop);
	}

	return bs;
}

static uint32_t ptm_bfd_gen_ID(void)
{
	static uint32_t sessionID = 1;

	return (sessionID++);
}

void ptm_bfd_start_xmt_timer(struct bfd_session *bfd, bool is_echo)
{
	uint64_t jitter, xmt_TO;
	int maxpercent;

	xmt_TO = is_echo ? bfd->echo_xmt_TO : bfd->xmt_TO;

	/*
	 * From section 6.5.2: trasmit interval should be randomly jittered
	 * between
	 * 75% and 100% of nominal value, unless detect_mult is 1, then should
	 * be
	 * between 75% and 90%.
	 */
	maxpercent = (bfd->detect_mult == 1) ? 16 : 26;
	jitter = (xmt_TO * (75 + (random() % maxpercent))) / 100;
	/* XXX remove that division above */

	if (is_echo)
		bfd_echo_xmttimer_update(bfd, jitter);
	else
		bfd_xmttimer_update(bfd, jitter);
}

static void ptm_bfd_echo_xmt_TO(struct bfd_session *bfd)
{
	/* Send the scheduled echo  packet */
	ptm_bfd_echo_snd(bfd);

	/* Restart the timer for next time */
	ptm_bfd_start_xmt_timer(bfd, true);
}

void ptm_bfd_xmt_TO(struct bfd_session *bfd, int fbit)
{
	/* Send the scheduled control packet */
	ptm_bfd_snd(bfd, fbit);

	/* Restart the timer for next time */
	ptm_bfd_start_xmt_timer(bfd, false);
}

void ptm_bfd_echo_stop(struct bfd_session *bfd, int polling)
{
	bfd->echo_xmt_TO = 0;
	bfd->echo_detect_TO = 0;
	BFD_UNSET_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE);

	bfd_echo_xmttimer_delete(bfd);
	bfd_echo_recvtimer_delete(bfd);

	if (polling) {
		bfd->polling = polling;
		bfd->new_timers.desired_min_tx = bfd->up_min_tx;
		bfd->new_timers.required_min_rx = bfd->timers.required_min_rx;
		ptm_bfd_snd(bfd, 0);
	}
}

void ptm_bfd_echo_start(struct bfd_session *bfd)
{
	bfd->echo_detect_TO = (bfd->remote_detect_mult * bfd->echo_xmt_TO);
	ptm_bfd_echo_xmt_TO(bfd);

	bfd->polling = 1;
	bfd->new_timers.desired_min_tx = bfd->up_min_tx;
	bfd->new_timers.required_min_rx = bfd->timers.required_min_rx;
	ptm_bfd_snd(bfd, 0);
}

void ptm_bfd_ses_up(struct bfd_session *bfd)
{
	int old_state = bfd->ses_state;

	bfd->local_diag = 0;
	bfd->ses_state = PTM_BFD_UP;
	bfd->polling = 1;
	monotime(&bfd->uptime);

	/* If the peer is capable to receiving Echo pkts */
	if (bfd->echo_xmt_TO && !BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_MH)) {
		ptm_bfd_echo_start(bfd);
	} else {
		bfd->new_timers.desired_min_tx = bfd->up_min_tx;
		bfd->new_timers.required_min_rx = bfd->timers.required_min_rx;
		ptm_bfd_snd(bfd, 0);
	}

	control_notify(bfd);

	if (old_state != bfd->ses_state)
		log_info("state-change: [%s] %s -> %s", bs_to_string(bfd),
			 state_list[old_state].str,
			 state_list[bfd->ses_state].str);
}

void ptm_bfd_ses_dn(struct bfd_session *bfd, uint8_t diag)
{
	int old_state = bfd->ses_state;

	bfd->local_diag = diag;
	bfd->discrs.remote_discr = 0;
	bfd->ses_state = PTM_BFD_DOWN;
	bfd->polling = 0;
	bfd->demand_mode = 0;
	monotime(&bfd->downtime);

	ptm_bfd_snd(bfd, 0);

	/* only signal clients when going from up->down state */
	if (old_state == PTM_BFD_UP)
		control_notify(bfd);

	/* Stop echo packet transmission if they are active */
	if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE))
		ptm_bfd_echo_stop(bfd, 0);

	if (old_state != bfd->ses_state)
		log_info("state-change: [%s] %s -> %s reason:%s",
			 bs_to_string(bfd), state_list[old_state].str,
			 state_list[bfd->ses_state].str,
			 get_diag_str(bfd->local_diag));
}

static int ptm_bfd_get_vrf_name(char *port_name, char *vrf_name)
{
	struct bfd_iface *iface;
	struct bfd_vrf *vrf;

	if ((port_name == NULL) || (vrf_name == NULL))
		return -1;

	iface = bfd_iface_lookup(port_name);
	if (iface) {
		vrf = bfd_vrf_lookup(iface->vrf_id);
		if (vrf) {
			strlcpy(vrf_name, vrf->name, sizeof(vrf->name));
			return 0;
		}
	}
	return -1;
}

static struct bfd_session *bfd_find_disc(struct sockaddr_any *sa,
					 uint32_t ldisc)
{
	struct bfd_session *bs;

	bs = bfd_id_lookup(ldisc);
	if (bs == NULL)
		return NULL;

	/* Remove unused fields. */
	switch (sa->sa_sin.sin_family) {
	case AF_INET:
		sa->sa_sin.sin_port = 0;
		if (memcmp(sa, &bs->shop.peer, sizeof(sa->sa_sin)) == 0)
			return bs;
		break;
	case AF_INET6:
		sa->sa_sin6.sin6_port = 0;
		if (memcmp(sa, &bs->shop.peer, sizeof(sa->sa_sin6)) == 0)
			return bs;
		break;
	}

	return NULL;
}

struct bfd_session *ptm_bfd_sess_find(struct bfd_pkt *cp, char *port_name,
				      struct sockaddr_any *peer,
				      struct sockaddr_any *local,
				      char *vrf_name, bool is_mhop)
{
	struct bfd_session *l_bfd = NULL;
	struct bfd_mhop_key mhop;
	struct bfd_shop_key shop;
	char vrf_buf[MAXNAMELEN];

	/* Find our session using the ID signaled by the remote end. */
	if (cp->discrs.remote_discr)
		return bfd_find_disc(peer, ntohl(cp->discrs.remote_discr));

	/* Search for session without using discriminator. */
	if (is_mhop) {
		memset(&mhop, 0, sizeof(mhop));
		mhop.peer = *peer;
		mhop.local = *local;
		if (vrf_name && vrf_name[0]) {
			strlcpy(mhop.vrf_name, vrf_name, sizeof(mhop.vrf_name));
		} else if (port_name && port_name[0]) {
			memset(vrf_buf, 0, sizeof(vrf_buf));
			if (ptm_bfd_get_vrf_name(port_name, vrf_buf) != -1)
				strlcpy(mhop.vrf_name, vrf_buf,
					sizeof(mhop.vrf_name));
		}

		l_bfd = bfd_mhop_lookup(mhop);
	} else {
		memset(&shop, 0, sizeof(shop));
		shop.peer = *peer;
		if (port_name && port_name[0])
			strlcpy(shop.port_name, port_name,
				sizeof(shop.port_name));

		l_bfd = bfd_shop_lookup(shop);
	}

	/* XXX maybe remoteDiscr should be checked for remoteHeard cases. */
	return l_bfd;
}

#if 0  /* TODO VxLAN Support */
static void
_update_vxlan_sess_parms(struct bfd_session *bfd, bfd_sess_parms *sess_parms)
{
	struct bfd_session_vxlan_info *vxlan_info = &bfd->vxlan_info;
	bfd_parms_list *parms = &sess_parms->parms;

	vxlan_info->vnid = parms->vnid;
	vxlan_info->check_tnl_key = parms->check_tnl_key;
	vxlan_info->forwarding_if_rx = parms->forwarding_if_rx;
	vxlan_info->cpath_down = parms->cpath_down;
	vxlan_info->decay_min_rx = parms->decay_min_rx;

	inet_aton(parms->local_dst_ip, &vxlan_info->local_dst_ip);
	inet_aton(parms->remote_dst_ip, &vxlan_info->peer_dst_ip);

	memcpy(vxlan_info->local_dst_mac, parms->local_dst_mac, ETH_ALEN);
	memcpy(vxlan_info->peer_dst_mac, parms->remote_dst_mac, ETH_ALEN);

	/* The interface may change for Vxlan BFD sessions, so update
	 * the local mac and ifindex
	 */
	bfd->ifindex = sess_parms->ifindex;
	memcpy(bfd->local_mac, sess_parms->local_mac, sizeof(bfd->local_mac));
}
#endif /* VxLAN support */

int bfd_xmt_cb(struct thread *t)
{
	struct bfd_session *bs = THREAD_ARG(t);

	ptm_bfd_xmt_TO(bs, 0);

	return 0;
}

int bfd_echo_xmt_cb(struct thread *t)
{
	struct bfd_session *bs = THREAD_ARG(t);

	ptm_bfd_echo_xmt_TO(bs);

	return 0;
}

/* Was ptm_bfd_detect_TO() */
int bfd_recvtimer_cb(struct thread *t)
{
	struct bfd_session *bs = THREAD_ARG(t);

	switch (bs->ses_state) {
	case PTM_BFD_INIT:
	case PTM_BFD_UP:
		ptm_bfd_ses_dn(bs, BFD_DIAGDETECTTIME);
		bfd_recvtimer_update(bs);
		break;

	default:
		/* Second detect time expiration, zero remote discr (section
		 * 6.5.1)
		 */
		bs->discrs.remote_discr = 0;
		break;
	}

	return 0;
}

/* Was ptm_bfd_echo_detect_TO() */
int bfd_echo_recvtimer_cb(struct thread *t)
{
	struct bfd_session *bs = THREAD_ARG(t);

	switch (bs->ses_state) {
	case PTM_BFD_INIT:
	case PTM_BFD_UP:
		ptm_bfd_ses_dn(bs, BFD_DIAGDETECTTIME);
		break;
	}

	return 0;
}

static struct bfd_session *bfd_session_new(int sd)
{
	struct bfd_session *bs;

	bs = XCALLOC(MTYPE_BFDD_CONFIG, sizeof(*bs));
	if (bs == NULL)
		return NULL;

	QOBJ_REG(bs, bfd_session);

	bs->up_min_tx = BFD_DEFDESIREDMINTX;
	bs->timers.required_min_rx = BFD_DEFREQUIREDMINRX;
	bs->timers.required_min_echo = BFD_DEF_REQ_MIN_ECHO;
	bs->detect_mult = BFD_DEFDETECTMULT;
	bs->mh_ttl = BFD_DEF_MHOP_TTL;

	bs->sock = sd;
	monotime(&bs->uptime);
	bs->downtime = bs->uptime;

	return bs;
}

int bfd_session_update_label(struct bfd_session *bs, const char *nlabel)
{
	/* New label treatment:
	 * - Check if the label is taken;
	 * - Try to allocate the memory for it and register;
	 */
	if (bs->pl == NULL) {
		if (pl_find(nlabel) != NULL) {
			/* Someone is already using it. */
			return -1;
		}

		if (pl_new(nlabel, bs) == NULL)
			return -1;

		return 0;
	}

	/*
	 * Test label change consistency:
	 * - Do nothing if it's the same label;
	 * - Check if the future label is already taken;
	 * - Change label;
	 */
	if (strcmp(nlabel, bs->pl->pl_label) == 0)
		return -1;
	if (pl_find(nlabel) != NULL)
		return -1;

	strlcpy(bs->pl->pl_label, nlabel, sizeof(bs->pl->pl_label));
	return 0;
}

static void _bfd_session_update(struct bfd_session *bs,
				struct bfd_peer_cfg *bpc)
{
	if (bpc->bpc_echo) {
		/* Check if echo mode is already active. */
		if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO))
			goto skip_echo;

		BFD_SET_FLAG(bs->flags, BFD_SESS_FLAG_ECHO);
		ptm_bfd_echo_start(bs);

		/* Activate/update echo receive timeout timer. */
		bfd_echo_recvtimer_update(bs);
	} else {
		/* Check if echo mode is already disabled. */
		if (!BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO))
			goto skip_echo;

		BFD_UNSET_FLAG(bs->flags, BFD_SESS_FLAG_ECHO);
		ptm_bfd_echo_stop(bs, 0);
	}

skip_echo:
	if (bpc->bpc_has_txinterval)
		bs->up_min_tx = bpc->bpc_txinterval * 1000;

	if (bpc->bpc_has_recvinterval)
		bs->timers.required_min_rx = bpc->bpc_recvinterval * 1000;

	if (bpc->bpc_has_detectmultiplier)
		bs->detect_mult = bpc->bpc_detectmultiplier;

	if (bpc->bpc_has_echointerval)
		bs->timers.required_min_echo = bpc->bpc_echointerval * 1000;

	if (bpc->bpc_has_label)
		bfd_session_update_label(bs, bpc->bpc_label);

	if (bpc->bpc_shutdown) {
		/* Check if already shutdown. */
		if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN))
			return;

		BFD_SET_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN);

		/* Disable all events. */
		bfd_recvtimer_delete(bs);
		bfd_echo_recvtimer_delete(bs);
		bfd_xmttimer_delete(bs);
		bfd_echo_xmttimer_delete(bs);

		/* Change and notify state change. */
		bs->ses_state = PTM_BFD_ADM_DOWN;
		control_notify(bs);

		ptm_bfd_snd(bs, 0);
	} else {
		/* Check if already working. */
		if (!BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN))
			return;

		BFD_UNSET_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN);

		/* Change and notify state change. */
		bs->ses_state = PTM_BFD_DOWN;
		control_notify(bs);

		/* Enable all timers. */
		bfd_recvtimer_update(bs);
		bfd_xmttimer_update(bs, bs->xmt_TO);
		if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO)) {
			bfd_echo_recvtimer_update(bs);
			bfd_echo_xmttimer_update(bs, bs->echo_xmt_TO);
		}
	}
}

static int bfd_session_update(struct bfd_session *bs, struct bfd_peer_cfg *bpc)
{
	/* User didn't want to update, return failure. */
	if (bpc->bpc_createonly)
		return -1;

	_bfd_session_update(bs, bpc);

	/* TODO add VxLAN support. */

	control_notify_config(BCM_NOTIFY_CONFIG_UPDATE, bs);

	return 0;
}

static void bfd_session_free(struct bfd_session *bs)
{
	if (bs->sock != -1)
		close(bs->sock);

	bfd_recvtimer_delete(bs);
	bfd_echo_recvtimer_delete(bs);
	bfd_xmttimer_delete(bs);
	bfd_echo_xmttimer_delete(bs);

	bfd_id_delete(bs->discrs.my_discr);
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH))
		bfd_mhop_delete(bs->mhop);
	else
		bfd_shop_delete(bs->shop);

	pl_free(bs->pl);

	QOBJ_UNREG(bs);
	XFREE(MTYPE_BFDD_CONFIG, bs);
}

struct bfd_session *ptm_bfd_sess_new(struct bfd_peer_cfg *bpc)
{
	struct bfd_session *bfd, *l_bfd;
	int psock;

	/* check to see if this needs a new session */
	l_bfd = bs_peer_find(bpc);
	if (l_bfd) {
		/* Requesting a duplicated peer means update configuration. */
		if (bfd_session_update(l_bfd, bpc) == 0)
			return l_bfd;
		else
			return NULL;
	}

	/*
	 * Get socket for transmitting control packets.  Note that if we
	 * could use the destination port (3784) for the source
	 * port we wouldn't need a socket per session.
	 */
	if (bpc->bpc_ipv4) {
		psock = bp_peer_socket(bpc);
		if (psock == -1)
			return NULL;
	} else {
		psock = bp_peer_socketv6(bpc);
		if (psock == -1)
			return NULL;
	}

	/* Get memory */
	bfd = bfd_session_new(psock);
	if (bfd == NULL) {
		log_error("session-new: allocation failed");
		return NULL;
	}

	if (bpc->bpc_has_localif && !bpc->bpc_mhop) {
		bfd->ifindex = ptm_bfd_fetch_ifindex(bpc->bpc_localif);
		ptm_bfd_fetch_local_mac(bpc->bpc_localif, bfd->local_mac);
	}

	if (bpc->bpc_has_vxlan)
		BFD_SET_FLAG(bfd->flags, BFD_SESS_FLAG_VXLAN);

	if (bpc->bpc_ipv4 == false)
		BFD_SET_FLAG(bfd->flags, BFD_SESS_FLAG_IPV6);

	/* Initialize the session */
	bfd->ses_state = PTM_BFD_DOWN;
	bfd->discrs.my_discr = ptm_bfd_gen_ID();
	bfd->discrs.remote_discr = 0;
	bfd->local_ip = bpc->bpc_local;
	bfd->local_address = bpc->bpc_local;
	bfd->timers.desired_min_tx = bfd->up_min_tx;
	bfd->detect_TO = (bfd->detect_mult * BFD_DEF_SLOWTX);

	/* Use detect_TO first for slow detection, then use recvtimer_update. */
	bfd_recvtimer_update(bfd);

	bfd_id_insert(bfd);

	if (bpc->bpc_mhop) {
		BFD_SET_FLAG(bfd->flags, BFD_SESS_FLAG_MH);
		bfd->mhop.peer = bpc->bpc_peer;
		bfd->mhop.local = bpc->bpc_local;
		if (bpc->bpc_has_vrfname)
			strlcpy(bfd->mhop.vrf_name, bpc->bpc_vrfname,
				sizeof(bfd->mhop.vrf_name));

		bfd_mhop_insert(bfd);
	} else {
		bfd->shop.peer = bpc->bpc_peer;
		if (!bpc->bpc_has_vxlan && bpc->bpc_has_localif)
			strlcpy(bfd->shop.port_name, bpc->bpc_localif,
				sizeof(bfd->shop.port_name));

		bfd_shop_insert(bfd);
	}

	if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_VXLAN)) {
		static uint8_t bfd_def_vxlan_dmac[] = {0x00, 0x23, 0x20,
						       0x00, 0x00, 0x01};
		memcpy(bfd->peer_mac, bfd_def_vxlan_dmac,
		       sizeof(bfd_def_vxlan_dmac));
	}
#if 0 /* TODO */
	else if (event->rmac) {
		if (sscanf(event->rmac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		    &bfd->peer_mac[0], &bfd->peer_mac[1], &bfd->peer_mac[2],
		    &bfd->peer_mac[3], &bfd->peer_mac[4], &bfd->peer_mac[5])
		    != 6)
			DLOG("%s: Assigning remote mac = %s", __func__,
			     event->rmac);
	}
#endif

	/*
	 * XXX: session update triggers echo start, so we must have our
	 * discriminator ID set first.
	 */
	_bfd_session_update(bfd, bpc);

	/* Start transmitting with slow interval until peer responds */
	bfd->xmt_TO = BFD_DEF_SLOWTX;

	ptm_bfd_xmt_TO(bfd, 0);

	log_info("session-new: %s", bs_to_string(bfd));

	control_notify_config(BCM_NOTIFY_CONFIG_ADD, bfd);

	return bfd;
}

int ptm_bfd_ses_del(struct bfd_peer_cfg *bpc)
{
	struct bfd_session *bs;

	/* Find session and call free(). */
	bs = bs_peer_find(bpc);
	if (bs == NULL)
		return -1;

	/* This pointer is being referenced, don't let it be deleted. */
	if (bs->refcount > 0) {
		log_error("session-delete: refcount failure: %" PRIu64
			  " references",
			  bs->refcount);
		return -1;
	}

	log_info("session-delete: %s", bs_to_string(bs));

	control_notify_config(BCM_NOTIFY_CONFIG_DELETE, bs);

	bfd_session_free(bs);

	return 0;
}

void bfd_set_polling(struct bfd_session *bs)
{
	bs->new_timers.desired_min_tx = bs->up_min_tx;
	bs->new_timers.required_min_rx = bs->timers.required_min_rx;
	bs->new_timers.required_min_echo = bs->timers.required_min_echo;
	bs->polling = 1;
}


/*
 * Helper functions.
 */
static const char *get_diag_str(int diag)
{
	for (int i = 0; diag_list[i].str; i++) {
		if (diag_list[i].type == diag)
			return diag_list[i].str;
	}
	return "N/A";
}

const char *satostr(struct sockaddr_any *sa)
{
#define INETSTR_BUFCOUNT 8
	static char buf[INETSTR_BUFCOUNT][INET6_ADDRSTRLEN];
	static int bufidx;
	struct sockaddr_in *sin = &sa->sa_sin;
	struct sockaddr_in6 *sin6 = &sa->sa_sin6;

	bufidx += (bufidx + 1) % INETSTR_BUFCOUNT;
	buf[bufidx][0] = 0;

	switch (sin->sin_family) {
	case AF_INET:
		inet_ntop(AF_INET, &sin->sin_addr, buf[bufidx],
			  sizeof(buf[bufidx]));
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &sin6->sin6_addr, buf[bufidx],
			  sizeof(buf[bufidx]));
		break;

	default:
		strlcpy(buf[bufidx], "unknown", sizeof(buf[bufidx]));
		break;
	}

	return buf[bufidx];
}

const char *diag2str(uint8_t diag)
{
	switch (diag) {
	case 0:
		return "ok";
	case 1:
		return "control detection time expired";
	case 2:
		return "echo function failed";
	case 3:
		return "neighbor signaled session down";
	case 4:
		return "forwarding plane reset";
	case 5:
		return "path down";
	case 6:
		return "concatenated path down";
	case 7:
		return "administratively down";
	case 8:
		return "reverse concatenated path down";
	default:
		return "unknown";
	}
}

int strtosa(const char *addr, struct sockaddr_any *sa)
{
	memset(sa, 0, sizeof(*sa));

	if (inet_pton(AF_INET, addr, &sa->sa_sin.sin_addr) == 1) {
		sa->sa_sin.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sa->sa_sin.sin_len = sizeof(sa->sa_sin);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
		return 0;
	}

	if (inet_pton(AF_INET6, addr, &sa->sa_sin6.sin6_addr) == 1) {
		sa->sa_sin6.sin6_family = AF_INET6;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sa->sa_sin6.sin6_len = sizeof(sa->sa_sin6);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
		return 0;
	}

	return -1;
}

void integer2timestr(uint64_t time, char *buf, size_t buflen)
{
	unsigned int year, month, day, hour, minute, second;
	int rv;

#define MINUTES (60)
#define HOURS (24 * MINUTES)
#define DAYS (30 * HOURS)
#define MONTHS (12 * DAYS)
#define YEARS (MONTHS)
	if (time >= YEARS) {
		year = time / YEARS;
		time -= year * YEARS;

		rv = snprintf(buf, buflen, "%u year(s), ", year);
		buf += rv;
		buflen -= rv;
	}
	if (time >= MONTHS) {
		month = time / MONTHS;
		time -= month * MONTHS;

		rv = snprintf(buf, buflen, "%u month(s), ", month);
		buf += rv;
		buflen -= rv;
	}
	if (time >= DAYS) {
		day = time / DAYS;
		time -= day * DAYS;

		rv = snprintf(buf, buflen, "%u day(s), ", day);
		buf += rv;
		buflen -= rv;
	}
	if (time >= HOURS) {
		hour = time / HOURS;
		time -= hour * HOURS;

		rv = snprintf(buf, buflen, "%u hour(s), ", hour);
		buf += rv;
		buflen -= rv;
	}
	if (time >= MINUTES) {
		minute = time / MINUTES;
		time -= minute * MINUTES;

		rv = snprintf(buf, buflen, "%u minute(s), ", minute);
		buf += rv;
		buflen -= rv;
	}
	second = time % MINUTES;
	snprintf(buf, buflen, "%u second(s)", second);
}

const char *bs_to_string(struct bfd_session *bs)
{
	static char buf[256];
	int pos;
	bool is_mhop = BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH);

	pos = snprintf(buf, sizeof(buf), "mhop:%s", is_mhop ? "yes" : "no");
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH)) {
		pos += snprintf(buf + pos, sizeof(buf) - pos,
				" peer:%s local:%s", satostr(&bs->mhop.peer),
				satostr(&bs->mhop.local));

		if (bs->mhop.vrf_name[0])
			snprintf(buf + pos, sizeof(buf) - pos, " vrf:%s",
				 bs->mhop.vrf_name);
	} else {
		pos += snprintf(buf + pos, sizeof(buf) - pos, " peer:%s",
				satostr(&bs->shop.peer));

		if (bs->local_address.sa_sin.sin_family)
			pos += snprintf(buf + pos, sizeof(buf) - pos,
					" local:%s",
					satostr(&bs->local_address));

		if (bs->shop.port_name[0])
			snprintf(buf + pos, sizeof(buf) - pos, " interface:%s",
				 bs->shop.port_name);
	}

	return buf;
}


/*
 * BFD hash data structures to find sessions.
 */
static struct hash *bfd_id_hash;
static struct hash *bfd_shop_hash;
static struct hash *bfd_mhop_hash;
static struct hash *bfd_vrf_hash;
static struct hash *bfd_iface_hash;

static unsigned int bfd_id_hash_do(void *p);
static int bfd_id_hash_cmp(const void *n1, const void *n2);
static unsigned int bfd_shop_hash_do(void *p);
static int bfd_shop_hash_cmp(const void *n1, const void *n2);
static unsigned int bfd_mhop_hash_do(void *p);
static int bfd_mhop_hash_cmp(const void *n1, const void *n2);
static unsigned int bfd_vrf_hash_do(void *p);
static int bfd_vrf_hash_cmp(const void *n1, const void *n2);
static unsigned int bfd_iface_hash_do(void *p);
static int bfd_iface_hash_cmp(const void *n1, const void *n2);

static void _shop_key(struct bfd_session *bs, const struct bfd_shop_key *shop);
static void _shop_key2(struct bfd_session *bs, const struct bfd_shop_key *shop);
static void _mhop_key(struct bfd_session *bs, const struct bfd_mhop_key *mhop);
static int _iface_key(struct bfd_iface *iface, const char *ifname);

static void _bfd_free(struct hash_backet *hb,
		      void *arg __attribute__((__unused__)));
static void _vrf_free(void *arg);
static void _iface_free(void *arg);

/* BFD hash for our discriminator. */
static unsigned int bfd_id_hash_do(void *p)
{
	struct bfd_session *bs = p;

	return jhash_1word(bs->discrs.my_discr, 0);
}

static int bfd_id_hash_cmp(const void *n1, const void *n2)
{
	const struct bfd_session *bs1 = n1, *bs2 = n2;

	return bs1->discrs.my_discr == bs2->discrs.my_discr;
}

/* BFD hash for single hop. */
static unsigned int bfd_shop_hash_do(void *p)
{
	struct bfd_session *bs = p;

	return jhash(&bs->shop, sizeof(bs->shop), 0);
}

static int bfd_shop_hash_cmp(const void *n1, const void *n2)
{
	const struct bfd_session *bs1 = n1, *bs2 = n2;

	return memcmp(&bs1->shop, &bs2->shop, sizeof(bs1->shop)) == 0;
}

/* BFD hash for multi hop. */
static unsigned int bfd_mhop_hash_do(void *p)
{
	struct bfd_session *bs = p;

	return jhash(&bs->mhop, sizeof(bs->mhop), 0);
}

static int bfd_mhop_hash_cmp(const void *n1, const void *n2)
{
	const struct bfd_session *bs1 = n1, *bs2 = n2;

	return memcmp(&bs1->mhop, &bs2->mhop, sizeof(bs1->mhop)) == 0;
}

/* BFD hash for VRFs. */
static unsigned int bfd_vrf_hash_do(void *p)
{
	struct bfd_vrf *vrf = p;

	return jhash_1word(vrf->vrf_id, 0);
}

static int bfd_vrf_hash_cmp(const void *n1, const void *n2)
{
	const struct bfd_vrf *v1 = n1, *v2 = n2;

	return v1->vrf_id == v2->vrf_id;
}

/* BFD hash for interfaces. */
static unsigned int bfd_iface_hash_do(void *p)
{
	struct bfd_iface *iface = p;

	return string_hash_make(iface->ifname);
}

static int bfd_iface_hash_cmp(const void *n1, const void *n2)
{
	const struct bfd_iface *i1 = n1, *i2 = n2;

	return strcmp(i1->ifname, i2->ifname) == 0;
}

/* Helper functions */
static void _shop_key(struct bfd_session *bs, const struct bfd_shop_key *shop)
{
	bs->shop = *shop;

	/* Remove unused fields. */
	switch (bs->shop.peer.sa_sin.sin_family) {
	case AF_INET:
		bs->shop.peer.sa_sin.sin_port = 0;
		break;
	case AF_INET6:
		bs->shop.peer.sa_sin6.sin6_port = 0;
		break;
	}
}

static void _shop_key2(struct bfd_session *bs, const struct bfd_shop_key *shop)
{
	_shop_key(bs, shop);
	memset(bs->shop.port_name, 0, sizeof(bs->shop.port_name));
}

static void _mhop_key(struct bfd_session *bs, const struct bfd_mhop_key *mhop)
{
	bs->mhop = *mhop;

	/* Remove unused fields. */
	switch (bs->mhop.peer.sa_sin.sin_family) {
	case AF_INET:
		bs->mhop.peer.sa_sin.sin_port = 0;
		bs->mhop.local.sa_sin.sin_port = 0;
		break;
	case AF_INET6:
		bs->mhop.peer.sa_sin6.sin6_port = 0;
		bs->mhop.local.sa_sin6.sin6_port = 0;
		break;
	}
}

static int _iface_key(struct bfd_iface *iface, const char *ifname)
{
	size_t slen = sizeof(iface->ifname);

	memset(iface->ifname, 0, slen);
	if (strlcpy(iface->ifname, ifname, slen) >= slen)
		return -1;

	return 0;
}

/*
 * Hash public interface / exported functions.
 */

/* Lookup functions. */
struct bfd_session *bfd_id_lookup(uint32_t id)
{
	struct bfd_session bs;

	bs.discrs.my_discr = id;

	return hash_lookup(bfd_id_hash, &bs);
}

struct bfd_session *bfd_shop_lookup(struct bfd_shop_key shop)
{
	struct bfd_session bs, *bsp;

	_shop_key(&bs, &shop);

	bsp = hash_lookup(bfd_shop_hash, &bs);
	if (bsp == NULL && bs.shop.port_name[0] != 0) {
		/*
		 * Since the local interface spec is optional, try
		 * searching the key without it as well.
		 */
		_shop_key2(&bs, &shop);
		bsp = hash_lookup(bfd_shop_hash, &bs);
	}

	return bsp;
}

struct bfd_session *bfd_mhop_lookup(struct bfd_mhop_key mhop)
{
	struct bfd_session bs;

	_mhop_key(&bs, &mhop);

	return hash_lookup(bfd_shop_hash, &bs);
}

struct bfd_vrf *bfd_vrf_lookup(int vrf_id)
{
	struct bfd_vrf vrf;

	vrf.vrf_id = vrf_id;

	return hash_lookup(bfd_vrf_hash, &vrf);
}

struct bfd_iface *bfd_iface_lookup(const char *ifname)
{
	struct bfd_iface iface;

	if (_iface_key(&iface, ifname) != 0)
		return NULL;

	return hash_lookup(bfd_iface_hash, &iface);
}

/*
 * Delete functions.
 *
 * Delete functions searches and remove the item from the hash and
 * returns a pointer to the removed item data. If the item was not found
 * then it returns NULL.
 *
 * The data stored inside the hash is not free()ed, so you must do it
 * manually after getting the pointer back.
 */
struct bfd_session *bfd_id_delete(uint32_t id)
{
	struct bfd_session bs;

	bs.discrs.my_discr = id;

	return hash_release(bfd_id_hash, &bs);
}

struct bfd_session *bfd_shop_delete(struct bfd_shop_key shop)
{
	struct bfd_session bs, *bsp;

	_shop_key(&bs, &shop);
	bsp = hash_release(bfd_shop_hash, &bs);
	if (bsp == NULL && shop.port_name[0] != 0) {
		/*
		 * Since the local interface spec is optional, try
		 * searching the key without it as well.
		 */
		_shop_key2(&bs, &shop);
		bsp = hash_release(bfd_shop_hash, &bs);
	}

	return bsp;
}

struct bfd_session *bfd_mhop_delete(struct bfd_mhop_key mhop)
{
	struct bfd_session bs;

	_mhop_key(&bs, &mhop);

	return hash_release(bfd_mhop_hash, &bs);
}

struct bfd_vrf *bfd_vrf_delete(int vrf_id)
{
	struct bfd_vrf vrf;

	vrf.vrf_id = vrf_id;

	return hash_release(bfd_vrf_hash, &vrf);
}

struct bfd_iface *bfd_iface_delete(const char *ifname)
{
	struct bfd_iface iface;

	if (_iface_key(&iface, ifname) != 0)
		return NULL;

	return hash_release(bfd_iface_hash, &iface);
}

/* Iteration functions. */
void bfd_id_iterate(hash_iter_func hif, void *arg)
{
	hash_iterate(bfd_id_hash, hif, arg);
}

void bfd_shop_iterate(hash_iter_func hif, void *arg)
{
	hash_iterate(bfd_shop_hash, hif, arg);
}

void bfd_mhop_iterate(hash_iter_func hif, void *arg)
{
	hash_iterate(bfd_mhop_hash, hif, arg);
}

void bfd_vrf_iterate(hash_iter_func hif, void *arg)
{
	hash_iterate(bfd_vrf_hash, hif, arg);
}

void bfd_iface_iterate(hash_iter_func hif, void *arg)
{
	hash_iterate(bfd_iface_hash, hif, arg);
}

/*
 * Insert functions.
 *
 * Inserts session into hash and returns `true` on success, otherwise
 * `false`.
 */
bool bfd_id_insert(struct bfd_session *bs)
{
	return (hash_get(bfd_id_hash, bs, hash_alloc_intern) == bs);
}

bool bfd_shop_insert(struct bfd_session *bs)
{
	return (hash_get(bfd_shop_hash, bs, hash_alloc_intern) == bs);
}

bool bfd_mhop_insert(struct bfd_session *bs)
{
	return (hash_get(bfd_mhop_hash, bs, hash_alloc_intern) == bs);
}

bool bfd_vrf_insert(struct bfd_vrf *vrf)
{
	return (hash_get(bfd_vrf_hash, vrf, hash_alloc_intern) == vrf);
}

bool bfd_iface_insert(struct bfd_iface *iface)
{
	return (hash_get(bfd_iface_hash, iface, hash_alloc_intern) == iface);
}

void bfd_initialize(void)
{
	bfd_id_hash = hash_create(bfd_id_hash_do, bfd_id_hash_cmp,
				  "BFD discriminator hash");
	bfd_shop_hash = hash_create(bfd_shop_hash_do, bfd_shop_hash_cmp,
				    "BFD single hop hash");
	bfd_mhop_hash = hash_create(bfd_mhop_hash_do, bfd_mhop_hash_cmp,
				    "BFD multihop hop hash");
	bfd_vrf_hash =
		hash_create(bfd_vrf_hash_do, bfd_vrf_hash_cmp, "BFD VRF hash");
	bfd_iface_hash = hash_create(bfd_iface_hash_do, bfd_iface_hash_cmp,
				     "BFD interface hash");
}

static void _bfd_free(struct hash_backet *hb,
		      void *arg __attribute__((__unused__)))
{
	struct bfd_session *bs = hb->data;

	bfd_session_free(bs);
}

static void _vrf_free(void *arg)
{
	struct bfd_vrf *vrf = arg;

	XFREE(MTYPE_BFDD_CONFIG, vrf);
}

static void _iface_free(void *arg)
{
	struct bfd_iface *iface = arg;

	XFREE(MTYPE_BFDD_CONFIG, iface);
}

void bfd_shutdown(void)
{
	/*
	 * Close and free all BFD sessions.
	 *
	 * _bfd_free() will call bfd_session_free() which will take care
	 * of removing the session from all hashes, so we just run an
	 * assert() here to make sure it really happened.
	 */
	bfd_id_iterate(_bfd_free, NULL);
	assert(bfd_shop_hash->count == 0);
	assert(bfd_mhop_hash->count == 0);

	/* Clean the VRF and interface hashes. */
	hash_clean(bfd_vrf_hash, _vrf_free);
	hash_clean(bfd_iface_hash, _iface_free);

	/* Now free the hashes themselves. */
	hash_free(bfd_id_hash);
	hash_free(bfd_shop_hash);
	hash_free(bfd_mhop_hash);
	hash_free(bfd_vrf_hash);
	hash_free(bfd_iface_hash);
}
