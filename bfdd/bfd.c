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
static struct bfd_session *bs_peer_waiting_find(struct bfd_peer_cfg *bpc);

static uint32_t ptm_bfd_gen_ID(void);
static void ptm_bfd_echo_xmt_TO(struct bfd_session *bfd);
static void bfd_session_free(struct bfd_session *bs);
static struct bfd_session *bfd_session_new(void);
static struct bfd_session *bfd_find_disc(struct sockaddr_any *sa,
					 uint32_t ldisc);
static int bfd_session_update(struct bfd_session *bs, struct bfd_peer_cfg *bpc);
static const char *get_diag_str(int diag);

static void bs_admin_down_handler(struct bfd_session *bs, int nstate);
static void bs_down_handler(struct bfd_session *bs, int nstate);
static void bs_init_handler(struct bfd_session *bs, int nstate);
static void bs_up_handler(struct bfd_session *bs, int nstate);


/*
 * Functions
 */
static struct bfd_session *bs_peer_waiting_find(struct bfd_peer_cfg *bpc)
{
	struct bfd_session_observer *bso;
	struct bfd_session *bs = NULL;
	bool is_shop, is_ipv4;

	TAILQ_FOREACH(bso, &bglobal.bg_obslist, bso_entry) {
		bs = bso->bso_bs;

		is_shop = !BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH);
		is_ipv4 = !BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_IPV6);
		/* Quick checks first. */
		if (is_shop != (!bpc->bpc_mhop))
			continue;
		if (is_ipv4 != bpc->bpc_ipv4)
			continue;

		/*
		 * Slow lookup without hash because we don't have all
		 * information yet.
		 */
		if (is_shop) {
			if (strcmp(bs->ifname, bpc->bpc_localif))
				continue;
			if (memcmp(&bs->shop.peer, &bpc->bpc_peer,
				   sizeof(bs->shop.peer)))
				continue;

			break;
		}

		if (strcmp(bs->vrfname, bpc->bpc_vrfname))
			continue;
		if (memcmp(&bs->mhop.peer, &bpc->bpc_peer,
			   sizeof(bs->mhop.peer)))
			continue;
		if (memcmp(&bs->mhop.local, &bpc->bpc_local,
			   sizeof(bs->mhop.local)))
			continue;

		break;
	}
	if (bso == NULL)
		bs = NULL;

	return bs;
}

struct bfd_session *bs_peer_find(struct bfd_peer_cfg *bpc)
{
	struct bfd_session *bs;
	struct peer_label *pl;
	struct interface *ifp;
	struct vrf *vrf;
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
		if (bpc->bpc_has_vrfname) {
			vrf = vrf_lookup_by_name(bpc->bpc_vrfname);
			if (vrf == NULL)
				return NULL;

			mhop.vrfid = vrf->vrf_id;
		}

		bs = bfd_mhop_lookup(mhop);
	} else {
		memset(&shop, 0, sizeof(shop));
		shop.peer = bpc->bpc_peer;
		if (bpc->bpc_has_localif) {
			ifp = if_lookup_by_name_all_vrf(bpc->bpc_localif);
			if (ifp == NULL)
				return NULL;

			shop.ifindex = ifp->ifindex;
		}

		bs = bfd_shop_lookup(shop);
	}

	if (bs != NULL)
		return bs;

	/* Search for entries that are incomplete. */
	return bs_peer_waiting_find(bpc);
}

/*
 * Starts a disabled BFD session.
 *
 * A session is disabled when the specified interface/VRF doesn't exist
 * yet. It might happen on FRR boot or with virtual interfaces.
 */
int bfd_session_enable(struct bfd_session *bs)
{
	struct sockaddr_in6 *sin6;
	struct interface *ifp = NULL;
	struct vrf *vrf = NULL;
	int psock;

	/*
	 * If the interface or VRF doesn't exist, then we must register
	 * the session but delay its start.
	 */
	if (bs->ifname[0] != 0) {
		ifp = if_lookup_by_name_all_vrf(bs->ifname);
		if (ifp == NULL) {
			log_error(
				"session-enable: specified interface doesn't exists.");
			return 0;
		}

		vrf = vrf_lookup_by_id(ifp->vrf_id);
		if (vrf == NULL) {
			log_error("session-enable: specified VRF doesn't exists.");
			return 0;
		}
	}

	if (bs->vrfname[0] != 0) {
		vrf = vrf_lookup_by_name(bs->vrfname);
		if (vrf == NULL) {
			log_error("session-enable: specified VRF doesn't exists.");
			return 0;
		}
	}

	/* Assign interface/VRF pointers. */
	bs->vrf = vrf;
	if (bs->vrf == NULL)
		bs->vrf = vrf_lookup_by_id(VRF_DEFAULT);

	if (bs->ifname[0] != 0 &&
	    BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH) == 0)
		bs->ifp = ifp;

	/* Set the IPv6 scope id for link-local addresses. */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_IPV6)) {
		sin6 = &bs->mhop.peer.sa_sin6;
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
			sin6->sin6_scope_id = bs->ifp != NULL
						      ? bs->ifp->ifindex
						      : IFINDEX_INTERNAL;

		sin6 = &bs->mhop.local.sa_sin6;
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
			sin6->sin6_scope_id = bs->ifp != NULL
						      ? bs->ifp->ifindex
						      : IFINDEX_INTERNAL;

		bs->local_ip.sa_sin6 = *sin6;
		bs->local_address.sa_sin6 = *sin6;
	}

	/*
	 * Get socket for transmitting control packets.  Note that if we
	 * could use the destination port (3784) for the source
	 * port we wouldn't need a socket per session.
	 */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_IPV6) == 0) {
		psock = bp_peer_socket(bs);
		if (psock == -1)
			return -1;
	} else {
		psock = bp_peer_socketv6(bs);
		if (psock == -1)
			return -1;
	}

	/*
	 * We've got a valid socket, lets start the timers and the
	 * protocol.
	 */
	bs->sock = psock;
	bfd_recvtimer_update(bs);
	ptm_bfd_start_xmt_timer(bs, false);

	/* Registrate session into data structures. */
	bs->discrs.my_discr = ptm_bfd_gen_ID();
	bfd_id_insert(bs);
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH)) {
		if (vrf != NULL)
			bs->mhop.vrfid = vrf->vrf_id;
		else
			bs->mhop.vrfid = VRF_DEFAULT;

		bfd_mhop_insert(bs);
	} else {
		if (ifp != NULL)
			bs->shop.ifindex = ifp->ifindex;
		else
			bs->shop.ifindex = IFINDEX_INTERNAL;

		bfd_shop_insert(bs);
	}

	return 0;
}

/*
 * Disabled a running BFD session.
 *
 * A session is disabled when the specified interface/VRF gets removed
 * (e.g. virtual interfaces).
 */
void bfd_session_disable(struct bfd_session *bs)
{
	/* Free up socket resources. */
	if (bs->sock != -1) {
		close(bs->sock);
		bs->sock = -1;
	}

	/* Disable all timers. */
	bfd_recvtimer_delete(bs);
	bfd_echo_recvtimer_delete(bs);
	bfd_xmttimer_delete(bs);
	bfd_echo_xmttimer_delete(bs);

	/* Unregister session from hashes to avoid unwanted activation. */
	bfd_id_delete(bs->discrs.my_discr);
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH))
		bfd_mhop_delete(bs->mhop);
	else
		bfd_shop_delete(bs->shop);
}

static uint32_t ptm_bfd_gen_ID(void)
{
	uint32_t session_id;

	/*
	 * RFC 5880, Section 6.8.1. recommends that we should generate
	 * random session identification numbers.
	 */
	do {
		session_id = ((random() << 16) & 0xFFFF0000)
			     | (random() & 0x0000FFFF);
	} while (session_id == 0 || bfd_id_lookup(session_id) != NULL);

	return session_id;
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

void ptm_bfd_echo_stop(struct bfd_session *bfd)
{
	bfd->echo_xmt_TO = 0;
	bfd->echo_detect_TO = 0;
	BFD_UNSET_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE);

	bfd_echo_xmttimer_delete(bfd);
	bfd_echo_recvtimer_delete(bfd);
}

void ptm_bfd_echo_start(struct bfd_session *bfd)
{
	bfd->echo_detect_TO = (bfd->remote_detect_mult * bfd->echo_xmt_TO);
	if (bfd->echo_detect_TO > 0)
		ptm_bfd_echo_xmt_TO(bfd);
}

void ptm_bfd_ses_up(struct bfd_session *bfd)
{
	int old_state = bfd->ses_state;

	bfd->local_diag = 0;
	bfd->ses_state = PTM_BFD_UP;
	monotime(&bfd->uptime);

	/* Connection is up, lets negotiate timers. */
	bfd_set_polling(bfd);

	/* Start sending control packets with poll bit immediately. */
	ptm_bfd_snd(bfd, 0);

	control_notify(bfd);

	if (old_state != bfd->ses_state) {
		bfd->stats.session_up++;
		log_info("state-change: [%s] %s -> %s", bs_to_string(bfd),
			 state_list[old_state].str,
			 state_list[bfd->ses_state].str);
	}
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

	/* Slow down the control packets, the connection is down. */
	bs_set_slow_timers(bfd);

	/* only signal clients when going from up->down state */
	if (old_state == PTM_BFD_UP)
		control_notify(bfd);

	/* Stop echo packet transmission if they are active */
	if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE))
		ptm_bfd_echo_stop(bfd);

	if (old_state != bfd->ses_state) {
		bfd->stats.session_down++;
		log_info("state-change: [%s] %s -> %s reason:%s",
			 bs_to_string(bfd), state_list[old_state].str,
			 state_list[bfd->ses_state].str,
			 get_diag_str(bfd->local_diag));
	}
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

struct bfd_session *ptm_bfd_sess_find(struct bfd_pkt *cp,
				      struct sockaddr_any *peer,
				      struct sockaddr_any *local,
				      ifindex_t ifindex, vrf_id_t vrfid,
				      bool is_mhop)
{
	struct bfd_session *l_bfd = NULL;
	struct bfd_mhop_key mhop;
	struct bfd_shop_key shop;

	/* Find our session using the ID signaled by the remote end. */
	if (cp->discrs.remote_discr)
		return bfd_find_disc(peer, ntohl(cp->discrs.remote_discr));

	/* Search for session without using discriminator. */
	if (is_mhop) {
		memset(&mhop, 0, sizeof(mhop));
		mhop.peer = *peer;
		mhop.local = *local;
		mhop.vrfid = vrfid;

		l_bfd = bfd_mhop_lookup(mhop);
	} else {
		memset(&shop, 0, sizeof(shop));
		shop.peer = *peer;
		shop.ifindex = ifindex;

		l_bfd = bfd_shop_lookup(shop);
	}

	/* XXX maybe remoteDiscr should be checked for remoteHeard cases. */
	return l_bfd;
}

int bfd_xmt_cb(struct thread *t)
{
	struct bfd_session *bs = THREAD_ARG(t);

	ptm_bfd_xmt_TO(bs, 0);

	return 0;
}

int bfd_echo_xmt_cb(struct thread *t)
{
	struct bfd_session *bs = THREAD_ARG(t);

	if (bs->echo_xmt_TO > 0)
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
		ptm_bfd_ses_dn(bs, BD_CONTROL_EXPIRED);
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
		ptm_bfd_ses_dn(bs, BD_ECHO_FAILED);
		break;
	}

	return 0;
}

static struct bfd_session *bfd_session_new(void)
{
	struct bfd_session *bs;

	bs = XCALLOC(MTYPE_BFDD_CONFIG, sizeof(*bs));
	if (bs == NULL)
		return NULL;

	QOBJ_REG(bs, bfd_session);

	bs->timers.desired_min_tx = BFD_DEFDESIREDMINTX;
	bs->timers.required_min_rx = BFD_DEFREQUIREDMINRX;
	bs->timers.required_min_echo = BFD_DEF_REQ_MIN_ECHO;
	bs->detect_mult = BFD_DEFDETECTMULT;
	bs->mh_ttl = BFD_DEF_MHOP_TTL;
	bs->ses_state = PTM_BFD_DOWN;

	/* Initiate connection with slow timers. */
	bs_set_slow_timers(bs);

	/* Initiate remote settings as well. */
	bs->remote_timers = bs->cur_timers;
	bs->remote_detect_mult = BFD_DEFDETECTMULT;

	bs->sock = -1;
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

		/* Activate/update echo receive timeout timer. */
		bs_echo_timer_handler(bs);
	} else {
		/* Check if echo mode is already disabled. */
		if (!BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO))
			goto skip_echo;

		BFD_UNSET_FLAG(bs->flags, BFD_SESS_FLAG_ECHO);
		ptm_bfd_echo_stop(bs);
	}

skip_echo:
	if (bpc->bpc_has_txinterval)
		bs->timers.desired_min_tx = bpc->bpc_txinterval * 1000;

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

		/* Don't try to send packets with a disabled session. */
		if (bs->sock != -1)
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
	}
}

static int bfd_session_update(struct bfd_session *bs, struct bfd_peer_cfg *bpc)
{
	/* User didn't want to update, return failure. */
	if (bpc->bpc_createonly)
		return -1;

	_bfd_session_update(bs, bpc);

	control_notify_config(BCM_NOTIFY_CONFIG_UPDATE, bs);

	return 0;
}

static void bfd_session_free(struct bfd_session *bs)
{
	struct bfd_session_observer *bso;

	bfd_session_disable(bs);

	/* Remove observer if any. */
	TAILQ_FOREACH(bso, &bglobal.bg_obslist, bso_entry) {
		if (bso->bso_bs != bs)
			continue;

		break;
	}
	if (bso != NULL)
		bs_observer_del(bso);

	pl_free(bs->pl);

	QOBJ_UNREG(bs);
	XFREE(MTYPE_BFDD_CONFIG, bs);
}

struct bfd_session *ptm_bfd_sess_new(struct bfd_peer_cfg *bpc)
{
	struct bfd_session *bfd, *l_bfd;

	/* check to see if this needs a new session */
	l_bfd = bs_peer_find(bpc);
	if (l_bfd) {
		/* Requesting a duplicated peer means update configuration. */
		if (bfd_session_update(l_bfd, bpc) == 0)
			return l_bfd;
		else
			return NULL;
	}

	/* Get BFD session storage with its defaults. */
	bfd = bfd_session_new();
	if (bfd == NULL) {
		log_error("session-new: allocation failed");
		return NULL;
	}

	/*
	 * Store interface/VRF name in case we need to delay session
	 * start. See `bfd_session_enable` for more information.
	 */
	if (bpc->bpc_has_localif)
		strlcpy(bfd->ifname, bpc->bpc_localif, sizeof(bfd->ifname));

	if (bpc->bpc_has_vrfname)
		strlcpy(bfd->vrfname, bpc->bpc_vrfname, sizeof(bfd->vrfname));

	/* Add observer if we have moving parts. */
	if (bfd->ifname[0] || bfd->vrfname[0])
		bs_observer_add(bfd);

	/* Copy remaining data. */
	if (bpc->bpc_ipv4 == false)
		BFD_SET_FLAG(bfd->flags, BFD_SESS_FLAG_IPV6);

	if (bpc->bpc_mhop) {
		BFD_SET_FLAG(bfd->flags, BFD_SESS_FLAG_MH);
		bfd->mhop.peer = bpc->bpc_peer;
		bfd->mhop.local = bpc->bpc_local;
	} else {
		bfd->shop.peer = bpc->bpc_peer;
	}

	bfd->local_ip = bpc->bpc_local;
	bfd->local_address = bpc->bpc_local;

	/* Try to enable session and schedule for packet receive/send. */
	if (bfd_session_enable(bfd) == -1) {
		/* Unrecoverable failure, remove the session/peer. */
		bfd_session_free(bfd);
		return NULL;
	}

	/* Apply other configurations. */
	_bfd_session_update(bfd, bpc);

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
	/*
	 * Start polling procedure: the only timers that require polling
	 * to change value without losing connection are:
	 *
	 *   - Desired minimum transmission interval;
	 *   - Required minimum receive interval;
	 *
	 * RFC 5880, Section 6.8.3.
	 */
	bs->polling = 1;
}

/*
 * bs_<state>_handler() functions implement the BFD state machine
 * transition mechanism. `<state>` is the current session state and
 * the parameter `nstate` is the peer new state.
 */
static void bs_admin_down_handler(struct bfd_session *bs
				  __attribute__((__unused__)),
				  int nstate __attribute__((__unused__)))
{
	/*
	 * We are administratively down, there is no state machine
	 * handling.
	 */
}

static void bs_down_handler(struct bfd_session *bs, int nstate)
{
	switch (nstate) {
	case PTM_BFD_ADM_DOWN:
		/*
		 * Remote peer doesn't want to talk, so lets keep the
		 * connection down.
		 */
	case PTM_BFD_UP:
		/* Peer can't be up yet, wait it go to 'init' or 'down'. */
		break;

	case PTM_BFD_DOWN:
		/*
		 * Remote peer agreed that the path is down, lets try to
		 * bring it up.
		 */
		bs->ses_state = PTM_BFD_INIT;
		break;

	case PTM_BFD_INIT:
		/*
		 * Remote peer told us his path is up, lets turn
		 * activate the session.
		 */
		ptm_bfd_ses_up(bs);
		break;

	default:
		log_debug("state-change: unhandled neighbor state: %d", nstate);
		break;
	}
}

static void bs_init_handler(struct bfd_session *bs, int nstate)
{
	switch (nstate) {
	case PTM_BFD_ADM_DOWN:
		/*
		 * Remote peer doesn't want to talk, so lets make the
		 * connection down.
		 */
		bs->ses_state = PTM_BFD_DOWN;
		break;

	case PTM_BFD_DOWN:
		/* Remote peer hasn't moved to first stage yet. */
		break;

	case PTM_BFD_INIT:
	case PTM_BFD_UP:
		/* We agreed on the settings and the path is up. */
		ptm_bfd_ses_up(bs);
		break;

	default:
		log_debug("state-change: unhandled neighbor state: %d", nstate);
		break;
	}
}

static void bs_up_handler(struct bfd_session *bs, int nstate)
{
	switch (nstate) {
	case PTM_BFD_ADM_DOWN:
	case PTM_BFD_DOWN:
		/* Peer lost or asked to shutdown connection. */
		ptm_bfd_ses_dn(bs, BD_NEIGHBOR_DOWN);
		break;

	case PTM_BFD_INIT:
	case PTM_BFD_UP:
		/* Path is up and working. */
		break;

	default:
		log_debug("state-change: unhandled neighbor state: %d", nstate);
		break;
	}
}

void bs_state_handler(struct bfd_session *bs, int nstate)
{
	switch (bs->ses_state) {
	case PTM_BFD_ADM_DOWN:
		bs_admin_down_handler(bs, nstate);
		break;
	case PTM_BFD_DOWN:
		bs_down_handler(bs, nstate);
		break;
	case PTM_BFD_INIT:
		bs_init_handler(bs, nstate);
		break;
	case PTM_BFD_UP:
		bs_up_handler(bs, nstate);
		break;

	default:
		log_debug("state-change: [%s] is in invalid state: %d",
			  bs_to_string(bs), nstate);
		break;
	}
}

/*
 * Handles echo timer manipulation after updating timer.
 */
void bs_echo_timer_handler(struct bfd_session *bs)
{
	uint32_t old_timer;

	/*
	 * Before doing any echo handling, check if it is possible to
	 * use it.
	 *
	 *   - Check for `echo-mode` configuration.
	 *   - Check that we are not using multi hop (RFC 5883,
	 *     Section 3).
	 *   - Check that we are already at the up state.
	 */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO) == 0
	    || BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH)
	    || bs->ses_state != PTM_BFD_UP)
		return;

	/* Remote peer asked to stop echo. */
	if (bs->remote_timers.required_min_echo == 0) {
		if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO_ACTIVE))
			ptm_bfd_echo_stop(bs);

		return;
	}

	/*
	 * Calculate the echo transmission timer: we must not send
	 * echo packets faster than the minimum required time
	 * announced by the remote system.
	 *
	 * RFC 5880, Section 6.8.9.
	 */
	old_timer = bs->echo_xmt_TO;
	if (bs->remote_timers.required_min_echo > bs->timers.required_min_echo)
		bs->echo_xmt_TO = bs->remote_timers.required_min_echo;
	else
		bs->echo_xmt_TO = bs->timers.required_min_echo;

	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO_ACTIVE) == 0
	    || old_timer != bs->echo_xmt_TO)
		ptm_bfd_echo_start(bs);
}

/*
 * RFC 5880 Section 6.5.
 *
 * When a BFD control packet with the final bit is received, we must
 * update the session parameters.
 */
void bs_final_handler(struct bfd_session *bs)
{
	/* Start using our new timers. */
	bs->cur_timers.desired_min_tx = bs->timers.desired_min_tx;
	bs->cur_timers.required_min_rx = bs->timers.required_min_rx;

	/*
	 * TODO: demand mode. See RFC 5880 Section 6.1.
	 *
	 * When using demand mode we must disable the detection timer
	 * for lost control packets.
	 */
	if (bs->demand_mode) {
		/* Notify watchers about changed timers. */
		control_notify_config(BCM_NOTIFY_CONFIG_UPDATE, bs);
		return;
	}

	/*
	 * Calculate detection time based on new timers.
	 *
	 * Transmission calculation:
	 * We must respect the RequiredMinRxInterval from the remote
	 * system: if our desired transmission timer is more than the
	 * minimum receive rate, then we must lower it to at least the
	 * minimum receive interval.
	 *
	 * RFC 5880, Section 6.8.3.
	 */
	if (bs->timers.desired_min_tx > bs->remote_timers.required_min_rx)
		bs->xmt_TO = bs->remote_timers.required_min_rx;
	else
		bs->xmt_TO = bs->timers.desired_min_tx;

	/* Apply new transmission timer immediately. */
	ptm_bfd_start_xmt_timer(bs, false);

	/*
	 * Detection timeout calculation:
	 * The minimum detection timeout is the remote detection
	 * multipler (number of packets to be missed) times the agreed
	 * transmission interval.
	 *
	 * RFC 5880, Section 6.8.4.
	 *
	 * TODO: support sending/counting more packets inside detection
	 * timeout.
	 */
	if (bs->remote_timers.required_min_rx > bs->timers.desired_min_tx)
		bs->detect_TO = bs->remote_detect_mult
				* bs->remote_timers.required_min_rx;
	else
		bs->detect_TO = bs->remote_detect_mult
				* bs->timers.desired_min_tx;

	/* Apply new receive timer immediately. */
	bfd_recvtimer_update(bs);

	/* Notify watchers about changed timers. */
	control_notify_config(BCM_NOTIFY_CONFIG_UPDATE, bs);
}

void bs_set_slow_timers(struct bfd_session *bs)
{
	/*
	 * BFD connection must use slow timers before going up or after
	 * losing connectivity to avoid wasting bandwidth.
	 *
	 * RFC 5880, Section 6.8.3.
	 */
	bs->cur_timers.desired_min_tx = BFD_DEF_SLOWTX;
	bs->cur_timers.required_min_rx = BFD_DEF_SLOWTX;
	bs->cur_timers.required_min_echo = 0;

	/* Set the appropriated timeouts for slow connection. */
	bs->detect_TO = (BFD_DEFDETECTMULT * BFD_DEF_SLOWTX);
	bs->xmt_TO = BFD_DEF_SLOWTX;
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
#define HOURS (60 * MINUTES)
#define DAYS (24 * HOURS)
#define MONTHS (30 * DAYS)
#define YEARS (12 * MONTHS)
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

		if (bs->mhop.vrfid != VRF_DEFAULT)
			snprintf(buf + pos, sizeof(buf) - pos, " vrf:%u",
				 bs->mhop.vrfid);
	} else {
		pos += snprintf(buf + pos, sizeof(buf) - pos, " peer:%s",
				satostr(&bs->shop.peer));

		if (bs->local_address.sa_sin.sin_family)
			pos += snprintf(buf + pos, sizeof(buf) - pos,
					" local:%s",
					satostr(&bs->local_address));

		if (bs->shop.ifindex)
			snprintf(buf + pos, sizeof(buf) - pos, " ifindex:%u",
				 bs->shop.ifindex);
	}

	return buf;
}

int bs_observer_add(struct bfd_session *bs)
{
	struct bfd_session_observer *bso;

	bso = XMALLOC(MTYPE_BFDD_SESSION_OBSERVER, sizeof(*bso));
	bso->bso_bs = bs;
	bso->bso_isinterface = !BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH);
	if (bso->bso_isinterface)
		strlcpy(bso->bso_entryname, bs->ifname,
			sizeof(bso->bso_entryname));
	else
		strlcpy(bso->bso_entryname, bs->vrfname,
			sizeof(bso->bso_entryname));

	TAILQ_INSERT_TAIL(&bglobal.bg_obslist, bso, bso_entry);

	return 0;
}

void bs_observer_del(struct bfd_session_observer *bso)
{
	TAILQ_REMOVE(&bglobal.bg_obslist, bso, bso_entry);
	XFREE(MTYPE_BFDD_SESSION_OBSERVER, bso);
}


/*
 * BFD hash data structures to find sessions.
 */
static struct hash *bfd_id_hash;
static struct hash *bfd_shop_hash;
static struct hash *bfd_mhop_hash;

static unsigned int bfd_id_hash_do(void *p);
static unsigned int bfd_shop_hash_do(void *p);
static unsigned int bfd_mhop_hash_do(void *p);

static void _shop_key(struct bfd_session *bs, const struct bfd_shop_key *shop);
static void _shop_key2(struct bfd_session *bs, const struct bfd_shop_key *shop);
static void _mhop_key(struct bfd_session *bs, const struct bfd_mhop_key *mhop);

static void _bfd_free(struct hash_bucket *hb,
		      void *arg __attribute__((__unused__)));

/* BFD hash for our discriminator. */
static unsigned int bfd_id_hash_do(void *p)
{
	struct bfd_session *bs = p;

	return jhash_1word(bs->discrs.my_discr, 0);
}

static bool bfd_id_hash_cmp(const void *n1, const void *n2)
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

static bool bfd_shop_hash_cmp(const void *n1, const void *n2)
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

static bool bfd_mhop_hash_cmp(const void *n1, const void *n2)
{
	const struct bfd_session *bs1 = n1, *bs2 = n2;

	return memcmp(&bs1->mhop, &bs2->mhop, sizeof(bs1->mhop)) == 0;
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
	bs->shop.ifindex = IFINDEX_INTERNAL;
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
	if (bsp == NULL && bs.shop.ifindex != 0) {
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

	return hash_lookup(bfd_mhop_hash, &bs);
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
	if (bsp == NULL && shop.ifindex != 0) {
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

void bfd_initialize(void)
{
	bfd_id_hash = hash_create(bfd_id_hash_do, bfd_id_hash_cmp,
				  "BFD discriminator hash");
	bfd_shop_hash = hash_create(bfd_shop_hash_do, bfd_shop_hash_cmp,
				    "BFD single hop hash");
	bfd_mhop_hash = hash_create(bfd_mhop_hash_do, bfd_mhop_hash_cmp,
				    "BFD multihop hop hash");
}

static void _bfd_free(struct hash_bucket *hb,
		      void *arg __attribute__((__unused__)))
{
	struct bfd_session *bs = hb->data;

	bfd_session_free(bs);
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

	/* Now free the hashes themselves. */
	hash_free(bfd_id_hash);
	hash_free(bfd_shop_hash);
	hash_free(bfd_mhop_hash);
}
