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

DEFINE_MTYPE_STATIC(BFDD, BFDD_CONFIG, "long-lived configuration memory")
DEFINE_MTYPE_STATIC(BFDD, BFDD_SESSION_OBSERVER, "Session observer")
DEFINE_MTYPE_STATIC(BFDD, BFDD_VRF, "BFD VRF")

/*
 * Prototypes
 */
static uint32_t ptm_bfd_gen_ID(void);
static void ptm_bfd_echo_xmt_TO(struct bfd_session *bfd);
static struct bfd_session *bfd_find_disc(struct sockaddr_any *sa,
					 uint32_t ldisc);
static int bfd_session_update(struct bfd_session *bs, struct bfd_peer_cfg *bpc);
static const char *get_diag_str(int diag);

static void bs_admin_down_handler(struct bfd_session *bs, int nstate);
static void bs_down_handler(struct bfd_session *bs, int nstate);
static void bs_init_handler(struct bfd_session *bs, int nstate);
static void bs_up_handler(struct bfd_session *bs, int nstate);
static void bs_neighbour_admin_down_handler(struct bfd_session *bfd,
					    uint8_t diag);

/* Zeroed array with the size of an IPv6 address. */
struct in6_addr zero_addr;

/*
 * Functions
 */
void gen_bfd_key(struct bfd_key *key, struct sockaddr_any *peer,
		 struct sockaddr_any *local, bool mhop, const char *ifname,
		 const char *vrfname)
{
	memset(key, 0, sizeof(*key));

	switch (peer->sa_sin.sin_family) {
	case AF_INET:
		key->family = AF_INET;
		memcpy(&key->peer, &peer->sa_sin.sin_addr,
		       sizeof(peer->sa_sin.sin_addr));
		memcpy(&key->local, &local->sa_sin.sin_addr,
		       sizeof(local->sa_sin.sin_addr));
		break;
	case AF_INET6:
		key->family = AF_INET6;
		memcpy(&key->peer, &peer->sa_sin6.sin6_addr,
		       sizeof(peer->sa_sin6.sin6_addr));
		memcpy(&key->local, &local->sa_sin6.sin6_addr,
		       sizeof(local->sa_sin6.sin6_addr));
		break;
	}

	key->mhop = mhop;
	if (ifname && ifname[0])
		strlcpy(key->ifname, ifname, sizeof(key->ifname));
	if (vrfname && vrfname[0])
		strlcpy(key->vrfname, vrfname, sizeof(key->vrfname));
	else
		strlcpy(key->vrfname, VRF_DEFAULT_NAME, sizeof(key->vrfname));
}

struct bfd_session *bs_peer_find(struct bfd_peer_cfg *bpc)
{
	struct bfd_session *bs;
	struct peer_label *pl;
	struct bfd_key key;

	/* Try to find label first. */
	if (bpc->bpc_has_label) {
		pl = pl_find(bpc->bpc_label);
		if (pl != NULL) {
			bs = pl->pl_bs;
			return bs;
		}
	}

	/* Otherwise fallback to peer/local hash lookup. */
	gen_bfd_key(&key, &bpc->bpc_peer, &bpc->bpc_local, bpc->bpc_mhop,
		    bpc->bpc_localif, bpc->bpc_vrfname);

	return bfd_key_lookup(key);
}

/*
 * Starts a disabled BFD session.
 *
 * A session is disabled when the specified interface/VRF doesn't exist
 * yet. It might happen on FRR boot or with virtual interfaces.
 */
int bfd_session_enable(struct bfd_session *bs)
{
	struct interface *ifp = NULL;
	struct vrf *vrf = NULL;
	int psock;

	/*
	 * If the interface or VRF doesn't exist, then we must register
	 * the session but delay its start.
	 */
	if (bs->key.vrfname[0]) {
		vrf = vrf_lookup_by_name(bs->key.vrfname);
		if (vrf == NULL) {
			log_error(
				"session-enable: specified VRF doesn't exists.");
			return 0;
		}
	}

	if (bs->key.ifname[0]) {
		if (vrf)
			ifp = if_lookup_by_name(bs->key.ifname, vrf->vrf_id);
		else
			ifp = if_lookup_by_name_all_vrf(bs->key.ifname);
		if (ifp == NULL) {
			log_error(
				  "session-enable: specified interface doesn't exists.");
			return 0;
		}
		if (bs->key.ifname[0] && !vrf) {
			vrf = vrf_lookup_by_id(ifp->vrf_id);
			if (vrf == NULL) {
				log_error(
					  "session-enable: specified VRF doesn't exists.");
				return 0;
			}
		}
	}

	/* Assign interface/VRF pointers. */
	bs->vrf = vrf;
	if (bs->vrf == NULL)
		bs->vrf = vrf_lookup_by_id(VRF_DEFAULT);
	assert(bs->vrf);

	if (bs->key.ifname[0]
	    && BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH) == 0)
		bs->ifp = ifp;

	/* Sanity check: don't leak open sockets. */
	if (bs->sock != -1) {
		log_debug("session-enable: previous socket open");
		close(bs->sock);
		bs->sock = -1;
	}

	/*
	 * Get socket for transmitting control packets.  Note that if we
	 * could use the destination port (3784) for the source
	 * port we wouldn't need a socket per session.
	 */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_IPV6) == 0) {
		psock = bp_peer_socket(bs);
		if (psock == -1)
			return 0;
	} else {
		psock = bp_peer_socketv6(bs);
		if (psock == -1)
			return 0;
	}

	/*
	 * We've got a valid socket, lets start the timers and the
	 * protocol.
	 */
	bs->sock = psock;
	bfd_recvtimer_update(bs);
	ptm_bfd_start_xmt_timer(bs, false);

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
	bfd_xmttimer_delete(bs);
	ptm_bfd_echo_stop(bs);
	bs->vrf = NULL;
	bs->ifp = NULL;

	/* Set session down so it doesn't report UP and disabled. */
	ptm_bfd_sess_dn(bs, BD_PATH_DOWN);
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

void ptm_bfd_sess_up(struct bfd_session *bfd)
{
	int old_state = bfd->ses_state;

	bfd->local_diag = 0;
	bfd->ses_state = PTM_BFD_UP;
	monotime(&bfd->uptime);

	/* Connection is up, lets negotiate timers. */
	bfd_set_polling(bfd);

	/* Start sending control packets with poll bit immediately. */
	ptm_bfd_snd(bfd, 0);

	control_notify(bfd, bfd->ses_state);

	if (old_state != bfd->ses_state) {
		bfd->stats.session_up++;
		log_info("state-change: [%s] %s -> %s", bs_to_string(bfd),
			 state_list[old_state].str,
			 state_list[bfd->ses_state].str);
	}
}

void ptm_bfd_sess_dn(struct bfd_session *bfd, uint8_t diag)
{
	int old_state = bfd->ses_state;

	bfd->local_diag = diag;
	bfd->discrs.remote_discr = 0;
	bfd->ses_state = PTM_BFD_DOWN;
	bfd->polling = 0;
	bfd->demand_mode = 0;
	monotime(&bfd->downtime);

	/*
	 * Only attempt to send if we have a valid socket:
	 * this function might be called by session disablers and in
	 * this case we won't have a valid socket (i.e. interface was
	 * removed or VRF doesn't exist anymore).
	 */
	if (bfd->sock != -1)
		ptm_bfd_snd(bfd, 0);

	/* Slow down the control packets, the connection is down. */
	bs_set_slow_timers(bfd);

	/* only signal clients when going from up->down state */
	if (old_state == PTM_BFD_UP)
		control_notify(bfd, PTM_BFD_DOWN);

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

	switch (bs->key.family) {
	case AF_INET:
		if (memcmp(&sa->sa_sin.sin_addr, &bs->key.peer,
			   sizeof(sa->sa_sin.sin_addr)))
			return NULL;
		break;
	case AF_INET6:
		if (memcmp(&sa->sa_sin6.sin6_addr, &bs->key.peer,
			   sizeof(sa->sa_sin6.sin6_addr)))
			return NULL;
		break;
	}

	return bs;
}

struct bfd_session *ptm_bfd_sess_find(struct bfd_pkt *cp,
				      struct sockaddr_any *peer,
				      struct sockaddr_any *local,
				      ifindex_t ifindex, vrf_id_t vrfid,
				      bool is_mhop)
{
	struct interface *ifp;
	struct vrf *vrf;
	struct bfd_key key;

	/* Find our session using the ID signaled by the remote end. */
	if (cp->discrs.remote_discr)
		return bfd_find_disc(peer, ntohl(cp->discrs.remote_discr));

	/* Search for session without using discriminator. */
	ifp = if_lookup_by_index(ifindex, vrfid);

	vrf = vrf_lookup_by_id(vrfid);

	gen_bfd_key(&key, peer, local, is_mhop, ifp ? ifp->name : NULL,
		    vrf ? vrf->name : VRF_DEFAULT_NAME);

	/* XXX maybe remoteDiscr should be checked for remoteHeard cases. */
	return bfd_key_lookup(key);
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
		ptm_bfd_sess_dn(bs, BD_CONTROL_EXPIRED);
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
		ptm_bfd_sess_dn(bs, BD_ECHO_FAILED);
		break;
	}

	return 0;
}

struct bfd_session *bfd_session_new(void)
{
	struct bfd_session *bs;

	bs = XCALLOC(MTYPE_BFDD_CONFIG, sizeof(*bs));

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
		control_notify(bs, bs->ses_state);

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
		control_notify(bs, bs->ses_state);

		/* Enable all timers. */
		bfd_recvtimer_update(bs);
		bfd_xmttimer_update(bs, bs->xmt_TO);
	}
	if (bpc->bpc_cbit) {
		if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_CBIT))
			return;

		BFD_SET_FLAG(bs->flags, BFD_SESS_FLAG_CBIT);
	} else {
		if (!BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_CBIT))
			return;

		BFD_UNSET_FLAG(bs->flags, BFD_SESS_FLAG_CBIT);
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

void bfd_session_free(struct bfd_session *bs)
{
	struct bfd_session_observer *bso;

	bfd_session_disable(bs);

	bfd_key_delete(bs->key);
	bfd_id_delete(bs->discrs.my_discr);

	/* Remove observer if any. */
	TAILQ_FOREACH(bso, &bglobal.bg_obslist, bso_entry) {
		if (bso->bso_bs != bs)
			continue;

		break;
	}
	if (bso != NULL)
		bs_observer_del(bso);

	pl_free(bs->pl);

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
		strlcpy(bfd->key.ifname, bpc->bpc_localif,
			sizeof(bfd->key.ifname));

	if (bpc->bpc_has_vrfname)
		strlcpy(bfd->key.vrfname, bpc->bpc_vrfname,
			sizeof(bfd->key.vrfname));
	else
		strlcpy(bfd->key.vrfname, VRF_DEFAULT_NAME,
			sizeof(bfd->key.vrfname));

	/* Copy remaining data. */
	if (bpc->bpc_ipv4 == false)
		BFD_SET_FLAG(bfd->flags, BFD_SESS_FLAG_IPV6);

	bfd->key.family = (bpc->bpc_ipv4) ? AF_INET : AF_INET6;
	switch (bfd->key.family) {
	case AF_INET:
		memcpy(&bfd->key.peer, &bpc->bpc_peer.sa_sin.sin_addr,
		       sizeof(bpc->bpc_peer.sa_sin.sin_addr));
		memcpy(&bfd->key.local, &bpc->bpc_local.sa_sin.sin_addr,
		       sizeof(bpc->bpc_local.sa_sin.sin_addr));
		break;

	case AF_INET6:
		memcpy(&bfd->key.peer, &bpc->bpc_peer.sa_sin6.sin6_addr,
		       sizeof(bpc->bpc_peer.sa_sin6.sin6_addr));
		memcpy(&bfd->key.local, &bpc->bpc_local.sa_sin6.sin6_addr,
		       sizeof(bpc->bpc_local.sa_sin6.sin6_addr));
		break;

	default:
		assert(1);
		break;
	}

	if (bpc->bpc_mhop)
		BFD_SET_FLAG(bfd->flags, BFD_SESS_FLAG_MH);

	bfd->key.mhop = bpc->bpc_mhop;

	if (bs_registrate(bfd) == NULL)
		return NULL;

	/* Apply other configurations. */
	_bfd_session_update(bfd, bpc);

	return bfd;
}

struct bfd_session *bs_registrate(struct bfd_session *bfd)
{
	/* Registrate session into data structures. */
	bfd_key_insert(bfd);
	bfd->discrs.my_discr = ptm_bfd_gen_ID();
	bfd_id_insert(bfd);

	/* Try to enable session and schedule for packet receive/send. */
	if (bfd_session_enable(bfd) == -1) {
		/* Unrecoverable failure, remove the session/peer. */
		bfd_session_free(bfd);
		return NULL;
	}

	/* Add observer if we have moving parts. */
	if (bfd->key.ifname[0] || bfd->key.vrfname[0] || bfd->sock == -1)
		bs_observer_add(bfd);

	log_info("session-new: %s", bs_to_string(bfd));

	control_notify_config(BCM_NOTIFY_CONFIG_ADD, bfd);

	return bfd;
}

int ptm_bfd_sess_del(struct bfd_peer_cfg *bpc)
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
		ptm_bfd_sess_up(bs);
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
		ptm_bfd_sess_up(bs);
		break;

	default:
		log_debug("state-change: unhandled neighbor state: %d", nstate);
		break;
	}
}

static void bs_neighbour_admin_down_handler(struct bfd_session *bfd,
					    uint8_t diag)
{
	int old_state = bfd->ses_state;

	bfd->local_diag = diag;
	bfd->discrs.remote_discr = 0;
	bfd->ses_state = PTM_BFD_DOWN;
	bfd->polling = 0;
	bfd->demand_mode = 0;
	monotime(&bfd->downtime);

	/* Slow down the control packets, the connection is down. */
	bs_set_slow_timers(bfd);

	/* only signal clients when going from up->down state */
	if (old_state == PTM_BFD_UP)
		control_notify(bfd, PTM_BFD_ADM_DOWN);

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

static void bs_up_handler(struct bfd_session *bs, int nstate)
{
	switch (nstate) {
	case PTM_BFD_ADM_DOWN:
		bs_neighbour_admin_down_handler(bs, BD_ADMIN_DOWN);
		break;

	case PTM_BFD_DOWN:
		/* Peer lost or asked to shutdown connection. */
		ptm_bfd_sess_dn(bs, BD_NEIGHBOR_DOWN);
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

const char *bs_to_string(const struct bfd_session *bs)
{
	static char buf[256];
	char addr_buf[INET6_ADDRSTRLEN];
	int pos;
	bool is_mhop = BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH);

	pos = snprintf(buf, sizeof(buf), "mhop:%s", is_mhop ? "yes" : "no");
	pos += snprintf(buf + pos, sizeof(buf) - pos, " peer:%s",
			inet_ntop(bs->key.family, &bs->key.peer, addr_buf,
				  sizeof(addr_buf)));
	pos += snprintf(buf + pos, sizeof(buf) - pos, " local:%s",
			inet_ntop(bs->key.family, &bs->key.local, addr_buf,
				  sizeof(addr_buf)));
	if (bs->key.vrfname[0])
		pos += snprintf(buf + pos, sizeof(buf) - pos, " vrf:%s",
				bs->key.vrfname);
	if (bs->key.ifname[0])
		pos += snprintf(buf + pos, sizeof(buf) - pos, " ifname:%s",
				bs->key.ifname);

	(void)pos;

	return buf;
}

int bs_observer_add(struct bfd_session *bs)
{
	struct bfd_session_observer *bso;

	bso = XCALLOC(MTYPE_BFDD_SESSION_OBSERVER, sizeof(*bso));
	bso->bso_bs = bs;
	bso->bso_addr.family = bs->key.family;
	memcpy(&bso->bso_addr.u.prefix, &bs->key.local,
	       sizeof(bs->key.local));

	TAILQ_INSERT_TAIL(&bglobal.bg_obslist, bso, bso_entry);

	return 0;
}

void bs_observer_del(struct bfd_session_observer *bso)
{
	TAILQ_REMOVE(&bglobal.bg_obslist, bso, bso_entry);
	XFREE(MTYPE_BFDD_SESSION_OBSERVER, bso);
}

void bs_to_bpc(struct bfd_session *bs, struct bfd_peer_cfg *bpc)
{
	memset(bpc, 0, sizeof(*bpc));

	bpc->bpc_ipv4 = (bs->key.family == AF_INET);
	bpc->bpc_mhop = bs->key.mhop;

	switch (bs->key.family) {
	case AF_INET:
		bpc->bpc_peer.sa_sin.sin_family = AF_INET;
		memcpy(&bpc->bpc_peer.sa_sin.sin_addr, &bs->key.peer,
		       sizeof(bpc->bpc_peer.sa_sin.sin_addr));

		if (memcmp(&bs->key.local, &zero_addr, sizeof(bs->key.local))) {
			bpc->bpc_local.sa_sin.sin_family = AF_INET6;
			memcpy(&bpc->bpc_local.sa_sin.sin_addr, &bs->key.local,
			       sizeof(bpc->bpc_local.sa_sin.sin_addr));
		}
		break;

	case AF_INET6:
		bpc->bpc_peer.sa_sin.sin_family = AF_INET6;
		memcpy(&bpc->bpc_peer.sa_sin6.sin6_addr, &bs->key.peer,
		       sizeof(bpc->bpc_peer.sa_sin6.sin6_addr));

		bpc->bpc_local.sa_sin6.sin6_family = AF_INET6;
		memcpy(&bpc->bpc_local.sa_sin6.sin6_addr, &bs->key.local,
		       sizeof(bpc->bpc_local.sa_sin6.sin6_addr));
		break;
	}

	if (bs->key.ifname[0]) {
		bpc->bpc_has_localif = true;
		strlcpy(bpc->bpc_localif, bs->key.ifname,
			sizeof(bpc->bpc_localif));
	}

	if (bs->key.vrfname[0]) {
		bpc->bpc_has_vrfname = true;
		strlcpy(bpc->bpc_vrfname, bs->key.vrfname,
			sizeof(bpc->bpc_vrfname));
	}
}


/*
 * BFD hash data structures to find sessions.
 */
static struct hash *bfd_id_hash;
static struct hash *bfd_key_hash;

static unsigned int bfd_id_hash_do(const void *p);
static unsigned int bfd_key_hash_do(const void *p);

static void _bfd_free(struct hash_bucket *hb,
		      void *arg __attribute__((__unused__)));

/* BFD hash for our discriminator. */
static unsigned int bfd_id_hash_do(const void *p)
{
	const struct bfd_session *bs = p;

	return jhash_1word(bs->discrs.my_discr, 0);
}

static bool bfd_id_hash_cmp(const void *n1, const void *n2)
{
	const struct bfd_session *bs1 = n1, *bs2 = n2;

	return bs1->discrs.my_discr == bs2->discrs.my_discr;
}

/* BFD hash for single hop. */
static unsigned int bfd_key_hash_do(const void *p)
{
	const struct bfd_session *bs = p;

	return jhash(&bs->key, sizeof(bs->key), 0);
}

static bool bfd_key_hash_cmp(const void *n1, const void *n2)
{
	const struct bfd_session *bs1 = n1, *bs2 = n2;

	return memcmp(&bs1->key, &bs2->key, sizeof(bs1->key)) == 0;
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

struct bfd_key_walk_partial_lookup {
	struct bfd_session *given;
	struct bfd_session *result;
};

/* ignore some parameters */
static int bfd_key_lookup_ignore_partial_walker(struct hash_bucket *b,
						void *data)
{
	struct bfd_key_walk_partial_lookup *ctx =
		(struct bfd_key_walk_partial_lookup *)data;
	struct bfd_session *given = ctx->given;
	struct bfd_session *parsed = b->data;

	if (given->key.family != parsed->key.family)
		return HASHWALK_CONTINUE;
	if (given->key.mhop != parsed->key.mhop)
		return HASHWALK_CONTINUE;
	if (memcmp(&given->key.peer, &parsed->key.peer,
		   sizeof(struct in6_addr)))
		return HASHWALK_CONTINUE;
	if (memcmp(given->key.vrfname, parsed->key.vrfname, MAXNAMELEN))
		return HASHWALK_CONTINUE;
	ctx->result = parsed;
	/* ignore localaddr or interface */
	return HASHWALK_ABORT;
}

struct bfd_session *bfd_key_lookup(struct bfd_key key)
{
	struct bfd_session bs, *bsp;
	struct bfd_key_walk_partial_lookup ctx;
	char peer_buf[INET6_ADDRSTRLEN];

	bs.key = key;
	bsp = hash_lookup(bfd_key_hash, &bs);
	if (bsp)
		return bsp;

	inet_ntop(bs.key.family, &bs.key.peer, peer_buf,
		  sizeof(peer_buf));
	/* Handle cases where local-address is optional. */
	if (bs.key.family == AF_INET) {
		memset(&bs.key.local, 0, sizeof(bs.key.local));
		bsp = hash_lookup(bfd_key_hash, &bs);
		if (bsp) {
			char addr_buf[INET6_ADDRSTRLEN];

			inet_ntop(bs.key.family, &key.local, addr_buf,
				  sizeof(addr_buf));
			log_debug(" peer %s found, but loc-addr %s ignored",
				  peer_buf, addr_buf);
			return bsp;
		}
	}

	bs.key = key;
	/* Handle cases where ifname is optional. */
	if (bs.key.ifname[0]) {
		memset(bs.key.ifname, 0, sizeof(bs.key.ifname));
		bsp = hash_lookup(bfd_key_hash, &bs);
		if (bsp) {
			log_debug(" peer %s found, but ifp %s ignored",
				  peer_buf, key.ifname);
			return bsp;
		}
	}

	/* Handle cases where local-address and ifname are optional. */
	if (bs.key.family == AF_INET) {
		memset(&bs.key.local, 0, sizeof(bs.key.local));
		bsp = hash_lookup(bfd_key_hash, &bs);
		if (bsp) {
			char addr_buf[INET6_ADDRSTRLEN];

			inet_ntop(bs.key.family, &bs.key.local, addr_buf,
				  sizeof(addr_buf));
			log_debug(" peer %s found, but ifp %s"
				  " and loc-addr %s ignored",
				  peer_buf, key.ifname,
				  addr_buf);
			return bsp;
		}
	}
	bs.key = key;

	/* Handle case where a context more complex ctx is present.
	 * input has no iface nor local-address, but a context may
	 * exist
	 */
	ctx.result = NULL;
	ctx.given = &bs;
	hash_walk(bfd_key_hash,
		  &bfd_key_lookup_ignore_partial_walker,
		  &ctx);
	/* change key */
	if (ctx.result) {
		bsp = ctx.result;
		log_debug(" peer %s found, but ifp"
			  " and/or loc-addr params ignored", peer_buf);
	}
	return bsp;
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

struct bfd_session *bfd_key_delete(struct bfd_key key)
{
	struct bfd_session bs, *bsp;

	bs.key = key;
	bsp = hash_lookup(bfd_key_hash, &bs);
	if (bsp == NULL && key.ifname[0]) {
		memset(bs.key.ifname, 0, sizeof(bs.key.ifname));
		bsp = hash_lookup(bfd_key_hash, &bs);
	}

	return hash_release(bfd_key_hash, bsp);
}

/* Iteration functions. */
void bfd_id_iterate(hash_iter_func hif, void *arg)
{
	hash_iterate(bfd_id_hash, hif, arg);
}

void bfd_key_iterate(hash_iter_func hif, void *arg)
{
	hash_iterate(bfd_key_hash, hif, arg);
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

bool bfd_key_insert(struct bfd_session *bs)
{
	return (hash_get(bfd_key_hash, bs, hash_alloc_intern) == bs);
}

void bfd_initialize(void)
{
	bfd_id_hash = hash_create(bfd_id_hash_do, bfd_id_hash_cmp,
				  "BFD session discriminator hash");
	bfd_key_hash = hash_create(bfd_key_hash_do, bfd_key_hash_cmp,
				   "BFD session hash");
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
	assert(bfd_key_hash->count == 0);

	/* Now free the hashes themselves. */
	hash_free(bfd_id_hash);
	hash_free(bfd_key_hash);
}

struct bfd_session_iterator {
	int bsi_stop;
	bool bsi_mhop;
	const struct bfd_session *bsi_bs;
};

static int _bfd_session_next(struct hash_bucket *hb, void *arg)
{
	struct bfd_session_iterator *bsi = arg;
	struct bfd_session *bs = hb->data;

	/* Previous entry signaled stop. */
	if (bsi->bsi_stop == 1) {
		/* Match the single/multi hop sessions. */
		if (bs->key.mhop != bsi->bsi_mhop)
			return HASHWALK_CONTINUE;

		bsi->bsi_bs = bs;
		return HASHWALK_ABORT;
	}

	/* We found the current item, stop in the next one. */
	if (bsi->bsi_bs == hb->data) {
		bsi->bsi_stop = 1;
		/* Set entry to NULL to signal end of list. */
		bsi->bsi_bs = NULL;
	} else if (bsi->bsi_bs == NULL && bsi->bsi_mhop == bs->key.mhop) {
		/* We want the first list item. */
		bsi->bsi_stop = 1;
		bsi->bsi_bs = hb->data;
		return HASHWALK_ABORT;
	}

	return HASHWALK_CONTINUE;
}

/*
 * bfd_session_next: uses the current session to find the next.
 *
 * `bs` might point to NULL to get the first item of the data structure.
 */
const struct bfd_session *bfd_session_next(const struct bfd_session *bs,
					   bool mhop)
{
	struct bfd_session_iterator bsi;

	bsi.bsi_stop = 0;
	bsi.bsi_bs = bs;
	bsi.bsi_mhop = mhop;
	hash_walk(bfd_key_hash, _bfd_session_next, &bsi);
	if (bsi.bsi_stop == 0)
		return NULL;

	return bsi.bsi_bs;
}

static void _bfd_session_remove_manual(struct hash_bucket *hb,
				       void *arg __attribute__((__unused__)))
{
	struct bfd_session *bs = hb->data;

	/* Delete only manually configured sessions. */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_CONFIG) == 0)
		return;

	bs->refcount--;
	BFD_UNSET_FLAG(bs->flags, BFD_SESS_FLAG_CONFIG);

	/* Don't delete sessions still in use. */
	if (bs->refcount != 0)
		return;

	bfd_session_free(bs);
}

/*
 * bfd_sessions_remove_manual: remove all manually configured sessions.
 *
 * NOTE: this function doesn't remove automatically created sessions.
 */
void bfd_sessions_remove_manual(void)
{
	hash_iterate(bfd_key_hash, _bfd_session_remove_manual, NULL);
}

/*
 * VRF related functions.
 */
static int bfd_vrf_new(struct vrf *vrf)
{
	log_debug("VRF Created: %s(%u)", vrf->name, vrf->vrf_id);
	return 0;
}

static int bfd_vrf_delete(struct vrf *vrf)
{
	log_debug("VRF Deletion: %s(%u)", vrf->name, vrf->vrf_id);
	return 0;
}

static int bfd_vrf_update(struct vrf *vrf)
{
	if (!vrf_is_enabled(vrf))
		return 0;
	log_debug("VRF update: %s(%u)", vrf->name, vrf->vrf_id);
	/* a different name is given; update bfd list */
	bfdd_sessions_enable_vrf(vrf);
	return 0;
}

static int bfd_vrf_enable(struct vrf *vrf)
{
	struct bfd_vrf_global *bvrf;

	/* a different name */
	if (!vrf->info) {
		bvrf = XCALLOC(MTYPE_BFDD_VRF, sizeof(struct bfd_vrf_global));
		bvrf->vrf = vrf;
		vrf->info = (void *)bvrf;
	} else
		bvrf = vrf->info;
	log_debug("VRF enable add %s id %u", vrf->name, vrf->vrf_id);
	if (vrf->vrf_id == VRF_DEFAULT ||
	    vrf_get_backend() == VRF_BACKEND_NETNS) {
		if (!bvrf->bg_shop)
			bvrf->bg_shop = bp_udp_shop(vrf->vrf_id);
		if (!bvrf->bg_mhop)
			bvrf->bg_mhop = bp_udp_mhop(vrf->vrf_id);
		if (!bvrf->bg_shop6)
			bvrf->bg_shop6 = bp_udp6_shop(vrf->vrf_id);
		if (!bvrf->bg_mhop6)
			bvrf->bg_mhop6 = bp_udp6_mhop(vrf->vrf_id);
		if (!bvrf->bg_echo)
			bvrf->bg_echo = bp_echo_socket(vrf->vrf_id);
		if (!bvrf->bg_echov6)
			bvrf->bg_echov6 = bp_echov6_socket(vrf->vrf_id);

		/* Add descriptors to the event loop. */
		if (!bvrf->bg_ev[0])
			thread_add_read(master, bfd_recv_cb, bvrf, bvrf->bg_shop,
					&bvrf->bg_ev[0]);
		if (!bvrf->bg_ev[1])
			thread_add_read(master, bfd_recv_cb, bvrf, bvrf->bg_mhop,
					&bvrf->bg_ev[1]);
		if (!bvrf->bg_ev[2])
			thread_add_read(master, bfd_recv_cb, bvrf, bvrf->bg_shop6,
					&bvrf->bg_ev[2]);
		if (!bvrf->bg_ev[3])
			thread_add_read(master, bfd_recv_cb, bvrf, bvrf->bg_mhop6,
					&bvrf->bg_ev[3]);
		if (!bvrf->bg_ev[4])
			thread_add_read(master, bfd_recv_cb, bvrf, bvrf->bg_echo,
					&bvrf->bg_ev[4]);
		if (!bvrf->bg_ev[5])
			thread_add_read(master, bfd_recv_cb, bvrf, bvrf->bg_echov6,
					&bvrf->bg_ev[5]);
	}
	if (vrf->vrf_id != VRF_DEFAULT) {
		bfdd_zclient_register(vrf->vrf_id);
		bfdd_sessions_enable_vrf(vrf);
	}
	return 0;
}

static int bfd_vrf_disable(struct vrf *vrf)
{
	struct bfd_vrf_global *bvrf;

	if (!vrf->info)
		return 0;
	bvrf = vrf->info;

	if (vrf->vrf_id != VRF_DEFAULT) {
		bfdd_sessions_disable_vrf(vrf);
		bfdd_zclient_unregister(vrf->vrf_id);
	}

	log_debug("VRF disable %s id %d", vrf->name, vrf->vrf_id);

	/* Disable read/write poll triggering. */
	THREAD_OFF(bvrf->bg_ev[0]);
	THREAD_OFF(bvrf->bg_ev[1]);
	THREAD_OFF(bvrf->bg_ev[2]);
	THREAD_OFF(bvrf->bg_ev[3]);
	THREAD_OFF(bvrf->bg_ev[4]);
	THREAD_OFF(bvrf->bg_ev[5]);

	/* Close all descriptors. */
	socket_close(&bvrf->bg_echo);
	socket_close(&bvrf->bg_shop);
	socket_close(&bvrf->bg_mhop);
	socket_close(&bvrf->bg_shop6);
	socket_close(&bvrf->bg_mhop6);
	socket_close(&bvrf->bg_echo);
	socket_close(&bvrf->bg_echov6);

	/* free context */
	XFREE(MTYPE_BFDD_VRF, bvrf);
	vrf->info = NULL;

	return 0;
}

void bfd_vrf_init(void)
{
	vrf_init(bfd_vrf_new, bfd_vrf_enable, bfd_vrf_disable,
		 bfd_vrf_delete, bfd_vrf_update);
}

void bfd_vrf_terminate(void)
{
	vrf_terminate();
}

struct bfd_vrf_global *bfd_vrf_look_by_session(struct bfd_session *bfd)
{
	struct vrf *vrf;

	if (!vrf_is_backend_netns()) {
		vrf = vrf_lookup_by_id(VRF_DEFAULT);
		if (vrf)
			return (struct bfd_vrf_global *)vrf->info;
		return NULL;
	}
	if (!bfd)
		return NULL;
	if (!bfd->vrf)
		return NULL;
	return bfd->vrf->info;
}

void bfd_session_update_vrf_name(struct bfd_session *bs, struct vrf *vrf)
{
	if (!vrf || !bs)
		return;
	/* update key */
	hash_release(bfd_key_hash, bs);
	/*
	 * HACK: Change the BFD VRF in the running configuration directly,
	 * bypassing the northbound layer. This is necessary to avoid deleting
	 * the BFD and readding it in the new VRF, which would have
	 * several implications.
	 */
	if (yang_module_find("frr-bfdd") && bs->key.vrfname[0]) {
		struct lyd_node *bfd_dnode;
		char xpath[XPATH_MAXLEN], xpath_srcaddr[XPATH_MAXLEN + 32];
		char addr_buf[INET6_ADDRSTRLEN];
		int slen;

		/* build xpath */
		if (bs->key.mhop) {
			inet_ntop(bs->key.family, &bs->key.local, addr_buf, sizeof(addr_buf));
			snprintf(xpath_srcaddr, sizeof(xpath_srcaddr), "[source-addr='%s']",
				 addr_buf);
		} else
			xpath_srcaddr[0] = 0;
		inet_ntop(bs->key.family, &bs->key.peer, addr_buf, sizeof(addr_buf));
		slen = snprintf(xpath, sizeof(xpath),
				"/frr-bfdd:bfdd/bfd/sessions/%s%s[dest-addr='%s']",
				bs->key.mhop ? "multi-hop" : "single-hop", xpath_srcaddr,
				addr_buf);
		if (bs->key.ifname[0])
			slen += snprintf(xpath + slen, sizeof(xpath) - slen,
					 "[interface='%s']", bs->key.ifname);
		else
			slen += snprintf(xpath + slen, sizeof(xpath) - slen,
					 "[interface='']");
		snprintf(xpath + slen, sizeof(xpath) - slen, "[vrf='%s']/vrf",
			 bs->key.vrfname);

		bfd_dnode = yang_dnode_get(running_config->dnode, xpath,
					   bs->key.vrfname);
		if (bfd_dnode) {
			yang_dnode_change_leaf(bfd_dnode, vrf->name);
			running_config->version++;
		}
	}
	memset(bs->key.vrfname, 0, sizeof(bs->key.vrfname));
	strlcpy(bs->key.vrfname, vrf->name, sizeof(bs->key.vrfname));
	hash_get(bfd_key_hash, bs, hash_alloc_intern);
}
