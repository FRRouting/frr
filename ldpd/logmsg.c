// SPDX-License-Identifier: ISC
/*	$OpenBSD$ */

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 */

#include <zebra.h>
#include "lib/printfrr.h"

#include "mpls.h"

#include "ldpd.h"
#include "ldpe.h"
#include "lde.h"

#define NUM_LOGS	4
const char *
log_sockaddr(void *vp)
{
	static char	 buf[NUM_LOGS][NI_MAXHOST];
	static int	 round = 0;
	struct sockaddr	*sa = vp;

	round = (round + 1) % NUM_LOGS;

	if (getnameinfo(sa, sockaddr_len(sa), buf[round], NI_MAXHOST, NULL, 0,
	    NI_NUMERICHOST))
		return ("(unknown)");
	else
		return (buf[round]);
}

const char *
log_in6addr(const struct in6_addr *addr)
{
	struct sockaddr_in6	sa_in6;

	memset(&sa_in6, 0, sizeof(sa_in6));
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	sa_in6.sin6_len = sizeof(sa_in6);
#endif
	sa_in6.sin6_family = AF_INET6;
	sa_in6.sin6_addr = *addr;

	recoverscope(&sa_in6);

	return (log_sockaddr(&sa_in6));
}

const char *
log_in6addr_scope(const struct in6_addr *addr, ifindex_t ifindex)
{
	struct sockaddr_in6	sa_in6;

	memset(&sa_in6, 0, sizeof(sa_in6));
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	sa_in6.sin6_len = sizeof(sa_in6);
#endif
	sa_in6.sin6_family = AF_INET6;
	sa_in6.sin6_addr = *addr;

	addscope(&sa_in6, ifindex);

	return (log_sockaddr(&sa_in6));
}

const char *
log_addr(int af, const union ldpd_addr *addr)
{
	static char	 buf[NUM_LOGS][INET6_ADDRSTRLEN];
	static int	 round = 0;

	switch (af) {
	case AF_INET:
		round = (round + 1) % NUM_LOGS;
		if (inet_ntop(AF_INET, &addr->v4, buf[round],
		    sizeof(buf[round])) == NULL)
			return ("???");
		return (buf[round]);
	case AF_INET6:
		return (log_in6addr(&addr->v6));
	default:
		break;
	}

	return ("???");
}

#define	TF_BUFS	4
#define	TF_LEN	32

char *
log_label(uint32_t label)
{
	char		*buf;
	static char	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	static int	 idx = 0;

	buf = tfbuf[idx++];
	if (idx == TF_BUFS)
		idx = 0;

	switch (label) {
	case NO_LABEL:
		snprintf(buf, TF_LEN, "-");
		break;
	case MPLS_LABEL_IMPLICIT_NULL:
		snprintf(buf, TF_LEN, "imp-null");
		break;
	case MPLS_LABEL_IPV4_EXPLICIT_NULL:
	case MPLS_LABEL_IPV6_EXPLICIT_NULL:
		snprintf(buf, TF_LEN, "exp-null");
		break;
	default:
		snprintf(buf, TF_LEN, "%u", label);
		break;
	}

	return (buf);
}

const char *
log_time(time_t t)
{
	char		*buf;
	static char	 tfbuf[TF_BUFS][TF_LEN];	/* ring buffer */
	static int	 idx = 0;
	uint64_t	 sec, min, hrs, day, week;

	buf = tfbuf[idx++];
	if (idx == TF_BUFS)
		idx = 0;

	week = t;

	sec = week % 60;
	week /= 60;
	min = week % 60;
	week /= 60;
	hrs = week % 24;
	week /= 24;
	day = week % 7;
	week /= 7;

	if (week > 0)
		snprintfrr(buf, TF_LEN,
			   "%02" PRIu64 "w%01" PRIu64 "d%02" PRIu64 "h", week,
			   day, hrs);
	else if (day > 0)
		snprintfrr(buf, TF_LEN,
			   "%01" PRIu64 "d%02" PRIu64 "h%02" PRIu64 "m", day,
			   hrs, min);
	else
		snprintfrr(buf, TF_LEN,
			   "%02" PRIu64 ":%02" PRIu64 ":%02" PRIu64, hrs, min,
			   sec);

	return (buf);
}

char *
log_hello_src(const struct hello_source *src)
{
	static char buf[64];

	switch (src->type) {
	case HELLO_LINK:
		snprintf(buf, sizeof(buf), "iface %s",
		    src->link.ia->iface->name);
		break;
	case HELLO_TARGETED:
		snprintf(buf, sizeof(buf), "source %s",
		    log_addr(src->target->af, &src->target->addr));
		break;
	}

	return (buf);
}

const char *
log_map(const struct map *map)
{
	static char	buf[128];

	switch (map->type) {
	case MAP_TYPE_WILDCARD:
		if (snprintf(buf, sizeof(buf), "wildcard") < 0)
			return ("???");
		break;
	case MAP_TYPE_PREFIX:
		if (snprintf(buf, sizeof(buf), "%s/%u",
		    log_addr(map->fec.prefix.af, &map->fec.prefix.prefix),
		    map->fec.prefix.prefixlen) == -1)
			return ("???");
		break;
	case MAP_TYPE_PWID:
		if (snprintf(buf, sizeof(buf), "pw-id %u group-id %u (%s)",
		    map->fec.pwid.pwid, map->fec.pwid.group_id,
		    pw_type_name(map->fec.pwid.type)) == -1)
			return ("???");
		break;
	case MAP_TYPE_TYPED_WCARD:
		if (snprintf(buf, sizeof(buf), "typed wildcard") < 0)
			return ("???");
		switch (map->fec.twcard.type) {
		case MAP_TYPE_PREFIX:
			if (snprintf(buf + strlen(buf), sizeof(buf) -
			    strlen(buf), " (prefix, address-family %s)",
			    af_name(map->fec.twcard.u.prefix_af)) < 0)
				return ("???");
			break;
		case MAP_TYPE_PWID:
			if (snprintf(buf + strlen(buf), sizeof(buf) -
			    strlen(buf), " (pwid, type %s)",
			    pw_type_name(map->fec.twcard.u.pw_type)) < 0)
				return ("???");
			break;
		default:
			if (snprintf(buf + strlen(buf), sizeof(buf) -
			    strlen(buf), " (unknown type)") < 0)
				return ("???");
			break;
		}
		break;
	default:
		return ("???");
	}

	return (buf);
}

const char *
log_fec(const struct fec *fec)
{
	static char	buf[64];
	union ldpd_addr	addr;

	switch (fec->type) {
	case FEC_TYPE_IPV4:
		addr.v4 = fec->u.ipv4.prefix;
		if (snprintf(buf, sizeof(buf), "ipv4 %s/%u",
		    log_addr(AF_INET, &addr), fec->u.ipv4.prefixlen) == -1)
			return ("???");
		break;
	case FEC_TYPE_IPV6:
		addr.v6 = fec->u.ipv6.prefix;
		if (snprintf(buf, sizeof(buf), "ipv6 %s/%u",
		    log_addr(AF_INET6, &addr), fec->u.ipv6.prefixlen) == -1)
			return ("???");
		break;
	case FEC_TYPE_PWID:
		if (snprintfrr(buf, sizeof(buf),
			       "pwid %u (%s) - %pI4",
			       fec->u.pwid.pwid, pw_type_name(fec->u.pwid.type),
			       &fec->u.pwid.lsr_id) == -1)
			return ("???");
		break;
	default:
		return ("???");
	}

	return (buf);
}

/* names */
const char *
af_name(int af)
{
	switch (af) {
	case AF_INET:
		return ("ipv4");
	case AF_INET6:
		return ("ipv6");
#ifdef AF_MPLS
	case AF_MPLS:
		return ("mpls");
#endif
	default:
		return ("UNKNOWN");
	}
}

const char *
socket_name(int type)
{
	switch (type) {
	case LDP_SOCKET_DISC:
		return ("discovery");
	case LDP_SOCKET_EDISC:
		return ("extended discovery");
	case LDP_SOCKET_SESSION:
		return ("session");
	default:
		return ("UNKNOWN");
	}
}

const char *
nbr_state_name(int state)
{
	switch (state) {
	case NBR_STA_PRESENT:
		return ("PRESENT");
	case NBR_STA_INITIAL:
		return ("INITIALIZED");
	case NBR_STA_OPENREC:
		return ("OPENREC");
	case NBR_STA_OPENSENT:
		return ("OPENSENT");
	case NBR_STA_OPER:
		return ("OPERATIONAL");
	default:
		return ("UNKNOWN");
	}
}

const char *
if_state_name(int state)
{
	switch (state) {
	case IF_STA_DOWN:
		return ("DOWN");
	case IF_STA_ACTIVE:
		return ("ACTIVE");
	default:
		return ("UNKNOWN");
	}
}

const char *
if_type_name(enum iface_type type)
{
	switch (type) {
	case IF_TYPE_POINTOPOINT:
		return ("POINTOPOINT");
	case IF_TYPE_BROADCAST:
		return ("BROADCAST");
	}
	/* NOTREACHED */
	return ("UNKNOWN");
}

const char *
msg_name(uint16_t msg)
{
	static char buf[16];

	switch (msg) {
	case MSG_TYPE_NOTIFICATION:
		return ("notification");
	case MSG_TYPE_HELLO:
		return ("hello");
	case MSG_TYPE_INIT:
		return ("initialization");
	case MSG_TYPE_KEEPALIVE:
		return ("keepalive");
	case MSG_TYPE_CAPABILITY:
		return ("capability");
	case MSG_TYPE_ADDR:
		return ("address");
	case MSG_TYPE_ADDRWITHDRAW:
		return ("address withdraw");
	case MSG_TYPE_LABELMAPPING:
		return ("label mapping");
	case MSG_TYPE_LABELREQUEST:
		return ("label request");
	case MSG_TYPE_LABELWITHDRAW:
		return ("label withdraw");
	case MSG_TYPE_LABELRELEASE:
		return ("label release");
	case MSG_TYPE_LABELABORTREQ:
	default:
		snprintf(buf, sizeof(buf), "[%08x]", msg);
		return (buf);
	}
}

const char *
status_code_name(uint32_t status)
{
	static char buf[16];

	switch (status) {
	case S_SUCCESS:
		return ("Success");
	case S_BAD_LDP_ID:
		return ("Bad LDP Identifier");
	case S_BAD_PROTO_VER:
		return ("Bad Protocol Version");
	case S_BAD_PDU_LEN:
		return ("Bad PDU Length");
	case S_UNKNOWN_MSG:
		return ("Unknown Message Type");
	case S_BAD_MSG_LEN:
		return ("Bad Message Length");
	case S_UNKNOWN_TLV:
		return ("Unknown TLV");
	case S_BAD_TLV_LEN:
		return ("Bad TLV Length");
	case S_BAD_TLV_VAL:
		return ("Malformed TLV Value");
	case S_HOLDTIME_EXP:
		return ("Hold Timer Expired");
	case S_SHUTDOWN:
		return ("Shutdown");
	case S_LOOP_DETECTED:
		return ("Loop Detected");
	case S_UNKNOWN_FEC:
		return ("Unknown FEC");
	case S_NO_ROUTE:
		return ("No Route");
	case S_NO_LABEL_RES:
		return ("No Label Resources");
	case S_AVAILABLE:
		return ("Label Resources Available");
	case S_NO_HELLO:
		return ("Session Rejected, No Hello");
	case S_PARM_ADV_MODE:
		return ("Rejected Advertisement Mode Parameter");
	case S_MAX_PDU_LEN:
		return ("Rejected Max PDU Length Parameter");
	case S_PARM_L_RANGE:
		return ("Rejected Label Range Parameter");
	case S_KEEPALIVE_TMR:
		return ("KeepAlive Timer Expired");
	case S_LAB_REQ_ABRT:
		return ("Label Request Aborted");
	case S_MISS_MSG:
		return ("Missing Message Parameters");
	case S_UNSUP_ADDR:
		return ("Unsupported Address Family");
	case S_KEEPALIVE_BAD:
		return ("Bad KeepAlive Time");
	case S_INTERN_ERR:
		return ("Internal Error");
	case S_ILLEGAL_CBIT:
		return ("Illegal C-Bit");
	case S_WRONG_CBIT:
		return ("Wrong C-Bit");
	case S_INCPT_BITRATE:
		return ("Incompatible bit-rate");
	case S_CEP_MISCONF:
		return ("CEP-TDM mis-configuration");
	case S_PW_STATUS:
		return ("PW Status");
	case S_UNASSIGN_TAI:
		return ("Unassigned/Unrecognized TAI");
	case S_MISCONF_ERR:
		return ("Generic Misconfiguration Error");
	case S_WITHDRAW_MTHD:
		return ("Label Withdraw PW Status Method");
	case S_UNSSUPORTDCAP:
		return ("Unsupported Capability");
	case S_ENDOFLIB:
		return ("End-of-LIB");
	case S_TRANS_MISMTCH:
		return ("Transport Connection Mismatch");
	case S_DS_NONCMPLNCE:
		return ("Dual-Stack Noncompliance");
	default:
		snprintf(buf, sizeof(buf), "[%08x]", status);
		return (buf);
	}
}

const char *
pw_type_name(uint16_t pw_type)
{
	static char buf[64];

	switch (pw_type) {
	case PW_TYPE_ETHERNET_TAGGED:
		return ("Eth Tagged");
	case PW_TYPE_ETHERNET:
		return ("Ethernet");
	case PW_TYPE_WILDCARD:
		return ("Wildcard");
	default:
		snprintf(buf, sizeof(buf), "[%0x]", pw_type);
		return (buf);
	}
}

const char *
pw_error_code(uint8_t status)
{
	static char buf[16];

	switch (status) {
	case F_PW_NO_ERR:
		return ("No Error");
	case F_PW_LOCAL_NOT_FWD:
		return ("local not forwarding");
	case F_PW_REMOTE_NOT_FWD:
		return ("remote not forwarding");
	case F_PW_NO_REMOTE_LABEL:
		return ("no remote label");
	case F_PW_MTU_MISMATCH:
		return ("mtu mismatch between peers");
	default:
		snprintf(buf, sizeof(buf), "[%0x]", status);
		return (buf);
	}
}
