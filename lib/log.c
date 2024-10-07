// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Logging of zebra
 * Copyright (C) 1997, 1998, 1999 Kunihiro Ishiguro
 */

#define FRR_DEFINE_DESC_TABLE

#include <zebra.h>

#ifdef HAVE_GLIBC_BACKTRACE
#include <execinfo.h>
#endif /* HAVE_GLIBC_BACKTRACE */

#include "zclient.h"
#include "log.h"
#include "memory.h"
#include "command.h"
#include "lib_errors.h"
#include "lib/hook.h"
#include "printfrr.h"
#include "frr_pthread.h"

#ifdef HAVE_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <dlfcn.h>
#endif

/**
 * Looks up a message in a message list by key.
 *
 * If the message is not found, returns the provided error message.
 *
 * Terminates when it hits a struct message that's all zeros.
 *
 * @param mz the message list
 * @param kz the message key
 * @param nf the message to return if not found
 * @return the message
 */
const char *lookup_msg(const struct message *mz, int kz, const char *nf)
{
	static struct message nt = {0};
	const char *rz = nf ? nf : "(no message found)";
	const struct message *pnt;
	for (pnt = mz; memcmp(pnt, &nt, sizeof(struct message)); pnt++)
		if (pnt->key == kz) {
			rz = pnt->str ? pnt->str : rz;
			break;
		}
	return rz;
}

/* For time string format. */
size_t frr_timestamp(int timestamp_precision, char *buf, size_t buflen)
{
	static struct {
		time_t last;
		size_t len;
		char buf[28];
	} cache;
	struct timeval clock;

	gettimeofday(&clock, NULL);

	/* first, we update the cache if the time has changed */
	if (cache.last != clock.tv_sec) {
		struct tm tm;
		cache.last = clock.tv_sec;
		localtime_r(&cache.last, &tm);
		cache.len = strftime(cache.buf, sizeof(cache.buf),
				     "%Y/%m/%d %H:%M:%S", &tm);
	}
	/* note: it's not worth caching the subsecond part, because
	   chances are that back-to-back calls are not sufficiently close
	   together
	   for the clock not to have ticked forward */

	if (buflen > cache.len) {
		memcpy(buf, cache.buf, cache.len);
		if ((timestamp_precision > 0)
		    && (buflen > cache.len + 1 + timestamp_precision)) {
			/* should we worry about locale issues? */
			static const int divisor[] = {0,   100000, 10000, 1000,
						      100, 10,     1};
			int prec;
			char *p = buf + cache.len + 1
				  + (prec = timestamp_precision);
			*p-- = '\0';
			while (prec > 6)
			/* this is unlikely to happen, but protect anyway */
			{
				*p-- = '0';
				prec--;
			}
			clock.tv_usec /= divisor[prec];
			do {
				*p-- = '0' + (clock.tv_usec % 10);
				clock.tv_usec /= 10;
			} while (--prec > 0);
			*p = '.';
			return cache.len + 1 + timestamp_precision;
		}
		buf[cache.len] = '\0';
		return cache.len;
	}
	if (buflen > 0)
		buf[0] = '\0';
	return 0;
}

/*
 * crash handling
 *
 * NB: only AS-Safe (async-signal) functions can be used here!
 */

/* Note: the goal here is to use only async-signal-safe functions. */
void zlog_signal(int signo, const char *action, void *siginfo_v,
		 void *program_counter)
{
	siginfo_t *siginfo = siginfo_v;
	time_t now;
	char buf[sizeof("DEFAULT: Received signal S at T (si_addr 0xP, PC 0xP); aborting...")
		 + 100];
	struct fbuf fb = { .buf = buf, .pos = buf, .len = sizeof(buf) };

	time(&now);

	bprintfrr(&fb, "Received signal %d at %lld", signo, (long long)now);
	if (program_counter)
		bprintfrr(&fb, " (si_addr 0x%tx, PC 0x%tx)",
			  (ptrdiff_t)siginfo->si_addr,
			  (ptrdiff_t)program_counter);
	else
		bprintfrr(&fb, " (si_addr 0x%tx)",
			  (ptrdiff_t)siginfo->si_addr);
	bprintfrr(&fb, "; %s\n", action);

	zlog_sigsafe(fb.buf, fb.pos - fb.buf);

	zlog_backtrace_sigsafe(LOG_CRIT, program_counter);

	fb.pos = buf;

	struct event *tc;
	tc = pthread_getspecific(thread_current);

	if (!tc)
		bprintfrr(&fb, "no thread information available\n");
	else
		bprintfrr(&fb, "in thread %s scheduled from %s:%d %s()\n",
			  tc->xref->funcname, tc->xref->xref.file,
			  tc->xref->xref.line, tc->xref->xref.func);

	zlog_sigsafe(fb.buf, fb.pos - fb.buf);
}

/* Log a backtrace using only async-signal-safe functions.
   Needs to be enhanced to support syslog logging. */
void zlog_backtrace_sigsafe(int priority, void *program_counter)
{
#ifdef HAVE_LIBUNWIND
	char buf[256];
	struct fbuf fb = { .buf = buf, .len = sizeof(buf) };
	unw_cursor_t cursor;
	unw_context_t uc;
	unw_word_t ip, off, sp;
	Dl_info dlinfo;

	memset(&uc, 0, sizeof(uc));
	memset(&cursor, 0, sizeof(cursor));

	unw_getcontext(&uc);
	unw_init_local(&cursor, &uc);
	while (unw_step(&cursor) > 0) {
		char name[128] = "?";

		unw_get_reg(&cursor, UNW_REG_IP, &ip);
		unw_get_reg(&cursor, UNW_REG_SP, &sp);

		if (!unw_get_proc_name(&cursor, buf, sizeof(buf), &off))
			snprintfrr(name, sizeof(name), "%s+%#lx",
				   buf, (long)off);

		fb.pos = buf;
		if (unw_is_signal_frame(&cursor))
			bprintfrr(&fb, "    ---- signal ----\n");
		bprintfrr(&fb, "%-30s %16lx %16lx", name, (long)ip, (long)sp);
		if (dladdr((void *)ip, &dlinfo))
			bprintfrr(&fb, " %s (mapped at %p)",
				  dlinfo.dli_fname, dlinfo.dli_fbase);
		bprintfrr(&fb, "\n");
		zlog_sigsafe(fb.buf, fb.pos - fb.buf);
	}
#elif defined(HAVE_GLIBC_BACKTRACE)
	void *array[64];
	int size, i;
	char buf[128];
	struct fbuf fb = { .buf = buf, .pos = buf, .len = sizeof(buf) };
	char **bt = NULL;

	size = backtrace(array, array_size(array));
	if (size <= 0 || (size_t)size > array_size(array))
		return;

	bprintfrr(&fb, "Backtrace for %d stack frames:", size);
	zlog_sigsafe(fb.pos, fb.buf - fb.pos);

	bt = backtrace_symbols(array, size);

	for (i = 0; i < size; i++) {
		fb.pos = buf;
		if (bt)
			bprintfrr(&fb, "%s", bt[i]);
		else
			bprintfrr(&fb, "[bt %d] 0x%tx", i,
				  (ptrdiff_t)(array[i]));
		zlog_sigsafe(fb.buf, fb.pos - fb.buf);
	}
	if (bt)
		free(bt);
#endif /* HAVE_STRACK_TRACE */
}

void zlog_backtrace(int priority)
{
#ifdef HAVE_LIBUNWIND
	char buf[100];
	unw_cursor_t cursor = {};
	unw_context_t uc;
	unw_word_t ip, off, sp;
	Dl_info dlinfo;

	unw_getcontext(&uc);
	unw_init_local(&cursor, &uc);
	zlog(priority, "Backtrace:");
	while (unw_step(&cursor) > 0) {
		char name[128] = "?";

		unw_get_reg(&cursor, UNW_REG_IP, &ip);
		unw_get_reg(&cursor, UNW_REG_SP, &sp);

		if (unw_is_signal_frame(&cursor))
			zlog(priority, "    ---- signal ----");

		if (!unw_get_proc_name(&cursor, buf, sizeof(buf), &off))
			snprintf(name, sizeof(name), "%s+%#lx",
				buf, (long)off);

		if (dladdr((void *)ip, &dlinfo))
			zlog(priority, "%-30s %16lx %16lx %s (mapped at %p)",
				name, (long)ip, (long)sp,
				dlinfo.dli_fname, dlinfo.dli_fbase);
		else
			zlog(priority, "%-30s %16lx %16lx",
				name, (long)ip, (long)sp);
	}
#elif defined(HAVE_GLIBC_BACKTRACE)
	void *array[20];
	int size, i;
	char **strings;

	size = backtrace(array, array_size(array));
	if (size <= 0 || (size_t)size > array_size(array)) {
		flog_err_sys(
			EC_LIB_SYSTEM_CALL,
			"Cannot get backtrace, returned invalid # of frames %d (valid range is between 1 and %lu)",
			size, (unsigned long)(array_size(array)));
		return;
	}
	zlog(priority, "Backtrace for %d stack frames:", size);
	if (!(strings = backtrace_symbols(array, size))) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "Cannot get backtrace symbols (out of memory?)");
		for (i = 0; i < size; i++)
			zlog(priority, "[bt %d] %p", i, array[i]);
	} else {
		for (i = 0; i < size; i++)
			zlog(priority, "[bt %d] %s", i, strings[i]);
		free(strings);
	}
#else /* !HAVE_GLIBC_BACKTRACE && !HAVE_LIBUNWIND */
	zlog(priority, "No backtrace available on this platform.");
#endif
}

void zlog_thread_info(int log_level)
{
	struct event *tc;
	tc = pthread_getspecific(thread_current);

	if (tc)
		zlog(log_level,
		     "Current thread function %s, scheduled from file %s, line %u in %s()",
		     tc->xref->funcname, tc->xref->xref.file,
		     tc->xref->xref.line, tc->xref->xref.func);
	else
		zlog(log_level, "Current thread not known/applicable");
}

void memory_oom(size_t size, const char *name)
{
	zlog(LOG_CRIT,
	     "out of memory: failed to allocate %zu bytes for %s object",
	     size, name);
	zlog_backtrace(LOG_CRIT);
	log_memstats(stderr, "log");
	abort();
}

/* Wrapper around strerror to handle case where it returns NULL. */
const char *safe_strerror(int errnum)
{
	const char *s = strerror(errnum);
	return (s != NULL) ? s : "Unknown error";
}

#define DESC_ENTRY(T) [(T)] = { (T), (#T), '\0' }
static const struct zebra_desc_table command_types[] = {
	DESC_ENTRY(ZEBRA_INTERFACE_ADD),
	DESC_ENTRY(ZEBRA_INTERFACE_DELETE),
	DESC_ENTRY(ZEBRA_INTERFACE_ADDRESS_ADD),
	DESC_ENTRY(ZEBRA_INTERFACE_ADDRESS_DELETE),
	DESC_ENTRY(ZEBRA_INTERFACE_UP),
	DESC_ENTRY(ZEBRA_INTERFACE_DOWN),
	DESC_ENTRY(ZEBRA_INTERFACE_SET_MASTER),
	DESC_ENTRY(ZEBRA_INTERFACE_SET_PROTODOWN),
	DESC_ENTRY(ZEBRA_ROUTE_ADD),
	DESC_ENTRY(ZEBRA_ROUTE_DELETE),
	DESC_ENTRY(ZEBRA_ROUTE_NOTIFY_OWNER),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_ADD),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_DELETE),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_DEFAULT_ADD),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_DEFAULT_DELETE),
	DESC_ENTRY(ZEBRA_ROUTER_ID_ADD),
	DESC_ENTRY(ZEBRA_ROUTER_ID_DELETE),
	DESC_ENTRY(ZEBRA_ROUTER_ID_UPDATE),
	DESC_ENTRY(ZEBRA_HELLO),
	DESC_ENTRY(ZEBRA_CAPABILITIES),
	DESC_ENTRY(ZEBRA_NEXTHOP_REGISTER),
	DESC_ENTRY(ZEBRA_NEXTHOP_UNREGISTER),
	DESC_ENTRY(ZEBRA_NEXTHOP_UPDATE),
	DESC_ENTRY(ZEBRA_INTERFACE_NBR_ADDRESS_ADD),
	DESC_ENTRY(ZEBRA_INTERFACE_NBR_ADDRESS_DELETE),
	DESC_ENTRY(ZEBRA_INTERFACE_BFD_DEST_UPDATE),
	DESC_ENTRY(ZEBRA_BFD_DEST_REGISTER),
	DESC_ENTRY(ZEBRA_BFD_DEST_DEREGISTER),
	DESC_ENTRY(ZEBRA_BFD_DEST_UPDATE),
	DESC_ENTRY(ZEBRA_BFD_DEST_REPLAY),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_ROUTE_ADD),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_ROUTE_DEL),
	DESC_ENTRY(ZEBRA_VRF_ADD),
	DESC_ENTRY(ZEBRA_VRF_DELETE),
	DESC_ENTRY(ZEBRA_VRF_LABEL),
	DESC_ENTRY(ZEBRA_BFD_CLIENT_REGISTER),
	DESC_ENTRY(ZEBRA_BFD_CLIENT_DEREGISTER),
	DESC_ENTRY(ZEBRA_INTERFACE_ENABLE_RADV),
	DESC_ENTRY(ZEBRA_INTERFACE_DISABLE_RADV),
	DESC_ENTRY(ZEBRA_NEXTHOP_LOOKUP_MRIB),
	DESC_ENTRY(ZEBRA_INTERFACE_LINK_PARAMS),
	DESC_ENTRY(ZEBRA_MPLS_LABELS_ADD),
	DESC_ENTRY(ZEBRA_MPLS_LABELS_DELETE),
	DESC_ENTRY(ZEBRA_MPLS_LABELS_REPLACE),
	DESC_ENTRY(ZEBRA_SR_POLICY_SET),
	DESC_ENTRY(ZEBRA_SR_POLICY_DELETE),
	DESC_ENTRY(ZEBRA_SR_POLICY_NOTIFY_STATUS),
	DESC_ENTRY(ZEBRA_IPMR_ROUTE_STATS),
	DESC_ENTRY(ZEBRA_LABEL_MANAGER_CONNECT),
	DESC_ENTRY(ZEBRA_LABEL_MANAGER_CONNECT_ASYNC),
	DESC_ENTRY(ZEBRA_GET_LABEL_CHUNK),
	DESC_ENTRY(ZEBRA_RELEASE_LABEL_CHUNK),
	DESC_ENTRY(ZEBRA_FEC_REGISTER),
	DESC_ENTRY(ZEBRA_FEC_UNREGISTER),
	DESC_ENTRY(ZEBRA_FEC_UPDATE),
	DESC_ENTRY(ZEBRA_ADVERTISE_DEFAULT_GW),
	DESC_ENTRY(ZEBRA_ADVERTISE_SVI_MACIP),
	DESC_ENTRY(ZEBRA_ADVERTISE_SUBNET),
	DESC_ENTRY(ZEBRA_ADVERTISE_ALL_VNI),
	DESC_ENTRY(ZEBRA_LOCAL_ES_ADD),
	DESC_ENTRY(ZEBRA_LOCAL_ES_DEL),
	DESC_ENTRY(ZEBRA_REMOTE_ES_VTEP_ADD),
	DESC_ENTRY(ZEBRA_REMOTE_ES_VTEP_DEL),
	DESC_ENTRY(ZEBRA_LOCAL_ES_EVI_ADD),
	DESC_ENTRY(ZEBRA_LOCAL_ES_EVI_DEL),
	DESC_ENTRY(ZEBRA_VNI_ADD),
	DESC_ENTRY(ZEBRA_VNI_DEL),
	DESC_ENTRY(ZEBRA_L3VNI_ADD),
	DESC_ENTRY(ZEBRA_L3VNI_DEL),
	DESC_ENTRY(ZEBRA_REMOTE_VTEP_ADD),
	DESC_ENTRY(ZEBRA_REMOTE_VTEP_DEL),
	DESC_ENTRY(ZEBRA_MACIP_ADD),
	DESC_ENTRY(ZEBRA_MACIP_DEL),
	DESC_ENTRY(ZEBRA_IP_PREFIX_ROUTE_ADD),
	DESC_ENTRY(ZEBRA_IP_PREFIX_ROUTE_DEL),
	DESC_ENTRY(ZEBRA_REMOTE_MACIP_ADD),
	DESC_ENTRY(ZEBRA_REMOTE_MACIP_DEL),
	DESC_ENTRY(ZEBRA_DUPLICATE_ADDR_DETECTION),
	DESC_ENTRY(ZEBRA_PW_ADD),
	DESC_ENTRY(ZEBRA_PW_DELETE),
	DESC_ENTRY(ZEBRA_PW_SET),
	DESC_ENTRY(ZEBRA_PW_UNSET),
	DESC_ENTRY(ZEBRA_PW_STATUS_UPDATE),
	DESC_ENTRY(ZEBRA_RULE_ADD),
	DESC_ENTRY(ZEBRA_RULE_DELETE),
	DESC_ENTRY(ZEBRA_RULE_NOTIFY_OWNER),
	DESC_ENTRY(ZEBRA_TABLE_MANAGER_CONNECT),
	DESC_ENTRY(ZEBRA_GET_TABLE_CHUNK),
	DESC_ENTRY(ZEBRA_RELEASE_TABLE_CHUNK),
	DESC_ENTRY(ZEBRA_IPSET_CREATE),
	DESC_ENTRY(ZEBRA_IPSET_DESTROY),
	DESC_ENTRY(ZEBRA_IPSET_ENTRY_ADD),
	DESC_ENTRY(ZEBRA_IPSET_ENTRY_DELETE),
	DESC_ENTRY(ZEBRA_IPSET_NOTIFY_OWNER),
	DESC_ENTRY(ZEBRA_IPSET_ENTRY_NOTIFY_OWNER),
	DESC_ENTRY(ZEBRA_IPTABLE_ADD),
	DESC_ENTRY(ZEBRA_IPTABLE_DELETE),
	DESC_ENTRY(ZEBRA_IPTABLE_NOTIFY_OWNER),
	DESC_ENTRY(ZEBRA_VXLAN_FLOOD_CONTROL),
	DESC_ENTRY(ZEBRA_VXLAN_SG_ADD),
	DESC_ENTRY(ZEBRA_VXLAN_SG_DEL),
	DESC_ENTRY(ZEBRA_VXLAN_SG_REPLAY),
	DESC_ENTRY(ZEBRA_MLAG_PROCESS_UP),
	DESC_ENTRY(ZEBRA_MLAG_PROCESS_DOWN),
	DESC_ENTRY(ZEBRA_MLAG_CLIENT_REGISTER),
	DESC_ENTRY(ZEBRA_MLAG_CLIENT_UNREGISTER),
	DESC_ENTRY(ZEBRA_MLAG_FORWARD_MSG),
	DESC_ENTRY(ZEBRA_NHG_ADD),
	DESC_ENTRY(ZEBRA_NHG_DEL),
	DESC_ENTRY(ZEBRA_NHG_NOTIFY_OWNER),
	DESC_ENTRY(ZEBRA_EVPN_REMOTE_NH_ADD),
	DESC_ENTRY(ZEBRA_EVPN_REMOTE_NH_DEL),
	DESC_ENTRY(ZEBRA_SRV6_LOCATOR_ADD),
	DESC_ENTRY(ZEBRA_SRV6_LOCATOR_DELETE),
	DESC_ENTRY(ZEBRA_SRV6_MANAGER_GET_LOCATOR_CHUNK),
	DESC_ENTRY(ZEBRA_SRV6_MANAGER_RELEASE_LOCATOR_CHUNK),
	DESC_ENTRY(ZEBRA_SRV6_MANAGER_GET_LOCATOR),
	DESC_ENTRY(ZEBRA_SRV6_MANAGER_GET_SRV6_SID),
	DESC_ENTRY(ZEBRA_SRV6_MANAGER_RELEASE_SRV6_SID),
	DESC_ENTRY(ZEBRA_ERROR),
	DESC_ENTRY(ZEBRA_CLIENT_CAPABILITIES),
	DESC_ENTRY(ZEBRA_OPAQUE_MESSAGE),
	DESC_ENTRY(ZEBRA_OPAQUE_REGISTER),
	DESC_ENTRY(ZEBRA_OPAQUE_UNREGISTER),
	DESC_ENTRY(ZEBRA_NEIGH_DISCOVER),
	DESC_ENTRY(ZEBRA_ROUTE_NOTIFY_REQUEST),
	DESC_ENTRY(ZEBRA_CLIENT_CLOSE_NOTIFY),
	DESC_ENTRY(ZEBRA_NEIGH_ADDED),
	DESC_ENTRY(ZEBRA_NEIGH_REMOVED),
	DESC_ENTRY(ZEBRA_NEIGH_GET),
	DESC_ENTRY(ZEBRA_NEIGH_REGISTER),
	DESC_ENTRY(ZEBRA_NEIGH_UNREGISTER),
	DESC_ENTRY(ZEBRA_NEIGH_IP_ADD),
	DESC_ENTRY(ZEBRA_NEIGH_IP_DEL),
	DESC_ENTRY(ZEBRA_CONFIGURE_ARP),
	DESC_ENTRY(ZEBRA_GRE_GET),
	DESC_ENTRY(ZEBRA_GRE_UPDATE),
	DESC_ENTRY(ZEBRA_GRE_SOURCE_SET),
	DESC_ENTRY(ZEBRA_TC_QDISC_INSTALL),
	DESC_ENTRY(ZEBRA_TC_QDISC_UNINSTALL),
	DESC_ENTRY(ZEBRA_TC_CLASS_ADD),
	DESC_ENTRY(ZEBRA_TC_CLASS_DELETE),
	DESC_ENTRY(ZEBRA_TC_FILTER_ADD),
	DESC_ENTRY(ZEBRA_TC_FILTER_DELETE),
	DESC_ENTRY(ZEBRA_OPAQUE_NOTIFY),
	DESC_ENTRY(ZEBRA_SRV6_SID_NOTIFY)
};
#undef DESC_ENTRY

static const struct zebra_desc_table unknown = {0, "unknown", '?'};

static const struct zebra_desc_table *zroute_lookup(unsigned int zroute)
{
	unsigned int i;

	if (zroute >= array_size(route_types)) {
		flog_err(EC_LIB_DEVELOPMENT, "unknown zebra route type: %u",
			 zroute);
		return &unknown;
	}
	if (zroute == route_types[zroute].type)
		return &route_types[zroute];
	for (i = 0; i < array_size(route_types); i++) {
		if (zroute == route_types[i].type) {
			zlog_warn(
				"internal error: route type table out of order while searching for %u, please notify developers",
				zroute);
			return &route_types[i];
		}
	}
	flog_err(EC_LIB_DEVELOPMENT,
		 "internal error: cannot find route type %u in table!", zroute);
	return &unknown;
}

const char *zebra_route_string(unsigned int zroute)
{
	return zroute_lookup(zroute)->string;
}

char zebra_route_char(unsigned int zroute)
{
	return zroute_lookup(zroute)->chr;
}

const char *zserv_command_string(unsigned int command)
{
	if (command >= array_size(command_types)) {
		flog_err(EC_LIB_DEVELOPMENT, "unknown zserv command type: %u",
			 command);
		return unknown.string;
	}
	return command_types[command].string;
}

#define DESC_ENTRY(T) [(T)] = {(T), (#T), '\0'}
static const struct zebra_desc_table gr_client_cap_types[] = {
	DESC_ENTRY(ZEBRA_CLIENT_GR_CAPABILITIES),
	DESC_ENTRY(ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE),
	DESC_ENTRY(ZEBRA_CLIENT_ROUTE_UPDATE_PENDING),
	DESC_ENTRY(ZEBRA_CLIENT_GR_DISABLE),
	DESC_ENTRY(ZEBRA_CLIENT_RIB_STALE_TIME),
};
#undef DESC_ENTRY

const char *zserv_gr_client_cap_string(uint32_t zcc)
{
	if (zcc >= array_size(gr_client_cap_types)) {
		flog_err(EC_LIB_DEVELOPMENT, "unknown zserv command type: %u",
			 zcc);
		return unknown.string;
	}
	return gr_client_cap_types[zcc].string;
}

int proto_name2num(const char *s)
{
	unsigned i;

	for (i = 0; i < array_size(route_types); ++i)
		if (strcasecmp(s, route_types[i].string) == 0)
			return route_types[i].type;
	return -1;
}

int proto_redistnum(int afi, const char *s)
{
	if (!s)
		return -1;

	if (afi == AFI_IP) {
		if (strmatch(s, "kernel"))
			return ZEBRA_ROUTE_KERNEL;
		else if (strmatch(s, "connected"))
			return ZEBRA_ROUTE_CONNECT;
		else if (strmatch(s, "local"))
			return ZEBRA_ROUTE_LOCAL;
		else if (strmatch(s, "static"))
			return ZEBRA_ROUTE_STATIC;
		else if (strmatch(s, "rip"))
			return ZEBRA_ROUTE_RIP;
		else if (strmatch(s, "eigrp"))
			return ZEBRA_ROUTE_EIGRP;
		else if (strmatch(s, "ospf"))
			return ZEBRA_ROUTE_OSPF;
		else if (strmatch(s, "isis"))
			return ZEBRA_ROUTE_ISIS;
		else if (strmatch(s, "bgp"))
			return ZEBRA_ROUTE_BGP;
		else if (strmatch(s, "table"))
			return ZEBRA_ROUTE_TABLE;
		else if (strmatch(s, "vnc"))
			return ZEBRA_ROUTE_VNC;
		else if (strmatch(s, "vnc-direct"))
			return ZEBRA_ROUTE_VNC_DIRECT;
		else if (strmatch(s, "nhrp"))
			return ZEBRA_ROUTE_NHRP;
		else if (strmatch(s, "babel"))
			return ZEBRA_ROUTE_BABEL;
		else if (strmatch(s, "sharp"))
			return ZEBRA_ROUTE_SHARP;
		else if (strmatch(s, "openfabric"))
			return ZEBRA_ROUTE_OPENFABRIC;
		else if (strmatch(s, "table-direct"))
			return ZEBRA_ROUTE_TABLE_DIRECT;
	}
	if (afi == AFI_IP6) {
		if (strmatch(s, "kernel"))
			return ZEBRA_ROUTE_KERNEL;
		else if (strmatch(s, "connected"))
			return ZEBRA_ROUTE_CONNECT;
		else if (strmatch(s, "local"))
			return ZEBRA_ROUTE_LOCAL;
		else if (strmatch(s, "static"))
			return ZEBRA_ROUTE_STATIC;
		else if (strmatch(s, "ripng"))
			return ZEBRA_ROUTE_RIPNG;
		else if (strmatch(s, "ospf6"))
			return ZEBRA_ROUTE_OSPF6;
		else if (strmatch(s, "isis"))
			return ZEBRA_ROUTE_ISIS;
		else if (strmatch(s, "bgp"))
			return ZEBRA_ROUTE_BGP;
		else if (strmatch(s, "table"))
			return ZEBRA_ROUTE_TABLE;
		else if (strmatch(s, "vnc"))
			return ZEBRA_ROUTE_VNC;
		else if (strmatch(s, "vnc-direct"))
			return ZEBRA_ROUTE_VNC_DIRECT;
		else if (strmatch(s, "nhrp"))
			return ZEBRA_ROUTE_NHRP;
		else if (strmatch(s, "babel"))
			return ZEBRA_ROUTE_BABEL;
		else if (strmatch(s, "sharp"))
			return ZEBRA_ROUTE_SHARP;
		else if (strmatch(s, "openfabric"))
			return ZEBRA_ROUTE_OPENFABRIC;
		else if (strmatch(s, "table-direct"))
			return ZEBRA_ROUTE_TABLE_DIRECT;
	}
	return -1;
}

void zlog_hexdump(const void *mem, size_t len)
{
	char line[64];
	const uint8_t *src = mem;
	const uint8_t *end = src + len;

	if (len == 0) {
		zlog_debug("%016lx: (zero length / no data)", (long)src);
		return;
	}

	while (src < end) {
		struct fbuf fb = {
			.buf = line,
			.pos = line,
			.len = sizeof(line),
		};
		const uint8_t *lineend = src + 8;
		unsigned line_bytes = 0;

		bprintfrr(&fb, "%016lx: ", (long)src);

		while (src < lineend && src < end) {
			bprintfrr(&fb, "%02x ", *src++);
			line_bytes++;
		}
		if (line_bytes < 8)
			bprintfrr(&fb, "%*s", (8 - line_bytes) * 3, "");

		src -= line_bytes;
		while (src < lineend && src < end && fb.pos < fb.buf + fb.len) {
			uint8_t byte = *src++;

			if (isprint(byte))
				*fb.pos++ = byte;
			else
				*fb.pos++ = '.';
		}

		zlog_debug("%.*s", (int)(fb.pos - fb.buf), fb.buf);
	}
}

const char *zlog_sanitize(char *buf, size_t bufsz, const void *in, size_t inlen)
{
	const char *inbuf = in;
	char *pos = buf, *end = buf + bufsz;
	const char *iend = inbuf + inlen;

	memset(buf, 0, bufsz);
	for (; inbuf < iend; inbuf++) {
		/* don't write partial escape sequence */
		if (end - pos < 5)
			break;

		if (*inbuf == '\n')
			snprintf(pos, end - pos, "\\n");
		else if (*inbuf == '\r')
			snprintf(pos, end - pos, "\\r");
		else if (*inbuf == '\t')
			snprintf(pos, end - pos, "\\t");
		else if (*inbuf < ' ' || *inbuf == '"' || *inbuf >= 127)
			snprintf(pos, end - pos, "\\x%02hhx", *inbuf);
		else
			*pos = *inbuf;

		pos += strlen(pos);
	}
	return buf;
}
