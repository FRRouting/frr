/*
 * Zebra privileges.
 *
 * Copyright (C) 2003 Paul Jakma.
 * Copyright (c) 2005, 2011, Oracle and/or its affiliates. All rights reserved.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>
#include "log.h"
#include "privs.h"
#include "memory.h"

#ifdef HAVE_CAPABILITIES

DEFINE_MTYPE_STATIC(LIB, PRIVS, "Privilege information")

/* sort out some generic internal types for:
 *
 * privilege values (cap_value_t, priv_t) 	-> pvalue_t
 * privilege set (..., priv_set_t) 		-> pset_t
 * privilege working storage (cap_t, ...) 	-> pstorage_t
 *
 * values we think of as numeric (they're ints really, but we dont know)
 * sets are mostly opaque, to hold a set of privileges, related in some way.
 * storage binds together a set of sets we're interested in.
 * (in reality: cap_value_t and priv_t are ints)
 */
#ifdef HAVE_LCAPS
/* Linux doesn't have a 'set' type: a set of related privileges */
struct _pset {
	int num;
	cap_value_t *caps;
};
typedef cap_value_t pvalue_t;
typedef struct _pset pset_t;
typedef cap_t pstorage_t;

#elif defined(HAVE_SOLARIS_CAPABILITIES)
typedef priv_t pvalue_t;
typedef priv_set_t pset_t;
typedef priv_set_t *pstorage_t;
#else /* neither LCAPS nor SOLARIS_CAPABILITIES */
#error "HAVE_CAPABILITIES defined, but neither LCAPS nor Solaris Capabilties!"
#endif /* HAVE_LCAPS */
#endif /* HAVE_CAPABILITIES */

/* the default NULL state we report is RAISED, but could be LOWERED if
 * zprivs_terminate is called and the NULL handler is installed.
 */
static zebra_privs_current_t zprivs_null_state = ZPRIVS_RAISED;

/* internal privileges state */
static struct _zprivs_t {
#ifdef HAVE_CAPABILITIES
	pstorage_t caps;   /* working storage        */
	pset_t *syscaps_p; /* system-type requested permitted caps    */
	pset_t *syscaps_i; /* system-type requested inheritable caps  */
#endif			   /* HAVE_CAPABILITIES */
	uid_t zuid,	/* uid to run as            */
		zsuid;     /* saved uid                */
	gid_t zgid;	/* gid to run as            */
	gid_t vtygrp;      /* gid for vty sockets      */
} zprivs_state;

/* externally exported but not directly accessed functions */
#ifdef HAVE_CAPABILITIES
int zprivs_change_caps(zebra_privs_ops_t);
zebra_privs_current_t zprivs_state_caps(void);
#endif /* HAVE_CAPABILITIES */
int zprivs_change_uid(zebra_privs_ops_t);
zebra_privs_current_t zprivs_state_uid(void);
int zprivs_change_null(zebra_privs_ops_t);
zebra_privs_current_t zprivs_state_null(void);

#ifdef HAVE_CAPABILITIES
/* internal capability API */
static pset_t *zcaps2sys(zebra_capabilities_t *, int);
static void zprivs_caps_init(struct zebra_privs_t *);
static void zprivs_caps_terminate(void);

/* Map of Quagga abstract capabilities to system capabilities */
static struct {
	int num;
	pvalue_t *system_caps;
} cap_map[ZCAP_MAX] = {
#ifdef HAVE_LCAPS /* Quagga -> Linux capabilities mappings */
		[ZCAP_SETID] =
			{
				2, (pvalue_t[]){CAP_SETGID, CAP_SETUID},
			},
		[ZCAP_BIND] =
			{
				1, (pvalue_t[]){CAP_NET_BIND_SERVICE},
			},
		[ZCAP_NET_ADMIN] =
			{
				1, (pvalue_t[]){CAP_NET_ADMIN},
			},
		[ZCAP_NET_RAW] =
			{
				1, (pvalue_t[]){CAP_NET_RAW},
			},
		[ZCAP_CHROOT] =
			{
				1,
				(pvalue_t[]){
					CAP_SYS_CHROOT,
				},
			},
		[ZCAP_NICE] =
			{
				1, (pvalue_t[]){CAP_SYS_NICE},
			},
		[ZCAP_PTRACE] =
			{
				1, (pvalue_t[]){CAP_SYS_PTRACE},
			},
		[ZCAP_DAC_OVERRIDE] =
			{
				1, (pvalue_t[]){CAP_DAC_OVERRIDE},
			},
		[ZCAP_READ_SEARCH] =
			{
				1, (pvalue_t[]){CAP_DAC_READ_SEARCH},
			},
		[ZCAP_SYS_ADMIN] =
			{
				1, (pvalue_t[]){CAP_SYS_ADMIN},
			},
		[ZCAP_FOWNER] =
			{
				1, (pvalue_t[]){CAP_FOWNER},
			},
#elif defined(HAVE_SOLARIS_CAPABILITIES) /* HAVE_LCAPS */
		/* Quagga -> Solaris privilege mappings */
		[ZCAP_SETID] =
			{
				1, (pvalue_t[]){PRIV_PROC_SETID},
			},
		[ZCAP_BIND] =
			{
				1, (pvalue_t[]){PRIV_NET_PRIVADDR},
			},
/* IP_CONFIG is a subset of NET_CONFIG and is allowed in zones */
#ifdef PRIV_SYS_IP_CONFIG
		[ZCAP_NET_ADMIN] =
			{
				1, (pvalue_t[]){PRIV_SYS_IP_CONFIG},
			},
#else
		[ZCAP_NET_ADMIN] =
			{
				1, (pvalue_t[]){PRIV_SYS_NET_CONFIG},
			},
#endif
		[ZCAP_NET_RAW] =
			{
				2, (pvalue_t[]){PRIV_NET_RAWACCESS,
						PRIV_NET_ICMPACCESS},
			},
		[ZCAP_CHROOT] =
			{
				1, (pvalue_t[]){PRIV_PROC_CHROOT},
			},
		[ZCAP_NICE] =
			{
				1, (pvalue_t[]){PRIV_PROC_PRIOCNTL},
			},
		[ZCAP_PTRACE] =
			{
				1, (pvalue_t[]){PRIV_PROC_SESSION},
			},
		[ZCAP_DAC_OVERRIDE] =
			{
				5, (pvalue_t[]){PRIV_FILE_DAC_EXECUTE,
						PRIV_FILE_DAC_READ,
						PRIV_FILE_DAC_SEARCH,
						PRIV_FILE_DAC_WRITE,
						PRIV_FILE_DAC_SEARCH},
			},
		[ZCAP_READ_SEARCH] =
			{
				2, (pvalue_t[]){PRIV_FILE_DAC_SEARCH,
						PRIV_FILE_DAC_READ},
			},
		[ZCAP_SYS_ADMIN] =
			{
				1, (pvalue_t[]){PRIV_SYS_ADMIN},
			},
		[ZCAP_FOWNER] =
			{
				1, (pvalue_t[]){PRIV_FILE_OWNER},
			},
#endif /* HAVE_SOLARIS_CAPABILITIES */
};

#ifdef HAVE_LCAPS
/* Linux forms of capabilities methods */
/* convert zebras privileges to system capabilities */
static pset_t *zcaps2sys(zebra_capabilities_t *zcaps, int num)
{
	pset_t *syscaps;
	int i, j = 0, count = 0;

	if (!num)
		return NULL;

	/* first count up how many system caps we have */
	for (i = 0; i < num; i++)
		count += cap_map[zcaps[i]].num;

	if ((syscaps = XCALLOC(MTYPE_PRIVS, (sizeof(pset_t) * num))) == NULL) {
		fprintf(stderr, "%s: could not allocate syscaps!", __func__);
		return NULL;
	}

	syscaps->caps = XCALLOC(MTYPE_PRIVS, (sizeof(pvalue_t) * count));

	if (!syscaps->caps) {
		fprintf(stderr, "%s: could not XCALLOC caps!", __func__);
		return NULL;
	}

	/* copy the capabilities over */
	count = 0;
	for (i = 0; i < num; i++)
		for (j = 0; j < cap_map[zcaps[i]].num; j++)
			syscaps->caps[count++] =
				cap_map[zcaps[i]].system_caps[j];

	/* iterations above should be exact same as previous count, obviously..
	 */
	syscaps->num = count;

	return syscaps;
}

/* set or clear the effective capabilities to/from permitted */
int zprivs_change_caps(zebra_privs_ops_t op)
{
	cap_flag_value_t cflag;

	/* should be no possibility of being called without valid caps */
	assert(zprivs_state.syscaps_p && zprivs_state.caps);
	if (!(zprivs_state.syscaps_p && zprivs_state.caps))
		exit(1);

	if (op == ZPRIVS_RAISE)
		cflag = CAP_SET;
	else if (op == ZPRIVS_LOWER)
		cflag = CAP_CLEAR;
	else
		return -1;

	if (!cap_set_flag(zprivs_state.caps, CAP_EFFECTIVE,
			  zprivs_state.syscaps_p->num,
			  zprivs_state.syscaps_p->caps, cflag))
		return cap_set_proc(zprivs_state.caps);
	return -1;
}

zebra_privs_current_t zprivs_state_caps(void)
{
	int i;
	cap_flag_value_t val;

	/* should be no possibility of being called without valid caps */
	assert(zprivs_state.syscaps_p && zprivs_state.caps);
	if (!(zprivs_state.syscaps_p && zprivs_state.caps))
		exit(1);

	for (i = 0; i < zprivs_state.syscaps_p->num; i++) {
		if (cap_get_flag(zprivs_state.caps,
				 zprivs_state.syscaps_p->caps[i], CAP_EFFECTIVE,
				 &val)) {
			zlog_warn(
				"zprivs_state_caps: could not cap_get_flag, %s",
				safe_strerror(errno));
			return ZPRIVS_UNKNOWN;
		}
		if (val == CAP_SET)
			return ZPRIVS_RAISED;
	}
	return ZPRIVS_LOWERED;
}

static void zprivs_caps_init(struct zebra_privs_t *zprivs)
{
	zprivs_state.syscaps_p = zcaps2sys(zprivs->caps_p, zprivs->cap_num_p);
	zprivs_state.syscaps_i = zcaps2sys(zprivs->caps_i, zprivs->cap_num_i);

	/* Tell kernel we want caps maintained across uid changes */
	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
		fprintf(stderr,
			"privs_init: could not set PR_SET_KEEPCAPS, %s\n",
			safe_strerror(errno));
		exit(1);
	}

	/* we have caps, we have no need to ever change back the original user
	 */
	/* only change uid if we don't have the correct one */
	if ((zprivs_state.zuid) && (zprivs_state.zsuid != zprivs_state.zuid)) {
		if (setreuid(zprivs_state.zuid, zprivs_state.zuid)) {
			fprintf(stderr,
				"zprivs_init (cap): could not setreuid, %s\n",
				safe_strerror(errno));
			exit(1);
		}
	}

	if (!zprivs_state.syscaps_p)
		return;

	if (!(zprivs_state.caps = cap_init())) {
		fprintf(stderr, "privs_init: failed to cap_init, %s\n",
			safe_strerror(errno));
		exit(1);
	}

	if (cap_clear(zprivs_state.caps)) {
		fprintf(stderr, "privs_init: failed to cap_clear, %s\n",
			safe_strerror(errno));
		exit(1);
	}

	/* set permitted caps */
	cap_set_flag(zprivs_state.caps, CAP_PERMITTED,
		     zprivs_state.syscaps_p->num, zprivs_state.syscaps_p->caps,
		     CAP_SET);

	/* set inheritable caps, if any */
	if (zprivs_state.syscaps_i && zprivs_state.syscaps_i->num) {
		cap_set_flag(zprivs_state.caps, CAP_INHERITABLE,
			     zprivs_state.syscaps_i->num,
			     zprivs_state.syscaps_i->caps, CAP_SET);
	}

	/* apply caps. CAP_EFFECTIVE is cleared. we'll raise the caps as
	 * and when, and only when, they are needed.
	 */
	if (cap_set_proc(zprivs_state.caps)) {
		cap_t current_caps;
		char *current_caps_text = NULL;
		char *wanted_caps_text = NULL;

		fprintf(stderr, "privs_init: initial cap_set_proc failed: %s\n",
			safe_strerror(errno));

		current_caps = cap_get_proc();
		if (current_caps) {
			current_caps_text = cap_to_text(current_caps, NULL);
			cap_free(current_caps);
		}

		wanted_caps_text = cap_to_text(zprivs_state.caps, NULL);
		fprintf(stderr, "Wanted caps: %s\n",
			wanted_caps_text ? wanted_caps_text : "???");
		fprintf(stderr, "Have   caps: %s\n",
			current_caps_text ? current_caps_text : "???");
		if (current_caps_text)
			cap_free(current_caps_text);
		if (wanted_caps_text)
			cap_free(wanted_caps_text);

		exit(1);
	}

	/* set methods for the caller to use */
	zprivs->change = zprivs_change_caps;
	zprivs->current_state = zprivs_state_caps;
}

static void zprivs_caps_terminate(void)
{
	/* clear all capabilities */
	if (zprivs_state.caps)
		cap_clear(zprivs_state.caps);

	/* and boom, capabilities are gone forever */
	if (cap_set_proc(zprivs_state.caps)) {
		fprintf(stderr, "privs_terminate: cap_set_proc failed, %s",
			safe_strerror(errno));
		exit(1);
	}

	/* free up private state */
	if (zprivs_state.syscaps_p->num) {
		XFREE(MTYPE_PRIVS, zprivs_state.syscaps_p->caps);
		XFREE(MTYPE_PRIVS, zprivs_state.syscaps_p);
	}

	if (zprivs_state.syscaps_i && zprivs_state.syscaps_i->num) {
		XFREE(MTYPE_PRIVS, zprivs_state.syscaps_i->caps);
		XFREE(MTYPE_PRIVS, zprivs_state.syscaps_i);
	}

	cap_free(zprivs_state.caps);
}
#elif defined(HAVE_SOLARIS_CAPABILITIES) /* !HAVE_LCAPS */

/* Solaris specific capability/privilege methods
 *
 * Resources:
 * - the 'privileges' man page
 * - http://cvs.opensolaris.org
 * -
 * http://blogs.sun.com/roller/page/gbrunett?entry=privilege_enabling_set_id_programs1
 */

static pset_t *zprivs_caps_minimal()
{
	pset_t *minimal;

	if ((minimal = priv_str_to_set("basic", ",", NULL)) == NULL) {
		fprintf(stderr, "%s: couldn't get basic set!\n", __func__);
		exit(1);
	}

	/* create a minimal privilege set from the basic set */
	(void)priv_delset(minimal, PRIV_PROC_EXEC);
	(void)priv_delset(minimal, PRIV_PROC_INFO);
	(void)priv_delset(minimal, PRIV_PROC_SESSION);
	(void)priv_delset(minimal, PRIV_FILE_LINK_ANY);

	return minimal;
}

/* convert zebras privileges to system capabilities */
static pset_t *zcaps2sys(zebra_capabilities_t *zcaps, int num)
{
	pset_t *syscaps;
	int i, j = 0;

	if ((syscaps = priv_allocset()) == NULL) {
		fprintf(stderr, "%s: could not allocate syscaps!\n", __func__);
		exit(1);
	}

	priv_emptyset(syscaps);

	for (i = 0; i < num; i++)
		for (j = 0; j < cap_map[zcaps[i]].num; j++)
			priv_addset(syscaps, cap_map[zcaps[i]].system_caps[j]);

	return syscaps;
}

/* callback exported to users to RAISE and LOWER effective privileges
 * from nothing to the given permitted set and back down
 */
int zprivs_change_caps(zebra_privs_ops_t op)
{
	pset_t *privset;

	/* should be no possibility of being called without valid caps */
	assert(zprivs_state.syscaps_p);
	if (!zprivs_state.syscaps_p) {
		fprintf(stderr, "%s: Eek, missing privileged caps!", __func__);
		exit(1);
	}

	assert(zprivs_state.caps);
	if (!zprivs_state.caps) {
		fprintf(stderr, "%s: Eek, missing caps!", __func__);
		exit(1);
	}

	/* to raise: copy original permitted as our working effective set
	 * to lower: copy regular effective set stored in zprivs_state.caps
	 */
	if (op == ZPRIVS_RAISE)
		privset = zprivs_state.syscaps_p;
	else if (op == ZPRIVS_LOWER)
		privset = zprivs_state.caps;
	else
		return -1;

	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, privset) != 0)
		return -1;

	return 0;
}

/* Retrieve current privilege state, is it RAISED or LOWERED? */
zebra_privs_current_t zprivs_state_caps(void)
{
	zebra_privs_current_t result;
	pset_t *effective;

	if ((effective = priv_allocset()) == NULL) {
		fprintf(stderr, "%s: failed to get priv_allocset! %s\n",
			__func__, safe_strerror(errno));
		return ZPRIVS_UNKNOWN;
	}

	if (getppriv(PRIV_EFFECTIVE, effective)) {
		fprintf(stderr, "%s: failed to get state! %s\n", __func__,
			safe_strerror(errno));
		result = ZPRIVS_UNKNOWN;
	} else {
		if (priv_isequalset(effective, zprivs_state.syscaps_p))
			result = ZPRIVS_RAISED;
		else if (priv_isequalset(effective, zprivs_state.caps))
			result = ZPRIVS_LOWERED;
		else
			result = ZPRIVS_UNKNOWN;
	}

	priv_freeset(effective);
	return result;
}

static void zprivs_caps_init(struct zebra_privs_t *zprivs)
{
	pset_t *basic;
	pset_t *minimal;

	/* the specified sets */
	zprivs_state.syscaps_p = zcaps2sys(zprivs->caps_p, zprivs->cap_num_p);
	zprivs_state.syscaps_i = zcaps2sys(zprivs->caps_i, zprivs->cap_num_i);

	/* nonsensical to have gotten here but not have capabilities */
	if (!zprivs_state.syscaps_p) {
		fprintf(stderr,
			"%s: capabilities enabled, "
			"but no valid capabilities supplied\n",
			__func__);
	}

	/* We retain the basic set in our permitted set, as Linux has no
	 * equivalent. The basic set on Linux hence is implicit, always
	 * there.
	 */
	if ((basic = priv_str_to_set("basic", ",", NULL)) == NULL) {
		fprintf(stderr, "%s: couldn't get basic set!\n", __func__);
		exit(1);
	}

	/* Add the basic set to the permitted set */
	priv_union(basic, zprivs_state.syscaps_p);
	priv_freeset(basic);

	/* Hey kernel, we know about privileges!
	 * this isn't strictly required, use of setppriv should have same effect
	 */
	if (setpflags(PRIV_AWARE, 1)) {
		fprintf(stderr, "%s: error setting PRIV_AWARE!, %s\n", __func__,
			safe_strerror(errno));
		exit(1);
	}

	/* need either valid or empty sets for both p and i.. */
	assert(zprivs_state.syscaps_i && zprivs_state.syscaps_p);

	/* we have caps, we have no need to ever change back the original user
	 * change real, effective and saved to the specified user.
	 */
	/* only change uid if we don't have the correct one */
	if ((zprivs_state.zuid) && (zprivs_state.zsuid != zprivs_state.zuid)) {
		if (setreuid(zprivs_state.zuid, zprivs_state.zuid)) {
			fprintf(stderr, "%s: could not setreuid, %s\n",
				__func__, safe_strerror(errno));
			exit(1);
		}
	}

	/* set the permitted set */
	if (setppriv(PRIV_SET, PRIV_PERMITTED, zprivs_state.syscaps_p)) {
		fprintf(stderr, "%s: error setting permitted set!, %s\n",
			__func__, safe_strerror(errno));
		exit(1);
	}

	/* set the inheritable set */
	if (setppriv(PRIV_SET, PRIV_INHERITABLE, zprivs_state.syscaps_i)) {
		fprintf(stderr, "%s: error setting inheritable set!, %s\n",
			__func__, safe_strerror(errno));
		exit(1);
	}

	/* we need a minimal basic set for 'effective', potentially for
	 * inheritable too */
	minimal = zprivs_caps_minimal();

	/* now set the effective set with a subset of basic privileges */
	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, minimal)) {
		fprintf(stderr, "%s: error setting effective set!, %s\n",
			__func__, safe_strerror(errno));
		exit(1);
	}

	/* we'll use the minimal set as our working-storage privset */
	zprivs_state.caps = minimal;

	/* set methods for the caller to use */
	zprivs->change = zprivs_change_caps;
	zprivs->current_state = zprivs_state_caps;
}

static void zprivs_caps_terminate(void)
{
	assert(zprivs_state.caps);

	/* clear all capabilities by using working-storage privset */
	setppriv(PRIV_SET, PRIV_EFFECTIVE, zprivs_state.caps);
	setppriv(PRIV_SET, PRIV_PERMITTED, zprivs_state.caps);
	setppriv(PRIV_SET, PRIV_INHERITABLE, zprivs_state.caps);

	/* free up private state */
	if (zprivs_state.syscaps_p)
		priv_freeset(zprivs_state.syscaps_p);
	if (zprivs_state.syscaps_i)
		priv_freeset(zprivs_state.syscaps_i);

	priv_freeset(zprivs_state.caps);
}
#else /* !HAVE_LCAPS && ! HAVE_SOLARIS_CAPABILITIES */
#error "Neither Solaris nor Linux capabilities, dazed and confused..."
#endif /* HAVE_LCAPS */
#endif /* HAVE_CAPABILITIES */

int zprivs_change_uid(zebra_privs_ops_t op)
{
	if (zprivs_state.zsuid == zprivs_state.zuid)
		return 0;
	if (op == ZPRIVS_RAISE)
		return seteuid(zprivs_state.zsuid);
	else if (op == ZPRIVS_LOWER)
		return seteuid(zprivs_state.zuid);
	else
		return -1;
}

zebra_privs_current_t zprivs_state_uid(void)
{
	return ((zprivs_state.zuid == geteuid()) ? ZPRIVS_LOWERED
						 : ZPRIVS_RAISED);
}

int zprivs_change_null(zebra_privs_ops_t op)
{
	return 0;
}

zebra_privs_current_t zprivs_state_null(void)
{
	return zprivs_null_state;
}

#ifndef HAVE_GETGROUPLIST
/* Solaris 11 has no getgrouplist() */
static int getgrouplist(const char *user, gid_t group, gid_t *groups,
			int *ngroups)
{
	struct group *grp;
	size_t usridx;
	int pos = 0, ret;

	if (pos < *ngroups)
		groups[pos] = group;
	pos++;

	setgrent();
	while ((grp = getgrent())) {
		if (grp->gr_gid == group)
			continue;
		for (usridx = 0; grp->gr_mem[usridx] != NULL; usridx++)
			if (!strcmp(grp->gr_mem[usridx], user)) {
				if (pos < *ngroups)
					groups[pos] = grp->gr_gid;
				pos++;
				break;
			}
	}
	endgrent();

	ret = (pos <= *ngroups) ? pos : -1;
	*ngroups = pos;
	return ret;
}
#endif /* HAVE_GETGROUPLIST */

void zprivs_preinit(struct zebra_privs_t *zprivs)
{
	struct passwd *pwentry = NULL;
	struct group *grentry = NULL;

	if (!zprivs) {
		fprintf(stderr, "zprivs_init: called with NULL arg!\n");
		exit(1);
	}

	if (zprivs->vty_group) {
		/* in a "NULL" setup, this is allowed to fail too, but still
		 * try. */
		if ((grentry = getgrnam(zprivs->vty_group)))
			zprivs_state.vtygrp = grentry->gr_gid;
		else
			zprivs_state.vtygrp = (gid_t)-1;
	}

	/* NULL privs */
	if (!(zprivs->user || zprivs->group || zprivs->cap_num_p
	      || zprivs->cap_num_i)) {
		zprivs->change = zprivs_change_null;
		zprivs->current_state = zprivs_state_null;
		return;
	}

	if (zprivs->user) {
		if ((pwentry = getpwnam(zprivs->user)) == NULL) {
			/* cant use log.h here as it depends on vty */
			fprintf(stderr,
				"privs_init: could not lookup user %s\n",
				zprivs->user);
			exit(1);
		}

		zprivs_state.zuid = pwentry->pw_uid;
		zprivs_state.zgid = pwentry->pw_gid;
	}

	grentry = NULL;

	if (zprivs->group) {
		if ((grentry = getgrnam(zprivs->group)) == NULL) {
			fprintf(stderr,
				"privs_init: could not lookup group %s\n",
				zprivs->group);
			exit(1);
		}

		zprivs_state.zgid = grentry->gr_gid;
	}
}

void zprivs_init(struct zebra_privs_t *zprivs)
{
	gid_t groups[NGROUPS_MAX];
	int i, ngroups = 0;
	int found = 0;

	/* NULL privs */
	if (!(zprivs->user || zprivs->group || zprivs->cap_num_p
	      || zprivs->cap_num_i))
		return;

	if (zprivs->user) {
		ngroups = sizeof(groups);
		if (getgrouplist(zprivs->user, zprivs_state.zgid, groups,
				 &ngroups)
		    < 0) {
			/* cant use log.h here as it depends on vty */
			fprintf(stderr,
				"privs_init: could not getgrouplist for user %s\n",
				zprivs->user);
			exit(1);
		}
	}

	if (zprivs->vty_group)
	/* Add the vty_group to the supplementary groups so it can be chowned to
	   */
	{
		if (zprivs_state.vtygrp == (gid_t)-1) {
			fprintf(stderr,
				"privs_init: could not lookup vty group %s\n",
				zprivs->vty_group);
			exit(1);
		}

		for (i = 0; i < ngroups; i++)
			if (groups[i] == zprivs_state.vtygrp) {
				found++;
				break;
			}

		if (!found) {
			fprintf(stderr,
				"privs_init: user(%s) is not part of vty group specified(%s)\n",
				zprivs->user, zprivs->vty_group);
			exit(1);
		}
		if (i >= ngroups && ngroups < (int)ZEBRA_NUM_OF(groups)) {
			groups[i] = zprivs_state.vtygrp;
		}
	}

	zprivs_state.zsuid = geteuid(); /* initial uid */
	/* add groups only if we changed uid - otherwise skip */
	if ((ngroups) && (zprivs_state.zsuid != zprivs_state.zuid)) {
		if (setgroups(ngroups, groups)) {
			fprintf(stderr, "privs_init: could not setgroups, %s\n",
				safe_strerror(errno));
			exit(1);
		}
	}

	/* change gid only if we changed uid - otherwise skip */
	if ((zprivs_state.zgid) && (zprivs_state.zsuid != zprivs_state.zuid)) {
		/* change group now, forever. uid we do later */
		if (setregid(zprivs_state.zgid, zprivs_state.zgid)) {
			fprintf(stderr, "zprivs_init: could not setregid, %s\n",
				safe_strerror(errno));
			exit(1);
		}
	}

#ifdef HAVE_CAPABILITIES
	zprivs_caps_init(zprivs);

	/*
	 * If we have initialized the system with no requested
	 * capabilities, change will not have been set
	 * to anything by zprivs_caps_init, As such
	 * we should make sure that when we attempt
	 * to raize privileges that we actually have
	 * a do nothing function to call instead of a
	 * crash :).
	 */
	if (!zprivs->change)
		zprivs->change = zprivs_change_null;

#else  /* !HAVE_CAPABILITIES */
	/* we dont have caps. we'll need to maintain rid and saved uid
	 * and change euid back to saved uid (who we presume has all neccessary
	 * privileges) whenever we are asked to raise our privileges.
	 *
	 * This is not worth that much security wise, but all we can do.
	 */
	zprivs_state.zsuid = geteuid();
	/* only change uid if we don't have the correct one */
	if ((zprivs_state.zuid) && (zprivs_state.zsuid != zprivs_state.zuid)) {
		if (setreuid(-1, zprivs_state.zuid)) {
			fprintf(stderr,
				"privs_init (uid): could not setreuid, %s\n",
				safe_strerror(errno));
			exit(1);
		}
	}

	zprivs->change = zprivs_change_uid;
	zprivs->current_state = zprivs_state_uid;
#endif /* HAVE_CAPABILITIES */
}

void zprivs_terminate(struct zebra_privs_t *zprivs)
{
	if (!zprivs) {
		fprintf(stderr, "%s: no privs struct given, terminating",
			__func__);
		exit(0);
	}

#ifdef HAVE_CAPABILITIES
	if (zprivs->user || zprivs->group || zprivs->cap_num_p
	    || zprivs->cap_num_i)
		zprivs_caps_terminate();
#else  /* !HAVE_CAPABILITIES */
	/* only change uid if we don't have the correct one */
	if ((zprivs_state.zuid) && (zprivs_state.zsuid != zprivs_state.zuid)) {
		if (setreuid(zprivs_state.zuid, zprivs_state.zuid)) {
			fprintf(stderr,
				"privs_terminate: could not setreuid, %s",
				safe_strerror(errno));
			exit(1);
		}
	}
#endif /* HAVE_LCAPS */

	zprivs->change = zprivs_change_null;
	zprivs->current_state = zprivs_state_null;
	zprivs_null_state = ZPRIVS_LOWERED;
	return;
}

void zprivs_get_ids(struct zprivs_ids_t *ids)
{

	ids->uid_priv = getuid();
	(zprivs_state.zuid) ? (ids->uid_normal = zprivs_state.zuid)
			    : (ids->uid_normal = -1);
	(zprivs_state.zgid) ? (ids->gid_normal = zprivs_state.zgid)
			    : (ids->gid_normal = -1);
	(zprivs_state.vtygrp) ? (ids->gid_vty = zprivs_state.vtygrp)
			      : (ids->gid_vty = -1);

	return;
}
