// SPDX-License-Identifier: ISC
/*	$OpenBSD$ */

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 */

#include <zebra.h>

#include "ldpd.h"
#include "ldpe.h"
#include "lde.h"
#include "log.h"
#include "printfrr.h"

#include <lib/log.h>

const char	*log_procname;

void
logit(int pri, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vlog(pri, fmt, ap);
	va_end(ap);
}

void
vlog(int pri, const char *fmt, va_list ap)
{
	char	 buf[1024];

	switch (ldpd_process) {
	case PROC_LDE_ENGINE:
		vsnprintfrr(buf, sizeof(buf), fmt, ap);
		lde_imsg_compose_parent_sync(IMSG_LOG, pri, buf, strlen(buf) + 1);
		break;
	case PROC_LDP_ENGINE:
		vsnprintfrr(buf, sizeof(buf), fmt, ap);
		ldpe_imsg_compose_parent_sync(IMSG_LOG, pri, buf, strlen(buf) + 1);
		break;
	case PROC_MAIN:
		vzlog(pri, fmt, ap);
		break;
	}
}

void
log_warn(const char *emsg, ...)
{
	char	*nfmt;
	va_list	 ap;

	/* best effort to even work in out of memory situations */
	if (emsg == NULL)
		logit(LOG_ERR, "%s", strerror(errno));
	else {
		va_start(ap, emsg);

		if (asprintf(&nfmt, "%s: %s", emsg, strerror(errno)) == -1) {
			/* we tried it... */
			vlog(LOG_ERR, emsg, ap);
			logit(LOG_ERR, "%s", strerror(errno));
		} else {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
			/* format extended above */
			vlog(LOG_ERR, nfmt, ap);
#pragma GCC diagnostic pop
			free(nfmt);
		}
		va_end(ap);
	}
}

void
log_warnx(const char *emsg, ...)
{
	va_list	 ap;

	va_start(ap, emsg);
	vlog(LOG_ERR, emsg, ap);
	va_end(ap);
}

void
log_info(const char *emsg, ...)
{
	va_list	 ap;

	va_start(ap, emsg);
	vlog(LOG_INFO, emsg, ap);
	va_end(ap);
}

void
log_notice(const char *emsg, ...)
{
	va_list	 ap;

	va_start(ap, emsg);
	vlog(LOG_NOTICE, emsg, ap);
	va_end(ap);
}

void
log_debug(const char *emsg, ...)
{
	va_list	 ap;

	va_start(ap, emsg);
	vlog(LOG_DEBUG, emsg, ap);
	va_end(ap);
}

void
fatal(const char *emsg)
{
	if (emsg == NULL)
		logit(LOG_CRIT, "fatal in %s: %s", log_procname, strerror(errno));
	else
		if (errno)
			logit(LOG_CRIT, "fatal in %s: %s: %s",
			    log_procname, emsg, strerror(errno));
		else
			logit(LOG_CRIT, "fatal in %s: %s", log_procname, emsg);

	exit(1);
}

void
fatalx(const char *emsg)
{
	errno = 0;
	fatal(emsg);
}
