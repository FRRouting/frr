/*
 * $Id: log.c,v 1.24 2005/02/03 16:42:40 ajs Exp $
 *
 * Logging of zebra
 * Copyright (C) 1997, 1998, 1999 Kunihiro Ishiguro
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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "command.h"
#ifndef SUNOS_5
#include <sys/un.h>
#endif

static int crashlog_fd = -1;   /* Used for last-resort crash logfile when a
				  signal is caught. */

struct zlog *zlog_default = NULL;

const char *zlog_proto_names[] = 
{
  "NONE",
  "DEFAULT",
  "ZEBRA",
  "RIP",
  "BGP",
  "OSPF",
  "RIPNG",
  "OSPF6",
  "ISIS",
  "MASC",
  NULL,
};

const char *zlog_priority[] =
{
  "emergencies",
  "alerts",
  "critical",
  "errors",
  "warnings",
  "notifications",
  "informational",
  "debugging",
  NULL,
};
  


/* For time string format. */
#define TIME_BUF 27

/* Utility routine for current time printing. */
static void
time_print (FILE *fp)
{
  int ret;
  char buf [TIME_BUF];
  time_t clock;
  struct tm *tm;
  
  time (&clock);
  tm = localtime (&clock);

  ret = strftime (buf, TIME_BUF, "%Y/%m/%d %H:%M:%S", tm);
  if (ret == 0) {
    zlog_warn ("strftime error");
  }

  fprintf (fp, "%s ", buf);
}

/* va_list version of zlog. */
static void
vzlog (struct zlog *zl, int priority, const char *format, va_list args)
{
  /* If zlog is not specified, use default one. */
  if (zl == NULL)
    zl = zlog_default;

  /* When zlog_default is also NULL, use stderr for logging. */
  if (zl == NULL)
    {
      time_print (stderr);
      fprintf (stderr, "%s: ", "unknown");
      vfprintf (stderr, format, args);
      fprintf (stderr, "\n");
      fflush (stderr);

      /* In this case we return at here. */
      return;
    }

  /* Syslog output */
  if (priority <= zl->maxlvl[ZLOG_DEST_SYSLOG])
    {
      va_list ac;
      va_copy(ac, args);
      vsyslog (priority|zlog_default->facility, format, ac);
      va_end(ac);
    }

  /* File output. */
  if ((priority <= zl->maxlvl[ZLOG_DEST_FILE]) && zl->fp)
    {
      va_list ac;
      time_print (zl->fp);
      if (zl->record_priority)
	fprintf (zl->fp, "%s: ", zlog_priority[priority]);
      fprintf (zl->fp, "%s: ", zlog_proto_names[zl->protocol]);
      va_copy(ac, args);
      vfprintf (zl->fp, format, ac);
      va_end(ac);
      fprintf (zl->fp, "\n");
      fflush (zl->fp);
    }

  /* stdout output. */
  if (priority <= zl->maxlvl[ZLOG_DEST_STDOUT])
    {
      va_list ac;
      time_print (stdout);
      if (zl->record_priority)
	fprintf (stdout, "%s: ", zlog_priority[priority]);
      fprintf (stdout, "%s: ", zlog_proto_names[zl->protocol]);
      va_copy(ac, args);
      vfprintf (stdout, format, ac);
      va_end(ac);
      fprintf (stdout, "\n");
      fflush (stdout);
    }

  /* Terminal monitor. */
  if (priority <= zl->maxlvl[ZLOG_DEST_MONITOR])
    vty_log ((zl->record_priority ? zlog_priority[priority] : NULL),
	     zlog_proto_names[zl->protocol], format, args);
}

static char *
str_append(char *dst, int len, const char *src)
{
  while ((len-- > 0) && *src)
    *dst++ = *src++;
  return dst;
}

static char *
num_append(char *s, int len, u_long x)
{
  char buf[30];
  char *t;

  if (!x)
    return str_append(s,len,"0");
  *(t = &buf[sizeof(buf)-1]) = '\0';
  while (x && (t > buf))
    {
      *--t = '0'+(x % 10);
      x /= 10;
    }
  return str_append(s,len,t);
}

#if defined(SA_SIGINFO) || defined(HAVE_GLIBC_BACKTRACE)
static char *
hex_append(char *s, int len, u_long x)
{
  char buf[30];
  char *t;

  if (!x)
    return str_append(s,len,"0");
  *(t = &buf[sizeof(buf)-1]) = '\0';
  while (x && (t > buf))
    {
      u_int cc = (x % 16);
      *--t = ((cc < 10) ? ('0'+cc) : ('a'+cc-10));
      x /= 16;
    }
  return str_append(s,len,t);
}
#endif

/* Needs to be enhanced to support Solaris. */
static int
syslog_connect(void)
{
#ifdef SUNOS_5
  return -1;
#else
  int fd;
  char *s;
  struct sockaddr_un addr;

  if ((fd = socket(AF_UNIX,SOCK_DGRAM,0)) < 0)
    return -1;
  addr.sun_family = AF_UNIX;
#ifdef _PATH_LOG
#define SYSLOG_SOCKET_PATH _PATH_LOG
#else
#define SYSLOG_SOCKET_PATH "/dev/log"
#endif
  s = str_append(addr.sun_path,sizeof(addr.sun_path),SYSLOG_SOCKET_PATH);
#undef SYSLOG_SOCKET_PATH
  *s = '\0';
  if (connect(fd,(struct sockaddr *)&addr,sizeof(addr)) < 0)
    {
      close(fd);
      return -1;
    }
  return fd;
#endif
}

static void
syslog_sigsafe(int priority, const char *msg, size_t msglen)
{
  static int syslog_fd = -1;
  char buf[sizeof("<1234567890>ripngd[1234567890]: ")+msglen+50];
  char *s;

  if ((syslog_fd < 0) && ((syslog_fd = syslog_connect()) < 0))
    return;

#define LOC s,buf+sizeof(buf)-s
  s = buf;
  s = str_append(LOC,"<");
  s = num_append(LOC,priority);
  s = str_append(LOC,">");
  /* forget about the timestamp, too difficult in a signal handler */
  s = str_append(LOC,zlog_default->ident);
  if (zlog_default->syslog_options & LOG_PID)
    {
      s = str_append(LOC,"[");
      s = num_append(LOC,getpid());
      s = str_append(LOC,"]");
    }
  s = str_append(LOC,": ");
  s = str_append(LOC,msg);
  write(syslog_fd,buf,s-buf);
#undef LOC
}

static int
open_crashlog(void)
{
#define CRASHLOG_PREFIX "/var/tmp/quagga."
#define CRASHLOG_SUFFIX "crashlog"
  if (zlog_default && zlog_default->ident)
    {
      /* Avoid strlen since it is not async-signal-safe. */
      const char *p;
      size_t ilen;

      for (p = zlog_default->ident, ilen = 0; *p; p++)
	ilen++;
      {
	char buf[sizeof(CRASHLOG_PREFIX)+ilen+sizeof(CRASHLOG_SUFFIX)+3];
	char *s = buf;
#define LOC s,buf+sizeof(buf)-s
	s = str_append(LOC, CRASHLOG_PREFIX);
	s = str_append(LOC, zlog_default->ident);
	s = str_append(LOC, ".");
	s = str_append(LOC, CRASHLOG_SUFFIX);
#undef LOC
	*s = '\0';
	return open(buf, O_WRONLY|O_CREAT|O_EXCL, LOGFILE_MASK);
      }
    }
  return open(CRASHLOG_PREFIX CRASHLOG_SUFFIX, O_WRONLY|O_CREAT|O_EXCL,
	      LOGFILE_MASK);
#undef CRASHLOG_SUFFIX
#undef CRASHLOG_PREFIX
}

/* Note: the goal here is to use only async-signal-safe functions. */
void
zlog_signal(int signo, const char *action
#ifdef SA_SIGINFO
	    , siginfo_t *siginfo, void *program_counter
#endif
	   )
{
  time_t now;
  char buf[sizeof("DEFAULT: Received signal S at T (si_addr 0xP, PC 0xP); aborting...")+100];
  char *s = buf;
  char *msgstart = buf;
#define LOC s,buf+sizeof(buf)-s

  time(&now);
  if (zlog_default)
    {
      s = str_append(LOC,zlog_proto_names[zlog_default->protocol]);
      *s++ = ':';
      *s++ = ' ';
      msgstart = s;
    }
  s = str_append(LOC,"Received signal ");
  s = num_append(LOC,signo);
  s = str_append(LOC," at ");
  s = num_append(LOC,now);
#ifdef SA_SIGINFO
  s = str_append(LOC," (si_addr 0x");
  s = hex_append(LOC,(u_long)(siginfo->si_addr));
  if (program_counter)
    {
      s = str_append(LOC,", PC 0x");
      s = hex_append(LOC,(u_long)program_counter);
    }
  s = str_append(LOC,"); ");
#else /* SA_SIGINFO */
  s = str_append(LOC,"; ");
#endif /* SA_SIGINFO */
  s = str_append(LOC,action);
  if (s < buf+sizeof(buf))
    *s++ = '\n';

  /* N.B. implicit priority is most severe */
#define PRI LOG_CRIT

#define DUMP(FD) write(FD, buf, s-buf);
  /* If no file logging configured, try to write to fallback log file. */
  if ((!zlog_default || !zlog_default->fp) &&
      ((crashlog_fd = open_crashlog()) >= 0))
    DUMP(crashlog_fd)
  if (!zlog_default)
    DUMP(fileno(stderr))
  else
    {
      if ((PRI <= zlog_default->maxlvl[ZLOG_DEST_FILE]) && zlog_default->fp)
        DUMP(fileno(zlog_default->fp))
      if (PRI <= zlog_default->maxlvl[ZLOG_DEST_STDOUT])
        DUMP(fileno(stdout))
      /* Remove trailing '\n' for monitor and syslog */
      *--s = '\0';
      if (PRI <= zlog_default->maxlvl[ZLOG_DEST_MONITOR])
        vty_log_fixed(buf,s-buf);
      if (PRI <= zlog_default->maxlvl[ZLOG_DEST_SYSLOG])
	syslog_sigsafe(PRI|zlog_default->facility,msgstart,s-msgstart);
    }
#undef DUMP

  zlog_backtrace_sigsafe(PRI,
#ifdef SA_SIGINFO
  			 program_counter
#else
			 NULL
#endif
			);
#undef PRI
#undef LOC
}

/* Log a backtrace using only async-signal-safe functions.
   Needs to be enhanced to support syslog logging. */
void
zlog_backtrace_sigsafe(int priority, void *program_counter)
{
#ifdef HAVE_GLIBC_BACKTRACE
  static const char pclabel[] = "Program counter: ";
  void *array[20];
  int size;
  char buf[100];
  char *s;
#define LOC s,buf+sizeof(buf)-s

  if (((size = backtrace(array,sizeof(array)/sizeof(array[0]))) <= 0) ||
      ((size_t)size > sizeof(array)/sizeof(array[0])))
    return;
  s = buf;
  s = str_append(LOC,"Backtrace for ");
  s = num_append(LOC,size);
  s = str_append(LOC," stack frames:\n");

#define DUMP(FD) { \
  if (program_counter) \
    { \
      write(FD, pclabel, sizeof(pclabel)-1); \
      backtrace_symbols_fd(&program_counter, 1, FD); \
    } \
  write(FD, buf, s-buf);	\
  backtrace_symbols_fd(array, size, FD); \
}

  if (crashlog_fd >= 0)
    DUMP(crashlog_fd)
  if (!zlog_default)
    DUMP(fileno(stderr))
  else
    {
      if ((priority <= zlog_default->maxlvl[ZLOG_DEST_FILE]) &&
	  zlog_default->fp)
	DUMP(fileno(zlog_default->fp))
      if (priority <= zlog_default->maxlvl[ZLOG_DEST_STDOUT])
	DUMP(fileno(stdout))
      /* Remove trailing '\n' for monitor and syslog */
      *--s = '\0';
      if (priority <= zlog_default->maxlvl[ZLOG_DEST_MONITOR])
	vty_log_fixed(buf,s-buf);
      if (priority <= zlog_default->maxlvl[ZLOG_DEST_SYSLOG])
	syslog_sigsafe(priority|zlog_default->facility,buf,s-buf);
      {
	int i;
	/* Just print the function addresses. */
	for (i = 0; i < size; i++)
	  {
	    s = buf;
	    s = str_append(LOC,"[bt ");
	    s = num_append(LOC,i);
	    s = str_append(LOC,"] 0x");
	    s = hex_append(LOC,(u_long)(array[i]));
	    *s = '\0';
	    if (priority <= zlog_default->maxlvl[ZLOG_DEST_MONITOR])
	      vty_log_fixed(buf,s-buf);
	    if (priority <= zlog_default->maxlvl[ZLOG_DEST_SYSLOG])
	      syslog_sigsafe(priority|zlog_default->facility,buf,s-buf);
	  }
      }
    }
#undef DUMP
#undef LOC
#endif /* HAVE_GLIBC_BACKTRACE */
}

void
zlog_backtrace(int priority)
{
#ifndef HAVE_GLIBC_BACKTRACE
  zlog(NULL, priority, "No backtrace available on this platform.");
#else
  void *array[20];
  int size, i;
  char **strings;

  if (((size = backtrace(array,sizeof(array)/sizeof(array[0]))) <= 0) ||
      ((size_t)size > sizeof(array)/sizeof(array[0])))
    {
      zlog_err("Cannot get backtrace, returned invalid # of frames %d "
	       "(valid range is between 1 and %u)",
	       size, sizeof(array)/sizeof(array[0]));
      return;
    }
  zlog(NULL, priority, "Backtrace for %d stack frames:", size);
  if (!(strings = backtrace_symbols(array, size)))
    {
      zlog_err("Cannot get backtrace symbols (out of memory?)");
      for (i = 0; i < size; i++)
	zlog(NULL, priority, "[bt %d] %p",i,array[i]);
    }
  else
    {
      for (i = 0; i < size; i++)
	zlog(NULL, priority, "[bt %d] %s",i,strings[i]);
      free(strings);
    }
#endif /* HAVE_GLIBC_BACKTRACE */
}

void
zlog (struct zlog *zl, int priority, const char *format, ...)
{
  va_list args;

  va_start(args, format);
  vzlog (zl, priority, format, args);
  va_end (args);
}

#define ZLOG_FUNC(FUNCNAME,PRIORITY) \
void \
FUNCNAME(const char *format, ...) \
{ \
  va_list args; \
  va_start(args, format); \
  vzlog (NULL, PRIORITY, format, args); \
  va_end(args); \
}

ZLOG_FUNC(zlog_err, LOG_ERR)

ZLOG_FUNC(zlog_warn, LOG_WARNING)

ZLOG_FUNC(zlog_info, LOG_INFO)

ZLOG_FUNC(zlog_notice, LOG_NOTICE)

ZLOG_FUNC(zlog_debug, LOG_DEBUG)

#undef ZLOG_FUNC

#define PLOG_FUNC(FUNCNAME,PRIORITY) \
void \
FUNCNAME(struct zlog *zl, const char *format, ...) \
{ \
  va_list args; \
  va_start(args, format); \
  vzlog (zl, PRIORITY, format, args); \
  va_end(args); \
}

PLOG_FUNC(plog_err, LOG_ERR)

PLOG_FUNC(plog_warn, LOG_WARNING)

PLOG_FUNC(plog_info, LOG_INFO)

PLOG_FUNC(plog_notice, LOG_NOTICE)

PLOG_FUNC(plog_debug, LOG_DEBUG)

#undef PLOG_FUNC

void
_zlog_assert_failed (const char *assertion, const char *file,
		     unsigned int line, const char *function)
{
  if (zlog_default && !zlog_default->fp)
    {
      /* Force fallback file logging. */
      int fd;
      FILE *fp;

      if (((fd = open_crashlog()) >= 0) && ((fp = fdopen(fd, "w")) != NULL))
	{
	  zlog_default->fp = fp;
	  zlog_default->maxlvl[ZLOG_DEST_FILE] = LOG_ERR;
        }
    }
  zlog(NULL, LOG_CRIT, "Assertion `%s' failed in file %s, line %u, function %s",
       assertion,file,line,(function ? function : "?"));
  zlog_backtrace(LOG_CRIT);
  abort();
}


/* Open log stream */
struct zlog *
openzlog (const char *progname, zlog_proto_t protocol,
	  int syslog_flags, int syslog_facility)
{
  struct zlog *zl;
  u_int i;

  zl = XCALLOC(MTYPE_ZLOG, sizeof (struct zlog));

  zl->ident = progname;
  zl->protocol = protocol;
  zl->facility = syslog_facility;
  zl->syslog_options = syslog_flags;

  /* Set default logging levels. */
  for (i = 0; i < sizeof(zl->maxlvl)/sizeof(zl->maxlvl[0]); i++)
    zl->maxlvl[i] = ZLOG_DISABLED;
  zl->maxlvl[ZLOG_DEST_MONITOR] = LOG_DEBUG;
  zl->default_lvl = LOG_DEBUG;

  openlog (progname, syslog_flags, zl->facility);
  
  return zl;
}

void
closezlog (struct zlog *zl)
{
  closelog();
  fclose (zl->fp);

  XFREE (MTYPE_ZLOG, zl);
}

/* Called from command.c. */
void
zlog_set_level (struct zlog *zl, zlog_dest_t dest, int log_level)
{
  if (zl == NULL)
    zl = zlog_default;

  zl->maxlvl[dest] = log_level;
}

int
zlog_set_file (struct zlog *zl, const char *filename, int log_level)
{
  FILE *fp;
  mode_t oldumask;

  /* There is opend file.  */
  zlog_reset_file (zl);

  /* Set default zl. */
  if (zl == NULL)
    zl = zlog_default;

  /* Open file. */
  oldumask = umask (0777 & ~LOGFILE_MASK);
  fp = fopen (filename, "a");
  umask(oldumask);
  if (fp == NULL)
    return 0;

  /* Set flags. */
  zl->filename = strdup (filename);
  zl->maxlvl[ZLOG_DEST_FILE] = log_level;
  zl->fp = fp;

  return 1;
}

/* Reset opend file. */
int
zlog_reset_file (struct zlog *zl)
{
  if (zl == NULL)
    zl = zlog_default;

  if (zl->fp)
    fclose (zl->fp);
  zl->fp = NULL;
  zl->maxlvl[ZLOG_DEST_FILE] = ZLOG_DISABLED;

  if (zl->filename)
    free (zl->filename);
  zl->filename = NULL;

  return 1;
}

/* Reopen log file. */
int
zlog_rotate (struct zlog *zl)
{
  int level;

  if (zl == NULL)
    zl = zlog_default;

  if (zl->fp)
    fclose (zl->fp);
  zl->fp = NULL;
  level = zl->maxlvl[ZLOG_DEST_FILE];
  zl->maxlvl[ZLOG_DEST_FILE] = ZLOG_DISABLED;

  if (zl->filename)
    {
      mode_t oldumask;
      int save_errno;

      oldumask = umask (0777 & ~LOGFILE_MASK);
      zl->fp = fopen (zl->filename, "a");
      save_errno = errno;
      umask(oldumask);
      if (zl->fp == NULL)
        {
	  zlog_err("Log rotate failed: cannot open file %s for append: %s",
	  	   zl->filename, safe_strerror(save_errno));
	  return -1;
        }	
      zl->maxlvl[ZLOG_DEST_FILE] = level;
    }

  return 1;
}

/* Message lookup function. */
const char *
lookup (struct message *mes, int key)
{
  struct message *pnt;

  for (pnt = mes; pnt->key != 0; pnt++) 
    if (pnt->key == key) 
      return pnt->str;

  return "";
}

/* Very old hacky version of message lookup function.  Still partly
   used in bgpd and ospfd. FIXME Seems that it's not used any more. */
const char *
mes_lookup (struct message *meslist, int max, int index)
{
  if (index < 0 || index >= max) 
    {
      zlog_err ("message index out of bound: %d", max);
      return NULL;
    }
  return meslist[index].str;
}

/* Wrapper around strerror to handle case where it returns NULL. */
const char *
safe_strerror(int errnum)
{
  const char *s = strerror(errnum);
  return (s != NULL) ? s : "Unknown error";
}
