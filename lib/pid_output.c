/*
 * Process id output.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
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
#include <fcntl.h>
#include <log.h>
#include "version.h"

pid_t
pid_output (const char *path)
{
#ifndef HAVE_FCNTL
  FILE *fp;
  pid_t pid;
  mask_t oldumask;

  pid = getpid();

  oldumask = umask(0777 & ~LOGFILE_MASK);
  fp = fopen (path, "w");
  if (fp != NULL) 
    {
      fprintf (fp, "%d\n", (int) pid);
      fclose (fp);
      umask(oldumask);
      return -1;
    }
  umask(oldumask);
  return pid;
#else
  static pid_t pid_output_lock (const char *);

  return pid_output_lock(path);
#endif /* HAVE_FCNTL */
}

#ifdef HAVE_FCNTL
static pid_t
pid_output_lock (const char *path)
{
  int tmp;
  int fd;
  pid_t pid;
  char buf[16];
  struct flock lock;  
  mode_t oldumask;

  pid = getpid ();

  oldumask = umask(0777 & ~LOGFILE_MASK);
  fd = open (path, O_RDWR | O_CREAT, LOGFILE_MASK);
      if (fd < 0)
        {
        zlog_err( "Can't creat pid lock file %s (%s), exit", 
                 path, safe_strerror(errno));
      umask(oldumask);
      exit (-1);
    }
  else
    {
      size_t pidsize;

      umask(oldumask);
      memset (&lock, 0, sizeof(lock));

      lock.l_type = F_WRLCK;
      lock.l_whence = SEEK_SET;

      if (fcntl(fd, F_SETLK, &lock) < 0)
        {
          zlog_err("Could not lock pid_file %s, exit", path);
          exit (-1);
        }

      sprintf (buf, "%d\n", (int) pid);
      pidsize = strlen(buf);
      if ((tmp = write (fd, buf, pidsize)) != (int)pidsize)
        zlog_err("Could not write pid %d to pid_file %s, rc was %d: %s",
	         (int)pid,path,tmp,safe_strerror(errno));
      else if (ftruncate(fd, pidsize) < 0)
        zlog_err("Could not truncate pid_file %s to %u bytes: %s",
	         path,(u_int)pidsize,safe_strerror(errno));
    }
  return pid;
}
#endif /* HAVE_FCNTL */
