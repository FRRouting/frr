/*
 * Utility functions for working with time.
 *
 * This module implements:
 *   - Arithmetic operations on struct timespec and struct timeval
 *   - Conversion functions between struct timespec and struct timeval
 *   - Portability wrappers for platform-dependent time calls
 *
 * --
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Copyright (C) 1998, 2000, Kunihiro Ishiguro <kunihiro@zebra.org>
 *
 * This file is part of Free Range Routing.
 *
 * Free Range Routing is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any later
 * version.
 *
 * Free Range Routing is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Free Range Routing; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include "timeutil.h"

/* XXX:
 * MacOS Sierra adds support for clock_gettime() and provides a monotonic
 * system clock. This platform specific include and associated #ifdef switch
 * later on in this file can be removed in the future. */
#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_time.h>
#endif


struct timespec
timeval2timespec (struct timeval tv)
{
  struct timespec ts;
  ts.tv_sec = tv.tv_sec;
  ts.tv_nsec = tv.tv_usec * 1000;
  return ts;
}

struct timeval
timespec2timeval (struct timespec ts)
{
  struct timeval tv;
  tv.tv_sec = ts.tv_sec;
  tv.tv_usec = ts.tv_nsec / 1000;
  return tv;
}

struct timespec
timespec_adjust (struct timespec ts)
{
  while (ts.tv_nsec >= NANOS_IN_SECOND)
    {
      ts.tv_nsec -= NANOS_IN_SECOND;
      ts.tv_sec++;
    }

  while (ts.tv_nsec < 0)
    {
      ts.tv_nsec += NANOS_IN_SECOND;
      ts.tv_sec--;
    }

  if (ts.tv_sec < 0)
    ts.tv_sec = ts.tv_nsec = 0;

  return ts;
}

struct timeval
timeval_adjust (struct timeval tv)
{
  while (tv.tv_usec >= MICROS_IN_SECOND)
    {
      tv.tv_usec -= MICROS_IN_SECOND;
      tv.tv_sec++;
    }

  while (tv.tv_usec < 0)
    {
      tv.tv_usec += MICROS_IN_SECOND;
      tv.tv_sec--;
    }

  if (tv.tv_sec < 0)
      tv.tv_sec = tv.tv_usec = 0;

  return tv;
}

struct timespec
timespec_subtract (struct timespec a, struct timespec b)
{
  struct timespec ret;

  ret.tv_nsec = a.tv_nsec - b.tv_nsec;
  ret.tv_sec = a.tv_sec - b.tv_sec;

  return timespec_adjust (ret);
}

struct timeval
timeval_subtract (struct timeval a, struct timeval b)
{
  struct timeval ret;

  ret.tv_usec = a.tv_usec - b.tv_usec;
  ret.tv_sec = a.tv_sec - b.tv_sec;

  return timeval_adjust (ret);
}

int
timespec_cmp (struct timespec a, struct timespec b)
{
  return (a.tv_sec == b.tv_sec ?
          a.tv_nsec - b.tv_nsec : a.tv_sec - b.tv_sec);
}

int
timeval_cmp (struct timeval a, struct timeval b)
{
  return (a.tv_sec == b.tv_sec ?
          a.tv_usec - b.tv_usec : a.tv_sec - b.tv_sec);
}

unsigned long
timespec_elapsed (struct timespec a, struct timespec b)
{
  return (((a.tv_sec - b.tv_sec) * NANOS_IN_SECOND)
          + (a.tv_nsec - b.tv_nsec));
}

unsigned long
timeval_elapsed (struct timeval a, struct timeval b)
{
  return (((a.tv_sec - b.tv_sec) * MICROS_IN_SECOND)
          + (a.tv_usec - b.tv_usec));
}

struct timeval
frr_monotonic (int *status)
{
  struct timeval result = { 0 };

#ifdef HAVE_CLOCK_MONOTONIC
  {
    struct timespec tp;
    *status = clock_gettime (CLOCK_MONOTONIC, &tp);
    result = timespec2timeval (tp);
  }
#elif defined(__APPLE__)
  {
    uint64_t ticks;
    uint64_t useconds;
    static mach_timebase_info_data_t timebase_info;

    ticks = mach_absolute_time();
    if (timebase_info.denom == 0)
      mach_timebase_info(&timebase_info);

    useconds = ticks * timebase_info.numer / timebase_info.denom / 1000;
    result.tv_sec = useconds / 1000000;
    result.tv_usec = useconds % 1000000;
  }

#else /* !HAVE_CLOCK_MONOTONIC && !__APPLE__ */
#error no monotonic clock on this system
#endif /* HAVE_CLOCK_MONOTONIC */

  return result;
}

int
frr_gettime (enum frr_clkid clkid, struct timeval *tv)
{
  int status = 0;
  switch (clkid)
    {
      case FRR_CLK_MONOTONIC:
        *tv = frr_monotonic (&status);
        break;
      case FRR_CLK_REALTIME:
        status = gettimeofday (tv, NULL);
        break;
      default:
        errno = EINVAL;
        status = -1;
        break;
    }
  return status;
}
