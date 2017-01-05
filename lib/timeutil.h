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
#ifndef _TIMEUTIL_H
#define _TIMEUTIL_H

#include <sys/time.h>
#include <time.h>

#define NANOS_IN_SECOND  1000000000 // one billion
#define MICROS_IN_SECOND 1000000    // one million
#define MILLIS_IN_SECOND 1000       // one thousand

/* Clocks supported by FRR. */
enum frr_clkid {
  /* Monotonically increasing clock. Indeterminate base. Analagous to
   * CLOCK_MONOTONIC for clock_gettime(). */
  FRR_CLK_MONOTONIC = 1,
  /* Realtime (wall) clock. Analagous to CLOCK_REALTIME for clock_gettime(). */
  FRR_CLK_REALTIME  = 2,
};

/**
 * Converts a timespec to a timeval.
 *
 * The caller must ensure that (tv_usec * 1000) is in the range of a signed
 * long. It is recommended to adjust a timeval by calling timeval_adjust()
 * before passing it to this function.
 *
 * @param timeval to convert
 * @return the resultant timespec
 */
struct timespec
timeval2timespec (struct timeval);

/**
 * Converts a timeval to a timespec.
 *
 * tv_nsec is divided by 1000 and rounded to the nearest microsecond.
 *
 * @param timespec to convert
 * @return the resultant timeval
 */
struct timeval
timespec2timeval (struct timespec);

/**
 * Adjusts a timespec so that tv_nsec is in the range [0, NANOS_IN_SECOND).
 *
 * tv_nsec is reduced in increments of NANOS_IN_SECOND until it is in range.
 * Each reduction of tv_nsec increments tv_sec by 1.
 *
 * If the timespec represents a negative value, its fields are set to 0.
 *
 * @param timespec to adjust
 * @return the adjusted timespec
 */
struct timespec
timespec_adjust (struct timespec);

/**
 * Adjusts a timeval so that tv_usec is in the range [0, MICROS_IN_SECOND).
 *
 * tv_nsec is reduced in increments of MICROS_IN_SECOND until it is in range.
 * Each reduction of tv_usec increments tv_sec by 1.
 *
 * If the timeval represents a negative value, its fields are set to 0.
 *
 * @param timeval to adjust
 * @return the adjusted timeval
 */
struct timeval
timeval_adjust (struct timeval);

/**
 * Computes the difference between two timespecs.
 *
 * Timespec b is subtracted from timespec a. The result is then adjusted with a
 * call to timespec_adjust().
 *
 * @param a minuend timespec
 * @param b subtrahend timespec
 * @return timespec_adjust (a - b)
 */
struct timespec
timespec_subtract (struct timespec a, struct timespec b);

/**
 * Computes the difference between two timevals.
 *
 * Timeval b is subtracted from timeval a. The result is then adjusted with a
 * call to timeval_adjust().
 *
 * @param a minuend timeval
 * @param b subtrahend timeval
 * @return timeval_adjust (a - b)
 */
struct timeval
timeval_subtract (struct timeval a, struct timeval b);

/**
 * Compares two timespecs.
 *
 * Return values:
 *   a > b ==> positive
 *   a < b ==> negative
 *   a = b ==> 0
 *
 * @param a first timespec
 * @param b second timespec
 * @return comparison result as described
 */
int
timespec_cmp (struct timespec a, struct timespec n);

/**
 * Compares two timevals.
 *
 * Return values:
 *   a > b ==> positive
 *   a < b ==> negative
 *   a = b ==> 0
 *
 * @param a first timeval
 * @param b second timeval
 * @return comparison result as described
 */
int
timeval_cmp (struct timeval a, struct timeval b);

/**
 * Computes the elapsed time between two timespecs in seconds.
 *
 * @param a first timespec
 * @param b second timespec
 * @return elapsed time in seconds
 */
unsigned long
timespec_elapsed (struct timespec a, struct timespec b);

/**
 * Computes the elapsed time between two timevals in seconds.
 *
 * @param a first timeval
 * @param b second timeval
 * @return elapsed time in seconds
 */
unsigned long
timeval_elapsed (struct timeval a, struct timeval b);

/**
 * Get the system monotonic time.
 *
 * This is the platform equivalent of clock_gettime (CLOCK_MONOTONIC, ...);
 * It should be used in place of that function within FRR because
 * clock_gettime() is not available on all supported platforms.
 *
 * @param[out] status code
 *              0 => success
 *             -1 => check errno
 * @return a timeval representing the system monotonic time 0 for success
 */
struct timeval
frr_monotonic (int *);

/**
 * Get the system time.
 *
 * This is a portability wrapper for clock_gettime(), which is not available on
 * all platforms. The available clocks are enumerated and documented in frr_clkid.
 * This wrapper should be used in place of clock_gettime() in all FRR code in order
 * to maintain portability.
 *
 * @param[in] clkid the clock ID
 * @param[out] tv the timeval to store the result in
 * @return status code
 *          0 => success
 *         -1 => check errno
 */
int
frr_gettime (enum frr_clkid clkid, struct timeval *tv);

#endif /* _TIMEUTIL_H */
