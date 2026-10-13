// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2026 Qipeng Ding */
#ifndef _BFDD_TIMER_H
#define _BFDD_TIMER_H

#include <stdint.h>
#include <sys/time.h>

/* RFC 5880 section 6.8.4, asynchronous receive detection time, in usec.
 * A uint8_t multiplier and uint32_t interval fit in uint64_t, provided
 * the multiplication itself is widened before it is evaluated.
 */
static inline uint64_t bfd_detection_timeout_us(uint8_t multiplier, uint32_t local_min_rx,
						uint32_t remote_min_tx)
{
	uint32_t interval = local_min_rx > remote_min_tx ? local_min_rx : remote_min_tx;

	return (uint64_t)multiplier * interval;
}

/* Divide before assigning to timeval: suseconds_t may be only 32 bits. */
static inline struct timeval bfd_detection_timeout_tv(uint64_t usec)
{
	struct timeval tv = { .tv_sec = usec / 1000000, .tv_usec = usec % 1000000 };

	return tv;
}

#endif /* _BFDD_TIMER_H */
