// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Very simple prng to allow for randomized tests with reproducable
 * results.
 *
 * Copyright (C) 2012 by Open Source Routing.
 * Copyright (C) 2012 by Internet Systems Consortium, Inc. ("ISC")
 *
 * This file is part of Quagga
 */
#ifndef _PRNG_H
#define _PRNG_H

struct prng;

struct prng *prng_new(unsigned long long seed);
int prng_rand(struct prng *);
const char *prng_fuzz(struct prng *, const char *string, const char *charset,
		      unsigned int operations);
void prng_free(struct prng *);

#endif
