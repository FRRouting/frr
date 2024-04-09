// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Babel-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */

#ifndef __BABEL_ERRORS_H__
#define __BABEL_ERRORS_H__

#include "lib/ferr.h"

enum babel_log_refs {
	EC_BABEL_MEMORY = BABEL_FERR_START,
	EC_BABEL_PACKET,
	EC_BABEL_CONFIG,
	EC_BABEL_ROUTE,
};

extern void babel_error_init(void);

#endif
