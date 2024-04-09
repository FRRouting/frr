// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */

#ifndef __PIM_ERRORS_H__
#define __PIM_ERRORS_H__

#include "lib/ferr.h"

enum pim_log_refs {
	EC_PIM_MSDP_PACKET = PIM_FERR_START,
	EC_PIM_CONFIG,
};

extern void pim_error_init(void);

#endif
