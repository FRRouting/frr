// SPDX-License-Identifier: GPL-2.0-or-later

#include "log.h"

#define NHRP_DEBUG_COMMON	(1 << 0)
#define NHRP_DEBUG_KERNEL	(1 << 1)
#define NHRP_DEBUG_IF		(1 << 2)
#define NHRP_DEBUG_ROUTE	(1 << 3)
#define NHRP_DEBUG_VICI		(1 << 4)
#define NHRP_DEBUG_EVENT	(1 << 5)
#define NHRP_DEBUG_ALL		(0xFFFF)

extern unsigned int debug_flags;

#define debugf(level, ...)                                                     \
	do {                                                                   \
		if (unlikely(debug_flags & level))                             \
			zlog_debug(__VA_ARGS__);                               \
	} while (0)
