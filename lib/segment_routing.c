// SPDX-License-Identifier: GPL-2.0-or-later
/*********************************************************************
 * Copyright 2022 Hiroki Shirokura, LINE Corporation
 * Copyright 2022 Masakazu Asama
 * Copyright 2022 6WIND S.A.
 *
 * segment_routing.c: Segment-Routing Library
 *
 * Authors
 * -------
 * Hiroki Shirokura
 * Masakazu Asama
 * Louis Scalbert
 */

#include "segment_routing.h"

const char *sr_algorithm_string(uint8_t algo)
{
	switch (algo) {
	case SR_ALGORITHM_SPF:
		return "SPF";
	case SR_ALGORITHM_STRICT_SPF:
		return "Strict SPF";
	case SR_ALGORITHM_UNSET:
		return "Unset";
	default:
		return algo >= SR_ALGORITHM_FLEX_MIN ? "Flex-Algo" : "Unknown";
	}
}
