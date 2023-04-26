// SPDX-License-Identifier: GPL-2.0-or-later
/*********************************************************************
 * Copyright 2022 Hiroki Shirokura, LINE Corporation
 * Copyright 2022 Masakazu Asama
 * Copyright 2022 6WIND S.A.
 *
 * segment_routing.h: Segment-Routing Library
 *
 * Authors
 * -------
 * Hiroki Shirokura
 * Masakazu Asama
 * Louis Scalbert
 */

#ifndef _FRR_SR_H
#define _FRR_SR_H

#include <zebra.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * IGP Algorithm Types
 * https://www.iana.org/assignments/igp-parameters/igp-parameters.xhtml
 */
#define SR_ALGORITHM_SPF 0	/* RFC8665 */
#define SR_ALGORITHM_STRICT_SPF 1 /* RFC8665 */
#define SR_ALGORITHM_UNSET 127    /* FRRouting defined */
#define SR_ALGORITHM_FLEX_MIN 128 /* RFC9350 Flex-Algorithm */
#define SR_ALGORITHM_FLEX_MAX 255 /* RFC9350 Flex-Algorithm */
#define SR_ALGORITHM_COUNT 256

const char *sr_algorithm_string(uint8_t algo);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_SR_H */
