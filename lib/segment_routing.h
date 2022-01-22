/*
 * Flexible Algorithm definitions
 * Copyright (C) 2022  Hiroki Shirokura, LINE Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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
#define SR_ALGORITHM_SPF	0   /* RFC8665 */
#define SR_ALGORITHM_STRICT_SPF	1   /* RFC8665 */
#define SR_ALGORITHM_UNSET	127 /* FRRouting defined */
#define SR_ALGORITHM_FLEX_MIN	128 /* draft-ietf-lsr-flex-algo-20 */
#define SR_ALGORITHM_FLEX_MAX	255 /* draft-ietf-lsr-flex-algo-20 */
#define SR_ALGORITHM_COUNT	256

const char *sr_algorithm_string(uint8_t algo);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_SR_H */
