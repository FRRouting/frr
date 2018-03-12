/*
 * Debugging utilities.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 * Quentin Young
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
#ifndef _FRRDEBUG_H
#define _FRRDEBUG_H

#include <zebra.h>
#include "command.h"
#include "frratomic.h"

/*
 * Debugging modes.
 *
 * FRR's convention is that a debug statement issued under the vty CONFIG_NODE
 * persists to the config file, whereas the same debug statement issued from
 * the ENABLE_NODE only persists for the current session. These are mapped to
 * DEBUG_MODE_CONF and DEBUG_MODE_TERM respectively.
 *
 * They are not mutually exclusive and are placed in the MSB of the flags
 * field in a debugging record.
 */
#define DEBUG_MODE_TERM 0x01000000
#define DEBUG_MODE_CONF 0x02000000
#define DEBUG_MODE_ALL (DEBUG_MODE_TERM | DEBUG_MODE_CONF)
#define DEBUG_MODE_NONE 0x00000000
#define DEBUG_OPT_ALL 0x00FFFFFF
#define DEBUG_OPT_NONE 0x00000000


/*
 * Debugging record.
 *
 * All operations on this record exposed in this header are MT-safe.
 *
 * flags
 *    A bitfield with the following format (bytes high to low)
 *    - [0] Debugging mode field (MSB)  | Mode
 *    - [1] Arbitrary flag field        | Option
 *    - [2] Arbitrary flag field        | Option
 *    - [3] Arbitrary flag field (LSB)  | Option
 *
 *              ALL THESE BYTES ARE YOURS - EXCEPT MODE.
 *                      ATTEMPT NO BIT OPS THERE.
 *
 *    The MSB of this field determines the debug mode, Use the DEBUG_MODE*
 *    macros to manipulate this byte.
 *
 *    The low 3 bytes of this field may be used to store arbitrary information.
 *    Usually they are used to store flags that tune how detailed the logging
 *    for a particular debug record is. Use the DEBUG_OPT* macros to manipulate
 *    those bytes.
 *
 *    All operations performed on this field should be done using the macros
 *    later in this header file. They are guaranteed to be atomic operations
 *    with respect to this field. Using anything except the macros to
 *    manipulate the flags field in a multithreaded environment results in
 *    undefined behavior.
 *
 * desc
 *    Human-readable description of this debugging record.
 */
struct debug {
	_Atomic uint32_t flags;
	const char *desc;
};

/*
 * Callback set for debugging code.
 *
 * debug_set_all
 *    Function pointer to call when the user requests that all debugs have a
 *    mode set.
 */
struct debug_callbacks {
	/*
	 * flags
	 *    flags to set on debug flag fields
	 *
	 * set
	 *    true: set flags
	 *    false: unset flags
	 */
	void (*debug_set_all)(uint32_t flags, bool set);
};

/*
 * Check if a mode is set for a debug.
 *
 * MT-Safe
 */
#define DEBUG_MODE_CHECK(name, type)                                           \
	CHECK_FLAG_ATOMIC(&(name)->flags, (type)&DEBUG_MODE_ALL)

/*
 * Check if an option bit is set for a debug.
 *
 * MT-Safe
 */
#define DEBUG_OPT_CHECK(name, type)                                            \
	CHECK_FLAG_ATOMIC(&(name)->flags, (type)&DEBUG_OPT_ALL)

/*
 * Check if bits are set for a debug.
 *
 * MT-Safe
 */
#define DEBUG_FLAGS_CHECK(name, type) CHECK_FLAG_ATOMIC(&(name)->flags, (type))

/*
 * Check if any mode is on for a debug.
 *
 * MT-Safe
 */
#define DEBUG(name) DEBUG_MODE_CHECK((name), DEBUG_MODE_ALL)

/*
 * Set modes on a debug.
 *
 * MT-Safe
 */
#define DEBUG_MODE_SET(name, type)                                             \
	SET_FLAG_ATOMIC(&(name)->flags, (type)&DEBUG_MODE_ALL)

/*
 * Unset modes on a debug.
 *
 * MT-Safe
 */
#define DEBUG_MODE_UNSET(name, type)                                           \
	UNSET_FLAG_ATOMIC(&(name)->flags, (type)&DEBUG_MODE_ALL)

/*
 * Set options on a debug.
 *
 * MT-Safe
 */
#define DEBUG_OPT_SET(name, type)                                              \
	SET_FLAG_ATOMIC(&(name)->flags, (type)&DEBUG_OPT_ALL)

/*
 * Unset options on a debug.
 *
 * MT-Safe
 */
#define DEBUG_OPT_UNSET(name, type)                                            \
	UNSET_FLAG_ATOMIC(&(name)->flags, (type)&DEBUG_OPT_ALL)

/*
 * Set bits on a debug.
 *
 * MT-Safe
 */
#define DEBUG_FLAGS_SET(name, type) SET_FLAG_ATOMIC(&(name)->flags, (type))

/*
 * Unset bits on a debug.
 *
 * MT-Safe
 */
#define DEBUG_FLAGS_UNSET(name, type) UNSET_FLAG_ATOMIC(&(name)->flags, (type))

/*
 * Unset all modes and options on a debug.
 *
 * MT-Safe
 */
#define DEBUG_CLEAR(name) RESET_FLAG_ATOMIC(&(name)->flags)

/*
 * Set all modes and options on a debug.
 *
 * MT-Safe
 */
#define DEBUG_ON(name)                                                         \
	SET_FLAG_ATOMIC(&(name)->flags, DEBUG_MODE_ALL | DEBUG_OPT_ALL)

/*
 * Map a vty node to the correct debugging mode flags. FRR behaves such that a
 * debug statement issued under the config node persists to the config file,
 * whereas the same debug statement issued from the enable node only persists
 * for the current session.
 *
 * MT-Safe
 */
#define DEBUG_NODE2MODE(vtynode)                                               \
	(((vtynode) == CONFIG_NODE) ? DEBUG_MODE_ALL : DEBUG_MODE_TERM)


/*
 * Optional initializer for debugging. Highly recommended.
 *
 * This function installs common debugging commands and allows the caller to
 * specify callbacks to take when these commands are issued, allowing the
 * caller to respond to events such as a request to turn off all debugs.
 *
 * MT-Safe
 */
void debug_init(const struct debug_callbacks *cb);

#endif /* _FRRDEBUG_H */
