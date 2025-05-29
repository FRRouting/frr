// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
 */

#ifndef _FRRATOMIC_H
#define _FRRATOMIC_H

/* C++ compatibility */
#ifdef __cplusplus
#include <stdint.h>
#include <atomic>
using std::atomic_int;
using std::memory_order;
using std::memory_order_relaxed;
using std::memory_order_acquire;
using std::memory_order_release;
using std::memory_order_acq_rel;
using std::memory_order_consume;
using std::memory_order_seq_cst;

typedef std::atomic<bool>		atomic_bool;
typedef std::atomic<size_t>		atomic_size_t;
typedef std::atomic<uint_fast32_t>	atomic_uint_fast32_t;
typedef std::atomic<uintptr_t>		atomic_uintptr_t;

#else
#include <stdatomic.h>
#endif

#endif /* _FRRATOMIC_H */
