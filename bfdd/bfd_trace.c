// SPDX-License-Identifier: GPL-2.0-or-later
/* Tracing for BFD
 *
 * Copyright (C) 2024  NVIDIA Corporation
 * Based on BGP tracing implementation
 */

#define TRACEPOINT_CREATE_PROBES
#define TRACEPOINT_DEFINE

#include <zebra.h>

#include "bfd_trace.h"
