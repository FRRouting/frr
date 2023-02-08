// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Javier Garcia <javier.garcia@voltanet.io>
 *
 */

/*
 *  Timer definitions to be used internally by the pcep_timers library.
 */

#ifndef PCEP_TIMERS_EVENT_LOOP_H_
#define PCEP_TIMERS_EVENT_LOOP_H_

#include "pcep_timer_internals.h"

void walk_and_process_timers(pcep_timers_context *timers_context);

#endif
