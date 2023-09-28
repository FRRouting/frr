// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_TIME_H
#define PIM_TIME_H

#include <stdint.h>

#include <zebra.h>
#include "frrevent.h"

int64_t pim_time_monotonic_sec(void);
int64_t pim_time_monotonic_dsec(void);
int64_t pim_time_monotonic_usec(void);
int pim_time_mmss(char *buf, int buf_size, long sec);
void pim_time_timer_to_mmss(char *buf, int buf_size, struct event *t);
void pim_time_timer_to_hhmmss(char *buf, int buf_size, struct event *t);
void pim_time_uptime(char *buf, int buf_size, int64_t uptime_sec);
void pim_time_uptime_begin(char *buf, int buf_size, int64_t now, int64_t begin);
long pim_time_timer_remain_msec(struct event *t_timer);

#endif /* PIM_TIME_H */
