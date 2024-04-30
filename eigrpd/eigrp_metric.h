// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * EIGRP Metric Math Functions.
 * Copyright (C) 2013-2016
 * Authors:
 *   Donnie Savage
 */

#ifndef _ZEBRA_EIGRP_METRIC_H_
#define _ZEBRA_EIGRP_METRIC_H_

/* Constants */
#define EIGRP_BANDWIDTH_MIN 0x1ull		  /* 1 */
#define EIGRP_BANDWIDTH_SCALER 10000000ull	  /* Inversion value */
#define EIGRP_BANDWIDTH_MAX 0xffffffffffffffffull /* 1.84467441x10^19 */

#define EIGRP_DELAY_MIN 0x1ull /* 1 */
#define EIGRP_DELAY_PICO 1000000ull
#define EIGRP_DELAY_MAX 0xffffffffffffffffull /* 1.84467441x10^19 */

#define EIGRP_MAX_LOAD 256
#define EIGRP_MAX_HOPS 100

#define EIGRP_INACCESSIBLE 0xFFFFFFFFFFFFFFFFull

#define EIGRP_METRIC_MAX 0xffffffffffffffffull /* 1.84467441x10^19 */
#define EIGRP_METRIC_MAX_CLASSIC 0xffffffff
#define EIGRP_METRIC_SCALER 65536	       /* CLASSIC to WIDE conversion */

#define EIGRP_CLASSIC_MAX 0xffffffff /* 4294967295 */
#define EIGRP_CLASSIC_SCALER 256     /* IGRP to EIGRP conversion */


/* Prototypes */
extern eigrp_scaled_t eigrp_bandwidth_to_scaled(eigrp_bandwidth_t bw);
extern eigrp_bandwidth_t eigrp_scaled_to_bandwidth(eigrp_scaled_t scale);
extern eigrp_scaled_t eigrp_delay_to_scaled(eigrp_delay_t delay);
extern eigrp_delay_t eigrp_scaled_to_delay(eigrp_scaled_t scale);

extern eigrp_metric_t eigrp_calculate_metrics(struct eigrp *eigrp,
					      struct eigrp_metrics metric);
extern eigrp_metric_t
eigrp_calculate_total_metrics(struct eigrp *eigrp,
			      struct eigrp_route_descriptor *rd);
extern bool eigrp_metrics_is_same(struct eigrp_metrics m1,
				  struct eigrp_metrics m2);

#endif /* _ZEBRA_EIGRP_METRIC_H_ */
