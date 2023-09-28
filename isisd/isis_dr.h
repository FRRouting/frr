// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_dr.h
 *                             IS-IS designated router related routines
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */

#ifndef _ZEBRA_ISIS_DR_H
#define _ZEBRA_ISIS_DR_H

void isis_run_dr(struct event *thread);
int isis_dr_elect(struct isis_circuit *circuit, int level);
int isis_dr_resign(struct isis_circuit *circuit, int level);
int isis_dr_commence(struct isis_circuit *circuit, int level);
const char *isis_disflag2string(int disflag);

enum isis_dis_state {
	ISIS_IS_NOT_DIS,
	ISIS_IS_DIS,
	ISIS_WAS_DIS,
	ISIS_UNKNOWN_DIS
};

#endif /* _ZEBRA_ISIS_DR_H */
