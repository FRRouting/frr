// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_events.h
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */
#ifndef _ZEBRA_ISIS_EVENTS_H
#define _ZEBRA_ISIS_EVENTS_H

/*
 * Events related to circuit
 */
void isis_event_circuit_state_change(struct isis_circuit *circuit,
				     struct isis_area *area, int state);
void isis_event_circuit_type_change(struct isis_circuit *circuit, int newtype);
/*
 * Events related to adjacencies
 */
void isis_event_dis_status_change(struct event *thread);

/*
 * Error events
 */
#define AUTH_ERROR_TYPE_LSP   3
#define AUTH_ERROR_TYPE_SNP   2
#define AUTH_ERROR_TYPE_HELLO 1
void isis_event_auth_failure(char *area_tag, const char *error_string,
			     uint8_t *sysid);

#endif /* _ZEBRA_ISIS_EVENTS_H */
