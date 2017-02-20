/*
 * This is an implementation of the IETF SPF delay algorithm
 * as explain in draft-ietf-rtgwg-backoff-algo
 *
 * Module name: isis_spf_delay.h 
 * Version:     0.1
 * Created:     25-01-2017 by S. Litkowski
 * Copyright (C) 2017 Orange Labs http://www.orange.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#ifndef ISIS_SPF_DELAY_H
#define ISIS_SPF_DELAY_H

#define	ISIS_SPF_DELAY_STATE_QUIET				0
#define ISIS_SPF_DELAY_STATE_SHORT_WAIT			1
#define ISIS_SPF_DELAY_STATE_LONG_WAIT			2

extern const char	*isis_spf_delay_states[3];
	
struct isis_spf_delay_reinit {
  // Struct used to store some informations needed to reinit SPF algo
  struct isis_area	*area;
  int			level;
};


struct isis_spf_delay_ietf
{
  unsigned int		short_delay;
  unsigned int		init_delay;
  unsigned int		long_delay;
  unsigned int		holddown;
  unsigned int		timetolearn;
  struct timeval        first_event_time;       // Store first event timestamp msec
  struct timeval        last_event_time;        // Store last event received timestamp msec
  unsigned char         state;                  // Store state of algo
  struct thread         *t_holddown;            // Thread for HOLDDOWN timer
  struct thread         *t_timetolearn;         // Thread for TIMETOLEARN timer
	
};

int
isis_spf_delay_event_holddown_expires(struct thread *);

int
isis_spf_delay_event_ttl_expires(struct thread *);

struct isis_spf_delay_ietf *
isis_create_spf_delay_ietf(void);

int
isis_spf_delay_ietf_schedule (struct isis_area *area, int level);

void
isis_delete_spf_delay_ietf(struct isis_area *area);



#endif
