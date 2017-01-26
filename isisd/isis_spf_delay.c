/*
 * This is an implementation of the IETF SPF delay algorithm 
 * as explain in draft-ietf-rtgwg-backoff-algo
 *
 * Module name: isis_spf_delay.c
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

#include <zebra.h>
#include <sys/time.h>
#include <stdlib.h>

#include "thread.h"
#include "memory.h"
#include "prefix.h"

#include "isisd/isis_constants.h"
#include "isisd/isisd.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_spf_delay.h"

const char       *isis_spf_delay_states[3] = { "QUIET", 
					       "SHORT_WAIT", 
					       "LONG_WAIT"};

DEFINE_MTYPE_STATIC(ISISD, ISIS_SPF_DELAY_REINIT, "ISIS spf delay reinit")
DEFINE_MTYPE_STATIC(ISISD, ISIS_SPF_DELAY_AF, "ISIS spf delay af")
DEFINE_MTYPE_STATIC(ISISD, ISIS_SPF_DELAY, "ISIS spf delay")


int
isis_spf_delay_event_ttl_expires(struct thread *thread) {

  int level = 0;
  struct isis_spf_delay_reinit    *reinit;
  struct isis_area        *area;
  int family = 0;

  reinit = THREAD_ARG(thread);
  
  area = reinit->area;
  level = reinit->level;
  family = reinit->family;

  if (family == AF_INET) {
    family = 0;
  } else if (family == AF_INET6) {
    family = 1; 
  }
  
  area->spf_delay_ietf[level-1]->family[family]->state = ISIS_SPF_DELAY_STATE_LONG_WAIT;
  timerclear(&area->spf_delay_ietf[level-1]->family[family]->ttl_time);	
  area->spf_delay_ietf[level-1]->family[family]->t_timetolearn = NULL;	
  if (isis->debugs & DEBUG_SPF_IETF) {
    zlog_debug ("ISIS-Spf (%s) L%d IETF SPF delay TIMETOLEARN expired moved to state %d (%s) family %d\n",
                area->area_tag, 
		level, 
		area->spf_delay_ietf[level-1]->family[family]->state,
                isis_spf_delay_states[area->spf_delay_ietf[level-1]->family[family]->state],
		family);
  }

  return 1;
}


int
isis_spf_delay_event_holddown_expires(struct thread *thread) {

  int level = 0; 
  struct isis_spf_delay_reinit	*reinit;	
  struct isis_area	*area;
  int family = 0;

  reinit = THREAD_ARG(thread);
  
  area = reinit->area;
  level = reinit->level;	
  family = reinit->family;
	
  if (family == AF_INET) {
    family = 0;
  } else if (family == AF_INET6) {
    family = 1;
  }

  if (isis->debugs & DEBUG_SPF_IETF)
    zlog_debug ("ISIS-Spf (%s) L%d F%d IETF SPF delay : disabling timetolearn (thread %p)",
                area->area_tag, 
		level, 
		family, 
		area->spf_delay_ietf[level-1]->family[family]->t_timetolearn);

  THREAD_TIMER_OFF(area->spf_delay_ietf[level-1]->family[family]->t_timetolearn);
  area->spf_delay_ietf[level-1]->family[family]->t_holddown = NULL;
  area->spf_delay_ietf[level-1]->family[family]->t_timetolearn = NULL;
  timerclear(&area->spf_delay_ietf[level-1]->family[family]->first_event_time);
  timerclear(&area->spf_delay_ietf[level-1]->family[family]->resettime);
  timerclear(&area->spf_delay_ietf[level-1]->family[family]->ttl_time);
  area->spf_delay_ietf[level-1]->family[family]->state = ISIS_SPF_DELAY_STATE_QUIET;

  if (isis->debugs & DEBUG_SPF_IETF) {
    zlog_debug ("ISIS-Spf (%s) L%d IETF SPF delay HOLDDOWN expired moved to state %d (%s) family %d\n",
		area->area_tag, 
		level, 
		area->spf_delay_ietf[level-1]->family[family]->state,
		isis_spf_delay_states[area->spf_delay_ietf[level-1]->family[family]->state],
		family);
  }
	
  return 1;
}

int
isis_spf_delay_ietf_schedule(struct isis_area *area, int level, int family) {
  struct timeval time_now, time_now_rt;
  long current_wait_time;
  struct isis_spf_delay_reinit  *reinit;
  unsigned char old_spf_state;

  reinit = XMALLOC(MTYPE_ISIS_SPF_DELAY_REINIT, sizeof(struct isis_spf_delay_reinit));
  old_spf_state = area->spf_delay_ietf[level-1]->family[family]->state;
 
  if (family != 0) 
   return ISIS_OK; 
  
  reinit->area = area;
  reinit->level = level;
  reinit->family = AF_INET;

  gettimeofday(&time_now_rt, NULL);
  monotime(&time_now);

  if (isis->debugs & DEBUG_SPF_EVENTS)
    zlog_debug ("ISIS-Spf (%s) L%d SPF F%d schedule called using IETF algorithm, ttl thread : %p, holddown thread : %p",
                area->area_tag, 
		level, 
		family, 
		area->spf_delay_ietf[level-1]->family[family]->t_timetolearn,
		area->spf_delay_ietf[level-1]->family[family]->t_holddown);


  // If first event equals 0, we init first event to current time
  area->spf_delay_ietf[level-1]->family[family]->last_event_time = time_now_rt;
 
  if (area->spf_delay_ietf[level-1]->family[family]->first_event_time.tv_sec == 0)
    area->spf_delay_ietf[level-1]->family[family]->first_event_time = time_now_rt;

  // We compute the appropriate wait time and new state
  if (area->spf_delay_ietf[level-1]->family[family]->state == ISIS_SPF_DELAY_STATE_QUIET) {
    // QUIET state behavior
    
    current_wait_time = area->spf_delay_ietf[level-1]->init_delay;
    area->spf_delay_ietf[level-1]->family[family]->state = ISIS_SPF_DELAY_STATE_SHORT_WAIT;

    // We disable Time to learn timer
    if (isis->debugs & DEBUG_SPF_IETF)
      zlog_debug ("ISIS-Spf (%s) L%d F%d IETF SPF delay : disabling timetolearn (thread %p)",
                  area->area_tag,
		  level,
		  family,
		  area->spf_delay_ietf[level-1]->family[family]->t_timetolearn);

    THREAD_TIMER_OFF(area->spf_delay_ietf[level-1]->family[family]->t_timetolearn);
 
    // Start timetolearn timer 
    if (isis->debugs & DEBUG_SPF_IETF)
      zlog_debug ("ISIS-Spf (%s) L%d F%d IETF SPF delay launch TIMETOLEARN timer\n",
                  area->area_tag,
		  level,
		  family);
      area->spf_delay_ietf[level-1]->family[family]->ttl_time = timeval_add_msec(time_now,area->spf_delay_ietf[level-1]->timetolearn); 
      THREAD_TIMER_MSEC_ON(master,
                           area->spf_delay_ietf[level-1]->family[family]->t_timetolearn,
                           isis_spf_delay_event_ttl_expires,
                           reinit,
                           area->spf_delay_ietf[level-1]->timetolearn);

    // We disable Holddown timer
    if (isis->debugs & DEBUG_SPF_IETF)
      zlog_debug ("ISIS-Spf (%s) L%d F%d IETF SPF delay : disabling holddown (thread %p)",
                  area->area_tag,
		  level,
		  family,
		  area->spf_delay_ietf[level-1]->family[family]->t_holddown);

    THREAD_TIMER_OFF(area->spf_delay_ietf[level-1]->family[family]->t_holddown);
	 
    // Start Holddown timer  
    if (isis->debugs & DEBUG_SPF_IETF)
      zlog_debug ("ISIS-Spf (%s) L%d F%d IETF SPF delay launch HOLDDOWN timer\n",
                  area->area_tag,
		  level,
		  family);
      area->spf_delay_ietf[level-1]->family[family]->resettime = timeval_add_msec(time_now,
										  area->spf_delay_ietf[level-1]->holddown);
      THREAD_TIMER_MSEC_ON (master, area->spf_delay_ietf[level-1]->family[family]->t_holddown, 
      isis_spf_delay_event_holddown_expires,reinit,area->spf_delay_ietf[level-1]->holddown);
  
  } else if (area->spf_delay_ietf[level-1]->family[family]->state == ISIS_SPF_DELAY_STATE_SHORT_WAIT) {
    // SHORT WAIT state behavior
    
    current_wait_time = area->spf_delay_ietf[level-1]->short_delay;

    // We disable Holddown timer
    if (isis->debugs & DEBUG_SPF_IETF)
      zlog_debug ("ISIS-Spf (%s) L%d F%d IETF SPF delay : disabling holddown (thread %p)",
                  area->area_tag,
                  level,
		  family,
		  area->spf_delay_ietf[level-1]->family[family]->t_holddown);

      THREAD_TIMER_OFF(area->spf_delay_ietf[level-1]->family[family]->t_holddown);
  
      // Start Holddown timer
      if (isis->debugs & DEBUG_SPF_IETF)
        zlog_debug ("ISIS-Spf (%s) L%d F%d IETF SPF delay launch HOLDDOWN timer\n",
                    area->area_tag,
		    level,
		    family);
      area->spf_delay_ietf[level-1]->family[family]->resettime = timeval_add_msec(time_now,
										  area->spf_delay_ietf[level-1]->holddown);
      THREAD_TIMER_MSEC_ON (master,
			    area->spf_delay_ietf[level-1]->family[family]->t_holddown,
                            isis_spf_delay_event_holddown_expires,
			    reinit,
			    area->spf_delay_ietf[level-1]->holddown);
  } else {
    // LONG WAIT state behavior
    
    current_wait_time = area->spf_delay_ietf[level-1]->long_delay;
    // We disable Holddown timer
    if (isis->debugs & DEBUG_SPF_IETF)
      zlog_debug ("ISIS-Spf (%s) L%d F%d IETF SPF delay : disabling holddown (thread %p)",
                  area->area_tag,
		  level,
		  family,
		  area->spf_delay_ietf[level-1]->family[family]->t_holddown);

    THREAD_TIMER_OFF(area->spf_delay_ietf[level-1]->family[family]->t_holddown);
	 
    // Start Holddown timer
    if (isis->debugs & DEBUG_SPF_IETF)
      zlog_debug ("ISIS-Spf (%s) L%d F%d IETF SPF delay launch HOLDDOWN timer\n",
                  area->area_tag,
		  level,
		  family);
    area->spf_delay_ietf[level-1]->family[family]->resettime = timeval_add_msec(time_now,
										area->spf_delay_ietf[level-1]->holddown);
    THREAD_TIMER_MSEC_ON (master,
			  area->spf_delay_ietf[level-1]->family[family]->t_holddown,
			  isis_spf_delay_event_holddown_expires,
			  reinit,
			  area->spf_delay_ietf[level-1]->holddown);
  }

  // We check if SPF is already scheduled
  if (area->spf_delay_ietf[level-1]->family[family]->pending) {
    if  (isis->debugs & DEBUG_SPF_IETF) {	
      zlog_debug ("ISIS-Spf (%s) L%d F%d IETF SPF already scheduled, due in %ld msec",
                  area->area_tag,
		  level,
		  family,
		  timeval_elapsed(area->spf_delay_ietf[level-1]->family[family]->next_spf, 
                                  time_now) / 1000);	
    }

    return ISIS_OK;
  }

  // We deactivate current SPT
  if (isis->debugs & DEBUG_SPF_IETF)
    zlog_debug ("ISIS-Spf (%s) L%d F%d IETF SPF delay disabling SPF timer %p",
		area->area_tag, level, family,	
		area->spf_delay_ietf[level-1]->family[family]->t_spf);
 
  THREAD_TIMER_OFF(area->spf_delay_ietf[level-1]->family[family]->t_spf);
 
  if (isis->debugs & DEBUG_SPF_IETF)
    zlog_debug ("ISIS-Spf (%s) L%d F%d IETF SPF delay move from state %d (%s) to state %d (%s)\n",
	        area->area_tag,
		level,
		family,
		old_spf_state, 
 	        isis_spf_delay_states[old_spf_state],
	        area->spf_delay_ietf[level-1]->family[family]->state,
	        isis_spf_delay_states[area->spf_delay_ietf[level-1]->family[family]->state]);

  area->spf_delay_ietf[level-1]->family[family]->next_spf = timeval_add_msec(time_now,
									     current_wait_time);

  if (isis->debugs & DEBUG_SPF_IETF)
    zlog_debug ("ISIS-Spf (%s) L%d F%d IETF SPF delay : next SPF scheduled in %ld msec\n",
	        area->area_tag,
		level,
		family,
	        current_wait_time);

  // Schedule SPF
  if (level == 1) {
    if (family == 0) // IPv4
      THREAD_TIMER_MSEC_ON (master,
			    area->spf_delay_ietf[level-1]->family[family]->t_spf,
			    isis_run_spf_l1,
			    area,
                            current_wait_time);
    if (family == 1) // IPv6
      THREAD_TIMER_MSEC_ON (master,
			    area->spf_delay_ietf[level-1]->family[family]->t_spf,
			    isis_run_spf6_l1,
			    area,
                            current_wait_time);
  } else  {
    if (family == 0) // IPv4
      THREAD_TIMER_MSEC_ON (master,
			    area->spf_delay_ietf[level-1]->family[family]->t_spf,
			    isis_run_spf_l2,
			    area,
                            current_wait_time);
    if (family == 1) // IPv6
      THREAD_TIMER_MSEC_ON (master,
			    area->spf_delay_ietf[level-1]->family[family]->t_spf,
			    isis_run_spf6_l2,
			    area,
                            current_wait_time);
  }

  area->spf_delay_ietf[level-1]->family[family]->pending = 1;

  return ISIS_OK;
}


void
isis_delete_spf_delay_ietf(struct isis_area *area)
{
  struct isis_spf_delay_ietf *s;
	
  if (!area)
    return ;

  s = area->spf_delay_ietf[0];
  THREAD_TIMER_OFF(s->family[0]->t_spf);
  THREAD_TIMER_OFF(s->family[1]->t_spf);
  THREAD_TIMER_OFF(s->family[0]->t_holddown);
  THREAD_TIMER_OFF(s->family[1]->t_holddown);	
  THREAD_TIMER_OFF(s->family[0]->t_timetolearn);	
  THREAD_TIMER_OFF(s->family[1]->t_timetolearn);	
  XFREE(MTYPE_ISIS_SPF_DELAY_AF, s->family[0]);
  XFREE(MTYPE_ISIS_SPF_DELAY_AF, s->family[1]);	
  XFREE(MTYPE_ISIS_SPF_DELAY, s);

  s = area->spf_delay_ietf[1];
  THREAD_TIMER_OFF(s->family[0]->t_spf);
  THREAD_TIMER_OFF(s->family[1]->t_spf);
  THREAD_TIMER_OFF(s->family[0]->t_holddown);
  THREAD_TIMER_OFF(s->family[1]->t_holddown);
  THREAD_TIMER_OFF(s->family[0]->t_timetolearn);	
  THREAD_TIMER_OFF(s->family[1]->t_timetolearn); 
  XFREE(MTYPE_ISIS_SPF_DELAY_AF, s->family[0]);
  XFREE(MTYPE_ISIS_SPF_DELAY_AF, s->family[1]);
  XFREE(MTYPE_ISIS_SPF_DELAY, s);

  area->spf_delay_ietf[0] = 0;
  area->spf_delay_ietf[1] = 0;		
}



struct isis_spf_delay_ietf *
isis_create_spf_delay_ietf(void) {

  struct isis_spf_delay_ietf *s1; 
  struct isis_spf_delay_ietf_af *a1; 
  struct isis_spf_delay_ietf_af *a2; 
  
  s1 = XMALLOC(MTYPE_ISIS_SPF_DELAY, sizeof(struct isis_spf_delay_ietf));
  a1 = XMALLOC(MTYPE_ISIS_SPF_DELAY_AF, sizeof(struct isis_spf_delay_ietf_af));
  a2 = XMALLOC(MTYPE_ISIS_SPF_DELAY_AF, sizeof(struct isis_spf_delay_ietf_af));
  
  zlog_debug("ISIS-Spf Initialize IETF SPF algorithm\n"); 

  s1->short_delay = 0;
  s1->init_delay = 0;
  s1->long_delay = 0;
  s1->timetolearn = 0;
  s1->holddown = 0;
       
  a1->state = ISIS_SPF_DELAY_STATE_QUIET; 
  timerclear(&a1->first_event_time);
  timerclear(&a1->last_event_time);
  timerclear(&a1->next_spf);
  a1->t_spf = NULL;
  a1->t_holddown = NULL;
  a1->t_timetolearn = NULL;
  timerclear(&a1->ttl_time);
  timerclear(&a1->resettime);
  a1->pending = 0;	
  s1->family[0] = a1;

  a2->state = ISIS_SPF_DELAY_STATE_QUIET;
  timerclear(&a2->first_event_time);
  timerclear(&a2->last_event_time);
  timerclear(&a2->next_spf);
  a2->t_spf = NULL;
  a2->t_holddown = NULL; 
  a2->t_timetolearn = NULL;	
  timerclear(&a2->ttl_time);
  timerclear(&a2->resettime);
  a2->pending = 0; 
  s1->family[1] = a2;

  return s1;
}
