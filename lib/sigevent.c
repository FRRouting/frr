/* Quagga signal handling functions.
 * Copyright (C) 2004 Paul Jakma,
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>
#include <sigevent.h>
#include <log.h>

struct quagga_sigevent_master_t
{
  struct thread_master *tm;
  struct thread *t;

  struct quagga_signal_t *signals;
  int sigc;
 
} sigmaster; 

/* Generic signal handler 
 * Schedules signal event thread
 */
void
quagga_signal_handler (int signo)
{
  int i;
  struct quagga_signal_t *sig;
  
  for (i = 0; i < sigmaster.sigc; i++)
    {
      sig = &(sigmaster.signals[i]);
      
      if (sig->signal == signo)
        sig->caught++;
    }
} 

int
quagga_signal_timer (struct thread *t)
{
  sigset_t newmask, oldmask;
  struct quagga_sigevent_master_t *sigm;
  struct quagga_signal_t *sig;
  int i;

  sigm = THREAD_ARG (t);
  
  /* block all signals */
  sigfillset (&newmask);
  if ( (sigprocmask (SIG_BLOCK, &newmask, &oldmask)) < 0)
    {
      zlog_err ("quagga_signal_timer: couldnt block signals!");
		  sigm->t = thread_add_timer (sigm->tm, quagga_signal_timer, 
		                              &sigmaster, QUAGGA_SIGNAL_TIMER_INTERVAL);    
      return -1;
    }
  
  for (i = 0; i < sigm->sigc; i++)
    {
      sig = &(sigm->signals[i]);
      if (sig->caught > 0)
        {
          sig->caught = 0;
          sig->handler();
        }
    }
  
  sigm->t = thread_add_timer (sigm->tm, quagga_signal_timer, &sigmaster, 
                                           QUAGGA_SIGNAL_TIMER_INTERVAL);

  if ( sigprocmask (SIG_UNBLOCK, &oldmask, NULL) < 0 );
    return -1;
  
  return 0;
}

/* Initialization of signal handles. */
/* Signale wrapper. */
int
signal_set (int signo)
{
  int ret;
  struct sigaction sig;
  struct sigaction osig;

  sig.sa_handler = &quagga_signal_handler;
  sigfillset (&sig.sa_mask);
  sig.sa_flags = 0;
  if (signo == SIGALRM) {
#ifdef SA_INTERRUPT
      sig.sa_flags |= SA_INTERRUPT; /* SunOS */
#endif
  } else {
#ifdef SA_RESTART
      sig.sa_flags |= SA_RESTART;
#endif /* SA_RESTART */
  }

  ret = sigaction (signo, &sig, &osig);
  if (ret < 0) 
    return ret;
  else
    return 0;
}

void 
signal_init (struct thread_master *m, 
             int sigc, struct quagga_signal_t signals[])
{

  int i = 0;
  struct quagga_signal_t *sig;
  
  while (i < sigc)
    {
      sig = &signals[i];
      if ( signal_set (sig->signal) < 0 )
        exit (-1);
      i++;
    }

  sigmaster.sigc = sigc;
  sigmaster.signals = signals;
  sigmaster.tm = m;
  
  sigmaster.t = 
    thread_add_timer (m, quagga_signal_timer, &sigmaster, 
                      QUAGGA_SIGNAL_TIMER_INTERVAL);

}

