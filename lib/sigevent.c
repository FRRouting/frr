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

/* master signals descriptor struct */
struct quagga_sigevent_master_t
{
  struct thread *t;

  struct quagga_signal_t *signals; 
  int sigc;
  
  volatile sig_atomic_t caught;
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
        sig->caught = 1;
    }
  
  sigmaster.caught = 1;
} 

/* check if signals have been caught and run appropriate handlers */
int
quagga_sigevent_process (void)
{
  struct quagga_signal_t *sig;
  int i;
#ifdef SIGEVENT_BLOCK_SIGNALS
  /* shouldnt need to block signals, but potentially may be needed */
  sigset_t newmask, oldmask;

  /*
   * Block most signals, but be careful not to defer SIGTRAP because
   * doing so breaks gdb, at least on NetBSD 2.0.  Avoid asking to
   * block SIGKILL, just because we shouldn't be able to do so.
   */
  sigfillset (&newmask);
  sigdelset (&newmask, SIGTRAP);
  sigdelset (&newmask, SIGKILL);
   
  if ( (sigprocmask (SIG_BLOCK, &newmask, &oldmask)) < 0)
    {
      zlog_err ("quagga_signal_timer: couldnt block signals!");
      return -1;
    }
#endif /* SIGEVENT_BLOCK_SIGNALS */

  if (sigmaster.caught > 0)
    {
      sigmaster.caught = 0;
      /* must not read or set sigmaster.caught after here,
       * race condition with per-sig caught flags if one does
       */
      
      for (i = 0; i < sigmaster.sigc; i++)
        {
          sig = &(sigmaster.signals[i]);

          if (sig->caught > 0)
            {
              sig->caught = 0;
              sig->handler ();
            }
        }
    }

#ifdef SIGEVENT_BLOCK_SIGNALS
  if ( sigprocmask (SIG_UNBLOCK, &oldmask, NULL) < 0 );
    return -1;
#endif /* SIGEVENT_BLOCK_SIGNALS */

  return 0;
}

#ifdef SIGEVENT_SCHEDULE_THREAD
/* timer thread to check signals. Shouldnt be needed */
int
quagga_signal_timer (struct thread *t)
{
  struct quagga_sigevent_master_t *sigm;
  struct quagga_signal_t *sig;
  int i;

  sigm = THREAD_ARG (t);
  sigm->t = thread_add_timer (sigm->t->master, quagga_signal_timer, &sigmaster,
                              QUAGGA_SIGNAL_TIMER_INTERVAL);
  return quagga_sigevent_process ();
}
#endif /* SIGEVENT_SCHEDULE_THREAD */

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
signal_init (struct thread_master *m, int sigc, 
             struct quagga_signal_t signals[])
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

#ifdef SIGEVENT_SCHEDULE_THREAD  
  sigmaster.t = 
    thread_add_timer (m, quagga_signal_timer, &sigmaster, 
                      QUAGGA_SIGNAL_TIMER_INTERVAL);
#endif /* SIGEVENT_SCHEDULE_THREAD */
}
