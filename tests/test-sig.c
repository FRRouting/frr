#include <zebra.h>
#include <sigevent.h>
#include "lib/log.h"

void
sighup (void)
{
  printf ("processed hup\n");
}

void
sigusr1 (void)
{
  printf ("processed usr1\n");
}

void
sigusr2 (void)
{
  printf ("processed usr2\n");
}

struct quagga_signal_t sigs[] = 
{
  {
    .signal = SIGHUP,
    .handler = &sighup,
  },
  {
    .signal = SIGUSR1,
    .handler = &sigusr1,
  },
  {
    .signal = SIGUSR2,
    .handler = &sigusr2,
  }
};

struct thread_master *master;
struct thread t;

int
main (void)
{
  master = thread_master_create ();
  signal_init (master, Q_SIGC(sigs), sigs);
  
  zlog_default = openzlog("testsig", ZLOG_NONE,
                          LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);
  zlog_set_level (NULL, ZLOG_DEST_SYSLOG, ZLOG_DISABLED);
  zlog_set_level (NULL, ZLOG_DEST_STDOUT, LOG_DEBUG);
  zlog_set_level (NULL, ZLOG_DEST_MONITOR, ZLOG_DISABLED);
  
  while (thread_fetch (master, &t))
    thread_call (&t);

  exit (0);
}
