# ZEBRA for Dummies

a.k.a. Learn ZEBRA in 2 hours
a.k.a. Zebra Hacking How-To

author: yon uriarte

(C) Feb. 2001

[TOC]

## Disclaimers

This documentation is an attempt to recreate original documentation for the development in FR Routing based on original work done for Zebra by the author (with lots of help of the WayBackMachine).

## Introduction

The author makes the following assumptions about the reader:
* a certain C know-how
* some motivation
* knows what zebra is and does
* has read at least 2 pages about the general architecture of zebra
* can read a 3 liner unified diff without getting confused
* knows the socket(2) syscall and companions

This is not a 100% documentation. When in doubt, do a "less ../lib/*.[ch]"

This document is based on zebra 0.91

## Overview

For the sake of this how-to, let assume you want to write a zebra daemon for a new protocol, ZAP (ZAP's Another Protocol).

You have downloaded a copy of zebra. I'll assume _/frr_ contains the unpacked files. There are some subdirectories, like _/frr/ospfd_, containing the different protocol implementations. There is a subdirectory containing the library _/frr/lib_, the main zebra daemon is in _/frr/zebra_.

Quite a good part of your program will be ZAP specific, but some functionality will be needed from the zebra framework. That is, you want to link the libzebra.a library to use certain common functions and you want to connect to a running zebra daemon to have information about the system (interfaces and routes).

The library includes functions and structures for:
 * connecting to the zebra daemon (zclient.h)
 * vty management (access method (telnet), terminal mangling and cli control)
 command registration
 * access lists (commands and functionality) (filter.h)
 * prefix lists (commands and functionality) (plist.h)
 * route maps
 * keychains
 * satanism (becoming a daemon)
 * logging
 * linked lists, vectors and hashes
 * memory management, including cli
 * cooperative multithreading (using select(2))
 * FSF's getopt() & regexs
 * MD5
 * interface structs and functions, including zebra protocol functions (if.h)
 * socket mangling (sockunion.h and sockopt.h)
 * ip v4&6 route tables (if_rmap.h) ?

and some internally used functions, like serialization support routines for the zebra protocol and whatnot.

## Main

Now, just create a subdirectory, _/frr/zapd_, to store zapd's files. I'll start with main(), as usual, so let's call this file zapd_main.c, here it goes. It is based on ospfd.

```C
/*
 * ZAPd main
 * zapd_main.c (c) 2001 you <me@localhost>
 */

/* just some includes, as usual */

#include <zebra.h>

#include "log.h"
#include "version.h"
#include <getopt.h>
#include "command.h"
#include "thread.h"
#include <signal.h>

/* you might want to put the following #defines on a zapd.h file */

/*
 * this will be the name of the config file in the zebra
 * config directory (could be /usr/local/etc/)
 */
#define ZAPD_DEFAULT_CONFIG "zapd.conf"

/* telnet to this port to login to the zapd vty */
#define ZAPD_VTY_PORT 26666

/* name of the unix socket to communicate with the vtysh */
#define ZAPD_VTYSH_PATH "/tmp/.zapd"

/* Global Variables */
char config_current[] = LDPD_DEFAULT_CONFIG;
char config_default[] = SYSCONFDIR LDPD_DEFAULT_CONFIG;
/* zebra does #define  SYSCONFDIR */

struct option longopts[] =
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "config_file", required_argument, NULL, 'f'},
  { "help",        no_argument,       NULL, 'h'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "version",     no_argument,       NULL, 'v'},
  { 0 }
};

/* will contain (mangled) argv[0] */
char* progname;

/* needed by the thread implementation */
struct thread_master *master;

/* some signal initialization, to avoid getting
 * the floor pulled under you, this is defined after
 * main(), if you are curious
 */
void signal_init(void);

/* These 2 are defined somewhere else, say in libzapd.a */
#ifdef REALLY_DUMMY
void zap_init(void) {return;};
void zap_terminate(void) {return;};
#else
void zap_init(void);
void zap_terminate(void);
#endif

/* Help information display. */
static void
usage (int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {
      printf ("Usage : %s [OPTION...]\n\
Daemon which manages ZAP.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-P, --vty_port     Set vty's port number\n\
-v, --version      Print program version\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n", progname, ZEBRA_BUG_ADDRESS);
    }
  exit (status);
}

/* Main function */
int main(int argc, char** argv, char** envp) {
  char *p;
  int vty_port = 0;
  int daemon_mode = 0;
  char *config_file = NULL;
  struct thread thread;

  umask(0027);

  progname =  ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  zlog_default = openzlog (progname, ZLOG_NOLOG, ZLOG_ZAP,
			   LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);

/* initialize the log subsystem, you will have to include
 * ZLOG_ZAP in the zlog_proto_t enum type definition in
 * lib/log.h
 */

/* this while just reads the options */
  while (1)
    {
      int opt;

      opt = getopt_long (argc, argv, "dlf:hP:v", longopts, 0);

      if (opt == EOF)
	    break;

      switch (opt)
	  {
	  case 0:
	    break;
	  case 'd':
	    daemon_mode = 1;
	    break;
	  case 'f':
	    config_file = optarg;
	    break;
	  case 'P':
	    vty_port = atoi (optarg);
	    break;
	  case 'v':
	    print_version ();
	    exit (0);
	    break;
	  case 'h':
	    usage (0);
	    break;
	  default:
	    usage (1);
	    break;
	  }
    }

/* one to control them all, ... */
/* this the main thread controlling structure,
 * nothing to remember.
 */
  master = thread_make_master ();


/* before you start the engine, put your safety belt on */
  signal_init ();


/* Library inits */
/* First, initializes the command sub-system, if arg, add some commands
 * which are mostly only useful for humans on the vty */
  cmd_init (1);

/* these are all from libzebra */
  vty_init ();
  memory_init ();
  access_list_init ();
  prefix_list_init ();

/*
 * ZAP inits
 */
/* this is implemented somewhere, e.g. on libzap.a
 * here, you could start some threads (the thread subsystem
 * is not running yet), register some commands, ...
 */
 zap_init();

/* This is needed by the command subsystem to finish initialization. */
  sort_node();

/* Read the config file, your commands should be defined before this */
vty_read_config (config_file, config_current, config_default);

/* Change to the daemon program. */
  if (daemon_mode)
    daemon (0, 0);

/* Create VTY socket: start the TCP and unix socket listeners */
  vty_serv_sock (vty_port ? vty_port : LDPD_VTY_PORT, LDPD_VTYSH_PATH);

/* Print banner. */
  zlog (NULL, LOG_INFO, "ZAP (%s) starts", ZEBRA_VERSION);

/* this is the main event loop */
/* Fetch next active thread. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

/* never reached */
  return 0;
}
```

The various signal handlers could call various functions depending on what you would manage: terminate, log rotate ...

```C
/* SIGHUP handler */
void
sighup (int sig)
{
  zlog (NULL, LOG_INFO, "SIGHUP received");
}

/* SIGINT handler. */
void
sigint (int sig)
{
  zlog (NULL, LOG_INFO, "Terminating on signal");

  zap_terminate ();
/* this is your clean-up function */

  exit (0);
}

/* SIGUSR1 handler. */
void
sigusr1 (int sig)
{
  zlog_rotate (NULL);
}

#define RETSIGTYPE void
/* Signal wrapper. */
RETSIGTYPE *
signal_set (int signo, void (*func)(int))
{
  int ret;
  struct sigaction sig;
  struct sigaction osig;

  sig.sa_handler = func;
  sigemptyset (&sig.sa_mask);
  sig.sa_flags = 0;
#ifdef SA_RESTART
  sig.sa_flags |= SA_RESTART;
#endif /* SA_RESTART */

  ret = sigaction (signo, &sig, &osig);

  if (ret < 0)
    return (SIG_ERR);
  else
    return (osig.sa_handler);
}

/* Initialization of signal handles. */
void
signal_init ()
{
  signal_set (SIGHUP, sighup);
  signal_set (SIGINT, sigint);
  signal_set (SIGTERM, sigint);
  signal_set (SIGPIPE, SIG_IGN);
#ifdef SIGTSTP
  signal_set (SIGTSTP, SIG_IGN);
#endif
#ifdef SIGTTIN
  signal_set (SIGTTIN, SIG_IGN);
#endif
#ifdef SIGTTOU
  signal_set (SIGTTOU, SIG_IGN);
#endif
  signal_set (SIGUSR1, sigusr1);
}
```

In complement, you will need a sample zapd.conf, looking more like this:

```
!----------------------------------------------------------------
!
! ZAPd sample configuratin file
!
! zapd.conf
!
hostname zapd
password zebra
!
!log file zapd.log
!
log stdout
!
!----------------------------------------------------------------
```

Which you will have to put in zebra''s config dir, specified with *--prefix=DIR* when running *./configure* to build the library. If you are just experimenting, you might want to define
it as *$HOME/etc* or somesuch and run zebra as non-root, just-in-case. This way, depending on platform, zapd will receive interface and route information but won't be able to change anything.

Now compile it (there is no libzapd.a, yet)

```
  gcc -o zapd -I. -I.. -I../lib zapd_main.c ../lib/libzebra.a libzapd.a
```
and run it
```
  ./zapd &
```
and connect to it:
```
 telnet localhost 26666
```

## Zebra Threads

They are of the easily-and-somewhat-portably-implemented cooperatively-multitasking kind, using select(2).

There are 3 possibilities for a thread to be scheduled:
  1. timer expiration,
  1. I/O event (read or write, not both at once)
  1. as an event (to decouple threads)

The main data structure is struct thread, consider it opaque. The functions for setting up a thread are:

```C
typedef int (*cb)(struct thread* );
/* cb == callback  */

struct thread *
thread_add_read (struct thread_master *m,
		 cb func, void *arg, int fd);
struct thread *
thread_add_write (struct thread_master *m,
		  cb func, void *arg, int fd);

struct thread *
thread_add_timer (struct thread_master *m,
                  cb func, void *arg, long timer);

struct thread *
thread_add_event (struct thread_master *m,
		  cb func, void *arg, int val);
```

All callback functions can read a single parameter, _void* arg_, which is accessed through a simple _THREAD_ARG(struct thread*)_ macro.

The add_read and add_write functions expect a file descriptor, a read thread example follows:

```C
extern struct thread_master* master;
extern int my_read_fd;
extern struct zap_fd_data* per_fd_data;

struct thread* tp;

/* This is the handler function */
int thread_read_handler(struct thread* th) {
 int which_fd;
 struct zap_fd_data* my_fd_data;
 u_int8_t c;

 which_fd = THREAD_FD(th);
 my_fd_data = THREAD_ARG(th);

 read(which_fd,&c,1);

/* do something useful with the data */
 zap_input(my_arg,which_fd,c);

/* reschedule the read thread */
tp = thread_add_read(master, &thread_read_handler, my_fd_data, which_fd);
 return 0;
}

/* Intall it for the first time */
tp = thread_add_read(master, &thread_read_handler, per_fd_data, my_read_fd);
```

Function thread_add_timer expects a "seconds" argument as its last parameter instead of a fd and the thread_add_event function allows for an int val parameter, which you can read in the thread handler with the *THREAD_VAL* macro.

Event threads have priority over timer threads.

All threads are one-time events. If you want some sort of recurring timer or reading/writing more than once you must reschedule your handler inside your handler.

Using _"void thread_cancel (struct thread \*thread);"_ you can remove any thread from the scheduler's list, and citing _thread.c_:

```C
/* Delete all events which has argument value arg. */
void thread_cancel_event (struct thread_master *m, void *arg);
```

## Talking to Zebra

You will want your protocol daemon to communicate with the main zebra daemon. It will tell you about interfaces and routes, allowing you to know which interfaces exist and their configuration and which routes are installed and by whom (ospf,bgp,static,...).

The _zclient.h_ library declares the API, interesting are the main structure for talking to the main daemon:

```C
/* Structure for the zebra client. */
struct zclient
{
...

  /* Flag of communication to zebra is enabled or not.  Default is on.
     This flag is disabled by `no router zebra' statement. */
  int enable;
...
  /* Pointer to the callback functions. */
  int (*interface_add) (int, struct zclient *, zebra_size_t);
  int (*interface_delete) (int, struct zclient *, zebra_size_t);
  int (*interface_up) (int, struct zclient *, zebra_size_t);
  int (*interface_down) (int, struct zclient *, zebra_size_t);
  int (*interface_address_add) (int, struct zclient *, zebra_size_t);
  int (*interface_address_delete) (int, struct zclient *, zebra_size_t);
  int (*ipv4_route_add) (int, struct zclient *, zebra_size_t);
  int (*ipv4_route_delete) (int, struct zclient *, zebra_size_t);
  int (*ipv6_route_add) (int, struct zclient *, zebra_size_t);
  int (*ipv6_route_delete) (int, struct zclient *, zebra_size_t);
};
```

and the many function prototypes, which will be described as they are used.

So, for a starter, let's create a new file, _zap_zebra.c_

```C
/*----------------------------------------
 *  zap_zebra.c
 */

/* might as well be defined here and exported over zap_zebra.h
 * as it could be needed somewhere else
 */
extern struct zclient* zclient;


void zap_zebra_init(void) {
  int i;

  zclient = zclient_new ();
  zclient_init (zclient, ZEBRA_ROUTE_ZAP);
/* create such a struct, and initialize it,
 * thus making it ready to connect when the threads are started
 * ZEBRA_ROUTE_ZAP is the type of routes you are not interested in.
 * It is defined in zebra.h and you will have to extend it, e.g. :

 #define ZEBRA_ROUTE_BGP                  8
 #define ZEBRA_ROUTE_ZAP                  9
 #define ZEBRA_ROUTE_MAX                  10
```

And edit _/frr/zebra/rib.c_ too, in at least two places as well as functions *command_exit* and *command_end* in _/frr/lib/command.c_ file.

**FIXME** is this true: ROUTE_MAX seems to have some magic semantics, it seems to be some sort of default route placeholder even though the defaults fields exist.

```C
/* set the routes we want to get from zebra, in this case:
 * tell me all routes but my own
 */
 for(i=0; i++ < ZEBRA_ROUTE_MAX;)
  if( i != ZEBRA_ROUTE_ZAP)
    zclient_redistribute_set (zclient, i);

/* fill in the callbacks */
  zclient->interface_add = zap_interface_add;
  zclient->interface_delete = zap_interface_delete;
  zclient->interface_up = zap_interface_state_up;
  zclient->interface_down = zap_interface_state_down;
  zclient->interface_address_add = zap_interface_address_add;
  zclient->interface_address_delete = zap_interface_address_delete;
  zclient->ipv4_route_add = zap_zebra_route_manage;
  zclient->ipv4_route_delete = zap_zebra_route_manage;

 /* Install zebra node. **FIXME** is this needed?*/
 install_node (&zebra_node, zebra_config_write);
}
```

Now, your functions (declared and defined elsewhere) will be called whenever such an event happens. You might want to define some dummy functions, which just print the arguments.

Now you might want to get information about the interfaces on the system, just add the following functions to the start of _zap_zebra.c_ and you will get a list of all interfaces active on the machine.

```C
/* Inteface addition message from zebra. */
int
zap_interface_add (int command, struct zclient *zclient, zebra_size_t length)
{
  struct interface *ifp;

/* now, is your duty to extract the interface information from
 * the serialized zebra protocol stream, this was just an event
 * indication. This will add the interface to the library's global
 * interface list, so you can search for it later on.
 */
  ifp = zebra_interface_add_read (zclient->ibuf);
  zlog_info ("Zebra: interface add %s index %d flags %d metric %d mtu %d",
	       ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);
  return 0;
}

int
zap_interface_delete (int command, struct zclient *zclient,
		       zebra_size_t length)
{
  struct interface *ifp;

/* again, it is your job to pluck the interface information off the stream
 */
  ifp = zebra_interface_state_read (zclient->ibuf);

  if (ifp == NULL)
    return 0;
  if (if_is_up (ifp))
      zlog_warn ("Zebra: got delete of %s, but interface is still up",
		 ifp->name);

  zlog_info ("Zebra: interface delete %s index %d flags %d metric %d mtu %d",
	       ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);

  if_delete(ifp);
  return 0;
}
```

Taking a look at _if.h_ you will see the following functions:

```C
int if_is_up (struct interface *);
int if_is_loopback (struct interface *);
int if_is_broadcast (struct interface *);
int if_is_pointopoint (struct interface *);
int if_is_multicast (struct interface *);
```

which are just flag testers, as used in the above example. Now for the up and down callbacks:

```C
int
zap_interface_state_up (int command, struct zclient *zclient,
			 zebra_size_t length)
{
  struct interface *ifp;
  struct interface if_tmp;
  u_int32_t old_cost;


/* searches for the interface by that name (the name specified
 * in the stream) in the existing interface list.
 */
  ifp = zebra_interface_state_read (zclient->ibuf);

  if (ifp == NULL)
    return 0;

  assert(if_is_up(ifp)); /* maybe untrue **FIXME** */
  zlog_info ("Zebra: Interface[%s] state change to up.", ifp->name);
  return 0;
}

int
zap_interface_state_down (int command, struct zclient *zclient,
			   zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_state_read (zclient->ibuf);
  if (ifp == NULL)
    return 0;
  zlog_info ("Zebra: Interface[%s] state change to down.", ifp->name);
  return 0;
}
```

There are two interface add event triggers:
  1. a real interface is announced via the zebra protocol
  1. the user types "interface foo" on the command line

For the second case, the only information about the interface is its name, and for the first one the whole struct interface might be relevant. This structure is also defined in _if.h_ :

```C
/* Interface structure */
struct interface
{
  /* Interface name. */
  char name[INTERFACE_NAMSIZ + 1];
/* INTERFACE_NAMSIZ is a #define, usually 20 (bytes) */
...
  /* Hardware address. */
#ifdef HAVE_SOCKADDR_DL
  struct sockaddr_dl sdl;
#else
  unsigned short hw_type;
  u_char hw_addr[INTERFACE_HWADDR_MAX];
  int hw_addr_len;
#endif /* HAVE_SOCKADDR_DL */
/* hw dependant hw address
 * INTERFACE_HWADDR_MAX is #defined to 20
 */
...
  /* Connected address list. */
  list connected;
/* This are the addresses on the interface, with masks */

  /* Daemon specific interface data pointer. */
  void *info;
/* This is for your convenience */
...};
```

A struct connected looks like this:

```C
/* Connected address structure. */
struct connected
{
  /* Attached interface. */
  struct interface *ifp;

  /* Flags for configuration. */
  u_char conf;
#define ZEBRA_IFC_REAL         (1 << 0)
#define ZEBRA_IFC_CONFIGURED   (1 << 1)

  /* Flags for connected address. */
  u_char flags;
#define ZEBRA_IFA_SECONDARY   (1 << 0)

  /* Address of connected network. */
  struct prefix *address;
  struct prefix *destination;

...};
```

thus you have access to the IP addresses of the interface. Now you are ready for the next callbacks:

```C
int
zap_interface_address_add (int command, struct zclient *zclient,
                            zebra_size_t length)
{
  struct connected *c;
  struct prefix *p;

/* read the address from the zebra protocol stream */
  c = zebra_interface_address_add_read (zclient->ibuf);
  if (c == NULL)
    return 0;
  p = c->address;
  if (p->family == AF_INET)
   zlog_info (" new connected IPv4 address %s/%d on interface %s",
                inet_ntoa (p->u.prefix4), p->prefixlen, c->ifp->name);
  else if(p->family == AF_INET6)
   zlog_info (" new connected IPv6 address on interface %s", c->ifp->name);
  return 0;
}

int
zap_interface_address_delete (int command, struct zclient *zclient,
			       zebra_size_t length)
{
  struct connected *c;

  c = zebra_interface_address_delete_read (zclient->ibuf);
  if (c == NULL)
    return 0;
/* you might want to print something over here */

  connected_free (c);
/* what you must do, is free the connected struct, which was implicitely
 * created in the zebra_interface_address_delete_read call
 */
  return 0;
}
```

And now, the only callbacks left to fill in, are the route callbacks.

**FIXME** I am not so sure about this part.

Apparently, there is no function in the library to do the deserialization of the zebra protocol stream, so you have to do it by hand:

```C
void zclient_read_zapi_ipv4( struct zclient* zclient,
 struct zapi_ipv4 *zapi, struct prefix_ipv4* p,
 unsigned long* ifindex,  struct in_addr* nexthop)
{
  struct stream *s;


  s = zclient->ibuf;

/* read the header */
  zapi->type = stream_getc (s);
  zapi->flags = stream_getc (s);
  zapi->message = stream_getc (s);

/* and the prefix */
  memset (p, 0, sizeof (struct prefix_ipv4));
  p->family = AF_INET;
  p->prefixlen = stream_getc (s);
  stream_get (&p->prefix, s, PSIZE (p->prefixlen));

  if (CHECK_FLAG (zapi->message, ZAPI_MESSAGE_NEXTHOP))
    {
      zapi->nexthop_num = stream_getc (s);
      nexthop->s_addr = stream_get_ipv4 (s);
    }
  if (CHECK_FLAG (zapi->message, ZAPI_MESSAGE_IFINDEX))
    {
      zapi->ifindex_num = stream_getc (s);
      *ifindex = stream_getl (s);
    }
  if (CHECK_FLAG (zapi->message, ZAPI_MESSAGE_DISTANCE))
    zapi->distance = stream_getc (s);
  if (CHECK_FLAG (zapi->message, ZAPI_MESSAGE_METRIC))
    zapi->metric = stream_getl (s);

}
```

and then just call it from the unified routed add/del manager:

```C
int zap_zebra_route_manage (int command, struct zclient *zclient,
                            zebra_size_t length) {

  struct prefix_ipv4 p;
  struct zapi_ipv4 zapi;
  unsigned long ifindex;
  struct in_addr nexthop;

  zclient_read_zapi_ipv4( zclient, &zapi, &p,&ifindex,&nexthop);

  if (command == ZEBRA_IPV4_ROUTE_ADD) {
   zlog_info (" new IPv4 route %s/%d on interface ifindex %d",
                inet_atop (p->u.prefix4), p->prefixlen, ifindex);

  } else { /* ZEBRA_IPV4_ROUTE_DELETE */

  }
  return 0;
}
```

And to end this chapter, let us take a look at the API for setting and deleting routes:

```C
/* Zebra API message flag. */
#define ZAPI_MESSAGE_NEXTHOP  0x01
#define ZAPI_MESSAGE_IFINDEX  0x02
#define ZAPI_MESSAGE_DISTANCE 0x04
#define ZAPI_MESSAGE_METRIC   0x08

/* Zebra IPv4 route message API. */
struct zapi_ipv4
{
  u_char type;
  u_char flags;
  u_char message;
  u_char nexthop_num;
  struct in_addr **nexthop;
  u_char ifindex_num;
  unsigned int *ifindex;
  u_char distance;
  u_int32_t metric;
};

int
zapi_ipv4_add (struct zclient *, struct prefix_ipv4 *, struct zapi_ipv4 *);

int
zapi_ipv4_delete (struct zclient *, struct prefix_ipv4 *, struct zapi_ipv4 *);

 Usage example:

struct zapi_ipv4 zr;

zr.type = ZEBRA_ROUTE_ZAP;
zr.flags = 0;
SET_FLAG (zr->message, ZAPI_MESSAGE_NEXTHOP);
SET_FLAG (zr->message, ZAPI_MESSAGE_METRIC);
zr.nexthop_num = 1;
zr.nexthop = &some_nexthop;
zr.metric = 111;
zapi_ipv4_add(&zc, &the_prefix, &zr);
```

This will set a route of type ZAP to the destination prefix the_prefix with nexthop some_nexthop and metric 111. Interface routes are supported.

**FIXME** is this right? can a daemon set an interface route without a nexthop? The code suggests only ZAPI_MESSAGE_NEXTHOP is checked and then nexthops and ifindices are sent.

You can combine a number of nexthop/ifindex to install an equal weight load balancing route, if the underlying OS supports it.

## Defining Commands

You know the cisco interface, which changes the available commands depending on the configuration mode you are. These configuration modes are called nodes in the implementation. All defines and functions are in _lib/command.h_ file. The available nodes are defined in the _enum node_type_, which looks like this:

```C
/* There are some command levels which called from command node. */
enum node_type
{
  AUTH_NODE,			/* Authentication mode of vty interface. */
  VIEW_NODE,			/* View node. Default mode of vty interface. */
...
  ENABLE_NODE,			/* Enable node. */
  CONFIG_NODE,			/* Config node. Default mode of config file. */
...
  INTERFACE_NODE,		/* Interface mode node. */
...
  RIP_NODE,			/* RIP protocol mode node. */
...
  ACCESS_NODE,			/* Access list node. */
  PREFIX_NODE,			/* Prefix list node. */
...
  VTY_NODE			/* Vty node. */
};
```

As you will want a router-zap node, you will have to extend the enum to include ZAP_NODE. ZAP has some per interface configuration options, but the interface node for the per-interface configuration mode is not installed per default. The following code installs both the interface and the zap node.

```C
#include <stdarg.h>
#include <zebra.h>
#include "command.h"

int zap_interface_config_write (struct vty *vty);
int zap_router_config_write (struct vty *vty);
/* I'll come to this later
 */

/* zapd's interface node. */
struct cmd_node zap_interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
  1 /* vtysh ? yes */
};

/* zapd's router node. */
struct cmd_node zap_router_node =
{
  ZAP_NODE,
  "%s(config-router)# ",
  1 /* vtysh ? yes */
};

void zap_cmd_init(void) {
 if_init();

/* Install interface nodes. */
  install_node (&zap_interface_node, zap_interface_config_write);
  install_element (CONFIG_NODE, &interface_cmd); /* from if.h */
  install_default (INTERFACE_NODE);
  install_element (INTERFACE_NODE, &interface_desc_cmd); /* from if.h */
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);

/* Install router nodes. */
  install_node (&zap_router_node, zap_router_config_write);
/* add the default commands, like exit(!) */
  install_default(ZAP_NODE);
}
```

This code just made possible to define commands for the router zap configuration mode. There is, of course, no way to reach the node, at the moment. So you will have to define
a command to change into ZAP configuration mode. So, let's start:

```C
extern zap_instance_t zap_global;

DEFUN (router_zap,
       router_zap_cmd,
       "router zap",
       "Enable a routing process\n"
       "Enter ZAP configuration mode\n")
{
  vty->node = ZAP_NODE;
  vty->index = zap_global;
  return CMD_SUCCESS;
}
```

and later on:

```C
 install_element (CONFIG_NODE, &router_zap_cmd);
```

The _**DEFUN**_ macro defines a command, first parameter is function name, second parameter is a name for a struct, 3rd is the whole command (some control parameters are allowed), and the fourth parameter is a help string, containing as many _\n_ separated help lines as arguments has the command.

With *install_element* you register the command at the main configuration node (after *conf XXX*).

Suppose you are using a german keyboard, which switches the y and z keys, so you want to add a command *"router yap"*, which does the same as router_zap (calls the same function). Then, just add the following lines.

```C
ALIAS (router_zap,
       router_yap_cmd,
       "router yap",
       "Enable a routing process\n"
       "Enter ZAP configuration mode\n")
```

Just make sure the first parameter is the same as the one in the *DEFUN* macro and the second isn't. To register this command, we reference the struct again:

```C
 install_element (CONFIG_NODE, &router_yap_cmd);
```

Now, whenever the user types *"router zap"* or *"router yap"*, the same function is called. The function, called *router_zap* in this example, has the signature:

```C
 f(struct cmd_element *self, struct vty *vty, int argc, char **argv)
```

So, whenever your commands are called, you have a struct vty to print information to, a reference to the command struct and the usual argc/argv combo (which, for this example will be 0,GARBAGE).

Getting back to our example, the router_zap function modifies the struct vty, setting the node to ZAP_NODE, so only commands defined in that node are available, and setting the index to point to zap_global.

The index allows you to have a per node private void\*. This could be useful when expanding router zap to run with multiple instances, allowing a single lookup of the relevant information on the *"router yap XX"* command, so you won't have to find the relevant data struct on every call to a *ZAP\_NODE* command. A quick _zap_instance_t zi= (zap_instance_t) vty->index;_ will be enough (assuming zap_instance_t is some kind of pointer).

A quick look at command.[ch] suggest a special meaning for certain formats in the command line in DEFUN. This helps the parsing routines, so you don't have to start playing with all those horrible str* functions. A (**FIXME** partial?) list follows:

```C
"A.B.C.D"    IPV4
"A.B.C.D/M"   IPV4_PREFIX
"X:X::X:X"   IPV6
"X:X::X:X/M"  IPV6_PREFIX
```

Words starting with a capital letter are variables, those are put in argv. For example:

```C
DEFUN (...,
    "router zap AS",
    STR_ROUTER
    STR_ZAP
    "Autonomous System number for this routing process\n")
```
will give you the user input in arg[0].

For some variables only range of values make sense. This is represented with the "<" symbol, the above example would now be: _"router zap <1-65535>"_.

Optional arguments are between square brackets. For ZAP the default AS number is 1, so instead of defining and registering two commands ("router zap" and "router zap AS") you could just define it as:

```C
DEFUN(..., "router zap [AS]", ...) {
 unsigned long int as = argc == 0 ? 1 : strtoul(argv[0]);
 if ( (as == 0) || (as & ! 0xFFFF) ) {
  vty_out(vty, "Invalid AS number %d%s", as, VTY_NEWLINE);
  return CMD_WARNING;
 }
/* switch to ROUTER_ZAP node */
}
```

**FIXME** nesting of meta characters: can I define "router zap[<1-65535>]" ?

For inputs requiring a variable word number you use "." to signal a vararg input. ZAP requires a passphrase for authentication, so you could add a "zap passphrase .PASSPHRASE" command to the inferface node.

**FIXME** argc == 1 or argc == number of words?

## Using access lists

Access list functions are defined in _filter.h_. Once you have initialised the subsystem with _access_list_init()_ function, the user has the following commands available:

```
 access-list WORD (deny|permit) (A.B.C.D/M|any)
 access-list WORD (deny|permit) A.B.C.D/M (exact-match|)
 no access-list WORD (deny|permit) (A.B.C.D/M|any)
 no access-list WORD (deny|permit) A.B.C.D/M (exact-match|)
 no access-list WORD
 access-list WORD remark .LINE
 no access-list WORD remark
 no access-list WORD remark .LINE
```

If ipv6 support is configured another set of commands for ipv6 access lists is created.

You have the following functions available (from filter.h):

```C
void access_list_reset (void);
void access_list_add_hook (void (*func)(struct access_list *));
void access_list_delete_hook (void (*func)(struct access_list *));
struct access_list *access_list_lookup (int, char *);
enum filter_type access_list_apply (struct access_list *, void *);
```
 * **access_list_reset** just removes all access-lists.
 * **access_list_[add|delete]_hook** citing filter.c:
   * "Hook function which is executed when new access_list is added."
   * "Hook function which is executed when access_list is deleted."
 * **access_list_lookup**: first parameter is AF_INET or AF_INET6, second is the name of the list, e.g. "101".
 * **access_list_apply** citing filter.c:
   * "Apply access list to object (which should be struct prefix *)"
   * enum filter_type is {FILTER_DENY, FILTER_PERMIT, FILTER_DYNAMIC}
   * non-existant or empty lists return DENY.

## Using prefix lists

Prefix list functions are defined in *plist.h*. Just a quick glance over *plist.h* shows the following interesting information:

```C
enum prefix_list_type { PREFIX_DENY, PREFIX_PERMIT };
enum prefix_name_type { PREFIX_TYPE_STRING, PREFIX_TYPE_NUMBER};

/* Prototypes. */
void prefix_list_reset (void);
void prefix_list_add_hook (void (*func) (void));
void prefix_list_delete_hook (void (*func) (void));
struct prefix_list *prefix_list_lookup (int family, char *);
enum prefix_list_type prefix_list_apply (struct prefix_list *, void *);
```

The prototypes look like the access-list API ones, read it there. The structure prefix has the following layout:

```C
/* IPv4 and IPv6 unified prefix structure. */
struct prefix
{
  u_char family;
  u_char safi;
  u_char prefixlen;
  u_char padding;
  union
  {
    u_char prefix;
    struct in_addr prefix4;
#ifdef HAVE_IPV6
    struct in6_addr prefix6;
#endif /* HAVE_IPV6 */
    struct
    {
      struct in_addr id;
      struct in_addr adv_router;
    } lp;
    u_char val[8];
  } u;
};
```

For *access_list_apply* and *prefix_list_apply*, you only need to fill in the _prefixlen_ and _u_, though it might be useful to fill in the _family_ and _safi_ fields, depending on compilation time configuration.

**FIXME** I'm not so sure about this last paragraph, are afi and safi needed?

## Routing tables

**FIXME** This chapter need to be reviewed

You might want to store the routes you get from zebra on a radix tree, for fast retrieval. The library offers such a service, just include _table.h_.

A little peek at the .h file shows two structures: *route_table* and *route_node*:

```C
struct route_table {  struct route_node *top; };

struct route_node {
  /* Actual prefix of this radix. */
  struct prefix p;

  /* Tree link. */
/* radix tree, 1 bit per depth, max 32 lookups for IPv4
 */

  /* Lock of this radix */
  unsigned int lock;

  /* Each node of route. */
  void *info;
/* info is yours to use */

  /* Aggregation. */
  void *aggregate;
/* doesn't seem to be used much
 **FIXME** What is this for? can it be used by the daemon? table.c doesn't touch it at all
 or any file in /frr/zebra/ for that matter. */
};
```

A mix of usage example and function list follows:

```C
/* zap_rib_example.c */

#include "table.h"

struct route_table table1;
struct route_node entry;
struct prefix dst;
struct zap_per_route_t route_info;
/* [...] */

/* create a new table */
table1  = route_table_init();

/* Quoting: "Add node to routing table."
 * more detailed: if dst matches an entry exactly, return that entry,
 * otherwise create it;
 * The reference counter is set to 1 (**FIXME** sure? )
*/
entry = route_node_get (table1, dst);

/* store our per route info, if none exists yet*/
if (entry->info != NULL )
  entry->info = route_info;

/* decrements reference counter and frees the node if it is 0 */
void route_unlock_node (struct route_node *node);

/* (node->info == NULL && node->lock == 0) must hold for calling this */
void route_node_delete (struct route_node *node);

/* Quoting:
 * Get fist node and lock it.  This function is useful when one wants
 *   to lookup all the nodes in the routing table.
 */
struct route_node *route_top (struct route_table *);

/* Quoting:
 * Unlock current node and lock next node then return it.
 */
struct route_node *route_next (struct route_node *);

/* Quoting:
 *  Unlock current node and lock next node until limit.
 */
struct route_node *route_next_until (struct route_node *, struct route_node *);

/* Quoting:
 * Add node to routing table. */
struct route_node *route_node_get (struct route_table *, struct prefix *);

/* exact match or NULL */
struct route_node *route_node_lookup (struct route_table *, struct prefix *);

/* increments the reference counter */
entry = route_lock_node (entry);

/* walks down the radix tree and returns the longest matching route */
struct route_node *route_node_match (struct route_table *, struct prefix *);

/* creates a struct prefix from in_addr and calls route_node_match */
struct route_node *route_node_match_ipv4 (struct route_table *,
					  struct in_addr *);

/* Free the table and its contents */
route_table_finish(table1);
```

## Hash tables

**FIXME** Need to be rewrite to be conform to the new set of hash_XXX() functions.

You know the drill. BUGLET:
  1. hash_push:hash.c count++ but not --
  1. hash_clean:hash.c missing count=0

The hash.h suggests it could be possible to have hash with different table sizes. But hash.c, specifically hash_clean, works with a fixed size of HASHTABSIZE.

```C
/* for Hash tables */
#define HASHTABSIZE     2048

typedef struct HashBacket
{
  void *data;
  struct HashBacket *next;
} HashBacket;

struct Hash
{
  /* Hash backet. */
  HashBacket **index;

  /* Hash size. */
  int size;

  /* Key make function. */
  unsigned int (*hash_key)();
/* in fact, unsigned int (*hash_key)(void* )
 */

  /* Data compare function. */
  int (*hash_cmp)();
/* in fact, unsigned int (*hash_cmp)(void*, void* )
 * returns 1 if equal. (not !0, but == 1)
 */

  /* Backet alloc. */
  unsigned long count;
};

 For each void* p,q with hash_key(p) == hash_key(q),
 hash_cmp(p,q) != 1 must hold.

/* hash instance ctor & dtor */
struct Hash *hash_new (int size);
void hash_free (struct Hash *hash);
/* remember to set the 2 functions in the Hash struct, e.g.
unsigned int my_hash_key_gen(zap_some_data* e)
{  return e %HASHTABSIZE; /* simplest hash function */ }
int my_hash_cmp(zap_some_data* p, zap_some_data* q)
{ return p->whatever == q->whatever ? 1 : 0; }

h = hash_new(HASHTABSIZE);
h->hash_key = my_hash_key_gen;
h->hash_cmp = my_hash_cmp;
 */

/* returns the first hash bucket of the hash bucket linked list
 * for key int (0 <= key < HASHTABSIZE)
*/
HashBacket *hash_head (struct Hash *, int);
/* usage example:
  HashBacket* t; int i;
for( i=0; i < HASHTABSIZE; i++)
  for (t=hash_head(my_hash,i); t != NULL, t = t->next)
           do_something(t->data);
*/

/* insert the data in the hash */
HashBacket *hash_push (struct Hash *, void *);

/* returns the bucket data portion or NULL
 * and removes the hash entry */
void *hash_pull (struct Hash *, void *);

/* returns the bucket data portion or NULL */
void *hash_search (struct Hash *, void *);

/* Deletes all entries from the hash (but not the hash itself)
 * calls func on each node's data (if func !=  NULL)
void hash_clean (struct Hash *hash, void (* func) (void *));
```

## Network portability and utility library

I assume you are already familiar with the usual socket framework (sockopt.h, sockunion.h, network.h). A short description of the available API follows.

First sockopt.h:

I can say it better than the code:

>   Set up a multicast socket options for IPv4
>   This is here so that people only have to do their OS multicast mess
>   in one place rather than all through zebra, ospfd, and ripd

```C
sockopt.h, sockunion.h, network.h
int
setsockopt_multicast_ipv4(int sock,
			int optname,
			struct in_addr if_addr,
			unsigned int mcast_addr,
			unsigned int ifindex);
```

optname is one of IP_MULTICAST_IF, IP_ADD_MEMBERSHIP or IP_DROP_MEMBERSHIP.

And the IPv6 sockopts, which I won't describe here. And then sockunion.h, which defines a socket interface, which should be portable.

Starting with 2 simple types:

```C
union sockunion
{
  struct sockaddr sa;
  struct sockaddr_in sin;
#ifdef HAVE_IPV6
  struct sockaddr_in6 sin6;
#endif /* HAVE_IPV6 */
};

enum connect_result {
 connect_error,  connect_success, connect_in_progress
};
```

some macros, e.g.:

```C
#define sock2ip(X)   (((struct sockaddr_in *)(X))->sin_addr.s_addr)
#define sock2ip6(X)  (((struct sockaddr_in6 *)(X))->sin6_addr.s6_addr)
#define sockunion_family(X)  (X)->sa.sa_family
```

and many functions:

```C
/* Prototypes. */

/* sockunion is already allocated, parse str into it, 0 if no prob */
int str2sockunion (char *, union sockunion *);

/*  print the sockunion param1 in buffer param2 of size param3 */
const char *sockunion2str (union sockunion *, char *, size_t);

/* 1,0,-1 for param1 >,==,< param2*/
int sockunion_cmp (union sockunion *, union sockunion *);

/* Quote: "If same family and same prefix return 1." */
int sockunion_same (union sockunion *, union sockunion *);

/* returns pointer to newly allocated buffer with the sockunion
printed into in. remember to free the buffer **FIXME** man strdup */
char *sockunion_su2str (union sockunion *su);

/* create a sockunion from a str, allocates it.
 returns NULL if not possible. */
union sockunion *sockunion_str2su (char *str);

/* **FIXME** seems to be a zombie prototype in sockunion.h */
struct in_addr sockunion_get_in_addr (union sockunion *su);

/* accepts on sock, returns new client in sockunion */
int sockunion_accept (int sock, union sockunion *);

/* makes stream socket of the family specified in sockunion.
 If no family is specified, it is ipv6 unless ipv6 is not
 compiled in, in that case, it is ipv4 */
int sockunion_stream_socket (union sockunion *);

/* bind to addr param4, port param3 (port in host byte order)
 returns the socket or <0
  if param4 is NULL, use INADDR_ANY (or ipv6 equivalent) ,
  param2 must not be NULL and will hold the address the socket was bound
  to */
int sockunion_bind (int sock, union sockunion *, unsigned short, union sockunion *);

/* 0 if no problems */
int sockopt_reuseaddr (int);
int sockopt_reuseport (int);
int sockopt_ttl (int family, int sock, int ttl);

/* returns STREAM socket of sockunion type specified in su,
 or error (<0)*/
int sockunion_socket (union sockunion *su);

const char *inet_sutop (union sockunion *su, char *str);

/* returns pointer to *static* buffer where su is printed */
char *sockunion_log (union sockunion *su);

/* fd is socket number, su is the target,  port is in network byte order,
     last param is ifindex for ipv6 linklocal addresses  */
enum connect_result
 sockunion_connect (int fd, union sockunion *su, unsigned short port, unsigned int);

/* Quoting:
  "After TCP connection is established.  Get local address and port."
 or NULL */
union sockunion *sockunion_getsockname (int);

/* Quoting
"After TCP connection is established.  Get remote address and port. "
 or NULL */
union sockunion *sockunion_getpeername (int);

/* print addrptr in len length strptr buffer,
 return NULL or strptr */
const char *inet_ntop (int family, const void *addrptr, char *strptr, size_t len);

/* put strptr in addrptr (which is a struct in_addr*),
 return 1 if ok */
int inet_pton (int family, const char *strptr, void *addrptr);

/* put cp in inaddr (network byteorder)
 return 1 if ok , 0 if problem */
int inet_aton (const char *cp, struct in_addr *inaddr);
```

And last network.h

```C
int readn (int, char *, int);
int writen (int, char *, int);
```

This is for the known case, where write(2) and read(2) return the number of bytes written/read, which need not be the number of bytes requested, and which doesn't necessarily imply an error.

  * readn returns 0 if all data was read, otherwise, if an error ocurred, the return value of read(2) is returned (<0). If the connection was closed, the number of bytes sent is returned.
  * writen returns 0 if all data was sent, the error return value (<0) otherwise.
