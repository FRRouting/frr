Developer's Guide to Logging
============================

One of the most frequent decisions to make while writing code for FRR is what
to log, what level to log it at, and when to log it.  Here is a list of
recommendations for these decisions.


Errors and warnings
-------------------

If it is something that the user will want to look at and maybe do
something, it is either an **error** or a **warning**.

We're expecting that warnings and errors are in some way visible to the
user (in the worst case by looking at the log after the network broke, but
maybe by a syslog collector from all routers.)  Therefore, anything that
needs to get the user in the loop—and only these things—are warnings or
errors.

Note that this doesn't neccessarily mean the user needs to fix something in
the FRR instance.  It also includes when we detect something else needs
fixing, for example another router, the system we're running on, or the
configuration.  The common point is that the user should probably do
*something*.

Deciding between a warning and an error is slightly less obvious; the rule
of thumb here is that an error will cause considerable fallout beyond its
direct effect.  Closing a BGP session due to a malformed update is an error
since all routes from the peer are dropped; discarding one route because
its attributes don't make sense is a warning.

This also loosely corresponds to the kind of reaction we're expecting from
the user.  An error is likely to need immediate response while a warning
might be snoozed for a bit and addressed as part of general maintenance.
If a problem will self-repair (e.g. by retransmits), it should be a
warning—unless the impact until that self-repair is very harsh.

Examples for warnings:

* a BGP update, LSA or LSP could not be processed, but operation is
  proceeding and the broken pieces are likely to self-fix later
* some kind of controller cannot be reached, but we can work without it
* another router is using some unknown or unsupported capability

Examples for errors:

* dropping a BGP session due to malformed data
* a socket for routing protocol operation cannot be opened
* desynchronization from network state because something went wrong
* *everything that we as developers would really like to be notified about,
  i.e. some assumption in the code isn't holding up*


Informational messages
----------------------

Anything that provides introspection to the user during normal operation
is an **info** message.

This includes all kinds of operational state transitions and events,
especially if they might be interesting to the user during the course of
figuring out a warning or an error.

By itself, these messages should mostly be statements of fact.  They might
indicate the order and relationship in which things happened.  Also covered
are conditions that might be "operational issues" like a link failure due
to an unplugged cable.  If it's pretty much the point of running a routing
daemon for, it's not a warning or an error, just business as usual.

The user should be able to see the state of these bits from operational
state output, i.e. `show interface` or `show foobar neighbors`.  The log
message indicating the change may have been printed weeks ago, but the
state can always be viewed.  (If some state change has an info message but
no "show" command, maybe that command needs to be added.)

Examples:

* all kinds of up/down state changes

  * interface coming up or going down
  * addresses being added or deleted
  * peers and neighbors coming up or going down

* rejection of some routes due to user-configured route maps
* backwards compatibility handling because another system on the network
  has a different or smaller feature set

.. note::
   The previously used **notify** priority is replaced with *info* in all
   cases.  We don't currently have a well-defined use case for it.


Debug messages and asserts
--------------------------

Everything that is only interesting on-demand, or only while developing,
is a **debug** message.  It might be interesting to the user for a
particularly evasive issue, but in general these are details that an
average user might not even be able to make sense of.

Most (or all?) debug messages should be behind a `debug foobar` category
switch that controls which subset of these messages is currently
interesting and thus printed.  If a debug message doesn't have such a
guard, there should be a good explanation as to why.

Conversely, debug messages are the only thing that should be guarded by
these switches.  Neither info nor warning or error messages should be
hidden in this way.

**Asserts** should only be used as pretty crashes.  We are expecting that
asserts remain enabled in production builds, but please try to not use
asserts in a way that would cause a security problem if the assert wasn't
there (i.e. don't use them for length checks.)

The purpose of asserts is mainly to help development and bug hunting.  If
the daemon crashes, then having some more information is nice, and the
assert can provide crucial hints that cut down on the time needed to track
an issue.  That said, if the issue can be reasonably handled and/or isn't
going to crash the daemon, it shouldn't be an assert.

For anything else where internal constraints are violated but we're not
breaking due to it, it's an error instead (not a debug.)  These require
"user action" of notifying the developers.

Examples:

* mismatched :code:`prev`/:code:`next` pointers in lists
* some field that is absolutely needed is :code:`NULL`
* any other kind of data structure corruption that will cause the daemon
  to crash sooner or later, one way or another
