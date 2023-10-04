Auto-generated CLI commands
~~~~~~~~~~~~~~~~~~~~~~~~~~~

In order to have less code to maintain, it should be possible to write a
tool that auto-generates CLI commands based on the FRR YANG models. As a
matter of fact, there are already a number of NETCONF-based CLIs that do
exactly that (e.g. `Clixon <https://github.com/clicon/clixon>`__,
ConfD’s CLI).

The problem however is that there isn’t an exact one-to-one mapping
between the existing CLI commands and the corresponding YANG nodes from
the native models. As an example, ripd’s
``timers basic (5-2147483647) (5-2147483647) (5-2147483647)`` command
changes three YANG leaves at the same time. In order to auto-generate
CLI commands and retain their original form, it’s necessary to add
annotations in the YANG modules to specify how the commands should look
like. Without YANG annotations, the CLI auto-generator will generate a
command for each YANG leaf, (leaf-)list and presence-container. The
ripd’s ``timers basic`` command, for instance, would become three
different commands, which would be undesirable.

   This Tail-f’s®
   `document <http://info.tail-f.com/hubfs/Whitepapers/Tail-f_ConfD-CLI__Cfg_Mode_App_Note_Rev%20C.pdf>`__
   shows how to customize ConfD auto-generated CLI commands using YANG
   annotations.

The good news is that *libyang* allows users to create plugins to
implement their own YANG extensions, which can be used to implement CLI
annotations. If done properly, a CLI generator can save FRR developers
from writing and maintaining hundreds if not thousands of DEFPYs!

CLI on a separate program
~~~~~~~~~~~~~~~~~~~~~~~~~

The flexible design of the northbound architecture opens the door to
move the CLI to a separate program in the long-term future. Some
advantages of doing so would be: \* Treat the CLI as just another
northbound client, instead of having CLI commands embedded in the
binaries of all FRR daemons. \* Improved robustness: bugs in CLI
commands (e.g. null-pointer dereferences) or in the CLI code itself
wouldn’t affect the FRR daemons. \* Foster innovation by allowing other
CLI programs to be implemented, possibly using higher level programming
languages.

The problem, however, is that the northbound retrofitting process will
convert only the CLI configuration commands and EXEC commands in a first
moment. Retrofitting the “show” commands is a completely different story
and shouldn’t happen anytime soon. This should hinder progress towards
moving the CLI to a separate program.

Proposed feature: confirmed commits
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Confirmed commits allow the user to request an automatic rollback to the
previous configuration if the commit operation is not confirmed within a
number of minutes. This is particularly useful when the user is
accessing the CLI through the network (e.g. using SSH) and any
configuration change might cause an unexpected loss of connectivity
between the user and the router (e.g. misconfiguration of a routing
protocol). By using a confirmed commit, the user can rest assured the
connectivity will be restored after the given timeout expires, avoiding
the need to access the router physically to fix the problem.

Example of how this feature could be provided in the CLI:
``commit confirmed [minutes <1-60>]``. The ability to do confirmed
commits should also be exposed in the northbound API so that the
northbound plugins can also take advantage of it (in the case of the
Sysrepo and ConfD plugins, confirmed commits are implemented externally
in the *netopeer2-server* and *confd* daemons, respectively).

Proposed feature: enable/disable configuration commands/sections
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Since the ``lyd_node`` data structure from *libyang* can hold private
data, it should be possible to mark configuration commands or sections
as active or inactive. This would allow CLI users to leverage this
feature to disable parts of the running configuration without actually
removing the associated commands, and then re-enable the disabled
configuration commands or sections later when necessary. Example:

::

   ripd(config)# show configuration running
   Configuration:
   [snip]
   !
   router rip
    default-metric 2
    distance 80
    network eth0
    network eth1
   !
   end
   ripd(config)# disable router rip
   ripd(config)# commit
   % Configuration committed successfully (Transaction ID #7).

   ripd(config)# show configuration running
   Configuration:
   [snip]
   !
   !router rip
    !default-metric 2
    !distance 80
    !network eth0
    !network eth1
   !
   end
   ripd(config)# enable router rip
   ripd(config)# commit
   % Configuration committed successfully (Transaction ID #8).

   ripd(config)# show configuration running
   [snip]
   frr defaults traditional
   !
   router rip
    default-metric 2
    distance 80
    network eth0
    network eth1
   !
   end

This capability could be useful in a number of occasions, like disabling
configuration commands that are no longer necessary (e.g. ACLs) but that
might be necessary at a later point in the future. Other example is
allowing users to disable a configuration section for testing purposes,
and then re-enable it easily without needing to copy and paste any
command.

Configuration reloads
~~~~~~~~~~~~~~~~~~~~~

Given the limitations of the previous northbound architecture, the FRR
daemons didn’t have the ability to reload their configuration files by
themselves. The SIGHUP handler of most daemons would only re-read the
configuration file and merge it into the running configuration. In most
cases, however, what is desired is to replace the running configuration
by the updated configuration file. The *frr-reload.py* script was
written to work around this problem and it does it well to a certain
extent. The problem with the *frr-reload.py* script is that it’s full of
special cases here and there, which makes it fragile and unreliable.
Maintaining the script is also an additional burden for FRR developers,
few of whom are familiar with its code or know when it needs to be
updated to account for a new feature.

In the new northbound architecture, reloading the configuration file can
be easily implemented using a configuration transaction. Once the FRR
northbound retrofitting process is complete, all daemons should have the
ability to reload their configuration files upon receiving the SIGHUP
signal, or when the ``configuration load [...] replace`` command is
used. Once that point is reached, the *frr-reload.py* script will no
longer be necessary and should be removed from the FRR repository.

Configuration changes coming from the kernel
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This
`post <http://discuss.tail-f.com/t/who-should-not-set-configuration-once-a-system-is-up-and-running/111>`__
from the Tail-f’s® forum describes the problem of letting systems
configure themselves behind the users back. Here are some selected
snippets from it: > Traditionally, northbound interface users are the
ones in charge of providing configuration data for systems. > > In some
systems, we see a deviation from this traditional practice; allowing
systems to configure “themselves” behind the scenes (or behind the users
back). > > While there might be a business case for such a practice,
this kind of configuration remains “dangerous” from northbound users
perspective and makes systems hard to predict and even harder to debug.
(…) > > With the advent of transactional Network configuration, this
practice can not work anymore. The fact that systems are given the right
to change configuration is a key here in breaking transactional
configuration in a Network.

FRR is immune to some of the problems described in the aforementioned
post. Management clients can configure interfaces that don’t yet exist,
and once an interface is deleted from the kernel, its configuration is
retained in FRR.

There are however some cases where information learned from the kernel
(e.g. using netlink) can affect the running configuration of all FRR
daemons. Examples: interface rename events, VRF rename events, interface
being moved to a different VRF, etc. In these cases, since these events
can’t be ignored, the best we can do is to send YANG notifications to
the management clients to inform about the configuration changes. The
management clients should then be prepared to handle such notifications
and react accordingly.

Interfaces and VRFs
~~~~~~~~~~~~~~~~~~~

As of now zebra doesn’t have the ability to create VRFs or virtual
interfaces in the kernel. The ``vrf`` and ``interface`` commands only
create pre-provisioned VRFs and interfaces that are only activated when
the corresponding information is learned from the kernel. When
configuring FRR using an external management client, like a NETCONF
client, it might be desirable to actually create functional VRFs and
virtual interfaces (e.g. VLAN subinterfaces, bridges, etc) that are
installed in the kernel using OS-specific APIs (e.g. netlink, routing
socket, etc). Work needs to be done in this area to make this possible.

Shared configuration objects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

One of the existing problems in FRR is that it’s hard to ensure that all
daemons are in sync with respect to the shared configuration objects
(e.g. interfaces, VRFs, route-maps, ACLs, etc). When a route-map is
configured using *vtysh*, the same command is sent to all relevant
daemons (the daemons that implement route-maps), which ensures
synchronization among them. The problem is when a daemon starts after
the route-maps are created. In this case this daemon wouldn’t be aware
of the previously configured route-maps (unlike the other daemons),
which can lead to a lot of confusion and unexpected problems.

With the new northbound architecture, configuration objects can be
manipulated using higher level abstractions, which opens more
possibilities to solve this decades-long problem. As an example, one
solution would be to make the FRR daemons fetch the shared configuration
objects from zebra using the ZAPI interface during initialization. The
shared configuration objects could be requested using a list of XPaths
expressions in the ``ZEBRA_HELLO`` message, which zebra would respond by
sending the shared configuration objects encoded in the JSON format.
This solution however doesn’t address the case where zebra starts or
restarts after the other FRR daemons. Other solution would be to store
the shared configuration objects in the northbound SQL database and make
all daemons fetch these objects from there. So far no work has been made
on this area as more investigation needs to be done.

vtysh support
~~~~~~~~~~~~~

As explained in the [[Transactional CLI]] page, all commands introduced
by the transactional CLI are not yet available in *vtysh*. This needs to
be addressed in the short term future. Some challenges for doing that
work include: \* How to display configurations (running, candidates and
rollbacks) in a more clever way? The implementation of the
``show running-config`` command in *vtysh* is not something that should
be followed as an example. A better idea would be to fetch the desired
configuration from all daemons (encoded in JSON for example), merge them
all into a single ``lyd_node`` variable and then display the combined
configurations from this variable (the configuration merges would
transparently take care of combining the shared configuration objects).
In order to be able to manipulate the JSON configurations, *vtysh* will
need to load the YANG modules from all daemons at startup (this might
have a minimal impact on startup time). The only issue with this
approach is that the ``cli_show()`` callbacks from all daemons are
embedded in their binaries and thus not accessible externally. It might
be necessary to compile these callbacks on a separate shared library so
that they are accessible to *vtysh* too. Other than that, displaying the
combined configurations in the JSON/XML formats should be
straightforward. \* With the current design, transaction IDs are
per-daemon and not global across all FRR daemons. This means that the
same transaction ID can represent different transactions on different
daemons. Given this observation, how to implement the
``rollback configuration`` command in *vtysh*? The easy solution would
be to add a ``daemon WORD`` argument to specify the context of the
rollback, but per-daemon rollbacks would certainly be confusing and
convoluted to end users. A better idea would be to attack the root of
the problem: change configuration transactions to be global instead of
being per-daemon. This involves a bigger change in the northbound
architecture, and would have implications on how transactions are stored
in the SQL database (daemon-specific and shared configuration objects
would need to have their own tables or columns). \* Loading
configuration files in the JSON or XML formats will be tricky, as
*vtysh* will need to know which sections of the configuration should be
sent to which daemons. *vtysh* will either need to fetch the YANG
modules implemented by all daemons at runtime or obtain this information
at compile-time somehow.

Detecting type mismatches at compile-time
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

As described in the [[Retrofitting Configuration Commands]] page, the
northbound configuration callbacks detect type mismatches at runtime
when fetching data from the the ``dnode`` parameter (which represents
the configuration node being created, modified, deleted or moved). When
a type mismatch is detected, the program aborts and displays a backtrace
showing where the problem happened. It would be desirable to detect such
type mismatches at compile-time, the earlier the problems are detected
the sooner they are fixed.

One possible solution to this problem would be to auto-generate C
structures from the YANG models and provide a function that converts a
libyang’s ``lyd_node`` variable to a C structure containing the same
information. The northbound callbacks could then fetch configuration
data from this C structure, which would naturally lead to type
mismatches being detected at compile time. One of the challenges of
doing this would be the handling of YANG lists and leaf-lists. It would
be necessary to use dynamic data structures like hashes or rb-trees to
hold all elements of the lists and leaf-lists, and the process of
converting a ``lyd_node`` to an auto-generated C-structure could be
expensive. At this point it’s unclear if it’s worth adding more
complexity in the northbound architecture to solve this specific
problem.
