.. _lua:

Lua
===

Lua is currently experimental within FRR and has very limited
support.  If you would like to compile FRR with Lua you must
follow these steps:

1. Installation of Relevant Libraries

   .. code-block:: shell

      apt-get install lua5.3 liblua5-3 liblua5.3-dev

   These are the Debian libraries that are needed.  There should
   be equivalent RPM's that can be found

2. Compilation

   Configure needs these options

   .. code-block:: shell

      ./configure --enable-dev-build --enable-lua <all other interesting options>

   Typically you just include the two new enable lines to build with it.

3. Using Lua

   * Copy tools/lua.scr into /etc/frr

   * Create a route-map match command

   .. code-block:: console

      !
      router bgp 55
        neighbor 10.50.11.116 remote-as external
          address-family ipv4 unicast
            neighbor 10.50.11.116 route-map TEST in
          exit-address-family
      !
      route-map TEST permit 10
        match command mooey
      !

   * In the lua.scr file make sure that you have a function named 'mooey'

   .. code-block:: console

      function mooey ()
         zlog_debug(string.format("afi: %d: %s %d ifdx: %d aspath: %s localpref: %d",
                    prefix.family, prefix.route, nexthop.metric,
                    nexthop.ifindex, nexthop.aspath, nexthop.localpref))

         nexthop.metric =  33
         nexthop.localpref = 13
         return 3
      end

4. General Comments

   Please be aware that this is extremely experimental and needs a ton of work
   to get this up into a state that is usable.
