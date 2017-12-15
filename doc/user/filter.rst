*********
Filtering
*********

Frr provides many very flexible filtering features.  Filtering is used
for both input and output of the routing information.  Once filtering is
defined, it can be applied in any direction.

@comment  node-name,  next,  previous,  up

IP Access List
==============

.. index:: {Command} {access-list `name` permit `ipv4-network`} {}

{Command} {access-list `name` permit `ipv4-network`} {}
.. index:: {Command} {access-list `name` deny `ipv4-network`} {}

{Command} {access-list `name` deny `ipv4-network`} {}

  Basic filtering is done by `access-list` as shown in the
  following example.

::

    access-list filter deny 10.0.0.0/9
    access-list filter permit 10.0.0.0/8
    

  @comment  node-name,  next,  previous,  up

IP Prefix List
==============

*ip prefix-list* provides the most powerful prefix based
filtering mechanism.  In addition to *access-list* functionality,
*ip prefix-list* has prefix length range specification and
sequential number specification.  You can add or delete prefix based
filters to arbitrary points of prefix-list using sequential number specification.

If no ip prefix-list is specified, it acts as permit.  If *ip prefix-list* 
is defined, and no match is found, default deny is applied.

.. index:: {Command} {ip prefix-list `name` (permit|deny) `prefix` [le `len`] [ge `len`]} {}

{Command} {ip prefix-list `name` (permit|deny) `prefix` [le `len`] [ge `len`]} {}
.. index:: {Command} {ip prefix-list `name` seq `number` (permit|deny) `prefix` [le `len`] [ge `len`]} {}

{Command} {ip prefix-list `name` seq `number` (permit|deny) `prefix` [le `len`] [ge `len`]} {}
    You can create *ip prefix-list* using above commands.



*@asis{seq}*
      seq `number` can be set either automatically or manually.  In the
      case that sequential numbers are set manually, the user may pick any
      number less than 4294967295.  In the case that sequential number are set
      automatically, the sequential number will increase by a unit of five (5)
      per list.  If a list with no specified sequential number is created
      after a list with a specified sequential number, the list will
      automatically pick the next multiple of five (5) as the list number.
      For example, if a list with number 2 already exists and a new list with
      no specified number is created, the next list will be numbered 5.  If
      lists 2 and 7 already exist and a new list with no specified number is
      created, the new list will be numbered 10.


*@asis{le}*
      *le* command specifies prefix length.  The prefix list will be 
      applied if the prefix length is less than or equal to the le prefix length.


*@asis{ge}*
      *ge* command specifies prefix length.  The prefix list will be 
      applied if the prefix length is greater than or equal to the ge prefix length.


  Less than or equal to prefix numbers and greater than or equal to
  prefix numbers can be used together.  The order of the le and ge
  commands does not matter.

  If a prefix list with a different sequential number but with the exact
  same rules as a previous list is created, an error will result.
  However, in the case that the sequential number and the rules are
  exactly similar, no error will result.

  If a list with the same sequential number as a previous list is created,
  the new list will overwrite the old list.

  Matching of IP Prefix is performed from the smaller sequential number to the
  larger.  The matching will stop once any rule has been applied.

  In the case of no le or ge command, the prefix length must match exactly the
  length specified in the prefix list.

.. index:: {Command} {no ip prefix-list `name`} {}

{Command} {no ip prefix-list `name`} {}

.. _ip_prefix-list_description:

ip prefix-list description
--------------------------

.. index:: {Command} {ip prefix-list `name` description `desc`} {}

{Command} {ip prefix-list `name` description `desc`} {}
  Descriptions may be added to prefix lists.  This command adds a
  description to the prefix list.

.. index:: {Command} {no ip prefix-list `name` description [`desc`]} {}

{Command} {no ip prefix-list `name` description [`desc`]} {}
  Deletes the description from a prefix list.  It is possible to use the
  command without the full description.

.. _ip_prefix-list_sequential_number_control:

ip prefix-list sequential number control
----------------------------------------

.. index:: {Command} {ip prefix-list sequence-number} {}

{Command} {ip prefix-list sequence-number} {}
  With this command, the IP prefix list sequential number is displayed.
  This is the default behavior.

.. index:: {Command} {no ip prefix-list sequence-number} {}

{Command} {no ip prefix-list sequence-number} {}
  With this command, the IP prefix list sequential number is not
  displayed.

.. _Showing_ip_prefix-list:

Showing ip prefix-list
----------------------

.. index:: {Command} {show ip prefix-list} {}

{Command} {show ip prefix-list} {}
  Display all IP prefix lists.

.. index:: {Command} {show ip prefix-list `name`} {}

{Command} {show ip prefix-list `name`} {}
  Show IP prefix list can be used with a prefix list name.

.. index:: {Command} {show ip prefix-list `name` seq `num`} {}

{Command} {show ip prefix-list `name` seq `num`} {}
  Show IP prefix list can be used with a prefix list name and sequential
  number.

.. index:: {Command} {show ip prefix-list `name` `a.b.c.d/m`} {}

{Command} {show ip prefix-list `name` `a.b.c.d/m`} {}
  If the command longer is used, all prefix lists with prefix lengths equal to
  or longer than the specified length will be displayed.
  If the command first match is used, the first prefix length match will be
  displayed.

.. index:: {Command} {show ip prefix-list `name` `a.b.c.d/m` longer} {}

{Command} {show ip prefix-list `name` `a.b.c.d/m` longer} {}
.. index:: {Command} {show ip prefix-list `name` `a.b.c.d/m` first-match} {}

{Command} {show ip prefix-list `name` `a.b.c.d/m` first-match} {}
.. index:: {Command} {show ip prefix-list summary} {}

{Command} {show ip prefix-list summary} {}
.. index:: {Command} {show ip prefix-list summary `name`} {}

{Command} {show ip prefix-list summary `name`} {}
.. index:: {Command} {show ip prefix-list detail} {}

{Command} {show ip prefix-list detail} {}
.. index:: {Command} {show ip prefix-list detail `name`} {}

{Command} {show ip prefix-list detail `name`} {}

Clear counter of ip prefix-list
-------------------------------

.. index:: {Command} {clear ip prefix-list} {}

{Command} {clear ip prefix-list} {}
  Clears the counters of all IP prefix lists.  Clear IP Prefix List can be
  used with a specified name and prefix.

.. index:: {Command} {clear ip prefix-list `name`} {}

{Command} {clear ip prefix-list `name`} {}
.. index:: {Command} {clear ip prefix-list `name` `a.b.c.d/m`} {}

{Command} {clear ip prefix-list `name` `a.b.c.d/m`} {}

