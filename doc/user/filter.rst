*********
Filtering
*********

FRR provides many very flexible filtering features. Filtering is used
for both input and output of the routing information. Once filtering is
defined, it can be applied in any direction.

IP Access List
==============

.. clicmd:: access-list NAME [seq (1-4294967295)] permit IPV4-NETWORK

.. clicmd:: access-list NAME [seq (1-4294967295)] deny IPV4-NETWORK

   seq
      seq `number` can be set either automatically or manually. In the
      case that sequential numbers are set manually, the user may pick any
      number less than 4294967295. In the case that sequential number are set
      automatically, the sequential number will increase by a unit of five (5)
      per list. If a list with no specified sequential number is created
      after a list with a specified sequential number, the list will
      automatically pick the next multiple of five (5) as the list number.
      For example, if a list with number 2 already exists and a new list with
      no specified number is created, the next list will be numbered 5. If
      lists 2 and 7 already exist and a new list with no specified number is
      created, the new list will be numbered 10.

   Basic filtering is done by `access-list` as shown in the
   following example.

   .. code-block:: frr

      access-list filter deny 10.0.0.0/9
      access-list filter permit 10.0.0.0/8
      access-list filter seq 13 permit 10.0.0.0/7

.. clicmd:: show <ip|ipv6> access-list [json]

   Display all IPv4 or IPv6 access lists.

   If the ``json`` option is specified, output is displayed in JSON format.

.. clicmd:: show <ip|ipv6> access-list WORD [json]

   Display the specified IPv4 or IPv6 access list.

   If the ``json`` option is specified, output is displayed in JSON format.


IP Prefix List
==============

*ip prefix-list* provides the most powerful prefix based
filtering mechanism. In addition to *access-list* functionality,
*ip prefix-list* has prefix length range specification and
sequential number specification. You can add or delete prefix based
filters to arbitrary points of prefix-list using sequential number specification.

If no ip prefix-list is specified, it acts as permit. If *ip prefix-list*
is defined, and no match is found, default deny is applied.

.. clicmd:: ip prefix-list NAME (permit|deny) PREFIX [le LEN] [ge LEN]

.. clicmd:: ip prefix-list NAME seq NUMBER (permit|deny) PREFIX [le LEN] [ge LEN]

   You can create *ip prefix-list* using above commands.

   seq
      seq `number` can be set either automatically or manually. In the
      case that sequential numbers are set manually, the user may pick any
      number less than 4294967295. In the case that sequential number are set
      automatically, the sequential number will increase by a unit of five (5)
      per list. If a list with no specified sequential number is created
      after a list with a specified sequential number, the list will
      automatically pick the next multiple of five (5) as the list number.
      For example, if a list with number 2 already exists and a new list with
      no specified number is created, the next list will be numbered 5. If
      lists 2 and 7 already exist and a new list with no specified number is
      created, the new list will be numbered 10.

   le
      Specifies prefix length. The prefix list will be applied if the prefix
      length is less than or equal to the le prefix length.

   ge
      Specifies prefix length. The prefix list will be applied if the prefix
      length is greater than or equal to the ge prefix length.


   Less than or equal to prefix numbers and greater than or equal to
   prefix numbers can be used together. The order of the le and ge
   commands does not matter.

   If a prefix list with a different sequential number but with the exact
   same rules as a previous list is created, an error will result.
   However, in the case that the sequential number and the rules are
   exactly similar, no error will result.

   If a list with the same sequential number as a previous list is created,
   the new list will overwrite the old list.

   Matching of IP Prefix is performed from the smaller sequential number to the
   larger. The matching will stop once any rule has been applied.

   In the case of no le or ge command, the prefix length must match exactly the
   length specified in the prefix list.


.. _ip-prefix-list-description:

ip prefix-list description
--------------------------

.. clicmd:: ip prefix-list NAME description DESC

   Descriptions may be added to prefix lists. This command adds a
   description to the prefix list.


.. _showing-ip-prefix-list:

Showing ip prefix-list
----------------------

.. clicmd:: show ip prefix-list [json]

   Display all IP prefix lists.

   If the ``json`` option is specified, output is displayed in JSON format.

.. clicmd:: show ip prefix-list NAME [json]

   Show IP prefix list can be used with a prefix list name.

   If the ``json`` option is specified, output is displayed in JSON format.

.. clicmd:: show ip prefix-list NAME seq NUM [json]

   Show IP prefix list can be used with a prefix list name and sequential
   number.

   If the ``json`` option is specified, output is displayed in JSON format.

.. clicmd:: show ip prefix-list NAME A.B.C.D/M

   If the command longer is used, all prefix lists with prefix lengths equal to
   or longer than the specified length will be displayed. If the command first
   match is used, the first prefix length match will be displayed.

.. clicmd:: show ip prefix-list NAME A.B.C.D/M longer
.. clicmd:: show ip prefix-list NAME A.B.C.D/M first-match
.. clicmd:: show ip prefix-list summary [json]
.. clicmd:: show ip prefix-list summary NAME [json]
.. clicmd:: show ip prefix-list detail [json]
.. clicmd:: show ip prefix-list detail NAME [json]

.. clicmd:: debug prefix-list NAME match <A.B.C.D/M|X:X::X:X/M> [address-mode]

   Execute the prefix list matching code for the specified list and prefix.
   Shows which entry matched, if any.  (``address-mode`` is used for
   PIM RP lookups and skips prefix length checks.)

   The return value from this command is success only if the prefix-list
   result is to permit the prefix, so the command can be used in scripting.

Clear counter of ip prefix-list
-------------------------------

.. clicmd:: clear ip prefix-list [NAME [A.B.C.D/M]]

   Clears the counters of all IP prefix lists. Clear IP Prefix List can be used
   with a specified NAME or NAME and prefix.
