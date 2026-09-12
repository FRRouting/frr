..
   Shared BGP Lua ``attributes`` table. Included from user and developer
   scripting.rst. Not a standalone document (listed in exclude_patterns).

.. _bgp-lua-attributes-table:

BGP ``attributes`` table reference
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Optional wire attributes use ``nil`` when absent. Returning
``RM_MATCH_AND_CHANGE`` with an ``attributes`` table applies changes onto
``path->attr`` (including presence flags and community/aspath ownership).

+----------------------+-----------------------------------------------+
| Lua key              | C / semantics                                 |
+======================+===============================================+
| ``metric``           | MED (``BGP_ATTR_MULTI_EXIT_DISC``)            |
+----------------------+-----------------------------------------------+
| ``localpref``        | Local preference                              |
+----------------------+-----------------------------------------------+
| ``origin``           | ``"igp"`` / ``"egp"`` / ``"incomplete"``      |
+----------------------+-----------------------------------------------+
| ``weight``           | Local weight                                  |
+----------------------+-----------------------------------------------+
| ``distance``         | Administrative distance                       |
+----------------------+-----------------------------------------------+
| ``tag``              | Route tag                                     |
+----------------------+-----------------------------------------------+
| ``table``            | ``rmap_table_id``                             |
+----------------------+-----------------------------------------------+
| ``label_index``      | Prefix-SID label index                        |
+----------------------+-----------------------------------------------+
| ``aigp_metric``      | AIGP metric                                   |
+----------------------+-----------------------------------------------+
| ``atomic_aggregate`` | boolean                                       |
+----------------------+-----------------------------------------------+
| ``aspath``           | AS path string                                |
+----------------------+-----------------------------------------------+
| ``community``        | Community string                              |
+----------------------+-----------------------------------------------+
| ``large_community``  | Large community string                        |
+----------------------+-----------------------------------------------+
| ``extcommunity``     | Extended community string                     |
+----------------------+-----------------------------------------------+
| ``ipv6_extcommunity``| IPv6 extended community string                |
+----------------------+-----------------------------------------------+
| ``nexthop.*``        | ``ipv4``, ``ipv6_global``, ``ipv6_local``,    |
|                      | ``vpnv4``, ``mp_len``, ``ifindex``,           |
|                      | ``lla_ifindex``, ``prefer_global``            |
+----------------------+-----------------------------------------------+
| ``ifindex``          | Flat nexthop ifindex (compat)                 |
+----------------------+-----------------------------------------------+
| ``rmap_change_flags``| ``BATTR_RMAP_*`` bitfield                     |
+----------------------+-----------------------------------------------+
| ``aggregator``       | ``{ as, address }``                           |
+----------------------+-----------------------------------------------+
| ``originator_id``    | Originator ID string                          |
+----------------------+-----------------------------------------------+
| ``evpn.gateway_ip``  | EVPN gateway IP                               |
+----------------------+-----------------------------------------------+
| ``evpn.flags``       | ``sticky`` / ``default_gw`` / ``router``      |
+----------------------+-----------------------------------------------+

Additional arguments: ``path`` (trailing; ``type`` / ``type_id`` /
``sub_type`` for source-protocol matching, and ``srte_color`` for
``set sr-te color`` semantics on ``bgp_path_info_extra``) and EVPN
``prefix.route_type`` when ``prefix.family`` is AF_EVPN. Returning
``RM_MATCH_AND_CHANGE`` with a modified ``path`` table applies
``path.srte_color``.
