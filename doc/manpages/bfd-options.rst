BFD
---

The following options controls the BFD daemon auxiliary sockets.

.. option:: --dplaneaddr <type>:<address>[<:port>]

   Configure the distributed BFD data plane listening socket bind address.

   One would expect the data plane to run in the same machine as FRR, so
   the suggested configuration would be:

      ``--dplaneaddr unix:/var/run/frr/bfdd_dplane.sock``

   Or using IPv4:

      ``--dplaneaddr ipv4:127.0.0.1``

   Or using IPv6:

      ``--dplaneaddr ipv6:[::1]``

   It is also possible to specify a port (for IPv4/IPv6 only):

     ``--dplaneaddr ipv6:[::1]:50701``

   (if omitted the default port is ``50700``).

   It is also possible to operate in client mode (instead of listening for
   connections). To connect to a data plane server append the letter 'c' to
   the protocol, example:

     ``--dplaneaddr ipv4c:127.0.0.1``
