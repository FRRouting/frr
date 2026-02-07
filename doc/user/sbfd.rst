.. _sbfd:

****
SBFD
****

:abbr:`SBFD (Seamless Bidirectional Forwarding Detection)` is:

   Seamless Bidirectional Forwarding Detection, a simplified mechanism for using BFD with a large
   proportion of negotiation aspects eliminated, thus providing benefits
   such as quick provisioning, as well as improved control and
   flexibility for network nodes initiating path monitoring.

  -- :rfc:`7880`

It is described and extended by the following RFCs:

* :rfc:`7880`
* :rfc:`7881`

.. _sbfd-sate-machine:

SBFD state machine
==================

SBFD takes the same data packet format as BFD, but with a much simpler state machine.
According to RFC7880, SBFD has a stateless SBFDReflector and a stateful SBFDInitiator with the state machine as below:

::

                       +--+
          ADMIN DOWN,  |  |
          TIMER        |  V
                     +------+   UP                +------+
                     |      |-------------------->|      |----+
                     | DOWN |                     |  UP  |    | UP
                     |      |<--------------------|      |<---+
                     +------+   ADMIN DOWN,       +------+
                                TIMER

               Figure 1: SBFDInitiator Finite State Machine

* If SBFDInitiator doesn't receive the response packet in time, session is DOWN.
* If SBFDInitiator receives the response packet in time: reponse state is ADMINDOWN, session goes DOWN; reponse state is UP, session goes UP.

.. note::

   SBFDReflector is stateless, it just transmit a packet in response to a received S-BFD packet having a valid S-BFD Discriminator in the Your Discriminator field.


.. _sbfd-extention:

SBFD extension - SRv6 encapsulation
===================================

SBFDInitiator periodically send packets to monitor the connection to SBFDReflector. We set up an SBFD connection between the source and the destination node of a path,
with the source node serving as Initiator and the destination node as Reflector. The communicated SBFD packets should also follow every exact hop in the path,
from the source to the destination, which could be achieved by segment routing. This requirement extends the node verification to the path verification.
In the following example, we set up a sbfd session to monitor the path A-B-D (all nodes in the topo are SRv6 ready, which can decap and forward SRv6 packets).

::

                        +------------C-----------+
                       /                           \
                     A---------------B---------------D
                     ^               ^               ^
                     |               |               |
               End: 100::A       End: 100::B        End: 100::D
          Loopback: 200::A                     Loopback: 200::D
       BFD Discrim: 123                     BFD Discrim: 456
   

A is the SBFDInitiator, and D is the SBFDReflector, A will trasmit the SBFD packet to B as the format:

::

   IPv6(src="200::A", dst="100::B", nh=43)/IPv6ExtHdrSegmentRouting(addresses=["100::D"], nh=41, segleft=1)/IPv6(src="200::A", dst="200::D")/UDP(dport=7784)/BFD(my_dis=123, your_disc=456, state=UP)


Upon receiving the packet, B will take the Srv6 End action since the dst ip 100::B is the End address, B will the shift the dst address according to Srv6 spec, then trasmit the SBFD packet to D as the format:

::

   IPv6(src="200::A", dst="100::D", nh=41)/IPv6(src="200::A", dst="200::D")/UDP(dport=7784)/BFD(my_dis=123, your_disc=456, state=UP)


After D receive the packet, It will decap the outer IPv6 header since the dst ip 100::D is the End address, the decapped packet is:

::

   IPv6(src="200::A", dst="200::D")/UDP(dport=7784)/BFD(my_dis=123, your_disc=456, state=UP)


This packet will be routed to kernel stack of D since its dst is 200::D. Then the SBFDReflector service on D will get the packet and Reflect it. The response packet will be:

::

   IPv6(src="200::D", dst="200::A")/UDP(sport=7784)/BFD(my_dis=456, your_disc=123, state=UP)


This packet will be routed in the topo according to the dst ip 200::A, it will go back to A by D-B-A or D-C-A in this case.



   In this example, Command used to configure the SBFDInitiator on A is:

.. clicmd:: peer 200::D bfd-mode sbfd-init bfd-name a-b-d multihop local-address 200::A remote-discr 456 srv6-source-ipv6 200::A srv6-encap-data 100::B 100::D


   Command used to configure the SBFDReflector on D is:

.. clicmd:: sbfd reflector source-address 200::D discriminator 456


.. _sbfd-echo:

Echo SBFD with SRv6 encapsulation
=================================

The SBFD Initiator-Reflector mode requires the configuration on both source and destination nodes. It can not work if the remote node has no SBD feature supported, especial on some third-party devices.
The Echo SBFD can solve this kind of deployment issue since it only requires the configuration on source node. This is also known as One-Arm BFD Echo or unaffiliated BFD Echo.
For example, we use Echo SBFD session to protect Srv6 path: A-B-D

::

                        +------------C-----------+
                       /                           \
                     A---------------B---------------D
                     ^               ^               ^
                     |               |               |
               End: 100::A       End: 100::B        End: 100::D
          Loopback: 200::A                     Loopback: 200::D
       BFD Discrim: 123


A is also the SBFDInitiator, and B, C, D is Srv6 ready nodes, A will trasmit the SBFD packet to B as the format:

::

   IPv6(src="200::A", dst="100::B", nh=43)/IPv6ExtHdrSegmentRouting(addresses=["100::D"], nh=41, segleft=1)/IPv6(src="200::A", dst="200::A")/UDP(dport=3785)/BFD(my_dis=123, your_disc=123, state=UP)


Upon receiving the packet, B will take the Srv6 End action since the dst ip 100::B is the End address, B will the shift the dst address according to Srv6 spec, then trasmit the SBFD packet to D as the format:

::

   IPv6(src="200::A", dst="100::D", nh=41)/IPv6(src="200::A", dst="200::A")/UDP(dport=3785)/BFD(my_dis=123, your_disc=123, state=UP)


After D receive the packet, It will decap the outer IPv6 header since the dst ip 100::D is the End address, the decapped packet is:

::

   IPv6(src="200::A", dst="200::A")/UDP(dport=3785)/BFD(my_dis=123, your_disc=123, state=UP)


This packet will be routed in the topo according to the dst ip 200::A, it will go back to A by D-B-A or D-C-A in this case.



   In this example, Command used to configure the SBFDInitiator on A is:

.. clicmd:: peer 200::A bfd-mode sbfd-echo bfd-name a-b-d local-address 200::A srv6-source-ipv6 200::A srv6-encap-data 100::B 100::D


   no configuration needed on D.


.. _sbfd-normal:

normal SBFD with no SRv6 encapsulation
======================================

We can also configure a SBFD Initiator-Reflector session based on simple IPv6/IPv4 packet, no Srv6 involved in this case.  

::

                        +------------C-----------+
                       /                           \
                     A---------------B---------------D
                     ^               ^               ^
                     |               |               |
          Loopback: 200::A                     Loopback: 200::D
       BFD Discrim: 123                     BFD Discrim: 456



A is the SBFDInitiator, and D is the SBFDReflector, A will trasmit the SBFD packet to B or C as the format: 

::

   IPv6(src="200::A", dst="200::D")/UDP(dport=7784)/BFD(my_dis=123, your_disc=456, state=UP)


Upon receiving the packet, B/C will route the packet to D according to the dst ip 200::D.

After D receive the packet, packet will be sent to kernel stack of D since its dst is 200::D. Then the SBFDReflector service on D will get the packet and reflect it. The response packet will be:

::

   IPv6(src="200::D", dst="200::A")/UDP(sport=7784)/BFD(my_dis=456, your_disc=123, state=UP)


This packet will be routed in the topo according to the dst ip 200::A, it will go back to A by D-B-A or D-C-A in this case.


   In this example, Command used to configure the SBFDInitiator on A is:

.. clicmd:: peer 200::D bfd-mode sbfd-init bfd-name a-d local-address 200::A remote-discr 456


   Command used to configure the SBFDReflector on D is the same as
   documented earlier in the SBFD section.

.. note::

   Currently some features are not yet implemented:
   1) SBFD in IPv4 only packet
   2) The ADMIN DOWN logic
   3) SBFD echo function in a initiator session
   4) SBFD over MPLS


.. _sbfd-show:

show command
============

The exsiting bfd show command is also appliable to SBFD sessions, for example: 
This command will show all the BFD and SBFD sessions in the bfdd:

.. clicmd:: show bfd peers


::

   BFD Peers:
           peer 200::D bfd-mode sbfd-init bfd-name a-d multihop local-address 200::A vrf default remote-discr 456
                ID: 1421669725
                Remote ID: 456
                Active mode
                Minimum TTL: 254
                Status: up
                Uptime: 5 hour(s), 48 minute(s), 39 second(s)
                Diagnostics: ok
                Remote diagnostics: ok
                Peer Type: sbfd initiator
                Local timers:
                        Detect-multiplier: 3
                        Receive interval: 300ms
                        Transmission interval: 1000ms
                        Echo receive interval: 50ms
                        Echo transmission interval: disabled
                Remote timers:
                        Detect-multiplier: -
                        Receive interval: -
                        Transmission interval: -
                        Echo receive interval: -

This command will show all the BFD and SBFD session packet counters:

.. clicmd:: show bfd peers counters

::

   BFD Peers:
        peer 200::A bfd-mode sbfd-echo bfd-name a-b-d local-address 200::A vrf default srv6-source-ipv6 200::A srv6-encap-data 100::B 100::D
                Control packet input: 0 packets
                Control packet output: 0 packets
                Echo packet input: 23807 packets
                Echo packet output: 23807 packets
                Session up events: 1
                Session down events: 0
                Zebra notifications: 1
                Tx fail packet: 0

        peer 200::D bfd-mode sbfd-init bfd-name a-d local-address 200::A vrf default remote-discr 456
                Control packet input: 25289 packets
                Control packet output: 51812 packets
                Echo packet input: 0 packets
                Echo packet output: 0 packets
                Session up events: 5
                Session down events: 4
                Zebra notifications: 9
                Tx fail packet: 0


we also implemented a new show command to display BFD sessions with a bfd-name, the bfd-name is the key to search the sessioon.

.. clicmd:: show bfd bfd-name a-b-d

::

   BFD Peers:
        peer 200::A bfd-mode sbfd-echo bfd-name a-b-d local-address 200::A vrf default srv6-source-ipv6 200::A srv6-encap-data 100::B 100::D
                ID: 123
                Remote ID: 123
                Active mode
                Status: up
                Uptime: 5 hour(s), 39 minute(s), 34 second(s)
                Diagnostics: ok
                Remote diagnostics: ok
                Peer Type: echo
                Local timers:
                        Detect-multiplier: 3
                        Receive interval: 300ms
                        Transmission interval: 300ms
                        Echo receive interval: 300ms
                        Echo transmission interval: 1000ms
                Remote timers:
                        Detect-multiplier: -
                        Receive interval: -
                        Transmission interval: -
                        Echo receive interval: -
