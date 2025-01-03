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

SBFD takes the same data packet formart as BFD, but with a much simpler state machine.
According to RFC7880, SBFD has a statelss SBFDReflector and a stateful SBFDInitiator with the state machine as below:
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
In the following example, we set up a sbfd session to monitor the path A-B-D (all the nodes in the topo are SRv6 ready, which can decap and forward SRv6 packets).

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


After D receive the packet, It will decap the outer IPv6 header since the dst ip 100::D is the End address, the decaped packet is:

::
   IPv6(src="200::A", dst="200::D")/UDP(dport=7784)/BFD(my_dis=123, your_disc=456, state=UP)


This packet will be routed to kernel stack of D since its dst is 200::D. Then the SBFDReflector service on D will get the packet and Reflect it. The response packet will be:

::
   IPv6(src="200::D", dst="200::A")/UDP(sport=7784)/BFD(my_dis=456, your_disc=123, state=UP)


This packet will be routed in the topo according to the dst ip 200::A, it will go back to A by D-B-A or D-C-A in this case.



   In this example, Command used to configure the SBFDInitiator on A is:

.. clicmd:: peer 200::D bfd-mode sbfd-init bfd-name a-b-d local-address 200::A remote-discr 456 encap-type SRv6 encap-data 100::B,100::D source-ipv6 200::A


   Command used to configure the SBFDReflector on D is:

.. clicmd:: sbfd reflector source-address 200::D discriminator 456


.. _sbfd-echo:

Echo SBFD with SRv6 encapsulation
=================================

The SBFD Initiator-Reflector mode requires the configuration on both source and destination nodes. It can not work if the remote node has no SBD feature supported, especial on some third-party devices.
The Echo SBFD can solve this kind of deployment issue since it only requires the configuration on source node.
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


After D receive the packet, It will decap the outer IPv6 header since the dst ip 100::D is the End address, the decaped packet is:

::
   IPv6(src="200::A", dst="200::A")/UDP(dport=3785)/BFD(my_dis=123, your_disc=123, state=UP)


This packet will be routed in the topo according to the dst ip 200::A, it will go back to A by D-B-A or D-C-A in this case.



   In this example, Command used to configure the SBFDInitiator on A is:

.. clicmd:: peer 200::A bfd-mode sbfd-echo bfd-name a-b-d local-address 200::A encap-type SRv6 encap-data 100::B,100::D source-ipv6 200::A


   no confiuration needed on D.


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

After D receive the packet, packet will be sent to kernel stack of D since its dst is 200::D. Then the SBFDReflector service on D will get the packet and Reflect it. The response packet will be:

::
   IPv6(src="200::D", dst="200::A")/UDP(sport=7784)/BFD(my_dis=456, your_disc=123, state=UP)


This packet will be routed in the topo according to the dst ip 200::A, it will go back to A by D-B-A or D-C-A in this case.


   In this example, Command used to configure the SBFDInitiator on A is:

.. clicmd:: peer 200::D bfd-mode sbfd-init bfd-name a-d local-address 200::A remote-discr 456


   Command used to configure the SBFDReflector on D is:

.. clicmd:: sbfd reflector source-address 200::D discriminator 456


.. note::

   Currently some features are not yet implemented: 
   1) SBFD in IPv4 packet 
   2) the ADMIN DOWN logic 
   3) SBFD echo function


.. _sbfd-show:

show commond
============

The exsiting bfd show command is also appliable to SBFD sessions, for example: 
This command will show all the BFD and SBFD sessions in the bfdd:

.. clicmd:: show bfd peers


::
   BFD Peers:
           peer 200::D bfd-mode sbfd-init bfd-name a-d local-address 200::A remote-discr 456 vrf default
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
        peer 200::A bfd-mode sbfd-echo bfd-name a-b-d local-address 200::A encap-type SRv6 encap-data 100::B,100::D source-ipv6 200::A
                Control packet input: 0 packets
                Control packet output: 0 packets
                Echo packet input: 23807 packets
                Echo packet output: 23807 packets
                Session up events: 1
                Session down events: 0
                Zebra notifications: 1
                Tx fail packet: 0

        peer 200::D bfd-mode sbfd-init bfd-name a-d local-address 200::A remote-discr 456 vrf default
                Control packet input: 25289 packets
                Control packet output: 51812 packets
                Echo packet input: 0 packets
                Echo packet output: 0 packets
                Session up events: 5
                Session down events: 4
                Zebra notifications: 9
                Tx fail packet: 0


we also implemented a new show command to display SBFD session only, the bfd-name is the key to search the sessioon.

.. clicmd:: show bfd bfd-name a-b-d

::
   BFD Peers:
        peer 200::A bfd-mode sbfd-echo bfd-name a-b-d local-address 200::A encap-type SRv6 encap-data 100::B,100::D source-ipv6 200::A
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


.. _sbfd-implement:

implementation
===============

Some considerations when implementing sbfd.



.. _sbfd-implement-coexist:

SBFD Co-exist with BFD
--------------------------

Both SBFD and Classical BFD have their unique discriminator, SBFD can co-exist with BFD since they sharing a same discriminator pool in bfdd.
Also in bfdd SBFD and BFD can share most code logic, SBFD packet and BFD packet are demultiplexed by different discriminators.


.. _sbfd-implement-bfdname:

SBFD name
---------

We introduced a bfd-name for every sbfd session. A unique bfd-name can be used to identify a sbfd session quickly. This is quite useful in our Srv6 deployment for path protection case.
In the previous example, if use the sbfd session to protect the path A-B-D, we would assign the name 'path-a-b-d' or 'a-b-d' to the session.

Meanwhile bfdd will notify the sbfd status to the Pathd, we should add the bfd-name field in PTM bfd notify message ZEBRA_BFD_DEST_REPLAY:

::
	 * Message format:
	 * - header: command, vrf
	 * - l: interface index
	 * - c: family
	 *   - AF_INET:
	 *     - 4 bytes: ipv4
	 *   - AF_INET6:
	 *     - 16 bytes: ipv6
	 *   - c: prefix length
	 * - l: bfd status
	 * - c: family
	 *   - AF_INET:
	 *     - 4 bytes: ipv4
	 *   - AF_INET6:
	 *     - 16 bytes: ipv6
	 *   - c: prefix length
	 * - c: cbit
	 * - c: bfd name len              <---- new field
	 * - Xbytes: bfd name             <---- new field
	 *
	 * Commands: ZEBRA_BFD_DEST_REPLAY
	 *
	 * q(64), l(32), w(16), c(8)



.. _sbfd-implement-port:

SBFD UDP port
---------

According to RFC7881, SBFD Control packet dst port should be 7784, src port can be any but NOT 7784. In our implementation, the UDP ports in packet are set as:

::
   UDP(sport=4784, dport=7784)/BFD()

we choose the 4784 as the source port, so the reflected packet will take 4784 as the dst port, this is a local BFD_MULTI_HOP_PORT so the reflected packet can be handled by the existing bfd_recv_cb function.



For echo SBFD with SRv6 encapsulation case, we re-use the BFD Echo port, the UDP ports in packet are set as:

::
   UDP(sport=3785, dport=3785)/BFD()


we choose the 3785 as the source port, so the echo back packet will take 3785 as the dst port, this is a local BFD_DEF_ECHO_PORT so the packet can be handled by the existing bfd_recv_cb function.
