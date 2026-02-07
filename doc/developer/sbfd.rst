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

.. _sbfd-extention:

SBFD extension - SRv6 encapsulation
===================================

SBFDInitiator periodically send packets to monitor the connection to SBFDReflector. We set up an SBFD connection between the source and the destination node of a path,
with the source node serving as Initiator and the destination node as Reflector. The communicated SBFD packets should also follow every exact hop in the path,
from the source to the destination, which could be achieved by segment routing. This requirement extends the node verification to the path verification.

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
A bfd-name is always associated with a TE path, for example if we use the sbfd session to protect the path A-B-D, we would assign the name 'path-a-b-d' or 'a-b-d' to the session.

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
	 * - c: bfd name len               <---- new field
	 * - Xbytes: bfd name              <---- new field
	 *
	 * Commands: ZEBRA_BFD_DEST_REPLAY
	 *
	 * q(64), l(32), w(16), c(8)



.. _sbfd-implement-port:

SBFD UDP port
-------------

According to RFC7881, SBFD Control packet dst port should be 7784, src port can be any but NOT 7784. In our implementation, the UDP ports in packet are set as:


::

   UDP(sport=4784, dport=7784)/BFD() or UDP(sport=3784, dport=7784)/BFD()

if "multihop" is specified for sbfd initiator we choose the 4784 as the source port, so the reflected packet will take 4784 as the dst port, this is a local BFD_MULTI_HOP_PORT so the reflected packet can be handled by the existing bfd_recv_cb function.
if "multihop" is not specified for sbfd initiator we choose the 3784 as the source port, this is a local BFD_DEFDESTPORT so the reflected packet can be handled by the existing bfd_recv_cb function.


For echo SBFD with SRv6 encapsulation case, we re-use the BFD Echo port, the UDP ports in packet are set as:

::

   UDP(sport=3785, dport=3785)/BFD()


we choose the 3785 as the source port, so the echo back packet will take 3785 as the dst port, this is a local BFD_DEF_ECHO_PORT so the packet can be handled by the existing bfd_recv_cb function.


.. _sbfd-not-implemented:

Todo list for SBFD
------------------

   Currently some features are not yet implemented for SBFD, will add it in future:
   1) SBFD in IPv4 only packet
   2) The ADMIN DOWN logic
   3) SBFD echo function in a initiator session
   4) SBFD over MPLS
