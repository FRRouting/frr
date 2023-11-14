Handling SNMP Traps
===================

To handle snmp traps make sure your snmp setup of frr works correctly as
described in the frr documentation in :ref:`snmp-support`.

The BGP4 mib will send traps on peer up/down events. These should be visible in
your snmp logs with a message similar to:

::

   snmpd[13733]: Got trap from peer on fd 14

To react on these traps they should be handled by a trapsink. Configure your
trapsink by adding the following lines to :file:`/etc/snmpd/snmpd.conf`:

::

   # send traps to the snmptrapd on localhost
   trapsink localhost


This will send all traps to an snmptrapd running on localhost. You can of
course also use a dedicated management station to catch traps. Configure the
snmptrapd daemon by adding the following line to
:file:`/etc/snmpd/snmptrapd.conf`:

::

   traphandle .1.3.6.1.4.1.3317.1.2.2 /etc/snmp/snmptrap_handle.sh


This will use the bash script :file:`/etc/snmp/snmptrap_handle.sh` to handle
the BGP4 traps. To add traps for other protocol daemons, lookup their
appropriate OID from their mib. (For additional information about which traps
are supported by your mib, lookup the mib on
`http://www.oidview.com/mibs/detail.html <http://www.oidview.com/mibs/detail.html>`_).

Make sure *snmptrapd* is started.

The snmptrap_handle.sh script I personally use for handling BGP4 traps is
below. You can of course do all sorts of things when handling traps, like sound
a siren, have your display flash, etc., be creative ;).

.. code-block:: shell

   #!/bin/bash

   # routers name
   ROUTER=`hostname -s`

   #email address use to sent out notification
   EMAILADDR="john@doe.com"
   #email address used (allongside above) where warnings should be sent
   EMAILADDR_WARN="sms-john@doe.com"

   # type of notification
   TYPE="Notice"

   # local snmp community for getting AS belonging to peer
   COMMUNITY="<community>"

   # if a peer address is in $WARN_PEERS a warning should be sent
   WARN_PEERS="192.0.2.1"

   # get stdin
   INPUT=`cat -`

   # get some vars from stdin
   uptime=`echo $INPUT | cut -d' ' -f5`
   peer=`echo $INPUT | cut -d' ' -f8 | sed -e 's/SNMPv2-SMI::mib-2.15.3.1.14.//g'`
   peerstate=`echo $INPUT | cut -d' ' -f13`
   errorcode=`echo $INPUT | cut -d' ' -f9 | sed -e 's/\\"//g'`
   suberrorcode=`echo $INPUT | cut -d' ' -f10 | sed -e 's/\\"//g'`
   remoteas=`snmpget -v2c -c $COMMUNITY localhost SNMPv2-SMI::mib-2.15.3.1.9.$peer | cut -d' ' -f4`

   WHOISINFO=`whois -h whois.ripe.net " -r AS$remoteas" | egrep '(as-name|descr)'`
   asname=`echo "$WHOISINFO" | grep "^as-name:" | sed -e 's/^as-name://g' -e 's/  //g' -e 's/^ //g' | uniq`
   asdescr=`echo "$WHOISINFO" | grep "^descr:" | sed -e 's/^descr://g' -e 's/  //g' -e 's/^ //g' | uniq`

   # if peer address is in $WARN_PEER, the email should also
   # be sent to $EMAILADDR_WARN
   for ip in $WARN_PEERS; do
   if [ "x$ip" == "x$peer" ]; then
   EMAILADDR="$EMAILADDR,$EMAILADDR_WARN"
   TYPE="WARNING"
   break
   fi
   done

   # convert peer state
   case "$peerstate" in
   1) peerstate="Idle" ;;
   2) peerstate="Connect" ;;
   3) peerstate="Active" ;;
   4) peerstate="Opensent" ;;
   5) peerstate="Openconfirm" ;;
   6) peerstate="Established" ;;
   *) peerstate="Unknown" ;;
   esac

   # get textual messages for errors
   case "$errorcode" in
   00)
   error="No error"
   suberror=""
   ;;
   01)
   error="Message Header Error"
   case "$suberrorcode" in
   01) suberror="Connection Not Synchronized" ;;
   02) suberror="Bad Message Length" ;;
   03) suberror="Bad Message Type" ;;
   *) suberror="Unknown" ;;
   esac
   ;;
   02)
   error="OPEN Message Error"
   case "$suberrorcode" in
   01) suberror="Unsupported Version Number" ;;
   02) suberror="Bad Peer AS" ;;
   03) suberror="Bad BGP Identifier" ;;
   04) suberror="Unsupported Optional Parameter" ;;
   05) suberror="Authentication Failure" ;;
   06) suberror="Unacceptable Hold Time" ;;
   *) suberror="Unknown" ;;
   esac
   ;;
   03)
   error="UPDATE Message Error"
   case "$suberrorcode" in
   01) suberror="Malformed Attribute List" ;;
   02) suberror="Unrecognized Well-known Attribute" ;;
   03) suberror="Missing Well-known Attribute" ;;
   04) suberror="Attribute Flags Error" ;;
   05) suberror="Attribute Length Error" ;;
   06) suberror="Invalid ORIGIN Attribute" ;;
   07) suberror="AS Routing Loop" ;;
   08) suberror="Invalid NEXT_HOP Attribute" ;;
   09) suberror="Optional Attribute Error" ;;
   10) suberror="Invalid Network Field" ;;
   11) suberror="Malformed AS_PATH" ;;
   *) suberror="Unknown" ;;
   esac
   ;;
   04)
   error="Hold Timer Expired"
   suberror=""
   ;;
   05)
   error="Finite State Machine Error"
   suberror=""
   ;;
   06)
   error="Cease"
   case "$suberrorcode" in
   01) suberror="Maximum Number of Prefixes Reached" ;;
   02) suberror="Administrative Shutdown" ;;
   03) suberror="Peer De-configured" ;;
   04) suberror="Administrative Reset" ;;
   05) suberror="Connection Rejected" ;;
   06) suberror="Other Configuration Change" ;;
   07) suberror="Connection Collision Resolution" ;;
   08) suberror="Out of Resources" ;;
   09) suberror="MAX" ;;
   *) suberror="Unknown" ;;
   esac
   ;;
   *)
   error="Unknown"
   suberror=""
   ;;
   esac

   # create textual message from errorcodes
   if [ "x$suberror" == "x" ]; then
   NOTIFY="$errorcode ($error)"
   else
   NOTIFY="$errorcode/$suberrorcode ($error/$suberror)"
   fi

   # form a decent subject
   SUBJECT="$TYPE: $ROUTER [bgp] $peer is $peerstate: $NOTIFY"
   # create the email body
   MAIL=`cat << EOF
   BGP notification on router $ROUTER.

   Peer: $peer
   AS: $remoteas
   New state: $peerstate
   Notification: $NOTIFY

   Info:
   $asname
   $asdescr

   Snmpd uptime: $uptime
   EOF`

   # mail the notification
   echo "$MAIL" | mail -s "$SUBJECT" $EMAILADDR
