#!/bin/bash

# Public domain, not copyrighted..

NUM=5
VTYBASE=2610
ASBASE=64560
BGPD=/path/to/bgpd
PREFIX=192.168.145

for H in `seq 1 ${NUM}` ; do
	CONF=/etc/quagga/bgpd${H}.conf
	ADDR=${PREFIX}.${H}
	
	if [ ! -e "$CONF" ] ; then
		# This sets up a ring of bgpd peerings
		NEXT=$(( ($H % ${NUM}) + 1 ))
		PREV=$(( (($H + 3) % ${NUM}) + 1 ))
		NEXTADDR="${PREFIX}.${NEXT}"
		NEXTAS=$((${ASBASE} + $NEXT))
		PREVADDR="${PREFIX}.${PREV}"
		PREVAS=$((${ASBASE} + $PREV))
		
		# Edit config to suit.
		cat > "$CONF" <<- EOF
			password whatever
			service advanced-vty
			!
			router bgp $((64560+${H}))
			 bgp router-id ${ADDR}
			 network 10.${H}.1.0/24 pathlimit 1
			 network 10.${H}.2.0/24 pathlimit 2
			 network 10.${H}.3.0/24 pathlimit 3
			 neighbor default peer-group
			 neighbor default update-source ${ADDR}
			 neighbor default capability orf prefix-list both
			 neighbor default soft-reconfiguration inbound
			 neighbor ${NEXTADDR} remote-as ${NEXTAS}
			 neighbor ${NEXTADDR} peer-group default
			 neighbor ${PREVADDR} remote-as ${PREVAS}
			 neighbor ${PREVADDR} peer-group default
		EOF
		chown quagga:quagga "$CONF"
	fi
	# You may want to automatically add configure a local address
	# on a loop interface.
	#
	# Solaris: ifconfig vni${H} plumb ${ADDR}/32 up
	# Linux:   ip address add ${ADDR}/32 dev lo 2> /dev/null
	${BGPD} -i /var/run/quagga/bgpd${H}.pid \
		-l ${ADDR} \
		-f /etc/quagga/bgpd${H}.conf \
		-P $((${VTYBASE}+${H})) \
		-d
done
