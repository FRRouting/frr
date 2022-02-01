#!/bin/bash
#input : 'ipset_script_get.sh --list <NAME>'
#description: call 'fpcmd nf-ipset <NAME>'
#output: similar output as with netfilter ipset --list <NAME> command

netns=$(ip netns identify $$)
if [ "$netns" == "" ]
then
	if command -v vrfctl >/dev/null 2>&1
	then
		netns_id=$(vrfctl list vrfname $netns | awk -F'vrf| |\t' '{print $2}')
	else
		echo Cannot get Netns ID: vrfctl not found. >&2
	fi
else
	netns_id=0
fi

if [ $# -eq 2 ]
then
    fp-cli vrf-exec $netns_id nf-ipset $2
fi
