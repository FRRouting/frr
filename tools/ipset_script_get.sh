#!/bin/bash
#input : 'ipset_script_get.sh --list <NAME>'
#description: call 'fpcmd nf-ipset <NAME>'
#output: similar output as with netfilter ipset --list <NAME> command
if [ $# -eq 2 ]
then
    fpcmd nf-ipset $2
fi
