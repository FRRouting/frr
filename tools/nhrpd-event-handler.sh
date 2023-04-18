#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later

# Author: Joe Maimon
# Released to public domain
#

PROGNAME=`basename $0`
VERSION="0.0.6"
#api fields
EV_ID="eventid"
EV_TYPE="type"
EV_OTYPE="old_type"
EV_NUMNHS="num_nhs"
EV_INT="interface"
EV_LADDR="local_address"
EV_VCINIT="vc_initiated"
EV_LNBMA="local_nbma"
EV_LCERT="local_cert"
EV_RADDR="remote_addr"
EV_RNBMA="remote_nbma"
EV_RCERT="remote_cert"

usage()
{
        echo "Usage: $PROGNAME [-s nhrp-sock] [-d] [-i interface-name] [-t table] [-e execute-cmd] [-u user] [-g group] [-r] [-l logfile]"
        echo ""
        echo "-s nhrp-sock file"
        echo "-i interface-name to execute on, may be repeated multiple times"
        echo "-t tableid to execute on for immdiate preceeding interface"
        echo "-e execute command for immmediate preceeding interface"
        echo "   The command will be passed the following arguments $EV_ID $EV_TYPE $EV_INT $EV_LNMBA $EV_RADDR $EV_RNBMA int_table"
        echo "-u user to own the sock"
        echo "-g group to own the sock"
        echo "-r send rejection (testing)"
        echo "-l logfile to record conversation with nhrpd"
        echo "-d daemonize"

        exit 1
}

declare -A EXECARR
declare -A TABLEARR
declare -Ag NHRPEVENT
SOCK="/var/run/frr/nhrp.sock"
USER="frr"
GROUP="frr"
DAEMON=0
j=0
RESULT="accept"

while getopts rds:i:u:g:l:t:e: opt; do
        case "$opt" in
                d)
                        DAEMON=1
                        ;;
                s)
                        SOCK="$OPTARG"
                        ;;
                i)
                        INTARR[((j++))]="$OPTARG"
                        ;;
                e)
                        if [[ "$j" == "0" ]] || [[ "${INTARR[((j-1))]}" == "" ]]; then
                                echo "execute argument must follow interface argument"
                                usage
                        fi
                        EXECARR["${INTARR[((j-1))]}"]="$OPTARG"
                        ;;
                t)
                        if [[ "$j" == "0" ]] || [[ "${INTARR[((j-1))]}" == "" ]]; then
                                echo "execute argument must follow interface argument"
                                usage
                        fi
                        TABLEARR["${INTARR[((j-1))]}"]="$OPTARG"
                        ;;
                u)
                        USER="$OPTARG"
                        ;;
                g)
                        GROUP="$OPTARG"
                        ;;
                r)
                        RESULT="reject"
                        ;;
                l)
                        EVLOGFILE="${OPTARG}"
                        ;;
        esac;
done

if [[ "$EVLOGFILE" != "" ]]; then
        if [[ ! -w "${EVLOGFILE}" ]]; then
                touch "$EVLOGFILE" || ( echo "Cannot write to logfile $EVLOGFILE" ; usage )
        fi
        echo -e "PROG: $0 Startup\nPROG: Arguments $*" >> $EVLOGFILE
fi


function mainloop()
{

if [[ "$EVLOGFILE" != "" ]]; then
        echo -e "PROG: `date -R`\nPROG: Starting mainloop" >> $EVLOGFILE
fi

coproc socat - UNIX-LISTEN:$SOCK,unlink-early,setuid-early=$USER,unlink-close=0 || exit 1
test -S $SOCK && chown $USER:$GROUP $SOCK

OLDIFS="$IFS"

TABLE="table "

while read -r S; do
        if [[ "$EVLOGFILE" != "" ]]; then
                echo "IN: $S" >> $EVLOGFILE
        fi
        if [[ "$S" == "" ]]; then
                if [[ "${NHRPEVENT[$EV_ID]}" != "" ]]; then
                        OUTMSG="eventid=${NHRPEVENT[$EV_ID]}\nresult=$RESULT\n"
                        echo -e "$OUTMSG" >&"${COPROC[1]}"
                        if [[ "$EVLOGFILE" != "" ]]; then
                                echo -e "OUT:\n${OUTMSG}" >> $EVLOGFILE;
                        fi
                fi


                for((i=0;i<${#INTARR[@]};i++)); do
                        if [[ "${NHRPEVENT[$EV_INT]}" == "" ]]; then break; fi
                        if [[ "${INTARR[$i]}" != "${NHRPEVENT[$EV_INT]}" ]]; then continue; fi
                        EVINT="${NHRPEVENT[$EV_INT]}"
                        if [[ "${NHRPEVENT[$EV_RADDR]}" == "" ]]; then break; fi
                        if [[ "${NHRPEVENT[$EV_RNBMA]}" == "" ]]; then break; fi
                        if [[ "${NHRPEVENT[$EV_TYPE]}" != "dynamic" ]]; then break; fi

                        INTEXEC=${EXECARR["$EVINT"]}
                        INTABLE=${TABLEARR["$EVINT"]}

                        unset CMD
                        unset CMDEND
                        CMDADD="ip neigh add "
                        CMDREPL="ip neigh replace"
                        CMDBEG="$CMDADD"
                        if [[ "$INTEXEC" != "" ]]; then
                                CMD="$INTEXEC ${NHRPEVENT[$EV_ID]:-nil}"
                                CMD="$CMD ${NHRPEVENT[$EV_TYPE]:-nil}"
                                CMD="$CMD ${NHRPEVENT[$EV_INT]:-nil}"
                                CMD="$CMD ${NHRPEVENT[$EV_LNBMA]:-nil}"
                                CMD="$CMD ${NHRPEVENT[$EV_RADDR]:-nil}"
                                CMD="$CMD ${NHRPEVENT[$EV_RNBMA]:-nil}"
                                CMD="$CMD ${INTABLE:-nil}"
                                unset CMDBEG
                        else
                                CMDTAB="${INTABLE:+${TABLE}${INTABLE}}"
                                CMDEND="$CMDEND ${NHRPEVENT[$EV_RADDR]} dev $EVINT lladdr ${NHRPEVENT[$EV_RNBMA]} nud noarp"
                                CMD="$CMDEND"
                        fi
                        unset CMDTAB
                        for ((k=0;k<2;k++)); do
                                for ((l=0;l<2;l++)); do
                                        if [[ "$EVLOGFILE" != "" ]]; then
                                                echo "PROG: Executing $CMD" >> $EVLOGFILE
                                                        CMDOUT=`$CMDBEG $CMD $CMDTAB 2>&1`
                                                        CMDRET="$?"
                                                        if [[ "$CMDOUT" != "" ]]; then
                                                                echo "PROG: Execution output: $CMDOUT" >> $EVLOGFILE
                                                        fi
                                        else
                                                $CMDBEG $CMD $CMDTAB
                                        fi
                                        if [[ "$CMDTAB" == "" ]] || [[ "$INTEXEC" != "" ]]; then break; fi
                                done
                                if [[ "$INTEXEC" != "" ]] || [[ "$CMDRET" == "0" ]]; then
                                        break
                                fi
                                CMDBEG="$CMDREPL"
                        done
                        break
                done

                unset NHRPEVENT
                declare -Ag NHRPEVENT
                continue
                continue;
        fi
        IFS="${IFS}="
        SA=($S)
        IFS="$OLDIFS"
        eval NHRPEVENT[${SA[0]}]="\"${SA[1]}\""

done <&"${COPROC[0]}"

if [[ "$COPROC_PID" != "" ]]; then kill "$COPROC_PID"; fi

}

while true; do
        mainloop $*
        if [[ "$DAEMON" == "0" ]]; then
                break;
        fi
        sleep 10
done
