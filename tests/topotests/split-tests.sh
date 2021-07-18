#/bin/bash
export TOPOTEST_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
export FRR_DIR="$( cd "$TOPOTEST_DIR" >/dev/null 2>&1 && cd ../.. && pwd )"
cd ${TOPOTEST_DIR}

set -e

usage () {
    cat <<EOF
$*: [-ABclnr] [-f filter] [-g num-groups]
        -A :: Address Sanitizer
        -b :: build local docker run image
        -c :: clean build before building
        -f filter :: only run tests that match this extended-grep filter RE
        -F topotestdir :: only run tests that didn't pass in the given topotest results
        -g num-groups :: run tests in this number of groups
        -l :: run under linux vs docker containers
        -n :: dry run
        -p :: pull remote docker run image
        -r :: rerun (don't compile)
EOF
    exit 1
}

export TOPOTEST_SANITIZER=0

# Change to 1 after we get things working
export TOPOTEST_PULL=0

DORUN=
f_linux=0
f_rerun=0
o_ngroup=$(($(nproc) - 4))
o_filter=""
o_failed_xml=""
while getopts AbcF:f:g:hlnpr opt; do
    case $opt in
        A)
            export TOPOTEST_SANITIZER=1
            ;;
        b)
            export TOPOTEST_PULL=0
            ;;
        c)
            export TOPOTEST_CLEAN=1
            ;;
        f)
            o_filter="${OPTARG}"
            ;;
        F)
            o_failed="${OPTARG}"
            ;;
        g)
            o_ngroup="${OPTARG}"
            ;;
        h)
            usage
            ;;
        l)
            f_linux=1
            ;;
        n)
            DORUN="echo DRYRUN:"
            ;;
        p)
            export TOPOTEST_PULL=1
            ;;
        r)
            f_rerun=1
            ;;
        *)
            echo "unknown option: $opt" >2
            usage
            ;;
    esac
done
shift $(($OPTIND - 1))
TTARGS="$@"

declare alltest_init=""
if [[ -n ${o_failed} ]]; then
    alltest_init=$(${TOPOTEST_DIR}/analyze-split.py -r ${o_failed} | grep -Ee "${o_filter}")
else
    alltest_init=$(ls */*.py | grep -v __init__ | grep -Ee "${o_filter}")
fi
echo "DBG: ALLINIT: $alltest_init"
declare -a alltest=($(echo $alltest_init | sort -u))
declare num_test=${#alltest[@]}

if (( ! f_rerun && ! $TOPOTEST_PULL )); then
    echo "== Building docker run image"
    $DORUN ./docker/build.sh
fi

if (( ! f_rerun )); then
    echo "== Building FRR"
    mkdir -p /tmp/topotests
    # $DORUN env TOPOTEST_CLEAN=1 TOPOTEST_BUILDCACHE=${FRR_DIR}/buildcache ./docker/frr-topotests.sh /bin/sleep 1
    $DORUN env TOPOTEST_LOGS=/tmp/topotests \
         ./docker/frr-topotests.sh /bin/sleep 1
fi

declare -A tests pids
declare group_size=$((num_test / o_ngroup))
declare extra=$((num_test % o_ngroup))
declare -a tmptests=(${alltest[@]})
declare aidx=0

# Mininet wants more resources
SYSC=net.core.wmem_max; VAL=16777216
(( $(cat /proc/sys/${SYSC//.//}) > $VAL )) || sudo sysctl -w $SYSC=$VAL

SYSC=net.core.rmem_max; VAL=16777216
(( $(cat /proc/sys/${SYSC//.//}) > $VAL )) || sudo sysctl -w $SYSC=$VAL

SYSC=net.ipv4.neigh.default.gc_thresh1; VAL=4096
(( $(cat /proc/sys/${SYSC//.//}) > $VAL )) || sudo sysctl -w $SYSC=$VAL

SYSC=net.ipv4.neigh.default.gc_thresh2; VAL=8192
(( $(cat /proc/sys/${SYSC//.//}) > $VAL )) || sudo sysctl -w $SYSC=$VAL

SYSC=net.ipv4.neigh.default.gc_thresh3; VAL=16384
(( $(cat /proc/sys/${SYSC//.//}) > $VAL )) || sudo sysctl -w $SYSC=$VAL

SYSC=net.core.netdev_max_backlog; VAL=5000
(( $(cat /proc/sys/${SYSC//.//}) > $VAL )) || sudo sysctl -w $SYSC=$VAL

SYSC=net.ipv4.route.max_size; VAL=32768
(( $(cat /proc/sys/${SYSC//.//}) > $VAL )) || sudo sysctl -w $SYSC=$VAL

# Special case of running a single node
if (( group_size == 0 && extra == 1 )); then
    $DORUN mkdir -p /tmp/topotests

    declare i=0
    tests[$i]="${alltest[@]:0:1}"

    echo "Running: ${tests[$i]}"

    # TOPOTEST_BUILDCACHE=${FRR_DIR}/buildcache
    env TOPOTEST_CLEAN=0 \
        TOPOTEST_LOGS=/tmp \
        TOPOTEST_NOCOMPILE=1 \
        TOPOTEST_PULL=0 \
        TOPOTEST_OPTIONS="--cpus=1" \
	TOPOTEST_SANITIZER=$TOPOTEST_SANITIZER \
        ./docker/frr-topotests.sh "$@" ${tests[$i]}
    exit $?
fi

echo "Splitting runs into $o_ngroup groups"
for ((i=0; i<o_ngroup; i++)); do
    declare size=$group_size
    if (( extra )); then
        size=$((size+1))
        extra=$((extra-1))
    fi
    # If we have no more tests then we are done
    if (( size == 0 )); then
        break
    fi

    $DORUN mkdir -p /tmp/topotests/tt-group-$i

    tests[$i]="${alltest[@]:$aidx:$size}"
    aidx=$((aidx + size))

    echo "Launching $i: ${tests[$i]}"

    if (( (i % 12) == 0 )); then
        tmux_subcmd="new-window -P"
    else
        tmux select-window -t "$cwin"
        tmux_subcmd="split-window -h"
    fi

    # TOPOTEST_BUILDCACHE=${FRR_DIR}/buildcache

    TOUT=$(tmux $tmux_subcmd env \
         TOPOTEST_CLEAN=0 \
         TOPOTEST_OPTIONS=--cpus="1" \
         TOPOTEST_LOGS=/tmp/topotests/tt-group-$i \
         TOPOTEST_NOCOMPILE=1 \
         TOPOTEST_PULL=0 \
	 TOPOTEST_SANITIZER=$TOPOTEST_SANITIZER \
         bash -c "./docker/frr-topotests.sh ${tests[$i]}; echo done: status: $?; tail -f /dev/null")

    if (( (i % 12) == 0 )); then
        cwin="$TOUT"
        echo "New current tmux window: $cwin"
    fi

    $DORUN tmux select-layout -t "$cwin" tiled
    $DORUN sleep 2
done
# ./tests/topotests/docker/frr-topotests.sh -m "$(cat isisd/markers)"
