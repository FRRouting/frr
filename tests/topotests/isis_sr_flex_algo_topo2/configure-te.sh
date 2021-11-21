#!/bin/sh

if [ $# -ne 1 ]; then
	echo "invalid command syntax" 1>&2
	echo "Usage: $0 <0|128|129|130>" 1>&2
	exit 1
fi

case "$1" in
  0   ) echo ;;
  128 ) echo ;;
  129 ) echo ;;
  130 ) echo ;;
  *   )   echo "error" ; exit ;;
esac

R0=$(cat /tmp/topotests/isis_sr_flex_algo_topo2.test_isis_sr_flex_algo_topo2/rt0.pid)
R9=$(cat /tmp/topotests/isis_sr_flex_algo_topo2.test_isis_sr_flex_algo_topo2/rt9.pid)

set -x

cat <<EOF | nsenter -a -t $R0 vtysh
conf te
segment-routing
 traffic-eng
  policy color 1 endpoint 9.9.9.9
   name sid-algorithm
   binding-sid 111
   candidate-path preference 100 name sid-algorithm explicit segment-list sid-algorithm-$1
  exit
 exit
exit
EOF

cat <<EOF | nsenter -a -t $R9 vtysh
conf te
segment-routing
 traffic-eng
  policy color 1 endpoint 10.10.10.10
   name sid-algorithm
   binding-sid 222
   candidate-path preference 100 name sid-algorithm explicit segment-list sid-algorithm-$1
  exit
 exit
exit
EOF
