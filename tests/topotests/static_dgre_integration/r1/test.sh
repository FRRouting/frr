#!/usr/bin/sh
set -o nounset -o errexit

errmsg() { printf %s\\n "$@" >&2 ; }
log() { printf %s\\n "$@" ; }

tunnel_count=4000 # Must not be higher than 65534
parallel_count=128 # Number of scripts to run in parallel to emulate IKE daemon's thread pool.

dgre_netns='main' # This netns must already exist, can be 'main' to use the default netns.

script_dir="$(cd "$(dirname "$0")" && pwd)"

dgre_python_script=$script_dir/dgre.py
echo $dgre_python_script
ifname_prefix='dgreike' # Dynamic GRE interfaces will use this prefix and be numbered starting from 1

l3vrf_prefix='l3vrf' # Any l3vrf intrefaces must be created in advance and named using the given prefix and consecutive numbers starting from 1.
l3vrf_count=800 # Must be set to at least 1. To stop using l3vrfs, remove the --l3vrf flag and it's argument from install_dgre_routes().

local_addr_from_index() {
	i="$(($1 + 1))"
	printf "10.42.%d.%d" "$((i / 256))" "$((i % 256))"
}

remote_addr_from_index() {
	i="$(($1 + 1))"
	printf "10.24.%d.%d" "$((i / 256))" "$((i % 256))"
}

ipv4_route_from_index() {
	i="$(($1 + 1))"
	printf "10.6.%d.%d/32 tag %d" "$((i / 256))" "$((i % 256))" "$i"
}

ipv6_route_from_index() {
	i="$1"
	printf "fd00:0042:0000:%04x::/64 tag %d" "$i" "$((i+1))"
}

l3vrf_name_from_index() {
	i="$1"
	printf '%s%d' "$l3vrf_prefix" "$(( (i % l3vrf_count) + 1 ))"
}

ifname_from_index() {
	i="$1"
	printf '%s%d' "$ifname_prefix" "$((i + 1))"
}

count_routes() {
	netns="$1"

	if test "$netns" = 'main' ; then
		ip route show table all | grep dgre | egrep -v '^local|^anycast|^multicast|^fe80::/64' 2>&- | wc -l
	else
		ip -netns "$netns" route show table all | grep dgre | egrep -v '^local|^anycast|^multicast|^fe80::/64' 2>&- | wc -l
	fi
}

dgre_loop() {
	start="$1"
	count="$2"

	if test "$static_ifaces" = 'true' ; then
		dynamic=''
	else
		dynamic='true'
	fi

	if test "$vtysh" = 'true' ; then
		method='vtysh'
	else
		method='socket'
	fi

	i="$start"
	end="$((start + count))"
	while test "$i" -lt "$end" ; do
		python3 "$dgre_python_script" "$action" "$(ifname_from_index "$i")" \
			${dynamic:+--dynamic "$(local_addr_from_index "$i")" "$(remote_addr_from_index "$i")"} \
			--netns "$dgre_netns" \
			--l3vrf "$(l3vrf_name_from_index "$i")" \
			--method "$method" \
			"$(ipv4_route_from_index "$i")" "$(ipv6_route_from_index "$i")"
		i="$((i + 1))"
	done

	log "waiting for routes..."
	try=0
	[ "$action" == "add" ] && route_count=$((tunnel_count * 2)) || route_count=0
	while test "$(count_routes "$dgre_netns")" -lt "$route_count" && test $try -lt 30 ; do
		try=$((try + 1))
		sleep 2
	done
}

count_ifaces() {
	netns="$1"
	type="$2"

	if test "$netns" = 'main' ; then
		ip -brief link show type "$type" 2>&- | wc -l
	else
		ip -brief -netns "$netns" link show type "$type" 2>&- | wc -l
	fi
}

vrf_config() {
	i=0
	while test "$i" -lt "$l3vrf_count" ; do
		ip link add $(l3vrf_name_from_index "$i") type vrf table $((i+1000))
		ip link set $(l3vrf_name_from_index "$i") up
		i="$((i+1))"
	done

	if test "$static_ifaces" = 'true' ; then
		i=0
		while test "$i" -lt "$tunnel_count" ; do
			ip link add "$(ifname_from_index "$i")" type gre local "$(local_addr_from_index "$i")" remote "$(remote_addr_from_index "$i")"
			ip link set "$(ifname_from_index "$i")" master "$(l3vrf_name_from_index "$i")"
			ip link set "$(ifname_from_index "$i")" up
			i="$((i+1))"
		done
	fi
}

reconfigure() {
	vrf_config

	if test "$dgre_netns" != 'main' ; then
		log "waiting for netns $dgre_netns..."
		try=0
		while ! ip netns list 2>&- | grep -qE "^$dgre_netns" && test $try -lt 30; do
			try=$((try + 1))
			sleep 2
		done
	fi

	log "waiting for l3vrfs..."
	try=0
	while test "$(count_ifaces "$dgre_netns" vrf)" -lt "$l3vrf_count" && test $try -lt 30; do
		try=$((try + 1))
		sleep 2
	done

	if test "$static_ifaces" = 'true' ; then
		log "waiting for static GRE interfaces..."
		# Use tunnel_count + 1 to account for the gre0 interface
		try=0
		while test "$(count_ifaces "$dgre_netns" gre)" -lt "$((tunnel_count + 1))" && test $try -lt 30; do
			try=$((try + 1))
			sleep 2
		done
	fi
}

usage() {
	cat >&2 <<- EOF
	usage: ${0##*/} [-h|--help] [--tunnel-count COUNT] [--l3vrf-count COUNT] [--parallel-count COUNT] [--script PATH] [--static-ifaces] [--vtysh] {add|del|reconf}

	--tunnel-count defaults to $tunnel_count
	--l3vrf-count defaults to $l3vrf_count
	--parallel-count defaults to $parallel_count
	--script defaults to $dgre_python_script

	--static-ifaces should be used so that 'reconf' creates the gre interfaces instead of 'add'
	--vtysh can be used to have the script go through vtysh rather than directly connecting to the vty socket.
	EOF
}

static_ifaces='false'
vtysh='false'

if test $# -eq 0 ; then
	usage
	exit 1
fi

while test $# -ge 1 ; do
	case "${1:-}" in
		-h|--help)
			usage
			exit
			;;
		--tunnel-count)
			if test $# -lt 2 ; then usage ; exit 1 ; fi
			tunnel_count="$2"
			shift
			;;
		--l3vrf-count)
			if test $# -lt 2 ; then usage ; exit 1 ; fi
			l3vrf_count="$2"
			shift
			;;
		--parallel-count)
			if test $# -lt 2 ; then usage ; exit 1 ; fi
			parallel_count="$2"
			shift
			;;
		--script)
			if test $# -lt 2 ; then usage ; exit 1 ; fi
			dgre_python_script="$2"
			shift
			;;
		--static-ifaces)
			static_ifaces='true'
			;;
		--vtysh)
			vtysh='true'
			;;
		add|del|reconf)
			action="$1"
			;;
		*)
			errmsg "unrecognized argument: $1"
			usage
			exit 1
			;;
	esac
	shift
done

if test "$action" = 'reconf' ; then
	reconfigure
	exit
fi

tunnels_per_process="$((tunnel_count / parallel_count))"
tunnels_remainder="$((tunnel_count % parallel_count))"

process_count=0
assigned_tunnels=0
while test "$process_count" -lt "$tunnels_remainder" ; do
	dgre_loop "$assigned_tunnels" "$((tunnels_per_process + 1))" > /dev/null &
	assigned_tunnels="$((assigned_tunnels + tunnels_per_process + 1))"
	process_count="$((process_count + 1))"
done

while test "$process_count" -lt "$parallel_count" ; do
	dgre_loop "$assigned_tunnels" "$((tunnels_per_process))" > /dev/null &
	assigned_tunnels="$((assigned_tunnels + tunnels_per_process))"
	process_count="$((process_count + 1))"
done

wait
