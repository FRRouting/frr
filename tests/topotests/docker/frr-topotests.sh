#!/bin/bash
#
# Copyright 2018 Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

set -e

if [[ "$1" = "-h" ]] || [[ "$1" = "--help" ]]; then
	cat >&2 <<-EOF

	This script runs the FRRouting topotests on the FRR tree
	in the current working directory.

	Usage: $0 [args...]

	If any arguments are provided and the first argument starts with / or ./
	the arguments are interpreted as command and will be executed instead
	of pytest.

	Behavior can be further modified by the following environment variables:

	TOPOTEST_AUTOLOAD       If set to 1, the script will try to load necessary
	                        kernel modules without asking for confirmation first.

	TOPOTEST_NOLOAD         If set to 1, don't try to load necessary kernel
	                        modules and don't even ask.

	TOPOTEST_BUILDCACHE     Docker volume used for caching multiple FRR builds
	                        over container runs. By default a
	                        \`topotest-buildcache\` volume will be created for
	                        that purpose.

	TOPOTEST_CLEAN          Clean all previous build artifacts prior to
	                        building. Disabled by default, set to 1 to enable.

	TOPOTEST_DOC            Build the documentation associated with FRR.
	                        Disabled by default, set to 1 to enable.

	TOPOTEST_FRR            If set, don't test the FRR in the current working
	                        directory, but the one at the given path.

	TOPOTEST_LOGS           If set, don't use \`/tmp/topotest_logs\` directory
	                        but use the provided path instead.

	TOPOTEST_OPTIONS        These options are appended to the docker-run
	                        command for starting the tests.

	TOPOTEST_PULL           If set to 0, don't try to pull the most recent
	                        version of the docker image from dockerhub.

	TOPOTEST_SANITIZER      Controls whether to use the address sanitizer.
	                        Enabled by default, set to 0 to disable.

	TOPOTEST_VERBOSE        Show detailed build output.
	                        Enabled by default, set to 0 to disable.

	EOF
	exit 1
fi

#
# These two modules are needed to run the MPLS tests.
# They are often not automatically loaded.
#
# We cannot load them from the container since we don't
# have host kernel modules available there. If we load
# them from the host however, they can be used just fine.
#

export PATH="$PATH:/sbin:/usr/sbin:/usr/local/sbin"

if [ "$TOPOTEST_NOLOAD" != "1" ]; then
	for module in mpls-router mpls-iptunnel; do
		if modprobe -n $module 2> /dev/null; then
			:
		else
			# If the module doesn't exist, we cannot do anything about it
			continue
		fi

		if [ $(grep -c ${module/-/_} /proc/modules) -ne 0 ]; then
			# If the module is loaded, we don't have to do anything
			continue
		fi

		if [ "$TOPOTEST_AUTOLOAD" != "1" ]; then
			echo "To run all the possible tests, we need to load $module."
			echo -n "Do you want to proceed? [y/n] "
			read answer
			if [ x"$answer" != x"y" ]; then
				echo "Not loading."
				continue
			fi
		fi

		if [ x"$(whoami)" = x"root" ]; then
			modprobe $module
		else
			sudo modprobe $module
		fi
	done
fi

if [ -z "$TOPOTEST_LOGS" ]; then
	mkdir -p /tmp/topotest_logs
	TOPOTEST_LOGS="/tmp/topotest_logs"
fi

if [ -z "$TOPOTEST_FRR" ]; then
	TOPOTEST_FRR="$(git rev-parse --show-toplevel || true)"
	if [ -z "$TOPOTEST_FRR" ]; then
		echo "Could not determine base of FRR tree." >&2
		echo "frr-topotests only works if you have your tree in git." >&2
		exit 1
	fi
	git -C "$TOPOTEST_FRR" ls-files -z > "${TOPOTEST_LOGS}/git-ls-files"
fi

if [ -z "$TOPOTEST_BUILDCACHE" ]; then
	TOPOTEST_BUILDCACHE=topotest-buildcache
	docker volume inspect "${TOPOTEST_BUILDCACHE}" &> /dev/null \
		|| docker volume create "${TOPOTEST_BUILDCACHE}"
fi

if [ "${TOPOTEST_PULL:-1}" = "1" ]; then
	docker pull frrouting/topotests:latest
fi

if [[ -n "$TMUX" ]]; then
    TMUX_OPTIONS="-v $(dirname $TMUX):$(dirname $TMUX) -e TMUX=$TMUX -e TMUX_PANE=$TMUX_PANE"
fi

if [[ -n "$STY" ]]; then
    SCREEN_OPTIONS="-v /run/screen:/run/screen -e STY=$STY"
fi
set -- --rm -i \
        -v "$HOME:$HOME:ro" \
	-v "$TOPOTEST_LOGS:/tmp" \
	-v "$TOPOTEST_FRR:/root/host-frr:ro" \
	-v "$TOPOTEST_BUILDCACHE:/root/persist" \
	-e "TOPOTEST_CLEAN=$TOPOTEST_CLEAN" \
	-e "TOPOTEST_VERBOSE=$TOPOTEST_VERBOSE" \
	-e "TOPOTEST_DOC=$TOPOTEST_DOC" \
	-e "TOPOTEST_SANITIZER=$TOPOTEST_SANITIZER" \
	--privileged \
        $SCREEN_OPTINS \
        $TMUX_OPTIONS \
	$TOPOTEST_OPTIONS \
	frrouting/topotests:latest "$@"

if [ -t 0 ]; then
	set -- -t "$@"
fi

exec docker run "$@"
