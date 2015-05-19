#!/bin/bash
#
### BEGIN INIT INFO
# Provides: quagga
# Required-Start: $local_fs $network $remote_fs $syslog
# Required-Stop: $local_fs $network $remote_fs $syslog
# Default-Start:  2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: start and stop the Quagga routing suite
# Description: Quagga is a routing suite for IP routing protocols like 
#              BGP, OSPF, RIP and others. This script contols the main 
#              daemon "quagga" as well as the individual protocol daemons.
### END INIT INFO
#

PATH=/bin:/usr/bin:/sbin:/usr/sbin
D_PATH=/usr/lib/quagga
C_PATH=/etc/quagga

# Local Daemon selection may be done by using /etc/quagga/daemons.
# See /usr/share/doc/quagga/README.Debian.gz for further information.
# Keep zebra first and do not list watchquagga!
DAEMONS="zebra bgpd ripd ripngd ospfd ospf6d isisd babeld"

# Print the name of the pidfile.
pidfile()
{
        echo "/var/run/quagga/$1.pid"
}

# Check if daemon is started by using the pidfile.
started()
{
        [ -e `pidfile $1` ] && kill -0 `cat \`pidfile $1\`` 2> /dev/null && return 0
        return 1
}

# Loads the config via vtysh -b if configured to do so.
vtysh_b ()
{
        # Rember, that all variables have been incremented by 1 in convert_daemon_prios()
        if [ "$vtysh_enable" = 2 -a -f $C_PATH/Quagga.conf ]; then
                /usr/bin/vtysh -b
        fi
}

# Check if the daemon is activated and if its executable and config files 
# are in place.
# params:       daemon name
# returns:      0=ok, 1=error
check_daemon()
{
        # If the integrated config file is used the others are not checked.
        if [ -r "$C_PATH/Quagga.conf" ]; then
          return 0
        fi 

        # vtysh_enable has no config file nor binary so skip check.
        # (Not sure why vtysh_enable is in this list but does not hurt)
        if [ $1 != "watchquagga" -a $1 != "vtysh_enable" ]; then
          # check for daemon binary
          if [ ! -x "$D_PATH/$1" ]; then return 1; fi
                
          # check for config file                 
          if [ ! -r "$C_PATH/$1.conf" ]; then
            echo -n " (not started without config file)"
            return 1
          fi
        fi
        return 0
}

# Starts the server if it's not alrady running according to the pid file.
# The Quagga daemons creates the pidfile when starting.
start()
{
        echo -n " $1"
        if ! check_daemon $1; then return; fi

        if [ "$1" = "watchquagga" ]; then
            start-stop-daemon \
                --start \
                --pidfile=`pidfile $1` \
                --exec "$D_PATH/$1" \
                -- \
                "${watchquagga_options[@]}"
        else
            start-stop-daemon \
                --start \
                --pidfile=`pidfile $1` \
                --exec "$D_PATH/$1" \
                -- \
                `eval echo "$""$1""_options"`
        fi
}

# Stop the daemon given in the parameter, printing its name to the terminal.
stop()
{
    if ! started "$1" ; then
        echo -n " ($1)"
        return 0
    else
        PIDFILE=`pidfile $1`
        PID=`cat $PIDFILE 2>/dev/null`
        start-stop-daemon --stop --quiet --oknodo --exec "$D_PATH/$1"
        #
        #       Now we have to wait until $DAEMON has _really_ stopped.
        #
        if test -n "$PID" && kill -0 $PID 2>/dev/null; then
            echo -n " (waiting) ."
            cnt=0
            while kill -0 $PID 2>/dev/null; do
                cnt=`expr $cnt + 1`
                if [ $cnt -gt 60 ]; then
                    # Waited 120 secs now, fail.
                    echo -n "Failed.. "
                    break
                fi
                sleep 2
                echo -n "."
                done
            fi
        echo -n " $1"
        rm -f `pidfile $1`
    fi
}

# Converts values from /etc/quagga/daemons to all-numeric values.
convert_daemon_prios()
{
        for name in $DAEMONS zebra vtysh_enable watchquagga_enable; do
          # First, assign the value set by the user to $value 
          eval value=\$$name

          # Daemon not activated or entry missing?
          if [ "$value" = "no" -o "$value" = "" ]; then value=0; fi

          # These strings parsed for backwards compatibility.
          if [ "$value" = "yes"  -o  "$value" = "true" ]; then value=1; fi

          # Zebra is threatened special. It must be between 0=off and the first
      # user assigned value "1" so we increase all other enabled daemons' values.
          if [ "$name" != "zebra" -a "$value" -gt 0 ]; then value=`expr "$value" + 1`; fi

          # If e.g. name is zebra then we set "zebra=yes".
          eval $name=$value
        done
}

# Starts watchquagga for all wanted daemons.
start_watchquagga()
{
    local daemon_name
    local daemon_prio
    local found_one

    # Start the monitor daemon only if desired.
    if [ 0 -eq "$watchquagga_enable" ]; then
        return
    fi

    # Check variable type
    if ! declare -p watchquagga_options | grep -q '^declare \-a'; then
      echo
      echo "ERROR: The variable watchquagga_options from /etc/quagga/debian.cnf must be a BASH array!"
      echo "ERROR: Please convert config file and restart!"
      exit 1
    fi

    # Which daemons have been started?
    found_one=0
    for daemon_name in $DAEMONS; do
        eval daemon_prio=\$$daemon_name
        if [ "$daemon_prio" -gt 0 ]; then
            watchquagga_options+=($daemon_name)
            found_one=1
        fi
    done

    # Start if at least one daemon is activated.
    if [ $found_one -eq 1 ]; then
      echo -n "Starting Quagga monitor daemon:"
      start watchquagga
      echo "."
    fi
}

# Stopps watchquagga.
stop_watchquagga()
{
    echo -n "Stopping Quagga monitor daemon:"
    stop watchquagga
    echo "."
}

# Stops all daemons that have a lower level of priority than the given.
# (technically if daemon_prio >= wanted_prio)
stop_prio() 
{
        local wanted_prio
        local daemon_prio
        local daemon_list

        wanted_prio=$1
        daemon_list=${2:-$DAEMONS}

        echo -n "Stopping Quagga daemons (prio:$wanted_prio):"

        for prio_i in `seq 10 -1 $wanted_prio`; do
            for daemon_name in $daemon_list; do
                eval daemon_prio=\$$daemon_name
                if [ $daemon_prio -eq $prio_i ]; then
                    stop "$daemon_name"
                fi
            done
        done
        echo "."
}

# Starts all daemons that have a higher level of priority than the given.
# (technically if daemon_prio <= wanted_prio)
start_prio()
{
        local wanted_prio
        local daemon_prio
        local daemon_list
        
        wanted_prio=$1
        daemon_list=${2:-$DAEMONS}

        echo -n "Starting Quagga daemons (prio:$wanted_prio):"

        for prio_i in `seq 1 $wanted_prio`; do
            for daemon_name in $daemon_list; do
                eval daemon_prio=\$$daemon_name
                if [ $daemon_prio -eq $prio_i ]; then
                    start "$daemon_name"
                fi
            done
        done
        echo "."
}

#########################################################
#               Main program                            #
#########################################################

# Config broken but script must exit silently.
[ ! -r "$C_PATH/daemons" ] && exit 0

# Load configuration
. "$C_PATH/daemons"
. "$C_PATH/debian.conf"

# Set priority of un-startable daemons to 'no' and substitute 'yes' to '0'
convert_daemon_prios

if [ ! -d /var/run/quagga ]; then
    mkdir -p /var/run/quagga
    chown quagga:quagga /var/run/quagga
    chmod 755 /var/run/quagga
fi

case "$1" in
    start)
        # Try to load this necessary (at least for 2.6) module.
        if [ -d /lib/modules/`uname -r` ] ; then
          echo "Loading capability module if not yet done."
          set +e; LC_ALL=C modprobe -a capability 2>&1 | egrep -v "(not found|Can't locate)"; set -e
        fi

        # Start all daemons
        cd $C_PATH/
        if [ "$2" != "watchquagga" ]; then
          start_prio 10 $2
        fi
        vtysh_b
        start_watchquagga
        ;;
        
    1|2|3|4|5|6|7|8|9|10)
        # Stop/start daemons for the appropriate priority level
        stop_prio $1
        start_prio $1
        vtysh_b
        ;;

    stop|0)
        # Stop all daemons at level '0' or 'stop'
        stop_watchquagga
        if [ "$2" != "watchquagga" ]; then
          stop_prio 0 $2
        fi

        if [ -z "$2" -o "$2" = "zebra" ]; then
          echo "Removing all routes made by zebra."
          ip route flush proto zebra
        fi
        ;;

    restart|force-reload)
        $0 stop $2
        sleep 1
        $0 start $2
        ;;

    *)
        echo "Usage: /etc/init.d/quagga {start|stop|restart|force-reload|<priority>} [daemon]"
        echo "       E.g. '/etc/init.d/quagga 5' would start all daemons with a prio 1-5."
        echo "       Read /usr/share/doc/quagga/README.Debian for details."
        exit 1
        ;;
esac

exit 0
