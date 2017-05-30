#!/bin/bash

### BEGIN INIT INFO
# Provides:             frr
# Required-Start:       $remote_fs $syslog
# Required-Stop:        $remote_fs $syslog
# Default-Start:        2 3 4 5
# Default-Stop:         
# Short-Description:    FreeRouting Project
### END INIT INFO



FRR_PATH="/opt/frr"
DAEMONS="zebra bgpd"
PARAMS="-A 0.0.0.0 -d"

ACTION=$1
SHELL_CMD=$(echo $@|cut -d ' ' -f 2-|tr ' ' '_')

case $SHELL_CMD in
	shell)
		unset SHELL_CMD
		;;
	* )
		true
		;;
esac

echo $SHELL_CMD

start(){
	PATH=$PATH:$FRR_PATH/bin:$FRR_PATH/sbin
	for a in $(echo $DAEMONS)
	do
		printf "Starting $a..."
		if $a $PARAMS
		then
			printf "OK\n"
		else
			printf "FAILED\n"
		fi
	done
}

stop(){
        	PATH=$PATH:$FRR_PATH/bin:$FRR_PATH:/sbin
	        for a in $(echo $DAEMONS)
       		 do
                printf "Starting $a..."
                if killall $a
                then
                        printf "OK\n"
                else
                        printf "FAILED\n" 
                fi
        	done
}

case $ACTION in
	start)
		start
		;;
	stop)
		stop
		;;
	shell)
		        PATH=$PATH:$FRR_PATH/bin:$FRR_PATH/sbin
			if test $SHELL_CMD
			then
				if vtysh -c "$(echo $SHELL_CMD|tr '_' ' ')"
				then
					exit 0
				else
					echo "E: Failed connect on vtysh"
					exit 1
				fi
			else
				true
			fi
				
			if vtysh
			then
				exit 0
			else
				echo "E: Failed to connect on vtysh"
				exit 1
			fi
		;;
	* )
		echo "Usage: start|stop|shell"
		;;
esac
