#!/bin/ksh
###################################################################
#
# NAME:		shmc_activate
#
# DESCRITPION:	This script will make sure the target ShMC is in
#		Active status, switching to it if necessary
#
# ARGUMENTS:	$1 	- target ShMC IP Addr
#
# RETURNS:	0 - target ShMC is already Active, no switchover
#		    performed.
#		1 - target ShMC is currently running Backup mode, 
#           	    and a switchover performed.
#		2 - other error case
#
###################################################################

trap "shmc_act_exit" 0

timeout=3

tmpfile=/tmp/shmc_activate.$$

#-----------------------------------------------------------------
# TRAP Function: shmc_act_exit
#
# This function will do the clean up work when the process exit
#-----------------------------------------------------------------

shmc_act_exit()
{
	# remove the temporary file if there is
       	rm -f ${tmpfile}
}

#-----------------------------------------------------------------
# Function: wait_with_timeout
#
# This function will check the target process running status 
#
# Argument:
#	$1 is used to pass in the target process ID
#
# Return:
#	0 - if target process finished successfully
#	1 - if target process finished unsuccessfully
#	2 - if target process timeout
#-----------------------------------------------------------------

wait_with_timeout()
{
	cnt=$(expr ${timeout} + 1)

	while [ ${cnt} -gt 0 ]; do
		kill -0 ${1} 2>/dev/null
		alive=${?}
		if [ ${alive} -eq 0 ]; then

			cnt=$(expr ${cnt} - 1)
		else
			wait ${1}
			ret=${?}
			if [ ${ret} -eq 0 ]; then
				return 0
			else
				return 1
			fi
		fi

		if [ ${cnt} -gt 0 ]; then
			sleep 1
		fi
	done

	# if we reach here with cnt set to 0 then we timed out
	if [ ${cnt} -eq 0 ]; then

		# terminate the uncompleted process
        	kill -9 ${1} 2>/dev/null
		return 2
	fi
}

#=================================================================
#	EXECUTABLE CODE
#=================================================================

# Check the argument 
if [ ${#} -ne 1 ]; then

	# argument error
	exit 2;
fi

ip_x=${1}

# Check the target ShMC status
rsh -n -l root ${ip_x} clia shmstatus > ${tmpfile} 2>/dev/null &
pid=${!}

if wait_with_timeout ${pid}; then

	grep "Host: \"Active\"" ${tmpfile} > /dev/null
	if [ ${?} -eq 0 ]; then

        	# ShMC is already ACTIVE
        	exit 0;
	fi

	grep "Host: \"Backup\"" ${tmpfile} > /dev/null
	if [ ${?} -eq 0 ]; then

		# ShMC is BACKUP, perform a switchover
		rsh -n -l root ${ip_x} clia switchover > ${tmpfile} 2>/dev/null &
		pid=${!}

		if wait_with_timeout ${pid}; then

			grep "Sending switchover request to the Active Host" ${tmpfile} > /dev/null
			if [ ${?} -eq 0 ]; then

				# ShMC switchover complete
				exit 1
			fi
		fi
	fi
fi

# ShMC switchover failed
exit 2;


