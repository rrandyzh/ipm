/**********************************************************************
 *
 * File:
 *      EIPM_wcnp.c
 *
 * Abstract:
 *	Contains the EIPM functions that, in combination with the code in
 *	the wcnp sub-directory, implement WCNP redundancy mode.
 *
 *   Description:
 *
 **********************************************************************/
#include <sys/time.h>

#include "EIPM_wcnp.h"
#include "EIPM_include.h"
#include "rm/EIPM_alertmon.h"

#include "ipm_util.h"
#include "nma_log.h"

int is_wcnp_inited = 0;
int is_switchover_done = 0;
struct timeval last_switchside_time;
int is_switchside_timer_running = 0;

void EIPM_wcnp_dump()
{
	int side;

	LOG_FORCE(0, "WCNP INFO DUMP BEING\n");
	LOG_FORCE(0, "WNCP: is_wcnp_inited %d, is_switchover_done %d, is_switchside_timer_running %d\n",
				is_wcnp_inited,
				is_switchover_done,
				is_switchside_timer_running);
	LOG_FORCE(0, "MCAST: is_mcast_inited %d mcast_port %d, mcast_ip %x, active_side %d\n",
				mcast_data.is_mcast_inited,
				mcast_data.mcast_port,
				mcast_data.mcast_ip,
				mcast_data.active_side);	
	
	for (side = 0; side < EIPM_ALERT_MAX; side++)
	{
		LOG_FORCE(0, "MCAST: side %d, last_time %u.%06u, mcast_recv_fix_ip %x, intf_name %s, intf_idx %d, accept_msg_cnt %d, drop_msg_cnt %d\n",
					side,
					mcast_data.mcast_side[side].last_time.tv_sec, mcast_data.mcast_side[side].last_time.tv_usec,
					mcast_data.mcast_side[side].mcast_recv_fix_ip,
					mcast_data.mcast_side[side].intf_name,
					mcast_data.mcast_side[side].intf_idx,
					mcast_data.mcast_side[side].accept_msg_cnt,
					mcast_data.mcast_side[side].drop_msg_cnt);
	}
	LOG_FORCE(0, "WCNP INFO DUMP END\n");
}

void EIPM_wcnp_init()
{
	EIPM_DATA       *shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	int wcnp_fix_inited = 0;
	int wcnp_act_inited = 0;
	int wcnp_stby_inited = 0;

	EIPM_INTF  *intf_ptr;
	EIPM_INTF_SPEC      *intfSpecDataP;
	int         intf_idx, sn_idx, ip_idx;
	EIPM_NET old_active;
	EIPM_IPDATA	*ip_ptr;
	EIPM_SUBNET *sn_ptr;
	static struct in_addr sin_fix[2];
	static char lintf[DEV_NLEN_MAX];
	static char rintf[DEV_NLEN_MAX];

	if ((is_wcnp_inited)
		&& (mcast_data.is_mcast_inited == 1))
	{
		return;
	}
	if (is_wcnp_inited == 0)
	{
		memset(lintf, 0, sizeof(lintf));
		memset(rintf, 0, sizeof(rintf));
		memset(sin_fix, 0, sizeof(sin_fix));

		/* Handle the timeout for all interfaces. */
		for( intf_idx=0; intf_idx < shm_ptr->intf_cnt; intf_idx++ )
		{
			intf_ptr = &(shm_ptr->intf_data[intf_idx]);
			for (sn_idx=0; sn_idx < intf_ptr->subnet_cnt; sn_idx++)
			{
				sn_ptr = &(intf_ptr->subnet[sn_idx]);
				if (sn_ptr->redundancy_mode != IPM_RED_EIPM_WCNP_ACTIVE &&
					sn_ptr->redundancy_mode != IPM_RED_EIPM_WCNP_STANDBY && 
					sn_ptr->redundancy_mode != IPM_RED_EIPM_WCNP_FIXLEFT &&
					sn_ptr->redundancy_mode != IPM_RED_EIPM_WCNP_FIXRIGHT)
				{
					continue;
				}
				for( ip_idx = 0; ip_idx < sn_ptr->ip_cnt; ip_idx++ )
				{
					ip_ptr = &(sn_ptr->ips[ip_idx]);
					if (ip_ptr->type == EIPM_IP_WCNP_FIXED)
					{
						if (sn_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_FIXLEFT) 
						{
							IPM_ipaddr2in( &(ip_ptr->ipaddr), &sin_fix[0]);
							strncpy(lintf, intf_ptr->lsn0_baseif, sizeof(lintf) -1);
							wcnp_fix_inited++;
						}
						else if (sn_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_FIXRIGHT)
						{
							IPM_ipaddr2in( &(ip_ptr->ipaddr), &sin_fix[1]);
							strncpy(rintf, intf_ptr->lsn1_baseif, sizeof(rintf) -1);
							wcnp_fix_inited++;
						}
						else
						{
							LOG_FORCE(0, "WARNING: it is fix ip but it is not fix left or fix right\n");
						}	
					}
					else if (ip_ptr->type == EIPM_IP_WCNP_ACTIVE)
					{
						wcnp_act_inited++;
					}
					else if (ip_ptr->type == EIPM_IP_WCNP_STANDBY)
					{
						wcnp_stby_inited++;
					}
				}
			}
		}

		//if ((wcnp_fix_inited == 2) && (wcnp_act_inited == 1) && (wcnp_stby_inited == 1))
		if (wcnp_fix_inited == 2)
		{
			is_wcnp_inited = 1;	
		}
		else
		{
			LOG_ERROR(0, "ERROR: WCNP IP configuration is wrong with fix ip count %d, active ip count %d, standby ip cout %d\n",
							wcnp_fix_inited, wcnp_act_inited, wcnp_stby_inited);
			return;
		}
	}
	if (is_wcnp_inited == 1)
	{
		EIPM_wcnp_InitMcast(sin_fix[0].s_addr, lintf, sin_fix[1].s_addr, rintf);
	}
}

int EIPM_wcnp_get_first_wcnp_subnet(EIPM_INTF  *intf_ptr)
{
	EIPM_SUBNET *sn_ptr;
	int sn_idx = -1;

	for (sn_idx = 0; sn_idx < intf_ptr->subnet_cnt; sn_idx++)
	{
		sn_ptr = &(intf_ptr->subnet[sn_idx]);
		if (sn_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_ACTIVE ||
			sn_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_STANDBY || 
			sn_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_FIXLEFT ||
			sn_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_FIXRIGHT)
		{
			return sn_idx;
		}
	}
	return  -1;
}
EIPM_NET EIPM_wcnp_get_active_side()
{
	/* Pointer to shared memory */
	EIPM_DATA		*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	EIPM_INTF  *intf_ptr;
	EIPM_INTF_SPEC      *intfSpecDataP;
	int 	intf_idx, num_intfs;
	EIPM_SUBNET	*sn_ptr;
	int sn_idx;

	num_intfs = shm_ptr->intf_cnt;

	/* active side is same for all wcnp interfaces and all wcnp subnets */
	for( intf_idx=0; intf_idx < num_intfs; intf_idx++ )
	{
		intf_ptr = &(shm_ptr->intf_data[intf_idx]);
		intfSpecDataP = &(intf_ptr->specData);

		if (intfSpecDataP->monitor == EIPM_MONITOR_WCNP)
		{
			if (intf_ptr->subnet_cnt <= 0)
			{
				continue;
			}
			sn_idx = EIPM_wcnp_get_first_wcnp_subnet(intf_ptr);
			if (sn_idx < 0)
			{
				LOG_OTHER(0, "WARNING: there is no redundancy mode of subnet named EIPM_WCNP under the interface which monitor type is WCNP\n");
				continue;
			}
			sn_ptr = &(intf_ptr->subnet[sn_idx]);
			return sn_ptr->sub2intf_mapping[0].route_priority;
		}
	}
	return LSN_NONE;
}

void EIPM_wcnp_get_active_timestamp(struct timeval *active_time)
{
	EIPM_NET active_side;
	EIPM_SWITCHSIDE wcnp_active;

	active_side = EIPM_wcnp_get_active_side();
	wcnp_active = CONVERTEIPMNET2WCNPSIDE(active_side);	

	memcpy(active_time, &(mcast_data.mcast_side[wcnp_active].last_time), sizeof(struct timeval));
	return;
}

int EIPM_wcnp_set_timer(struct timeval now)
{
	struct timeval active_time;
	unsigned long long activems, nowms;
	long long interval;
	
	EIPM_wcnp_get_active_timestamp(&active_time);
	activems = EIPM_WCNP_TIMEVAL2MSEC(active_time);
	nowms = EIPM_WCNP_TIMEVAL2MSEC(now);
	interval = activems - nowms + EIPM_WCNP_DELAY_TIMER;
	if (interval  > EIPM_WCNP_SWITCHOVER_DELAY_TIMER)
	{
		if ( interval > EIPM_WCNP_DELAY_TIMER )
		{
			return EIPM_WCNP_DELAY_TIMER;
		}
		else
		{
			return interval;
		}
	}
	return EIPM_WCNP_SWITCHOVER_DELAY_TIMER;
}

unsigned long long EIPM_time_elapse(struct timeval new, struct timeval old)
{
	unsigned long long oldms, newms;
	
	oldms = EIPM_WCNP_TIMEVAL2MSEC(old);	
	newms = EIPM_WCNP_TIMEVAL2MSEC(new);
	return newms - oldms;
}

void EIPM_switchover_service()
{
	char cmd[250];

	snprintf(cmd, sizeof(cmd), 
			"%s -t rmv -u -s %d -c %d -h %d >/dev/null 2>&1 &", 
			"/opt/LSS/sbin/upd_servicestate",
			BSP_Chassis_Id,
			BSP_Slot_Id,
			BSP_Host_Id);
	system(cmd);
	LOG_FORCE(0, "NOTICE: Switchover all services located in this blade, Run: %s\n", cmd); 
}

int EIPM_wcnp_check_iipm_degrade_timeout(EIPM_NET active_side)
{
	struct timeval now, degrade_timer;
	int side;
	unsigned long long iipm_time_elapse, active_time_elapse, standby_time_elapse;
	unsigned long long timeout;
	EIPM_SWITCHSIDE wcnp_active, wcnp_standby;
	int iipm_timer;

	gettimeofday(&now, 0);
	side = ipm_get_iipm_status(&degrade_timer, &iipm_timer);

	LOG_OTHER(0, "IIPM active side %d; EIPM active side %d\n", side, active_side);

	if ( side == LINK_NONE )
	{
		// Do nothing when init phase 
		return IPM_SUCCESS;
	}

	/* Active Side reported by Alertmon is available detected by IIPM, do nothing here */
	if (((active_side == LSN0) && ((side == LINK_ALL) || (side == LINK_0)))
		|| ((active_side == LSN1) && ((side == LINK_ALL) || (side == LINK_1)))
		)
	{
		is_switchover_done = 0;
		return IPM_SUCCESS;
	}

	if (is_switchover_done)
	{
		return IPM_SUCCESS;
	}
	if (active_side == LSN1)
	{
		wcnp_active = EIPM_ALERT_RIGHT;
		wcnp_standby = EIPM_ALERT_LEFT;
	}
	else
	{
		wcnp_active = EIPM_ALERT_LEFT;
		wcnp_standby = EIPM_ALERT_RIGHT;	
	}

	/* Calculate time elapse */	
	iipm_time_elapse = EIPM_time_elapse(now, degrade_timer);
	active_time_elapse = EIPM_time_elapse(now, mcast_data.mcast_side[wcnp_active].last_time);
	standby_time_elapse = EIPM_time_elapse(now, mcast_data.mcast_side[wcnp_standby].last_time);
	
	LOG_OTHER(0, "now %d.%d; degrade_timer %d.%d; mcast_data.mcast_side[%d].last_time %d.%d; mcast_data.mcast_side[%d].last_time %d.%d; iipm_time_elapse %llu; active_time_elapse %llu; standby_time_elapse %llu iipm_timer %llu",
			now.tv_sec, now.tv_usec, 
			degrade_timer.tv_sec, degrade_timer.tv_usec,
			wcnp_active, mcast_data.mcast_side[wcnp_active].last_time.tv_sec, mcast_data.mcast_side[wcnp_active].last_time.tv_usec,
			wcnp_standby, mcast_data.mcast_side[wcnp_standby].last_time.tv_sec, mcast_data.mcast_side[wcnp_standby].last_time.tv_usec,
			iipm_time_elapse, active_time_elapse, standby_time_elapse, iipm_timer);

	/* Conditions to switchover of all active software service instances 
	 * 1. An Alertmon multicast message has NOT been received on the active LAN side for more than 1.1 seconds 
	 * (implying that the most recent expected message was lost). 
	 * 2. An Alertmon multicast message HAS been received on the standby LAN side within the last second 
	 * 3. timer expires
	 */
	if ((active_time_elapse > EIPM_WCNP_DELAY_TIMER)
		&& (standby_time_elapse <= EIPM_WCNP_ALERT_TIMER)
		&& (iipm_time_elapse >= iipm_timer)
		)
	{
		/* Call upd_servicestate to switchover service */
		EIPM_switchover_service();
		is_switchover_done = 1;
	}
	return IPM_SUCCESS;
}

IPM_RETVAL EIPM_wcnp_mcast_update_side()
{
	/* Pointer to shared memory */
	EIPM_DATA       *shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;

	EIPM_INTF  *intf_ptr;
	EIPM_INTF_SPEC      *intfSpecDataP;
	int         intf_idx, sn_idx;
	int         num_intfs;
	EIPM_NET	old_active = LSN0;
	EIPM_NET	new_active;
	EIPM_SWITCHSIDE active_side;
	EIPM_SUBNET	*sn_ptr;
	char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];

	/* Check the latest active side from the latest alert message */
	active_side = mcast_data.active_side;
	new_active = CONVERTWCNPSIDE2EIPMNET(active_side);

	if (new_active == LSN_NONE)
	{
		//Do nothing
		return IPM_SUCCESS;
	}

	num_intfs = shm_ptr->intf_cnt;

	/* Handle the timeout for all interfaces. */
	for( intf_idx=0; intf_idx < num_intfs; intf_idx++ )
	{
		intf_ptr = &(shm_ptr->intf_data[intf_idx]);
		intfSpecDataP = &(intf_ptr->specData);
		if (intfSpecDataP->monitor != EIPM_MONITOR_WCNP)
		{
			continue;
		}
		for (sn_idx=0; sn_idx < intf_ptr->subnet_cnt; sn_idx++)
		{
			sn_ptr = &(intf_ptr->subnet[sn_idx]);
			if (sn_ptr->redundancy_mode != IPM_RED_EIPM_WCNP_ACTIVE &&
				sn_ptr->redundancy_mode != IPM_RED_EIPM_WCNP_STANDBY && 
				sn_ptr->redundancy_mode != IPM_RED_EIPM_WCNP_SERVICE && 
				sn_ptr->redundancy_mode != IPM_RED_EIPM_WCNP_FIXLEFT &&
				sn_ptr->redundancy_mode != IPM_RED_EIPM_WCNP_FIXRIGHT)
			{
				continue;
			}
			old_active = sn_ptr->sub2intf_mapping[0].route_priority;
			if (old_active != new_active)
			{
				LOG_FORCE(0, "NOTICE: subnet %s status changed from %d to %d\n", 
						IPM_ipaddr2p( &(sn_ptr->subnet_base), ipm_ipstr_buf, sizeof( ipm_ipstr_buf ) ),
						old_active, new_active);
				sn_ptr->sub2intf_mapping[0].route_priority = new_active;
				EIPM_CHECK_INTF_CONFIG(intfSpecDataP);
			}	
		}
	}
	if (old_active != new_active)
	{
		LOG_FORCE(0, "NOTICE: Active Interface is changed from %d to %d\n", old_active, new_active);
		/* start hysteresis 5 seconds timer */
		is_switchside_timer_running = 1;
		if (EIPM_time_elapse(mcast_data.mcast_side[EIPM_ALERT_LEFT].last_time, mcast_data.mcast_side[EIPM_ALERT_RIGHT].last_time) > 0)
		{
			memcpy(&last_switchside_time, &(mcast_data.mcast_side[EIPM_ALERT_LEFT].last_time), sizeof(struct timeval));
		}
		else
		{
			memcpy(&last_switchside_time, &(mcast_data.mcast_side[EIPM_ALERT_RIGHT].last_time), sizeof(struct timeval));
		}
		LOG_FORCE(0, "NOTICE: Start %d ms timer to ignore succeeding alert message, switch time %d.%d \n", 
					EIPM_WCNP_ALERT_DELAY_TIMER,
					last_switchside_time.tv_sec,
					last_switchside_time.tv_usec);
	}
	return IPM_SUCCESS;
}

IPM_RETVAL EIPM_wcnp_mcast_msg_handler(fd_set *read_sock_set)
{
	EIPM_DATA       *shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	IPM_RETVAL	retval;
	char msgBuf[ALERTMSGSZ];
	EIPM_ALERTMSG_TYPE alert_type;
	EIPM_SWITCHSIDE active_side;

	if ((shm_ptr->is_wcnp_environment == 0) 
		|| (mcast_data.is_mcast_inited == 0))
	{
		return IPM_SUCCESS;
	}


	retval = EIPM_wcnp_mcast_recv(read_sock_set);
	if (retval < 0)
	{
		return IPM_FAILURE;	
	}

	/* 5 seconds of hysteresis built in.  After switch the LANs, here will ignore alerts for the next 5 secs */
	if (is_switchside_timer_running)
	{
		struct timeval latesttime;
		if (EIPM_time_elapse(mcast_data.mcast_side[EIPM_ALERT_LEFT].last_time, mcast_data.mcast_side[EIPM_ALERT_RIGHT].last_time) > 0)
		{
			memcpy(&latesttime, &(mcast_data.mcast_side[EIPM_ALERT_LEFT].last_time), sizeof(struct timeval));
		}
		else
		{
		
			memcpy(&latesttime, &(mcast_data.mcast_side[EIPM_ALERT_RIGHT].last_time), sizeof(struct timeval));
		}
		if (EIPM_time_elapse(latesttime, last_switchside_time) > EIPM_WCNP_ALERT_DELAY_TIMER)
		{
			is_switchside_timer_running = 0;
			LOG_FORCE(0, "NOTICE: Stop %d seconds timer to process alert message again\n", EIPM_WCNP_ALERT_DELAY_TIMER);
		}
		else
		{
			LOG_ERROR(0, "NOTICE: switchside timer is still running last_switchside_time %d.%d; now %d.%d \n", 
							last_switchside_time.tv_sec,
							last_switchside_time.tv_usec,
							latesttime.tv_sec,
							latesttime.tv_usec );
			return retval;
		}
	}
	retval = EIPM_wcnp_mcast_update_side();
	return retval;
} 

void EIPM_set_wcnp_env()
{
	EIPM_DATA       *shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	shm_ptr->is_wcnp_environment =1;
}

void EIPM_wcnp_tout()
{
	/* Pointer to shared memory */
	EIPM_DATA		*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;

	EIPM_INTF	*intf_ptr;
	EIPM_INTF_SPEC		*intfSpecDataP;
	int			intf_idx;
	int			num_intfs;
	int			timeout_checked = 0;
	static int              num_timeouts = 0;
	int 	sn_idx;

	if (shm_ptr->is_wcnp_environment == 0) 
	{
		return ;
	}

	num_timeouts++;

	if ( num_timeouts >= (EIPM_ACM_INTERVAL_TIMER/EIPM_INTERVAL_TIMER) )
	{
		num_timeouts = 0;
	}
	else
	{
		return ;
	}

	EIPM_wcnp_init();

	if ((is_wcnp_inited == 0)
		|| (mcast_data.is_mcast_inited == 0))
	{
		return;
	}

	num_intfs = shm_ptr->intf_cnt;

	/* Handle the timeout for all interfaces. */
	for( intf_idx=0; intf_idx < num_intfs; intf_idx++ )
	{
		intf_ptr = &(shm_ptr->intf_data[intf_idx]);
		intfSpecDataP = &(intf_ptr->specData);

		if (intfSpecDataP->monitor == EIPM_MONITOR_WCNP)
		{
			(void)EIPM_wcnp_tout_intf(intf_ptr,intf_idx);
			if (timeout_checked == 0)
			{
				if (intf_ptr->subnet_cnt > 0)
				{
					sn_idx = EIPM_wcnp_get_first_wcnp_subnet(intf_ptr);
					if (sn_idx < 0)
					{	
						continue;
					}
					/* All WCNP subnet route priority is same */
					(void)EIPM_wcnp_check_iipm_degrade_timeout(intf_ptr->subnet[sn_idx].sub2intf_mapping[0].route_priority);
					timeout_checked = 1;
				}
			}
		}

	} /* end 'for each monitored interface' */

	return ;
} 

int EIPM_wcnp_tout_intf(EIPM_INTF *intf_ptr, int intf_idx)
{

	(void)EIPM_timeout_postprocess(intf_ptr, EIPM_BASE_INTF);

	return IPM_SUCCESS;

} 

