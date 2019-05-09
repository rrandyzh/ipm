/**********************************************************************
 *
 * File:
 *      EIPM_arpndp.c
 *
 * Abstract:
 *	Contains the EIPM functions that, in combination with the code in
 *	the ipm/arpndp sub-directory, implement ARP/NDP.
 *
 * Functions in this file:
 *
 *	EIPM_arpndp_fsm_init()	      - init an ARP/NDP FSM.
 *	EIPM_arpndp_fsm_start()	      - start an ARP/NDP FSM.
 *	EIPM_arpndp_fsm_restart()     - restart an ARP/NDP FSM.
 *
 *	EIPM_arpndp_start()	      - start an ARP/NDP session.
 *	EIPM_arpndp_stop()	      - stop an ARP/NDP session.
 *	EIPM_arpndp_get_status()      - get the status of an ARP/NDP session.
 *
 **********************************************************************/

#include "EIPM_arpndp.h"

int EIPM_arpndp_admin_change_cfg_sess(
		int		eipm_intf_idx,
		EIPM_SUBNET	*subnet_ptr,
		IPM_IPADDR	*local_ip_ptr
	)

{
	IPM_IPADDR	*remote_ip_ptr;
	uint8_t		detection_multiplier;
	uint32_t	desired_min_tx_interval;
	uint32_t	required_min_rx_interval;

	char		local_ip_addr[IPM_IPMAXSTRSIZE];
	char		remote_ip_addr[IPM_IPMAXSTRSIZE];
	ARPNDP_RETVAL	arpndp_retval = ARPNDP_SUCCESS;
	IPM_RETVAL	retval;
	int		os_intf_idx = 0;

	remote_ip_ptr		 = &(subnet_ptr->gateway);
	detection_multiplier	 = subnet_ptr->detection_multiplier;
	desired_min_tx_interval	 = subnet_ptr->desired_min_tx_interval;
	required_min_rx_interval = subnet_ptr->required_min_rx_interval;

	os_intf_idx = EIPM2OS_INTF_IDX(eipm_intf_idx);

	arpndp_retval = ARPNDP_change_cfg(
		os_intf_idx,
		remote_ip_ptr,
		local_ip_ptr,
		detection_multiplier,
		desired_min_tx_interval,
		required_min_rx_interval
	);

	if ( arpndp_retval == ARPNDP_SUCCESS )
	{
		retval = IPM_SUCCESS;
	}
	else
	{
		memset(local_ip_addr, 0, sizeof local_ip_addr);
		IPM_ipaddr2p(local_ip_ptr, local_ip_addr, IPM_IPMAXSTRSIZE);

		memset(remote_ip_addr, 0, sizeof remote_ip_addr);
		IPM_ipaddr2p(remote_ip_ptr, remote_ip_addr, IPM_IPMAXSTRSIZE);

		EIPM_LOG_ERROR( 0,
			"%s(): ARPNDP_change_cfg( %s, %s, %u, %u, %u ) failed [%d]\n",
			__FUNCTION__,
			(local_ip_addr[0] != '\0' ? local_ip_addr : "empty"),
			(remote_ip_addr[0] != '\0' ? remote_ip_addr : "empty"),
			detection_multiplier,
			desired_min_tx_interval,
			required_min_rx_interval,
			arpndp_retval
		);

		retval = IPM_FAILURE;
	}

	return retval;

} /* EIPM_arpndp_admin_change_cfg_sess() */

int EIPM_arpndp_admin_create_sess(
		int		eipm_intf_idx,
		EIPM_SUBNET	*subnet_ptr,
		IPM_IPADDR	*local_ip_ptr
	)

{
	IPM_IPADDR	*remote_ip_ptr;
	uint8_t		detection_multiplier;
	uint32_t	desired_min_tx_interval;
	uint32_t	required_min_rx_interval;

	char		local_ip_addr[IPM_IPMAXSTRSIZE];
	char		remote_ip_addr[IPM_IPMAXSTRSIZE];
	ARPNDP_RETVAL	arpndp_retval = ARPNDP_SUCCESS;
	IPM_RETVAL	retval;
	int		os_intf_idx = 0;

	remote_ip_ptr		 = &(subnet_ptr->gateway);
	detection_multiplier	 = subnet_ptr->detection_multiplier;
	desired_min_tx_interval	 = subnet_ptr->desired_min_tx_interval;
	required_min_rx_interval = subnet_ptr->required_min_rx_interval;

	os_intf_idx = EIPM2OS_INTF_IDX(eipm_intf_idx);

	arpndp_retval = ARPNDP_create_sess(
		os_intf_idx,
		remote_ip_ptr,
		local_ip_ptr,
		detection_multiplier,
		desired_min_tx_interval,
		required_min_rx_interval
	);

	if ( arpndp_retval == ARPNDP_SUCCESS )
	{
		retval = IPM_SUCCESS;
	}
	else
	{
		memset(local_ip_addr, 0, sizeof local_ip_addr);
		IPM_ipaddr2p(local_ip_ptr, local_ip_addr, IPM_IPMAXSTRSIZE);

		memset(remote_ip_addr, 0, sizeof remote_ip_addr);
		IPM_ipaddr2p(remote_ip_ptr, remote_ip_addr, IPM_IPMAXSTRSIZE);

		EIPM_LOG_ERROR( 0,
			"%s(): ARPNDP_create_sess( %s, %s, %u, %u, %u ) failed [%d]\n",
			__FUNCTION__,
			(local_ip_addr[0] != '\0' ? local_ip_addr : "empty"),
			(remote_ip_addr[0] != '\0' ? remote_ip_addr : "empty"),
			detection_multiplier,
			desired_min_tx_interval,
			required_min_rx_interval,
			arpndp_retval
		);

		retval = IPM_FAILURE;
	}

	return retval;

} /* EIPM_arpndp_admin_create_sess() */

int EIPM_arpndp_admin_destroy_sess( 
		int		eipm_intf_idx,
		IPM_IPADDR	*remote_ip_ptr
	)
{
	int		os_intf_idx = 0;

	os_intf_idx = EIPM2OS_INTF_IDX(eipm_intf_idx);

	ARPNDP_destroy_sess( os_intf_idx, remote_ip_ptr );

	return IPM_SUCCESS;

} /* EIPM_arpndp_admin_destroy_sess() */

int EIPM_arpndp_admin_set_state_sess( 
		int		eipm_intf_idx,
		IPM_IPADDR	*remote_ip_ptr,
		IPM_IPADDR	*local_ip_ptr,
		ARPNDP_ADMIN_STATE	state
	)
{
	char		local_ip_addr[IPM_IPMAXSTRSIZE];
	char		remote_ip_addr[IPM_IPMAXSTRSIZE];
	ARPNDP_RETVAL	arpndp_retval = ARPNDP_SUCCESS;
	IPM_RETVAL	retval;
	int		os_intf_idx = 0;

	os_intf_idx = EIPM2OS_INTF_IDX(eipm_intf_idx);

	arpndp_retval = ARPNDP_set_admin_state(
			os_intf_idx,
			remote_ip_ptr,
			state
		);

	memset(local_ip_addr, 0, sizeof local_ip_addr);
	IPM_ipaddr2p(local_ip_ptr, local_ip_addr, IPM_IPMAXSTRSIZE);

	memset(remote_ip_addr, 0, sizeof remote_ip_addr);
	IPM_ipaddr2p(remote_ip_ptr, remote_ip_addr, IPM_IPMAXSTRSIZE);

	if ( arpndp_retval != ARPNDP_SUCCESS )
	{
		EIPM_LOG_ERROR( 0,
			"%s() - ARPNDP_set_admin_state( %s, %s, %d ) failed with error [%d]\n",
			__FUNCTION__,
			(local_ip_addr[0] != '\0' ? local_ip_addr : "empty"),
			(remote_ip_addr[0] != '\0' ? remote_ip_addr : "empty"),
			(int)state,
			arpndp_retval
		    );

		retval = IPM_FAILURE;
	}
	else
	{
		LOG_FORCE(
			0,
			"%s() - ARPNDP admin state for ip %s, gateway %s, admin state %d\n",
			__FUNCTION__,
			(local_ip_addr[0] != '\0' ? local_ip_addr : "empty"),
			(remote_ip_addr[0] != '\0' ? remote_ip_addr : "empty"),
			(int)state
		);

		retval = IPM_SUCCESS;
	}

	return retval;

} /* EIPM_arpndp_admin_set_state_sess() */

int EIPM_arpndp_dump_sessions(
		EIPM_INTF	*intf_ptr,
		int		subnet_idx,
		IPM_IPADDR	*subnet_base_ptr,
		IPM_IPADDR	*ip_ptr,
		IPM_IPADDR	*gateway_ptr,
		int		check_ip,
		bool		*found_ip_ptr
	)
{
	EIPM_INTF_SPEC	*intfSpecDataP;
	int		intf_idx;
	EIPM_SUBNET	*subnet_ptr;

	EIPM_IPDATA	*ipdata_ptr;
	int		ip_idx;

	char		ip_addr[IPM_IPMAXSTRSIZE];
	char		gateway_addr[IPM_IPMAXSTRSIZE];
	ARPNDP_RETVAL	arpndp_retval = ARPNDP_SUCCESS;
	IPM_RETVAL	retval = IPM_SUCCESS;

	ARPNDP_SESS_STATE	sess_state;
	unsigned int	missed_hb;  

	*found_ip_ptr = FALSE;

	intfSpecDataP = &(intf_ptr->specData);
	intf_idx = intfSpecDataP->baseIntfIdx;
	subnet_ptr = &intf_ptr->subnet[subnet_idx];

	if ( ((IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode != IPM_RED_BFD_TRANSPORT) &&
	     ((IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode != IPM_RED_EIPM_ARPNDP) )
	{
		return IPM_SUCCESS;
	}

	/* check if want to check a certain arpndp session */
	if ( check_ip )
	{
		if( IPM_IPCMPADDR(&subnet_ptr->subnet_base, subnet_base_ptr) != IPM_SUCCESS &&
			IPM_IPCMPADDR(&subnet_ptr->gateway, gateway_ptr) != IPM_SUCCESS )
		{
			return IPM_SUCCESS;

		} /* subnet and gateway mis-match */
	}

	memset(gateway_addr, 0, sizeof(gateway_addr));
	IPM_ipaddr2p(&subnet_ptr->gateway, gateway_addr, IPM_IPMAXSTRSIZE);

	/* dump the information for the ips associated w/ this subnet */
	for ( ip_idx = 0, ipdata_ptr = &subnet_ptr->ips[0];
		ip_idx < subnet_ptr->ip_cnt;
		ip_idx++, ipdata_ptr++ )
	{
		if( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP && ip_idx != 0 )
		{
			continue;
		}

		if ( check_ip )
		{
			/* ip match */
			if( IPM_IPCMPADDR(&ipdata_ptr->ipaddr, ip_ptr) == IPM_SUCCESS )
			{
				*found_ip_ptr = TRUE;
			}
			else
			{
				continue;
			}
		}
		else
		{
			*ip_ptr = ipdata_ptr->ipaddr;
		}

		retval = EIPM_arpndp_dump_sess( intf_ptr, subnet_idx );

		if (retval != IPM_SUCCESS)
		{
			EIPM_LOG_ERROR( 0,
				"%s(): EIPM_arpndp_admin_change_cfg_sess() failed for intf_idx %d subnet_idx %d with error [%d]\n",
				__FUNCTION__,
				intf_idx,
				subnet_idx,
				retval
			);

			break;
		}

	}

	return retval;

} /* EIPM_arpndp_dump_sessions() */

int EIPM_arpndp_dump_sess(
		EIPM_INTF	*intf_ptr,
		int		subnet_idx
	)
{
	EIPM_SUBNET	*subnet_ptr;

	EIPM_IPDATA	*ipdata_ptr;

	char		gateway_addr[IPM_IPMAXSTRSIZE];
	ARPNDP_RETVAL	arpndp_retval = ARPNDP_SUCCESS;
	IPM_RETVAL	retval = IPM_SUCCESS;
	int		os_intf_idx = 0;

	ARPNDP_SESS_STATE	sess_state = ARPNDP_SESS_STATE_DOWN;
	unsigned int	missed_hb = 255;

	int eipm_intf_idx = intf_ptr->specData.baseIntfIdx;

	subnet_ptr = &intf_ptr->subnet[subnet_idx];

	memset(gateway_addr, 0, sizeof(gateway_addr));
	IPM_ipaddr2p(&subnet_ptr->gateway, gateway_addr, IPM_IPMAXSTRSIZE);

	os_intf_idx = EIPM2OS_INTF_IDX(eipm_intf_idx);

	/* Can only ARPNDP if at least 1 local IP address is provisioned */
	if (subnet_ptr->ip_cnt <= 0)
	{
		/*
		LOG_OTHER( 0, "%s Skipping BFD Transport Subnet eipm_intf_idx=%d, subnet_idx=%d, os_intf_idx=%d due to ip_cnt=%d.\n",
		    __FUNCTION__,
		    eipm_intf_idx, subnet_idx, os_intf_idx, subnet_ptr->ip_cnt );
		*/
		return IPM_SUCCESS;
	}

	arpndp_retval = ARPNDP_get_sess_state( os_intf_idx,
				&subnet_ptr->gateway, &sess_state );

	if ( arpndp_retval != ARPNDP_SUCCESS )
	{
		LOG_CRAFT( 0,
			"%s() - ARPNDP_get_sess_state( %d, %s ) for eipm_intf_idx %d failed with error [%d]\n",
			__FUNCTION__,
			os_intf_idx,
			gateway_addr,
			eipm_intf_idx,
			arpndp_retval
		);

		retval = IPM_FAILURE;
	}
	else
	{
		LOG_CRAFT(
			0,
			"%s() - ARPNDP session state for eipm_intf_idx %d, os_intf_idx %d, gateway %s, session state %d\n",
			__FUNCTION__,
			eipm_intf_idx,
			os_intf_idx,
			gateway_addr,
			sess_state
		);
	}

	arpndp_retval = ARPNDP_get_stats(
		os_intf_idx,
		&subnet_ptr->gateway,
		&missed_hb
	);

	if ( arpndp_retval != ARPNDP_SUCCESS )
	{
		LOG_CRAFT( 0,
			"%s() - ARPNDP_get_stats( %d, %s ) for eipm_intf_idx %d failed with error [%d]\n",
			__FUNCTION__,
			os_intf_idx,
			gateway_addr,
			eipm_intf_idx,
			arpndp_retval
		);

		retval = IPM_FAILURE;
	}
	else
	{
		LOG_CRAFT(
			0,
			"%s() - ARPNDP session stats for eipm_intf_idx %d, os_intf_idx %d, gateway %s, missed hb %d\n",
			__FUNCTION__,
			eipm_intf_idx,
			os_intf_idx,
			gateway_addr,
			missed_hb
		);
	}

	return retval;

} /* EIPM_arpndp_dump_sess() */

bool EIPM_arpndp_admin_state_valid(ARPNDP_ADMIN_STATE state)
{
	bool	ret;

	if ( (state == ARPNDP_ADMIN_STATE_DOWN) ||
	     (state == ARPNDP_ADMIN_STATE_UP) )
	{
		ret = TRUE;
	}
	else
	{
		ret = FALSE;
	}

	return ret;

} /* EIPM_arpndp_admin_state_valid() */

int EIPM_arpndp_fsm_init(ARPNDP_INIT_TYPE type)
{
	EIPM_DATA	*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	ARPNDP_RETVAL	arpndp_retval = ARPNDP_SUCCESS;
	int		retval;

	arpndp_retval = ARPNDP_init( /*audit_cb_func*/NULL,
				&(shm_ptr->arpndp_data),
				type );

	if (arpndp_retval == ARPNDP_SUCCESS)
	{
		retval = IPM_SUCCESS;
	}
	else
	{
		EIPM_LOG_ERROR( 0, "Error: EIPM_arpndp_fsm_init() - ARPNDP_init() returned failure=%d for type=%d\n", arpndp_retval, type );

		retval = IPM_FAILURE;
	}

	return retval;

} /* EIPM_arpndp_fsm_init() */

int EIPM_arpndp_fsm_start()
{
	int	retval;

	retval = EIPM_arpndp_fsm_init( ARPNDP_INIT_TYPE_FULL );

	return retval;

} /* EIPM_arpndp_fsm_init() */

int EIPM_arpndp_fsm_restart()
{
	int	retval;

	retval = EIPM_arpndp_fsm_init( ARPNDP_INIT_TYPE_RESTART );

	return retval;

} /* EIPM_arpndp_fsm_restart() */

int EIPM_arpndp_fsm_add_sockets(fd_set *read_sock_set, int *max_sock)
{
	ARPNDP_add_sockets(read_sock_set, max_sock);

	return IPM_SUCCESS;

} /* EIPM_arpndp_fsm_add_sockets() */

int EIPM_arpndp_fsm_recv(fd_set *read_sock_set)
{
	ARPNDP_recv(read_sock_set);

	return IPM_SUCCESS;

} /* EIPM_arpndp_fsm_recv() */

int EIPM_arpndp_start( int eipm_intf_idx, int sn_idx )
{
	/* Starts ARP/NDP if not already running */

	EIPM_DATA		*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	EIPM_INTF		*intf_ptr;
	EIPM_SUBNET		*sn_ptr;
	IPM_IPADDR		*remote_ip_ptr;

	ARPNDP_RETVAL		arpndp_retval = ARPNDP_SUCCESS;

	IPM_RETVAL		retval = IPM_SUCCESS;
	int			os_intf_idx = 0;

	intf_ptr = &(shm_ptr->intf_data[eipm_intf_idx]);
	sn_ptr = &(intf_ptr->subnet[sn_idx]);
	remote_ip_ptr = &(sn_ptr->gateway);

	/* Can only ARPNDP if at least 1 local IP address is provisioned */
	if (sn_ptr->ip_cnt <= 0)
	{
		/*
		LOG_OTHER( 0, "%s Skipping BFD Transport Subnet eipm_intf_idx=%d, sn_idx=%d, os_intf_idx=%d due to ip_cnt=%d.\n",
			__FUNCTION__,
			eipm_intf_idx, sn_idx, os_intf_idx, sn_ptr->ip_cnt );
		 */
		return IPM_SUCCESS;
	}

	os_intf_idx = EIPM2OS_INTF_IDX(eipm_intf_idx);

	arpndp_retval = ARPNDP_set_admin_state( os_intf_idx,
				remote_ip_ptr, ARPNDP_ADMIN_STATE_UP );
	
	if (arpndp_retval != ARPNDP_SUCCESS)
	{
		/* Failed to start ARP/NDP */
		EIPM_LOG_ERROR( 0, "Error: EIPM_arpndp_start() - ARPNDP_set_admin_state() returned failure=%d for eipm_intf_idx=%d, sn_idx=%d, os_intf_idx=%d\n", arpndp_retval, eipm_intf_idx, sn_idx, os_intf_idx );

		/* Make sure it's stopped since it has problems */
		(void)EIPM_arpndp_stop( eipm_intf_idx, sn_idx );

		retval = IPM_FAILURE;
	}

	return retval;

} /* EIPM_arpndp_start() */		

int EIPM_arpndp_stop( int eipm_intf_idx, int sn_idx )
{
	/* Stops ARP/NDP if it's running. */

	EIPM_DATA		*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	EIPM_INTF		*intf_ptr;
	EIPM_SUBNET		*sn_ptr;
	IPM_IPADDR		*remote_ip_ptr;
	int			os_intf_idx = 0;

	intf_ptr = &(shm_ptr->intf_data[eipm_intf_idx]);
	sn_ptr = &(intf_ptr->subnet[sn_idx]);
	remote_ip_ptr = &(sn_ptr->gateway);

	/* Can only ARPNDP if at least 1 local IP address is provisioned */
	if (sn_ptr->ip_cnt <= 0)
	{
		/*
		LOG_OTHER( 0, "%s Skipping BFD Transport Subnet eipm_intf_idx=%d, sn_idx=%d, os_intf_idx=%d due to ip_cnt=%d.\n",
			__FUNCTION__,
			eipm_intf_idx, sn_idx, os_intf_idx, sn_ptr->ip_cnt );
		 */
		return IPM_SUCCESS;
	}

	os_intf_idx = EIPM2OS_INTF_IDX(eipm_intf_idx);

	(void)ARPNDP_set_admin_state( os_intf_idx, remote_ip_ptr,
					ARPNDP_ADMIN_STATE_DOWN );

	return IPM_SUCCESS;
}

int EIPM_arpndp_get_status(
		int		eipm_intf_idx,
		int		sn_idx,
		EIPM_STATUS	*eipm_status_ptr
	)
{
	/* Checks status of ARP/NDP */

	/* Populates eipm_status_ptr with:
	 *
	 *	EIPM_UNKNOWN	= ARP/NDP running, result=unknown
	 *	EIPM_ONLINE	= ARP/NDP stopped, result=suceeded
	 *	EIPM_OFFLINE	= ARP/NDP stopped, result=failed
	 *	EIPM_INHIBITED	= ARP/NDP stopped, result=deactivated
	 */

	EIPM_DATA		*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	EIPM_INTF		*intf_ptr;
	EIPM_SUBNET		*sn_ptr;
	IPM_IPADDR		*remote_ip_ptr;

	ARPNDP_RETVAL		arpndp_retval = ARPNDP_SUCCESS;
	ARPNDP_SESS_STATE	arpndp_state = ARPNDP_SESS_STATE_DOWN;

	IPM_RETVAL		retval = IPM_SUCCESS;
	int			os_intf_idx = 0;

	intf_ptr = &(shm_ptr->intf_data[eipm_intf_idx]);
	sn_ptr = &(intf_ptr->subnet[sn_idx]);
	remote_ip_ptr = &(sn_ptr->gateway);

	os_intf_idx = EIPM2OS_INTF_IDX(eipm_intf_idx);

	*eipm_status_ptr = EIPM_OFFLINE;

	/* Can only ARPNDP if at least 1 local IP address is provisioned */
	if (sn_ptr->ip_cnt <= 0)
	{
		/*
		LOG_OTHER( 0, "%s Skipping BFD Transport Subnet eipm_intf_idx=%d, sn_idx=%d, os_intf_idx=%d due to ip_cnt=%d.\n",
		    __FUNCTION__,
		    eipm_intf_idx, sn_idx, os_intf_idx, sn_ptr->ip_cnt );
		*/
		return IPM_SUCCESS;
	}

	arpndp_retval = ARPNDP_get_sess_state( os_intf_idx, remote_ip_ptr,
						&arpndp_state );

	if (arpndp_retval == ARPNDP_SUCCESS)
	{
		switch(arpndp_state)
		{
		case ARPNDP_SESS_STATE_ADMIN_DOWN:
			/* ARP/NDP deactivated. */
			*eipm_status_ptr = EIPM_INHIBITED;
			break;
		
		case ARPNDP_SESS_STATE_INIT:
			/* ARP/NDP in progress. */
			*eipm_status_ptr = EIPM_UNKNOWN;
			break;
		
		case ARPNDP_SESS_STATE_UP:
			/* ARP/NDP succeeded. */
			*eipm_status_ptr = EIPM_ONLINE;
			break;
		
		case ARPNDP_SESS_STATE_DOWN:
			/* ARP/NDP failed. */
			*eipm_status_ptr = EIPM_OFFLINE;
			break;
	
		default:
			EIPM_LOG_ERROR( 0, "Error: EIPM_arpndp_get_status() - ARPNDP_get_sess_state() populated out of range ARPNDP_ADMIN_STATE=%d for eipm_intf_idx=%d, sn_idx=%d, os_intf_idx=%d\n", arpndp_state, eipm_intf_idx, sn_idx, os_intf_idx );

			/* Make sure it's stopped since it has problems */
			(void)EIPM_arpndp_stop( eipm_intf_idx, sn_idx );

			*eipm_status_ptr = EIPM_INHIBITED;
			break;
	
		} /* switch(arpndp_state) */
	}
	else
	{
		EIPM_LOG_ERROR( 0, "Error: EIPM_arpndp_get_status() - ARPNDP_get_sess_state() returned failure=%d for eipm_intf_idx=%d, sn_idx=%d, os_intf_idx=%d\n", arpndp_retval, eipm_intf_idx, sn_idx, os_intf_idx );

		/* Make sure it's stopped since it has problems */
		(void)EIPM_arpndp_stop( eipm_intf_idx, sn_idx );

		*eipm_status_ptr = EIPM_INHIBITED;
	}

	return retval;

} /* EIPM_arpndp_get_status() */		

int EIPM_arpndp_tout()
{
	EIPM_DATA		*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	EIPM_INTF		*intf_ptr;
	EIPM_INTF_SPEC		*intfSpecDataP;
	int			intf_idx;
	int			num_intfs;

	/* ARPNDP_timer() is called by EIPM_bfd_tout(), do not duplicate it here */

	num_intfs = shm_ptr->intf_cnt;

	/* Handle the timeout for all interfaces. */
	for( intf_idx=0; intf_idx < num_intfs; intf_idx++ )
	{
		intf_ptr = &(shm_ptr->intf_data[intf_idx]);

		intfSpecDataP = &(intf_ptr->specData);

		if (intfSpecDataP->monitor == EIPM_MONITOR_IP)
		{
			(void)EIPM_arpndp_tout_intf(intf_ptr,intf_idx);
		}

	}

	return IPM_SUCCESS;

}

int EIPM_arpndp_tout_intf(EIPM_INTF *intf_ptr, int intf_idx)
{

	EIPM_INTF_SPEC		*intfSpecDataP;
	EIPM_SUBNET		*sn_ptr;
	int			sn_idx;
	int			num_sns;

	num_sns = intf_ptr->subnet_cnt;

	for (sn_idx=0; sn_idx < num_sns; sn_idx++)
	{
		sn_ptr = &(intf_ptr->subnet[sn_idx]);

		if (sn_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP)
		{
			(void)EIPM_arpndp_tout_sn(intf_ptr,sn_idx);
		}

	}

	intfSpecDataP = &(intf_ptr->specData);

	/* Update interface status based on subnets statuses if subnets are present */
	if (num_sns > 0)
	{
		int		num_null = 0;
		int		num_unknown = 0;
		int		num_online = 0;
		int		num_degraded = 0;
		int		num_offline = 0;
		int		num_inhibited = 0;
		int		num_other = 0;
		bool		all_same_status = TRUE;
		EIPM_STATUS	prev_sn_status, curr_sn_status = EIPM_STAT_NULL;
		EIPM_STATUS	curr_intf_status, next_intf_status = EIPM_STAT_NULL;

		sn_ptr = &(intf_ptr->subnet[0]);

		/*
		 * Subnets with redundancy mode ARPNDP and NONE can coexist in the same interface.
		 * For interface status determination, a NONE subnet with status NULL counts as ONLINE.
		 */
		if ((sn_ptr->redundancy_mode == IPM_RED_NONE) && (sn_ptr->status == EIPM_STAT_NULL))
		{
			prev_sn_status = EIPM_ONLINE;
		}
		else
		{
			prev_sn_status = sn_ptr->status;
		}

		for (sn_idx=0; sn_idx < num_sns; sn_idx++)
		{
			sn_ptr = &(intf_ptr->subnet[sn_idx]);

			if ((sn_ptr->redundancy_mode == IPM_RED_NONE) && (sn_ptr->status == EIPM_STAT_NULL))
			{
				curr_sn_status = EIPM_ONLINE;
			}
			else
			{
				curr_sn_status = sn_ptr->status;
			}

			switch (curr_sn_status)
			{
			case EIPM_STAT_NULL:	num_null++;
						break;
	
			case EIPM_UNKNOWN:	num_unknown++;
						break;
	
			case EIPM_ONLINE:	num_online++;
						break;
	
			case EIPM_DEGRADED:	num_degraded++;
						break;
	
			case EIPM_OFFLINE:	num_offline++;
						break;
	
			case EIPM_INHIBITED:	num_inhibited++;
						break;
	
			default:		/* Report and treat as OFFLINE */
						EIPM_LOG_ERROR( 0, "Error: %s - invalid status %d for Intf %d, Subnet %d\n", __FUNCTION__, curr_sn_status, intf_idx, sn_idx );
						curr_sn_status = EIPM_OFFLINE;
						num_other++;
						break;
			}

			if (curr_sn_status != prev_sn_status)
			{
				all_same_status = FALSE;
			}

			prev_sn_status = curr_sn_status;
	
		} /* end 'for each subnet in current interface' */
	
		if ( all_same_status == TRUE )
		{
			/* All subnets have same status so make interface match */
			next_intf_status = curr_sn_status;
		}
		else
		{
			/* Subnets have various statuses so apply propagation rules */
			if ((num_online + num_null) == num_sns)
			{
				next_intf_status = EIPM_ONLINE;
			}
			else if (num_online != 0)
			{
				/* At least one but not all subnets is online */
				next_intf_status = EIPM_DEGRADED;
			}
			else if (num_degraded != 0)
			{
				/* No subnets online but at least one is degraded */
				next_intf_status = EIPM_DEGRADED;
			}
			else if (num_offline != 0)
			{
				/* No subnets online or degraded but at least one
				 * is offline so the interface is not NULL, UNKNOWN,
				 * or INHIBITED.
				 */
				next_intf_status = EIPM_OFFLINE;
			}
			else if (num_null != 0)
			{
				/* No subnets online, degraded, or offline but
				 * at least one is null so the interface is
				 * not UNKNOWN or INHIBITED.
				 */
				next_intf_status = EIPM_STAT_NULL;
			}
			else if (num_unknown != 0)
			{
				/* No subnets online, degraded, offline, or
				 * null but at least one is unknown so the
				 * interface is not INHIBITED.
				 */
				next_intf_status = EIPM_UNKNOWN;
			}
			else if (num_inhibited != 0)
			{
				/* No subnets online, degraded, offline, null,
				 * or unknown and at least one is inhibited so
				 * the interface is INHIBITED.
				 */
				next_intf_status = EIPM_INHIBITED;
			}
			else if (num_other != 0)
			{
				/* No subnets online, degraded, offline, null,
				 * unknown, or inhibited and at least one is
				 * some other status so treat the interface
				 * as OFFLINE.
				 */
				next_intf_status = EIPM_OFFLINE;
			}
		}

		curr_intf_status = intfSpecDataP->status;

		if (curr_intf_status != next_intf_status)
		{
    			// LOG_OTHER( 0, "%s changing Intfc %d status from %d to %d\n", __FUNCTION__, intf_idx, curr_intf_status, next_intf_status );

			intfSpecDataP->status = next_intf_status;

			EIPM_report_status();
		}

	}

	return IPM_SUCCESS;

}

int EIPM_arpndp_tout_sn( EIPM_INTF *intf_ptr, int sn_idx )
{
	/* Gets called once for every IPM_RED_EIPM_ARPNDP subnet
	 * in the current EIPM_INTF interface.
	 */

	EIPM_INTF_SPEC		*intfSpecDataP;
	int			intf_idx;
	EIPM_SUBNET		*sn_ptr = &(intf_ptr->subnet[sn_idx]);
	EIPM_STATUS		arpndp_status;

	if (sn_ptr->ip_cnt == 0)
	{
		return IPM_SUCCESS;
	}

	intfSpecDataP = &(intf_ptr->specData);
	intf_idx = intfSpecDataP->baseIntfIdx;

	(void) EIPM_arpndp_get_status( intf_idx, sn_idx, &arpndp_status );

	if (arpndp_status != sn_ptr->status)
	{
		if (arpndp_status == EIPM_OFFLINE)
		{
			/* ARP/NDP has failed, set alarm */
			EIPM_arpndp_alarm_sn_set(intf_ptr,sn_idx);
		}
		else if (arpndp_status == EIPM_ONLINE)
		{
			/* ARP/NDP has succeeded, clear alarm */
			EIPM_arpndp_alarm_sn_clr(intf_ptr,sn_idx);

			EIPM_SET_GRAT_ARP( sn_ptr, sn_ptr->sub2intf_mapping[0].route_priority);
		}

		sn_ptr->status = arpndp_status;
		sn_ptr->arpndp_status = arpndp_status;
	}

	return IPM_SUCCESS;

}

void EIPM_arpndp_alarm_sn_set( EIPM_INTF *intf_ptr, int sn_idx )
{
	char		*baseif_ptr;
	char		linebuf[256];
	char		gateway_addr[IPM_IPMAXSTRSIZE];
	EIPM_SUBNET	*sn_ptr = &(intf_ptr->subnet[sn_idx]);

	if ( (intf_ptr->lsn0_baseif[0] != 0) &&
	     (strlen(intf_ptr->lsn0_baseif) != 0) )
	{
		baseif_ptr = intf_ptr->lsn0_baseif;
	}
	else
	{
		baseif_ptr = intf_ptr->lsn1_baseif;
	}

	memset(gateway_addr, 0, sizeof(gateway_addr));
	IPM_ipaddr2p(&sn_ptr->gateway, gateway_addr, IPM_IPMAXSTRSIZE);

	sprintf( linebuf, "Lost connectivity on interface %s to Next Hop IP: %s", baseif_ptr, gateway_addr );

	EIPM_SEND_SUBNET_ALARM(
		EIPM_NEXTHOP_FAIL,
		1,
		intf_ptr,
		EIPM_BASE_INTF,
		sn_idx,
		FSAS_critical,
		baseif_ptr,
		linebuf
	);

	return;
}

void EIPM_arpndp_alarm_sn_clr( EIPM_INTF *intf_ptr, int sn_idx )
{

	EIPM_CLEAR_SUBNET_ALARM(
		intf_ptr, 
		 EIPM_BASE_INTF, 
		 sn_idx, 
		 EIPM_NEXTHOP_FAIL
	);

	return;
}
