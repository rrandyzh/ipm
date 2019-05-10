/**********************************************************************
 *
 * File:
 *      EIPM_bfd.c
 *
 * Abstract:
 *	Contains the EIPM functions that, in combination with the code in
 *	the bfd sub-directory, implement Bidirectional Forward Detection
 *	(BFD) redundancy mode.
 *
 *   Description:
 *
 *	BFD consists of:
 *
 *		a) Transport Subnets	(aka "BFD Transport Subnets")
 *		b) Sessions		(aka "BFD Sessions")
 *		c) Service Subnets	(aka "BFD Subnets")
 *
 *	A BFD Transport Subnet consists of M local IP addresses and 1
 *	remote IP address (on the Customer Endpoint router) and provides
 *	the transport mechanism between those pairs of endpoints. M could
 *	be any number. 2 might, for example, indicate the presence of 1
 *	Fixed and 1 Floating IP addresses, but at this level we don't know
 *	that - it's just 2 local IP addresses. A BFD Tranport Subnet will
 *	have a redundacy mode of IPM_RED_BFD_TRANSPORT.
 *
 *	A BFD Session is established over one BFD Transport Subnet, is
 *	associated with just one of the local IP addresses of that BFD
 *	Transport Subnet, and uses an exchange of BFD control packets
 *	to determine if that Session is Online or Offline. This is the
 *	level at which the FSM in the bfd sub-drectory operates.
 *
 *	A BFD Service Subnet consists of 1 local IP address and a
 *	relationship with N BFD Transport Subnets and uses them redundantly
 *	to provide service for a given protocol that uses BFD redundancy
 *	mode, e.g. S10 or S11. If all BFD Sessions are Offline, a BFD
 *	Service Subnet will employ ARP/ND to determine connectivity
 *	and only declare itself Offline if that also fails, otherwise
 *	it will be Online. A BFD Service Subnet will have a redundacy
 *	mode of IPM_RED_EIPM_BFD.
 *
 *      The way these concepts are represented in our data is described
 *	in detail at the bottom of this file.
 *
 * Functions in this file:
 *
 *   Administrative (i.e. can be invoked from CLI):
 *
 *	EIPM_bfd_admin_create_sess() 	 - populate data for a BFD session
 *	EIPM_bfd_admin_destroy_sess()	 - zap data for a BFD session
 *	EIPM_bfd_admin_change_cfg_sess() - change data for a BFD session
 *	EIPM_bfd_admin_set_state_sess()	 - set session admin state to up or down.
 *
 *   BFD Sessions FSM init, packet reception, and call-backs:
 *
 *	EIPM_bfd_fsm_init()	      - start or restart the BFD sessions FSM.
 *	EIPM_bfd_fsm_start()	      - start/initialize the BFD sessions FSM.
 *	EIPM_bfd_fsm_restart()	      - restart the BFD sessions FSM.
 *	EIPM_bfd_fsm_add_sockets()    - add socket to the list pselect() checks.
 *	EIPM_bfd_fsm_recv()	      - tell BFD FSM that a message is received.
 *	EIPM_bfd_fsm_cb_audit_sess()  - Call-back from BFD Session FSM to check
 *					if a session the BFD FSM thinks exists
 *					also exists in the EIPM data.
 *
 *   Utility:
 *
 *	EIPM_bfd_init_subnet_map()    - Init a mapping of BFD subnets.
 *	EIPM_bfd_bld_subnet_map()     - Build a mapping of BFD Services subnets
 *					to both Left and Right BFD Transport
 *					subnets.
 *	EIPM_bfd_get_subnet_map()     - Access the subnet_map data for a given
 *					interface+subnet pair.
 *	EIPM_bfd_bld_sessions_list()  - build an array of Service, Left, and
 *					Right subnets used to audit their data.
 *	EIPM_bfd_admin_state_valid()  - Checks if a given admin state is valid.
 *	EIPM_bfd_dump_sessions()      - Dumps information for all sessions
 *					in the given subnet.
 *	EIPM_bfd_dump_sess()	      - Dumps information for a given session.
 *
 *   IP Configuration:
 *
 *	EIPM_bfd_ipcfg_check_sn()     - check IP plumbing for a BFD Subnet as
 *					represented in EIPM_INTF structures
 *					against the OS representation in the
 *					IPM_IPTBL table. Update the OS table
 *					if necssary.
 *
 *   Alarms:
 *
 *	EIPM_bfd_alarm_sess_set()     - Set an alarm for a BFD Session.
 *	EIPM_bfd_alarm_sess_set_down() - Set an alarm for a BFD Session down.
 *	EIPM_bfd_alarm_sess_clr()     - Clear an alarm for a BFD Session.
 *	EIPM_bfd_alarm_tran_sn_set()  - Set an alarm for a BFD Transport Subnet.
 *	EIPM_bfd_alarm_tran_sn_set_no_sess() - Set an alarm for a BFD
 *					Transport Subnet that has no
 *					BFD Sessions provisioned.
 *	EIPM_bfd_alarm_tran_sn_set_sess_down() - Set an alarm for a BFD
 *					Transport Subnet that has all
 *					BFD Sessions down.
 *	EIPM_bfd_alarm_tran_sn_clr()  - Clear an alarm for a BFD Transport Sn.
 *	EIPM_bfd_alarm_svc_sn_set()   - Set an alarm for a BFD Service Subnet.
 *	EIPM_bfd_alarm_svc_sn_set_miss_tran() - Set an alarm for a BFD Service
 *					Subnet that has has fewer than 2 BFD
 *					Transport Subnets provisioned.
 *	EIPM_bfd_alarm_svc_sn_clr_miss_tran() - Clear an alarm for a BFD Service
 *					Subnet that has has fewer than 2 BFD
 *					Transport Subnets provisioned.
 *	EIPM_bfd_alarm_svc_sn_chk_miss_tran() - Check for fewer than 2 BFD
 *					Transport Subnets provisioned and
 *					either set or clear the alarm.
 *	EIPM_bfd_alarm_svc_sn_set_tran_down() - Set an alarm for a BFD Service
 *					Subnet that has all BFD Transport
 *					Subnets down.
 *	EIPM_bfd_alarm_svc_sn_clr_tran_down() - Clear an alarm for a BFD Service
 *					Subnet that has all BFD Transport
 *					Subnets down.
 *
 *
 *   Timeouts:
 *
 *	EIPM_bfd_tout()		      - all intfcs that contain BFD Subnet(s).
 *	EIPM_bfd_tout_intf()	      - 1 interface that contains BFD Subnet(s).
 *	EIPM_bfd_tout_transports()    - all BFD Transport sns on 1 Intfc.
 *	EIPM_bfd_tout_tran_sn()	      - 1 BFD Transport Subnet.
 *	EIPM_bfd_tout_sess()	      - 1 BFD Session on 1 BFD Transport Sn.
 *	EIPM_bfd_tout_services()      - all BFD Service sns on 1 Intfc.
 *	EIPM_bfd_tout_svc_sn()	      - 1 BFD Service Subnet.
 *
 *   Audits:
 *
 *	EIPM_bfd_audit()	      - all intfcs that contain BFD Subnet(s).
 *	EIPM_bfd_audit_intf()	      - 1 interface that contains BFD Subnet(s).
 *	EIPM_bfd_audit_transports()   - all BFD Transport sns on 1 Intfc.
 *	EIPM_bfd_audit_tran_sn()      - 1 BFD Transport Subnet.
 *	EIPM_bfd_audit_sess()	      - 1 BFD Session on 1 BFD Transport Sn.
 *	EIPM_bfd_audit_services()     - all BFD Service sns on 1 Intfc.
 *	EIPM_bfd_audit_svc_sn()	      - 1 BFD Service Subnet.
 *
 **********************************************************************/

#include "EIPM_bfd.h"
#include "EIPM_arpndp.h"

#define EIPM_BFD_DEBUG_SUBNET_MAP 0

#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
static int prev_dump_subnet_map = 0;
static int dump_subnet_map = 1;
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */

static int printed_subnet_map = 0;

static EIPM_BFD_SUBNET_MAP		bfd_subnet_map;
static EIPM_BFD_SESSIONS_LIST	bfd_sessions_list;

#define EIPM_BFD_LOG_IPV6 0

/* The intent of the following EIPM_bfd_admin_cfg_stable*() functions is to
 * give us a way to check whether or not a BFD Session or BFD Transport
 * Subnet or BFD Service Subnet has been newly configured so that, for
 * example, we can decide not to generate an alarm if the given entity is
 * OFFLINE but it's just been newly provisioned or re-configured and so
 * give the BFD or ARPNDP Session(s) a chance to come up.
 */
bool EIPM_bfd_admin_cfg_stable_sess(
		int		intf_idx,
		int		subnet_idx,
		EIPM_IPDATA	*ipdata_ptr
	)
{
	/* Returns TRUE if the BFD Session has been configured
	 * long enough ago that it should be stable, FALSE otherwise.
	 */
	bool		is_stable;

	is_stable = EIPM_check_ip_config_time(ipdata_ptr, EIPM_IP_BFD_CONFIG_TIMEOUT);

	return is_stable;

} /* EIPM_bfd_admin_cfg_stable_sess() */

bool EIPM_bfd_admin_cfg_stable_tran(
		int		intf_idx,
		int		subnet_idx
	)
{
	/* Returns TRUE if the BFD Transport Subnet has been configured
	 * long enough ago that it should be stable, FALSE otherwise.
	 */
	EIPM_DATA	*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	EIPM_INTF	*intf_ptr;
	EIPM_SUBNET	*subnet_ptr;
	EIPM_IPDATA	*ipdata_ptr;
	bool		is_stable = FALSE;

	intf_ptr	= &(shm_ptr->intf_data[intf_idx]);
	subnet_ptr	= &intf_ptr->subnet[subnet_idx];

	if (subnet_ptr->ip_cnt > 0)
	{
		ipdata_ptr = &(subnet_ptr->ips[0]);
		is_stable = EIPM_check_ip_config_time(ipdata_ptr, EIPM_IP_BFD_CONFIG_TIMEOUT);
	}

	return is_stable;

} /* EIPM_bfd_admin_cfg_stable_tran() */

bool EIPM_bfd_admin_cfg_stable_svc(
		int		intf_idx,
		int		subnet_idx
	)
{
	/* Returns TRUE if the BFD Service Subnet has been configured
	 * long enough ago that it should be stable, FALSE otherwise.
	 *
	 * NOTE: this function relies on the subnet map structure
	 * (bfd_subnet_map) having been populated so it can access the
	 * data for the Left and Right BFD Transports. The BFD Service
	 * subnet is only stable if it's own IP addr and both associated
	 * BFD Transports are stable.
	 */
	EIPM_DATA	*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	EIPM_INTF	*intf_ptr;
	EIPM_SUBNET	*subnet_ptr;
	EIPM_IPDATA	*ipdata_ptr;

	int		left_intf_idx;
	int		left_sn_idx;

	int		right_intf_idx;
	int		right_sn_idx;

	IPM_RETVAL	retval;
	bool		left_is_stable = FALSE;
	bool		right_is_stable = FALSE;
	bool		is_stable = FALSE;

	intf_ptr	= &(shm_ptr->intf_data[intf_idx]);
	subnet_ptr	= &intf_ptr->subnet[subnet_idx];

	if (subnet_ptr->ip_cnt > 0)
	{
		ipdata_ptr = &(subnet_ptr->ips[0]);
		is_stable = EIPM_check_ip_config_time(ipdata_ptr, EIPM_IP_BFD_CONFIG_TIMEOUT);
	}

	if (is_stable == TRUE)
	{
		retval = EIPM_bfd_map_svc2trans(
			intf_idx,
			subnet_idx,
			&left_intf_idx,
			&left_sn_idx,
			&right_intf_idx,
			&right_sn_idx
		);

		if (retval == IPM_SUCCESS)
		{

			/* We could be in an unstable (De)Growth state where
			 * we have a BFD Service subnet wihout one or both
			 * BFD Transport Subnets so make sure each transport
			 * subnet exists before trying to determing whether or
			 * not it is stable. If either transport doesn't
			 * exist then the BFD Service is not stable as it
			 * is not fully configured.
			 */
			if ( (left_intf_idx >= 0) && (left_sn_idx >= 0) )
			{
				left_is_stable = EIPM_bfd_admin_cfg_stable_tran(
						left_intf_idx, left_sn_idx );
			}

			if ( (right_intf_idx >= 0) && (right_sn_idx >= 0) )
			{
				right_is_stable = EIPM_bfd_admin_cfg_stable_tran(
						right_intf_idx, right_sn_idx );
			}

			if ( (left_is_stable == FALSE) || (right_is_stable == FALSE) )
			{
				is_stable = FALSE;
			}
		}
		else
		{
			EIPM_LOG_ERROR( 0,
				"%s(): EIPM_bfd_map_svc2trans() failed for intf_idx %d subnet_idx %d with error [%d]\n",
				__FUNCTION__,
				intf_idx,
				subnet_idx,
				retval
			);
		}
	}

	return is_stable;

} /* EIPM_bfd_admin_cfg_stable_svc() */

bool EIPM_bfd_admin_cfg_ready4audit_svc(
		int		intf_idx,
		int		subnet_idx
	)
{
	/* Returns TRUE if the BFD Service Subnet has been configured
	 * long enough ago that it is ready to be audited, FALSE otherwise.
	 *
	 * The BFD Service subnet is ready to be audited if it's own IP
	 * addr has been provisioned at least as long ago as the audit
	 * interval (15 mins).
	 */
	EIPM_DATA	*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	EIPM_INTF	*intf_ptr;
	EIPM_SUBNET	*subnet_ptr;
	EIPM_IPDATA	*ipdata_ptr;

	bool		is_ready = FALSE;

	intf_ptr	= &(shm_ptr->intf_data[intf_idx]);
	subnet_ptr	= &intf_ptr->subnet[subnet_idx];

	if (subnet_ptr->ip_cnt > 0)
	{
		ipdata_ptr = &(subnet_ptr->ips[0]);
		is_ready = EIPM_check_ip_audit_time(ipdata_ptr);
	}

	return is_ready;

} /* EIPM_bfd_admin_cfg_ready4audit_svc() */

int EIPM_bfd_admin_change_cfg_sess(
		int		intf_idx,
		int		subnet_idx,
		IPM_IPADDR	*local_ip_ptr
	)

{
	EIPM_DATA	*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	EIPM_INTF	*intf_ptr;
	EIPM_SUBNET	*subnet_ptr;
	IPM_IPADDR	*remote_ip_ptr;
	uint8_t		detection_multiplier;
	uint32_t	desired_min_tx_interval;
	uint32_t	required_min_rx_interval;

	char		local_ip_addr[IPM_IPMAXSTRSIZE];
	char		remote_ip_addr[IPM_IPMAXSTRSIZE];
	BFD_RETVAL	bfd_retval;
	IPM_RETVAL	arpndp_retval;
	IPM_RETVAL	retval;

	intf_ptr		 = &(shm_ptr->intf_data[intf_idx]);
	subnet_ptr		 = &intf_ptr->subnet[subnet_idx];
	remote_ip_ptr 		 = &(subnet_ptr->gateway);
	detection_multiplier	 = subnet_ptr->detection_multiplier;
	desired_min_tx_interval	 = subnet_ptr->desired_min_tx_interval;
	required_min_rx_interval = subnet_ptr->required_min_rx_interval;

	bfd_retval = BFD_change_cfg(
		local_ip_ptr,
		remote_ip_ptr,
		detection_multiplier,
		desired_min_tx_interval,
		required_min_rx_interval
	);

	if ( bfd_retval == BFD_SUCCESS )
	{
		/* Save the return code for debugging, but just base
		 * status on whether or not BFD succeeded, not ARP/NDP.
		 */
		arpndp_retval = EIPM_arpndp_admin_change_cfg_sess(
			intf_idx,
			subnet_ptr,
			&(subnet_ptr->ips[0])
		    );

		if (arpndp_retval != ARPNDP_SUCCESS)
		{
			EIPM_LOG_ERROR( 0,
				"%s(): EIPM_arpndp_admin_change_cfg_sess() failed for intf_idx %d subnet_idx %d with error [%d]\n",
				__FUNCTION__,
				intf_idx,
				subnet_idx,
				arpndp_retval
			);
		}

		retval = IPM_SUCCESS;
	}
	else
	{
		memset(local_ip_addr, 0, sizeof local_ip_addr);
		IPM_ipaddr2p(local_ip_ptr, local_ip_addr, IPM_IPMAXSTRSIZE);

		memset(remote_ip_addr, 0, sizeof remote_ip_addr);
		IPM_ipaddr2p(remote_ip_ptr, remote_ip_addr, IPM_IPMAXSTRSIZE);

		EIPM_LOG_ERROR( 0,
			"%s(): BFD_change_cfg( %s, %s, %u, %u, %u ) failed [%d]\n",
			__FUNCTION__,
			(local_ip_addr[0] != '\0' ? local_ip_addr : "empty"),
			(remote_ip_addr[0] != '\0' ? remote_ip_addr : "empty"),
			detection_multiplier,
			desired_min_tx_interval,
			required_min_rx_interval,
			bfd_retval
		);

		retval = IPM_FAILURE;
	}

	return retval;

} /* EIPM_bfd_admin_change_cfg_sess() */

int EIPM_bfd_admin_create_sess(
		int		intf_idx,
		int		subnet_idx,
		IPM_IPADDR	*local_ip_ptr
		,IPM_REDUNDANCY_MODE red_mode
	)

{
	EIPM_DATA	*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	EIPM_INTF	*intf_ptr;
	EIPM_SUBNET	*subnet_ptr;
	IPM_IPADDR	*remote_ip_ptr;
	uint8_t		detection_multiplier;
	uint32_t	desired_min_tx_interval;
	uint32_t	required_min_rx_interval;

	char		local_ip_addr[IPM_IPMAXSTRSIZE];
	char		remote_ip_addr[IPM_IPMAXSTRSIZE];
	BFD_RETVAL	bfd_retval;
	IPM_RETVAL	arpndp_retval;
	IPM_RETVAL	retval;

	intf_ptr		 = &(shm_ptr->intf_data[intf_idx]);
	subnet_ptr		 = &intf_ptr->subnet[subnet_idx];
	remote_ip_ptr 		 = &(subnet_ptr->gateway);
	detection_multiplier	 = subnet_ptr->detection_multiplier;
	desired_min_tx_interval	 = subnet_ptr->desired_min_tx_interval;
	required_min_rx_interval = subnet_ptr->required_min_rx_interval;

	bfd_retval = BFD_create_sess(
		local_ip_ptr,
		remote_ip_ptr,
		detection_multiplier,
		desired_min_tx_interval,
		required_min_rx_interval
	);

	if (EIPM_is_bfd_trans_rsr_svc_sn(intf_idx, subnet_idx) == IPM_SUCCESS)
	{
		bfd_retval = BFD_set_admin_state(
				local_ip_ptr,
				remote_ip_ptr,
				BFD_ADMIN_STATE_DOWN
			);
	}

	if ( bfd_retval == BFD_SUCCESS )
	{
		/*
		LOG_FORCE( 0,
			"BFD_DEBUG: %s(): BFD_create_sess() succeeded for intf_idx %d subnet_idx %d with ip_cnt=%d\n",
			__FUNCTION__,
			intf_idx,
			subnet_idx,
			subnet_ptr->ip_cnt
		);
		*/

		if ( subnet_ptr->ip_cnt == 1 )
		{
			/* Creating the first BFD Session in this
			 * BFD Transport subnet so create the ARP/NDP
			 * session too.
			 */

			/* Save the return code for debugging, but just base
			 * status on whether or not BFD succeeded, not ARP/NDP.
			 */
			arpndp_retval = EIPM_arpndp_admin_create_sess(
				intf_idx,
				subnet_ptr,
				local_ip_ptr
			    );

			if (arpndp_retval != ARPNDP_SUCCESS)
			{
				EIPM_LOG_ERROR( 0,
					"%s(): EIPM_arpndp_admin_create_sess() failed for intf_idx %d subnet_idx %d with error [%d]\n",
					__FUNCTION__,
					intf_idx,
					subnet_idx,
					arpndp_retval
				);
			}
			/*
			else
			{
				LOG_FORCE( 0,
					"BFD_DEBUG: %s(): EIPM_arpndp_admin_create_sess() succeeded for intf_idx %d subnet_idx %d with ip_cnt=%d\n",
					__FUNCTION__,
					intf_idx,
					subnet_idx,
					subnet_ptr->ip_cnt
				);
			}
			*/
		}

		retval = IPM_SUCCESS;
	}
	else
	{
		memset(local_ip_addr, 0, sizeof local_ip_addr);
		IPM_ipaddr2p(local_ip_ptr, local_ip_addr, IPM_IPMAXSTRSIZE);

		memset(remote_ip_addr, 0, sizeof remote_ip_addr);
		IPM_ipaddr2p(remote_ip_ptr, remote_ip_addr, IPM_IPMAXSTRSIZE);

		EIPM_LOG_ERROR( 0,
			"%s(): BFD_create_sess( %s, %s, %u, %u, %u ) failed [%d]\n",
			__FUNCTION__,
			(local_ip_addr[0] != '\0' ? local_ip_addr : "empty"),
			(remote_ip_addr[0] != '\0' ? remote_ip_addr : "empty"),
			detection_multiplier,
			desired_min_tx_interval,
			required_min_rx_interval,
			bfd_retval
		);

		retval = IPM_FAILURE;
	}

	return retval;

} /* EIPM_bfd_admin_create_sess() */

int EIPM_bfd_admin_destroy_sess( 
		int		intf_idx,
		int		subnet_idx,
		IPM_IPADDR	*local_ip_ptr
	)
{
	EIPM_DATA	*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	EIPM_INTF	*intf_ptr;
	EIPM_SUBNET	*subnet_ptr;
	IPM_IPADDR	*remote_ip_ptr;
	IPM_RETVAL	arpndp_retval;

	intf_ptr = &(shm_ptr->intf_data[intf_idx]);
	subnet_ptr = &intf_ptr->subnet[subnet_idx];
	remote_ip_ptr = &(subnet_ptr->gateway);

	BFD_destroy_sess( local_ip_ptr, remote_ip_ptr );

	if ( local_ip_ptr == &(subnet_ptr->ips[0]) )
	{
		/* We are about to remove the IP addr that identifies
		 * the local end of our ARP/NDP session so stop the
		 * associated ARP/NDP session if there are no IPs left
		 * in this subnet or change to use the next IP which
		 * will be suffled down afterwards by the calling
		 * deletion code.
		 */
		if (subnet_ptr->ip_cnt > 1)
		{
			/* Save the return code for debugging, but just base
			 * status on whether or not BFD succeeded, not ARP/NDP.
			 */

			arpndp_retval = EIPM_arpndp_admin_change_cfg_sess(
				intf_idx,
				subnet_ptr,
				&(subnet_ptr->ips[1])
			    );

			if (arpndp_retval != ARPNDP_SUCCESS)
			{
				EIPM_LOG_ERROR( 0,
					"%s(): EIPM_arpndp_admin_change_cfg_sess() failed for intf_idx %d subnet_idx %d with error [%d]\n",
					__FUNCTION__,
					intf_idx,
					subnet_idx,
					arpndp_retval
				);
			}
		}
		else
		{
			EIPM_arpndp_admin_destroy_sess( intf_idx, remote_ip_ptr );
		}
	}

	// LOG_FORCE( 0, "BFD_DEBUG: %s() Exiting for intf_idx %d, subnet_idx %d, ip_cnt %d\n",
		// __FUNCTION__, intf_idx, subnet_idx, subnet_ptr->ip_cnt );

	return IPM_SUCCESS;

} /* EIPM_bfd_admin_destroy_sess() */

int EIPM_bfd_admin_set_state_sess( 
		int		intf_idx,
		int		subnet_idx,
		EIPM_IPDATA	*ipdata_ptr,
		BFD_ADMIN_STATE	state
	)
{
	EIPM_DATA	*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	EIPM_INTF	*intf_ptr;
	EIPM_SUBNET	*subnet_ptr;
	IPM_IPADDR	*remote_ip_ptr;
	IPM_IPADDR	*local_ip_ptr;
	char		local_ip_addr[IPM_IPMAXSTRSIZE];
	char		remote_ip_addr[IPM_IPMAXSTRSIZE];
	BFD_RETVAL	bfd_retval;
	IPM_RETVAL	arpndp_retval;
	IPM_RETVAL	retval;

	intf_ptr = &(shm_ptr->intf_data[intf_idx]);
	subnet_ptr = &intf_ptr->subnet[subnet_idx];
	remote_ip_ptr = &(subnet_ptr->gateway);
	local_ip_ptr = &(ipdata_ptr->ipaddr);

	bfd_retval = BFD_set_admin_state(
			local_ip_ptr,
			remote_ip_ptr,
			state
		);

	memset(local_ip_addr, 0, sizeof local_ip_addr);
	IPM_ipaddr2p(local_ip_ptr, local_ip_addr, IPM_IPMAXSTRSIZE);

	memset(remote_ip_addr, 0, sizeof remote_ip_addr);
	IPM_ipaddr2p(remote_ip_ptr, remote_ip_addr, IPM_IPMAXSTRSIZE);

	if ( bfd_retval != BFD_SUCCESS )
	{
		LOG_CRAFT( 0,
			"%s() - BFD_set_admin_state( %s, %s, %d ) failed with error [%d]\n",
			__FUNCTION__,
			(local_ip_addr[0] != '\0' ? local_ip_addr : "empty"),
			(remote_ip_addr[0] != '\0' ? remote_ip_addr : "empty"),
			(int)state,
			bfd_retval
		    );

		retval = IPM_FAILURE;
	}
	else
	{
		LOG_CRAFT(
			0,
			"%s() - BFD admin state for ip %s, gateway %s, admin state %d\n",
			__FUNCTION__,
			(local_ip_addr[0] != '\0' ? local_ip_addr : "empty"),
			(remote_ip_addr[0] != '\0' ? remote_ip_addr : "empty"),
			(int)state
		);

		retval = IPM_SUCCESS;
	}

	EIPM_set_ip_config_time(ipdata_ptr);

	return retval;

} /* EIPM_bfd_admin_set_state_sess() */

int EIPM_bfd_dump_sessions(
		EIPM_INTF	*intf_ptr,
		int		subnet_idx,
		IPM_IPADDR	*subnet_base_ptr,
		IPM_IPADDR	*ip_ptr,
		IPM_IPADDR	*gateway_ptr,
		int		check_ip,
		bool		*found_ip_ptr
	)
{
	int		intf_idx;

	EIPM_SUBNET	*subnet_ptr;

	EIPM_IPDATA	*ipdata_ptr;
	int		ip_idx;

	char		ip_addr[IPM_IPMAXSTRSIZE];
	char		gateway_addr[IPM_IPMAXSTRSIZE];
	BFD_RETVAL	bfd_retval;
	IPM_RETVAL	arpndp_retval;
	IPM_RETVAL	retval = IPM_SUCCESS;

	BFD_SESS_STATE	sess_state;
	unsigned int	missed_hb;  

	*found_ip_ptr = FALSE;

	subnet_ptr = &intf_ptr->subnet[subnet_idx];

	if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode != IPM_RED_BFD_TRANSPORT )
	{
		return IPM_SUCCESS;
	}

	/* check if want to check a certain bfd session */
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

		retval = EIPM_bfd_dump_sess( intf_ptr, subnet_idx, ip_idx );

		if (retval != IPM_SUCCESS)
		{
			break;
		}

	}

	return retval;

} /* EIPM_bfd_dump_sessions() */

int EIPM_bfd_dump_sess(
		EIPM_INTF	*intf_ptr,
		int		subnet_idx,
		int		ip_idx
	)
{
	EIPM_INTF_SPEC	*intfSpecDataP;
	int		intf_idx;
	EIPM_SUBNET	*subnet_ptr;
	IPM_IPADDR	*ip_ptr;

	EIPM_IPDATA	*ipdata_ptr;

	char		ip_addr[IPM_IPMAXSTRSIZE];
	char		gateway_addr[IPM_IPMAXSTRSIZE];
	BFD_RETVAL	bfd_retval;
	IPM_RETVAL	arpndp_retval;
	IPM_RETVAL	retval = IPM_SUCCESS;

	BFD_SESS_STATE	sess_state;
	unsigned int	missed_hb;  
	unsigned int	corrupt_pkt;  

	intfSpecDataP = &(intf_ptr->specData);

	intf_idx = intfSpecDataP->baseIntfIdx;

	subnet_ptr = &intf_ptr->subnet[subnet_idx];
	ipdata_ptr = &(subnet_ptr->ips[ip_idx]);
	ip_ptr = &(ipdata_ptr->ipaddr);

	memset(gateway_addr, 0, sizeof(gateway_addr));
	IPM_ipaddr2p(&subnet_ptr->gateway, gateway_addr, IPM_IPMAXSTRSIZE);

	memset(ip_addr, 0, sizeof(ip_addr));
	IPM_ipaddr2p(ip_ptr, ip_addr, IPM_IPMAXSTRSIZE);

	bfd_retval = BFD_get_sess_state( ip_ptr, &subnet_ptr->gateway,
						&sess_state );

	if ( bfd_retval != BFD_SUCCESS )
	{
		LOG_CRAFT( 0,
			"%s() - BFD_get_sess_state( %s, %s ) failed with error [%d]\n",
			__FUNCTION__,
			ip_addr,
			gateway_addr,
			bfd_retval
		);

		retval = IPM_FAILURE;
	}
	else
	{
		LOG_CRAFT(
			0,
			"%s() - BFD session state for ip %s, gateway %s, session state %d\n",
			__FUNCTION__,
			ip_addr,
			gateway_addr,
			sess_state
		);
	}

	bfd_retval = BFD_get_stats(
		ip_ptr,
		&subnet_ptr->gateway,
		&missed_hb,
		&corrupt_pkt
	);

	if ( bfd_retval != BFD_SUCCESS )
	{
		LOG_CRAFT( 0,
			"%s() - BFD_get_stats( %s, %s ) failed with error [%d]\n",
			__FUNCTION__,
			ip_addr,
			gateway_addr,
			bfd_retval
		);

		retval = IPM_FAILURE;
	}
	else
	{
		LOG_CRAFT(
			0,
			"%s() - BFD session stats for ip %s, gateway %s, missed hb %u, corrupt_pkt %u\n",
			__FUNCTION__,
			ip_addr,
			gateway_addr,
			missed_hb,
			corrupt_pkt
		);
	}

	/* print the session parameters */
	LOG_CRAFT(
		0,
		"%s() - BFD session parameters for ip %s, gateway %s\n"
		"\tdetection multiplier: %u\n"
		"\tdesired min tx interval: %u\n"
		"\trequired min rx interval: %u\n", 
		__FUNCTION__,
		ip_addr,
		gateway_addr,
		subnet_ptr->detection_multiplier,
		subnet_ptr->desired_min_tx_interval,
		subnet_ptr->required_min_rx_interval
	);

	if ( ip_idx == 0 )
	{
		/* Save the return code for debugging, but just base
		 * status on whether or not BFD succeeded, not ARP/NDP.
		 */
		arpndp_retval = EIPM_arpndp_dump_sess(intf_ptr, subnet_idx);

		if (arpndp_retval != ARPNDP_SUCCESS)
		{
			EIPM_LOG_ERROR( 0,
				"%s(): EIPM_arpndp_dump_sess() failed for intf_idx %d subnet_idx %d with error [%d]\n",
				__FUNCTION__,
				intf_idx,
				subnet_idx,
				arpndp_retval
			);
		}
	}

	return retval;

} /* EIPM_bfd_dump_sess() */

bool EIPM_bfd_admin_state_valid(BFD_ADMIN_STATE state)
{
	bool	ret;

	if ( (state == BFD_ADMIN_STATE_DOWN) ||
	     (state == BFD_ADMIN_STATE_UP) )
	{
		ret = TRUE;
	}
	else
	{
		ret = FALSE;
	}

	return ret;

} /* EIPM_bfd_admin_state_valid() */

int EIPM_bfd_fsm_init(BFD_INIT_TYPE bfd_init_type)
{
	EIPM_DATA	*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	BFD_RETVAL	bfd_retval;
	int		retval;

	bfd_retval = BFD_init( EIPM_bfd_fsm_cb_audit_sess,
				/*state_change_cb_func*/ NULL,
				&(shm_ptr->bfd_data),
				bfd_init_type );

	if (bfd_retval == BFD_SUCCESS)
	{
		retval = IPM_SUCCESS;
	}
	else
	{
		retval = IPM_FAILURE;
	}

	return retval;

} /* EIPM_bfd_fsm_init() */

int EIPM_bfd_fsm_start()
{
	IPM_RETVAL	arpndp_retval;
	IPM_RETVAL	retval;

	retval = EIPM_bfd_fsm_init( BFD_INIT_TYPE_FULL );

	if (retval == IPM_SUCCESS)
	{
		/* Save the return code for debugging, but just base
		 * status on whether or not BFD succeeded, not ARP/NDP.
		 */
		arpndp_retval = EIPM_arpndp_fsm_init(ARPNDP_INIT_TYPE_FULL);

		if (arpndp_retval != ARPNDP_SUCCESS)
		{
			EIPM_LOG_ERROR( 0,
				"%s(): EIPM_arpndp_fsm_init(ARPNDP_INIT_TYPE_FULL) failed [%d].\n",
				__FUNCTION__,
				arpndp_retval
			);
		}
	}

	return retval;

} /* EIPM_bfd_fsm_init() */

int EIPM_bfd_fsm_restart()
{
	IPM_RETVAL	arpndp_retval;
	IPM_RETVAL	retval;

	retval = EIPM_bfd_fsm_init( BFD_INIT_TYPE_RESTART );

	if (retval == IPM_SUCCESS)
	{
		/* Save the return code for debugging, but just base
		 * status on whether or not BFD succeeded, not ARP/NDP.
		 */
		arpndp_retval = EIPM_arpndp_fsm_init(ARPNDP_INIT_TYPE_RESTART);

		if (arpndp_retval != ARPNDP_SUCCESS)
		{
			EIPM_LOG_ERROR( 0,
				"%s(): EIPM_arpndp_fsm_init(ARPNDP_INIT_TYPE_RESTART) failed [%d].\n",
				__FUNCTION__,
				arpndp_retval
			);
		}
	}

	return retval;

} /* EIPM_bfd_fsm_restart() */

int EIPM_bfd_fsm_add_sockets(fd_set *read_sock_set, int *max_sock)
{
	IPM_RETVAL	arpndp_retval;

	BFD_add_sockets(read_sock_set, max_sock);

	/* Save the return code for debugging, but just base
	 * status on whether or not BFD succeeded, not ARP/NDP.
	 */
	arpndp_retval = EIPM_arpndp_fsm_add_sockets(read_sock_set, max_sock);

	if (arpndp_retval != ARPNDP_SUCCESS)
	{
		EIPM_LOG_ERROR( 0,
			"%s(): EIPM_arpndp_fsm_add_sockets() failed [%d]\n",
			__FUNCTION__,
			arpndp_retval
		);
	}

	return IPM_SUCCESS;

} /* EIPM_bfd_fsm_add_sockets() */

int EIPM_bfd_fsm_recv(fd_set *read_sock_set)
{
	IPM_RETVAL	arpndp_retval;

	BFD_recv(read_sock_set);

	/* Save the return code for debugging, but just base
	 * status on whether or not BFD succeeded, not ARP/NDP.
	 */
	arpndp_retval = EIPM_arpndp_fsm_recv(read_sock_set);

	if (arpndp_retval != ARPNDP_SUCCESS)
	{
		EIPM_LOG_ERROR( 0,
			"%s(): EIPM_arpndp_fsm_recv() failed [%d]\n",
			__FUNCTION__,
			arpndp_retval
		);
	}

	return IPM_SUCCESS;

} /* EIPM_bfd_fsm_recv() */

void EIPM_bfd_get_stats()
{
	/* Retrieves AND CLEARS all of the stats kept by the BFD code
	 * but required for external use.
	 */

	/* Pointer to shared memory */
	EIPM_DATA		*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;

	register EIPM_INTF	*intf_ptr;
	EIPM_INTF_SPEC		*intfSpecDataP;
	int			intf_idx;
	int			num_intfs;

	num_intfs = shm_ptr->intf_cnt;

	/* Update the stats for all interfaces. */
	for( intf_idx=0; intf_idx < num_intfs; intf_idx++ )
	{
		intf_ptr = &(shm_ptr->intf_data[intf_idx]);

		intfSpecDataP = &(intf_ptr->specData);

		if (intfSpecDataP->monitor == EIPM_MONITOR_BFD)
		{
			(void)EIPM_bfd_get_stats_intf(intf_ptr);
		}

	} /* end 'for each monitored interface' */

	return IPM_SUCCESS;

} /* EIPM_bfd_get_stats() */

int EIPM_bfd_get_stats_intf(register EIPM_INTF *intf_ptr)
{
	/* Gets called once for every EIPM_INTF interface that uses
	 * BFD for redundancy.
	 */

	(void)EIPM_bfd_get_stats_transports(intf_ptr);

	return IPM_SUCCESS;

} /* EIPM_bfd_get_stats_intf() */

int EIPM_bfd_get_stats_transports(register EIPM_INTF *intf_ptr)
{
	/* Gets called once for every EIPM_INTF interface but
	 * only does work for interfaces with BFD Transport Subnets.
	 */

	register EIPM_SUBNET	*sn_ptr;
	int			sn_idx;
	int			num_sns;

	num_sns = intf_ptr->subnet_cnt;

	for (sn_idx=0; sn_idx < num_sns; sn_idx++)
	{
		sn_ptr = &(intf_ptr->subnet[sn_idx]);

		if (sn_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT)
		{
			(void)EIPM_bfd_get_stats_tran_sn(intf_ptr,sn_idx);
		}

	} /* end 'for each subnet in current interface' */

	return IPM_SUCCESS;

} /* EIPM_bfd_get_stats_transports() */

int EIPM_bfd_get_stats_tran_sn( register EIPM_INTF *intf_ptr, int sn_idx )
{
	/* Gets called once for every BFD Transport Subnet
	 * in the current EIPM_INTF interface.
	 */

	register EIPM_SUBNET	*sn_ptr = &(intf_ptr->subnet[sn_idx]);
	EIPM_INTF_SPEC		*intfSpecDataP;
	int			intf_idx;
	int			ip_idx;
	int			num_ips;

	intfSpecDataP = &(intf_ptr->specData);

	intf_idx = intfSpecDataP->baseIntfIdx;

	num_ips = sn_ptr->ip_cnt;

	/* Loop through the BFD Sessions as represented
	 * by the local IP addresses associated with this 
	 * BFD Transport Subnet.
	 */
	for (ip_idx=0; ip_idx<num_ips; ip_idx++)
	{
		(void)EIPM_bfd_get_stats_sess( intf_ptr, sn_idx, ip_idx );

	} /* for each local IP address in the subnet */

	return IPM_SUCCESS;

} /* EIPM_bfd_get_stats_tran_sn() */		

int EIPM_bfd_get_stats_sess(
		register EIPM_INTF	*intf_ptr,
		int			sn_idx,
		int			ip_idx
	)
{
	EIPM_INTF_SPEC		*intfSpecDataP;
	int			intf_idx;
	register EIPM_SUBNET	*sn_ptr;
	EIPM_IPDATA		*ip_ptr;
	IPM_IPADDR		*loc_ip_addr_ptr, *rmt_ip_addr_ptr;
	BFD_RETVAL		bfd_retval;
	IPM_RETVAL		retval = IPM_FAILURE;
	unsigned int		missed_hb;  
	unsigned int		corrupt_pkt; 

	/* Gets called once for every BFD Session in
	 * the current BFD Transport Subnet.
	 */

	intfSpecDataP = &(intf_ptr->specData);
	intf_idx = intfSpecDataP->baseIntfIdx;

	sn_ptr = &(intf_ptr->subnet[sn_idx]);
	ip_ptr = &(sn_ptr->ips[ip_idx]);
	loc_ip_addr_ptr = &(ip_ptr->ipaddr);
	rmt_ip_addr_ptr = &(sn_ptr->gateway);

	/* Get the BFD statistics,
	 * add them to the external counts,
	 * then clear them.
	 */
	bfd_retval = BFD_get_stats(
		loc_ip_addr_ptr,
		rmt_ip_addr_ptr,
                &missed_hb,
		&corrupt_pkt
        );

	if (bfd_retval == BFD_SUCCESS)
	{
		if (intfSpecDataP->lsn0_iface_indx > 0)
		{
			intfSpecDataP->lsn0_sequence_error_count += missed_hb;
			intfSpecDataP->lsn0_corrupt_packet_count += corrupt_pkt;
		}
		else
		{
			intfSpecDataP->lsn1_sequence_error_count += missed_hb;
			intfSpecDataP->lsn1_corrupt_packet_count += corrupt_pkt;
		}

		retval = IPM_SUCCESS;
	}

	BFD_clear_stats( loc_ip_addr_ptr, rmt_ip_addr_ptr );

	return retval;

} /* EIPM_bfd_get_stats_sess() */


void EIPM_bfd_clr_stats()
{
	/* Pointer to shared memory */
	EIPM_DATA		*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;

	register EIPM_INTF	*intf_ptr;
	EIPM_INTF_SPEC		*intfSpecDataP;
	int			intf_idx;
	int			num_intfs;

	num_intfs = shm_ptr->intf_cnt;

	/* Update the stats for all interfaces. */
	for( intf_idx=0; intf_idx < num_intfs; intf_idx++ )
	{
		intf_ptr = &(shm_ptr->intf_data[intf_idx]);

		intfSpecDataP = &(intf_ptr->specData);

		if (intfSpecDataP->monitor == EIPM_MONITOR_BFD)
		{
			(void)EIPM_bfd_clr_stats_intf(intf_ptr);
		}

	} /* end 'for each monitored interface' */

	return; 

} /* EIPM_bfd_clr_stats() */

int EIPM_bfd_clr_stats_intf(register EIPM_INTF *intf_ptr)
{
	/* Gets called once for every EIPM_INTF interface that uses
	 * BFD for redundancy.
	 */

	(void)EIPM_bfd_clr_stats_transports(intf_ptr);

	return IPM_SUCCESS;

} /* EIPM_bfd_clr_stats_intf() */

int EIPM_bfd_clr_stats_transports(register EIPM_INTF *intf_ptr)
{
	/* Gets called once for every EIPM_INTF interface but
	 * only does work for interfaces with BFD Transport Subnets.
	 */

	register EIPM_SUBNET	*sn_ptr;
	int			sn_idx;
	int			num_sns;

	num_sns = intf_ptr->subnet_cnt;

	for (sn_idx=0; sn_idx < num_sns; sn_idx++)
	{
		sn_ptr = &(intf_ptr->subnet[sn_idx]);

		if (sn_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT)
		{
			(void)EIPM_bfd_clr_stats_tran_sn(intf_ptr,sn_idx);
		}

	} /* end 'for each subnet in current interface' */

	return IPM_SUCCESS;

} /* EIPM_bfd_clr_stats_transports() */

int EIPM_bfd_clr_stats_tran_sn( register EIPM_INTF *intf_ptr, int sn_idx )
{
	/* Gets called once for every BFD Transport Subnet
	 * in the current EIPM_INTF interface.
	 */

	register EIPM_SUBNET	*sn_ptr = &(intf_ptr->subnet[sn_idx]);
	EIPM_INTF_SPEC		*intfSpecDataP;
	int			intf_idx;
	int			ip_idx;
	int			num_ips;

	intfSpecDataP = &(intf_ptr->specData);

	intf_idx = intfSpecDataP->baseIntfIdx;

	num_ips = sn_ptr->ip_cnt;

	/* Loop through the BFD Sessions as represented
	 * by the local IP addresses associated with this 
	 * BFD Transport Subnet.
	 */
	for (ip_idx=0; ip_idx<num_ips; ip_idx++)
	{
		(void)EIPM_bfd_clr_stats_sess( intf_ptr, sn_idx, ip_idx );

	} /* for each local IP address in the subnet */

	return IPM_SUCCESS;

} /* EIPM_bfd_clr_stats_tran_sn() */		

int EIPM_bfd_clr_stats_sess(
		register EIPM_INTF	*intf_ptr,
		int			sn_idx,
		int			ip_idx
	)
{
	EIPM_INTF_SPEC		*intfSpecDataP;
	int			intf_idx;
	register EIPM_SUBNET	*sn_ptr;
	EIPM_IPDATA		*ip_ptr;
	IPM_IPADDR		*loc_ip_addr_ptr, *rmt_ip_addr_ptr;

	/* Gets called once for every BFD Session in
	 * the current BFD Transport Subnet.
	 */

	intfSpecDataP = &(intf_ptr->specData);
	intf_idx = intfSpecDataP->baseIntfIdx;

	sn_ptr = &(intf_ptr->subnet[sn_idx]);
	ip_ptr = &(sn_ptr->ips[ip_idx]);
	loc_ip_addr_ptr = &(ip_ptr->ipaddr);
	rmt_ip_addr_ptr = &(sn_ptr->gateway);

	BFD_clear_stats( loc_ip_addr_ptr, rmt_ip_addr_ptr );

	return IPM_SUCCESS;

} /* EIPM_bfd_clr_stats_sess() */

void EIPM_bfd_init_subnet_map()
{
	bfd_subnet_map.populated = FALSE;

	return;

} /* EIPM_bfd_init_subnet_map() */

int EIPM_bfd_get_subnet_map(
		EIPM_BFD_MAP_SNGRP **subnet_map_ptr_ptr,
		int intf_idx,
		int sn_idx
	)
{
	IPM_RETVAL	retval;

	/* Since BFD Service Subnet status is based on availability
	 * of both Left and Right BFD Transport subnets, we need to
	 * make sure they're associated every time this function is called.
	 */

#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
	if (dump_subnet_map) LOG_FORCE( 0, "BFD_DEBUG: %s() calling EIPM_bfd_bld_subnet_map()\n", __FUNCTION__ );
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */

	retval = EIPM_bfd_bld_subnet_map();

	if (retval == IPM_SUCCESS)
	{
		retval = IPM_FAILURE;

		if ( bfd_subnet_map.intfcs[intf_idx].has_bfd_sn == TRUE )
		{
			if ( bfd_subnet_map.intfcs[intf_idx].sns[sn_idx].is_bfd_sn == TRUE )
			{
				*subnet_map_ptr_ptr = &(bfd_subnet_map.intfcs[intf_idx].sns[sn_idx]);
				retval = IPM_SUCCESS;
			}
		}
	}

	return retval;

} /* EIPM_bfd_get_subnet_map() */

int EIPM_bfd_prt_subnet_map()
{
	int	intf_idx;
	int	sn_idx;

	if (!printed_subnet_map)
	{
		LOG_FORCE( 0, "BFD_DEBUG: %s() ENTER {\n", __FUNCTION__ );

		LOG_FORCE( 0, "SUBNET_MAP: populated=%d\n", bfd_subnet_map.populated );

		for (intf_idx=0; intf_idx < EIPM_MAX_EXT_SUB; intf_idx++)
		{
			if (bfd_subnet_map.intfcs[intf_idx].has_bfd_sn == TRUE)
			{
				LOG_FORCE( 0, "SUBNET_MAP: start intf_idx=%d {\n", intf_idx );
				for (sn_idx=0; sn_idx < EIPM_MAX_SUBNETS; sn_idx++)
				{
					if (bfd_subnet_map.intfcs[intf_idx].sns[sn_idx].is_bfd_sn == TRUE)
					{
						LOG_FORCE( 0, "SUBNET_MAP:     start sn_idx=%d {\n", sn_idx );
						LOG_FORCE( 0, "SUBNET_MAP:     intfcs[%d].sns[%d].is_bfd_sn=%d\n", intf_idx, sn_idx, bfd_subnet_map.intfcs[intf_idx].sns[sn_idx].is_bfd_sn );
						LOG_FORCE( 0, "SUBNET_MAP:     intfcs[%d].sns[%d].svc.intf_idx=%d\n", intf_idx, sn_idx, bfd_subnet_map.intfcs[intf_idx].sns[sn_idx].svc.intf_idx );
						LOG_FORCE( 0, "SUBNET_MAP:     intfcs[%d].sns[%d].svc.sn_idx=%d\n", intf_idx, sn_idx, bfd_subnet_map.intfcs[intf_idx].sns[sn_idx].svc.sn_idx );
						LOG_FORCE( 0, "SUBNET_MAP:     intfcs[%d].sns[%d].left.intf_idx=%d\n", intf_idx, sn_idx, bfd_subnet_map.intfcs[intf_idx].sns[sn_idx].left.intf_idx );
						LOG_FORCE( 0, "SUBNET_MAP:     intfcs[%d].sns[%d].left.sn_idx=%d\n", intf_idx, sn_idx, bfd_subnet_map.intfcs[intf_idx].sns[sn_idx].left.sn_idx );
						LOG_FORCE( 0, "SUBNET_MAP:     intfcs[%d].sns[%d].right.intf_idx=%d\n", intf_idx, sn_idx, bfd_subnet_map.intfcs[intf_idx].sns[sn_idx].right.intf_idx );
						LOG_FORCE( 0, "SUBNET_MAP:     intfcs[%d].sns[%d].right.sn_idx=%d\n", intf_idx, sn_idx, bfd_subnet_map.intfcs[intf_idx].sns[sn_idx].right.sn_idx );
						LOG_FORCE( 0, "SUBNET_MAP:     end sn_idx=%d }\n", sn_idx );
					}
				}

				LOG_FORCE( 0, "SUBNET_MAP: end intf_idx=%d }\n", intf_idx );
			}
		}

		LOG_FORCE( 0, "BFD_DEBUG: %s() EXIT }\n", __FUNCTION__ );
	}

	printed_subnet_map = 1;

	return IPM_SUCCESS;
}

int EIPM_bfd_bld_subnet_map()
{
	/* Builds the SubNet MAP structure which is fundamentally a 2-D
	 * array that maps a given intreface index + subnet index to the
	 * other associated subnets. Note that (for each of IPV4 and IPV6
	 * subnets on a given interface separately):
	 *
	 * A given Left (or Right) BFD Transport subnet can be associated
	 * with multiple BFD Service subnets (e.g. S3 and S10).
	 *
	 * A given BFD Service subnet can only be associated with 1 Left
	 * and 1 Right BFD Transport Subnet.
	 *
	 * All of the BFD Service subnets on a given Interface are
	 * associated with THE Left BFD Transport subnet on that same
	 * interface and are also all associated with the same Right
	 * BFD Transport subnet as each other.
	 *
	 * So, this structure will directly provide the following mappings:
	 *
	 *	Service -> Left Transport
	 *	Service -> Right Transport
	 *	Left Transport -> Right Transport
	 *	Right Transport -> Left Transport
	 *
	 * but it will not directly provide a mapping from Left or Right
	 * Transport to Service Subnet(s). To find which Service subnet(s)
	 * are associated with a given Left or Right Transport, you need
	 * to search this structure.
	 */

	/* Pointer to shared memory */
	EIPM_DATA		*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	
	/* Variables to loop through all EIPM_INTFs */
	register EIPM_INTF	*all_intf_ptr;
	int			all_intf_idx;
	int			num_all_intfs;
	EIPM_INTF_SPEC		*intfSpecDataP;

	/* Variables to loop through the EIPM_SUBNETs associated with
	 * all EIPM_INTSs that have subnets assigned.
	 */
	register EIPM_SUBNET	*sn_ptr;
	int			sn_idx;
	int			num_sns;

	/* Variables to loop through only EIPM_INTFs containing
	 * targetted BFD Service Subnets.
	 */
	register EIPM_INTF	*svc_intf_ptr;
	int			svc_intf_idx;
	int			svc_sn_idx;
	IPM_IPADDRTYPE		svc_ip_type;
	EIPM_INTF_SN_IDX	svc_idxs[ EIPM_MAX_EXT_SUB ];
	int			num_svc_intfs = 0;
	int			svc_idx = 0;

	/* Variables to loop through only EIPM_INTFs containing
	 * targetted right BFD Transport Subnets.
	 */
	register EIPM_INTF	*right_intf_ptr;
	int			right_intf_idx;
	int			right_sn_idx;
	IPM_IPADDRTYPE		right_ip_type;
	EIPM_INTF_SN_IDX	right_idxs[ EIPM_MAX_EXT_SUB ];
	int			num_right_intfs = 0;
	int			right_idx = 0;

	int			left_intf_idx;
	int			left_sn_idx;

	int			v4tran_sn_idx;
	int			v6tran_sn_idx;

	/* Booleans to name progress conditions */
	bool			found_match;

	IPM_RETVAL		retval = IPM_SUCCESS;

	/* Pointers into array of subnets info, for convenience */
	EIPM_BFD_MAP_INTFC	*intfc2map_ptr;
	EIPM_BFD_MAP_SNGRP	*sngrp_ptr;

	/* BFD Service Subnets are stored in the same EIPM_INTF structure
	 * as their associated "left" BFD Transport Subnet (when populated),
	 * but their "right" BFD Transport Subnet is stored in a different
	 * EIPM_INTF structure. For our left/right redundancy strategy to
	 * work we need to associate the 2 so this function does that.
	 */

	if (bfd_subnet_map.populated == TRUE)
	{
		/* The array has already been populated during this
		 * interval. This function works this way so calling
		 * code doesn't need to worry about calling it multiple
		 * times, e.g. in the timeout scenario where it could
		 * get called once for every BFD Service Subnet so the
		 * main timeout function just sets "populated" to FALSE
		 * on entry and then this function sets it to TRUE on its
		 * first invocation afterwards.
		 */
		return retval;
	}

	num_all_intfs = shm_ptr->intf_cnt;

#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
	if (dump_subnet_map) LOG_FORCE( 0, "BFD_DEBUG: %s() ENTER num_all_intfs=%d\n {\n", __FUNCTION__, num_all_intfs );
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */

	/* Find all EIPM_INTFs that contain a BFD Service Subnet
	 * and/or a BFD Transport Subnet.
	 */
	for( all_intf_idx=0; all_intf_idx < num_all_intfs; all_intf_idx++ )
	{
		all_intf_ptr = &(shm_ptr->intf_data[all_intf_idx]);

		intfSpecDataP = &(all_intf_ptr->specData);

		intfc2map_ptr = &(bfd_subnet_map.intfcs[all_intf_idx]);

		intfc2map_ptr->has_bfd_sn = FALSE;

		if (all_intf_ptr->specData.monitor != EIPM_MONITOR_BFD)
		{
			continue;
		}

		/* We want to associate BFD Service Subnets with both
		 * their left and their right BFD Transport Subnets.
		 */

		num_sns = all_intf_ptr->subnet_cnt;

#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
		if (dump_subnet_map) LOG_FORCE( 0, "BFD_DEBUG: %s() all_intf_idx=%d, num_sns=%d\n", __FUNCTION__, all_intf_idx, num_sns);
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */

		for ( sn_idx=0; sn_idx < num_sns; sn_idx++ )
		{
			sngrp_ptr = &(intfc2map_ptr->sns[sn_idx]);

			sngrp_ptr->left.intf_idx  = -1;
			sngrp_ptr->left.sn_idx    = -1;
			sngrp_ptr->right.intf_idx = -1;
			sngrp_ptr->right.sn_idx   = -1;
			sngrp_ptr->svc.intf_idx   = -1;
			sngrp_ptr->svc.sn_idx     = -1;
			sngrp_ptr->is_bfd_sn	  = FALSE;
			sngrp_ptr->ip_type	  = IPM_IPBADVER;
		}

		/* Determine if we have V4 and/or V6 BFD Transport Subnets
		 * in this Interface. Can only be 0 or 1 of each.
		 */
		v4tran_sn_idx  = -1;
		v6tran_sn_idx  = -1;
		for ( sn_idx=0; sn_idx < num_sns; sn_idx++ )
		{
			sn_ptr = &(all_intf_ptr->subnet[sn_idx]);

			switch(sn_ptr->redundancy_mode)
			{
			case IPM_RED_BFD_TRANSPORT:

				/* Current EIPM_INTF contains a BFD Transport
				 * Subnet.
				 */
				sngrp_ptr = &(intfc2map_ptr->sns[sn_idx]);

				intfc2map_ptr->has_bfd_sn = TRUE;
				sngrp_ptr->is_bfd_sn      = TRUE;
				sngrp_ptr->ip_type        = sn_ptr->subnet_base.addrtype;

				if (sngrp_ptr->ip_type == IPM_IPV6)
				{
					/* This is an IPV6 BFD Transport */
					v6tran_sn_idx = sn_idx;
				}
				else if (sngrp_ptr->ip_type == IPM_IPV4)
				{
					/* This is an IPV4 BFD Transport */
					v4tran_sn_idx = sn_idx;
				}
				else
				{
					EIPM_LOG_ERROR( 0, "Error: %s - invalid ip_type %d for Intf %d, BFD Transport Subnet %d\n", __FUNCTION__, sngrp_ptr->ip_type, all_intf_idx, sn_idx );
				}

				if (intfSpecDataP->lsn0_iface_indx > 0)
				{
					/* This is a Left BFD Transport */
					sngrp_ptr->left.intf_idx = all_intf_idx;
					sngrp_ptr->left.sn_idx   = sn_idx;
				}
				else if (intfSpecDataP->lsn1_iface_indx > 0)
				{
					/* This is a Right BFD Transport */
					sngrp_ptr->right.intf_idx = all_intf_idx;
					sngrp_ptr->right.sn_idx   = sn_idx;

					/* Remember that the current interface
					 * contained a Right BFD Transport
					 * Subnet for later when trying to
					 * match up with a BFD Service Subnet.
					 */
					right_idxs[num_right_intfs].intf_idx = all_intf_idx;
					right_idxs[num_right_intfs].sn_idx   = sn_idx;
					num_right_intfs++;
				}
				else
				{
					EIPM_LOG_ERROR( 0, "Error: %s niether lsn0_iface_indx nor lsn1_iface_indx populated for Intf %d, BFD Transport Subnet %d\n", __FUNCTION__, sngrp_ptr->ip_type, all_intf_idx, sn_idx );
				}

				break;

			default:
				/* Not a BFD Transport subnet. Do nothing. */
				break;
			}

		} /* for ( sn_idx=0; sn_idx < num_sns; sn_idx++ ) */

		/* For each V4 and V6 BFD Service Subnet in this Interface.
		 * associate it with the previously found Left Transport
		 * Subnet in this interface and check if we have the data
		 * to later find an associated Right BFD Transport subnet.
		 * Note we need to have found the up-to-2 BFD Transport Subnets
		 * (0 or 1 IPV4 and/or 0 or 1 IPV6) on this interface before
		 * starting to look for the BFD Service subnets, hence the 2 loops.
		 */
		for ( sn_idx=0; sn_idx < num_sns; sn_idx++ )
		{
			sn_ptr = &(all_intf_ptr->subnet[sn_idx]);

			switch(sn_ptr->redundancy_mode)
			{
			case IPM_RED_BFD_RSR:
			case IPM_RED_EIPM_BFD:

				/* Current EIPM_INTF contains a BFD Service
				 * Subnet.
				 */
				sngrp_ptr = &(intfc2map_ptr->sns[sn_idx]);

				intfc2map_ptr->has_bfd_sn = TRUE;
				sngrp_ptr->is_bfd_sn      = TRUE;
				sngrp_ptr->svc.intf_idx   = all_intf_idx;
				sngrp_ptr->svc.sn_idx     = sn_idx;
				sngrp_ptr->ip_type        = sn_ptr->subnet_base.addrtype;

				if ( (sngrp_ptr->ip_type == IPM_IPV6) &&
				     (v6tran_sn_idx != -1) )
				{
					/* IPV6 Left Transport also present */
					sngrp_ptr->left.intf_idx = all_intf_idx;
					sngrp_ptr->left.sn_idx   = v6tran_sn_idx;
				}
				else if ( (sngrp_ptr->ip_type == IPM_IPV4) &&
					  (v4tran_sn_idx != -1) )
				{
					/* IPV4 Left Transport also present */
					sngrp_ptr->left.intf_idx = all_intf_idx;
					sngrp_ptr->left.sn_idx   = v4tran_sn_idx;
				}

				if (intfSpecDataP->lsn1_iface_indx > 0)
				{
					/* We should be able to later find a
					 * corresponding right BFD Transport.
					 * Remember that the current interface
					 * contained a BFD Service Subnet
					 * for later when trying to match up
					 * with a Right BFD Transport subnet.
					 */
                                	svc_idxs[num_svc_intfs].intf_idx = all_intf_idx;
                                	svc_idxs[num_svc_intfs].sn_idx   = sn_idx;
					num_svc_intfs++;
				}
				break;

			default:
				/* Unrelated to BFD. Do nothing. */
				break;
			}

#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
			if (dump_subnet_map) LOG_FORCE( 0, "BFD_DEBUG: %s() SN: sn_idx=%d, sn_ptr->redundancy_mode=%d, sn_idx=%d, v4tran_sn_idx=%d, v6tran_sn_idx=%d\n", __FUNCTION__, sn_idx, sn_ptr->redundancy_mode, sn_idx, v4tran_sn_idx, v6tran_sn_idx);
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */

		} /* for ( sn_idx=0; sn_idx < num_sns; sn_idx++ ) */

	} /* end 'for each monitored interface' */

	/* Loop through each BFD Service Subnet and find the
	 * corresponding right BFD Transport Subnet if it exists.
	 */

#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
	if (dump_subnet_map) {
		LOG_FORCE( 0, "BFD_DEBUG: %s() num_svc_intfs=%d, num_right_intfs=%d\n", __FUNCTION__, num_svc_intfs, num_right_intfs );

		EIPM_bfd_prt_subnet_map();
	}
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */

	for( svc_idx=0; svc_idx < num_svc_intfs; svc_idx++ )
	{
		bool found_match = FALSE;

		svc_intf_idx = svc_idxs[svc_idx].intf_idx;
		svc_sn_idx   = svc_idxs[svc_idx].sn_idx;
		svc_ip_type  = bfd_subnet_map.intfcs[svc_intf_idx].sns[svc_sn_idx].ip_type;

		svc_intf_ptr = &(shm_ptr->intf_data[svc_intf_idx]);

#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
		if (dump_subnet_map) LOG_FORCE( 0, "BFD_DEBUG: %s() svc_idx=%d, svc_intf_idx=%d, svc_sn_idx=%d\n", __FUNCTION__, svc_idx, svc_intf_idx, svc_sn_idx );
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */

		for ( right_idx=0; (found_match == FALSE) &&
		    	(right_idx < num_right_intfs); right_idx++ )
		{
			right_intf_idx = right_idxs[right_idx].intf_idx;
			right_sn_idx   = right_idxs[right_idx].sn_idx;

			if ( (right_intf_idx != -1) &&
			     (right_sn_idx != -1) )
			{
				right_ip_type  = bfd_subnet_map.intfcs[right_intf_idx].sns[right_sn_idx].ip_type;
	
				right_intf_ptr = &(shm_ptr->intf_data[right_intf_idx]);
	
#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
				if (dump_subnet_map) LOG_FORCE( 0, "BFD_DEBUG: %s() right_idx=%d, right_intf_idx=%d, right_sn_idx=%d\n", __FUNCTION__, right_idx, right_intf_idx, right_sn_idx );
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */
	
				if ( (svc_ip_type == right_ip_type) &&
				     (strcmp(svc_intf_ptr->lsn1_baseif,
					   right_intf_ptr->lsn1_baseif) == 0) )
				{
					found_match = TRUE;
				}
			}
			else
			{
				EIPM_LOG_ERROR( 0, "Error: %s BFD Service intf_idx %d, sn_idx %d found Right BFD Transport intf_idx %d, sn_idx %d\n", __FUNCTION__, svc_intf_idx, svc_sn_idx, right_intf_idx, right_sn_idx );
			}

		} /* end 'for each interface containing a right BFD Transport Subnet' */

		if (found_match == TRUE)
		{
			/* lsn1_baseif in the EIPM_INTF containing the
			 * BFD Service Subnet is the same as in the EIPM_INTF
			 * containing the right BFD Transport Subnet.
			 */

			/* Update Service with Right indices */
			bfd_subnet_map.intfcs[svc_intf_idx].sns[svc_sn_idx].right.intf_idx = right_intf_idx;
			bfd_subnet_map.intfcs[svc_intf_idx].sns[svc_sn_idx].right.sn_idx   = right_sn_idx;

			left_intf_idx = bfd_subnet_map.intfcs[svc_intf_idx].sns[svc_sn_idx].left.intf_idx;
			left_sn_idx   = bfd_subnet_map.intfcs[svc_intf_idx].sns[svc_sn_idx].left.sn_idx;

			if (left_intf_idx != -1)
			{
				/* Update Right with Left indices */
				bfd_subnet_map.intfcs[right_intf_idx].sns[right_sn_idx].left.intf_idx = left_intf_idx;
				bfd_subnet_map.intfcs[right_intf_idx].sns[right_sn_idx].left.sn_idx   = left_sn_idx;

				/* Update Left with Right indices */
				bfd_subnet_map.intfcs[left_intf_idx].sns[left_sn_idx].right.intf_idx = right_intf_idx;
				bfd_subnet_map.intfcs[left_intf_idx].sns[left_sn_idx].right.sn_idx   = right_sn_idx;
			}

#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
			if (dump_subnet_map)
			{
				LOG_FORCE( 0, "BFD_DEBUG: %s() svc_intf_idx=%d, svc_sn_idx=%d\n", __FUNCTION__, svc_intf_idx, svc_sn_idx);
				LOG_FORCE( 0, "BFD_DEBUG: %s() right_intf_idx=%d, right_sn_idx=%d\n", __FUNCTION__, right_intf_idx, right_sn_idx);
				LOG_FORCE( 0, "BFD_DEBUG: %s() left_intf_idx=%d, left_sn_idx=%d\n", __FUNCTION__, left_intf_idx, left_sn_idx);
			}
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */

		} /* if (found_match == TRUE) */

	} /* for( svc_idx=0; svc_idx < num_svc_intfs; svc_idx++ ) */

	bfd_subnet_map.populated = TRUE;

#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
	if (dump_subnet_map)
	{
		LOG_FORCE( 0, "BFD_DEBUG: %s() EXIT, retval=%d }\n", __FUNCTION__, retval);
		EIPM_bfd_prt_subnet_map();
	}
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */

	return retval;

} /* EIPM_bfd_bld_subnet_map() */

int EIPM_bfd_map_left2right(
		int left_intf_idx,
		int left_sn_idx,
		int *right_intf_idx_ptr,
		int *right_sn_idx_ptr
	)
{
	/* Given a pair of Left BFD Transport indices, populates
	 * the associated Right BFD Transport indices.
	 */

	EIPM_BFD_MAP_SNGRP *sngrp_ptr;	/* pointer to the set of Left BFD
					 * Transport, Right BFD Transport,
					 * and BFD Service subnets
					 * associated with the current subnet.
					 */

	IPM_RETVAL	retval;

	// LOG_OTHER( 0, "BFD_DEBUG: Entering %s() left_intf_idx=%d, left_sn_idx=%d\n", __FUNCTION__, left_intf_idx, left_sn_idx );

	*right_intf_idx_ptr	= -1;
	*right_sn_idx_ptr	= -1;

	retval = EIPM_bfd_get_subnet_map(&sngrp_ptr,left_intf_idx,left_sn_idx);

	if (retval == IPM_SUCCESS)
	{
		retval = IPM_FAILURE;

		if ( (sngrp_ptr->left.intf_idx == left_intf_idx) &&
		     (sngrp_ptr->left.sn_idx   == left_sn_idx) )
		{
			/* The provided interface and subnet indices
			 * do belong to a Left BFD Transport.
			 */
	
			if ( (sngrp_ptr->right.intf_idx != -1) &&
			     (sngrp_ptr->right.sn_idx != -1) )
			{
				/* There is a Right BFD Transport associated
				 * with this Left BFD Transport.
				 */
				*right_intf_idx_ptr = sngrp_ptr->right.intf_idx;
				*right_sn_idx_ptr   = sngrp_ptr->right.sn_idx;

				retval = IPM_SUCCESS;
			}
			else
			{
				EIPM_LOG_ERROR( 0, "Error: %s Left BFD Transport intf_idx %d, sn_idx %d associated with Right BFD Transport intf_idx %d, sn_idx %d\n", __FUNCTION__, sngrp_ptr->left.intf_idx, sngrp_ptr->left.sn_idx, sngrp_ptr->right.intf_idx, sngrp_ptr->right.sn_idx );
			}

		}
	}

	// LOG_OTHER( 0, "BFD_DEBUG: Exiting %s() right_intf_idx=%d, right_sn_idx=%d, retval=%d\n", __FUNCTION__, *right_intf_idx_ptr, *right_sn_idx_ptr, retval );

	return retval;

} /* EIPM_bfd_map_left2right() */

int EIPM_bfd_map_left2svc(
		int left_intf_idx,
		int left_sn_idx,
		int *svc_intf_idx_ptr,
		int *svc_sn_idx_ptr
	)
{
	/* Given a pair of Left BFD Transport indices, populates
	 * the associated BFD Service indices.
	 */

	EIPM_BFD_MAP_SNGRP *sngrp_ptr;	/* pointer to the set of Left BFD
					 * Transport, Right BFD Transport,
					 * and BFD Service subnets
					 * associated with the current subnet.
					 */

	IPM_RETVAL	retval;

	// LOG_OTHER( 0, "BFD_DEBUG: Entering %s() left_intf_idx=%d, left_sn_idx=%d\n", __FUNCTION__, left_intf_idx, left_sn_idx );

	*svc_intf_idx_ptr	= -1;
	*svc_sn_idx_ptr		= -1;

	retval = EIPM_bfd_get_subnet_map(&sngrp_ptr,left_intf_idx,left_sn_idx);

	if (retval == IPM_SUCCESS)
	{
		retval = IPM_FAILURE;

		if ( (sngrp_ptr->left.intf_idx == left_intf_idx) &&
		     (sngrp_ptr->left.sn_idx   == left_sn_idx) )
		{
			/* The provided interface and subnet indices
			 * do belong to a Left BFD Transport.
			 */
	
			if ( (sngrp_ptr->svc.intf_idx != -1) &&
			     (sngrp_ptr->svc.sn_idx != -1) )
			{
				/* There is a BFD Service associated
				 * with this Left BFD Transport.
				 */
				*svc_intf_idx_ptr = sngrp_ptr->svc.intf_idx;
				*svc_sn_idx_ptr   = sngrp_ptr->svc.sn_idx;

				retval = IPM_SUCCESS;
			}
			else
			{
				EIPM_LOG_ERROR( 0, "Error: %s Left BFD Transport intf_idx %d, sn_idx %d associated with BFD Service intf_idx %d, sn_idx %d\n", __FUNCTION__, sngrp_ptr->left.intf_idx, sngrp_ptr->left.sn_idx, sngrp_ptr->svc.intf_idx, sngrp_ptr->svc.sn_idx );
			}

		}
	}

	// LOG_OTHER( 0, "BFD_DEBUG: Exiting %s() svc_intf_idx=%d, svc_sn_idx=%d, retval=%d\n", __FUNCTION__, *svc_intf_idx_ptr, *svc_sn_idx_ptr, retval );

	return retval;

} /* EIPM_bfd_map_left2svc() */

int EIPM_bfd_map_left2svcs(
		int			left_intf_idx,
		int			left_sn_idx,
		EIPM_INTF_SN_IDX	svcs_ary[],
		int			*num_svcs_ptr
	)
{
	/* Given a pair of Left BFD Transport indices, populates
	 * an array of associated BFD Service indices.
	 */

	EIPM_BFD_MAP_SNGRP *left_sngrp_ptr;
	EIPM_BFD_MAP_SNGRP *loop_sngrp_ptr;

	int		loop_intf_idx = -1;
	int		loop_sn_idx   = -1;

	IPM_RETVAL	retval;

	// LOG_OTHER( 0, "BFD_DEBUG: Entering %s() left_intf_idx=%d, left_sn_idx=%d\n", __FUNCTION__, left_intf_idx, left_sn_idx );

	// LOG_FORCE( 0, "BFD_DEBUG: Entering %s() left_intf_idx=%d, left_sn_idx=%d\n", __FUNCTION__, left_intf_idx, left_sn_idx );

	(*num_svcs_ptr) = 0;

	retval = EIPM_bfd_get_subnet_map(&left_sngrp_ptr,left_intf_idx,left_sn_idx);

	if (retval == IPM_SUCCESS)
	{
		if ( (left_sngrp_ptr->left.intf_idx == left_intf_idx) &&
		     (left_sngrp_ptr->left.sn_idx   == left_sn_idx) )
		{
			/* The provided interface and subnet indices
			 * do belong to a Left BFD Transport.
			 */
			retval = IPM_SUCCESS;
		}
		else
		{
			retval = IPM_FAILURE;
		}
	}

	if (retval == IPM_SUCCESS)
	{
		for (loop_intf_idx=0; loop_intf_idx < EIPM_MAX_EXT_SUB; loop_intf_idx++)
		{
			if ( bfd_subnet_map.intfcs[loop_intf_idx].has_bfd_sn == TRUE )
			{
				for (loop_sn_idx=0; loop_sn_idx < EIPM_MAX_SUBNETS; loop_sn_idx++)
				{
					loop_sngrp_ptr = &(bfd_subnet_map.intfcs[loop_intf_idx].sns[loop_sn_idx]);
					if ( (loop_sngrp_ptr->is_bfd_sn == TRUE) &&
					     (loop_sngrp_ptr->svc.intf_idx  == loop_intf_idx) &&
					     (loop_sngrp_ptr->svc.sn_idx    == loop_sn_idx) &&
					     (loop_sngrp_ptr->left.intf_idx == left_intf_idx) &&
					     (loop_sngrp_ptr->left.sn_idx   == left_sn_idx) )
					{
						svcs_ary[*num_svcs_ptr].intf_idx = loop_intf_idx;
						svcs_ary[*num_svcs_ptr].sn_idx   = loop_sn_idx;
						(*num_svcs_ptr)++;

						// LOG_FORCE( 0, "BFD_DEBUG: In %s() found loop_intf_idx=%d, loop_sn_idx=%d, num_svcs=%d\n", __FUNCTION__, loop_intf_idx, loop_sn_idx, (*num_svcs_ptr) );
					}
				}
			}
		}
	}

	// LOG_OTHER( 0, "BFD_DEBUG: Exiting %s() loop_intf_idx=%d, loop_sn_idx=%d, retval=%d, num_svcs=%d\n", __FUNCTION__, loop_intf_idx, loop_sn_idx, retval, (*num_svcs_ptr) );

	// LOG_FORCE( 0, "BFD_DEBUG: Exiting %s() loop_intf_idx=%d, loop_sn_idx=%d, retval=%d, num_svcs=%d\n", __FUNCTION__, loop_intf_idx, loop_sn_idx, retval, (*num_svcs_ptr) );

	// int svc_nr;
	// for (svc_nr=0; svc_nr < (*num_svcs_ptr); svc_nr++)
	// {
		// LOG_FORCE( 0, "BFD_DEBUG: Exiting %s() svc_nr=%d, svc_intf_idx=%d, svc_sn_idx=%d\n", __FUNCTION__, svc_nr, svcs_ary[svc_nr].intf_idx, svcs_ary[svc_nr].sn_idx );
	// }

	return retval;

} /* EIPM_bfd_map_left2svcs() */

int EIPM_bfd_map_right2svcs(
		int			right_intf_idx,
		int			right_sn_idx,
		EIPM_INTF_SN_IDX	svcs_ary[],
		int			*num_svcs_ptr
	)
{
	/* Given a pair of Right BFD Transport indices, populates
	 * an array of associated BFD Service indices.
	 */

	EIPM_BFD_MAP_SNGRP *right_sngrp_ptr;
	EIPM_BFD_MAP_SNGRP *loop_sngrp_ptr;

	int		loop_intf_idx = -1;
	int		loop_sn_idx   = -1;

	IPM_RETVAL	retval;

	// LOG_OTHER( 0, "BFD_DEBUG: Entering %s() right_intf_idx=%d, right_sn_idx=%d\n", __FUNCTION__, right_intf_idx, right_sn_idx );

	// LOG_FORCE( 0, "BFD_DEBUG: Entering %s() right_intf_idx=%d, right_sn_idx=%d\n", __FUNCTION__, right_intf_idx, right_sn_idx );

	(*num_svcs_ptr) = 0;

	retval = EIPM_bfd_get_subnet_map(&right_sngrp_ptr,right_intf_idx,right_sn_idx);

	if (retval == IPM_SUCCESS)
	{
		if ( (right_sngrp_ptr->right.intf_idx == right_intf_idx) &&
		     (right_sngrp_ptr->right.sn_idx   == right_sn_idx) )
		{
			/* The provided interface and subnet indices
			 * do belong to a Right BFD Transport.
			 */
			retval = IPM_SUCCESS;
		}
		else
		{
			retval = IPM_FAILURE;
		}
	}

	if (retval == IPM_SUCCESS)
	{
		for (loop_intf_idx=0; loop_intf_idx < EIPM_MAX_EXT_SUB; loop_intf_idx++)
		{
			if ( bfd_subnet_map.intfcs[loop_intf_idx].has_bfd_sn == TRUE )
			{
				for (loop_sn_idx=0; loop_sn_idx < EIPM_MAX_SUBNETS; loop_sn_idx++)
				{
					loop_sngrp_ptr = &(bfd_subnet_map.intfcs[loop_intf_idx].sns[loop_sn_idx]);
					if ( (loop_sngrp_ptr->is_bfd_sn == TRUE) &&
					     (loop_sngrp_ptr->svc.intf_idx  == loop_intf_idx) &&
					     (loop_sngrp_ptr->svc.sn_idx    == loop_sn_idx) &&
					     (loop_sngrp_ptr->right.intf_idx == right_intf_idx) &&
					     (loop_sngrp_ptr->right.sn_idx   == right_sn_idx) )
					{
						svcs_ary[*num_svcs_ptr].intf_idx = loop_intf_idx;
						svcs_ary[*num_svcs_ptr].sn_idx   = loop_sn_idx;
						(*num_svcs_ptr)++;

						// LOG_FORCE( 0, "BFD_DEBUG: In %s() found loop_intf_idx=%d, loop_sn_idx=%d, num_svcs=%d\n", __FUNCTION__, loop_intf_idx, loop_sn_idx, (*num_svcs_ptr) );
					}
				}
			}
		}
	}

	// LOG_OTHER( 0, "BFD_DEBUG: Exiting %s() loop_intf_idx=%d, loop_sn_idx=%d, retval=%d, num_svcs=%d\n", __FUNCTION__, loop_intf_idx, loop_sn_idx, retval, (*num_svcs_ptr) );

	// LOG_FORCE( 0, "BFD_DEBUG: Exiting %s() loop_intf_idx=%d, loop_sn_idx=%d, retval=%d, num_svcs=%d\n", __FUNCTION__, loop_intf_idx, loop_sn_idx, retval, (*num_svcs_ptr) );

	// int svc_nr;
	// for (svc_nr=0; svc_nr < (*num_svcs_ptr); svc_nr++)
	// {
		// LOG_FORCE( 0, "BFD_DEBUG: Exiting %s() svc_nr=%d, svc_intf_idx=%d, svc_sn_idx=%d\n", __FUNCTION__, svc_nr, svcs_ary[svc_nr].intf_idx, svcs_ary[svc_nr].sn_idx );
	// }

	return retval;

} /* EIPM_bfd_map_right2svcs() */

int EIPM_bfd_map_right2left(
		int right_intf_idx,
		int right_sn_idx,
		int *left_intf_idx_ptr,
		int *left_sn_idx_ptr
	)
{
	/* Given a pair of Right BFD Transport indices, populates
	 * the associated Left BFD Transport indices.
	 */

	EIPM_BFD_MAP_SNGRP *sngrp_ptr;	/* pointer to the set of Left BFD
					 * Transport, Right BFD Transport,
					 * and BFD Service subnets
					 * associated with the current subnet.
					 */

	IPM_RETVAL	retval;

	// LOG_OTHER( 0, "BFD_DEBUG: Entering %s() right_intf_idx=%d, right_sn_idx=%d\n", __FUNCTION__, right_intf_idx, right_sn_idx );

	*left_intf_idx_ptr	= -1;
	*left_sn_idx_ptr	= -1;

	retval = EIPM_bfd_get_subnet_map(&sngrp_ptr,right_intf_idx,right_sn_idx);

	if (retval == IPM_SUCCESS)
	{
		retval = IPM_FAILURE;

		if ( (sngrp_ptr->right.intf_idx == right_intf_idx) &&
		     (sngrp_ptr->right.sn_idx   == right_sn_idx) )
		{
			/* The provided interface and subnet indices
			 * do belong to a Right BFD Transport.
			 */
	
			if ( (sngrp_ptr->left.intf_idx != -1) &&
			     (sngrp_ptr->left.sn_idx != -1) )
			{
				/* There is a Left BFD Transport associated
				 * with this Right BFD Transport.
				 */
				*left_intf_idx_ptr = sngrp_ptr->left.intf_idx;
				*left_sn_idx_ptr   = sngrp_ptr->left.sn_idx;

				retval = IPM_SUCCESS;
			}
			else
			{
				EIPM_LOG_ERROR( 0, "Error: %s Right BFD Transport intf_idx %d, sn_idx %d associated with Left BFD Transport intf_idx %d, sn_idx %d\n", __FUNCTION__, sngrp_ptr->right.intf_idx, sngrp_ptr->right.sn_idx, sngrp_ptr->left.intf_idx, sngrp_ptr->left.sn_idx );
			}

		}
	}

	// LOG_OTHER( 0, "BFD_DEBUG: Exiting %s() left_intf_idx=%d, left_sn_idx=%d, retval=%d\n", __FUNCTION__, *left_intf_idx_ptr, *left_sn_idx_ptr, retval );

	return retval;

} /* EIPM_bfd_map_right2left() */

int EIPM_bfd_map_right2svc(
		int right_intf_idx,
		int right_sn_idx,
		int *svc_intf_idx_ptr,
		int *svc_sn_idx_ptr
	)
{
	/* Given a pair of Right BFD Transport indices, populates
	 * the associated BFD Service indices.
	 */

	EIPM_BFD_MAP_SNGRP *sngrp_ptr;	/* pointer to the set of Left BFD
					 * Transport, Right BFD Transport,
					 * and BFD Service subnets
					 * associated with the current subnet.
					 */

	IPM_RETVAL	retval;

	// LOG_OTHER( 0, "BFD_DEBUG: Entering %s() right_intf_idx=%d, right_sn_idx=%d\n", __FUNCTION__, right_intf_idx, right_sn_idx );

	*svc_intf_idx_ptr	= -1;
	*svc_sn_idx_ptr		= -1;

	retval = EIPM_bfd_get_subnet_map(&sngrp_ptr,right_intf_idx,right_sn_idx);

	if (retval == IPM_SUCCESS)
	{
		retval = IPM_FAILURE;

		if ( (sngrp_ptr->right.intf_idx == right_intf_idx) &&
		     (sngrp_ptr->right.sn_idx   == right_sn_idx) )
		{
			/* The provided interface and subnet indices
			 * do belong to a Right BFD Transport.
			 */
	
			if ( (sngrp_ptr->svc.intf_idx != -1) &&
			     (sngrp_ptr->svc.sn_idx != -1) )
			{
				/* There is a BFD Service associated
				 * with this Right BFD Transport.
				 */
				*svc_intf_idx_ptr = sngrp_ptr->svc.intf_idx;
				*svc_sn_idx_ptr   = sngrp_ptr->svc.sn_idx;

				retval = IPM_SUCCESS;
			}
			else
			{
				EIPM_LOG_ERROR( 0, "Error: %s Right BFD Transport intf_idx %d, sn_idx %d associated with BFD Service intf_idx %d, sn_idx %d\n", __FUNCTION__, sngrp_ptr->right.intf_idx, sngrp_ptr->right.sn_idx, sngrp_ptr->svc.intf_idx, sngrp_ptr->svc.sn_idx );
			}

		}
	}

	// LOG_OTHER( 0, "BFD_DEBUG: Exiting %s() svc_intf_idx=%d, svc_sn_idx=%d, retval=%d\n", __FUNCTION__, *svc_intf_idx_ptr, *svc_sn_idx_ptr, retval );

	return retval;

} /* EIPM_bfd_map_right2svc() */

int EIPM_bfd_map_svc2trans(
		int svc_intf_idx,
		int svc_sn_idx,
		int *left_intf_idx_ptr,
		int *left_sn_idx_ptr,
		int *right_intf_idx_ptr,
		int *right_sn_idx_ptr
	)
{
	/* Given a pair of BFD Service subnet indices, populates
	 * the associated Left and Right BFD Transport indices.
	 */

	EIPM_BFD_MAP_SNGRP *sngrp_ptr;	/* pointer to the set of Left BFD
					 * Transport, Right BFD Transport,
					 * and BFD Service subnets
					 * associated with the current subnet.
					 */

	IPM_RETVAL	retval;

	// LOG_OTHER( 0, "BFD_DEBUG: Entering %s() svc_intf_idx=%d, svc_sn_idx=%d\n", __FUNCTION__, svc_intf_idx, svc_sn_idx );

	*left_intf_idx_ptr	= -1;
	*left_sn_idx_ptr	= -1;
	*right_intf_idx_ptr	= -1;
	*right_sn_idx_ptr	= -1;

	retval = EIPM_bfd_get_subnet_map(&sngrp_ptr,svc_intf_idx,svc_sn_idx);

	if (retval == IPM_SUCCESS)
	{
		retval = IPM_FAILURE;

		if ( (sngrp_ptr->svc.intf_idx == svc_intf_idx) &&
		     (sngrp_ptr->svc.sn_idx   == svc_sn_idx) )
		{
			/* The provided interface and subnet indices
			 * do belong to a BFD Service Subnet.
			 */
	
			*left_intf_idx_ptr  = sngrp_ptr->left.intf_idx;
			*left_sn_idx_ptr    = sngrp_ptr->left.sn_idx;
			*right_intf_idx_ptr = sngrp_ptr->right.intf_idx;
			*right_sn_idx_ptr   = sngrp_ptr->right.sn_idx;

			retval = IPM_SUCCESS;
		}
	}

	// LOG_OTHER( 0, "BFD_DEBUG: Exiting %s() left_intf_idx=%d, left_sn_idx=%d, right_intf_idx=%d, right_sn_idx=%d, retval=%d\n", __FUNCTION__, *left_intf_idx_ptr, *left_sn_idx_ptr, *right_intf_idx_ptr, *right_sn_idx_ptr, retval );

	return retval;

} /* EIPM_bfd_map_svc2trans() */

int EIPM_bfd_tout()
{
	/* Pointer to shared memory */
	EIPM_DATA		*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;

	register EIPM_INTF	*intf_ptr;
	EIPM_INTF_SPEC		*intfSpecDataP;
	int			intf_idx;
	int			num_intfs;

#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
	prev_dump_subnet_map = dump_subnet_map;
	dump_subnet_map = 0;	// necessary to avoid dumping it every 5ms
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */

	/* Inform the BFD FSM that its timer has expired so it can
	 * decide whether or not it's time to send a new BFD control
	 * packet and/or check for having received a BFD control packet
	 * in the required interval for all of it's BFD Sessions.
	 */
	BFD_timer();

	/* Ditto for ARPNDP FSM */
	ARPNDP_timer();

	num_intfs = shm_ptr->intf_cnt;

	/* Init the array that maps BFD Subnets to each other because we
	 * need to associated left, right, and service subnets during the
	 * audit and BFD subnets may have been added, deleted, or modified
	 * since the last time this function was called.
	 */
	EIPM_bfd_init_subnet_map();

	/* Handle the timeout for all interfaces. */
	for( intf_idx=0; intf_idx < num_intfs; intf_idx++ )
	{
		intf_ptr = &(shm_ptr->intf_data[intf_idx]);

		intfSpecDataP = &(intf_ptr->specData);

		if (intfSpecDataP->monitor == EIPM_MONITOR_BFD)
		{

#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
			if (dump_subnet_map) LOG_FORCE( 0, "BFD_DEBUG: %s calling EIPM_bfd_tout_intf(), intf_idx=%d, num_intfs=%d\n", __FUNCTION__, intf_idx, num_intfs );
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */

			if ( EIPM_GET_INTF_CHECK_TIMER( intfSpecDataP ) == 0 
			     && (EIPM_GET_INTF_CHECK_DISABLE( intfSpecDataP ) == FALSE ))
			{
				EIPM_check_ip_plumbing( intf_ptr, EIPM_BASE_INTF );
			}

			(void)EIPM_bfd_tout_intf(intf_ptr,intf_idx);
		}

	} /* end 'for each monitored interface' */

	/* Re-Init the array that maps BFD Subnets to each other in case
	 * other functionality needs this type of information but BFD
	 * subnets may have been added, deleted, or modified since this
	 * function was called so we need to ensure that that other
	 * functionality knows to rebuild the array. Hopefully the array
	 * will be initialized explicitly by that functionality but
	 * given pre-existing code structure that may not always be
	 * possible so this is a cheap and easy way to ensure the array
	 * init flag is set correctly anyway.
	 */
	EIPM_bfd_init_subnet_map();

#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
	dump_subnet_map = prev_dump_subnet_map;
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */

	return IPM_SUCCESS;

} /* EIPM_bfd_tout() */

int EIPM_bfd_tout_intf(register EIPM_INTF *intf_ptr, int intf_idx)
{
	/* Gets called once for every EIPM_INTF interface that uses
	 * BFD for redundancy.
	 */

	EIPM_INTF_SPEC		*intfSpecDataP;
	register EIPM_SUBNET	*sn_ptr;
	int			sn_idx;
	int			num_sns = 0;

	/* Need to loop through all subnets twice to process the timeout
	 * first for all BFD Transport Subnets, then for all BFD Service
	 * Subnets afterwards as that processing relies on updated status
	 * of the BFD Transport Subnets.
	 */

	(void)EIPM_bfd_tout_transports(intf_ptr);

#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
	if (dump_subnet_map) LOG_FORCE( 0, "BFD_DEBUG: %s calling EIPM_bfd_tout_services(), intf_idx=%d\n", __FUNCTION__, intf_idx );
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */

	(void)EIPM_bfd_tout_services(intf_ptr,intf_idx);

	intfSpecDataP = &(intf_ptr->specData);

	num_sns = intf_ptr->subnet_cnt;

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
		int		num_svc_sns = 0;
		bool		all_same_status = TRUE;
		EIPM_STATUS	prev_sn_status, curr_sn_status = EIPM_STAT_NULL;
		EIPM_STATUS	curr_intf_status, next_intf_status = EIPM_STAT_NULL;

		sn_ptr = &(intf_ptr->subnet[0]);
		prev_sn_status = sn_ptr->status;

		for (sn_idx=0; sn_idx < num_sns; sn_idx++)
		{
			sn_ptr = &(intf_ptr->subnet[sn_idx]);
			curr_sn_status = sn_ptr->status;

			if ((sn_ptr->redundancy_mode == IPM_RED_EIPM_BFD) ||
			    (sn_ptr->redundancy_mode == IPM_RED_BFD_RSR))
			{
				num_svc_sns++;
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

		/*
		 * Interfaces with no service subnet can be at most degraded.
		 */
		if (num_svc_sns == 0 && next_intf_status == EIPM_OFFLINE)
		{
			/*
			 * If all secondary subnets are offline and the corresponding
			 * primary interface is offline (meaning all primary subnets are offline), 
			 * then consider the secondary interface offline.
			 */
			if ((intf_ptr->lsn0_baseif[0] == 0 || 
			     strlen(intf_ptr->lsn0_baseif) == 0) &&
			    (intf_ptr->lsn1_baseif[0] != 0 &&
			     strlen(intf_ptr->lsn1_baseif) != 0))
			{
				for (sn_idx=0; sn_idx < num_sns; sn_idx++)
				{
					int		left_intf_idx;
					int		left_sn_idx;
					IPM_RETVAL	bfd_map_retval;
					EIPM_DATA	*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;

					bfd_map_retval = EIPM_bfd_map_right2left(intf_idx, sn_idx, &left_intf_idx, &left_sn_idx);
					if (bfd_map_retval == IPM_SUCCESS)
					{
						if (shm_ptr->intf_data[left_intf_idx].specData.status != EIPM_OFFLINE)
						{
							next_intf_status = EIPM_DEGRADED;
						}
						break;
					}
				}
			}
			else
			{
				next_intf_status = EIPM_DEGRADED;
			}
		}

		curr_intf_status = intfSpecDataP->status;

		if (curr_intf_status != next_intf_status)
		{
    			// LOG_OTHER( 0, "%s changing Intfc %d status from %d to %d\n", __FUNCTION__, intf_idx, curr_intf_status, next_intf_status );

			intfSpecDataP->status = next_intf_status;
		}

	}

	(void)EIPM_timeout_postprocess(intf_ptr, EIPM_BASE_INTF);

	return IPM_SUCCESS;

} /* EIPM_bfd_tout_intf() */

int EIPM_bfd_tout_transports(register EIPM_INTF *intf_ptr)
{
	/* Gets called once for every EIPM_INTF interface but
	 * only does work for interfaces with BFD Transport Subnets.
	 */

	register EIPM_SUBNET	*sn_ptr;
	int			sn_idx;
	int			num_sns;

	num_sns = intf_ptr->subnet_cnt;

	for (sn_idx=0; sn_idx < num_sns; sn_idx++)
	{
		sn_ptr = &(intf_ptr->subnet[sn_idx]);

		if (sn_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT)
		{
			(void)EIPM_bfd_tout_tran_sn(intf_ptr,sn_idx);
		}

	} /* end 'for each subnet in current interface' */

	return IPM_SUCCESS;

} /* EIPM_bfd_tout_transports() */

int EIPM_bfd_tout_tran_sn( register EIPM_INTF *intf_ptr, int sn_idx )
{
	/* Gets called once for every BFD Transport Subnet
	 * in the current EIPM_INTF interface.
	 */

	register EIPM_SUBNET	*sn_ptr = &(intf_ptr->subnet[sn_idx]);
	EIPM_INTF_SPEC		*intfSpecDataP;
	int			intf_idx;
	int			ip_idx;
	int			num_ips;
	int			num_down = 0;
	EIPM_STATUS		curr_tran_status, next_tran_status;
	EIPM_STATUS		bfd_status;
	EIPM_STATUS		arpndp_status = EIPM_OFFLINE;
	IPM_RETVAL		arpndp_retval;

	intfSpecDataP = &(intf_ptr->specData);

	intf_idx = intfSpecDataP->baseIntfIdx;

	/* This is a BFD Transport Subnet so we need to check the
	 * state of each BFD Session to see if any have now gone
	 * down (in which case raise an Alarm) or come up (in which
	 * case clear any outstanding Alarm).
	 */
	num_ips = sn_ptr->ip_cnt;

	/* 1) check if any BFD Sessions are up */

	/* Loop through the BFD Sessions as represented
	 * by the local IP addresses associated with this 
	 * BFD Transport Subnet.
	 */
	for (ip_idx=0; ip_idx<num_ips; ip_idx++)
	{
		(void)EIPM_bfd_tout_sess( intf_ptr, sn_idx, ip_idx );

		if (sn_ptr->ips[ip_idx].state != EIPM_ONLINE)
		{
			num_down++;
		}

	} /* for each local IP address in the subnet */

	curr_tran_status = sn_ptr->status;
	next_tran_status = curr_tran_status;

	/* Check what we should set the overall subnet status to now to
	 * reflect the condition of the BFD Sessions in this subnet.
	 */
	if (num_ips == 0)
	{
		/* No BFD Sessions provisioned. */
		bfd_status = EIPM_STAT_NULL;
	}
	else if (num_down == 0)
	{
		/* All BFD Sessions are up. */
		bfd_status = EIPM_ONLINE;
	}
	else if (num_down < num_ips)
	{
		/* Some but not all BFD Sessions are down. */
		bfd_status = EIPM_DEGRADED;
	}
	else
	{
		/* All BFD Sessions are down. */
		bfd_status = EIPM_OFFLINE;
	}

	/* 2) start/stop ARP/NDP if necessary */

	if (bfd_status == EIPM_OFFLINE)
	{
		/* All BFD Sessions are down on this BFD Tranport
		 * subnet but we have at least one IP Address provisioned
		 * so we need to ARP/NDP to discover if we have connectivity.
		 */
		arpndp_retval = EIPM_arpndp_start( intf_idx, sn_idx );

		if (arpndp_retval != ARPNDP_SUCCESS)
		{
			EIPM_LOG_ERROR( 0,
				"%s(): EIPM_arpndp_start() failed for intf_idx %d subnet_idx %d with error [%d]\n",
				__FUNCTION__,
				intf_idx,
				sn_idx,
				arpndp_retval
			);
		}

		arpndp_retval = EIPM_arpndp_get_status(intf_idx,sn_idx,&arpndp_status);

		if (arpndp_retval != ARPNDP_SUCCESS)
		{
			EIPM_LOG_ERROR( 0,
				"%s(): EIPM_arpndp_get_status() failed for intf_idx %d subnet_idx %d with error [%d]\n",
				__FUNCTION__,
				intf_idx,
				sn_idx,
				arpndp_retval
			);
		}
	}
	else if ( (bfd_status == EIPM_ONLINE) || (bfd_status == EIPM_DEGRADED) )
	{
		/* At least 1 BFD Session is up so that determines
		 * the next overall BFD Transport subnet status so
		 * stop ARP/NDP if it's running
		 */
		arpndp_retval = EIPM_arpndp_stop( intf_idx, sn_idx );

		if (arpndp_retval != ARPNDP_SUCCESS)
		{
			EIPM_LOG_ERROR( 0,
				"%s(): EIPM_arpndp_stop() failed for intf_idx %d subnet_idx %d with error [%d]\n",
				__FUNCTION__,
				intf_idx,
				sn_idx,
				arpndp_retval
			);
		}

		arpndp_status = EIPM_INHIBITED;
	}

	/* 3) set the next overall status for this BFD Transport based on
	 *    the state of the BFD sessions and, if necessary, the state
	 *    of ARP/NDP.
	 */

	if (bfd_status == EIPM_OFFLINE)
	{
		switch (arpndp_status)
		{
		case EIPM_INHIBITED:	/* ARP/NDP deactivated. */
			next_tran_status = EIPM_OFFLINE;
			break;

		case EIPM_ONLINE:	/* ARP/NDP succeeded. */
			if (EIPM_is_bfd_trans_rsr_svc_sn(intf_idx, sn_idx) == IPM_SUCCESS)
			{
				next_tran_status = EIPM_ONLINE;
			}
			else
			{
				next_tran_status = EIPM_DEGRADED;
			}
			break;

		case EIPM_OFFLINE:	/* ARP/NDP failed. */
			next_tran_status = EIPM_OFFLINE;
			break;

		case EIPM_UNKNOWN:	/* ARP/NDP in progress. */
			if (curr_tran_status == EIPM_ONLINE) {
				next_tran_status = EIPM_DEGRADED;
			}
			break;

		default:
			EIPM_LOG_ERROR( 0, "Error: %s() - EIPM_arpndp_get_status() populated out of range arpndp_status =%d\n", __FUNCTION__, arpndp_status );

			arpndp_status = EIPM_STAT_NULL;

			next_tran_status = curr_tran_status;
			break;

		} /* switch(arpndp_status) */
	}
	else
	{
		arpndp_status = EIPM_INHIBITED;

		next_tran_status = bfd_status;
	}

	/* 4) Check if we need to Set, Clear, or Modify an Alarm.  */

	switch(curr_tran_status)
	{
	case EIPM_ONLINE:
		switch(next_tran_status) {
		case EIPM_ONLINE:
			/* Do Nothing: All BFD Sessions are still up. */
			break;
		case EIPM_OFFLINE:
			/* Set Alarm: All BFD Sessions went down and
			 * ARP/NDP has failed.
			 */
			EIPM_bfd_alarm_tran_sn_set_sess_down(intf_ptr,sn_idx);
			break;
		case EIPM_DEGRADED:
			/* Do Nothing: Some BFD Sessions are still up
			 * or ARP/NDP has succeeded or is in progress.
			 */
			break;
		case EIPM_STAT_NULL:
			/* Do Nothing: all IP addrs have been deprovisioned.
			 */
			break;
		default:
			EIPM_LOG_ERROR( 0, "Error: %s() using out of range EIPM_STATUS - next_tran_status=%d\n", __FUNCTION__, next_tran_status );

			/* Set Alarm: Assume All BFD Sessions went down
			 * and ARP/NDP has failed.
			 */
			EIPM_bfd_alarm_tran_sn_set_sess_down(intf_ptr,sn_idx);

			next_tran_status = EIPM_OFFLINE;
			break;
		}
		break;

	case EIPM_OFFLINE:
		switch(next_tran_status) {
		case EIPM_ONLINE:
			/* Clear Alarm: All BFD Sessions came up. */
			EIPM_bfd_alarm_tran_sn_clr(intf_ptr,sn_idx);
			break;
		case EIPM_OFFLINE:
			/*  Ensure an alarm is generated if offline, but
			 *  allow for ARP/NDP to succeed.
			 */
			if (arpndp_status != EIPM_UNKNOWN )
			{
				/* Set Alarm: Assume All BFD Sessions went down
				 * and ARP/NDP has failed.
				 */
				EIPM_bfd_alarm_tran_sn_set_sess_down(intf_ptr,sn_idx);
			}
			break;
		case EIPM_DEGRADED:
			/* Clear Alarm: Some BFD Sessions came up
			 * or ARP/NDP succeeded.
			 */
			EIPM_bfd_alarm_tran_sn_clr(intf_ptr,sn_idx);
			break;
		case EIPM_STAT_NULL:
			/* Clear Alarm: all IP addrs have been deprovisioned.
			 */
			EIPM_bfd_alarm_tran_sn_clr(intf_ptr,sn_idx);
			break;
		default:
			EIPM_LOG_ERROR( 0, "Error: %s() using out of range EIPM_STATUS - next_tran_status=%d\n", __FUNCTION__, next_tran_status );

			/* Do Nothing: Assume All BFD Sessions are still down
			 * and ARP/NDP has failed.
			 */

			next_tran_status = EIPM_OFFLINE;
			break;
		}
		break;

	case EIPM_DEGRADED:
		switch(next_tran_status) {
		case EIPM_ONLINE:
			/* Do Nothing: Remaining BFD Sessions came up. */
			break;
		case EIPM_OFFLINE:
			/* Set Alarm: Remaining BFD Sessions went down
			 * and ARP/NDP has failed.
			 */
			EIPM_bfd_alarm_tran_sn_set_sess_down(intf_ptr,sn_idx);
			break;
		case EIPM_DEGRADED:
			/* Do Nothing: Some BFD Sessions are still up
			 * or ARP/NDP succeeded or is in progress.
			 */
			break;
		case EIPM_STAT_NULL:
			/* Do Nothing: all IP addrs have been deprovisioned.
			 */
			break;
		default:
			EIPM_LOG_ERROR( 0, "Error: %s() using out of range EIPM_STATUS - next_tran_status=%d\n", __FUNCTION__, next_tran_status );

			/* Set Alarm: Assume All BFD Sessions went down
			 * and ARP/NDP has failed.
			 */
			EIPM_bfd_alarm_tran_sn_set_sess_down(intf_ptr,sn_idx);

			next_tran_status = EIPM_OFFLINE;
			break;
		}
		break;

	case EIPM_STAT_NULL:
		switch(next_tran_status) {
		case EIPM_ONLINE:
			/* Do Nothing: All BFD Sessions came up. */
			break;
		case EIPM_OFFLINE:
			/* Set Alarm: All BFD Sessions went down
			 * and ARP/NDP has failed.
			 */
			EIPM_bfd_alarm_tran_sn_set_sess_down(intf_ptr,sn_idx);
			break;
		case EIPM_DEGRADED:
			/* Do Nothing: Some BFD Sessions came up
			 * or ARP/NDP succeeded.
			 */
			break;
		case EIPM_STAT_NULL:
			/* Do Nothing: still no IP addrs provisioned.
			 */
			break;
		default:
			EIPM_LOG_ERROR( 0, "Error: %s() using out of range EIPM_STATUS - next_tran_status=%d\n", __FUNCTION__, next_tran_status );

			/* Do Nothing: Assume All BFD Sessions are still down
			 * and ARP/NDP has failed.
			 */

			next_tran_status = EIPM_OFFLINE;
			break;
		}
		break;

	default:
		switch(next_tran_status) {
		case EIPM_ONLINE:
			/* Clear Alarm: All BFD Sessions are up. */
			EIPM_bfd_alarm_tran_sn_clr(intf_ptr,sn_idx);
			break;
		case EIPM_OFFLINE:
			/* Set Alarm: All BFD Sessions are down and
			 * ARP/NDP has failed.
			 */
			EIPM_bfd_alarm_tran_sn_set_sess_down(intf_ptr,sn_idx);
			break;
		case EIPM_DEGRADED:
			/* Clear Alarm: Some BFD Sessions are up os
			 * ARP/NDP has succeeded.
			 */
			EIPM_bfd_alarm_tran_sn_clr(intf_ptr,sn_idx);
			break;
		case EIPM_STAT_NULL:
			/* Clear Alarm: all IP addrs have been deprovisioned.
			 */
			EIPM_bfd_alarm_tran_sn_clr(intf_ptr,sn_idx);
			break;
		default:
			EIPM_LOG_ERROR( 0, "Error: %s() using out of range EIPM_STATUS - next_tran_status=%d\n", __FUNCTION__, next_tran_status );

			/* Set Alarm: Assume All BFD Sessions went down
			 * and ARP/NDP has failed.
			 */
			EIPM_bfd_alarm_tran_sn_set_sess_down(intf_ptr,sn_idx);

			next_tran_status = EIPM_OFFLINE;
			break;
		}
		break;

	}

	sn_ptr->bfd_status = bfd_status;
	sn_ptr->arpndp_status = arpndp_status;

	if (curr_tran_status != next_tran_status)
	{
	    // LOG_OTHER( 0, "BFD Transport Subnet status updated from %d to %d.\n", curr_tran_status, next_tran_status );

		sn_ptr->status = next_tran_status;
	}

	return IPM_SUCCESS;

} /* EIPM_bfd_tout_tran_sn() */		


#if EIPM_BFD_DEBUG_SESS_STATUS /* { */

static int  bfd_prev_sess_status[EIPM_MAX_EXT_SUB][EIPM_MAX_SUBNETS][EIPM_MAX_IPS];
static bool bfd_prev_sess_status_populated = FALSE;

#endif /* } EIPM_BFD_DEBUG_SESS_STATUS */

int EIPM_bfd_tout_sess(
		register EIPM_INTF	*intf_ptr,
		int			sn_idx,
		int			ip_idx
	)
{
	EIPM_INTF_SPEC		*intfSpecDataP;
	int			intf_idx;
	register EIPM_SUBNET	*sn_ptr;
	EIPM_IPDATA		*ip_ptr;
	IPM_IPADDR		*loc_ip_addr_ptr, *rmt_ip_addr_ptr;
	EIPM_STATUS		curr_sess_status, next_sess_status;
	BFD_SESS_STATE		sess_state;
	BFD_RETVAL              bfd_retval;

	/* Gets called once for every BFD Session in
	 * the current BFD Transport Subnet.
	 */

	intfSpecDataP = &(intf_ptr->specData);
	intf_idx = intfSpecDataP->baseIntfIdx;

	sn_ptr = &(intf_ptr->subnet[sn_idx]);
	ip_ptr = &(sn_ptr->ips[ip_idx]);
	loc_ip_addr_ptr = &(ip_ptr->ipaddr);
	rmt_ip_addr_ptr = &(sn_ptr->gateway);

	curr_sess_status = ip_ptr->state;

	bfd_retval = BFD_get_sess_state(loc_ip_addr_ptr,rmt_ip_addr_ptr,&sess_state);

	if ( bfd_retval != BFD_SUCCESS )
	{

		char	loc_ip_addr[IPM_IPMAXSTRSIZE];
		char	rmt_ip_addr[IPM_IPMAXSTRSIZE];

		memset(loc_ip_addr, 0, sizeof(loc_ip_addr));
		IPM_ipaddr2p(loc_ip_addr_ptr, loc_ip_addr, IPM_IPMAXSTRSIZE);

		memset(rmt_ip_addr, 0, sizeof(rmt_ip_addr));
		IPM_ipaddr2p(rmt_ip_addr_ptr, rmt_ip_addr, IPM_IPMAXSTRSIZE);

		EIPM_LOG_ERROR( 0,
			"Error: %s() - BFD_get_sess_state( %s, %s ) failed with error [%d]\n",
			__FUNCTION__,
			loc_ip_addr,
			rmt_ip_addr,
			bfd_retval
		);

		sess_state = BFD_SESS_STATE_DOWN;

	}

	switch (sess_state)
	{
	case BFD_SESS_STATE_UP:
		/* Normal case, transport is working */
		next_sess_status = EIPM_ONLINE;
		break;

	case BFD_SESS_STATE_DOWN:
		/* Down due to problems on the transport */
		next_sess_status = EIPM_OFFLINE;
		break;

	case BFD_SESS_STATE_ADMIN_DOWN:
		/* Taken down manually for administrative reasons. */
		next_sess_status = EIPM_OFFLINE;
		break;

	case BFD_SESS_STATE_INIT:
		/* Down but initializing */
		next_sess_status = EIPM_OFFLINE;
		break;

	default:
		/* Out of range */
		EIPM_LOG_ERROR( 0, "Error: BFD_get_sess_state() returned out of range BFD_SESS_STATE sess_state=%d\n", sess_state);
		next_sess_status = EIPM_OFFLINE;
		break;

	} /* switch (sess_state) */

	/* Check if we need to Set, Clear, or Modify an Alarm for
	 * this BFD Session.
	 */

#if EIPM_BFD_DEBUG_SESS_STATUS /* { */

	if (bfd_prev_sess_status_populated == FALSE)
	{
		int	tmp_intf_idx;
		int	tmp_sn_idx;
		int	tmp_ip_idx;
		for (tmp_intf_idx=0; tmp_intf_idx<EIPM_MAX_EXT_SUB; tmp_intf_idx++)
		{
			for (tmp_sn_idx=0; tmp_sn_idx<EIPM_MAX_SUBNETS; tmp_sn_idx++)
			{
				for (tmp_ip_idx=0; tmp_ip_idx<EIPM_MAX_IPS; tmp_ip_idx++)
				{
					bfd_prev_sess_status[tmp_intf_idx][tmp_sn_idx][tmp_ip_idx] = -1;
				}
			}
		}
		bfd_prev_sess_status_populated = TRUE;
	}

	int prev_sess_status = bfd_prev_sess_status[intf_idx][sn_idx][ip_idx];

	if ( (curr_sess_status != prev_sess_status) ||
	     (curr_sess_status != next_sess_status) )
	{

		LOG_FORCE( 0, "BFD_DEBUG: %s intf_idx=%d, subnet_idx=%d, ip_idx=%d, prev_sess_status=%d, curr_sess_status=%d, next_sess_status=%d\n", __FUNCTION__, intf_idx, sn_idx, ip_idx, prev_sess_status, curr_sess_status, next_sess_status );

		bfd_prev_sess_status[intf_idx][sn_idx][ip_idx] = curr_sess_status;
	}

#endif /* } EIPM_BFD_DEBUG_SESS_STATUS */

	switch(curr_sess_status)
	{
	case EIPM_ONLINE:
		switch(next_sess_status) {
		case EIPM_ONLINE:
			/* Do Nothing: This BFD Session is still up. */
			break;
		case EIPM_OFFLINE:
			if (sess_state != BFD_SESS_STATE_ADMIN_DOWN)
			{
				/* Set Alarm: This BFD Session went down
				 * but not as a result of manual action.
				 */
				EIPM_bfd_alarm_sess_set_down(intf_ptr,sn_idx,ip_idx);
			}
			break;
		default:
			EIPM_LOG_ERROR( 0, "Error: %s() using out of range EIPM_STATUS - next_sess_status=%d\n", __FUNCTION__, next_sess_status );

			if (sess_state != BFD_SESS_STATE_ADMIN_DOWN)
			{
				/* Set Alarm: Assume this BFD Session went down 
				 * but not as a result of manual action.
				 */
				EIPM_bfd_alarm_sess_set_down(intf_ptr,sn_idx,ip_idx);
			}
			next_sess_status = EIPM_OFFLINE;
			break;
		}
		break;

	case EIPM_OFFLINE:
		switch(next_sess_status) {
		case EIPM_ONLINE:
			/* Clear Alarm: This BFD Session came up. */
			EIPM_bfd_alarm_sess_clr(intf_ptr,sn_idx,ip_idx);
			break;
		case EIPM_OFFLINE:
			if (sess_state == BFD_SESS_STATE_ADMIN_DOWN)
			{
				/* This BFD Session is down as
				 * a result of manual action.  
				 * Clear any existing alarm.
				 */
				EIPM_bfd_alarm_sess_clr(intf_ptr,sn_idx,ip_idx);
			}
			else
			{
				/* Make sure the alarm is set. We need to do this
				 * to ensure the alarm is set in the scenarion
				 * when we initially are provisioned and the state
				 * is set to OFFLINE but then a failure in
				 * establishing the BFD Session means it stays
				 * OFFLINE so we can't rely on a previous state
				 * of OFFLINE meaning that an alarm is already set.
				 */
				EIPM_bfd_alarm_sess_set_down(intf_ptr,sn_idx,ip_idx);
			}
			break;
		default:
			EIPM_LOG_ERROR( 0, "Error: %s() using out of range EIPM_STATUS - next_sess_status=%d\n", __FUNCTION__, next_sess_status );

			/* Do Nothing: Assume this BFD Session is still down */

			next_sess_status = EIPM_OFFLINE;
			break;
		}
		break;

	case EIPM_STAT_NULL:
		switch(next_sess_status) {
		case EIPM_ONLINE:
			/* Do Nothing: This BFD Session came up from
			 * initially being grown in. There was no alarm
			 * so nothing to clear.
			 */
			break;
		case EIPM_OFFLINE:
			if (sess_state == BFD_SESS_STATE_ADMIN_DOWN)
			{
				/* This BFD Session is down as
				 * a result of manual action.  
				 * Clear any existing alarm.
				 */
				EIPM_bfd_alarm_sess_clr(intf_ptr,sn_idx,ip_idx);
			}
			else
			{
				/* Set Alarm: This BFD Session was just
				 * provisioned but immediately went
				 * offline.
				 */
				EIPM_bfd_alarm_sess_set_down(intf_ptr,sn_idx,ip_idx);
			}
			break;
		default:
			EIPM_LOG_ERROR( 0, "Error: %s() using out of range EIPM_STATUS - next_sess_status=%d\n", __FUNCTION__, next_sess_status );

			if (sess_state != BFD_SESS_STATE_ADMIN_DOWN)
			{
				/* Set Alarm: Assume this BFD Session went down 
				 * but not as a result of manual action.
				 */
				EIPM_bfd_alarm_sess_set_down(intf_ptr,sn_idx,ip_idx);
			}
			next_sess_status = EIPM_OFFLINE;
			break;
		}
		break;

	default:
		switch(next_sess_status) {
		case EIPM_ONLINE:
			/* Clear Alarm: This BFD Session is up. */
			EIPM_bfd_alarm_sess_clr(intf_ptr,sn_idx,ip_idx);
			break;
		case EIPM_OFFLINE:
			if (sess_state == BFD_SESS_STATE_ADMIN_DOWN)
			{
				/* Clear Alarm: This BFD Session may have
				 * been down previously and had an alarm
				 * on it but now it is down as a result of
				 * manual action and so must not be alarmed.
				 */
				EIPM_bfd_alarm_sess_clr(intf_ptr,sn_idx,ip_idx);
			}
			else
			{
				/* Set Alarm: This BFD Session may have
				 * been down previously as a result of
				 * manual action but now it is not.
				 */
				EIPM_bfd_alarm_sess_set_down(intf_ptr,sn_idx,ip_idx);
			}
			break;
		default:
			EIPM_LOG_ERROR( 0, "Error: %s() using out of range EIPM_STATUS - next_sess_status=%d\n", __FUNCTION__, next_sess_status );

			if (sess_state != BFD_SESS_STATE_ADMIN_DOWN)
			{
				/* Set Alarm: Assume this BFD Session went down 
				 * but not as a result of manual action.
				 */
				EIPM_bfd_alarm_sess_set_down(intf_ptr,sn_idx,ip_idx);
			}
			next_sess_status = EIPM_OFFLINE;
			break;
		}
		break;

	}

	if (curr_sess_status != next_sess_status)
	{
	    // LOG_OTHER( 0, "BFD Session status updated from %d to %d.\n", curr_sess_status, next_sess_status );

		ip_ptr->state = next_sess_status;
	}

	return IPM_SUCCESS;

} /* EIPM_bfd_tout_sess() */

int EIPM_bfd_tout_services(register EIPM_INTF *intf_ptr, int intf_idx)
{
	/* Gets called once for every EIPM_INTF interface but
	 * only does work for interfaces with BFD Service Subnets.
	 */
	register EIPM_SUBNET	*sn_ptr;
	int			sn_idx;
	int			num_sns;

	num_sns = intf_ptr->subnet_cnt;

	for (sn_idx=0; sn_idx < num_sns; sn_idx++)
	{
		sn_ptr = &(intf_ptr->subnet[sn_idx]);

		if ((sn_ptr->redundancy_mode == IPM_RED_EIPM_BFD) ||
		    (sn_ptr->redundancy_mode == IPM_RED_BFD_RSR))
		{
			/* Found a BFD Service Subnet so check all the
			 * BFD Transports to determine the current side
			 * to route over and set alarms if necessary.
			 */

#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
			if (dump_subnet_map) LOG_FORCE( 0, "BFD_DEBUG: %s calling EIPM_bfd_tout_svc_sn(), intf_idx=%d, sn_idx=%d\n", __FUNCTION__, intf_idx, sn_idx );
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */

			(void)EIPM_bfd_tout_svc_sn(intf_ptr,intf_idx,sn_idx );
		}

	} /* end 'for each subnet in current interface' */

	return IPM_SUCCESS;

} /* EIPM_bfd_tout_services() */

int EIPM_bfd_tout_svc_sn( register EIPM_INTF *svc_intf_ptr,
			int svc_intf_idx,
			int svc_sn_idx )
{
	/* Gets called once for every BFD Service Subnet */

	EIPM_DATA		*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;

	EIPM_INTF_SPEC		*intfSpecDataP;

	register EIPM_SUBNET	*svc_sn_ptr = (EIPM_SUBNET*)NULL;

	register EIPM_INTF	*left_intf_ptr = (EIPM_INTF*)NULL;
	int			left_intf_idx;
	register EIPM_SUBNET	*left_sn_ptr = (EIPM_SUBNET*)NULL;
	int			left_sn_idx;

	register EIPM_INTF	*right_intf_ptr = (EIPM_INTF*)NULL;
	int			right_intf_idx;
	register EIPM_SUBNET	*right_sn_ptr = (EIPM_SUBNET*)NULL;
	int			right_sn_idx;

	/* Pointers into array of subnets info, for convenience */
	EIPM_BFD_MAP_INTFC	*intfc2map_ptr = (EIPM_BFD_MAP_INTFC*)NULL;
	EIPM_BFD_MAP_SNGRP	*sngrp_ptr = (EIPM_BFD_MAP_SNGRP*)NULL;

	EIPM_NET		curr_route_priority, next_route_priority;

	EIPM_STATUS		left_status, right_status;
	EIPM_STATUS		curr_svc_status, next_svc_status;
	EIPM_STATUS		left_bfd_status, right_bfd_status;
	EIPM_STATUS		left_arpndp_status, right_arpndp_status;

	IPM_RETVAL		retval;

	/* This is a BFD Service Subnet so we need to check the
	 * state of each BFD Transport Subnet it uses to see if
	 * we need to change the routing. At a high level the
	 * algorithm used is:
	 *
	 * if (Left BFD Transport Subnet is available due to BFD)
	 * {
	 *	set routing to use Left (Primary)
	 * }
	 * else if (Right BFD Transport Subnet is available due to BFD)
	 * {
	 *	set routing to use Right (Secondary)
	 * }
	 * else if (Left BFD Transport Subnet is available due to ARP/NDP)
	 * {
	 *	set routing to use Left (Primary)
	 * }
	 * else if (Right BFD Transport Subnet is available due to ARP/NDP)
	 * {
	 *	set routing to use Right (Secondary)
	 * }
	 * else
	 * {
	 *	leave routing as it was.
	 * }
	 */

#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
	if (dump_subnet_map) LOG_FORCE( 0, "BFD_DEBUG: %s calling EIPM_bfd_get_subnet_map(), intf_idx=%d, sn_idx=%d\n", __FUNCTION__, svc_intf_idx, svc_sn_idx );
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */

	intfSpecDataP = &(svc_intf_ptr->specData);
	svc_sn_ptr = &(svc_intf_ptr->subnet[svc_sn_idx]);

	/*****************************************************/
	/* Collect Transports status */
	retval = EIPM_bfd_get_subnet_map(&sngrp_ptr,svc_intf_idx,svc_sn_idx);

	if (retval != IPM_SUCCESS)
	{
		return retval;
	}

	left_status = left_bfd_status = left_arpndp_status = EIPM_STAT_NULL;

	left_intf_idx = sngrp_ptr->left.intf_idx;

	if (left_intf_idx != -1)
	{
		/* We have a left BFD Transport Subnet so get it's
		 * status.
		 */
		left_sn_idx = sngrp_ptr->left.sn_idx;

		left_intf_ptr = &(shm_ptr->intf_data[left_intf_idx]);

		left_sn_ptr = &(left_intf_ptr->subnet[left_sn_idx]);

		left_status = left_sn_ptr->status;

		left_bfd_status = left_sn_ptr->bfd_status;

		left_arpndp_status = left_sn_ptr->arpndp_status;
	}

	right_status = right_bfd_status = right_arpndp_status = EIPM_STAT_NULL;

	right_intf_idx = sngrp_ptr->right.intf_idx;

	if (right_intf_idx != -1)
	{
		/* We have a right BFD Transport Subnet so get it's
		 * status.
		 */
		right_sn_idx = sngrp_ptr->right.sn_idx;

		right_intf_ptr = &(shm_ptr->intf_data[right_intf_idx]);

		right_sn_ptr = &(right_intf_ptr->subnet[right_sn_idx]);

		right_status = right_sn_ptr->status;

		right_bfd_status = right_sn_ptr->bfd_status;

		right_arpndp_status = right_sn_ptr->arpndp_status;
	}

	/*****************************************************/
	/* Check routing */
	curr_route_priority = next_route_priority 
		= svc_sn_ptr->sub2intf_mapping[0].route_priority;

	if ( (left_bfd_status == EIPM_ONLINE) ||
	     (left_bfd_status == EIPM_DEGRADED) )
	{
	 	/* Some or all BFD sessions up on Left Transport Subnet
	 	 * so set routing to use Left (Primary)
		 */
		next_route_priority = LSN0;
	}
	else if ( (right_bfd_status == EIPM_ONLINE) ||
		  (right_bfd_status == EIPM_DEGRADED) )
	{
	 	/* All BFD sessions down on Left Transport Subnet but
	 	 * some or all BFD sessions up on Right Transport Subnet
	 	 * so set routing to use Right (Secondary)
		 */
		next_route_priority = LSN1;
	}
	else if (left_arpndp_status == EIPM_ONLINE)
	{
	 	/* All BFD sessions down on Left Transport Subnet but
	 	 * ARP/NDP succeeded on Left Transport Subnet
	 	 * so set routing to use Left (Primary)
		 */
		next_route_priority = LSN0;
	}
	else if (right_arpndp_status == EIPM_ONLINE)
	{
	 	/* All BFD sessions down on Left Transport Subnet and
	 	 * all BFD sessions down on Right Transport Subnet but
	 	 * ARP/NDP succeeded on Right Transport Subnet
	 	 * so set routing to use Right (Secondary)
		 */
		next_route_priority = LSN1;
	}

	if (curr_route_priority != next_route_priority)
	{
		// LOG_OTHER( 0, "BFD Service Subnet route priority updated from %d to %d.\n", curr_route_priority, next_route_priority );

		EIPM_update_subnet_route_priority( intfSpecDataP, svc_sn_ptr, next_route_priority );

		EIPM_CHECK_INTF_CONFIG(intfSpecDataP);

		EIPM_SET_GRAT_ARP(svc_sn_ptr, svc_sn_ptr->sub2intf_mapping[0].route_priority);

		if (left_sn_ptr != (EIPM_SUBNET*)NULL)
		{
		    /* Since the Left subnet contains the routes, it's
		     * priority must be the same as the Service Subnet
		     * to satisfy the existing routing code.
		     */
		    // LOG_OTHER( 0, "BFD Left Transport Subnet route priority updated from %d to %d.\n", left_sn_ptr->route_priority,svc_sn_ptr->sub2intf_mapping[0].route_priority); 

		   EIPM_update_subnet_route_priority( intfSpecDataP, left_sn_ptr, svc_sn_ptr->sub2intf_mapping[0].route_priority );
		}
	}

	/*****************************************************/
	/* Check alarms */
	curr_svc_status = next_svc_status = svc_sn_ptr->status;

	/* Now set the overall status of this BFD Service subnet */
	if (svc_sn_ptr->ip_cnt == 0)
	{
		/* No IP addresses provisioned */
		next_svc_status = EIPM_STAT_NULL;
	}
	else
	{
		if (left_status == EIPM_ONLINE)
		{
			if (right_status == EIPM_ONLINE)
			{
				next_svc_status = EIPM_ONLINE;
			}
			else
			{
				next_svc_status = EIPM_DEGRADED;
			}
		}
		else if (left_status == EIPM_DEGRADED)
		{
			next_svc_status = EIPM_DEGRADED;
		}
		else if ( (right_status == EIPM_ONLINE) ||
			  (right_status == EIPM_DEGRADED) )
		{
			next_svc_status = EIPM_DEGRADED;
		}
		else
		{
			/* All BFD Sessions and ARP/NDP are down on
			 * both the left and right BFD Transports.
			 */
			next_svc_status = EIPM_OFFLINE;
		}
	}

	if (curr_svc_status != next_svc_status)
	{
		if ( (left_status != EIPM_STAT_NULL) &&
		     (right_status != EIPM_STAT_NULL) )
		{
			/* Both transports are provisioned so clear the
			 * "Missing Transports" alarm/condition if it was set.
			 */
			EIPM_bfd_alarm_svc_sn_clr_miss_tran(svc_intf_ptr,svc_sn_idx);
		}
	
		switch(curr_svc_status)
		{
		case EIPM_ONLINE:
			switch(next_svc_status) {
			case EIPM_OFFLINE:
				/* Set Alarm: Both BFD Transports are down. */
				EIPM_bfd_alarm_svc_sn_set_tran_down(svc_intf_ptr,svc_sn_idx);
				break;
			case EIPM_DEGRADED:
				/* Do Nothing: Only one BFD Transport not ONLINE. */
				break;
			case EIPM_STAT_NULL:
				/* Do Nothing: all IP addrs have been deprovisioned. */
				break;
			default:
				EIPM_LOG_ERROR( 0, "Error: %s() unexpected status change curr_svc_status=%d, next_svc_status=%d\n", __FUNCTION__, curr_svc_status, next_svc_status );
				break;
			}
			break;
	
		case EIPM_OFFLINE:
			switch(next_svc_status) {
			case EIPM_ONLINE:
				/* Clear Alarm: Both BFD Transports came up. */
				EIPM_bfd_alarm_svc_sn_clr_tran_down(svc_intf_ptr,svc_sn_idx);
				break;
			case EIPM_DEGRADED:
				/* Clear Alarm: BFD Transport(s) no longer OFFLINE. */
				EIPM_bfd_alarm_svc_sn_clr_tran_down(svc_intf_ptr,svc_sn_idx);
				break;
			case EIPM_STAT_NULL:
				/* Clear Alarm: all IP addrs have been deprovisioned. */
				EIPM_bfd_alarm_svc_sn_clr_tran_down(svc_intf_ptr,svc_sn_idx);
				break;
			default:
				EIPM_LOG_ERROR( 0, "Error: %s() unexpected status change curr_svc_status=%d, next_svc_status=%d\n", __FUNCTION__, curr_svc_status, next_svc_status );
				break;
			}
			break;
	
		case EIPM_DEGRADED:
			switch(next_svc_status) {
			case EIPM_ONLINE:
				/* Do Nothing: Both BFD Transport now up. */
				break;
			case EIPM_OFFLINE:
				/* Set Alarm: Both BFD Transport now down. */
				EIPM_bfd_alarm_svc_sn_set_tran_down(svc_intf_ptr,svc_sn_idx);
				break;
			case EIPM_STAT_NULL:
				/* Do Nothing: all IP addrs have been deprovisioned. */
				break;
			default:
				EIPM_LOG_ERROR( 0, "Error: %s() unexpected status change curr_svc_status=%d, next_svc_status=%d\n", __FUNCTION__, curr_svc_status, next_svc_status );
				break;
			}
			break;
	
		case EIPM_STAT_NULL:
			switch(next_svc_status) {
			case EIPM_ONLINE:
				/* Do Nothing: Left BFD Transport came up. */
				break;
			case EIPM_OFFLINE:
				/* Set Alarm: Both BFD Transports went down. */
				EIPM_bfd_alarm_svc_sn_set_tran_down(svc_intf_ptr,svc_sn_idx);
				break;
			case EIPM_DEGRADED:
				/* Do Nothing : BFD Transport(s) not ONLINE. */
				break;
			case EIPM_STAT_NULL:
				/* Do Noting: still no IP addrs provisioned. */
				break;
			default:
				EIPM_LOG_ERROR( 0, "Error: %s() unexpected status change curr_svc_status=%d, next_svc_status=%d\n", __FUNCTION__, curr_svc_status, next_svc_status );
				break;
			}
			break;
	
		default:
			switch(next_svc_status) {
			case EIPM_ONLINE:
				/* Clear Alarm: Both BFD Transports are up. */
				EIPM_bfd_alarm_svc_sn_clr_tran_down(svc_intf_ptr,svc_sn_idx);
				break;
			case EIPM_OFFLINE:
				/* Set Alarm: Both BFD Transports are down. */
				EIPM_bfd_alarm_svc_sn_set_tran_down(svc_intf_ptr,svc_sn_idx);
				break;
			case EIPM_DEGRADED:
				/* Clear Alarm: BFD Transport(s) not OFFLINE. */
				EIPM_bfd_alarm_svc_sn_clr_tran_down(svc_intf_ptr,svc_sn_idx);
				break;
			case EIPM_STAT_NULL:
				/* Clear Alarm: all IP addrs have been deprovisioned. */
				EIPM_bfd_alarm_svc_sn_clr_tran_down(svc_intf_ptr,svc_sn_idx);
				break;
			default:
				/* Do nothing, logged below */
				break;
			}

			EIPM_LOG_ERROR( 0, "Error: %s() unexpected status change curr_svc_status=%d, next_svc_status=%d\n", __FUNCTION__, curr_svc_status, next_svc_status );
			break;
	
		}

		// LOG_OTHER( 0, "BFD Service Subnet status updated from %d to %d.\n", curr_svc_status, next_svc_status );
	
		svc_sn_ptr->status = next_svc_status;
	}
	else
	{
		if (next_svc_status == EIPM_OFFLINE) 
		{
			/* Set Alarm: Both BFD Transports are down. */
			EIPM_bfd_alarm_svc_sn_set_tran_down(svc_intf_ptr,svc_sn_idx);
		}
	}
	return IPM_SUCCESS;

} /* EIPM_bfd_tout_svc_sn() */

int EIPM_bfd_ipcfg_check_sn(
		bool			found_entry,
		EIPM_INTF		*intf_ptr,
		EIPM_SUBNET		*subnet_ptr,
		EIPM_IPDATA		*ip_ptr,
		EIPM_TABLE_ENTRY	*ip_tbl_ptr,
		EIPM_INTF_SPEC		*intfSpecDataP,
		EIPM_NET		plumbed_interface,
		int			nl_socket
	)
{
	/* Check and update if necessary IP plumbing for a subnet
	 * that uses BFD redundancy protocol.
	 */

	int retval 			= IPM_SUCCESS;
	int temp_retval 		= IPM_SUCCESS;

	bool lsn0_eipm_populated	= FALSE;
	bool lsn1_eipm_populated	= FALSE;

	bool lsn0_os_populated		= FALSE;
	bool lsn1_os_populated		= FALSE;

	bool lsn0_garp_required 	= FALSE;
	bool lsn1_garp_required 	= FALSE;

	bool updated_ip_config 		= FALSE;

	if ( (intfSpecDataP->lsn0_iface_indx > 0) &&
	     (ip_ptr->lsn0_iface[0] != 0) &&
  	     (strlen(ip_ptr->lsn0_iface) != 0) )
	{
		lsn0_eipm_populated = TRUE;
	}

	if ( (intfSpecDataP->lsn1_iface_indx > 0) &&
	     (ip_ptr->lsn1_iface[0] != 0) &&
  	     (strlen(ip_ptr->lsn1_iface) != 0) )
	{
		lsn1_eipm_populated = TRUE;
	}

	if (found_entry == TRUE)
	{
		if ( ip_tbl_ptr->lsnA_idx != -1 )
		{
			/* lsnA_idx is populated in the OS, now let's
			 * see which of the EIPM lsn0 or lsn1 values
			 * it represents.
			 */
			if ( ip_tbl_ptr->lsnA_idx == intfSpecDataP->lsn0_iface_indx )
			{
				lsn0_os_populated = TRUE;
			}
			else if ( ip_tbl_ptr->lsnA_idx == intfSpecDataP->lsn1_iface_indx )
			{
				lsn1_os_populated = TRUE;
			}
			else
			{
				/* OS lsnA is populated but matches neither
				 * EIPM lsn0 nor lsn1 so delete it.
				 */
				temp_retval = EIPM_DELETE_IP( nl_socket,
					ip_ptr->type,
					&ip_tbl_ptr->ipaddr,
					ip_tbl_ptr->prefix,
					ip_tbl_ptr->lsnA_idx,
					"" );

				// LOG_OTHER( 0, "EMDUMP: %s() deleting ip_tbl_ptr->lsnA_idx=%d, result=%d\n", __FUNCTION__, ip_tbl_ptr->lsnA_idx, temp_retval );

				if ( retval == IPM_SUCCESS )
				{
					retval = temp_retval;
				}

				updated_ip_config = TRUE;
			}
		}

		if ( ip_tbl_ptr->lsnB_idx != -1 )
		{
			/* lsnB_idx is populated in the OS, now let's
			 * see which of the EIPM lsn0 or lsn1 values
			 * it represents.
			 */
			if ( ip_tbl_ptr->lsnB_idx == intfSpecDataP->lsn0_iface_indx )
			{
				lsn0_os_populated = TRUE;
			}
			else if ( ip_tbl_ptr->lsnB_idx == intfSpecDataP->lsn1_iface_indx )
			{
				lsn1_os_populated = TRUE;
			}
			else
			{
				/* OS lsnB is populated but matches neither
				 * EIPM lsn0 nor lsn1 so delete it.
				 */
				temp_retval = EIPM_DELETE_IP( nl_socket,
					ip_ptr->type,
					&ip_tbl_ptr->ipaddr,
					ip_tbl_ptr->prefix,
					ip_tbl_ptr->lsnB_idx,
					"" );

				// LOG_OTHER( 0, "EMDUMP: %s() deleting ip_tbl_ptr->lsnB_idx=%d, result=%d\n", __FUNCTION__, ip_tbl_ptr->lsnB_idx, temp_retval );

				if ( retval == IPM_SUCCESS )
				{
					retval = temp_retval;
				}

				updated_ip_config = TRUE;
			}
		}
	}

	if ( (lsn0_eipm_populated == TRUE) && (lsn0_os_populated == FALSE) )
	{
		temp_retval = EIPM_ADD_IP( nl_socket, 
				ip_ptr->type,
				&ip_ptr->ipaddr,
				subnet_ptr->prefixlen,
				intfSpecDataP->lsn0_iface_indx,
				ip_ptr->lsn0_iface );

		// LOG_OTHER( 0, "EMDUMP: %s() adding intfSpecDataP->lsn0_iface_indx=%d, result=%d\n", __FUNCTION__, intfSpecDataP->lsn0_iface_indx, temp_retval );

		if ( retval == IPM_SUCCESS )
		{
			retval = temp_retval;
		}

		lsn0_garp_required = TRUE;

		updated_ip_config = TRUE;
	}

	if ( (lsn1_eipm_populated == TRUE) && (lsn1_os_populated == FALSE) )
	{
               	temp_retval = EIPM_ADD_IP( nl_socket, 
				ip_ptr->type,
				&ip_ptr->ipaddr,
				subnet_ptr->prefixlen,
				intfSpecDataP->lsn1_iface_indx,
				ip_ptr->lsn1_iface );

		// LOG_OTHER( 0, "EMDUMP: %s() adding intfSpecDataP->lsn1_iface_indx=%d, result=%d\n", __FUNCTION__, intfSpecDataP->lsn1_iface_indx, temp_retval );

		if ( retval == IPM_SUCCESS )
		{
			retval = temp_retval;
		}

		lsn1_garp_required = TRUE;

		updated_ip_config = TRUE;
	}

	if ( (lsn0_garp_required == TRUE) && (lsn1_garp_required == TRUE) )
	{
		EIPM_SET_GRAT_ARP(subnet_ptr, LSN_BOTH);
	}
	else if (lsn0_garp_required == TRUE)
	{
		EIPM_SET_GRAT_ARP(subnet_ptr, LSN0);
	}
	else if (lsn1_garp_required == TRUE)
	{
		EIPM_SET_GRAT_ARP(subnet_ptr, LSN1);
	}

	if ( updated_ip_config == TRUE )
	{
		EIPM_set_ip_config_time(ip_ptr);
	}

	return retval;

} /* EIPM_bfd_ipcfg_check_sn() */

int EIPM_bfd_bld_sessions_list()
{
	/* Pointer to shared memory */
	EIPM_DATA		*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	
	/* Variables to loop through all EIPM_INTFs */
	register EIPM_INTF	*intf_ptr;
	int			intf_idx;
	int			num_intfs;

	/* Variables to loop through the EIPM_SUBNETs associated with
	 * all EIPM_INTSs that have subnets assigned.
	 */
	register EIPM_SUBNET	*sn_ptr;
	int			sn_idx;
	int			num_sns;

	/* Variables to loop through the IP addresses (BFD Sessions)
	 * associated with all BFD Transport subnets.
	 */
	register EIPM_IPDATA	*ip_ptr;
	int			ip_idx;
	int			num_ips;

	/* temp variable to store bfd_sessions_list.sessions[current] mainly
	 * just to reduce length of lines.
	 */
	EIPM_BFD_SESS_PARAMS	*sess_ptr;

	bfd_sessions_list.num_sess	= 0;
	bfd_sessions_list.sess_nr	= 0;

	num_intfs = shm_ptr->intf_cnt;

	/* Find all EIPM_INTFs that contain a BFD Transport Subnet */
	for( intf_idx=0; intf_idx < num_intfs; intf_idx++ )
	{
		intf_ptr = &(shm_ptr->intf_data[intf_idx]);

		num_sns = intf_ptr->subnet_cnt;
		for ( sn_idx=0; sn_idx < num_sns; sn_idx++ )
		{
			sn_ptr = &(intf_ptr->subnet[sn_idx]);
	
			if(sn_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT)
			{
				/* Loop through the BFD Sessions as
				 * represented by the local IP addresses
				 * associated with this BFD Transport Subnet.
				 */
				num_ips = sn_ptr->ip_cnt;

				for (ip_idx=0; ip_idx<num_ips; ip_idx++)
				{
					ip_ptr = &(sn_ptr->ips[ip_idx]);

					sess_ptr = &(bfd_sessions_list.sessions[bfd_sessions_list.num_sess++]);

					sess_ptr->ipaddr = ip_ptr->ipaddr;
					sess_ptr->gateway = sn_ptr->gateway;
					sess_ptr->detection_multiplier =
						sn_ptr->detection_multiplier;
					sess_ptr->desired_min_tx_interval =
						sn_ptr->desired_min_tx_interval;
					sess_ptr->required_min_rx_interval =
						sn_ptr->required_min_rx_interval;

				} /* for each local IP address in the subnet */
			}
		}

	}

	return IPM_SUCCESS;

} /* EIPM_bfd_bld_sessions_list() */

BFD_RETVAL EIPM_bfd_fsm_cb_audit_sess(
		IPM_IPADDR *ipaddr_ptr,
		IPM_IPADDR *gateway_ptr,
		uint8_t detection_multiplier,
		uint32_t desired_min_tx_interval,
		uint32_t required_min_rx_interval
	)
{
	/*
	 * Logic:
	 *
	 * if BFD session exists at LCP
	 *     if BFD session parameters are the same
	 *         return BFD_SUCCESS
	 *     else
	 *         BFD_change_cfg()
	 *         return BFD_SUCCESS
	 *     end if
	 * else
	 *     return BFD_INTERNAL_FAIL
	 * end if
	 */

	EIPM_BFD_SESS_PARAMS	*sess_ptr;
	BFD_RETVAL			retval = BFD_INTERNAL_FAIL;
	bool				sess_exists = FALSE;
	int				sess_idx;

	/* Note that we only expect this function to get called when the
	 * BFD FSM code thinks that it has data about a BFD session
	 * that the EIPM code does not know about so efficiency isn't a
	 * signifcant concern.
	 */

	for (sess_idx=0;
		(sess_idx < bfd_sessions_list.num_sess) && (sess_exists == FALSE);
			sess_idx++)
	{
		sess_ptr = &(bfd_sessions_list.sessions[sess_idx]);

		if ( (IPM_IPCMPADDR(&(sess_ptr->ipaddr),ipaddr_ptr) ==
					IPM_SUCCESS) &&
		     (IPM_IPCMPADDR(&(sess_ptr->gateway),gateway_ptr) ==
					IPM_SUCCESS) )
		{
			sess_exists = TRUE;
		}
	}

	if (sess_exists == TRUE)
	{
		if ( (sess_ptr->detection_multiplier ==
					detection_multiplier) &&
		     (sess_ptr->desired_min_tx_interval ==
					desired_min_tx_interval) &&
		     (sess_ptr->required_min_rx_interval ==
					required_min_rx_interval) )
		{
			retval = BFD_SUCCESS;
		}
		else
		{
			retval = BFD_change_cfg(
					&(sess_ptr->ipaddr),
					&(sess_ptr->gateway),
					sess_ptr->detection_multiplier,
					sess_ptr->desired_min_tx_interval,
					sess_ptr->required_min_rx_interval
				);
		}
	}
	else
	{
		retval = BFD_INTERNAL_FAIL;
	}

	return retval;

} /* EIPM_bfd_fsm_cb_audit_sess() */

int EIPM_bfd_audit()
{
	/* Gets called at 15 min intervals (at time of writing - check
	 * current value) to audit all EIPM BFD data.
	 */

	/* Pointer to shared memory */
	EIPM_DATA		*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;

	register EIPM_INTF	*intf_ptr;
	EIPM_INTF_SPEC		*intfSpecDataP;
	int			intf_idx;
	int			num_intfs;

#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
	prev_dump_subnet_map = dump_subnet_map;
	dump_subnet_map = 1;	// OK to dump it every 15mins
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */

	/* Need the subnet map to verify relationships between each
	 * BFD Service and its associated BFD Transport subnets. Need
	 * to init it first to ensure it gets built right now.
	 */
	EIPM_bfd_init_subnet_map();
	(void)EIPM_bfd_bld_subnet_map();

	/* Need the sessions list to verify data stored in the BFD FSM
	 * data structures against the data in the EIPM_INTF structures.
	 * This data ALWAYS gets rebuilt when its "bld" function is called.
	 */
	(void)EIPM_bfd_bld_sessions_list();

	num_intfs = shm_ptr->intf_cnt;

	/* Handle the audit for all interfaces. */
	for( intf_idx=0; intf_idx < num_intfs; intf_idx++ )
	{
		intf_ptr = &(shm_ptr->intf_data[intf_idx]);

		intfSpecDataP = &(intf_ptr->specData);

		if (intfSpecDataP->monitor == EIPM_MONITOR_BFD)
		{
			(void)EIPM_bfd_audit_intf(intf_ptr,intf_idx);
		}

	} /* end 'for each monitored interface' */

	/* Re-init the subnet map so it gets rebuilt on next invocation
	 * from the timeout handling functions or anywhere else as data
	 * could have changed by then.
	 */
	EIPM_bfd_init_subnet_map();

#if EIPM_BFD_DEBUG_SUBNET_MAP /* { */
	dump_subnet_map = prev_dump_subnet_map;
#endif /* } EIPM_BFD_DEBUG_SUBNET_MAP */

	return IPM_SUCCESS;

} /* EIPM_bfd_audit() */

int EIPM_bfd_audit_intf(register EIPM_INTF *intf_ptr, int intf_idx)
{
	/* Gets called once for every EIPM_INTF interface
	 * that contains BFD subnet(s).
	 */

	/* Process BFD Transport subnets first to find and clean up any
	 * issues there before working on the BFD Service subnets that
	 * use those Transport subnets.
	 */

	(void)EIPM_bfd_audit_transports(intf_ptr);

	(void)EIPM_bfd_audit_services(intf_ptr,intf_idx);

	return IPM_SUCCESS;

} /* EIPM_bfd_audit_intf() */

int EIPM_bfd_audit_transports(register EIPM_INTF *intf_ptr)
{
	/* Gets called once for every EIPM_INTF interface but
	 * only does work for interfaces with BFD Transport Subnets.
	 */

	register EIPM_SUBNET	*sn_ptr;
	int			sn_idx;
	int			num_sns;

	num_sns = intf_ptr->subnet_cnt;

	for (sn_idx=0; sn_idx < num_sns; sn_idx++)
	{
		sn_ptr = &(intf_ptr->subnet[sn_idx]);

		if (sn_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT)
		{
			(void)EIPM_bfd_audit_tran_sn(intf_ptr,sn_idx);
		}

	} /* end 'for each subnet in current interface' */

	return IPM_SUCCESS;

} /* EIPM_bfd_audit_transports() */

int EIPM_bfd_audit_tran_sn( register EIPM_INTF *intf_ptr, int sn_idx )
{
	/* Gets called once for every BFD Transport Subnet
	 * in the current EIPM_INTF interface.
	 */

	EIPM_DATA		*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;

	register EIPM_SUBNET	*sn_ptr = &(intf_ptr->subnet[sn_idx]);

	int			intf_idx = intf_ptr->specData.baseIntfIdx;

	int			ip_idx;
	int			num_ips;
	EIPM_IPDATA		*ip_ptr;

	int			rt_idx;
	int			num_rts;
	EIPM_ROUTES		*rt_ptr;

	int 			subnet_rt_cnt;
	int			lsn0_baseif_len = 0;
	int			lsn1_baseif_len = 0;

	bool			is_left = FALSE;
	bool			is_right = FALSE;

	/* lsn1_baseif[] may be populated in the same EIPM_INTF where a
	 * Left BFD Transport subnet is stored by virtue of it sharing
	 * space with a BFD Service Subnet.
	 */

	if (intf_ptr->lsn0_baseif[0] != 0)
	{
		lsn0_baseif_len = strlen(intf_ptr->lsn0_baseif);
	}

	if (intf_ptr->lsn1_baseif[0] != 0)
	{
		lsn1_baseif_len = strlen(intf_ptr->lsn1_baseif);
	}

	if ( lsn0_baseif_len != 0 )
	{
		is_left = TRUE;
	}
	else if ( lsn1_baseif_len != 0 )
	{
		is_right = TRUE;
	}

	num_ips = sn_ptr->ip_cnt;

	for (ip_idx=0; ip_idx < num_ips; ip_idx++)
	{
		ip_ptr = &(sn_ptr->ips[ip_idx]);

		if ( IPM_IPADDR_ISUNSPECIFIED(&(ip_ptr->ipaddr)) )
		{
			/* ERROR: IP address not specified. */
			EIPM_LOG_ERROR( 0, "Error: %s() IP address not specified. %d\n", __FUNCTION__, sn_idx);
		}

		if (ip_ptr->type != EIPM_IP_ALIAS)
		{
			/* ERROR: invalid type */
			EIPM_LOG_ERROR( 0, "Error: %s() Invalid type. %d\n", __FUNCTION__, sn_idx);
		}

		if (is_left == TRUE)
		{
			if ( (ip_ptr->lsn0_iface[0] == 0) ||
		  	     (strlen(ip_ptr->lsn0_iface) == 0) )
			{
				/* ERROR: left interface name must be
				 * populated like in the Interface.
				 */
				EIPM_LOG_ERROR( 0, "Error: %s() No Left interface name. %d\n", __FUNCTION__, sn_idx);
			}
			else
			{
				if ( strncmp(ip_ptr->lsn0_iface,
					intf_ptr->lsn0_baseif,
					lsn0_baseif_len ) != 0 )
				{
					/* ERROR: left interface name must
					 * match the Interface.
					 */
					EIPM_LOG_ERROR( 0, "Error: %s() Incorrect Left interface name. %d\n", __FUNCTION__, sn_idx);
				}
			}
		}
		else if (is_right == TRUE)
		{
			if ( (ip_ptr->lsn1_iface[0] == 0) ||
		  	     (strlen(ip_ptr->lsn1_iface) == 0) )
			{
				/* ERROR: right interface name must be
				 * populated like in the Interface.
				 */
				EIPM_LOG_ERROR( 0, "Error: %s() No Right interface name. %d\n", __FUNCTION__, sn_idx);
			}
			else
			{
				if ( strncmp(ip_ptr->lsn1_iface,
					intf_ptr->lsn1_baseif,
					lsn1_baseif_len) != 0 )
				{
					/* ERROR: right interface name must
					 * match the Interface.
					 */
					EIPM_LOG_ERROR( 0, "Error: %s() Incorrect Right interface name. %d\n", __FUNCTION__, sn_idx);
				}
			}
		}

	} /* for (ip_idx=0; ip_idx < num_ips; ip_idx++) */

	/* If this is a Left BFD Transport subnet, it should have
	 * a single SUBNET route associated with it plus OTHER routes.
	 *
	 * If this is a Right BFD Transport subnet, it should have
	 * a single SUBNET route associated with it. All OTHER routes
	 * are on the Left BFD Transport subnet.
	 */
	num_rts = sn_ptr->route_cnt;
	subnet_rt_cnt = 0;
	for (rt_idx=0; rt_idx < num_rts; rt_idx++)
	{
		rt_ptr = &(sn_ptr->routes[rt_idx]);
		switch ( rt_ptr->type )
		{
		case EIPM_ROUTE_SUBN:
			subnet_rt_cnt++;

			if ( ! IPM_IPADDR_ISUNSPECIFIED(&(rt_ptr->nexthop)) )
			{
				/* ERROR: nexthop should not be populated */
				EIPM_LOG_ERROR( 0, "Error: %s() Nexthop unexpectedly populated.\n", __FUNCTION__ );
				EIPM_bfd_prt_route(intf_idx,sn_idx,rt_idx,TRUE);
			}
			break;

		case EIPM_ROUTE_OTH:
			if ( is_right == TRUE )
			{
				/* ERROR: invalid route type for a Right
				 * BFD Transport.
				 */
				EIPM_LOG_ERROR( 0, "Error: %s() Invalid Right BFD Transport route type. %d\n", __FUNCTION__, sn_idx);
				EIPM_bfd_prt_route(intf_idx,sn_idx,rt_idx,TRUE);
			}

			if ( (is_left == TRUE) &&
			     IPM_IPADDR_ISUNSPECIFIED(&(rt_ptr->nexthop)) )
			{
				/* ERROR: nexthop should be populated */
				EIPM_LOG_ERROR( 0, "Error: %s() Nexthop not populated. %d\n", __FUNCTION__, sn_idx);
				EIPM_bfd_prt_route(intf_idx,sn_idx,rt_idx,TRUE);
			}
			break;

		default:
			/* ERROR: invalid route type for a BFD Transport. */
			EIPM_LOG_ERROR( 0, "Error: %s() Invalid BFD Transport route type. %d\n", __FUNCTION__, sn_idx);
			EIPM_bfd_prt_route(intf_idx,sn_idx,rt_idx,TRUE);
			break;
		}
	}

	if ( num_ips > 0 )
	{
		if ( num_rts == 0 )
		{
			/* ERROR: no routes */
			EIPM_LOG_ERROR( 0, "Error: %s() No routes. %d\n", __FUNCTION__, sn_idx);
		}
		else if ( subnet_rt_cnt == 0 )
		{
			/* ERROR: no SUBNET route */
			EIPM_LOG_ERROR( 0, "Error: %s() No SUBNET routes. %d\n", __FUNCTION__, sn_idx);
		}
	}

	if ( subnet_rt_cnt > 1 )
	{
		/* ERROR: too many SUBNET routes */
		EIPM_LOG_ERROR( 0, "Error: %s() Too many SUBNET routes. %d\n", __FUNCTION__, sn_idx);
	}

	if ( IPM_IPADDR_ISUNSPECIFIED(&(sn_ptr->gateway)) )
	{
		/* ERROR: no gateway specified */
		EIPM_LOG_ERROR( 0, "Error: %s() no gateway. %d\n", __FUNCTION__, sn_idx);
	}

	/* Audit each BFD Session between EIPM and the BFD FSM. Loop
	 * through the BFD Sessions as represented by the local IP
	 * addresses associated with this BFD Transport Subnet.
	 */
	for (ip_idx=0; ip_idx<num_ips; ip_idx++)
	{
		(void)EIPM_bfd_audit_sess( intf_ptr, sn_idx, ip_idx );

	} /* for each local IP address in the subnet */

	// LOG_ERROR( 0, "BFD_DEBUG: %s() intf_idx=%d, subnet_idx=%d, is_left=%d, is_right=%d, num_ips=%d\n", __FUNCTION__, intf_idx, sn_idx, is_left, is_right, num_ips);

	if ( (is_left == FALSE) && (is_right == FALSE) )
	{
		EIPM_LOG_ERROR( 0, "Error: %s() BFD Transport is neither Left nor Right intf_idx=%d, subnet_idx=%d\n", __FUNCTION__, intf_idx, sn_idx );
	}
	else
	{
		/* Now verify that a Service subnet exists for this Transport */
		EIPM_INTF	*svc_intf_ptr;
		EIPM_SUBNET	*svc_sn_ptr;
		int		svc_intf_idx = -1;
		int		svc_sn_idx = -1;
		IPM_RETVAL	bfd_map_retval = IPM_FAILURE;

		EIPM_INTF_SN_IDX	svcs_ary[EIPM_MAX_EXT_SUB*EIPM_MAX_SUBNETS];
		int			num_svcs = 0;
		int			svc_nr;

		if (is_left == TRUE)
		{
			bfd_map_retval = EIPM_bfd_map_left2svcs(intf_idx,sn_idx,svcs_ary,&num_svcs);
		}
		else
		{
			bfd_map_retval = EIPM_bfd_map_right2svcs(intf_idx,sn_idx,svcs_ary,&num_svcs);
		}

		// LOG_ERROR( 0, "BFD_DEBUG: %s() bfd_map_retval=%d, num_svcs=%d\n", __FUNCTION__, bfd_map_retval, num_svcs );

		if ( (bfd_map_retval == IPM_SUCCESS) && (num_svcs > 0) )
		{
			if ( num_ips == 0 )
			{
				/* This is only an error if there is a
				 * corresponding BFD Service Subnet and
				 * that BFD Service subnet has an IP
				 * address provisioned and that IP address
				 * was provisioned at least 15 minutes ago.
				 */

				int	svc_num_ips = 0;

				for (svc_nr=0; (svc_nr < num_svcs) &&
					(svc_num_ips == 0); svc_nr++)
				{
					svc_intf_idx = svcs_ary[svc_nr].intf_idx;
					svc_sn_idx   = svcs_ary[svc_nr].sn_idx;

					svc_intf_ptr = &(shm_ptr->intf_data[svc_intf_idx]);
					svc_sn_ptr   = &(svc_intf_ptr->subnet[svc_sn_idx]);

					if ( EIPM_bfd_admin_cfg_ready4audit_svc(
						svc_intf_idx, svc_sn_idx ) == TRUE )
					{
						svc_num_ips = svc_sn_ptr->ip_cnt;
					}
				}

				// LOG_ERROR( 0, "BFD_DEBUG: %s() svc_intf_idx=%d, svc_subnet_idx=%d, svc_sn_ptr->ip_cnt=%d\n", __FUNCTION__, svc_intf_idx, svc_sn_idx, svc_sn_ptr->ip_cnt );

				if (svc_num_ips > 0)
				{
					/* Set Alarm: BFD Transport with no
					 * BFD Sessions but an associated
					 * BFD Service Subnet with an IP
					 * address provisioned at least as long
					 * ago as the audit interval exists.
					 */
					EIPM_bfd_alarm_tran_sn_set_no_sess(intf_ptr,sn_idx);

					EIPM_LOG_ERROR( 0, "Error: %s() Missing BFD Sessions(s): intf_idx=%d, subnet_idx=%d\n", __FUNCTION__, intf_idx, sn_idx );
				}
			}
		}
		else
		{
			EIPM_LOG_ERROR( 0, "Error: %s() Missing BFD Service for Transport intf_idx=%d, subnet_idx=%d, is_left=%d, is_right=%d\n", __FUNCTION__, intf_idx, sn_idx, is_left, is_right );
		}

	}

	return IPM_SUCCESS;

} /* EIPM_bfd_audit_tran_sn() */		

int EIPM_bfd_audit_sess(
		register EIPM_INTF	*intf_ptr,
		int			sn_idx,
		int			ip_idx
	)
{
	register EIPM_SUBNET	*sn_ptr;
	EIPM_IPDATA		*ip_ptr;
	IPM_IPADDR		*loc_ip_addr_ptr, *rmt_ip_addr_ptr;
	BFD_AUDIT_SEQ		begin_middle_end;

	/* Gets called once for every BFD Session in
	 * the current BFD Transport Subnet.
	 */

	sn_ptr = &(intf_ptr->subnet[sn_idx]);
	ip_ptr = &(sn_ptr->ips[ip_idx]);
	loc_ip_addr_ptr = &(ip_ptr->ipaddr);
	rmt_ip_addr_ptr = &(sn_ptr->gateway);

	/* BFD_audit() builds an array of session data on first invocation
	 * only and also needs to know when EIPM is calling it for the final
	 * time so it can go check for any un-audited sessions in it's data.
	 */
	++bfd_sessions_list.sess_nr;
	if ( bfd_sessions_list.sess_nr == 1 )
	{
		begin_middle_end = BFD_AUDIT_SEQ_BEGIN;
	}
	else if ( bfd_sessions_list.sess_nr < bfd_sessions_list.num_sess )
	{
    		begin_middle_end = BFD_AUDIT_SEQ_MIDDLE;
	}
	else
	{
		begin_middle_end = BFD_AUDIT_SEQ_END;
	}

	BFD_audit(
		loc_ip_addr_ptr,
		rmt_ip_addr_ptr,
		sn_ptr->detection_multiplier,
		sn_ptr->desired_min_tx_interval,
		sn_ptr->required_min_rx_interval,
		begin_middle_end
	    );

	return IPM_SUCCESS;

} /* EIPM_bfd_audit_sess() */

int EIPM_bfd_audit_services(register EIPM_INTF *intf_ptr, int intf_idx)
{
	/* Gets called once for every EIPM_INTF interface but
	 * only does work for interfaces with BFD Service Subnets.
	 */
	register EIPM_SUBNET	*sn_ptr;
	int			sn_idx;
	int			num_sns;

	num_sns = intf_ptr->subnet_cnt;

	for (sn_idx=0; sn_idx < num_sns; sn_idx++)
	{
		sn_ptr = &(intf_ptr->subnet[sn_idx]);

		if ((sn_ptr->redundancy_mode == IPM_RED_EIPM_BFD) ||
		    (sn_ptr->redundancy_mode == IPM_RED_BFD_RSR))
		{
			/* Found a BFD Service Subnet */
			(void)EIPM_bfd_audit_svc_sn(intf_ptr,intf_idx,sn_idx);
		}

	} /* end 'for each subnet in current interface' */

	return IPM_SUCCESS;

} /* EIPM_bfd_audit_services() */

int EIPM_bfd_audit_svc_sn( register EIPM_INTF *svc_intf_ptr,
			int svc_intf_idx,
			int svc_sn_idx )
{
	/* Gets called once for every BFD Service Subnet
	 * in the current EIPM_INTF interface.
	 */

	register EIPM_SUBNET	*sn_ptr = &(svc_intf_ptr->subnet[svc_sn_idx]);

	int			ip_idx;
	int			num_ips;
	EIPM_IPDATA		*ip_ptr;

	int			num_rts;
	int			lsn0_baseif_len = 0;
	int			lsn1_baseif_len = 0;

	bool			has_left = FALSE;
	bool			has_right = FALSE;

	/* lsn1_baseif[] may be populated in the same EIPM_INTF where a
	 * Left BFD Transport subnet is stored by virtue of it sharing
	 * space with a BFD Service Subnet.
	 */

	if (svc_intf_ptr->lsn0_baseif[0] != 0)
	{
		lsn0_baseif_len = strlen(svc_intf_ptr->lsn0_baseif);
	}

	if (svc_intf_ptr->lsn1_baseif[0] != 0)
	{
		lsn1_baseif_len = strlen(svc_intf_ptr->lsn1_baseif);
	}

	if ( lsn0_baseif_len != 0 )
	{
		has_left = TRUE;
	}

	if ( lsn1_baseif_len != 0 )
	{
		has_right = TRUE;
	}

	num_ips = sn_ptr->ip_cnt;

	for (ip_idx=0; ip_idx < num_ips; ip_idx++)
	{
		ip_ptr = &(sn_ptr->ips[ip_idx]);

		if ( IPM_IPADDR_ISUNSPECIFIED(&(ip_ptr->ipaddr)) )
		{
			/* ERROR: IP address not specified. */
			EIPM_LOG_ERROR( 0, "Error: %s() IP address not specified. %d\n", __FUNCTION__, svc_sn_idx);
		}

		if (ip_ptr->type != EIPM_IP_ALIAS)
		{
			/* ERROR: invalid type */
			EIPM_LOG_ERROR( 0, "Error: %s() Invalid type. %d\n", __FUNCTION__, svc_sn_idx);
		}

		if (has_left == TRUE)
		{
			if ( (ip_ptr->lsn0_iface[0] == 0) ||
		  	     (strlen(ip_ptr->lsn0_iface) == 0) )
			{
				/* ERROR: left interface name must be
				 * populated like in the Interface.
				 */
				EIPM_LOG_ERROR( 0, "Error: %s() No Left interface name. %d\n", __FUNCTION__, svc_sn_idx);
			}
			else
			{
				if ( strncmp(ip_ptr->lsn0_iface,
					svc_intf_ptr->lsn0_baseif,
					lsn0_baseif_len) != 0 )
				{
					/* ERROR: left interface name must
					 * match the Interface.
					 */
					EIPM_LOG_ERROR( 0, "Error: %s() Incorrect Left interface name. %d\n", __FUNCTION__, svc_sn_idx);
				}
			}
		}

		if (has_right == TRUE)
		{
			if ( (ip_ptr->lsn1_iface[0] == 0) ||
		  	     (strlen(ip_ptr->lsn1_iface) == 0) )
			{
				/* ERROR: right interface name must be
				 * populated like in the Interface.
				 */
				EIPM_LOG_ERROR( 0, "Error: %s() No Right interface name. %d\n", __FUNCTION__, svc_sn_idx);
			}
			else
			{
				if ( strncmp(ip_ptr->lsn1_iface,
					svc_intf_ptr->lsn1_baseif,
					lsn1_baseif_len) != 0 )
				{
					/* ERROR: right interface name must
					 * match the Interface.
					 */
					EIPM_LOG_ERROR( 0, "Error: %s() Incorrect Right interface name. %d\n", __FUNCTION__, svc_sn_idx);
				}
			}
		}

	} /* for (ip_idx=0; ip_idx < num_ips; ip_idx++) */

	if ( ( (sn_ptr->subnet_base.addrtype == IPM_IPV4) &&
	     				(sn_ptr->prefixlen < 32) ) ||
	   ( ( (sn_ptr->subnet_base.addrtype == IPM_IPV6) &&
		 			(sn_ptr->prefixlen < 128) ) ) )
	{
		/* A subnet route is required */

		num_rts = sn_ptr->route_cnt;
	
		if (num_rts != 1)
		{
			/* ERROR: must have 1 SUBNET route
			 * associated with a BFD Service subnet.
			 */
			EIPM_LOG_ERROR( 0, "Error: %s() SUBNET route_cnt=%d in intf_idx=%d subnet_idx=%d\n", __FUNCTION__, num_rts, svc_intf_idx, svc_sn_idx);
		}
	}

	/* Alarm if there are missing BFD Transport Subnets.  */
	EIPM_bfd_alarm_svc_sn_chk_miss_tran(svc_intf_idx,svc_sn_idx);

	return IPM_SUCCESS;

} /* EIPM_bfd_audit_svc_sn() */

/* 
 * Determine if there is a BFD RSR service subnet associated with the subnet passed in.
 */
int EIPM_is_bfd_trans_rsr_svc_sn( int intf_idx,
			int sn_idx )
{
	/* Now verify that a Service subnet exists for this Transport */
	EIPM_DATA	*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	EIPM_INTF	*intf_ptr;
	EIPM_INTF	*svc_intf_ptr;
	EIPM_SUBNET	*svc_sn_ptr;
	int		svc_intf_idx = -1;
	int		svc_sn_idx = -1;
	IPM_RETVAL	bfd_map_retval = IPM_FAILURE;

	int			lsn0_baseif_len = 0;
	int			lsn1_baseif_len = 0;
	EIPM_INTF_SN_IDX	svcs_ary[EIPM_MAX_EXT_SUB*EIPM_MAX_SUBNETS];
	int			num_svcs = 0;
	int			svc_nr;

	bool			is_left = FALSE;
	bool			is_right = FALSE;

	intf_ptr = &(shm_ptr->intf_data[intf_idx]);

	if (intf_ptr->lsn0_baseif[0] != 0)
	{
		lsn0_baseif_len = strlen(intf_ptr->lsn0_baseif);
	}

	if (intf_ptr->lsn1_baseif[0] != 0)
	{
		lsn1_baseif_len = strlen(intf_ptr->lsn1_baseif);
	}

	if ( lsn0_baseif_len != 0 )
	{
		is_left = TRUE;
	}
	else if ( lsn1_baseif_len != 0 )
	{
		is_right = TRUE;
	}

	if (is_left == TRUE)
	{
		bfd_map_retval = EIPM_bfd_map_left2svcs(intf_idx,sn_idx,svcs_ary,&num_svcs);
	}
	else
	{
		bfd_map_retval = EIPM_bfd_map_right2svcs(intf_idx,sn_idx,svcs_ary,&num_svcs);
	}

	// LOG_ERROR( 0, "BFD_DEBUG: %s() bfd_map_retval=%d, num_svcs=%d\n", __FUNCTION__, bfd_map_retval, num_svcs );

	if ( (bfd_map_retval == IPM_SUCCESS) && (num_svcs > 0) )
	{
		for (svc_nr=0; svc_nr < num_svcs;
			svc_nr++)
		{
			svc_intf_idx = svcs_ary[svc_nr].intf_idx;
			svc_sn_idx   = svcs_ary[svc_nr].sn_idx;

			svc_intf_ptr = &(shm_ptr->intf_data[svc_intf_idx]);
			svc_sn_ptr   = &(svc_intf_ptr->subnet[svc_sn_idx]);

			if (svc_sn_ptr->redundancy_mode == IPM_RED_BFD_RSR)
			{
				return IPM_SUCCESS;
			}
		}
	}

	return IPM_FAILURE;
}

/* 
 * Find and administratively disable any BFD sessions.  This condition can occur
 * if a BFD transport subnet and IP comes in before a BFD service subnet.
 */
void EIPM_bfd_rsr_svc_sn_trans_sn_chk( int intf_idx,
			int sn_idx )
{
	EIPM_DATA	*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	EIPM_INTF	*bfd_trans_intf_ptr;
	EIPM_SUBNET	*bfd_trans_subnet_ptr;
	EIPM_IPDATA	*ipdata_ptr;

	int		left_intf_idx;
	int		left_sn_idx;

	int		right_intf_idx;
	int		right_sn_idx;

	int		ip_idx;
	IPM_RETVAL	retval;

	char		local_ip_addr[IPM_IPMAXSTRSIZE];
	char		remote_ip_addr[IPM_IPMAXSTRSIZE];

	retval = EIPM_bfd_map_svc2trans(
		intf_idx,
		sn_idx,
		&left_intf_idx,
		&left_sn_idx,
		&right_intf_idx,
		&right_sn_idx
	);

	if (retval == IPM_SUCCESS)
	{
		if ( (left_intf_idx >= 0) && (left_sn_idx >= 0) )
		{
			bfd_trans_intf_ptr	= &(shm_ptr->intf_data[left_intf_idx]);
			bfd_trans_subnet_ptr	= &bfd_trans_intf_ptr->subnet[left_sn_idx];
				
			for ( ip_idx = 0, ipdata_ptr = &bfd_trans_subnet_ptr->ips[0];
				ip_idx < bfd_trans_subnet_ptr->ip_cnt;
				ip_idx++, ipdata_ptr++ )
			{
				retval = BFD_set_admin_state(
						&ipdata_ptr->ipaddr,
						&bfd_trans_subnet_ptr->gateway,
						BFD_ADMIN_STATE_DOWN
						);

				if ( retval != BFD_SUCCESS )
				{
					memset(local_ip_addr, 0, sizeof local_ip_addr);
					IPM_ipaddr2p(&ipdata_ptr->ipaddr, local_ip_addr, IPM_IPMAXSTRSIZE);
									
					memset(remote_ip_addr, 0, sizeof remote_ip_addr);
					IPM_ipaddr2p(&bfd_trans_subnet_ptr->gateway, remote_ip_addr, IPM_IPMAXSTRSIZE);

					EIPM_LOG_ERROR( 0,
						"%s(): BFD_set_admin_state() failed for local ip %s remote ip %s with error [%d]\n",
						__FUNCTION__,
						(local_ip_addr[0] != '\0' ? local_ip_addr : "empty"),
						(remote_ip_addr[0] != '\0' ? remote_ip_addr : "empty"),
						retval
					);
				}
			}
		}

		if ( (right_intf_idx >= 0) && (right_sn_idx >= 0) )
		{
			bfd_trans_intf_ptr	= &(shm_ptr->intf_data[right_intf_idx]);
			bfd_trans_subnet_ptr	= &bfd_trans_intf_ptr->subnet[right_sn_idx];
				
			for ( ip_idx = 0, ipdata_ptr = &bfd_trans_subnet_ptr->ips[0];
				ip_idx < bfd_trans_subnet_ptr->ip_cnt;
				ip_idx++, ipdata_ptr++ )
			{
				retval = BFD_set_admin_state(
						&ipdata_ptr->ipaddr,
						&bfd_trans_subnet_ptr->gateway,
						BFD_ADMIN_STATE_DOWN
						);

				if ( retval != BFD_SUCCESS )
				{
					memset(local_ip_addr, 0, sizeof local_ip_addr);
					IPM_ipaddr2p(&ipdata_ptr->ipaddr, local_ip_addr, IPM_IPMAXSTRSIZE);
									
					memset(remote_ip_addr, 0, sizeof remote_ip_addr);
					IPM_ipaddr2p(&bfd_trans_subnet_ptr->gateway, remote_ip_addr, IPM_IPMAXSTRSIZE);

					EIPM_LOG_ERROR( 0,
						"%s(): BFD_set_admin_state() failed for local ip %s remote ip %s with error [%d]\n",
						__FUNCTION__,
						(local_ip_addr[0] != '\0' ? local_ip_addr : "empty"),
						(remote_ip_addr[0] != '\0' ? remote_ip_addr : "empty"),
						retval
					);
				}
			}
		}
		else
		{
			EIPM_LOG_ERROR( 0,
				"%s(): EIPM_bfd_map_svc2trans() failed for intf_idx %d subnet_idx %d with error [%d]\n",
				__FUNCTION__,
				intf_idx,
				sn_idx,
				retval
			);
		}
	}

	return;
}

void EIPM_bfd_alarm_sess_set(
		register EIPM_INTF	*intf_ptr,
		int			subnet_idx,
		int			ip_idx,
		int			threshold,
		int			severity,
		char			*reason
	)
{
	/* Set an Alarm for a BFD Session */

	char	*baseif_ptr;
	char	linebuf[256];

	if ( (intf_ptr->lsn0_baseif[0] != 0) &&
	     (strlen(intf_ptr->lsn0_baseif) != 0) )
	{
		/* lsn0_baseif[] is not populated for interfaces that
		 * contain Right BFD Transport Subnets, only lsn1_baseif[]
		 * is populated in that case. Since this alarm was fired
		 * while processing a BFD Transport subnet, if lsn0_baseif[]
		 * is populated then this is a Left BFD Transport so we
		 * should use lsn0_baseif[], otherwise it's a Right BFD
		 * Transport Subnet so we should use lsn1_baseif[].
		 * Note that for interfaces containing Left BFD Transport
		 * Subnets, lsn1_baseif[] may or may not also be populated.
		 */
		baseif_ptr = intf_ptr->lsn0_baseif;
	}
	else
	{
		baseif_ptr = intf_ptr->lsn1_baseif;
	}

	sprintf( linebuf, "BFD Session on interface %s, %s.", baseif_ptr, reason);

	EIPM_SEND_IP_ALARM(
		EIPM_SESSION_FAIL,
		threshold,
		intf_ptr,
		subnet_idx,
		ip_idx,
		severity,
		baseif_ptr,
		linebuf
	);

	return;

} /* EIPM_bfd_alarm_sess_set() */

void EIPM_bfd_alarm_sess_set_down(
		register EIPM_INTF	*intf_ptr,
		int			subnet_idx,
		int			ip_idx
	)
{
	/* Set an Alarm for a BFD Session being down */

	EIPM_INTF_SPEC	*intfSpecDataP;
	EIPM_SUBNET	*subnet_ptr;
	EIPM_IPDATA	*ipdata_ptr;
	int		intf_idx;

	intfSpecDataP	= &(intf_ptr->specData);
	intf_idx	= intfSpecDataP->baseIntfIdx;
	subnet_ptr	= &(intf_ptr->subnet[subnet_idx]);
	ipdata_ptr	= &(subnet_ptr->ips[ip_idx]);

	if ( EIPM_bfd_admin_cfg_stable_sess(
		intf_idx, subnet_idx, ipdata_ptr) == TRUE )
	{
		EIPM_bfd_alarm_sess_set( intf_ptr, subnet_idx, ip_idx,
			1, FSAS_major, "Session down" );
	}

	return;

} /* EIPM_bfd_alarm_sess_set_down() */

void EIPM_bfd_alarm_sess_clr(
		register EIPM_INTF	*intf_ptr,
		int			subnet_idx,
		int			ip_idx
	)
{
	/* Clear an Alarm for a BFD Session */

	EIPM_CLEAR_IP_ALARM( intf_ptr, subnet_idx, ip_idx, EIPM_SESSION_FAIL );

	return;

} /* EIPM_bfd_alarm_sess_clr() */

void EIPM_bfd_alarm_tran_sn_set(
		register EIPM_INTF	*intf_ptr,
		int			subnet_idx,
		int			threshold,
		int			severity,
		char			*reason
	)
{
	/* Set an Alarm for a BFD Transport Subnet */

	char	*baseif_ptr;
	char	linebuf[256];

	if ( (intf_ptr->lsn0_baseif[0] != 0) &&
	     (strlen(intf_ptr->lsn0_baseif) != 0) )
	{
		/* lsn0_baseif[] is not populated for interfaces that
		 * contain Right BFD Transport Subnets, only lsn1_baseif[]
		 * is populated in that case. Since this alarm was fired
		 * while processing a BFD Transport subnet, if lsn0_baseif[]
		 * is populated then this is a Left BFD Transport so we
		 * should use lsn0_baseif[], otherwise it's a Right BFD
		 * Transport Subnet so we should use lsn1_baseif[].
		 * Note that for interfaces containing Left BFD Transport
		 * Subnets, lsn1_baseif[] may or may not also be populated.
		 */
		baseif_ptr = intf_ptr->lsn0_baseif;
	}
	else
	{
		baseif_ptr = intf_ptr->lsn1_baseif;
	}

	sprintf( linebuf, "BFD Transport Subnet on interface %s, %s.", baseif_ptr, reason );

	// LOG_FORCE( 0, "Error: %s() reporting %s count=%d, threshold=%d->%d\n", __FUNCTION__, linebuf, intf_ptr->alarm[subnet_idx][EIPM_NEXTHOP_FAIL].count, intf_ptr->alarm[subnet_idx][EIPM_NEXTHOP_FAIL].threshold, threshold);

	EIPM_SEND_SUBNET_ALARM(
		EIPM_NEXTHOP_FAIL,
		threshold,
		intf_ptr,
		EIPM_BASE_INTF,
		subnet_idx,
		severity,
		baseif_ptr,
		linebuf
	);

	return;

} /* EIPM_bfd_alarm_tran_sn_set() */

void EIPM_bfd_alarm_tran_sn_set_no_sess(
		register EIPM_INTF	*intf_ptr,
		int			subnet_idx
	)
{
	/* Set an Alarm for a BFD Transport Subnet that has no
	 * BFD Sessions provisioned.
	 */

	EIPM_bfd_alarm_tran_sn_set( intf_ptr, subnet_idx,
		2, FSAS_major, "no BFD Sessions provisioned" );

	return;

} /* EIPM_bfd_alarm_tran_sn_set_no_sess() */

void EIPM_bfd_alarm_tran_sn_set_sess_down(
		register EIPM_INTF	*intf_ptr,
		int			subnet_idx
	)
{
	/* Set an Alarm for a BFD Transport Subnet that has all
	 * of it's BFD Sessions down
	 */

	EIPM_INTF_SPEC	*intfSpecDataP;
	int		intf_idx;

	intfSpecDataP	= &(intf_ptr->specData);
	intf_idx	= intfSpecDataP->baseIntfIdx;

	if ( EIPM_bfd_admin_cfg_stable_tran(intf_idx, subnet_idx) == TRUE )
	{
		EIPM_bfd_alarm_tran_sn_set( intf_ptr, subnet_idx,
			1, FSAS_major, "all Sessions down" );
	}

	return;

} /* EIPM_bfd_alarm_tran_sn_set_sess_down() */

void EIPM_bfd_alarm_tran_sn_clr(
		register EIPM_INTF	*intf_ptr,
		int			subnet_idx
	)
{
	/* Clear an Alarm for a BFD Transport Subnet */

	EIPM_CLEAR_SUBNET_ALARM( intf_ptr, 
				 EIPM_BASE_INTF, 
				 subnet_idx, 
				 EIPM_NEXTHOP_FAIL );

	return;

} /* EIPM_bfd_alarm_tran_sn_clr() */

void EIPM_bfd_alarm_svc_sn_set(
		register EIPM_INTF	*intf_ptr,
		int			subnet_idx,
		int			threshold,
		int			severity,
		char			*reason
	)
{
	/* Set an Alarm for a BFD Service Subnet */

	char		*baseif_ptr  = "empty";
	char		*rightif_ptr = "empty";
	char		linebuf[256];

	if ( (intf_ptr->lsn0_baseif[0] != 0) &&
	     (strlen(intf_ptr->lsn0_baseif) != 0) )
	{
		baseif_ptr = intf_ptr->lsn0_baseif;
	}

	if ( (intf_ptr->lsn1_baseif[0] != 0) &&
	     (strlen(intf_ptr->lsn1_baseif) != 0) )
	{
		rightif_ptr = intf_ptr->lsn1_baseif;
	}

	sprintf( linebuf, "BFD Service Subnet %s-%s, %s.", baseif_ptr, rightif_ptr, reason );

	// LOG_FORCE( 0, "Error: %s() reporting %s count=%d, threshold=%d->%d\n", __FUNCTION__, linebuf, intf_ptr->alarm[subnet_idx][EIPM_NEXTHOP_FAIL].count, intf_ptr->alarm[subnet_idx][EIPM_NEXTHOP_FAIL].threshold, threshold);

	EIPM_SEND_SUBNET_ALARM(
		EIPM_NEXTHOP_FAIL,
		threshold,
		intf_ptr,
		EIPM_BASE_INTF,
		subnet_idx,
		severity,
		baseif_ptr,
		linebuf
	);

	return;

} /* EIPM_bfd_alarm_svc_sn_set() */

void EIPM_bfd_alarm_svc_sn_set_miss_tran(
		register EIPM_INTF	*intf_ptr,
		int			subnet_idx,
		bool			has_left,
		bool			has_right
	)
{
	/* Set an Alarm for a BFD Service Subnet that is
	 * missing 1 or both BFD Transport subnets.
	 */

	EIPM_INTF_SPEC	*intfSpecDataP;
	int		intf_idx;
	EIPM_SUBNET	*subnet_ptr;
	char		*reason = "missing BFD Transport Subnet(s)";
	int		severity = FSAS_major;

	intfSpecDataP	= &(intf_ptr->specData);
	intf_idx	= intfSpecDataP->baseIntfIdx;
	subnet_ptr	= &(intf_ptr->subnet[subnet_idx]);

	// LOG_OTHER( 0, "Other: %s() called for intf_idx %d, subnet_idx %d with has_left=%d, has_right=%d\n", __FUNCTION__, intf_idx, subnet_idx, has_left, has_right);

#if 0 /* { setting severity and reason based on which transport(s) missing */

	/* Decide not to do this for now due to the problem of having to
	 * clear a previous NextHop alarm and then set it again if just
	 * the info changed from Left missing to Right missing or Both
	 * missing. May decide to do it in a later release so leave the
	 * code in place.
	 */
	if ( (has_left == FALSE) && (has_right == FALSE) )
	{
		reason = "missing Both BFD Transport Subnets";
		severity = FSAS_critical;
	}
	else if ( has_left == FALSE )
	{
		reason = "missing Left BFD Transport Subnet";
	}
	else if ( has_right == FALSE )
	{
		reason = "missing Right BFD Transport Subnet";
	}
	else
	{
		reason = "missing Unknown BFD Transport Subnets";

		EIPM_LOG_ERROR( 0, "Error: %s() called for intf_idx %d, subnet_idx %d with has_left=%d, has_right=%d\n", __FUNCTION__, intf_idx, subnet_idx, has_left, has_right);
	}

#endif /* } setting severity and reason based on which transport(s) missing */

	EIPM_bfd_alarm_svc_sn_set( intf_ptr, subnet_idx,
		2, severity, reason);

	/* One or both transports are not provisioned. */
	subnet_ptr->miss_tran = TRUE;

	return;

} /* EIPM_bfd_alarm_svc_sn_set_miss_tran() */

void EIPM_bfd_alarm_svc_sn_clr_miss_tran(
		register EIPM_INTF	*intf_ptr,
		int			subnet_idx
	)
{
	/* Clear an Alarm for a BFD Service Subnet */

	EIPM_INTF_SPEC	*intfSpecDataP;
	int		intf_idx;
	EIPM_SUBNET	*subnet_ptr;

	intfSpecDataP	= &(intf_ptr->specData);
	intf_idx	= intfSpecDataP->baseIntfIdx;
	subnet_ptr	= &(intf_ptr->subnet[subnet_idx]);

	if (subnet_ptr->miss_tran == TRUE)
	{
		EIPM_CLEAR_SUBNET_ALARM( intf_ptr, 
					 EIPM_BASE_INTF, 
					 subnet_idx, 
					 EIPM_NEXTHOP_FAIL );

		subnet_ptr->miss_tran = FALSE;
	}

	return;

} /* EIPM_bfd_alarm_svc_sn_clr_miss_tran() */

void EIPM_bfd_alarm_svc_sn_chk_miss_tran(
			int svc_intf_idx,
			int svc_sn_idx
	)
{
	/* Checks whether or not the BFD Service Subnet is missing
	 * one or both of its BFD Transport Subnets. Relies on
	 * the bfd_subnet_map being populated before this function
	 * is called. Alarms if either or both is missing, clears the
	 * alarm if both are present.
	 */

	EIPM_DATA		*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	register EIPM_INTF	*svc_intf_ptr;
	EIPM_SUBNET		*sn_ptr;

	int			left_intf_idx;
	int			left_sn_idx;
	int			right_intf_idx;
	int			right_sn_idx;
	IPM_RETVAL		bfd_map_retval;

	bool			has_left = FALSE;
	bool			has_right = FALSE;

	svc_intf_ptr = &(shm_ptr->intf_data[svc_intf_idx]);
	sn_ptr = &(svc_intf_ptr->subnet[svc_sn_idx]);

	/* Only do this when ip_cnt is > 0 to avoid
	 * alarming by mistake on the standby side.
	 */
	if (sn_ptr->ip_cnt > 0)
	{

		bfd_map_retval = EIPM_bfd_map_svc2trans(svc_intf_idx,svc_sn_idx,&left_intf_idx,&left_sn_idx,&right_intf_idx,&right_sn_idx);

		if ( bfd_map_retval == IPM_SUCCESS )
		{
			if ( (left_intf_idx >= 0) && (left_sn_idx >= 0) )
			{
				has_left = TRUE;
			}
	
			if ( (right_intf_idx >= 0) && (right_sn_idx >= 0) )
			{
				has_right = TRUE;
			}
		}
		else
		{
			EIPM_LOG_ERROR( 0, "Error: %s() Failed to get subnet map for Service intf_idx=%d, subnet_idx=%d\n", __FUNCTION__, svc_intf_idx, svc_sn_idx );
		}

		if ( (has_left == TRUE) && (has_right == TRUE) )
		{
			/* Clear Alarm (if set): BFD Service Subnet
			 * has both BFD Transport Subnet(s).
			 */
			EIPM_bfd_alarm_svc_sn_clr_miss_tran(svc_intf_ptr,svc_sn_idx);
		}
		else
		{
			/* Set Alarm: BFD Service Subnet with missing
			 * BFD Transport Subnet(s).
			 */
			EIPM_bfd_alarm_svc_sn_set_miss_tran(svc_intf_ptr,svc_sn_idx,has_left,has_right);

			EIPM_LOG_ERROR( 0, "Error: %s() Missing BFD Transport(s) for Service intf_idx=%d, subnet_idx=%d, subnet_cnt=%d, has_left=%d, has_right=%d\n", __FUNCTION__, svc_intf_idx, svc_sn_idx, svc_intf_ptr->subnet_cnt, has_left, has_right );
		}

	}

	return;

} /* EIPM_bfd_alarm_svc_sn_chk_miss_tran() */

void EIPM_bfd_alarm_svc_sn_set_tran_down(
		register EIPM_INTF	*intf_ptr,
		int			subnet_idx
	)
{
	/* Set an Alarm for a BFD Service Subnet that
	 * has both BFD Transport subnets down.
	 */

	EIPM_INTF_SPEC	*intfSpecDataP;
	int		intf_idx;

	intfSpecDataP	= &(intf_ptr->specData);
	intf_idx	= intfSpecDataP->baseIntfIdx;

	if ( EIPM_bfd_admin_cfg_stable_svc(intf_idx, subnet_idx) == TRUE )
	{
		/* This Transport subnet was configured long enough ago
		 * that it should be stable by now but it's apparently
		 * not so raise the alarm.
		 */
		EIPM_bfd_alarm_svc_sn_set( intf_ptr, subnet_idx,
			1, FSAS_critical, "all BFD Transport Subnets down" );
	}

	return;

} /* EIPM_bfd_alarm_svc_sn_set_tran_down() */

void EIPM_bfd_alarm_svc_sn_clr_tran_down(
		register EIPM_INTF	*intf_ptr,
		int			subnet_idx
	)
{
	/* Clear an Alarm for a BFD Service Subnet */

	EIPM_INTF_SPEC	*intfSpecDataP;
	int		intf_idx;
	EIPM_SUBNET	*subnet_ptr;

	intfSpecDataP	= &(intf_ptr->specData);
	intf_idx	= intfSpecDataP->baseIntfIdx;
	subnet_ptr	= &(intf_ptr->subnet[subnet_idx]);

	EIPM_CLEAR_SUBNET_ALARM( intf_ptr, 
				 EIPM_BASE_INTF, 
				 subnet_idx, 
				 EIPM_NEXTHOP_FAIL );

	/* Check for missing transports and re-instate that alarm
	 * if necessary.
	 */
	EIPM_bfd_alarm_svc_sn_chk_miss_tran(intf_idx,subnet_idx);

	return;

} /* EIPM_bfd_alarm_svc_sn_clr_tran_down() */

void EIPM_bfd_prt_route(
		int			intf_idx,
		int			subnet_idx,
		int			route_idx,
		bool			use_error
	)
{
	EIPM_DATA	*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	EIPM_INTF	*intf_ptr;
	EIPM_SUBNET	*subnet_ptr;
	EIPM_ROUTES	*route_ptr;

	char		intf_str[EIPM_INTF_STR_SIZE];
	char		subnet_str[EIPM_SUBNET_STR_SIZE];
	char		route_str[EIPM_ROUTES_STR_SIZE];

	intf_ptr   = &(shm_ptr->intf_data[intf_idx]);
	subnet_ptr = &(intf_ptr->subnet[subnet_idx]);
	route_ptr  = &(subnet_ptr->routes[route_idx]);

	EIPM_INTF2STR(intf_ptr,intf_str);
	EIPM_SUBNET2STR(subnet_ptr,subnet_str,0);
	EIPM_ROUTES2STR(route_ptr,route_str);

	if (use_error == TRUE)
	{
		EIPM_LOG_ERROR( 0, "Error: %s() called for intf_idx %d, subnet_idx %d, route_idx %d\n", __FUNCTION__, intf_idx, subnet_idx, route_idx);
		EIPM_LOG_ERROR( 0, "Error: %s() intf=%s, subnet=%s, route=%s\n", __FUNCTION__, intf_str, subnet_str, route_str );
	}
	else
	{
		LOG_OTHER( 0, "Other: %s() called for intf_idx %d, subnet_idx %d, route_idx %d\n", __FUNCTION__, intf_idx, subnet_idx, route_idx);
		LOG_OTHER( 0, "Other: %s() intf=%s, subnet=%s, route=%s\n", __FUNCTION__, intf_str, subnet_str, route_str );
	}

	return;

} /* EIPM_bfd_prt_route() */

void EIPM_bfd_prt_ipdata(
		int			intf_idx,
		int			subnet_idx,
		int			ipdata_idx,
		bool			use_error
	)
{
	EIPM_DATA	*shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	EIPM_INTF	*intf_ptr;
	EIPM_SUBNET	*subnet_ptr;
	EIPM_IPDATA	*ipdata_ptr;

	char		intf_str[EIPM_INTF_STR_SIZE];
	char		subnet_str[EIPM_SUBNET_STR_SIZE];
	char		ipdata_str[EIPM_IPDATA_STR_SIZE];

	intf_ptr   = &(shm_ptr->intf_data[intf_idx]);
	subnet_ptr = &(intf_ptr->subnet[subnet_idx]);
	ipdata_ptr = &(subnet_ptr->ips[ipdata_idx]);

	EIPM_INTF2STR(intf_ptr,intf_str);
	EIPM_SUBNET2STR(subnet_ptr,subnet_str,0);
	EIPM_IPDATA2STR(ipdata_ptr,ipdata_str);

	if (use_error == TRUE)
	{
		EIPM_LOG_ERROR( 0, "Error: %s() called for intf_idx %d, subnet_idx %d, ipdata_idx %d\n", __FUNCTION__, intf_idx, subnet_idx, ipdata_idx);
		EIPM_LOG_ERROR( 0, "Error: %s() intf=%s, subnet=%s, ipdata=%s\n", __FUNCTION__, intf_str, subnet_str, ipdata_str );
	}
	else
	{
		LOG_OTHER( 0, "Other: %s() called for intf_idx %d, subnet_idx %d, ipdata_idx %d\n", __FUNCTION__, intf_idx, subnet_idx, ipdata_idx);
		LOG_OTHER( 0, "Other: %s() intf=%s, subnet=%s, ipdata=%s\n", __FUNCTION__, intf_str, subnet_str, ipdata_str );
	}

	return;

} /* EIPM_bfd_prt_ipdata() */

/*************************************************************************
 *{ Start of BFD data description and configuration example.
 *
 * Terminology:
 *
 *	lsn0_baseif = left interface  = Hub/Malban7 = Primary
 *	lsn1_baseif = right interface = Hub/Malban8 = Secondary
 *
 * BEFORE a BFD Service Subnet has been grown in:
 *
 *    EIPM_INTF for a "left" BFD Transport Subnet mirrors the "right" one:
 *
 *	EIPM_INTF = {
 *	    int subnet_cnt = 1;
 *	    EIPM_SUBNET subnet[M] = left transport subnet info only;
 *	    char lsn0_baseif = ethL.vlanL;
 *	    char lsn1_baseif = null;
 *	}
 *
 *     EIPM_INTF for a "right" BFD Transport Subnet mirrors the "left" one:
 *
 *	EIPM_INTF = {
 *	    int subnet_cnt = 1;
 *	    EIPM_SUBNET subnet[N] = right transport subnet info only;
 *	    char lsn0_baseif = null;
 *	    char lsn1_baseif = ethR.vlanR;
 *	}
 *
 * AFTER a BFD Service Subnet has been grown in:
 *
 *    EIPM_INTF for the "right" BFD Transport Subnet stays as above but
 *    the "left" BFD Transport Subnet is updated to include the BFD
 *    Service Subnet information and the name of the "right" BFD
 *    Transport Subnet:
 *
 *	EIPM_INTF = {
 *	    int subnet_cnt = 2;
 *	    EIPM_SUBNET subnet[X] = left transport subnet info;
 *	    EIPM_SUBNET subnet[Y] = service subnet info;
 *		// M, N, X, or Y: depends on whether the BFD Transport
 *		// or BFD Service Subnet was grown in first and if
 *		// any other subnets are present in the EIPM_INTF.
 *	    char lsn0_baseif = ethL.vlanL;
 *	    char lsn1_baseif = ethR.vlanR;
 *	}
 *
 * So given an EIPM_INTF that contains a BFD Service Subnet, the subnet
 * data for the left BFD Transport Subnet is contained within the same
 * structure and the corresponding EIPM_INTF structure for the "right" BFD
 * Transport Subnet can be found by searching the other EIPM_INTF
 * structures for the one whose lsn1_baseif matches the target ethR.vlanR.
 *
 *      ############################################
 *      EIPM_INTF interface = {         # One per interface =
 *                                      # Ethernet port + VLAN
 *
 *	    EIPM_INTF_SPEC specData = {
 *    		EIPM_MONITOR_METHOD monitor;	# Set to EIPM_MONITOR_BFD
 *
 *          	EIPM_STATUS status;     # Status of this interface =
 *                                      # EIPM_ONLINE, EIPM_OFFLINE, or
 *                                      # EIPM_DEGRADED, see EIPM_intf.c.
 *	    }
 *
 *          ############################################
 *          int subnet_cnt = N;
 *          EIPM_SUBNET subnet[subnet_cnt] = {		# One per subnet
 *
 *              As identified by "redundancy_mode" each subnet could
 *              be either:
 *                  a) a BFD Transport Subnet (IPM_RED_BFD_TRANSPORT) or
 *                  b) a BFD Service Subnet (IPM_RED_EIPM_BFD) or
 *                  c) a subnet unrelated to BFD.
 *              Assume BFD for the rest of this data discussion.
 *
 *              EIPM_STATUS status;
 *		    Different meanings by subnet type:
 *
 *			For BFD Transport Subnets this is:
 *			    EIPM_ONLINE = All of it's BFD Sessions are in
 *				state BFD_ADMIN_STATE_UP
 *			    EIPM_OFFLINE = All of it's BFD Sessions are in
 *				state BFD_ADMIN_STATE_DOWN
 *			    EIPM_DEGRADED = At least one but not all of it's
 *				BFD Sessions are in state BFD_ADMIN_STATE_UP
 *
 *			For BFD Service Subnets this is:
 *			    EIPM_ONLINE = Both BFD Transports are EIPM_ONLINE.
 *			    EIPM_OFFLINE = Both BFD Transports are EIPM_OFFLINE.
 *			    EIPM_DEGRADED = At least one BFD Transport is
 *				EIPM_DEGRADED or EIPM_OFFLINE but both are
 *				not EIPM_OFFLINE.
 *
 *              IPM_REDUNDANCY_MODE redundancy_mode;    See above.
 *
 *              IPM_IPADDR gateway;     Remote IP address for all BFD
 *                                      Sessions on this BFD Transport
 *                                      Subnet. Not populated for BFD
 *                                      Service Subnets.
 *
 *              ############################################
 *              EIPM_IPDATA ips[int ip_cnt] = {
 *                      One per local IP address = One per BFD Session if
 *			this is a BFD Transport Subnet.
 *
 *                  BFD_ADMIN_STATE state;
 *                      Different meanings by subnet type:
 *
 *			    For BFD Transport Subnets this is
 *			    simply the state of this BFD Session:
 *			        BFD_ADMIN_STATE_UP = BFD Session up
 *			        BFD_ADMIN_STATE_DOWN = BFD Session down
 *
 *                  IPM_IPADDR ipaddr;  This local IP address.
 *
 *              } EIPM_IPDATA ips[ip_cnt];
 *              ############################################
 *
 *          } EIPM_SUBNET subnet[subnet_cnt];
 *          ############################################
 *
 *      } EIPM_INTF;
 *      ############################################
 *
 * See below for an example BFD configuration and how the main data
 * fields would be populated for that configuration.
 *
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 
 *          MPH 0                            CE A      S10 MSC A   S10 MSC B
 *          -----                            ----      ---------   ---------
 *      S10 Service
 *     135.183.2.1/32                                   S10MSCA     S10MSCB
 * 	  <................................................>
 * 	  <............................................................>
 * 
 * 	 Base Interface eth2 vlan610
 * 	     10.145.8.192/30            10.145.8.193/30
 * 		<---------------------------->
 * 
 * 	 Base Interface eth3 vlan611
 * 		^ 10.145.9.192/30
 *              |                           CE B
 *         via  |                           ----
 *        MPH 1 |                       10.145.9.193/30
 *              ----------------------------->
 * 
 *+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * 
 * Note that a /30 subnet mask is a mask where the first 30 of the 32-bit IP
 * address are matched, i.e. 11111111 11111111 11111111 11111100. An IP
 * address of 10.145.8.192 with a /30 subnet mask applies to the following 4
 * IP addresses:
 * 
 * 	10.145.8.191 = subnet base
 * 	10.145.8.192 = usable host IP
 * 	10.145.8.193 = usable host IP
 * 	10.145.8.194 = subnet broadcast
 * 
 * hence the use of 10.145.8.192 and 10.145.8.193 above and the appearance
 * of 10.145.8.191 in the data below.
 * 
 * ((EIPM_DATA *)EIPM_shm_ptr)->intf_data = an array of data per-interface;
 * 
 * EIPM_INTF intf_data[3] = {
 *
 *    EIPM_MONITOR_METHOD monitor = EIPM_MONITOR_BFD;
 *
 *    int subnet_cnt = 6;			// any number
 * 
 *    EIPM_SUBNET subnet[0,2,4,5] = { nothing to do with BFD }
 * 
 *    //////////////////////////////////////////////////////////////////
 *    EIPM_SUBNET subnet[1] = {		// The BFD Service Subnet
 *       IPM_IPADDR  subnet_base = ;
 *       EIPM_STATUS status = EIPM_(ONLINE || OFFLINE || DEGRADED);
 *       EIPM_NET    route_priority = LSN_(NONE || 0 || 1 || BOTH);
 * 
 *       int ip_cnt = 1;
 *       EIPM_IPDATA ips[0] = {
 *          IPM_IPADDR      ipaddr = 135.185.2.1/32;
 *          EIPM_IP_TYPE    type = EIPM_IP_ALIAS;
 *          char lsn0_iface[] = "eth2.610";
 *          char lsn1_iface[] = "eth3.611";
 *       }
 * 
 *       int route_cnt = 1;	// Will have just one SUBNET route
 *
 *       EIPM_ROUTES routes[0] = {
 *          EIPM_ROUTE_TYPE type = EIPM_ROUTE_SUBNET;
 *          IPM_IPADDR      dest = 10.145.8.191;	correct ????
 *          int             destprefix = 30;		correct ????
 *          IPM_IPADDR      nexthop = null;
 *       }
 *
 *       IPM_IPADDR gateway = "10.145.8.193/30";
 *
 *       int redundancy_mode = IPM_RED_EIPM_BFD;
 *    }
 * 
 *    //////////////////////////////////////////////////////////////////
 *    EIPM_SUBNET subnet[3] = {		// The Left BFD Transport Subnet
 *       IPM_IPADDR  subnet_base = ;
 *       EIPM_STATUS status = EIPM_(ONLINE || OFFLINE || DEGRADED);
 *       EIPM_NET    route_priority = LSN_(NONE || 0 || 1 || BOTH);
 * 
 *       int ip_cnt = 1;
 *       EIPM_IPDATA ips[0] = {	// 1 per BFD Session, e.g 1 for fixed and 1
 * 				// for floating IP addresses. Only 1 for AT&T.
 * 
 *          IPM_IPADDR      ipaddr = 10.145.8.192/30;
 *          EIPM_IP_TYPE    type = EIPM_IP_ALIAS;
 *          char lsn0_iface[] = "eth2.610";
 *          char lsn1_iface[] = "";
 *       }
 * 
 *       int route_cnt = 3;	// 1 for anything that wants to use the
 * 				// subnet info plus 1 for any service
 * 				// that just wants to reach addresses
 * 				// out in the network, e.g. the S10 MSCs,
 * 				// via the nexthop router (=gateway for BFD).
 *
 *       EIPM_ROUTES routes[0] = {
 *          EIPM_ROUTE_TYPE type = EIPM_ROUTE_SUBNET;
 *          IPM_IPADDR      dest = 10.145.8.191;
 *          int             destprefix = 30;
 *          IPM_IPADDR      nexthop = null;
 *       }
 * 
 *       EIPM_ROUTES routes[1] = {
 *          EIPM_ROUTE_TYPE type = EIPM_ROUTE_OTHER;
 *          IPM_IPADDR      dest = S10MSCA;
 *          int             destprefix = 32;
 *          IPM_IPADDR      nexthop = 10.145.8.193;
 *       }
 * 
 *       EIPM_ROUTES routes[2] = {
 *          EIPM_ROUTE_TYPE type = EIPM_ROUTE_OTHER;
 *          IPM_IPADDR      dest = S10MSCB;
 *          int             destprefix = 32;
 *          IPM_IPADDR      nexthop = 10.145.8.193;
 *       }
 * 
 *       IPM_IPADDR gateway = "10.145.8.193/30";
 * 
 *       int redundancy_mode = IPM_RED_BFD_TRANSPORT;
 *    }
 *    //////////////////////////////////////////////////////////////////
 * 
 *    char lsn0_baseif[] = "eth2.610";
 *    char lsn1_baseif[] = "eth3.611";
 * 
 *    EIPM_INTF_SPEC specData = { other info }
 * 
 * }
 * 
 * EIPM_INTF intf_data[7] = {
 *    int subnet_cnt = 4;			// any number
 * 
 *    EIPM_SUBNET subnet[0,1,3] = { nothing to do with BFD }
 * 
 *    //////////////////////////////////////////////////////////////////
 *    EIPM_SUBNET subnet[2] = {		// The Right BFD Transport Subnet
 *       IPM_IPADDR  subnet_base = ;
 *       EIPM_STATUS status = EIPM_(ONLINE || OFFLINE || DEGRADED);
 *       EIPM_NET    route_priority = LSN_(NONE || 0 || 1 || BOTH);
 * 
 *       int ip_cnt = 1;
 *       EIPM_IPDATA ips[0] = {	// 1 per BFD Session, e.g 1 for fixed and 1
 * 				// for floating IP addresses. Only 1 for AT&T.
 *
 *          IPM_IPADDR      ipaddr = 10.145.9.192/30;
 *          EIPM_IP_TYPE    type = EIPM_IP_ALIAS;
 *          char lsn0_iface[] = "";
 *          char lsn1_iface[] = "eth3.611";
 *       }
 * 
 *       int route_cnt = 1;	// Only a SUBNET route populated for Right
 * 				// BFD Transport. Use OTHER route info
 * 				// from Left BFD Tranport for other routes.
 *
 *       EIPM_ROUTES routes[0] = {
 *          EIPM_ROUTE_TYPE type = EIPM_ROUTE_SUBNET;
 *          IPM_IPADDR      dest = 10.145.9.191;
 *          int             destprefix = 30;
 *          IPM_IPADDR      nexthop = null;
 *       }
 * 
 *       IPM_IPADDR gateway = "10.145.9.193/30";
 * 
 *       int redundancy_mode = IPM_RED_BFD_TRANSPORT;
 *    }
 *    //////////////////////////////////////////////////////////////////
 * 
 *    char lsn0_baseif[] = "";
 *    char lsn1_baseif[] = "eth3.611";
 * 
 *    EIPM_INTF_SPEC specData = { other info }
 * }
 *
 *} End of BFD data description and configuration example.
 *************************************************************************/
