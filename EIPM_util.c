/**********************************************************************
 *
 * File:
 *	EIPM_util.c
 *
 * Functions in this file:
 *	EIPM_dumpshm()      - Go through internal data and log it.
 *	EIPM_status2str()   - Convert status to a string.
 *	EIPM_network2str()   - Convert network to a string.
 * 	EIPM_getstatus()    - Return summary of EIPM status.
 *	EIPM_clear_alarms() - Clear all alarms for an interface.
 *	EIPM_send_alarm()      - Send alarms granularity higher than IP addr.
 *	EIPM_send_ip_alarm()   - Send alarms at granularity of an IP address.
 *	EIPM_clear_ip_alarms() - Clear alarms at granularity of IP address.
 *	EIPM_report_ip_alarms()- Report set/clr for all IP granularity alarms.
 *	EIPM_report_alarms()- Report set/clr for all alarms 
 *	EIPM_send_status()  - Send status target interface
 *	EIPM_report_status()- Send status for all interfaces
 *	EIPM_recovery()     - Attempt recovery after errors
 *	EIPM_get_intf_to_nexthop() - determine the active interface to reach nexthop
 *	EIPM_close_sock()   - Close sockets
 *	EIPM_open_garpsock()- Open garp sockets if needed
 *	EIPM_check_route_priority()- Check subnet route priority
 *	ipv6cksm()	    - Compute checksum for IPv6
 *	ipcksm()	    - Compute IP checksum
 *      EIPM_findIntf       - Searches for a matching interface.
 *	EIPM_check_pivot()  - Audit pivot interface
 *	EIPM_getActiveSlave() - Get active slave info of a pivot interface
 *	EIPM_setActiveSlave() - Set active slave of a pivot interface
 *	EIPM_attach_pivot() - Attach slave interfaces to a pivot interface
 *
 **********************************************************************/

#if defined (_X86)
#define _GNU_SOURCE
#include <netinet/in.h>       
#endif
	
#include "EIPM_include.h"
#include "EIPM_bfd.h"
#include "PIPM_include.h"


/* Declare and init the global variables used for log throttling */
EIPM_THROT_DECL_VARS;

	
/**********************************************************************
 *
 * Name:	EIPM_dumpalarm()
 *
 * Abstract:	Loop through all alarms that has been fired 
 *		and log it.
 *
 * Parameters:	None
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int EIPM_dumpalarm( )
{
	register EIPM_INTF	*data_ptr;
	char			ipbuf[ IPM_IPMAXSTRSIZE ];
	int intf;

	/*
	 * Make sure we are attached to shared memory segment.
	 */
	if( EIPM_shm_ptr == NULL )
	{
		/*
		 * Fire an assert.
		 */
		ASRT_RPT( ASMISSING_DATA,
		          2,
		          sizeof( EIPM_shm_ptr ),
			  &EIPM_shm_ptr,
			  sizeof( EIPM_shmid ),
			  &EIPM_shmid,
		          "EIPM_dumpshm: EIPM not attached to shared memory segment\n" );
		
		return( IPM_FAILURE );
	}
	
	/*
	 * Loop through shared segment.
	 */
	LOG_FORCE(0, "ALARM DUMP BEGIN \n");
	for( intf = 0, data_ptr = &((EIPM_DATA *)EIPM_shm_ptr)->intf_data[ 0 ];
	     intf < ((EIPM_DATA *)EIPM_shm_ptr)->intf_cnt; 
	     intf++, data_ptr++ )
	{
		EIPM_ALARM_DATA (*alarm_ptr)[EIPM_MAX_ALARM];
		EIPM_ALARM_DATA *alarm_data;
		int alarmIdx;
		int subnetIdx;

		
		alarm_ptr = data_ptr->specData.alarm;

		for (subnetIdx = 0; subnetIdx < EIPM_MAX_SUBNETS; subnetIdx++)
		{
			for (alarmIdx =0; alarmIdx < EIPM_MAX_ALARM; alarmIdx++)
			{
				alarm_data = EIPM_ALARM_DATA_AT(alarm_ptr, subnetIdx, alarmIdx);
				if ( strlen(alarm_data->resource) == 0)
				{
					continue;
				}
				LOG_FORCE(0, "ALARM: Interface %s-%s subnet %s alarm %d, alarm_sent %s, count %d, threashold %d, link_id %s\n\tseverity %d, resource %s, user_text %s, file %s, line %d\n",
							( data_ptr->lsn0_baseif[0] != 0 ? data_ptr->lsn0_baseif : "empty" ),
							( data_ptr->lsn1_baseif[0] != 0 ? data_ptr->lsn1_baseif : "empty" ),
							IPM_chkipaddr2p(&(data_ptr->subnet[subnetIdx].subnet_base), ipbuf, sizeof(ipbuf)), alarmIdx,
							(alarm_data->alarm_sent==TRUE?"SENT":"NOT SENT"), alarm_data->count, alarm_data->threshold, alarm_data->link_id,
							alarm_data->severity, alarm_data->resource, alarm_data->user_text, alarm_data->file, alarm_data->line);
			}
		}
	}
	LOG_FORCE(0, "ALARM DUMP END\n");

	return IPM_SUCCESS;
}
	
/**********************************************************************
 *
 * Name:	EIPM_dumpshm()
 *
 * Abstract:	Loop through all data that has been provisioned
 *		and log it.
 *
 * Parameters:	None
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int EIPM_dumpshm( )
{
	register EIPM_INTF	*data_ptr;
	register EIPM_SUBNET	*subn_ptr;
	register EIPM_ROUTES	*rt_ptr;
	register EIPM_ARPLIST	*arp_ptr;
	char			prt_line[300];
	char			prt_buf[300 * EIPM_PRT_LINES];
	char			true[5];
	char			false[6];
	char			state[20];	
	char			status[20];	
	char			ip_type[20];	
	char			lsn_side_str[20];
	char			ipbuf[ IPM_IPMAXSTRSIZE ];
	char			gatewaybuf[ IPM_IPMAXSTRSIZE ];
	int			intf;
	int			subn;
	int			rt;
	int			arp;
	int			ip_cnt;
	int			cnt_to_prt;
	int			eipm_size=0;
	int			i=0;
	unsigned char		pivot_index;
	char		monit_str[32];
	char		mode_str[32];
	register IPM_TUNNEL_DATA	*tunnel_ptr;

	/*
	 * Make sure we are attached to shared memory segment.
	 */
	if( EIPM_shm_ptr == NULL )
	{
		/*
		 * Fire an assert.
		 */
		ASRT_RPT( ASMISSING_DATA,
		          2,
		          sizeof( EIPM_shm_ptr ),
			  &EIPM_shm_ptr,
			  sizeof( EIPM_shmid ),
			  &EIPM_shmid,
		          "EIPM_dumpshm: EIPM not attached to shared memory segment\n" );
		
		return( IPM_FAILURE );
	}
	
	eipm_size = sizeof(EIPM_DATA)/(1024*1024);
	LOG_FORCE(0, "EIPM_dumpshm: the size of EIPM_DATA:(%d)M\n",eipm_size);
	LOG_FORCE(0, "EIPM_dumpshm: Is this Virtual Env : (%s)\n",((ipm_isVirtual() == 1) ? "Yes" : "No"));

	LOG_FORCE(0, "EIPM_dumpshm: System level soak time: %d seconds\n", ((EIPM_DATA *) EIPM_shm_ptr)->soak_timer);
	strcpy( true, "TRUE" );
	strcpy( false, "FALSE" );
	
	EIPM_dump_tunnel_data();
	/*
	 * Loop through shared segment.
	 */
	for( intf = 0, data_ptr = &((EIPM_DATA *)EIPM_shm_ptr)->intf_data[ 0 ];
	     intf < ((EIPM_DATA *)EIPM_shm_ptr)->intf_cnt; 
	     intf++, data_ptr++ )
	{
		/*
		 * Convert state to string.
		 */
		switch ( data_ptr->specData.state )
		{
		case NULL_STATE:
			strcpy( state, "NULL" );
			break;
			
		case NORMAL_STATE:
			strcpy( state, "NORMAL" );
			break;
			
		case DETECTION_STATE:
			strcpy( state, "DETECTION" );
			break;
			
		case ACTION_STATE:
			strcpy( state, "ACTION" );
			break;
			
		case RESTORE_STATE:
			strcpy( state, "RESTORE" );
			break;
			
		case SOAK_STATE:
			strcpy( state, "SOAK" );
			break;
			
		case SOAK_AUXOP:
			strcpy( state, "SOAK_AUX" );
			break;
			
		default:
			
			/*
			 * State is bogus.  Makes me wonder how
			 * many other things are bogus.  However
			 * since the operational code also has 
			 * this check just assert here.
			 */
			ASRT_RPT( ASUNEXPECTEDVAL,
			          2,
			          100,
				  data_ptr,
				  100,
				  &data_ptr->subnet[0].routes[0],
			          "Error: EIPM_dumpshm - state is invalid.\niface=%s-%s, state=%d\n",
			          ( data_ptr->lsn0_baseif[0] != 0 ? data_ptr->lsn0_baseif : "empty" ),
			          ( data_ptr->lsn1_baseif[0] != 0 ? data_ptr->lsn1_baseif : "empty" ),
			          data_ptr->specData.state );
			
			/*
			 * Continue on - see how much more is broken...
			 */
			strcpy( state, "UNKNOWN" );
			  
			break;
		}
		
		/*
		 * Call function to convert status to a string.
		 */
		EIPM_status2str( data_ptr->specData.status, status );
		
		if( strcmp( status, "INVALID" ) == 0 )
		{
			/*
			 * State is bogus.  Makes me wonder how
			 * many other things are bogus.  However
			 * since the operational code also has 
			 * this check just assert here.
			 */
			ASRT_RPT( ASUNEXPECTEDVAL,
			          2,
			          100,
				  data_ptr,
				  100,
				  &data_ptr->subnet[0].routes[0],
			          "Error: EIPM_dumpshm - status is invalid.\niface=%s-%s, status=%d\n",
			          ( data_ptr->lsn0_baseif[0] != 0 ? data_ptr->lsn0_baseif : "empty" ),
			          ( data_ptr->lsn1_baseif[0] != 0 ? data_ptr->lsn1_baseif : "empty" ),
			          data_ptr->specData.status );
			
			/*
			 * Continue on - see how much more is broken...
			 */
			break;
			
		}

		EIPM_network2str( data_ptr->specData.preferred_side, lsn_side_str );
		
		/*
		 * Print out data for this interface.
		 */
		LOG_FORCE( 0,
	       	         "EIPM - Interface data dump, intf %d, Name %s-%s\nmonitor %s, subnet_cnt %d, state %s, status %s, preferred side %s, is_tunnel_intf=%d\n",
		         intf,
			 ( data_ptr->lsn0_baseif[0] != 0 ? data_ptr->lsn0_baseif : "empty" ),
			 ( data_ptr->lsn1_baseif[0] != 0 ? data_ptr->lsn1_baseif : "empty" ),
			 EIPM_monitor2str(data_ptr->specData.monitor, monit_str, sizeof(monit_str)),
		         data_ptr->subnet_cnt,
		         state,
		         status,
			 lsn_side_str,
			 data_ptr->is_tunnel_intf
			 );
		
			
		/*
		 * Now loop through all of the subnets on this
		 * interface and print that data.
		 */
		for( subn = 0, subn_ptr = &(data_ptr->subnet[0]);
		     subn < data_ptr->subnet_cnt;
		     subn++, subn_ptr++ )
		{
			EIPM_status2str( subn_ptr->status, status );

			EIPM_network2str( subn_ptr->sub2intf_mapping[0].route_priority, lsn_side_str );
			/*
			 * Print out the high level data for this
			 * subnet.
			 */
			LOG_FORCE( 0,
				"EIPM - Intf %d, "
				" subnet %d, "
				" subnet=%s/%d, "
				" status %s, "
				" bfd_status %d, "
				" arpndp_status %d, "
				" priority %s, "
				" routing_table %d,\n"
				" ip_cnt=%d, "
				" route_cnt=%d, "
				" arp_counter=%d, "
				" arp_failure_count=%d, "
				" garp_send_cnt=%d, "
				" gateway %s,\n"
				" redundancy_mode %s, "
				" delete_flag %d, "
				" detection_multiplier %u, "
				" desired_min_tx_interval %u, "
				" required_min_rx_interval %u\n",
				intf,
				subn,
				IPM_chkipaddr2p(&subn_ptr->subnet_base, ipbuf, sizeof(ipbuf)),
				subn_ptr->prefixlen,
				status,
				subn_ptr->bfd_status,
				subn_ptr->arpndp_status,
				lsn_side_str,
				subn_ptr->table_num,
				subn_ptr->ip_cnt,
				subn_ptr->route_cnt,
				subn_ptr->arp_counter,
				subn_ptr->arp_failure_count,
				EIPM_GET_GRAT_ARP_CNT(subn_ptr),
				IPM_chkipaddr2p(&subn_ptr->gateway, gatewaybuf, sizeof(gatewaybuf)),
				ipm_mode2str(subn_ptr->redundancy_mode, mode_str, sizeof(mode_str)),
				subn_ptr->delete_flag,
				subn_ptr->detection_multiplier,
				subn_ptr->desired_min_tx_interval,
				subn_ptr->required_min_rx_interval
			);
		
			/*
			 * Loop to print all of the IPs on this subnet.
			 */
			cnt_to_prt = -1;
			for( ip_cnt = 0; ip_cnt < subn_ptr->ip_cnt; ip_cnt++ )
			{
 				/*
				 * Buffer EIPM_PRT_LINES lines of IP
				 * data before printing.
				 */
                                EIPM_iptype2str( subn_ptr->ips[ip_cnt].type, ip_type );
				memset(ipbuf, 0, sizeof(ipbuf));
				sprintf( prt_line,
                                         "EIPM - Intf %d,"
					 " subnet %d," 
					 " ip %d,"
					 " ver=%d,"
					 " pivot id %d, pivot interface index=%d,\n"
					 " \tip=%s,"
					 "\ttype=%s,"
					 "\tiface=%s-%s\n",
				         intf,
				         subn,
				         ip_cnt,
					 subn_ptr->ips[ip_cnt].ipaddr.addrtype,
					 subn_ptr->ips[ip_cnt].pivot_id,
					 subn_ptr->pivot_iface_indx[0][subn_ptr->ips[ip_cnt].pivot_id],
					 IPM_chkipaddr2p(&subn_ptr->ips[ip_cnt].ipaddr, ipbuf, sizeof(ipbuf)),
                                         ip_type,
				         ( subn_ptr->ips[ip_cnt].lsn0_iface[0] != 0 ? subn_ptr->ips[ip_cnt].lsn0_iface : "empty" ),
				         ( subn_ptr->ips[ip_cnt].lsn1_iface[0] != 0 ? subn_ptr->ips[ip_cnt].lsn1_iface : "empty" )
				);
				
				/*
				 * Add this line to the big
				 * print buffer.
				 */
				if( ++cnt_to_prt == 0 )
				{
					strcpy( prt_buf, prt_line );
				}
				else
				{
					strcat( prt_buf, prt_line );
				}
				
				if( cnt_to_prt >= (EIPM_PRT_LINES - 1) )
				{
					/*
					 * We have accumulated
					 * EIPM_PRT_LINES in the buffer.
					 * Time to log it.
					 */
					LOG_FORCE( 0,
					         "%s",
					         prt_buf );
					
					/*
					 * Reset print count.
					 */
					cnt_to_prt = -1;
				}
				
			} /* end 'for all IP data' */
			
			if( cnt_to_prt != -1 )
			{
				/*
				 * We have some data left to print.
				 */
				LOG_FORCE( 0,
				         "%s",
				         prt_buf );
			}
			
			/*
			 * Now loop to print the route data for this
			 * subnet.
			 */
			cnt_to_prt = -1;
			for( rt = 0, rt_ptr = &(subn_ptr->routes[0]);
			     rt < subn_ptr->route_cnt;
			     rt++, rt_ptr++ )
			{
 				/*
				 * Buffer EIPM_PRT_LINES lines of route
				 * data before printing.
				 */
				char	destbuf[ IPM_IPMAXSTRSIZE ];
				char	source_ip[ IPM_IPMAXSTRSIZE ];
				IPM_chkipaddr2p(&rt_ptr->dest, destbuf, sizeof(destbuf));
				IPM_chkipaddr2p(&rt_ptr->nexthop, ipbuf, sizeof(ipbuf));
				IPM_chkipaddr2p(&rt_ptr->source_ip, source_ip, sizeof(source_ip));
				sprintf( prt_line,
				         "EIPM - Intf %d, subnet %d, route %d, pivot id %d, dest=%s/%d,\tnexthop=%s\tsource ip=%s\n",
				         intf,
				         subn,
				         rt,
					 rt_ptr->pivot_id,
				         destbuf,
				         rt_ptr->destprefix,
				         ipbuf,
					 ( strlen( source_ip ) > 0 ? source_ip : "empty" )
				);
				
				/*
				 * Add this line to the big
				 * print buffer.
				 */
				if( ++cnt_to_prt == 0 )
				{
					strcpy( prt_buf, prt_line );
				}
				else
				{
					strcat( prt_buf, prt_line );
				}
				
				if( cnt_to_prt >= (EIPM_PRT_LINES - 1) )
				{
					/*
					 * We have accumulated
					 * EIPM_PRT_LINES in the buffer.
					 * Time to log it.
					 */
					LOG_FORCE( 0,
					         "%s",
					         prt_buf );
					
					/*
					 * Reset print count.
					 */
					cnt_to_prt = -1;
				}
				
			} /* end 'for all route data' */
			
			if( cnt_to_prt != -1 )
			{
				/*
				 * We have some data left to print.
				 */
				LOG_FORCE( 0,
				         "%s",
				         prt_buf );
			}
			
			/*
			 * Now print the ARP data for this
			 * subnet.
			 */
			arp_ptr = &(data_ptr->subnet[subn].arpdata);
			
			/*
			 * Recall that ARP entries are stored by
			 * priority, so we have to loop through
			 * each one to see if it is valid.  The
			 * priority is the array index + 1;
			 */
			cnt_to_prt = -1;
			for( arp = 0; arp < MAX_ARP_ENTRIES; arp++ )
			{
                                if( arp_ptr->arp_list[arp].arp_ip.addrtype == IPM_IPV4 ||
                                    arp_ptr->arp_list[arp].arp_ip.addrtype == IPM_IPV6 )
				{
					/*
					 * Buffer EIPM_PRT_LINES lines
					 * of ARP data before printing.
					 */
					char ipbuf[IPM_IPMAXSTRSIZE];
					sprintf( prt_line,
					         "EIPM - Intf %d, subnet %d, arp_item %d, cur_index=%d, arpip=%s, prio=%d rcv0=%s, rcv1=%s\n",
					         intf,
					         subn,
					         arp,
						 arp_ptr->cur_index,
					         IPM_chkipaddr2p( &arp_ptr->arp_list[arp].arp_ip, ipbuf, sizeof(ipbuf) ),
					         arp + 1,
					         (arp_ptr->arp_list[arp].lsn0_arprcvd == TRUE)
					                ? true : false,
					         (arp_ptr->arp_list[arp].lsn1_arprcvd == TRUE)
					                ? true : false );
					
					/*
					 * Add this line to the big
					 * print buffer.
					 */
					if( ++cnt_to_prt == 0 )
					{
						strcpy( prt_buf, prt_line );
					}
					else
					{
						strcat( prt_buf, prt_line );
					}
					
					if( cnt_to_prt >= (EIPM_PRT_LINES - 1) )
					{
						/*
						 * We have accumulated
						 * EIPM_PRT_LINES in the
						 * buffer. Time to log it.
						 */
						LOG_FORCE( 0,
						         "%s",
						         prt_buf );
						
						/*
						 * Reset print count.
						 */
						cnt_to_prt = -1;
					}
					
				
				} /* end 'if ARP data is valid' */
				
			} /* end 'for all ARP data' */
			
			if( cnt_to_prt != -1 )
			{
				/*
				 * We have data left to print.
				 */
				LOG_FORCE( 0,
				         "%s",
				         prt_buf );
			}
			//dump all pivots and its active iface
			for (pivot_index = 0; pivot_index < MAX_NUM_PIVOT; pivot_index++)
			{
				if (subn_ptr->pivot_cnt[pivot_index] > 0)
				{
					LOG_FORCE( 0, "pivot id = %d, act iface %s, GARP socket: ipv4_garp_socket=%d, ipv6_ns_garp_socket=%d, ipv6_na_garp_socket=%d", 
						pivot_index, 
						subn_ptr->pivot_act_base[pivot_index] == LSN0 ? "LSN0" : "LSN1",
						data_ptr->eipm_pivot[pivot_index].ipv4_garp_socket,
						data_ptr->eipm_pivot[pivot_index].ipv6_ns_garp_socket,
						data_ptr->eipm_pivot[pivot_index].ipv6_na_garp_socket
						);
				}				
			}	
		} /* end 'for each subnet' */
		
	} /* end 'for each interface' */

	/* Temorary: Dump all the extension interfaces' data as well. */
        if ( ((EIPM_DATA *)EIPM_shm_ptr)->extnIntfCount > 0 )
        {
               EIPM_dumpExtnIntfData( 0, ((EIPM_DATA *)EIPM_shm_ptr)->extnIntfCount ); 
        }

	LOG_FORCE( 0, "proxy_server_enabled: %d\n", EIPM_GET_PROXY_SERVER_ENABLED() );
	LOG_FORCE( 0, "is_wcnp_environment: %d\n", ((EIPM_DATA *)EIPM_shm_ptr)->is_wcnp_environment );
	
	return( IPM_SUCCESS );
}

#define EIPM_LINE_BUFF_SIZE     150

/**********************************************************************
 *
 * Name:        EIPM_createExtnSubData()_
 *
 * Abstract:    Fill the subnet index and route_priority into input string
 *
 * Parameters:  vlanId - External interface VLAN number
 *		intfDataP - base interface data pointer
 *		logBuff - store the final string
 *              buffSize - the MAX size of logBuff, it should big than EIPM_LINE_BUFF_SIZE
 *
 * Returns:     None.
 *
 **********************************************************************/
void EIPM_createExtnSubData(uint16_t vlanId, EIPM_INTF *intfDataP, char *logBuff, int buffSize)
{
	int subnet_index=0;
	EIPM_SUBNET *subnet_ptr=NULL;
	char *logBuffPosP=NULL;

	if ( (logBuff == NULL) || 
		(intfDataP == NULL) ||
		(buffSize < 0) || 
		((buffSize > 0) && (buffSize < (EIPM_LINE_BUFF_SIZE*2))) ||
		(vlanId < 1) || 
		(vlanId > (EIPM_MAX_VLANS-1))
	   )
	{
		LOG_FORCE( 0, "EIPM_createExtnSubData: logBuff is NULL or intfDataP is NULL or buffSize(%d) is out of range (<%d) or vlanId (%d) is out of range (1-%d)\n", buffSize, EIPM_LINE_BUFF_SIZE, vlanId, (EIPM_MAX_VLANS-1));
		return;
	}

	*logBuff = '\0';
	logBuffPosP=logBuff;
	logBuffPosP += snprintf( logBuffPosP, buffSize, "subnet_index/route_priority ( ");
	for ( subnet_index=0, subnet_ptr=&(intfDataP->subnet[0]);
		subnet_index < intfDataP->subnet_cnt;
		subnet_index++, subnet_ptr++ )
	{
		if ( (EIPM_LINE_BUFF_SIZE+2) > (buffSize - (logBuffPosP-logBuff-1)) )
		{
			/*
			 * It should Not be here because the total string length 
			 * should be less than 100
			 */
			break;
		}
		if ( subnet_ptr->sub2intf_mapping[vlanId].is_intf_configured == 1 )
		{
			logBuffPosP += snprintf( logBuffPosP, EIPM_LINE_BUFF_SIZE, "%d/%d ", 
				subnet_index, subnet_ptr->sub2intf_mapping[vlanId].route_priority);
		}
	}
	logBuffPosP += snprintf( logBuffPosP, EIPM_LINE_BUFF_SIZE, ")");
	return;
}

/**********************************************************************
 *
 * Name:	EIPM_dumpExtnIntfData.
 *
 * Abstract:	Logs extension interfaces' data for the specified range.
 *
 * Parameters:	minIdx - Lower value of the range to log.
 *              maxIdx - Upper value of the range to log.
 *
 * Returns:	None.
 *
 **********************************************************************/

void EIPM_dumpExtnIntfData( int minIdx, int maxIdx )
{

        EIPM_DATA       *dataP;
        EIPM_INTF       *intfDataP;
        EIPM_INTF_SPEC  *intfSpecDataP;
        char            logBuff[UMAX_LOG_SIZE];
        char            lineBuff[EIPM_LINE_BUFF_SIZE];
        char            *logBuffPosP;
        char            intfStatusStr[20];
        char		lsnSideStr[20];
	// store the subnet index and routing priority information
        char		subIdxAndRoutePrio[EIPM_LINE_BUFF_SIZE*2];

        if ( NULL == EIPM_shm_ptr )
	{
		ASRT_RPT( ASMISSING_DATA,
		          2,
		          sizeof( EIPM_shm_ptr ),
			  &EIPM_shm_ptr,
			  sizeof( EIPM_shmid ),
			  &EIPM_shmid,
		          "EIPM not attached to shared memory segment\n",
                          (char *)(__func__) );
		
		return;
	}

        dataP = (EIPM_DATA *)EIPM_shm_ptr;
        logBuff[0] = '\0';
        logBuffPosP = logBuff;

        if ( ( minIdx < 0 ) || ( minIdx >= dataP->extnIntfCount ) )
        {
                /* Invalid lower range. Reset it. */
                minIdx = 0;
        }

        if ( ( maxIdx < 0 ) || ( maxIdx >= dataP->extnIntfCount ) )
        {
                /* Invalid upper range. Reset it. */
                maxIdx = ( dataP->extnIntfCount - 1 );
        }

        logBuffPosP += snprintf( logBuffPosP, UMAX_LOG_SIZE, 
                                "### EIPM EXTN INTF DUMP (%d thru %d, Count: %d) ###\n\n",
                                minIdx, maxIdx, dataP->extnIntfCount );

        /* -- Log the extension interfaces' data. -- */
        for ( ( intfSpecDataP = &(dataP->extnIntfData[minIdx]) );
              ( minIdx <= maxIdx );
              ( minIdx++, intfSpecDataP++ )  )
        {
                if ( !EIPM_IS_VALID_BASE_INTF_IDX( intfSpecDataP->baseIntfIdx ) )
                {
                        intfDataP = NULL;
                }
                else
                {
                        intfDataP = &(dataP->intf_data[intfSpecDataP->baseIntfIdx]);
                }

                if ( EIPM_LINE_BUFF_SIZE*2 > ( UMAX_LOG_SIZE - ( logBuffPosP - logBuff - 1 ) ) )
                {
                        /* Reached the buffer limit. Log whatever's in it first. */
                        LOG_FORCE( 0, logBuff );

                        /* Reset the buffer and position pointer. */
                        logBuff[0] = '\0';
                        logBuffPosP = logBuff;
                }

                EIPM_status2str( intfSpecDataP->status, intfStatusStr );
                EIPM_network2str( intfSpecDataP->preferred_side, lsnSideStr );


		subIdxAndRoutePrio[0]='\0';
		EIPM_createExtnSubData( intfSpecDataP->vlanId, intfDataP,
			subIdxAndRoutePrio,  EIPM_LINE_BUFF_SIZE*2);
		logBuffPosP += snprintf( logBuffPosP, (EIPM_LINE_BUFF_SIZE*2),
				"Idx: %d BaseIdx: %d Name: %s%s-%s%s Monitor: %d State: %s Status: %s PrefSide: %s, %s\n",
				minIdx,
				intfSpecDataP->baseIntfIdx,
				( intfDataP ? intfDataP->lsn0_baseif : "ERR" ),
				strlen(intfDataP->lsn0_baseif) > 0 ? ipm_getVLANStr(intfSpecDataP->vlanId, TRUE) : "empty",
				( intfDataP ? intfDataP->lsn1_baseif : "ERR" ),
				strlen(intfDataP->lsn1_baseif) > 0 ? ipm_getVLANStr(intfSpecDataP->vlanId, TRUE) : "empty",
				intfSpecDataP->monitor,
				EIPM_state2str( intfSpecDataP->state ),
				intfStatusStr,
				lsnSideStr,
				subIdxAndRoutePrio);

        } /* end 'extension interfaces loop' */

        LOG_FORCE( 0, logBuff );

} /* end 'EIPM_dumpExtnIntfData' */


/**********************************************************************
 *
 * Name:	EIPM_state2str.
 *
 * Abstract:	Translates 'EIPM_STATE' enum values to a string.
 *
 * Parameters:	intfState - Interface state to translate to a string.
 *
 * Returns:	The string representing the interface state.
 *
 **********************************************************************/

char *EIPM_state2str( EIPM_STATE intfState )
{

        switch ( intfState )
        {

                case NULL_STATE:
                        return "NULL";
			
		case NORMAL_STATE:
			return "NORMAL";
			
		case DETECTION_STATE:
			return "DETECTION";
			break;
			
		case ACTION_STATE:
			return "ACTION";
			break;
			
		case RESTORE_STATE:
			return "RESTORE";
			break;
			
		default:
			return "UNKNOWN";

        } /* end 'switch ( intfState )' */

} /* end 'EIPM_state2str' */




/**********************************************************************
 *
 * Name:	EIPM_status2str()
 *
 * Abstract:	Convert EIPM status variable to an enum
 *
 * Parameters:	status - Current status variable
 *		strptr - Pointer to string to fill in.
 *
 * Returns:	Function returns nothing, but fills in string pointer.
 *		strptr is set to "INVALID" if status is not a known
 *		status.
 *
 **********************************************************************/


void EIPM_status2str( EIPM_STATUS status, char *strptr )

{
	/*
	 * Convert status to string.
	 */
	switch( status )
	{
	case EIPM_STAT_NULL:
		strcpy( strptr, "NULL" );
		break;
		
	case EIPM_UNKNOWN:
		strcpy( strptr, "UNKNOWN" );
		break;
		
	case EIPM_ONLINE:
		strcpy( strptr, "ONLINE" );
		break;
		
	case EIPM_SOAKING:
		strcpy( strptr, "SOAKING" );
		break;
		
	case EIPM_DEGRADED:
		strcpy( strptr, "DEGRADED" );
		break;
		
	case EIPM_OFFLINE:
		strcpy( strptr, "OFFLINE" );
		break;
		
	case EIPM_INHIBITED:
		strcpy( strptr, "INHIBITED" );
		break;
		
	default:
		
		/*
		 * Status is bogus.  Set it to INVALID and let
		 * the caller decide what to do.
		 */
		strcpy( strptr, "INVALID" );
		  
		break;
	}
	return;
}



/**********************************************************************
 *
 * Name:	EIPM_iptype2str()
 *
 * Abstract:	Convert EIPM IP Type to a string
 *
 * Parameters:	type - Current IP Type variable
 *		strptr - Pointer to string to fill in.
 *
 **********************************************************************/

void EIPM_iptype2str( EIPM_IP_TYPE type, char *strptr )

{
	/*
	 * Convert type to string.
	 */
	switch( type )
	{
	case EIPM_IP_ALIAS:
		strcpy( strptr, "ALIAS" );
		break;

	case EIPM_IP_WCNP_FIXED:
		strcpy( strptr, "WCNP FIXED" );
		break;
		
	case EIPM_IP_WCNP_ACTIVE:
		strcpy( strptr, "WCNP ACTIVE" );
		break;
		
	case EIPM_IP_WCNP_STANDBY:
		strcpy( strptr, "WCNP STANDBY" );
		break;
		
	case EIPM_IP_PROXY_SERVER:
		strcpy( strptr, "PROXY SERVER" );
		break;
		
	case EIPM_IP_PROXY_CLIENT_ADDR:
		strcpy( strptr, "PROXY CLIENT ADDR" );
		break;
		
	case EIPM_IP_PROXY_CLIENT:
                strcpy( strptr, "PROXY CLIENT" );
                break;

	default:
		
		/*
		 * Type is bogus.  Set it to INVALID and let
		 * the caller decide what to do.
		 */
		strcpy( strptr, "INVALID" );
		  
		break;
	}
	return;
}


/**********************************************************************
 *
 * Name:	EIPM_network2str()
 *
 * Abstract:	Convert EIPM network variable to string
 *
 * Parameters:	status - Current network variable
 *		strptr - Pointer to string to fill in.
 *
 * Returns:	Function returns nothing, but fills in string pointer.
 *		strptr is set to "INVALID" if status is not a known
 *		status.
 *
 **********************************************************************/


void EIPM_network2str( EIPM_NET network, char *strptr )

{
	/*
	 * Convert status to string.
	 */
	switch( network )
	{
	case LSN_NONE:
		strcpy( strptr, "NONE" );
		break;
		
	case LSN0:
		strcpy( strptr, "LSN0" );
		break;
		
	case LSN1:
		strcpy( strptr, "LSN1" );
		break;
		
	case LSN_BOTH:
		strcpy( strptr, "BOTH" );
		break;
		
	default:
		
		/*
		 * Status is bogus.  Set it to INVALID and let
		 * the caller decide what to do.
		 */
		strcpy( strptr, "INVALID" );
		  
		break;
	}
	return;
}

EIPM_STATUS EIPM_getFailedIntfInfo( void *intfDataP, EIPM_INTF_TYPE intfType,
                                    char *intfInfoStr, int intfInfoStrLen,
                                    EIPM_STATUS intfStatus )
{
        EIPM_INTF       *baseIntfDataP;
        EIPM_INTF_SPEC  *intfSpecDataP;
        EIPM_SUBNET     *subnetDataP;
        char            failed_intfStr[EI_INTFNAMESIZE];
        int             subnetIdx;        

	uint16_t        vlanId=0;
        EIPM_SET_INTF_PTRS( intfDataP, intfType, baseIntfDataP, intfSpecDataP );

        if ( NULL == baseIntfDataP )
        {
                return EIPM_STAT_NULL;
        }

	if ( intfType == EIPM_EXTN_INTF )
	{
		vlanId = intfSpecDataP->vlanId;
	}

        failed_intfStr[0] = '\0';        

        for( ( subnetIdx = 0, subnetDataP = &(baseIntfDataP->subnet[0]) );
             ( subnetIdx < baseIntfDataP->subnet_cnt );
             ( subnetIdx++, subnetDataP++ ) )
        {

                switch ( subnetDataP->sub2intf_mapping[vlanId].route_priority )
                {

                        case LSN0:
                        {
                                snprintf( failed_intfStr, sizeof( failed_intfStr ),
                                          "%s",
                                          baseIntfDataP->lsn1_baseif );
                                break;
                        }

                        default:
                        {
                                snprintf( failed_intfStr, sizeof( failed_intfStr ),
                                          "%s",
                                          baseIntfDataP->lsn0_baseif );
                                break;
                        }

                }

                subnetIdx = baseIntfDataP->subnet_cnt;

        }       

        switch ( intfSpecDataP->status )
        {

                case EIPM_OFFLINE:
                {
                        intfStatus = EIPM_OFFLINE;
                        snprintf( intfInfoStr,intfInfoStrLen, "%s ", failed_intfStr );

                        break;
                } /* case EIPM_OFFLINE */

                case EIPM_DEGRADED:
                {
                        switch ( intfStatus )
                        {
                                case EIPM_OFFLINE:
                                        break;

                                default:
                                        intfStatus = EIPM_DEGRADED;
                                        break;
                        }

                        snprintf( intfInfoStr,intfInfoStrLen, "%s ", failed_intfStr );
                        break;
                } /* case EIPM_DEGRADED */

		case EIPM_SOAKING:
		{
			switch (intfStatus)
			{
				case EIPM_OFFLINE:
				case EIPM_DEGRADED:
					break;

				default:
					intfStatus = EIPM_SOAKING;
					break;
			}

			snprintf(intfInfoStr, intfInfoStrLen, "%s ", failed_intfStr);
			break;
		}

                case EIPM_ONLINE:
                {
                        switch ( intfStatus )
                        {
                                case EIPM_OFFLINE:
                                case EIPM_DEGRADED:
                                        break;

                                default:
                                        intfStatus = EIPM_ONLINE;
                                        break;
                        }

                        break;
                } /* case EIPM_ONLINE */

                case EIPM_INHIBITED:
                {
                        switch ( intfStatus )
                        {
                                case EIPM_STAT_NULL:
                                        intfStatus = EIPM_INHIBITED;
                                        break;

                                default:
                                        break;
                        }

                        break;
                } /* case EIPM_INHIBITED */

                case EIPM_UNKNOWN:
                case EIPM_STAT_NULL:
                default:
                {
                        break;
                } /* default */

        } /* switch ( intfSpecDataP->status ) */

        return intfStatus;

} /* end 'EIPM_getFailedIntfInfo' */

/**********************************************************************
 *
 * Name:	EIPM_getstatus()
 *
 * Abstract:	Loop through all data that has been provisioned
 *		and return overall status.
 *
 * Parameters:	None
 *
 * Returns:	summary of EIPM status
 *
 **********************************************************************/


EIPM_STATUS EIPM_getstatus( char *strptr, int str_len )
{
	register EIPM_INTF	*data_ptr;
	int			intf;
	EIPM_STATUS 		eipm_interface_status;
	char			eipm_str[16];
	char			eipm_info[512];
	int			idx;
	char                    intfInfoStr[MAX_NLEN_DEV];
        EIPM_INTF_SPEC          *intfSpecDataP;
        int                     extnIntfIdx;
        int                     badStateExtnIntfCount;
        char                    logBuff[UMAX_LOG_SIZE];
        char                    lineBuff[EIPM_LINE_BUFF_SIZE];
        char                    *logBuffPosP;
        BOOL                    bBaseIntfAdded;

	*strptr = '\0';

	if( eipm_enable == FALSE )
	{
		EIPM_status2str(EIPM_INHIBITED, strptr);

		return( EIPM_INHIBITED );
	}

	/*
	 * Make sure we are attached to shared memory segment.
	 */
	if( EIPM_shm_ptr == NULL )
	{
		/*
		 * Fire an assert.
		 */
		ASRT_RPT( ASMISSING_DATA,
		          2,
		          sizeof( EIPM_shm_ptr ),
			  &EIPM_shm_ptr,
			  sizeof( EIPM_shmid ),
			  &EIPM_shmid,
		          "EIPM_dumpshm: EIPM not attached to shared memory segment\n" );
		
		EIPM_status2str(EIPM_STAT_NULL, strptr);

		return( EIPM_STAT_NULL );
	}
	
	/*
	 * If data has not been initialized then there is nothing
	 * to do.
	 */
	if( ((EIPM_DATA *)EIPM_shm_ptr)->intf_cnt == 0 )
	{
		EIPM_status2str(EIPM_STAT_NULL, strptr);

		return( EIPM_STAT_NULL );
	}

	eipm_interface_status = EIPM_STAT_NULL;
	eipm_info[0] = '\0';
	idx = 0;
	
	/*
	 * Loop through shared segment.
	 */
	logBuffPosP = logBuff;
        logBuffPosP += snprintf( logBuffPosP, ( UMAX_LOG_SIZE - ( logBuffPosP - logBuff - 1 ) ),
                                 "Offline/Degraded Intfs:\n" );

        for ( ( intf = 0, data_ptr = &(((EIPM_DATA *)EIPM_shm_ptr)->intf_data[0]) );
	      ( intf < ((EIPM_DATA *)EIPM_shm_ptr)->intf_cnt );
	      ( intf++, data_ptr++ ) )
        {

                bBaseIntfAdded = FALSE;

                if ( EIPM_REPORT( &(data_ptr->specData) ) )
                {
                        /* Determine status of the base interface. */
                        eipm_interface_status = EIPM_getFailedIntfInfo( data_ptr, EIPM_BASE_INTF,
                                                                        intfInfoStr, sizeof( intfInfoStr ),
                                                                        eipm_interface_status );

			if (EIPM_OFFNORMAL(eipm_interface_status) && EIPM_OFFNORMAL(data_ptr->specData.status))
                        {
                                idx += snprintf( &eipm_info[idx], ( sizeof( eipm_info ) - idx ),
                                                 "%s ", intfInfoStr );
                                bBaseIntfAdded = TRUE;

                                if ( ( UMAX_LOG_SIZE - ( logBuffPosP - logBuff - 1 ) ) <  strlen( intfInfoStr ) )
                                {
                                        LOG_FORCE( 0, logBuff );
                                        logBuffPosP = logBuff;                                        
                                }

                                logBuffPosP += snprintf( logBuffPosP, ( UMAX_LOG_SIZE - ( logBuffPosP - logBuff - 1 ) ),
                                                         "%s ", intfInfoStr );
                        }
                }

                badStateExtnIntfCount = 0;

                if ( data_ptr->extnIntfIdx != -1 )
                {

                        for ( ( extnIntfIdx = 0, intfSpecDataP = &(((EIPM_DATA *)EIPM_shm_ptr)->extnIntfData[0]) );
                              ( extnIntfIdx < ((EIPM_DATA *)EIPM_shm_ptr)->extnIntfCount );
                              ( extnIntfIdx++, intfSpecDataP++ ) )
                        {

                                if (    ( intfSpecDataP->baseIntfIdx != intf ) 
                                     || ( !EIPM_REPORT( intfSpecDataP ) ) )
                                {
                                        continue;
                                }

                                /* Determine status of the base interface. */
                                eipm_interface_status = EIPM_getFailedIntfInfo( intfSpecDataP, EIPM_EXTN_INTF,
                                                                                intfInfoStr, sizeof( intfInfoStr ),
                                                                                eipm_interface_status );

				if (EIPM_OFFNORMAL(eipm_interface_status) && EIPM_OFFNORMAL(intfSpecDataP->status))
                                {
                                        if ( FALSE == bBaseIntfAdded )
                                        {
                                                idx += snprintf( &eipm_info[idx], ( sizeof( eipm_info ) - idx ),
                                                                 "%s VLANs ", intfInfoStr );
                                                bBaseIntfAdded = TRUE;

                                                if ( ( UMAX_LOG_SIZE - ( logBuffPosP - logBuff - 1 ) ) <  strlen( intfInfoStr ) )
                                                {
                                                        LOG_FORCE( 0, logBuff );
                                                        logBuffPosP = logBuff;                                                        
                                                }

                                                logBuffPosP += snprintf( logBuffPosP, ( UMAX_LOG_SIZE - ( logBuffPosP - logBuff - 1 ) ),
                                                                         "%s VLANs ", intfInfoStr );
                                        }

                                        badStateExtnIntfCount++;

                                        if ( ( UMAX_LOG_SIZE - ( logBuffPosP - logBuff - 1 ) ) <  4 )
                                        {
                                                LOG_FORCE( 0, logBuff );
                                                logBuffPosP = logBuff;                                                
                                        }

                                        logBuffPosP += snprintf( logBuffPosP, ( UMAX_LOG_SIZE - ( logBuffPosP - logBuff - 1 ) ),
                                                                 "%u ", intfSpecDataP->vlanId );
                                }

                        } /* end 'extension interfaces loop' */

                } /* end 'valid extension intf idx' */

                if ( badStateExtnIntfCount > 0 )
                {
                        idx += snprintf( &eipm_info[idx], ( sizeof( eipm_info ) - idx ), 
                                         "(%d) ", badStateExtnIntfCount );
                        badStateExtnIntfCount = 0;
                }

                LOG_FORCE( 0, logBuff );
                logBuffPosP = logBuff;

        } /* end 'base interfaces loop' */

	EIPM_status2str(eipm_interface_status, eipm_str);

	snprintf(strptr, str_len,
		 "%s %s",
		 eipm_str,
		 eipm_info);

	return( eipm_interface_status );
}




/**********************************************************************
 *
 * Name:	EIPM_send_alarm()
 *
 * Abstract:	Send an alarm using the alarm API
 *
 * Parameters:	alarm      - Internal alarm name
 *		threshold  - Number of times problem mut be seen
 *			     before alarm is sent.
 *		intfDataP - Pointer to data for base/extension interface
 *		intfType - Interface type to determine 'intfDataP'.
 *		subnet_index - index to subnet
 *		sev        - alarm severity
 *		link_id    - Link resource name for alarm
 *		user_strng - description of problem
 *		file       - file name (typically __FILE__ macro)
 *		line       - line number (typically __LINE__ macro )
 *
 * Returns:	None
 *
 **********************************************************************/

void
EIPM_send_alarm( EIPM_ALARM_LIST alarm,
		 int threshold,
		 void *intfDataP,
                 EIPM_INTF_TYPE intfType,
		 int subnet_index,
		 FSALARM_SEVERITY_TYPE sev,
/*               FSALARM_PROBLEM_TYPE type, */
		 char *link_id,
                 char *user_strng,
		 char *file,
		 int line )
{
	EIPM_INTF               *data_ptr;
        EIPM_INTF_SPEC          *intfSpecDataP;
        EIPM_ALARM_DATA         (*alarmDataP)[EIPM_MAX_ALARM];
	char resource[ FSALARM_RESOURCE_BUFFSZ ];
	char hostname[ EI_HOSTNAMESIZE ];
	char ipbuf[ IPM_IPMAXSTRSIZE ];
	FSALARM_PROBLEM_TYPE alarmCauseType;


	if ( EIPM_BASE_INTF == intfType )
        {
                data_ptr = (EIPM_INTF *)intfDataP;
                intfSpecDataP = &(data_ptr->specData);
                alarmDataP = intfSpecDataP->alarm;
        }
        else
        {
                intfSpecDataP = (EIPM_INTF_SPEC *)intfDataP;

                if ( EIPM_IS_VALID_BASE_INTF_IDX( intfSpecDataP->baseIntfIdx ) )
                {
                        data_ptr = &(((EIPM_DATA *)EIPM_shm_ptr)->intf_data[intfSpecDataP->baseIntfIdx]);
                        alarmDataP = intfSpecDataP->alarm;
                }
                else
                {
                        ASRT_RPT( ASBAD_DATA, 0, "Invalid base interface index %d (count: %d). intfType: %u\n",
                                  intfSpecDataP->baseIntfIdx, ((EIPM_DATA *)EIPM_shm_ptr)->intf_cnt,
                                  intfType );

                        return;
                }

        }
        if ( ( subnet_index < 0 ) || ( subnet_index >= EIPM_MAX_SUBNETS ) )
        {
                ASRT_RPT( ASBAD_DATA, 0, "Invalid subnet index %d for extension interface %s%s-%s%s\n",
                subnet_index, data_ptr->lsn0_baseif, ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
                data_ptr->lsn1_baseif, ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
                return;
        }

	if ( !EIPM_REPORT( intfSpecDataP ) )
	{
		return;
	}

	// If we have already raised this alarm don't send it again.
	if ( TRUE == EIPM_ALARM_DATA_AT( alarmDataP, subnet_index, alarm )->alarm_sent )
	{
		return;
	}
	
	data_ptr->specData.alarm[subnet_index][ alarm ].threshold  = threshold;

	if ( ++(data_ptr->specData.alarm[subnet_index][ alarm ].count) <
		data_ptr->specData.alarm[subnet_index][ alarm ].threshold )
	{
		/* We haven't seen this problem enough times yet
		 * to really send the alarm.
		 */
		return;
	}

	/*
	 * Generate resource string.
	 */
	int retval = gethostname( hostname, EI_HOSTNAMESIZE );
	if (retval < 0)
	{
		LOG_ERROR( 0, "EIPM_send_alarm(): Failed to get hostname, error %s.\n", strerror(errno));
		memset(hostname, 0, EI_HOSTNAMESIZE);
		strcpy(hostname, "UNKNOWN");
	}
        switch( alarm )
        {
        case EIPM_NEXTHOP_FAIL:
                /*
                 * For duplex interface failure, the critical alarm resource string is
                 * Machine=hostname:Resource_type=NextHop:Subnet=X
                 */
                sprintf( resource,
                        "Machine=%s%cResource_type=NextHop%cSubnet=%s",
                        hostname,
                        FSALARM_RESOURCE_FIELD_DELIMITER,
                        FSALARM_RESOURCE_FIELD_DELIMITER,
                        IPM_ipaddr2p(&data_ptr->subnet[subnet_index].subnet_base, ipbuf, sizeof(ipbuf)) );
                /*
                 * We encountered duplex interface failure, a Critical alarm will be sent out
                 * but before that, clear the Major alarm we send out before for single
                 * interface down.
                 */
		if ( TRUE == EIPM_ALARM_DATA_AT( alarmDataP, EIPM_INTF_SUBNET, EIPM_LNK_FAIL )->alarm_sent )
                {
                        EIPM_CLEAR_INTF_ALARM( intfDataP, intfType, EIPM_LNK_FAIL );
                }

                break;

        default:
	{
                /*
                 * All others alarms, resource string is
                 * Machine=hostname:Resource_type=Link:LinkId=lsn0_iface,lsn1_iface
                 */
		snprintf( resource,
                          sizeof( resource ),
                          "Machine=%s%cResource_type=Link%cLinkId=%s%s,%s%s",
                          hostname,
                          FSALARM_RESOURCE_FIELD_DELIMITER,
                          FSALARM_RESOURCE_FIELD_DELIMITER,
                          data_ptr->lsn0_baseif,
                          ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
                          data_ptr->lsn1_baseif,
                          ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

                break;
	} /* end 'default' */

        }

	if (alarm == EIPM_STATE_CHG)
	{
		alarmCauseType = FSAP_stateChange;
	}
	else
	{
		alarmCauseType = FSAP_externalConnectivity;
	}

	/*
	 * Class:		Ethernet
	 * Severity:		Passed in
	 * Cause/Type:		Ethernet error
	 * Resource type:	link
	 * Resource:		Set above.
	 * Far-end Resource:	Have to ponder if this should be set.
	 * User-String:		Passed in
	 * Description Type:	Unused (as specified in API)
	 * Recovery Type:	Unused (as specified in API)
	 * File:		Passed in (File alarm being called from)
	 * Line:		Passed in (Line alarm being called from)
	 */
	SEND_ALARM1( FSAC_ethernet,
	             sev,
	             alarmCauseType,
	             FSAR_link,
	             resource,
	             (char *)NULL,
	             user_strng,
	             FSADK_UNUSED,
	             FSADK_UNUSED,
	             file,
	             line );
	
	LOG_FORCE(0, "ALARM: FSAC_ethernet FSAP_externalConnectivity FSAR_link. Severity %d\nResource: %s\nInfo: %s\n",
            sev, resource, user_strng);
	
	/*
	 * Save data so we can clear alarm later.
	 */
	EIPM_ALARM_DATA_AT( alarmDataP, subnet_index, alarm )->alarm_sent = TRUE;
	++EIPM_ALARM_DATA_AT( alarmDataP, subnet_index, alarm )->count;
	strcpy( EIPM_ALARM_DATA_AT( alarmDataP, subnet_index, alarm )->link_id, link_id );
	EIPM_ALARM_DATA_AT( alarmDataP, subnet_index, alarm )->severity = sev;
	strcpy( EIPM_ALARM_DATA_AT( alarmDataP, subnet_index, alarm )->resource, resource );
	strncpy( EIPM_ALARM_DATA_AT( alarmDataP, subnet_index, alarm )->user_text, user_strng, FSALARM_UTEXT_BUFFSZ-1 );
	EIPM_ALARM_DATA_AT( alarmDataP, subnet_index, alarm )->user_text[FSALARM_UTEXT_BUFFSZ-1] = 0;
	EIPM_ALARM_DATA_AT( alarmDataP, subnet_index, alarm )->file = file;
	EIPM_ALARM_DATA_AT( alarmDataP, subnet_index, alarm )->line = line;
				
        EIPM_send_status(data_ptr);

} /* end EIPM_send_alarm() */


/**********************************************************************
 *
 * Name:	EIPM_send_ip_alarm()
 *
 * Abstract:	Send an IP-granularity alarm using the alarm API
 *
 * Parameters:	alarm      - Internal alarm name
 *		threshold  - Number of times problem mut be seen
 *			     before alarm is sent.
 *		data_ptr   - Pointer to data for this interface
 *		subnet_index - index to subnet on this interface
 *		ip_index   - index to IP address on this subnet
 *		sev        - alarm severity
 *		link_id    - Link resource name for alarm
 *		user_strng - description of problem
 *		file       - file name (typically __FILE__ macro)
 *		line       - line number (typically __LINE__ macro )
 *
 * Returns:	None
 *
 **********************************************************************/

void
EIPM_send_ip_alarm( EIPM_ALARM_LIST alarm,
		 int threshold,
                 EIPM_INTF *data_ptr,
		 int subnet_index,
		 int ip_index,
		 FSALARM_SEVERITY_TYPE sev,
		 char *link_id,
                 char *user_strng,
		 char *file,
		 int line )
{
	EIPM_INTF_SPEC  	*intfSpecDataP;
	EIPM_IP_ALARM_DATA	*ip_alarm_data_ptr;
	EIPM_ALARM_DATA		*alarm_ptr;
	IPM_IPADDR		*local_ip_ptr;
	IPM_IPADDR		*remote_ip_ptr;

	char	resource[FSALARM_RESOURCE_BUFFSZ];
	char	hostname[EI_HOSTNAMESIZE];
	char	local_ip_buf[IPM_IPMAXSTRSIZE];
	char	remote_ip_buf[IPM_IPMAXSTRSIZE];

	int	loop_idx;
	int	ip_key;		/* key in array is ip_index + 1 */
	bool	found_slot = FALSE;

	intfSpecDataP = &(data_ptr->specData);

	if ( !EIPM_REPORT(intfSpecDataP) )
	{
		return;
	}

	ip_key = ip_index + 1;

	for ( loop_idx=0;
	      (loop_idx < EIPM_MAX_IP_ALARMS) && (found_slot == FALSE);
	      loop_idx++ )
	{
		ip_alarm_data_ptr = &(data_ptr->ip_alarm[subnet_index][loop_idx]);

		if (ip_alarm_data_ptr->ip_key == ip_key)
		{
			/* Found the slot we're already using for
			 * this IP address.
			 */
			found_slot = TRUE;
		}
		else if (ip_alarm_data_ptr->ip_key == 0)
		{
			/* Found an empty slot so use it */
			found_slot = TRUE;

			memset(&(ip_alarm_data_ptr->alarm_data),
			       0,
			       sizeof(ip_alarm_data_ptr->alarm_data));
		}
	}

	if (found_slot == FALSE)
	{
		/* Could find neither an empty slot nor a slot we
		 * were using previously - report the problem and return.
		 */
		LOG_ERROR( 0, "EIPM_send_ip_alarm(): ran out of ip_alarm slots\n");
		return;
	}

	ip_alarm_data_ptr->ip_key = ip_key;
	alarm_ptr = &(ip_alarm_data_ptr->alarm_data);

	// If we have already raised this alarm don't send it again.
	if (alarm_ptr->alarm_sent == TRUE)
	{
		return;
	}
	
	alarm_ptr->threshold = threshold;

	if ( ++(alarm_ptr->count) < alarm_ptr->threshold )
	{
		/* We haven't seen this problem enough times yet
		 * to really send the alarm.
		 */
		return;
	}

	/*
	 * Generate resource string.
	 */
	int retval = gethostname( hostname, EI_HOSTNAMESIZE );
	if (retval < 0)
	{
		LOG_ERROR( 0, "EIPM_send_ip_alarm(): Failed to get hostname, error %s.\n", strerror(errno));
		memset(hostname, 0, EI_HOSTNAMESIZE);
		strcpy(hostname, "UNKNOWN");
	}

	/*
	 * Resource string is
	 * Machine=hostname:Resource_type=BFDSession:LocalIP=X:RemoteIP=Y
	 */
	local_ip_ptr  = &(data_ptr->subnet[subnet_index].ips[ip_index].ipaddr);
	IPM_ipaddr2p(local_ip_ptr, local_ip_buf, sizeof local_ip_buf),

	remote_ip_ptr = &(data_ptr->subnet[subnet_index].gateway);
	IPM_ipaddr2p(remote_ip_ptr, remote_ip_buf, sizeof remote_ip_buf),

	sprintf( resource,
	 	"Machine=%s%cResource_type=BFDSession%cLocalIP=%s%cRemoteIP=%s",
		hostname,
		FSALARM_RESOURCE_FIELD_DELIMITER,
		FSALARM_RESOURCE_FIELD_DELIMITER,
		local_ip_buf,
		FSALARM_RESOURCE_FIELD_DELIMITER,
		remote_ip_buf );

	if( strcmp(local_ip_buf, remote_ip_buf) == 0 )
	{
		LOG_ERROR(0,"%s(): loc==rmt IP %s.\n",__FUNCTION__,resource);
	}

	/*
	 * Class:		Ethernet
	 * Severity:		Passed in
	 * Cause/Type:		Ethernet error
	 * Resource type:	link
	 * Resource:		Set above.
	 * Far-end Resource:	Have to ponder if this should be set.
	 * User-String:		Passed in
	 * Description Type:	Unused (as specified in API)
	 * Recovery Type:	Unused (as specified in API)
	 * File:		Passed in (File alarm being called from)
	 * Line:		Passed in (Line alarm being called from)
	 */
	SEND_ALARM1( FSAC_ethernet,
	             sev,
	             FSAP_externalConnectivity,
	             FSAR_link,
	             resource,
	             (char *)NULL,
	             user_strng,
	             FSADK_UNUSED,
	             FSADK_UNUSED,
	             file,
	             line );
	
	
	/*
	 * Save data so we can clear alarm later.
	 */
	alarm_ptr->alarm_sent = TRUE;
	strcpy( alarm_ptr->link_id, link_id );
	alarm_ptr->severity = sev;
	strcpy( alarm_ptr->resource, resource );
	strcpy( alarm_ptr->user_text, user_strng );
	alarm_ptr->file = file;
	alarm_ptr->line = line;

        EIPM_send_status(data_ptr);

} /* end EIPM_send_ip_alarm() */


/**********************************************************************
 *
 * Name:	EIPM_clear_alarms()
 *
 * Abstract:	Communication has been successfully restored.
 * 		Clear all alarms for this interface.
 *
 * Parameters:	intfDataP - pointer to data for base/extension interface.
 *		intfType - Interface type to determine 'intfDataP'.
 *		subnet_index - index to subnet.
 *		alarm_index - index to EIPM alarm type.
 *
 * Returns:	None
 *
 **********************************************************************/

void
EIPM_clear_alarms( void *intfDataP, EIPM_INTF_TYPE intfType, int subnet_index, EIPM_ALARM_LIST alarm_index )
{
	EIPM_INTF       *data_ptr;
        EIPM_INTF_SPEC  *intfSpecDataP;
        EIPM_ALARM_DATA (*alarmDataP)[EIPM_MAX_ALARM];
	int             maxSubnets;
	int i;
	int j;
	FSALARM_PROBLEM_TYPE alarmCauseType;

	maxSubnets = EIPM_MAX_SUBNETS;

	if ( EIPM_BASE_INTF == intfType )
        {
                data_ptr = (EIPM_INTF *)intfDataP;
                intfSpecDataP = &(data_ptr->specData);
                alarmDataP = intfSpecDataP->alarm;
        }
        else
        {
                intfSpecDataP = (EIPM_INTF_SPEC *)intfDataP;

                if ( EIPM_IS_VALID_BASE_INTF_IDX( intfSpecDataP->baseIntfIdx ) )
                {
                        data_ptr = &(((EIPM_DATA *)EIPM_shm_ptr)->intf_data[intfSpecDataP->baseIntfIdx]);
                        alarmDataP = intfSpecDataP->alarm;
                }
                else
                {
                        ASRT_RPT( ASBAD_DATA, 0, "Invalid base interface index %d (count: %d). intfType: %u\n",
                                  intfSpecDataP->baseIntfIdx, ((EIPM_DATA *)EIPM_shm_ptr)->intf_cnt,
                                  intfType );

                        return;
                }

        }
	if ( ( subnet_index < 0 ) || ( subnet_index > maxSubnets ) )
        {
                ASRT_RPT( ASBAD_DATA, 0, "Invalid subnet index %d for extension interface %s%s-%s%s\n",
                subnet_index, data_ptr->lsn0_baseif, ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
                data_ptr->lsn1_baseif, ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
                return;
        }
	
	/*
	 * Loop on all of the possible alarms we can send and
	 * send a clear if an alarm was raised.
	 */
	for ( i = 0; i < maxSubnets; i++ )
	{
		for( j = 0; j < EIPM_MAX_ALARM; j++ )
		{
			if ( !EIPM_REPORT( intfSpecDataP ) )
			{
				continue;
			}
			/*
			 * See if alarm was generated.
			 */
			if (EIPM_ALARM_DATA_AT(alarmDataP, i, j)->alarm_sent != TRUE )
			{
				continue;
			}
	                if( (subnet_index != maxSubnets) &&
	                        (subnet_index != i) )
			{
	                        /* if the subnet is not what we care, goto next */
	                        continue;
			}
	               if( ((int)alarm_index != EIPM_MAX_ALARM) &&
	                        ((int)alarm_index != j) )
	                {
	                        /* if the alarm type is not what we care, goto next */
	                        continue;
	                }
			if ( 0 == strlen( EIPM_ALARM_DATA_AT( alarmDataP, i, j )->resource ) )
			{
				continue;
			}

			if (j == EIPM_STATE_CHG)
			{
				alarmCauseType = FSAP_stateChange;
			}
			else
			{
				alarmCauseType = FSAP_externalConnectivity;
			}

			
			/*
			 * Class:		Ethernet
			 * Severity:		Clear
			 * Cause/Type:		Ethernet Error
			 * Resource type:	Link
			 * Resource:		Set above.
			 * User-String:		Not Applicable
			 * Description Type:	Unused (as specified in API)
			 * Recovery Type:	Unused (as specified in API)
			 */
			SEND_ALARM( FSAC_ethernet,
			            FSAS_cleared,
			            alarmCauseType,
			            FSAR_link,
				    EIPM_ALARM_DATA_AT( alarmDataP, i, j )->resource,
			            (char *)NULL,
			            (char *)NULL,
			            FSADK_UNUSED,
			            FSADK_UNUSED );

			LOG_FORCE(0, "Alarm: FSAC_ethernet FSAP_externalConnectivity FSAR_link. Severity clear\nResource: %s\n",
                    EIPM_ALARM_DATA_AT( alarmDataP, i, j )->resource);

		
			/*
			 * Clear alarm tracking data.
			 */
			EIPM_ALARM_DATA_AT( alarmDataP, i, j )->alarm_sent   = FALSE;
			EIPM_ALARM_DATA_AT( alarmDataP, i, j )->count        = 0;
			EIPM_ALARM_DATA_AT( alarmDataP, i, j )->severity     = FSAS_cleared;
			EIPM_ALARM_DATA_AT( alarmDataP, i, j )->user_text[0] = '\0';
			EIPM_ALARM_DATA_AT( alarmDataP, i, j )->file         = __FILE__;
			EIPM_ALARM_DATA_AT( alarmDataP, i, j )->line         = __LINE__;

		} /* end 'for loop on all alarm status' */
	
	} /* end 'for loop on all subnet index' */

	if (alarm_index == EIPM_MAX_ALARM)
	{
		EIPM_CLEAR_IP_ALARM(data_ptr,subnet_index,EIPM_MAX_IPS,alarm_index);
	}

	EIPM_send_status( data_ptr );
	
} /* end EIPM_clear_alarms() */

/**********************************************************************
 *
 * Name:	EIPM_clear_ip_alarms()
 *
 * Abstract:	Communication has been successfully restored.
 * 		Clear all IP granularity alarms for this interface.
 *
 * Parameters:	data_ptr - pointer to data for this interface.
 *		subnet_index - index to subnet.
 *		ip_index - index to IP.
 *		alarm_index - index to EIPM alarm type.
 *		del - delete the entry
 *
 * Returns:	None
 *
 **********************************************************************/

void
EIPM_clear_ip_alarms( EIPM_INTF *data_ptr, int subnet_index, int ip_index, EIPM_ALARM_LIST alarm_index, bool del )
{
	EIPM_INTF_SPEC		*intfSpecDataP;
	EIPM_IP_ALARM_DATA	*ip_alarm_data_ptr;
	EIPM_ALARM_DATA		*alarm_ptr;

	int i;
	int j;

	int	loop_idx;
	int	ip_key = 0;		/* key in array is ip_index + 1 */
	int	found_idx = -1;
	
	intfSpecDataP = &(data_ptr->specData);

	if ( !EIPM_REPORT( intfSpecDataP ) )
	{
		return;
	}

	if( ip_index != EIPM_MAX_IPS )
	{
		ip_key = ip_index + 1;

		for ( loop_idx=0;
		      (loop_idx < EIPM_MAX_IP_ALARMS) && (found_idx == -1);
		      loop_idx++ )
		{
			ip_alarm_data_ptr = &(data_ptr->ip_alarm[subnet_index][loop_idx]);
	
			if (ip_alarm_data_ptr->ip_key == ip_key)
			{
				/* Found the slot we're using for
				 * this IP address.
				 */
				found_idx = loop_idx;
			}
		}
	
		if (found_idx == -1)
		{
			return;
		}
	}

	/*
	 * Loop on all of the possible alarms we can send and
	 * send a clear if an alarm was raised.
	 */
	for( i = 0; i < EIPM_MAX_SUBNETS; i++ )
	{
	    for( j = 0; j < EIPM_MAX_IP_ALARMS; j++ )
	    {
		ip_alarm_data_ptr = &(data_ptr->ip_alarm[i][j]);
		alarm_ptr = &(ip_alarm_data_ptr->alarm_data);


		if( (subnet_index != EIPM_MAX_SUBNETS) && (subnet_index != i) )
		{
			/* if the subnet is not what we care, goto next */
			continue;
		}

		if( (ip_index != EIPM_MAX_IPS) && (found_idx != j) )
		{
                        /* if the IP is not what we care, goto next */
                        continue;
		}

		/*
		 * See if alarm was generated.
		 */
		if( (alarm_ptr->alarm_sent == TRUE) &&
		    (strlen(alarm_ptr->resource) > 0) )
		{

			/*
			 * Class:		Ethernet
			 * Severity:		Clear
			 * Cause/Type:		Ethernet Error
			 * Resource type:	Link
			 * Resource:		Set above.
			 * User-String:		Not Applicable
			 * Description Type:	Unused (as specified in API)
			 * Recovery Type:	Unused (as specified in API)
			 */
			SEND_ALARM( FSAC_ethernet,
			            FSAS_cleared,
			            FSAP_externalConnectivity,
			            FSAR_link,
				    alarm_ptr->resource,
			            (char *)NULL,
			            (char *)NULL,
			            FSADK_UNUSED,
			            FSADK_UNUSED );

		}
	
		/*
		 * Clear alarm tracking data.
		 */
		alarm_ptr->alarm_sent	= FALSE;
		alarm_ptr->count	= 0;
		alarm_ptr->threshold	= 0;
		alarm_ptr->severity	= FSAS_cleared;
		alarm_ptr->user_text[0]	= '\0';
		alarm_ptr->file		= __FILE__;
		alarm_ptr->line		= __LINE__;

		if (del == TRUE)
		{
			/*
			 * Fill in the deleted alarm space by copying any
			 * remaining alarms.  In addition since ip index
			 * is changing so is ip key, so re-number after copying.
			 */
                        for( loop_idx = j;
                             loop_idx < EIPM_MAX_IP_ALARMS - 1;
                             loop_idx++ )
                        {
				memcpy(&(data_ptr->ip_alarm[i][loop_idx]), 
				       &(data_ptr->ip_alarm[i][loop_idx+1]),
					sizeof(data_ptr->ip_alarm[0][0]));

				if (data_ptr->ip_alarm[i][loop_idx].ip_key > ip_key)
				{
					data_ptr->ip_alarm[i][loop_idx].ip_key--;
				}
                        }			

			data_ptr->ip_alarm[i][EIPM_MAX_IP_ALARMS-1].ip_key = 0;

			memset(&(data_ptr->ip_alarm[i][EIPM_MAX_IP_ALARMS-1].alarm_data),
			       0,
			       sizeof(data_ptr->ip_alarm[0][0].alarm_data));
		}

	    } /* end 'for loop on all ip index' */
	
	} /* end 'for loop on all subnet index' */

	if (ip_index != EIPM_MAX_IPS)
	{
		/* This function should report status. */
		EIPM_send_status( data_ptr );
	}
	
} /* end EIPM_clear_ip_alarms() */

/**********************************************************************
 *
 * Name:	EIPM_report_alarms()
 *
 * Abstract:	Based on alarm data, send alarm reports/clears
 *
 * Parameters:	None
 *
 * Returns:	None
 *
 **********************************************************************/

void
EIPM_report_alarms()
{
EIPM_DATA *data_ptr = (EIPM_DATA *)EIPM_shm_ptr;
EIPM_INTF *intf_ptr = &data_ptr->intf_data[0];
EIPM_ALARM_DATA *alarm_ptr;
int intf_idx;
int subnet_index;
int alarm_index;

    for( intf_idx = 0; intf_idx < data_ptr->intf_cnt; intf_idx++, intf_ptr++ )
    {
	if( !EIPM_REPORT( &(intf_ptr->specData) ) )
	{
		continue;
	}

	for( subnet_index = 0; subnet_index < EIPM_MAX_SUBNETS; subnet_index++ )
	{
		for( alarm_index = 0; alarm_index < (int)EIPM_MAX_ALARM; alarm_index++ )
		{
		    alarm_ptr = &intf_ptr->specData.alarm[subnet_index][alarm_index];

	            if( strlen(alarm_ptr->resource) == 0 )
	            {
	                continue;
	            }

	            SEND_ALARM1( FSAC_ethernet,
	                         alarm_ptr->severity,
	                         FSAP_externalConnectivity,
	                         FSAR_link,
	                         alarm_ptr->resource,
	                         (char *)NULL,
	                         alarm_ptr->user_text,
	                         FSADK_UNUSED,
	                         FSADK_UNUSED,
	                         alarm_ptr->file,
	                         alarm_ptr->line );

		} /* end 'for loop on all alarm status' */

	} /* end 'for loop on subnet index alarm status' */

    } /* end 'for loop on all interfaces' */

    EIPM_report_ip_alarms();
	
} /* end EIPM_report_alarms() */


/**********************************************************************
 *
 * Name:	EIPM_report_ip_alarms()
 *
 * Abstract:	Based on alarm data, send alarm reports/clears
 *		for IP granularity alarms.
 *
 * Parameters:	None
 *
 * Returns:	None
 *
 **********************************************************************/

void
EIPM_report_ip_alarms()
{
EIPM_DATA *data_ptr = (EIPM_DATA *)EIPM_shm_ptr;
EIPM_INTF *intf_ptr = &data_ptr->intf_data[0];
EIPM_IP_ALARM_DATA *ip_alarm_data_ptr;
EIPM_ALARM_DATA *alarm_ptr;
int intf_idx;
int subnet_index;
int loop_idx;

    for( intf_idx = 0; intf_idx < data_ptr->intf_cnt; intf_idx++, intf_ptr++ )
    {
	if( !EIPM_REPORT( &(intf_ptr->specData) ) )
	{
		continue;
	}

	for( subnet_index = 0; subnet_index < EIPM_MAX_SUBNETS; subnet_index++ )
	{

	    for( loop_idx = 0; loop_idx < EIPM_MAX_IP_ALARMS; loop_idx++ )
	    {

		ip_alarm_data_ptr = &(intf_ptr->ip_alarm[subnet_index][loop_idx]);
		alarm_ptr = &(ip_alarm_data_ptr->alarm_data);

	        if ( strlen(alarm_ptr->resource) > 0 &&
		     ip_alarm_data_ptr->ip_key != 0 )
	        {

		    LOG_OTHER( 0, "EIPM_report_ip_alarms() reporting intf_idx %d, subnet_idx %d, ip_key %d\n", intf_idx, subnet_index, ip_alarm_data_ptr->ip_key );

	            SEND_ALARM1( FSAC_ethernet,
	                         alarm_ptr->severity,
	                         FSAP_externalConnectivity,
	                         FSAR_link,
	                         alarm_ptr->resource,
	                         (char *)NULL,
	                         alarm_ptr->user_text,
	                         FSADK_UNUSED,
	                         FSADK_UNUSED,
	                         alarm_ptr->file,
	                         alarm_ptr->line );

		}

	    } /* end 'for loop on IP index' */

	} /* end 'for loop on subnet index' */

    } /* end 'for loop on all interfaces' */
	
} /* end EIPM_report_ip_alarms() */



/**********************************************************************
 *
 * Name:	EIPM_recovery()
 *
 * Abstract:	Attempt to recover from run-time errors.
 *
 * Parameters:	rec_type  - type of error to recover from
 *		data_ptr  - pointer to data for this interface
 *		userdata1 - Data based on recovery needed
 *		userdata2 - Data based on recovery needed
 *		userptr1  - Pointer to data based on recovery needed
 *		userptr2  - Pointer to data based on recovery needed
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int EIPM_recovery( EIPM_RECOVERY rec_type,
		   EIPM_INTF *data_ptr,
		   int userdata1,
		   int userdata2,
		   void *userptr1,
		   void *userptr2 )
{
	
	int retval;
	
	switch( rec_type )
	{
	
	default:
		/*
		 * Either we were called with an unknown recovery
		 * type, or we haven't written the code for some
		 * case yet.  Assume failure.
		 */
		return( IPM_FAILURE );
		
	} /* end 'switch on recovery type' */
	
	return( IPM_SUCCESS );
	
} /* end EIPM_recovery() */




/**********************************************************************
 *
 * Name:	ipcksm()
 *
 * Abstract:	Compute checksums for IP packets.
 *
 * Parameters:	msg_ptr - pointer to data to be checksummed
 *		length  - size of data to be checksummed.
 *
 * Returns:	checksum
 *
 **********************************************************************/


#define ADDCARRY(x) ((x > 0xffff) ? (x & 0xffff)+1 : x)

unsigned short
ipcksm( unsigned short *msg_ptr, unsigned short length )
{
	register unsigned short *ptr;           /* Ptr to the message. */
	register unsigned long  sum;            /* Checksum value */
	register unsigned short num_shorts;     /* Number of shorts */
	
	sum = 0;
	
	/* Length was passed to us as the number of bytes
	 * we need number of shorts
	 */
	num_shorts = length >> 1;
	
	/* Loop through the message and calculate the checksum.
	 */
	for( ptr = msg_ptr; ptr < msg_ptr + num_shorts; ptr++ )
	{
		        sum += *ptr;
		        sum =  ADDCARRY( sum );
		}
	
	/* If the number of bytes requested is odd we need to
	 * process the last byte.
	 */
	if( (length & 1) != 0 )
	{
		        /* Length is odd.  Add the high byte of the next
		         * short to the checksum and then adjust again.
		         */
		        sum += (*ptr & 0xff00);
		        sum  = ADDCARRY( sum );
		}
	
	/* Return the calculated value of the checksum.
	 */
	return( (unsigned short) ~sum );
	
} /* End of ipcksm() */


/**********************************************************************
 *
 * Name:	ipv6cksm()
 *
 * Abstract:	Compute checksums for IPv6 packets.
 *
 * Parameters:	msg_ptr - pointer to data to be checksummed
 *		length  - size of data to be checksummed.
 *
 * Returns:	checksum
 *
 **********************************************************************/

u_int16_t ipv6cksm(void* buffer, int size, u_int8_t nxt, u_int32_t len )
{
   int sum = 0;
   int i;
   unsigned short *ptr = buffer;

        union {
                u_int16_t phs[4];
                struct {
	                      u_int32_t       ph_len;
			      u_int8_t        ph_zero[3];
			      u_int8_t        ph_nxt;
			} ph __attribute__((packed));
		 } uph;

         memset(&uph, 0, sizeof(uph));

        uph.ph.ph_len = htonl(len);
        uph.ph.ph_nxt = nxt;

        /* Payload length and upper layer identifier */
	for(i=0;i< 4; i++)
	{
	         sum += uph.phs[i];  
		 sum = ADDCARRY(sum);
	}
   while (size > 1)
   {
      sum += *ptr++;
      sum = ADDCARRY(sum);
    size -= 2;
   }
   if (size > 0)
   {
      sum += *(unsigned char *)ptr;
      sum = ADDCARRY(sum);
   }

   return(~sum & 0xffff );
}


/**********************************************************************
 *
 * Name:	EIPM_get_solicited_node_multicast_addr()
 *
 * Abstract:	Calculate the IPv6 solicited node multicast address
 *
 * Parameters:	target - target IPv6 address
 *		snma  - pointer to snma that will be calculated
 *
 * Returns:	pointer to snma
 *
 **********************************************************************/

struct in6_addr *EIPM_get_solicited_node_multicast_addr(struct in6_addr target, struct in6_addr *snma_ptr)
{
	int i;
	inet_pton(AF_INET6, "FF02::1:FF00:00", (char *)snma_ptr);
	for (i = 13; i < 16; i++)
	{
		snma_ptr->s6_addr[i] |= target.s6_addr[i];
	}
	return snma_ptr;
}



/**********************************************************************
 *
 * Name:	EIPM_check_sysctl_parameters()
 *
 * Abstract:	Check sysctl settings on the interface, update if needed
 *
 * Parameters:	intf_ptr - EIPM Interface data pointer
 *
 * Returns:	SUCCES, FAILURE
 *
 **********************************************************************/

void 
EIPM_check_sysctl_parameters( void *intfDataP, EIPM_INTF_TYPE intfType )
{
EIPM_INTF *intf_ptr;
EIPM_INTF_SPEC *intfSpecDataP;
EIPM_SUBNET *subnet_ptr;
int subnet_idx;
bool ipv4_present = FALSE;
bool ipv6_present = FALSE;
bool lsn0_iface_present = FALSE;
bool lsn1_iface_present = FALSE;
bool proxy_server_present = FALSE;
char lsn0_IntfName[MAX_NLEN_DEV];
char lsn1_IntfName[MAX_NLEN_DEV];

    EIPM_SET_INTF_PTRS( intfDataP, intfType, intf_ptr, intfSpecDataP );

    if ( NULL == intf_ptr )
    {
        return;
    }

    snprintf( lsn0_IntfName, MAX_NLEN_DEV, "%s%s",
              intf_ptr->lsn0_baseif, ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
    snprintf( lsn1_IntfName, MAX_NLEN_DEV, "%s%s",
              intf_ptr->lsn1_baseif, ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

    if( intf_ptr->lsn0_baseif[0] != 0 &&
        strlen(intf_ptr->lsn0_baseif) != 0 )
    {
	lsn0_iface_present = TRUE;
    }

    if( intf_ptr->lsn1_baseif[0] != 0 &&
        strlen(intf_ptr->lsn1_baseif) != 0 )
    {
	lsn1_iface_present = TRUE;
    }

    for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
         subnet_idx < intf_ptr->subnet_cnt;
         subnet_idx++, subnet_ptr++ )
    {
        EIPM_IPDATA *ip_ptr;
        int ip_idx;

        for( ip_idx = 0, ip_ptr = &subnet_ptr->ips[0];
             ip_idx < subnet_ptr->ip_cnt;
             ip_idx++, ip_ptr++ )
        {
            if( ip_ptr->ipaddr.addrtype == IPM_IPV4 )
            {
                ipv4_present = TRUE;
            }
            else if( ip_ptr->ipaddr.addrtype == IPM_IPV6 )
            {
                ipv6_present = TRUE;
            }

            if( ip_ptr->type == EIPM_IP_PROXY_SERVER )
            {
                proxy_server_present = TRUE;
            }
            
            if( ipv4_present == TRUE &&
                ipv6_present == TRUE &&
                proxy_server_present == TRUE )
            {
                ip_idx = subnet_ptr->ip_cnt;
                subnet_idx = intf_ptr->subnet_cnt;
            }
        }
    }

    if( ipv4_present == TRUE && 
        lsn0_iface_present == TRUE )
    {
	if (    ( intfSpecDataP->status == EIPM_ONLINE )
             && ( intfSpecDataP->preferred_side == LSN1 ) )
        {
	    if( EIPM_check_sysctl_value( lsn0_IntfName, "ipv4", "arp_ignore", 8) != IPM_SUCCESS )
            {
                LOG_ERROR( 0,
                           "EIPM_check_sysctl_parameters: Incorrect arp_ignore Parameter Value on interface %s\n",
                            lsn0_IntfName );

		(void)EIPM_set_sysctl_value(lsn0_IntfName, "ipv4", "arp_ignore", 8);
            }
        }
	else if ( ( intf_ptr->specData.preferred_side == LSN1 )
	     && ( intf_ptr->specData.monitor == EIPM_MONITOR_NULL ) )
	{
            if( EIPM_check_sysctl_value(intf_ptr->lsn1_baseif, "ipv4", "arp_ignore", 1) != IPM_SUCCESS )
	    {
                LOG_ERROR( 0,
                           "EIPM_check_sysctl_parameters: Incorrect arp_ignore Parameter Value on interface %s\n",
                            intf_ptr->lsn1_baseif );

                (void)EIPM_set_sysctl_value(intf_ptr->lsn1_baseif, "ipv4", "arp_ignore", 1);
	    }
	}
        else
        {
	    if( EIPM_check_sysctl_value(lsn0_IntfName, "ipv4", "arp_ignore", 1) != IPM_SUCCESS )
            {
                LOG_ERROR( 0,
                           "EIPM_check_sysctl_parameters: Incorrect arp_ignore Parameter Value on interface %s\n",
                            lsn0_IntfName );

                (void)EIPM_set_sysctl_value(lsn0_IntfName, "ipv4", "arp_ignore", 1);
            }
        }

        if( proxy_server_present == TRUE )
        {
	    if( EIPM_check_sysctl_value(lsn0_IntfName, "ipv4", "forwarding", 1) != IPM_SUCCESS && EIPM_GET_PROXY_SERVER_ENABLED() == TRUE)
            {
                LOG_ERROR( 0,
                           "EIPM_check_sysctl_parameters: Incorrect IPv4 forwarding Parameter Value on interface %s\n",
                            lsn0_IntfName );

                (void)EIPM_set_sysctl_value(lsn0_IntfName, "ipv4", "forwarding", 1);
            }
            else if (EIPM_GET_PROXY_SERVER_ENABLED() == FALSE && EIPM_check_sysctl_value(lsn0_IntfName, "ipv4", "forwarding", 1) == IPM_SUCCESS)
            {
                (void)EIPM_set_sysctl_value(lsn0_IntfName, "ipv4", "forwarding", 0);
            }
        }
    }

    if( ipv6_present == TRUE &&
        lsn0_iface_present == TRUE )
    {
	if( EIPM_check_sysctl_value(lsn0_IntfName, "ipv6", "dad_transmits", 0) != IPM_SUCCESS )
        {
            LOG_ERROR( 0,
                       "EIPM_check_sysctl_parameters: Incorrect dad_transmits Parameter Value on interface %s\n",
                        lsn0_IntfName );

            (void)EIPM_set_sysctl_value(lsn0_IntfName, "ipv6", "dad_transmits", 0);
        }

	if( EIPM_check_sysctl_value(lsn0_IntfName, "ipv6", "accept_dad", 0) != IPM_SUCCESS )
        {
            LOG_ERROR( 0,
                       "EIPM_check_sysctl_parameters: Incorrect accept_dad Parameter Value on interface %s\n",
                        lsn0_IntfName );

            (void)EIPM_set_sysctl_value(lsn0_IntfName, "ipv6", "accept_dad", 0);
        }

        if( proxy_server_present == TRUE )
        {
	    if( EIPM_check_sysctl_value(lsn0_IntfName, "ipv6", "forwarding", 1) != IPM_SUCCESS && EIPM_GET_PROXY_SERVER_ENABLED() == TRUE)
            {
                LOG_ERROR( 0,
                           "EIPM_check_sysctl_parameters: Incorrect IPv6 forwarding Parameter Value on interface %s\n",
                            lsn0_IntfName );

                (void)EIPM_set_sysctl_value(lsn0_IntfName, "ipv6", "forwarding", 1);
            }
            else if (EIPM_GET_PROXY_SERVER_ENABLED() == FALSE && EIPM_check_sysctl_value(lsn0_IntfName, "ipv6", "forwarding", 1) == IPM_SUCCESS)
            {
                (void)EIPM_set_sysctl_value(lsn0_IntfName, "ipv6", "forwarding", 0);
            }

            if( EIPM_check_sysctl_value(lsn0_IntfName, "ipv6", "proxy_ndp", 1) != IPM_SUCCESS && EIPM_GET_PROXY_SERVER_ENABLED() == TRUE)
            {
                LOG_ERROR( 0,
                           "EIPM_check_sysctl_parameters: Incorrect IPv6 proxy ndp Parameter Value on interface %s\n",
                            lsn0_IntfName );

                (void)EIPM_set_sysctl_value(lsn0_IntfName, "ipv6", "proxy_ndp", 1);
            }
            else if (EIPM_GET_PROXY_SERVER_ENABLED() == FALSE && EIPM_check_sysctl_value(lsn0_IntfName, "ipv6", "proxy_ndp", 1) == IPM_SUCCESS)
            {
                (void)EIPM_set_sysctl_value(lsn0_IntfName, "ipv6", "proxy_ndp", 0);
            }
        }
    }

    if( ipv4_present == TRUE &&
        lsn1_iface_present == TRUE )
    {
	(void)EIPM_set_sysctl_value(lsn1_IntfName, "ipv4", "arp_ignore", 1);

        if( proxy_server_present == TRUE && EIPM_GET_PROXY_SERVER_ENABLED() == TRUE)
        {
            (void)EIPM_set_sysctl_value(lsn1_IntfName, "ipv4", "forwarding", 1);
        }
        else if ( proxy_server_present == TRUE && EIPM_GET_PROXY_SERVER_ENABLED() == FALSE)
        {
            (void)EIPM_set_sysctl_value(lsn1_IntfName, "ipv4", "forwarding", 0);
        }
    }

    if( ipv6_present == TRUE &&
        lsn1_iface_present == TRUE )
    {
	(void)EIPM_set_sysctl_value(lsn1_IntfName, "ipv6", "dad_transmits", 0);

	(void)EIPM_set_sysctl_value(lsn1_IntfName, "ipv6", "accept_dad", 0);

        if( proxy_server_present == TRUE && EIPM_GET_PROXY_SERVER_ENABLED() == TRUE)
        {
            (void)EIPM_set_sysctl_value(lsn1_IntfName, "ipv6", "forwarding", 1);

            (void)EIPM_set_sysctl_value(lsn1_IntfName, "ipv6", "proxy_ndp", 1);
        }
        else if (proxy_server_present == TRUE && EIPM_GET_PROXY_SERVER_ENABLED() == FALSE)
        {
            (void)EIPM_set_sysctl_value(lsn1_IntfName, "ipv6", "forwarding", 0);

            (void)EIPM_set_sysctl_value(lsn1_IntfName, "ipv6", "proxy_ndp", 0);
        }
    }

    return;
}


/**********************************************************************
 *
 * Name:	EIPM_check_sysctl_value()
 *
 * Abstract:	Check sysctl parameter for given value on interface
 *
 * Parameters:	interface - interface to check
 *              iptype    - "ipv4" or "ipv6"
 *              parameter - parameter to check
 *              value     - value to check
 *
 * Returns:	SUCCES  - parameter is equal to value
 *              FAILURE - parameter is not equal to value
 *
 **********************************************************************/

int
EIPM_check_sysctl_value( char *interface, char *iptype, char *parameter, int value )
{
FILE *fp;
int file_value;
char file_name[256];
int retval;

    if ((interface == NULL) || (interface[0] == '\0'))
    {
        return IPM_FAILURE;
    }

    sprintf(file_name, 
            "/proc/sys/net/%s/conf/%s/%s", iptype, interface, parameter);

    fp = fopen(file_name, "r");

    if( fp == NULL )
    {
        return IPM_FAILURE;
    }

    file_value = fgetc(fp);

    fclose(fp);

    if( file_value == EOF )
    {
        return IPM_FAILURE;
    }

    if( value != (file_value - '0') )
    {
        return IPM_FAILURE;
    }

    return IPM_SUCCESS;
}


/**********************************************************************
 *
 * Name:	EIPM_set_sysctl_value()
 *
 * Abstract:	Set sysctl parameter to given value on interface
 *
 * Parameters:	interface - interface to set parameter for
 *              iptype    - "ipv4" or "ipv6"
 *              parameter - parameter to set
 *              value     - value to set
 *
 * Returns:	SUCCES  - parameter was set to value
 *              FAILURE - parameter was not set to value
 *
 **********************************************************************/

int
EIPM_set_sysctl_value( char *interface, char *iptype, char *parameter, int value )
{
FILE *fp;
int ret;
char file_name[256];
int retval;

    if ((interface == NULL) || (interface[0] == '\0'))
    {
        return IPM_FAILURE;
    }

    sprintf(file_name, 
            "/proc/sys/net/%s/conf/%s/%s", iptype, interface, parameter);

    fp = fopen(file_name, "w");

    if( fp == NULL )
    {
        return IPM_FAILURE;
    }

    ret = fputc(value + '0', fp);

    fclose(fp);

    if( ret == EOF )
    {
        ASRT_RPT( ASUNEXP_RETURN,
                  0,
                  "EIPM_set_sysctl_value: failure %c to %s\n",
                   value + '0', file_name );

        return IPM_FAILURE;
    }

    return IPM_SUCCESS;
}
/**********************************************************************
 *
 * Name:	EIPM_send_neighbor_solicitation()
 *
 * Abstract:	send neighbor solicitation to the solicited-node multicast address to request link layer address of target address
 *
 * Parameters:	ns_sock   - ICMPv6 socket fd
 *              ifindex   - interface index
 *              hw_addr   - local link layer address
 *              gateway   - gateway address
 *              source    - source address
 *
 * Returns:	SUCCES  - send neighbor solicitation successfully 
 *              FAILURE - fail to send neighbor solicitation
 *
 **********************************************************************/
int EIPM_send_neighbor_solicitation( int *ns_sock, int ifindex, char *ifname, char *hw_addr, IPM_IPADDR *gateway, IPM_IPADDR *source )
{
	struct ifreq		ifr;
	struct arp6_pkt		arp6;
	struct in6_addr		ip6;
	struct sockaddr_in6	whereto;
	struct in6_pktinfo	pktinfo;	
	struct msghdr 		msg;
	struct icmp6_filter 	filter;
	struct sockaddr_in6	saddr;
	int 			hoplimit = 255;
	int			on = 1;
	char 			pktbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	struct cmsghdr 		*cmptr;
	struct iovec 		iov[1];
	struct in6_pktinfo 	*pktinfo_ptr;
	unsigned char		hw_addr_buf[ETH_ALEN];
	unsigned char		*hw_addr_ptr = NULL;
	char 			ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
	bool			close_ns_sock = FALSE;
	int			sock;
	int			ns_sock_ptr;
	int			tmp_ns_sock = -1;
	int			retval;

	/*
	 * Send a neighbor solicitation for only IPv6 gateway addresses. 
	 */
	if( gateway->addrtype != IPM_IPV6 )
	{
		return IPM_SUCCESS;
	}

	/*
	 * Determine if the interface index and mac address have been provided.  If not,
	 * read them from the OS.
	 */
	if(( hw_addr == NULL ) ||
	   ( ifindex == 0 ))
	{
		/* Querying interface information.  */
		sock = socket(PF_INET, SOCK_RAW, htons(ETH_P_IP));

		if( sock < 0 )
		{
			 LOG_ERROR(0,
		  		   "Error: EIPM_send_neighbor_solicitation - Failed to open raw socket for interface=%s, errno %d",
				  ifname, errno );

			return IPM_FAILURE;
		}

		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_addr.sa_family = PF_INET;
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

		if( ifindex == 0 )
		{
			retval = ioctl(sock, SIOCGIFINDEX, &ifr);

			if( retval < 0 )
			{

				 LOG_ERROR(0,
					  "Error: EIPM_send_neighbor_solicitation - ioctl(SIOCGIFINDEX) failed for interface=%s, retval %d, errno %d",
					  ifname, retval, errno );

			        (void)close(sock);

			        return IPM_FAILURE;
			}

			ifindex = ifr.ifr_ifindex;
		}

		if( hw_addr == NULL )
		{
			ifr.ifr_ifindex = ifindex;
	
			/*
			 * Get MAC address
			 */
			retval = ioctl(sock, SIOCGIFHWADDR, &ifr);

			if( retval < 0 )
			{
				LOG_ERROR( 0,
			  		   "Error: EIPM_send_neighbor_solicitation ioctl(SIOCGIFHWADDR) failed for interface=%s, retval %d, errno %d",
					   ifname, retval, errno );
	
				(void)close(sock);

				return IPM_FAILURE;
			}

			hw_addr_ptr = &hw_addr_buf[0];

			/*
			 * Store MAC address.  
			 */
			memcpy( hw_addr_ptr,
			        ifr.ifr_ifru.ifru_hwaddr.sa_data,
			        ETH_ALEN );
		}
		else
		{
			hw_addr_ptr = hw_addr;			
		}

		(void)close(sock);
	}
	else
	{
		hw_addr_ptr = hw_addr;			
	}

	/*
	 * Determine if an ICMPV6 socket has been provided.  If not, setup one.
	 */
	if(( ns_sock == NULL ) ||
	   ( *ns_sock <= 0 ))
	{
		if( ns_sock == NULL )
		{
			close_ns_sock = TRUE;
		}
		else
		{
			close_ns_sock = FALSE;
		}

		/* 
		 * Create a ns_socket for sending IPv6 Neighbor Soliciation Messages.
		 */
		tmp_ns_sock =
			socket( PF_INET6, SOCK_RAW, IPPROTO_ICMPV6 );

		if( tmp_ns_sock < 0 )
		{
			LOG_ERROR( 0,
			       	 "Error: EIPM_send_neighbor_solicitation - creating ns_socket failed\nretval=%d, errno=0x%x\n",
				 tmp_ns_sock, errno );
			
			return( IPM_FAILURE );
		}
		else
		{
			LOG_OTHER( 0,
			       	 "EIPM_send_neighbor_solicitation - creating ns_socket\nretval=%d\n",
				 tmp_ns_sock );
		}							

		hoplimit = 255;
		retval = setsockopt( tmp_ns_sock, SOL_IPV6, IPV6_MULTICAST_HOPS,
				     &hoplimit, sizeof(hoplimit) );

		if( retval < 0 )
		{
			LOG_ERROR( 0,
			     	 "Error: EIPM_send_neighbor_solicitation - Set hoplimit failed, ret=0x%x, errno=0x%x\n",
			         retval, errno );
		
			(void)close( tmp_ns_sock );

			return( IPM_FAILURE );
		}

		retval = setsockopt( tmp_ns_sock, SOL_IPV6, IPV6_MULTICAST_IF,
				     &ifindex, sizeof(ifindex) );
		if( retval < 0 )
		{
			LOG_ERROR( 0,
			     	 "Error: EIPM_send_neighbor_solicitation - Set multicast interface failed, ifindex=%d ret=0x%x, errno=0x%x\n",
			         ifindex, retval, errno );
	
			(void)close( tmp_ns_sock );

			return( IPM_FAILURE );
		}	

		retval = setsockopt( tmp_ns_sock, SOL_IPV6, IPV6_RECVPKTINFO,
				     &on, sizeof(on) );

		if( retval < 0 )
		{
			LOG_ERROR( 0,
			     	 "Error: EIPM_send_neighbor_solicitation - Set recvpktinfo failed, ret=0x%x, errno=0x%x\n",
			         retval, errno );
		
			close( tmp_ns_sock );

			return( IPM_FAILURE );
		}

		/*
		 * Miminize the packets received on the socket by setting up
		 * a filter to pass only neighbor advertisements.
		 */
		ICMP6_FILTER_SETBLOCKALL(&filter);
		ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &filter);

		retval = setsockopt( tmp_ns_sock, SOL_ICMPV6, ICMP6_FILTER, 
				     &filter, sizeof(filter) ); 
		if( retval < 0 ) 
		{
			LOG_ERROR( 0,
			     	 "Error: EIPM_send_neighbor_solicitation - Set filter failed, ifindex=%d ret=0x%x, errno=0x%x\n",
			         ifindex, retval, errno );
		
			close( tmp_ns_sock );
	
			return( IPM_FAILURE );
		}
	}
	else
	{
		tmp_ns_sock = *ns_sock;
	}

	/*
	 * Create/send IPv6 "ARP" packet this is neighbor 
	 * solicitation packet.
	 *
	 * Zero out structure and create header.
	 */
	memset( &arp6, 0, sizeof(struct arp6_pkt) );
	
	arp6.na.nd_na_type = ND_NEIGHBOR_SOLICIT;
	arp6.na.nd_na_code = 0;
	arp6.na.nd_na_cksum = 0;
	
	/*
	 * Fill in the target address
	 */
	IPM_ipaddr2in( gateway, &(arp6.na.nd_na_target) );

	arp6.opt_hdr.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	arp6.opt_hdr.nd_opt_len = (ETH_ALEN + sizeof(struct nd_opt_hdr))/8;

	memcpy( &(arp6.hw_addr), (hw_addr_ptr), ETH_ALEN);

	memset( &whereto, 0, sizeof(whereto) );
	whereto.sin6_family = AF_INET6;
	whereto.sin6_port = 0;

	EIPM_get_solicited_node_multicast_addr( arp6.na.nd_na_target, &whereto.sin6_addr);

	/*
	 * Set up the structures to use sendmsg.
	 */
	msg.msg_name = &whereto;
	msg.msg_namelen = sizeof(whereto);
	iov[0].iov_base = &arp6;
	iov[0].iov_len = sizeof( struct arp6_pkt );
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	
	msg.msg_control = pktbuf;
	msg.msg_controllen = sizeof(pktbuf);
	cmptr = CMSG_FIRSTHDR(&msg);
	cmptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	cmptr->cmsg_level = IPPROTO_IPV6;

	/*
	 * Fill in the IPV6_PKTINFO structure this allows us to
	 * specifiy the source address and interface when sending
	 * the neighbor solication packet.
	 */
	cmptr->cmsg_type = IPV6_PKTINFO;
	pktinfo_ptr = (struct in6_pktinfo *) CMSG_DATA(cmptr);

	pktinfo_ptr->ipi6_ifindex = ifindex;
	if( source != NULL )
	{
		IPM_ipaddr2in( source, &(pktinfo_ptr->ipi6_addr) );
	}
	else
	{
		pktinfo_ptr->ipi6_addr = in6addr_any;
	}

	if( tmp_ns_sock < 0 )
	{
		LOG_ERROR( 0,
			"Error: EIPM_send_neighbor_solicitation - sending NS request failed - no socket tmp_ns_sock=%d, ifindex=%d\n",
			 tmp_ns_sock,
			 ifindex
			 );

		return( IPM_FAILURE );
	}

	retval = sendmsg( tmp_ns_sock, &msg, 0 );

	if( retval < 0 )
	{
		LOG_ERROR( 0,
		       	 "Error: EIPM_send_neighbor_solicitation - sending NS request failed - retval=%d\nerrno=%d, tmp_ns_sock=%d, ifindex=%d\n",
			 retval,
			 errno,
			 tmp_ns_sock,
			 ifindex
			 );

		(void)close( tmp_ns_sock );
		return( IPM_FAILURE );
	}
		
	if( close_ns_sock == TRUE )
	{
		(void)close( tmp_ns_sock );
	}
	else
	{
		*ns_sock = tmp_ns_sock;
	}

	LOG_OTHER( 0,
	       	 "EIPM_send_neighbor_solicitation - Sent NS to %s iface=%s\n",
		 IPM_ipaddr2p(gateway, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
		 ifname );
		
 	return( IPM_SUCCESS );
}


/**********************************************************************
 *
 * Name:	EIPM_get_intf_to_nexthop()
 *
 * Abstract:	get the interface to use to reach the next hop
 *
 * Parameters:	iface0_base_ptr   	  - interface 0
 *              iface1_base_ptr		  - interface 1
 *              nexthop_ip_ptr		  - next hop ip
 *		act_intf_ptr		  - pointer to store active interface
 *
 * Returns:	IPM_FAILURE
 *              IPM_SUCCESS		  - active interface populated
 *
 **********************************************************************/
int
EIPM_get_intf_to_nexthop( char *iface0_base_ptr, char *iface1_base_ptr, IPM_IPADDR *nexthop_ip_ptr, EIPM_NET *act_intf_ptr, uint16_t vlanId)
{
EIPM_DATA 	*data_ptr;
EIPM_INTF 	*intf_ptr;
EIPM_SUBNET 	*subnet_ptr;
EIPM_ROUTES 	*route_ptr;
EIPM_ARP_ITEM 	*arpitem_ptr;
int 		intf_idx;
int 		subnet_idx;
int 		route_idx;

	/* Check for EIPM memory */
	if( EIPM_shm_ptr == NULL )
	{
		LOG_ERROR(0, "EIPM_get_intf_to_next_hop: Shared memory null\n" );
		return IPM_FAILURE;
	}

	if ( vlanId >= EIPM_MAX_VLANS)
	{
		LOG_ERROR(0, "EIPM_get_intf_to_next_hop: wrong VLAN number :%d\n", vlanId);
		return IPM_FAILURE;
	}
	data_ptr = (EIPM_DATA *)EIPM_shm_ptr;

	/* Look through all interfaces */
	for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
	     intf_idx < data_ptr->intf_cnt;
 	     intf_idx++, intf_ptr++ )
	{
		if( strcmp(intf_ptr->lsn0_baseif, iface0_base_ptr) != 0 ||
		    strcmp(intf_ptr->lsn1_baseif, iface1_base_ptr) != 0 )
        	{
			continue;
		}


		/* Look through all subnets */
		for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
		     subnet_idx < intf_ptr->subnet_cnt;
		     subnet_idx++, subnet_ptr++ )
		{
	                IPM_IPADDR 	subnet_mask;
	                IPM_IPADDR 	nexthop_base;
			int 		ret;

			if( IPM_IPCMPADDRTYPE( &subnet_ptr->subnet_base, nexthop_ip_ptr ) != IPM_SUCCESS )
			{
				continue;
			}

	                IPM_ipaddr_init(&subnet_mask);

	                ret = IPM_ipmkmask(&subnet_mask, 
	                                   subnet_ptr->subnet_base.addrtype, 
	                                   subnet_ptr->prefixlen);

	                if( ret != IPM_SUCCESS )
	                {
				LOG_ERROR(0, "EIPM_get_intf_to_next_hop: Failure %d to create SubnetMask subnet prefix %d\n",
						ret, subnet_ptr->prefixlen);
			
				return IPM_FAILURE;
	                }

	                IPM_ipaddr_init(&nexthop_base);
	                IPM_get_subnet(nexthop_ip_ptr, &subnet_mask, &nexthop_base);

	                if( IPM_IPCMPADDR(&subnet_ptr->subnet_base, &nexthop_base) == IPM_SUCCESS )
			{
				*act_intf_ptr = subnet_ptr->sub2intf_mapping[vlanId].route_priority;
				return IPM_SUCCESS;
			}
		}
	}

	LOG_ERROR(0, "EIPM_get_intf_to_next_hop: failed to find a subnet match\n" );

	return IPM_FAILURE;
}

/**********************************************************************
 *
 * Name:	EIPM_create_arp_socket()
 *
 * Abstract:	create a socket for sending ARPs
 *
 * Parameters:	net   	  - which network LSN0, LSN1
 *              addr_type - IPv4 or IPv6
 *              ifindex   - interface index
 *		arpop	  - arp/nd operation
 *
 * Returns:	-1 	- failure
 *              >= 0 	- valid socket identifier
 *
 **********************************************************************/
int EIPM_create_arp_socket( EIPM_NET net, IPM_IPADDRTYPE addr_type, int ifindex, int arpop )
{
	int 			arp_sock;
	struct icmp6_filter 	filter;
	int 			hoplimit = 255;
	int			on = 1;
	struct sockaddr_ll	haddr;
	int			retval;

	if( net != LSN0  &&
	    net != LSN1 )
	{
		LOG_ERROR( 0,
		       	 "Error: EIPM_create_arp_socket - invalid network=%d\n",
			 net );
		return( -1 );
	}

	if( addr_type == IPM_IPV6 )
	{
	    if( arpop == ND_NEIGHBOR_SOLICIT )
	    {
		/* 
		 * Create a ns_socket for sending IPv6 Neighbor Soliciation Messages.
		 */
		arp_sock =
			socket( PF_INET6, SOCK_RAW, IPPROTO_ICMPV6 );

		if( arp_sock < 0 )
		{
			LOG_ERROR( 0,
			       	 "Error: EIPM_create_arp_socket - creating ns_socket failed\nretval=%d, errno=0x%x\n",
				 arp_sock, errno );
			
			return( -1 );
		}

		hoplimit = 255;
		retval = setsockopt( arp_sock, SOL_IPV6, IPV6_MULTICAST_HOPS,
				     &hoplimit, sizeof(hoplimit) );

		if( retval < 0 )
		{
			LOG_ERROR( 0,
			     	 "Error: EIPM_create_arp_socket - Set hoplimit failed, ret=0x%x, errno=0x%x\n",
			         retval, errno );
		
			close( arp_sock );

			return( -1 );
		}

		retval = setsockopt( arp_sock, SOL_IPV6, IPV6_MULTICAST_IF,
				     &ifindex, sizeof(ifindex) );
		if( retval < 0 )
		{
			LOG_ERROR( 0,
			     	 "Error: EIPM_create_arp_socket - Set multicast interface failed, ifindex=%d ret=0x%x, errno=0x%x\n",
			         ifindex, retval, errno );
	
			close( arp_sock );

			return( -1 );
		}	

		retval = setsockopt( arp_sock, SOL_IPV6, IPV6_RECVPKTINFO,
				     &on, sizeof(on) );

		if( retval < 0 )
		{
			LOG_ERROR( 0,
			     	 "Error: EIPM_create_arp_socket - Set recvpktinfo failed, ret=0x%x, errno=0x%x\n",
			         retval, errno );
		
			close( arp_sock );

			return( -1 );
		}

		/*
		 * Miminize the packets received on the socket by setting up
		 * a filter to pass only neighbor advertisements.
		 */
		ICMP6_FILTER_SETBLOCKALL(&filter);
		ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &filter);

		retval = setsockopt( arp_sock, SOL_ICMPV6, ICMP6_FILTER, 
				     &filter, sizeof(filter) ); 
		if( retval < 0 ) 
		{
			LOG_ERROR( 0,
			     	 "Error: EIPM_create_arp_socket - Set filter failed, ifindex=%d ret=0x%x, errno=0x%x\n",
			         ifindex, retval, errno );
		
			close( arp_sock );
	
			return( -1 );
		}
 	    }
	    else if( arpop == ND_NEIGHBOR_ADVERT )
	    {
		/* Open ICMP socket */
		arp_sock = socket( PF_PACKET, SOCK_RAW, htons(IPPROTO_ICMPV6) );

		if( arp_sock < 0 )
		{
			LOG_ERROR( 0, "socket failed, errno=%d\n", errno);
			return( -1 );
		}	

		/*
	         * Bind socket to the Ethernet device.  only sll_protocol and sll_ifindex are used
	         */
	        memset(&haddr, 0, sizeof(struct sockaddr_ll));
	        haddr.sll_family   = PF_PACKET;
	        haddr.sll_protocol = htons( IPPROTO_ICMPV6 );
		haddr.sll_ifindex = ifindex;	

		retval = bind( arp_sock, (struct sockaddr*)&haddr, sizeof(struct sockaddr_ll) );
		if( retval < 0 )
		{
			/*
			 * Fire an assert.
			 */
			ASRT_RPT( ASUNEXP_RETURN,
			          0,
			       	  "Error: EIPM_sendARP - bind for ipv6 NA socket failed\nretval=%d, errno=0x%x\n",
			          retval, 
				  errno );
				  
			/*
			 * Since we have only used the socket descriptor
			 * in this function don't worry about checking the
			 * return from close().
			 */
			(void)close( arp_sock );
		
			/*
			 * Calling function should raise alarm if appropriate.
			 */
			return -1;
		}
	    }
	    else
	    {
		LOG_ERROR( 0,
		       	 "Error: EIPM_create_arp_socket - invalid arpop=%d\n",
			 arpop );
		return( -1 );
	    }
	}
	else if( addr_type == IPM_IPV4 )
	{
		/*
		 * Create socket per interface for sending ARPs.
		 * We cannot re-use the ping-pong sockets because
		 * the protocol type is not the same.
		 */
		arp_sock =
		        socket( PF_PACKET, SOCK_RAW, htons(ETH_P_ARP) );
		
		if( arp_sock < 0 )
		{
			LOG_ERROR( 0,
			       	 "Error: EIPM_create_arp_socket - creating ARP socket failed\nretval=%d, errno=0x%x\n",
				 arp_sock, errno );
					
			return( -1 );
		}

		/*
		 * Bind socket to the Ethernet device
		 */
		memset(&haddr, 0, sizeof(haddr));
		haddr.sll_family   = PF_PACKET;
		haddr.sll_protocol = htons( ETH_P_ARP );
		haddr.sll_ifindex  = ifindex;

		retval = bind( arp_sock,
		               (struct sockaddr *)&haddr,
		               sizeof( struct sockaddr_ll ) );
		
		if( retval < 0 )
		{
			LOG_ERROR( 0,
			     	 "Error: EIPM_create_arp_socket - ARP socket bind to ifindex=%d failed, ret=%x, errno=0x%x\n",
			         haddr.sll_ifindex,
			         arp_sock, errno );
				
			close( arp_sock );
			
			return( -1 );
		}
	}
	else
	{
		LOG_ERROR( 0,
		       	 "Error: EIPM_create_arp_socket - invalid address type=%d\n",
			 addr_type );

		return( -1 );
	}

	LOG_DEBUG( 0,
       	 "EIPM_create_arp_socket - creating arp socket=%d net=%d addr type=%d\n",
	 arp_sock, net, addr_type );

	return( arp_sock );
}	


/**********************************************************************
 *
 * Name:	EIPM_send_status()
 *
 * Abstract:	Send status target interface
 *
 * Parameters:	Interface Pointer
 *
 * Returns:	None
 *
 **********************************************************************/
void 
EIPM_send_status( EIPM_INTF *intf_ptr )
{
#ifndef _VHE
ipm_status_t ipm_status;
ipm_subnet_status_t *subnet_status_ptr;
EIPM_SUBNET *subnet_ptr;
int subnet_index;
SMCarMulti_msg multi_msg;
EIPM_STATUS status;
int online_cnt;
int degraded_cnt;
int offline_cnt;
EIPM_DATA *data_ptr = (EIPM_DATA *)EIPM_shm_ptr;
EIPM_INTF *tmp_intf_ptr = &data_ptr->intf_data[0];
int intf_idx;
hrtime_t report_time;

    if ( !EIPM_REPORT( &(intf_ptr->specData) ) )
    {
	return;
    }

    /*
     * Determine an overall status of the host.
     */
    for( online_cnt = 0, degraded_cnt = 0, offline_cnt = 0, intf_idx = 0; 
	 intf_idx < data_ptr->intf_cnt; 
	 intf_idx++, tmp_intf_ptr++ )
    {
	switch ( tmp_intf_ptr->specData.status )
        {
        case EIPM_UNKNOWN:
        case EIPM_ONLINE:
            online_cnt++;
            break;
        case EIPM_DEGRADED:
	    degraded_cnt++;
            break;
        case EIPM_OFFLINE:
	    offline_cnt++;
            break;
	}
    }

    if( online_cnt > 0 &&
        degraded_cnt == 0 &&
	offline_cnt == 0 )
    {
	status = EIPM_ONLINE;
    }
    else if( offline_cnt > 0 &&
             degraded_cnt == 0 &&
	     online_cnt == 0 )
    {
	status = EIPM_OFFLINE;
    }
    else if( offline_cnt == 0 &&
             degraded_cnt == 0 &&
	     online_cnt == 0 )
    {
	status = EIPM_ONLINE;
    }
    else
    {
	status = EIPM_DEGRADED;
    }

    /*If the status is the same as the overall status
     *and within 5 seconds of the last update we should skip
     *this bulk update broadcast to the CAR manager.
     */
    report_time = gethrtime();
    if ( (status == data_ptr->last_rpt_status) && 
         ((report_time - data_ptr->last_rpt_time) < 5000000000LL) )
    {
        return;
    }

    data_ptr->last_rpt_status = status;
    data_ptr->last_rpt_time = report_time;

    multi_msg.hdr.tag = SMCarMultiMembersNotify;
    multi_msg.hdr.length = sizeof(multi_msg.msg.SMCarMultiMemNotify);
    strcpy(multi_msg.msg.SMCarMultiMemNotify.car_name, SM_CAR_EXTCONN);
    multi_msg.msg.SMCarMultiMemNotify.members[0] = 0;
    multi_msg.msg.SMCarMultiMemNotify.members[1] = 1;
    multi_msg.msg.SMCarMultiMemNotify.member_end = 2;
	
    switch (status)
    {
    case EIPM_UNKNOWN:
            multi_msg.msg.SMCarMultiMemNotify.event[0] = SM_CAR_NORM;
            multi_msg.msg.SMCarMultiMemNotify.event[1] = SM_CAR_NORM;
            break;
    case EIPM_ONLINE:
            multi_msg.msg.SMCarMultiMemNotify.event[0] = SM_CAR_NORM;
            multi_msg.msg.SMCarMultiMemNotify.event[1] = SM_CAR_NORM;
            break;
    case EIPM_DEGRADED:
	    multi_msg.msg.SMCarMultiMemNotify.event[0] = SM_CAR_OFFNORM;
            multi_msg.msg.SMCarMultiMemNotify.event[1] = SM_CAR_NORM;
            break;
    case EIPM_OFFLINE:
            multi_msg.msg.SMCarMultiMemNotify.event[0] = SM_CAR_OFFNORM;
            multi_msg.msg.SMCarMultiMemNotify.event[1] = SM_CAR_OFFNORM;
            break;
    }

    ipm_send_status(&multi_msg, sizeof(multi_msg));

    return;
/*need to revisit the IPM specific multicast - replaced w/CAR mcast.*/

    memset((void *)&ipm_status, 0, sizeof(ipm_status));

    strcpy(ipm_status.type, "External");

    strcpy(ipm_status.lsn0_baseif, intf_ptr->lsn0_baseif);
    strcpy(ipm_status.lsn1_baseif, intf_ptr->lsn1_baseif);

    EIPM_status2str( intf_ptr->specData.status, ipm_status.status );

    subnet_ptr = &intf_ptr->subnet[0];
    subnet_status_ptr = &ipm_status.subnet_status[0];

    for( subnet_index = 0; 
         subnet_index < intf_ptr->subnet_cnt; 
         subnet_index++, subnet_ptr++, subnet_status_ptr++ )
    {
        IPM_ipaddr2p(&subnet_ptr->subnet_base, 
                     subnet_status_ptr->subnet, 
                     sizeof(subnet_status_ptr->subnet));

        snprintf(subnet_status_ptr->prefix, IPM_MAX_PREFIX_STR, "%d", subnet_ptr->prefixlen);

        EIPM_status2str(subnet_ptr->status, subnet_status_ptr->status);
    }

    ipm_send_status(&ipm_status, sizeof(ipm_status));

#endif
    return;
}


/**********************************************************************
 *
 * Name:	EIPM_report_status()
 *
 * Abstract:	Send status for all interfaces
 *
 * Parameters:	None
 *
 * Returns:	None
 *
 **********************************************************************/

void
EIPM_report_status()
{
EIPM_DATA *data_ptr = (EIPM_DATA *)EIPM_shm_ptr;
EIPM_INTF *intf_ptr = &data_ptr->intf_data[0];
int intf_idx;

    for( intf_idx = 0; intf_idx < data_ptr->intf_cnt; intf_idx++, intf_ptr++ )
    {
        EIPM_send_status(intf_ptr);
    }

    return;
}

/**********************************************************************
 *
 * Name:        EIPM_init_pivot_socket()
 *
 * Abstract:    initialize all pivot sockets
 *
 * Parameters:  intf_ptr - Pointer to the interface data
 *
 * Returns:     None
 *
 **********************************************************************/
void EIPM_init_pivot_sock(EIPM_INTF * intf_ptr)
{
	int i=0;
	if( intf_ptr == NULL )
	{
		return;
	}

	// initialize all pivot socket variables
	for ( i=0; i < MAX_NUM_PIVOT; i++)
	{
		intf_ptr->eipm_pivot[i].ipv4_garp_socket = -1;
		intf_ptr->eipm_pivot[i].ipv6_ns_garp_socket = -1;
		intf_ptr->eipm_pivot[i].ipv6_na_garp_socket = -1;
	}
}

/**********************************************************************
 *
 * Name:        EIPM_close_pivot_sock()
 *
 * Abstract:    Close all pivot sockets
 *
 * Parameters:  intf_ptr - Pointer to the interface data
 *
 * Returns:     None
 *
 **********************************************************************/
void EIPM_close_pivot_sock(EIPM_INTF * intf_ptr)
{
	int i=0;
	if( intf_ptr == NULL )
	{
		return;
	}

	// close all opened pivot socket
	for ( i=0; i < MAX_NUM_PIVOT; i++)
	{
		if ( intf_ptr->eipm_pivot[i].ipv4_garp_socket >= 0 )
		{
			close(intf_ptr->eipm_pivot[i].ipv4_garp_socket);
			intf_ptr->eipm_pivot[i].ipv4_garp_socket = -1;
		}

		if ( intf_ptr->eipm_pivot[i].ipv6_ns_garp_socket >= 0 )
		{
			close(intf_ptr->eipm_pivot[i].ipv6_ns_garp_socket);
			intf_ptr->eipm_pivot[i].ipv6_ns_garp_socket = -1;
		}

		if ( intf_ptr->eipm_pivot[i].ipv6_na_garp_socket >= 0 )
		{
			close(intf_ptr->eipm_pivot[i].ipv6_na_garp_socket);
			intf_ptr->eipm_pivot[i].ipv6_na_garp_socket = -1;
		}
	}
}


/**********************************************************************
 *
 * Name:	EIPM_close_sock()
 *
 * Abstract:	Close all sockets
 *
 * Parameters:	intfSpecDataP - Pointer to interface specific data.
 *
 * Returns:	None
 *
 **********************************************************************/

void
EIPM_close_sock( EIPM_INTF_SPEC *intfSpecDataP )
{
	/*
	 * Close all interface sockets.
	 */
	if( intfSpecDataP->lsn1_garpsock >= 0 )
	{
		(void)close( intfSpecDataP->lsn1_garpsock );
		intfSpecDataP->lsn1_garpsock = -1;
	}

	if( intfSpecDataP->lsn0_garpsock >= 0 )
	{
		(void)close( intfSpecDataP->lsn0_garpsock );
		intfSpecDataP->lsn0_garpsock = -1;
	}

	if( intfSpecDataP->lsn1_v6garpsock >= 0 )
	{
		(void)close( intfSpecDataP->lsn1_v6garpsock );
		intfSpecDataP->lsn1_v6garpsock = -1;
	}

	if( intfSpecDataP->lsn0_v6garpsock >= 0 )
	{
		(void)close( intfSpecDataP->lsn0_v6garpsock );
		intfSpecDataP->lsn0_v6garpsock = -1;
	}

	if( intfSpecDataP->lsn1_arpsock >= 0 )
	{
		(void)close( intfSpecDataP->lsn1_arpsock );
		intfSpecDataP->lsn1_arpsock = -1;
	}

	if( intfSpecDataP->lsn0_arpsock >= 0 )
	{
		(void)close( intfSpecDataP->lsn0_arpsock );
		intfSpecDataP->lsn0_arpsock = -1;
	}

	if( intfSpecDataP->lsn1_v6arpsock >= 0 )
	{
		(void)close( intfSpecDataP->lsn1_v6arpsock );
		intfSpecDataP->lsn1_v6arpsock = -1;
	}

	if( intfSpecDataP->lsn0_v6arpsock >= 0 )
	{
		(void)close( intfSpecDataP->lsn0_v6arpsock );
		intfSpecDataP->lsn0_v6arpsock = -1;
	}

	if( intfSpecDataP->lsn1_socket >= 0 )
	{
		(void)close( intfSpecDataP->lsn1_socket );
		intfSpecDataP->lsn1_socket = -1;
	}

	if( intfSpecDataP->lsn0_socket >= 0 )
	{
		(void)close( intfSpecDataP->lsn0_socket );
		intfSpecDataP->lsn0_socket = -1;
	}

	return;
}


/**********************************************************************
 *
 * Name:	EIPM_open_garpsock()
 *
 * Abstract:	Open garp sockets if needed
 *
 * Parameters:	intfSpecDataP - Pointer to interface specific data.
 *           :  addr_type - IP address type.
 *
 * Returns:	None
 *
 **********************************************************************/

void
EIPM_open_garpsock( EIPM_INTF_SPEC *intfSpecDataP, IPM_IPADDRTYPE addr_type )
{
	if( addr_type == IPM_IPV6 )
	{
		if(( intfSpecDataP->lsn0_v6garpsock < 0 ) &&
		   ( intfSpecDataP->lsn0_iface_indx > 0 ))  
		{
			intfSpecDataP->lsn0_v6garpsock =
			        EIPM_create_arp_socket( LSN0, IPM_IPV6, intfSpecDataP->lsn0_iface_indx, ND_NEIGHBOR_ADVERT );
		}					

		if(( intfSpecDataP->lsn1_v6garpsock < 0 ) &&
		   ( intfSpecDataP->lsn1_iface_indx > 0 ))
		{
			intfSpecDataP->lsn1_v6garpsock =
			        EIPM_create_arp_socket( LSN1, IPM_IPV6, intfSpecDataP->lsn1_iface_indx, ND_NEIGHBOR_ADVERT );
		}
	}
	else if( addr_type == IPM_IPV4 )
	{
		if(( intfSpecDataP->lsn0_garpsock < 0 ) &&
		   ( intfSpecDataP->lsn0_iface_indx > 0 ))
		{
			intfSpecDataP->lsn0_garpsock =
			        EIPM_create_arp_socket( LSN0, IPM_IPV4, intfSpecDataP->lsn0_iface_indx, ARPOP_REPLY );
		}					

		if(( intfSpecDataP->lsn1_garpsock < 0 ) &&
		   ( intfSpecDataP->lsn1_iface_indx > 0 ))
		{
			intfSpecDataP->lsn1_garpsock =
			        EIPM_create_arp_socket( LSN1, IPM_IPV4, intfSpecDataP->lsn1_iface_indx, ARPOP_REPLY );
		}
	}
	else
	{
		LOG_ERROR( 0,
		       	 "Error: EIPM_open_garpsock - invalid address type=%d\n",
			 addr_type );
	}
	return;
}


/**********************************************************************
 *
 * Name:	EIPM_check_route_priority()
 *
 * Abstract:	Check sysctl settings on the interface, update if needed
 *
 * Parameters:	intf_ptr - EIPM Interface data pointer
 *
 * Returns:	SUCCES, FAILURE
 *
 **********************************************************************/

void 
EIPM_check_route_priority( EIPM_INTF *intf_ptr, uint16_t vlanId )
{
EIPM_SUBNET 	*subnet_ptr;
EIPM_ROUTES 	*route_ptr;
int 		subnet_idx;
int 		route_idx;
int 		ret;
unsigned char	act_intf;
char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];

	if ( (intf_ptr->specData.monitor == EIPM_MONITOR_SNDPKT) ||
	     (intf_ptr->specData.monitor == EIPM_MONITOR_BFD) )
	{
		if ( intf_ptr->specData.status == EIPM_ONLINE )
		{
		        /* Look through all subnets */
		        for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
		             subnet_idx < intf_ptr->subnet_cnt;
		             subnet_idx++, subnet_ptr++ )
		        {
				if(( subnet_ptr->status == EIPM_ONLINE ) &&
				   ( subnet_ptr->sub2intf_mapping[vlanId].route_priority != intf_ptr->specData.preferred_side ))
				{
					LOG_ERROR( 0,
			                   "EIPM_check_route_priority: subnet %s current priority %d new priority %d\n",
						IPM_ipaddr2p( &subnet_ptr->subnet_base, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
						subnet_ptr->sub2intf_mapping[vlanId].route_priority,
						intf_ptr->specData.preferred_side );

					EIPM_update_subnet_route_priority( &intf_ptr->specData, subnet_ptr, intf_ptr->specData.preferred_side);
				}
			}
		}
	}
	else if ( intf_ptr->specData.monitor == EIPM_MONITOR_ROUTE )
	{
	        /* Look through all subnets */
	        for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
	             subnet_idx < intf_ptr->subnet_cnt;
	             subnet_idx++, subnet_ptr++ )
	        {
		        for( route_idx = 0, route_ptr = &subnet_ptr->routes[0];
		             route_idx < subnet_ptr->route_cnt;
		             route_idx++, route_ptr++ )
		        {
				
				if( route_ptr->type != EIPM_ROUTE_OTH ||
				    (route_ptr->nexthop.addrtype != IPM_IPV4 &&
				     route_ptr->nexthop.addrtype != IPM_IPV6 ))
				{
					continue;
				}
				
				ret = ipm_get_intf_to_nexthop( intf_ptr->lsn0_baseif, intf_ptr->lsn1_baseif, &route_ptr->nexthop, &act_intf );
				if( ret == IPM_SUCCESS )
				{
					if( act_intf == LINK_0 && subnet_ptr->sub2intf_mapping[vlanId].route_priority != LSN0 )
					{
						LOG_ERROR( 0,
				                   "EIPM_check_route_priority: next hop %s subnet %s current priority %d new priority LSN0\n",
							IPM_ipaddr2p( &route_ptr->nexthop, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
							IPM_ipaddr2p( &subnet_ptr->subnet_base, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
							subnet_ptr->sub2intf_mapping[vlanId].route_priority );
	
						EIPM_update_subnet_route_priority( &intf_ptr->specData, subnet_ptr, LSN0);
					}
					else if( act_intf == LINK_1 && subnet_ptr->sub2intf_mapping[vlanId].route_priority != LSN1 )
					{
						LOG_ERROR( 0,
				                   "EIPM_check_route_priority: next hop %s subnet %s current priority %d new priority LSN1\n",
							IPM_ipaddr2p( &route_ptr->nexthop, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
							IPM_ipaddr2p( &subnet_ptr->subnet_base, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
							subnet_ptr->sub2intf_mapping[vlanId].route_priority );

						EIPM_update_subnet_route_priority( &intf_ptr->specData, subnet_ptr, LSN1);
					}
				}
				else
				{
					LOG_ERROR( 0,
			                   "EIPM_check_route_priority: ipm_get_intf_to_nexthop failed %d next hop %s subnet %s current priority %d\n",
						ret,
						IPM_ipaddr2p( &route_ptr->nexthop, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
						IPM_ipaddr2p( &subnet_ptr->subnet_base, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
						subnet_ptr->sub2intf_mapping[vlanId].route_priority );
				}
			}
		}
	}
	return;
}

/**********************************************************************
 *
 * Name:	EIPM_check_monitor_route
 *
 * Abstract:	Check if destination ip is within a monitor route subnet
 *
 * Parameters:	dest_ip    - destination ip ptr
 *
 * Returns:	IPM_SUCCESS - dest ip within a monitor route subnet
 *		IPM_FAILURE - dest ip is NOT within a montior route subnet
 *
 **********************************************************************/
int EIPM_check_monitor_route(IPM_IPADDR *dest_ip)
{
EIPM_DATA 	*data_ptr;
EIPM_INTF 	*intf_ptr;
EIPM_SUBNET 	*subnet_ptr;
IPM_IPADDR	subnet_mask;
IPM_IPADDR	subnet_base;
int 		intf_idx;
int 		subnet_idx;
int 		ret;
char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];

    if( dest_ip == NULL )
    {
	LOG_ERROR(0, "EIPM_check_route_update: dest_ip null\n" );
	return IPM_FAILURE;
    }

    if( EIPM_shm_ptr == NULL )
    {
	LOG_ERROR(0, "EIPM_check_route_update: Shared memory null\n" );
	return IPM_FAILURE;
    }

    data_ptr = (EIPM_DATA *)EIPM_shm_ptr;

    /* Look through all interfaces */
    for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
         intf_idx < data_ptr->intf_cnt;
         intf_idx++, intf_ptr++ )
    {
	if ( intf_ptr->specData.monitor != EIPM_MONITOR_ROUTE )
	{
	    continue;		
	}

        /* Look through all subnets */
        for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
             subnet_idx < intf_ptr->subnet_cnt;
             subnet_idx++, subnet_ptr++ )
        {
	    if( IPM_IPCMPADDRTYPE( &subnet_ptr->subnet_base, dest_ip ) != IPM_SUCCESS )
	    {
		continue;
	    }

    	    IPM_ipaddr_init(&subnet_mask);

    	    ret = IPM_ipmkmask(&subnet_mask, dest_ip->addrtype, subnet_ptr->prefixlen);
	    if( ret != IPM_SUCCESS )
	    {
		LOG_ERROR(0, "EIPM_check_route_update: IPM_ipmkmask failed ret = %d\n", ret );
		continue;
	    }

    	    IPM_ipaddr_init(&subnet_base);

    	    IPM_get_subnet(dest_ip, &subnet_mask, &subnet_base);

            if( IPM_IPCMPADDR(&subnet_ptr->subnet_base, &subnet_base) == IPM_SUCCESS )
	    {
	    	return IPM_SUCCESS;
	    }
	}
    }	
    return IPM_FAILURE;
}

/**********************************************************************
 *
 * Name:	EIPM_findIntf
 *
 * Abstract:
 *     Searches for a base and/or child interface. 
 *
 * Parameters:
 *     lsn0_intfName - LSN0 interface name (can be tagged/untagged).
 *     lsn1_intfName - LSN1 interface name (can be tagged/untagged).
 *     intfDataP - Base/parent interface pointer. Set to matching interface.
 *     intfSpecDataP - Extension/child interface pointer. Set to matching interface.
 *     intfType - Set to indicate whether matching interface is base/extension.
 *     baseIntfIdx - Indicates index of matching base interface.
 *
 * Returns:
 *     Returns the index of the matching base/extension interface.
 *     Returns -1 if there is no "exact" interface match; i.e., there maybe a partial match
 *     on the base interface but no exact match on the extension interface or no match at all
 *     on any interface.
 *
 **********************************************************************/

int EIPM_findIntf( char *lsn0_intfName, char *lsn1_intfName,
                   EIPM_INTF **intfDataP, EIPM_INTF_SPEC **intfSpecDataP, 
                   EIPM_INTF_TYPE *intfType, int *baseIntfIdx )
{

        EIPM_DATA       *dataP;
        int intfIdx;
        char            lsn0IntfName[MAX_NLEN_DEV];
        char            lsn1IntfName[MAX_NLEN_DEV];
        
        *baseIntfIdx = -1;
        *intfDataP = NULL;
        *intfSpecDataP = NULL;

        dataP = (EIPM_DATA *)EIPM_shm_ptr;
        *intfType = EIPM_INVALID_INTF;

	memset(lsn0IntfName, 0, MAX_NLEN_DEV);
	memset(lsn1IntfName, 0, MAX_NLEN_DEV);

        /* Search the base/parent interface data first for a matching interface. */
        for ( ( intfIdx = 0, *intfDataP = &(dataP->intf_data[0]) );
              ( intfIdx < dataP->intf_cnt );
              ( intfIdx++, (*intfDataP)++ ) )
        {
                if (    ( 0 == strcmp( (*intfDataP)->lsn0_baseif, lsn0_intfName ) )
                     && ( 0 == strcmp( (*intfDataP)->lsn1_baseif, lsn1_intfName ) ) )
                {
                        /* Exact match. Found the interface. */
                        *intfSpecDataP = &((*intfDataP)->specData);
                        *intfType = EIPM_BASE_INTF;
                        *baseIntfIdx = intfIdx;

                        return intfIdx;
                }
                else if (    ( strstr( lsn0_intfName, (*intfDataP)->lsn0_baseif ) != NULL ) 
                          && ( strstr( lsn1_intfName, (*intfDataP)->lsn1_baseif ) != NULL ) )
                {
                        /* Partial match. Will need to search the extension/child interfaces data for exact match. */
                        *baseIntfIdx = intfIdx;

                        break;
                }
        }

        /* Search the extension/child interface data for a matching interface now. */
        for ( ( intfIdx = 0, *intfSpecDataP = &(dataP->extnIntfData[0]) );
              ( intfIdx < dataP->extnIntfCount );
              ( intfIdx++, (*intfSpecDataP)++ ) )
        {
                if ( !EIPM_IS_VALID_BASE_INTF_IDX( (*intfSpecDataP)->baseIntfIdx ) )
                {
                        /* Invalid base interface index. Assert and continue. */
                        ASRT_RPT( ASBAD_DATA, 0, "Invalid base interface index %d (count: %d).\n",
                                  (*intfSpecDataP)->baseIntfIdx, ((EIPM_DATA *)EIPM_shm_ptr)->intf_cnt );
                        continue;
                }

                if (    ( *baseIntfIdx != -1 )
                     && ( *baseIntfIdx != (*intfSpecDataP)->baseIntfIdx ) )
                {
                        continue;
                }

                *intfDataP = &(dataP->intf_data[(*intfSpecDataP)->baseIntfIdx]);

                /* Create the complete interface name. */
		if (strlen((*intfDataP)->lsn0_baseif) > 0)
		{
			snprintf( lsn0IntfName, sizeof( lsn0IntfName ), "%s%s",
				(*intfDataP)->lsn0_baseif, ipm_getVLANStr( (*intfSpecDataP)->vlanId, TRUE ) );
		}

		if (strlen((*intfDataP)->lsn1_baseif) > 0)
		{
			snprintf( lsn1IntfName, sizeof( lsn1IntfName ), "%s%s",
				(*intfDataP)->lsn1_baseif, ipm_getVLANStr( (*intfSpecDataP)->vlanId, TRUE ) );
		}

                if (    ( 0 == strcmp( lsn0IntfName, lsn0_intfName ) )
                     && ( 0 == strcmp( lsn1IntfName, lsn1_intfName ) ) )
                {
                        /* Exact match. Found the interface. */
                        *intfType = EIPM_EXTN_INTF;
                        *baseIntfIdx = (*intfSpecDataP)->baseIntfIdx;

                        return intfIdx;
                }
        } /* end 'extension interfaces loop' */

        *intfDataP = NULL;
        *intfSpecDataP = NULL;

        return -1;

} /* end EIPM_findIntf() */

/**********************************************************************
*
* Name:        EIPM_check_intf_up()
*
* Abstract:    Check and bring up the interface if necessary
*
* Parameters:  iface_ptr - name of interface
*
* Returns:     IPM_SUCCESS on success.
*              IPM_FAILURE on failure.
*
**********************************************************************/

int EIPM_check_intf_up( char *iface_ptr )
{
#ifndef _VHE
        struct ifreq ifr;

	if (strlen(iface_ptr) == 0)
	{
		return IPM_SUCCESS;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, iface_ptr, IFNAMSIZ-1);

        //check if the interface is there
        if (ioctl(inetsocket, SIOCGIFFLAGS, &ifr) < 0)
        {
                ASRT_RPT(ASOSFNFAIL, 0,
                        "Unknown interface %s; errno=%d/%s",
                        iface_ptr, errno, strerror(errno));
                return IPM_FAILURE;
        }

	//check to see if it is up
	if (!(ifr.ifr_flags & IFF_UP))
	{
		EIPM_LOG_ERROR(0, "EIPM_check_intf_up: Interface %s flags 0x%x\n",
				iface_ptr, ifr.ifr_flags );

	        //make it up
	        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	        if (ioctl(inetsocket, SIOCSIFFLAGS, &ifr) < 0)
	        {
	                ASRT_RPT(ASOSFNFAIL, 0,
	                        "ioctl -  SIOCSIFFLAGS for IFF_UP | IFF_RUNNING failed; errno=%d/%s",
	                        errno, strerror(errno));
	                return IPM_FAILURE;
	        }
	}

	return IPM_SUCCESS;
#endif
}

/**********************************************************************
*
* Name:        EIPM_check_baseintf()
*
* Abstract:    Given an interface name, check that 
*
* Parameters:  iface_ptr - name of interface
*
* Returns:     IPM_SUCCESS on success.
*              IPM_FAILURE on failure.
*
**********************************************************************/

int EIPM_check_baseintf( char *iface_ptr )
{
#ifndef _VHE
	char iface[EI_INTFNAMESIZE];
	char baseiface[EI_INTFNAMESIZE];
	char vlan[EI_INTFNAMESIZE];
	char outervlan[EI_INTFNAMESIZE];
	char *tok, *remain;

	if (strlen(iface_ptr) == 0)
	{
		return IPM_SUCCESS;
	}

	memset(&iface, 0, sizeof(iface));
	memset(&baseiface, 0, sizeof(baseiface));
	memset(&vlan, 0, sizeof(vlan));
	memset(&outervlan, 0, sizeof(outervlan));

	strncpy( iface, iface_ptr, ( EI_INTFNAMESIZE-1 ) );

	tok = strtok_r( iface, ".", &remain );
	if (tok != NULL)
	{
		strncpy( baseiface, tok, ( EI_INTFNAMESIZE-1 ) );

		tok = strtok_r( NULL, ".", &remain );

		if (tok != NULL)
		{
			strncpy( vlan, tok, ( EI_INTFNAMESIZE-1 ) );			

			tok = strtok_r( NULL, ".", &remain );

			if (tok != NULL)
			{
				strncpy( outervlan, tok, ( EI_INTFNAMESIZE-1 ) );			
			}
		}
	}
	else
	{
		strncpy( baseiface, iface_ptr, ( EI_INTFNAMESIZE-1 ) );
	}

	EIPM_check_intf_up(baseiface);

	if (strlen(vlan) != 0)
	{
		strcat(baseiface, "."); 
		strcat(baseiface, vlan); 
		EIPM_check_intf_up(baseiface);

		if (strlen(outervlan) != 0)
		{
			strcat(baseiface, "."); 
			strcat(baseiface, outervlan); 
			EIPM_check_intf_up(baseiface);
		}
	}

	return IPM_SUCCESS;
#endif
}

/**********************************************************************
*
* Name:        EIPM_check_intf()
*
* Abstract:    Compare the OS interfaces against the IPM data.
*               Update OS if a discrepency is found.
*
* Parameters:  master - name of pivot interface
*                        actSlave - active slave name
*                        stbySlave = standby slave name
*
* Returns:     IPM_SUCCESS on success.
*                  IPM_FAILURE on failure.
*
**********************************************************************/

int EIPM_check_intf( EIPM_INTF *intf_ptr )
{
#ifndef _VHE

	if (ipm_isVirtual() != 1)
	{
        if( intf_ptr->specData.monitor == EIPM_MONITOR_ROUTE )
        {
		EIPM_check_pivot( intf_ptr );
		return IPM_SUCCESS;
        }
	}
	else
	{
		if (TRUE == intf_ptr->is_tunnel_intf)
		{
			if (IPM_FAILURE == EIPM_check_gre_tunnel_intf())
			{
				return IPM_FAILURE;
			}
			else
			{
				return IPM_SUCCESS;
			}
		}
	}


	if( strlen(intf_ptr->lsn0_baseif) != 0 )
	{
		EIPM_check_baseintf(intf_ptr->lsn0_baseif);
	}

	if( strlen(intf_ptr->lsn1_baseif) != 0 )
	{
		EIPM_check_baseintf(intf_ptr->lsn1_baseif);
	}

#endif
        return IPM_SUCCESS;
}

/**********************************************************************
*
* Name: EIPM_check_pivot
*
* Abstract:    Compare the OS pivot interfaces against the IPM data.
*               Update OS if a discrepency is found.
*
* Parameters:   intf_ptr - pointer to interface data
*
*
* Returns:      IPM_SUCCESS - OS pivot interface was successfully changed if needed
*               IPM_FAILURE - error occurred
*
**********************************************************************/
int EIPM_check_pivot( EIPM_INTF *intf_ptr )
{
#ifndef _VHE
        EIPM_SUBNET     *subnet_ptr;
        EIPM_IPDATA     *ipdata_ptr;
        int             subnet_idx;
        int             ip_idx;
        char            iface_l[EI_INTFNAMESIZE];
        char            iface_r[EI_INTFNAMESIZE];
        struct          ifreq ifr;
        struct          ifpivot ifp;

        if( intf_ptr->specData.monitor != EIPM_MONITOR_ROUTE )
        {
        return IPM_SUCCESS;
        }

        memset(iface_l, 0, sizeof(iface_l));
        memset(iface_r, 0, sizeof(iface_r));

        memset(&ifr, 0, sizeof(struct ifreq));
        memset(&ifp, 0, sizeof(struct ifpivot));

        // Look through all subnets
        for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
        subnet_idx < intf_ptr->subnet_cnt;
        subnet_idx++, subnet_ptr++ )
        {
                if (subnet_ptr->ip_cnt == 0)
                {
                        continue;
                }

                // Look through all IPs
                for( ip_idx = 0, ipdata_ptr = &subnet_ptr->ips[0];
                		ip_idx < subnet_ptr->ip_cnt;
                		ip_idx++, ipdata_ptr++ )
                {
                        if (ipdata_ptr->pivot_id == 0)
                        {
                                continue;
                        }

                        if (ipdata_ptr->pivot_id >= MAX_NUM_PIVOT)
                        {
                                ASRT_RPT( ASBAD_DATA,
                                        0,
                                        "EIPM_check_pivot - bad pivot_id - %d\n",
                                        ipdata_ptr->pivot_id );
                                return IPM_FAILURE;
                        }

                        sprintf(ifr.ifr_name, "%s%d", PIVOT_PREFIX, ipdata_ptr->pivot_id);

                        //check if the new interface is there
                        if (ioctl(inetsocket, SIOCGIFFLAGS, &ifr) < 0)
                        {
                                ASRT_RPT(ASOSFNFAIL, 0,
                                        "Unknown interface %s; errno=%d/%s",
                                        ifr.ifr_name, errno, strerror(errno));
                                return IPM_FAILURE;
                        }

                        //make sure it is up
                        if (!(ifr.ifr_flags & IFF_UP))
                        {
                                ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
                                if (ioctl(inetsocket, SIOCSIFFLAGS, &ifr) < 0)
                                {
                                        ASRT_RPT(ASOSFNFAIL, 0,
                                                "ioctl -  SIOCSIFFLAGS for IFF_UP | IFF_RUNNING failed; errno=%d/%s",
                                                errno, strerror(errno));
                                        return IPM_FAILURE;
                                }
                        }

                        //Get pivot info - active standby slaves
                        ifr.ifr_data = &ifp;
                        if (ioctl(inetsocket, SIOCPIVOTINFOQUERY, &ifr) < 0)
                        {
                                ASRT_RPT( ASOSFNFAIL,
                                        0,
                                        "EIPM_check_pivot - failed to query pivot slave info\npivot=%s, errno=%d/%s\n",
                                        ifr.ifr_name, errno, strerror(errno) );

                                return IPM_FAILURE;
                        }

                        //compare with IPM data.
                        if ( ifp.num_slaves == MAX_NB_DEV &&
                                ((strstr(ipdata_ptr->lsn0_iface, ifp.slave_name_list[0]) == 0 &&
                                strstr(ipdata_ptr->lsn1_iface, ifp.slave_name_list[1]) == 0) || (
                                strstr(ipdata_ptr->lsn0_iface, ifp.slave_name_list[1]) == 0 &&
                                strstr(ipdata_ptr->lsn1_iface, ifp.slave_name_list[0]) == 0)) )
                        {
                                continue;
                        }

                        //release and reconfigure
                        while (ifp.num_slaves > 0)
                        {
                                strcpy(ifr.ifr_slave, ifp.slave_name_list[ifp.num_slaves-1]);
                                if (ioctl(inetsocket, SIOCPIVOTRELEASE, &ifr) < 0)
                                {
                                        ASRT_RPT( ASOSFNFAIL, 0,
                                                "EIPM_check_pivot - failed to release slave %s on master %s, errno=%d/%s\n",
                                                ifr.ifr_slave, ifr.ifr_name, errno, strerror(errno) );
                                }
                                ifp.num_slaves--;
                        }

                        if (intf_ptr->lsn0_baseif[0] != '\0')
                        {
                                sprintf(iface_l, "%s.%d", intf_ptr->lsn0_baseif, ipdata_ptr->pivot_id);
                        }

                        if (intf_ptr->lsn1_baseif[1] != '\0')
                        {
                                sprintf(iface_r, "%s.%d", intf_ptr->lsn1_baseif, ipdata_ptr->pivot_id);
                        }

                        if (subnet_ptr->pivot_act_base[ipdata_ptr->pivot_id] == LSN0)
                        {
                                return EIPM_attach_pivot(ifr.ifr_name, iface_l, iface_r);
                        }
                        else
                        {
                                return EIPM_attach_pivot(ifr.ifr_name, iface_r, iface_l);
                        }
                }
        }
#endif
        return IPM_SUCCESS;
}

/**********************************************************************
*
* Name:        EIPM_getActiveSlave()
*
* Abstract:    Get active slave info of a pivot interface by pivot id.
*
* Parameters:  pivot_id - pivot id
*
* Returns:     LSN0/LSN1 on success.
*                  LSN_NONE on failure.
*
**********************************************************************/

EIPM_NET EIPM_getActiveSlave(uint8_t pivot_id)
{
#ifndef _VHE
        struct ifreq ifr;
        struct ifpivot ifp;

        if (pivot_id >= MAX_NUM_PIVOT)
        {
                ASRT_RPT( ASBAD_DATA,
                        0,
                        "EIPM_getActiveSlave - bad parameters: pivot_id - %d\n",
                        pivot_id );
                return LSN_NONE;
        }

        memset(&ifr, 0, sizeof(struct ifreq));
        memset(&ifp, 0, sizeof(struct ifpivot));

        sprintf(ifr.ifr_name, "%s%d", PIVOT_PREFIX, pivot_id);

        ifr.ifr_data = &ifp;
        if (ioctl(inetsocket, SIOCPIVOTINFOQUERY, &ifr) < 0)
        {
                ASRT_RPT( ASOSFNFAIL, 0,
                        "EIPM_getActiveSlave - failed to get pivot slave info\npivot=%s, errno=%d/%s\n",
                        ifr.ifr_name, errno, strerror(errno) );
                return LSN_NONE;
        }

        if (strstr(ifp.active_slave_name, "eth0"))
        {
                return LSN0;
        }
        else if (strstr(ifp.active_slave_name, "eth1"))
        {
                return LSN1;
        }

#endif
        return LSN_NONE;
}

/**********************************************************************
*
* Name:        EIPM_setActiveSlave()
*
* Abstract:    Set active slave of a pivot
*
* Parameters:  pivot_id - pivot id
*                     iface - slave interface base name, e.g. eth0.800
*
* Returns:     void
*
*
**********************************************************************/
void EIPM_setActiveSlave(uint8_t pivot_id, char* iface)
{
#ifndef _VHE
        struct ifreq ifr;
        struct ifpivot ifp;

	/* In Simplex Mode, don't need to change active interface for pivot */
        if (IS_SIMPLEX_MODE)
        {
                return;
        }

        if (pivot_id >= MAX_NUM_PIVOT)
        {
                ASRT_RPT( ASBAD_DATA, 0,
                        "EIPM_setActiveSlave - bad parameters: pivot_id - %d, active - %s\n",
                        pivot_id, iface );
                return;
        }

        memset(&ifr, 0, sizeof(struct ifreq));
        sprintf(ifr.ifr_name, "%s%d", PIVOT_PREFIX, pivot_id);

        //query master to see if the iface is a slave
        memset(&ifp, 0, sizeof(struct ifpivot));
        ifr.ifr_data = &ifp;
        if (ioctl(inetsocket, SIOCPIVOTINFOQUERY, &ifr) < 0)
        {
                ASRT_RPT( ASOSFNFAIL, 0,
                        "failed to get pivot slave info\npivot=%s, errno=%d/%s\n",
                        ifr.ifr_name, errno, strerror(errno) );
                return;
        }

        sprintf(ifr.ifr_slave, "%s.%d", iface, pivot_id);

        //already active
        if (strcmp(ifp.active_slave_name, ifr.ifr_slave) == 0)
        {
                return;
        }

        //is it possible there is no such a slave?
        if (ifp.num_slaves == 2 &&
                strcmp(ifp.slave_name_list[0], ifr.ifr_slave) != 0 &&
                strcmp(ifp.slave_name_list[1], ifr.ifr_slave) != 0)
        {
                ASRT_RPT( ASBAD_DATA, 0,
                        "failed to change %s active, not a slave",
                        ifr.ifr_slave);
                return;
        }
        else if (ifp.num_slaves == 1)
        {
                //add it as a slave and change it active.
                if (ioctl(inetsocket, SIOCPIVOTENSLAVE, &ifr) < 0)
                {
                        ASRT_RPT( ASOSFNFAIL, 0,
                                "Failed to enslave: master %s, slave %s; errno=%d/%s",
                                ifr.ifr_name, ifr.ifr_slave,
                                errno, strerror(errno) );
                        return;
                }
        }

        if ( ioctl(inetsocket, SIOCPIVOTCHANGEACTIVE, &ifr) < 0)
        {
                ASRT_RPT( ASOSFNFAIL, 0,
                        "EIPM_getActiveSlave - failed to get pivot slave info\npivot_id=%d, errno=%d/%s\n",
                        pivot_id, errno, strerror(errno) );
        }
#endif
}

/**********************************************************************
*
* Name:        EIPM_attach_pivot()
*
* Abstract:    Attach slave interfaces to a pivot interface
*
* Parameters:  master - name of pivot interface
*                        actSlave - active slave name
*                        stbySlave = standby slave name
*
* Returns:     IPM_SUCCESS on success.
*                  IPM_FAILURE on failure.
*
**********************************************************************/

int EIPM_attach_pivot(char *master, char *actSlave, char *stbySlave)
{
#ifndef _VHE
        struct ifreq ifr;
        struct ifpivot ifp;
        memset(&ifr, 0, sizeof(struct ifreq));

        strcpy(ifr.ifr_name, master);

        //query master to see if it has already got slaves.
        memset(&ifp, 0, sizeof(struct ifpivot));
        ifr.ifr_data = &ifp;
        if (ioctl(inetsocket, SIOCPIVOTINFOQUERY, &ifr) < 0)
        {
                ASRT_RPT( ASOSFNFAIL, 0,
                        "failed to get pivot slave info\npivot=%s, errno=%d/%s\n",
                        master, errno, strerror(errno) );

                return IPM_FAILURE;
        }

        //slaves are already there.
        if (ifp.num_slaves == 2 &&
		( ( strcmp(ifp.slave_name_list[0], actSlave) == 0 &&
                	strcmp(ifp.slave_name_list[1], stbySlave) == 0 ) ||
                  ( strcmp(ifp.slave_name_list[0], actSlave) == 0 &&
                	strcmp(ifp.slave_name_list[1], stbySlave) == 0 ) 
		)
	   )
        {
                return IPM_SUCCESS;
        }

        //release old slaves first
        while (ifp.num_slaves > 0)
        {
                strcpy(ifr.ifr_slave, ifp.slave_name_list[ifp.num_slaves-1]);
                if (ioctl(inetsocket, SIOCPIVOTRELEASE, &ifr) < 0)
                {
                        ASRT_RPT( ASOSFNFAIL, 0,
                                "failed to release pivot %s slave %s, errno=%d/%s\n",
                                master, ifr.ifr_slave, errno, strerror(errno) );
                        return IPM_FAILURE;
                }
                ifp.num_slaves--;
        }

        //enslave pivot
        //lsn0 is always active slave for first time
        if (actSlave[0] != '\0')
        {
			strncpy(ifr.ifr_slave, actSlave, IFNAMSIZ - 1);
			ifr.ifr_slave[IFNAMSIZ - 1] = '\0';
			if (ioctl(inetsocket, SIOCPIVOTENSLAVE, &ifr) < 0)
			{
				ASRT_RPT( ASOSFNFAIL, 0,
					"ipm_attach_pivot: Failed to enslave %s; errno=%d/%s",
					ifr.ifr_name,
					errno, strerror(errno) );
				return IPM_FAILURE;
			}
        }

        //lsn1 is standby slave.
        if(stbySlave[0] != '\0')
        {
			strncpy(ifr.ifr_slave, stbySlave, IFNAMSIZ - 1);
			ifr.ifr_slave[IFNAMSIZ - 1] = '\0';
			if (ioctl(inetsocket, SIOCPIVOTENSLAVE, &ifr) < 0)
			{
				ASRT_RPT( ASOSFNFAIL, 0,
					"ipm_attach_pivot: Failed to enslave %s; errno=%d/%s",
					ifr.ifr_name,
					errno, strerror(errno) );
				return IPM_FAILURE;
			}	
        }

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, master, IFNAMSIZ-1);

        //check if the master interface is there
        if (ioctl(inetsocket, SIOCGIFFLAGS, &ifr) < 0)
        {
                ASRT_RPT(ASOSFNFAIL, 0,
                        "Unknown interface %s; errno=%d/%s",
                        master, errno, strerror(errno));
                return IPM_FAILURE;
        }

        //make it up
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        if (ioctl(inetsocket, SIOCSIFFLAGS, &ifr) < 0)
        {
                ASRT_RPT(ASOSFNFAIL, 0,
                        "ioctl -  SIOCSIFFLAGS for IFF_UP | IFF_RUNNING failed; errno=%d/%s",
                        errno, strerror(errno));
                return IPM_FAILURE;
        }

#endif
        return IPM_SUCCESS;
}

/**********************************************************************
*
* Name:        EIPM_set_qinq_mtu()
*
* Abstract:    set mtu value to a interfaces due to QinQ packet size.
*
* Parameters:  name - name of interface
*              mtu - MTU value
*
* Returns:     IPM_SUCCESS on success.
*              IPM_FAILURE on failure.
*
**********************************************************************/

int EIPM_set_qinq_mtu(char *name, int mtu)
{
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(struct ifreq));

	strncpy(ifr.ifr_name, name, IFNAMSIZ-1);
        ifr.ifr_mtu = mtu;
        if (ioctl(inetsocket, SIOCSIFMTU, &ifr) < 0)
        {
                ASRT_RPT(ASOSFNFAIL, 0,
                        "ioctl -  SIOCSIFMTU failed for iface %s; errno=%d/%s",
                        ifr.ifr_name, errno, strerror(errno));
                return IPM_FAILURE;
        }

        return IPM_SUCCESS;
}

//This function is a workaround for arp issue found in microCP env
//RCC changed arp parameters to fix its bug, code change will be made later.
//Before we get code fix from RCC, just call this function to let arp work.
int EIPM_set_qinq_arp()
{
        (void)EIPM_set_sysctl_value( "eth0", "ipv4", "arp_filter", 0 );
        (void)EIPM_set_sysctl_value( "eth0", "ipv4", "arp_ignore", 1 );
        (void)EIPM_set_sysctl_value( "eth0", "ipv4", "arp_announce", 2 );
        (void)EIPM_set_sysctl_value( "eth1", "ipv4", "arp_filter", 0 );
        (void)EIPM_set_sysctl_value( "eth1", "ipv4", "arp_ignore", 1 );
        (void)EIPM_set_sysctl_value( "eth1", "ipv4", "arp_announce", 2 );
        (void)EIPM_set_sysctl_value( "all", "ipv4", "arp_filter", 0 );
        (void)EIPM_set_sysctl_value( "all", "ipv4", "arp_ignore", 1 );
        (void)EIPM_set_sysctl_value( "all", "ipv4", "arp_announce", 2 );
	return IPM_SUCCESS;
}

/*
 *  Function: EIPM_audit_sysctl_for_internalIntfs.
 *  Input   : None.
 *  Output  : None.
 *  Desc.   : Audits the 'sysctl' values for the internal interfaces.
 */
void EIPM_audit_sysctl_for_internalIntfs()
{

        EIPM_DATA       *dataP;
        EIPM_INTF       *intfDataP;
        int             intfIdx;
        EIPM_SUBNET     *subnetDataP;
        int             subnetIdx;
        int             pivotIdx;
        char            lsn0IntfStr[MAX_NLEN_DEV];
        char            lsn1IntfStr[MAX_NLEN_DEV];
        char            lsn0_stackedVlanIntf[MAX_NLEN_DEV];
        char            lsn1_stackedVlanIntf[MAX_NLEN_DEV];

        memset(lsn0_stackedVlanIntf, 0, sizeof(lsn0_stackedVlanIntf));
        memset(lsn1_stackedVlanIntf, 0, sizeof(lsn1_stackedVlanIntf));

        dataP = (EIPM_DATA *)EIPM_shm_ptr;

        /* Get the internal interfaces. Currently, there are only 2: eth0.800 & eth1.801. */
        ipm_get_internal_intfs( lsn0IntfStr, lsn1IntfStr );

        if ( ( '\0' == lsn0IntfStr[0] ) && ( '\0' == lsn1IntfStr[0] ) )
        {
                LOG_ERROR( 0,
                           "ERROR(%s): Failed to determine internal interfaces (%s - %s).\n",
                           (char *)(__func__),
                           lsn0IntfStr,
                           lsn1IntfStr );
                return;
        }

	if ( IPM_SUCCESS != EIPM_check_sysctl_value( lsn0IntfStr, "ipv6", "dad_transmits", 0 ) )
	{
		(void)EIPM_set_sysctl_value( lsn0IntfStr, "ipv6", "dad_transmits", 0 );
	}

	if ( IPM_SUCCESS != EIPM_check_sysctl_value( lsn0IntfStr, "ipv6", "accept_dad", 0 ) )
	{
		(void)EIPM_set_sysctl_value( lsn0IntfStr, "ipv6", "accept_dad", 0 );
	}

	if ( IPM_SUCCESS != EIPM_check_sysctl_value( lsn1IntfStr, "ipv6", "dad_transmits", 0 ) )
	{
		(void)EIPM_set_sysctl_value( lsn1IntfStr, "ipv6", "dad_transmits", 0 );
	}

	if ( IPM_SUCCESS != EIPM_check_sysctl_value( lsn1IntfStr, "ipv6", "accept_dad", 0 ) )
	{
		(void)EIPM_set_sysctl_value( lsn1IntfStr, "ipv6", "accept_dad", 0 );
	}

        for ( ( intfIdx = 0, intfDataP = &(dataP->intf_data[0]) );
              ( intfIdx < dataP->intf_cnt );
              ( intfIdx++, intfDataP++ ) )
        {

                for ( ( subnetIdx = 0, subnetDataP = &(intfDataP->subnet[0]) );
                      ( subnetIdx < intfDataP->subnet_cnt );
                      ( subnetIdx++, subnetDataP++ ) )
                {

                        if ( IPM_IPV4 != subnetDataP->subnet_base.addrtype )
                        {
                                continue;
                        }
                        
                        for ( pivotIdx = 0; ( pivotIdx < MAX_NUM_PIVOT ); pivotIdx++ )
                        {

                                if ( subnetDataP->pivot_cnt[pivotIdx] > 0 )
                                {
                                        if (lsn0IntfStr[0] != '\0')
                                        {
                                                snprintf( lsn0_stackedVlanIntf, sizeof( lsn0_stackedVlanIntf ),
                                                        "%s.%u", lsn0IntfStr, pivotIdx );                
                                        }
                                        if (lsn1IntfStr[0] != '\0')
                                        {
                                                snprintf( lsn1_stackedVlanIntf, sizeof( lsn1_stackedVlanIntf ),
                                                        "%s.%u", lsn1IntfStr, pivotIdx );                
                                        }

                                        if ( TRUE == EIPM_GET_PROXY_SERVER_ENABLED() )
                                        {
                                                if ( IPM_SUCCESS != EIPM_check_sysctl_value( lsn0_stackedVlanIntf, "ipv4", "arp_ignore", 0 ) )
                                                {
                                                        (void)EIPM_set_sysctl_value( lsn0_stackedVlanIntf, "ipv4", "arp_ignore", 0 );
                                                }

                                                if ( IPM_SUCCESS != EIPM_check_sysctl_value( lsn1_stackedVlanIntf, "ipv4", "arp_ignore", 0 ) )
                                                {
                                                        (void)EIPM_set_sysctl_value( lsn1_stackedVlanIntf, "ipv4", "arp_ignore", 0 );
                                                }
                                        }
                                        else if ( FALSE == EIPM_GET_PROXY_SERVER_ENABLED() )
                                        {
                                                if ( IPM_SUCCESS != EIPM_check_sysctl_value( lsn0_stackedVlanIntf, "ipv4", "arp_ignore", 8 ) )
                                                {
                                                        (void)EIPM_set_sysctl_value( lsn0_stackedVlanIntf, "ipv4", "arp_ignore", 8 );
                                                }

                                                if ( IPM_SUCCESS != EIPM_check_sysctl_value( lsn1_stackedVlanIntf, "ipv4", "arp_ignore", 8 ) )
                                                {
                                                        (void)EIPM_set_sysctl_value( lsn1_stackedVlanIntf, "ipv4", "arp_ignore", 8 );
                                                }
                                        }

                                }

                        } /* end 'pivots loop' */                       

                } /* end 'subnets loop' */

        } /* end 'external interfaces loop' */

} /* end 'EIPM_audit_sysctl_for_internalIntfs' */
/**********************************************************************
 *
 * Name:	EIPM_update_subnet_route_priority
 *
 * Abstract:	Update subnet route priority
 *
 * Parameters:	subnet_ptr     - pointer to subnet 
 * 		route_priority - new route priority
 *
 * Returns:	none
 *
 **********************************************************************/
void EIPM_update_subnet_route_priority(EIPM_INTF_SPEC *intfSpecDataP, EIPM_SUBNET *subnet_ptr, EIPM_NET route_priority)
{
	int	retval;
	char	ipbuf[ IPM_IPMAXSTRSIZE ];
	char	ipbuf2[ IPM_IPMAXSTRSIZE ];

	LOG_DEBUG( 0,
       	 	"EIPM_update_subnet_route_priority route priority %d gateway %s subnet_base %s prefixlen %d vlanId %d lsn0_iface_indx %d lsn1_iface_indx %d\n",
		route_priority,
		IPM_chkipaddr2p(&subnet_ptr->gateway, ipbuf, sizeof(ipbuf)),
		IPM_chkipaddr2p(&subnet_ptr->subnet_base, ipbuf2, sizeof(ipbuf2)),
		subnet_ptr->prefixlen,
		intfSpecDataP->vlanId,
		intfSpecDataP->lsn0_iface_indx,
		intfSpecDataP->lsn1_iface_indx );		

	if ( intfSpecDataP->vlanId > (EIPM_MAX_VLANS-1))
	{
		LOG_DEBUG( 0, "EIPM_update_subnet_route_priority: vlanId(%d) is out of range(0-%d)\n", intfSpecDataP->vlanId, (EIPM_MAX_VLANS-1));
	}
	else
	{
		subnet_ptr->sub2intf_mapping[intfSpecDataP->vlanId].route_priority = route_priority;
	}

	/*
	 * Skip processing a route update on BFD service subnet as they 
	 * will be processed on a BFD transport subnet update.
	 */
        if( subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD ||
            subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR )
        {
		return;
	}

	retval = PIPM_process_route_update( PIPM_UPDATE_SUBNET_ROUTE, NULL, intfSpecDataP->vlanId, &subnet_ptr->subnet_base, subnet_ptr->prefixlen, &subnet_ptr->gateway );
	if( retval != IPM_SUCCESS )
	{
		LOG_ERROR(0, "Error: PIPM_process_route_update failure ret %d", retval );
	}

	return;
}

/**********************************************************************
 *
 * Name:        EIPM_chk_pipong_packet()
 *
 * Abstract:    Check if the packet is a valid one
 *
 * Parameters:  src_intf - expected source interface
 *              src_mac - expected source mac address
 *              pkt_ptr - packet to be checked
 *
 * Returns:     IPM_SUCCESS on success.
 *              IPM_FAILURE on failure.
 *
 **********************************************************************/
int EIPM_chk_pipong_packet(int src_intf, unsigned char * src_mac, struct eipm_packet * pkt_ptr)
{
	struct pkt_hdr *hdr_ptr;
	int checksum;

	hdr_ptr = (struct pkt_hdr *) pkt_ptr;

	if (memcmp(src_mac, hdr_ptr->eth_hdr.h_source, ETH_ALEN) != 0)
	{
		unsigned char psrc_mac[ETH_ALEN];
		memcpy(psrc_mac, hdr_ptr->eth_hdr.h_source, ETH_ALEN);
		LOG_ERROR(0, "Source MAC address mismatches, packet verification failed.\n"
			"- Packet src MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X; Expected src MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
			psrc_mac[0],psrc_mac[1],psrc_mac[2],psrc_mac[3],psrc_mac[4],psrc_mac[5],
			src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
		return IPM_FAILURE;
	}

	if (src_intf != pkt_ptr->srcintf)
	{
		LOG_ERROR(0, "Source interface mismatches, packet verification failed. Packet intf: %d, expected intf: %d",
			pkt_ptr->srcintf, src_intf);
		return IPM_FAILURE;
	}

	checksum = hdr_ptr->eipm_hdr.check;

	hdr_ptr->eipm_hdr.check = 0;

	if (checksum != ipcksm((unsigned short *) &hdr_ptr->eipm_hdr, ntohs(hdr_ptr->eipm_hdr.len)))
	{
		LOG_ERROR(0, "Checksum mismatches, packet verification failed.");
		return IPM_FAILURE;
	}

	return IPM_SUCCESS;
}

/**********************************************************************
 *
 * Name:         EIPM_disable_all_policy_routes()
 *
 * Abstract:    Disable all policy routes (except routes in table 252) on a host
 *
 * Parameters:  
 *
 * Returns:     
 *
 **********************************************************************/
void EIPM_disable_all_policy_routes()
{
        register EIPM_INTF        *data_ptr;
        register EIPM_SUBNET      *subnet_ptr;
        int intf_idx;
        int subnet_idx;

        /*
         * Loop through shared data.
         */
        for( intf_idx = 0, data_ptr = &((EIPM_DATA *)EIPM_shm_ptr)->intf_data[ 0 ];
             intf_idx < ((EIPM_DATA *)EIPM_shm_ptr)->intf_cnt;
             intf_idx++, data_ptr++ )
        {
		for(subnet_idx = 0, subnet_ptr = &data_ptr->subnet[0];
			subnet_idx < data_ptr->subnet_cnt;
			subnet_idx++, subnet_ptr++)
		{
			subnet_ptr->table_num = 0;
		}
                (void)EIPM_check_routes( data_ptr, EIPM_BASE_INTF );

        } /* end 'for each monitored interface' */

        return;

}

/**********************************************************************
*
* Name:        EIPM_is_interface_existed()
*
* Abstract:    Check the interface by name
*
* Parameters:  
*		iface_ptr - the pointer of interface name
*
* Returns:     IPM_SUCCESS on success.
*              IPM_FAILURE on failure.
*
**********************************************************************/
int EIPM_is_interface_existed(char *iface_ptr )
{
	struct ifreq ifr;
	int inetsocket = -1;

	if (NULL == iface_ptr)
	{
		LOG_ERROR(0, "EIPM_is_interface_existed, iface_ptr is NULL\n");
		return IPM_FAILURE;
	}

	if (0 == strlen(iface_ptr))
	{
		LOG_ERROR(0, "EIPM_is_interface_existed, empty interface name\n");
		return IPM_FAILURE;
	}

	inetsocket = socket(PF_INET, SOCK_DGRAM, 0);
	if (inetsocket < 0)
	{
		LOG_ERROR(0, "EIPM_is_interface_existed, failed to create socket, inetsocket=%d, errno=%d, (%s)\n",
			inetsocket, errno, strerror(errno));
		return IPM_FAILURE;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, iface_ptr, IFNAMSIZ-1);
	if (ioctl(inetsocket, SIOCGIFFLAGS, &ifr) < 0)
	{
		// Don't report assert and it will be added if it isn't existed
		LOG_ERROR(0, "EIPM_is_interface_existed, Interface %s isn't existed, errno=%d, (%s)\n",
			iface_ptr, errno, strerror(errno));
		close(inetsocket);
		return IPM_FAILURE;
	}

	close(inetsocket);
	return IPM_SUCCESS;
}

/**********************************************************************
*
* Name:        EIPM_bring_interface_up()
*
* Abstract:    Bring the interface up by name
*
* Parameters:  
*		iface_ptr - the pointer of interface name
*
* Returns:     IPM_SUCCESS on success.
*              IPM_FAILURE on failure.
*
**********************************************************************/
int EIPM_bring_interface_up(char *iface_ptr )
{
	struct ifreq ifr;
	int ret = -1;
	int inetsocket = -1;

	if (NULL == iface_ptr)
	{
		LOG_FORCE(0, "EIPM_bring_interface_up, iface_ptr is NULL\n");
		return IPM_FAILURE;
	}

	if (0 == strlen(iface_ptr))
	{
		LOG_FORCE(0, "EIPM_bring_interface_up, empty interface name\n");
		return IPM_FAILURE;
	}
	
	inetsocket = socket(PF_INET, SOCK_DGRAM, 0);
	if (inetsocket < 0)
	{
		LOG_ERROR(0, "EIPM_bring_interface_up, failed to create socket, inetsocket=%d, errno=%d, (%s)\n",
			inetsocket, errno, strerror(errno));
		return IPM_FAILURE;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, iface_ptr, IFNAMSIZ-1);
	ret = ioctl(inetsocket, SIOCGIFFLAGS, &ifr);
	if (ret < 0)
	{
		LOG_FORCE(0, "EIPM_bring_interface_up, failed to get tunnel(%s) flag, ret=%d, errno=%d,(%s)\n",
			iface_ptr, ret,  errno, strerror(errno));
		close(inetsocket);
		return IPM_FAILURE;
	}

	if (!(ifr.ifr_flags & IFF_UP))
	{
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		ret = ioctl(inetsocket, SIOCSIFFLAGS, &ifr);
		if (ret < 0)
		{
			LOG_FORCE(0, "EIPM_bring_interface_up, failed to make tunnel(%s) up, ret=%d, errno=%d,(%s)\n",
				iface_ptr, ret,  errno, strerror(errno));
			close(inetsocket);
			return IPM_FAILURE;
		}
	}

	close(inetsocket);
	return IPM_SUCCESS;
}	

/**********************************************************************
*
* Name:        EIPM_check_gre_tunnel_intf()
*
* Abstract:    Check all GRE tunnel interfaces
*
* Parameters:  
*
* Returns:     IPM_SUCCESS on success.
*              IPM_FAILURE on failure.
*              
*
**********************************************************************/
int EIPM_check_gre_tunnel_intf(void)
{
	if (NULL == EIPM_shm_ptr)
	{
		// Nothing can be audit
		return IPM_SUCCESS;
	}

	int i = -1;
	int match_cnt = 0;
	int ret = -1;
	int inetsocket = -1;
	int ret_val = IPM_SUCCESS;
	struct ifreq ifr;
	struct ip_tunnel_parm ip_gre_tunnel_parm;
	char tunnel_name[IFNAMSIZ];
	IPM_TUNNEL_DATA *tunnel_data_ptr = NULL;
	EIPM_DATA      *data_ptr = (EIPM_DATA *)EIPM_shm_ptr;

	inetsocket = socket(PF_INET, SOCK_DGRAM, 0);
	if (inetsocket < 0)
	{
		LOG_ERROR(0, "EIPM_check_gre_tunnel_intf, failed to create socket, inetsocket=%d, errno=%d,(%s)\n",
			inetsocket, errno, strerror(errno));
		return IPM_FAILURE;
	}

	for (i = 0, tunnel_data_ptr = &data_ptr->tunnel_data[0];	
		i <= MAX_NUM_PIVOT;
		i++, tunnel_data_ptr++)
	{

		// Tunnel id 0 isn't used
		if (0 == tunnel_data_ptr->id)
		{
			continue;
		}

		if (match_cnt == data_ptr->tunnel_cnt)
		{
			// All valid tunnels have been audited
			break;
		}
		// Got valid tunnel
		match_cnt++;

		memset(&ifr, 0, sizeof(ifr));
        	memset(&ip_gre_tunnel_parm, 0, sizeof(ip_gre_tunnel_parm));
        	memset(tunnel_name, 0, sizeof(tunnel_name));
        	snprintf(tunnel_name, sizeof(tunnel_name), "%s%d", PIVOT_PREFIX, tunnel_data_ptr->id);
		strncpy(ifr.ifr_name, tunnel_name,  IFNAMSIZ-1);
        	ifr.ifr_ifru.ifru_data = (void*)&ip_gre_tunnel_parm;
		ret = ioctl(inetsocket, SIOCGETTUNNEL, &ifr);
		if (ret < 0)
		{
			LOG_ERROR(0, "EIPM_check_gre_tunnel_intf, failed to get tunnel(%s), ret=%d, errno=%d,(%s)\n",
				tunnel_name, ret,  errno, strerror(errno));
			if (errno == ENODEV)
			{
				// There is no this device and add it 
				ret = EIPM_add_gre_tunnel( tunnel_data_ptr->id,
					tunnel_data_ptr->ttl,
					tunnel_data_ptr->key,
					tunnel_data_ptr->mode,
					tunnel_data_ptr->lepip,
					tunnel_data_ptr->repip);
				if (ret < 0)
				{
					LOG_FORCE(0, "EIPM_check_gre_tunnel_intf, failed to add  tunnel(%s), ret=%d, errno=%d,(%s)\n",
						tunnel_name, ret,  errno, strerror(errno));
					// Don't return and try next tunnel
					ret_val = IPM_FAILURE;
					continue;
				}

				ret = EIPM_bring_interface_up(tunnel_name);
				if (ret < 0)
				{
					LOG_FORCE(0, "EIPM_check_gre_tunnel_intf, failed to make tunnel(%s) up, ret=%d, errno=%d,(%s)\n",
						tunnel_name, ret,  errno, strerror(errno));
					ret_val = IPM_FAILURE;
				}

				 EIPM_update_tunnel_intf_index(tunnel_data_ptr->id, IPM_ADD_TUNNEL);
				// Try next tunnel interface
				continue;
			}
			else
			{
				// Other failed cases and continue to try next tunnel interface
				ret_val = IPM_FAILURE;
				continue;
			}
		}
		
		/*
		 * Until now, find the tunnel interface by name
		 * make sure it is our expect tunnel interface 
		 * by comparing the shared memory data with system parameters
		 */
		if ( ( (tunnel_data_ptr->key != ntohl(ip_gre_tunnel_parm.i_key)) 
				|| (tunnel_data_ptr->key != ntohl(ip_gre_tunnel_parm.o_key)) )
			|| (tunnel_data_ptr->ttl != ip_gre_tunnel_parm.iph.ttl)
			|| (tunnel_data_ptr->mode != ip_gre_tunnel_parm.iph.protocol)
			|| (tunnel_data_ptr->lepip.ipaddr[0] != ip_gre_tunnel_parm.iph.saddr)
			|| (tunnel_data_ptr->repip.ipaddr[0] != ip_gre_tunnel_parm.iph.daddr)
		   )
		{
			LOG_ERROR(0, 
				"EIPM_check_gre_tunnel_intf, The tunnel (%s) parameter(s) mismatch\n"
				"\tEIPM  key=%d vs system i_key=%d, o_key=%d\n"
				"\tEIPM  ttl=%d vs system ttl=%d\n"
				"\tEIPM  mode=%d vs system protocol=%d\n"
				"\tEIPM  local_ip=0x%x, remote_ip=0x%x vs system saddr=0x%x, daddr=0x%x\n",
				tunnel_name,
				tunnel_data_ptr->key, ntohl(ip_gre_tunnel_parm.i_key), ntohl(ip_gre_tunnel_parm.o_key),
				tunnel_data_ptr->ttl, ip_gre_tunnel_parm.iph.ttl,
				tunnel_data_ptr->mode, ip_gre_tunnel_parm.iph.protocol,
				tunnel_data_ptr->lepip.ipaddr[0], tunnel_data_ptr->repip.ipaddr[0], 
				ip_gre_tunnel_parm.iph.saddr, ip_gre_tunnel_parm.iph.daddr);

			/*
			 * Update the tunnel with correct parameters
			 */
			ret = EIPM_update_gre_tunnel(tunnel_data_ptr->id,
				tunnel_data_ptr->ttl,
				tunnel_data_ptr->key,
				tunnel_data_ptr->mode,
				tunnel_data_ptr->lepip,
				tunnel_data_ptr->repip);
			if (ret < 0)
			{
				LOG_FORCE(0, "EIPM_check_gre_tunnel_intf, failed to update  tunnel(%s), ret=%d, errno=%d,(%s)\n",
					 tunnel_name, ret,  errno, strerror(errno));
				ret_val = IPM_FAILURE;
				continue;
			}
		}
		else
		{
			LOG_OTHER(0, 
				"EIPM_check_gre_tunnel_intf, The tunnel (%s) is there\n"
				"\tEIPM  key=%d vs system i_key=%d, o_key=%d\n"
				"\tEIPM  ttl=%d vs system ttl=%d\n"
				"\tEIPM  mode=%d vs system protocol=%d\n"
				"\tEIPM  local_ip=0x%x, remote_ip=0x%x vs system saddr=0x%x, daddr=0x%x\n",
				tunnel_name,
				tunnel_data_ptr->key, ntohl(ip_gre_tunnel_parm.i_key), ntohl(ip_gre_tunnel_parm.o_key),
				tunnel_data_ptr->ttl, ip_gre_tunnel_parm.iph.ttl,
				tunnel_data_ptr->mode, ip_gre_tunnel_parm.iph.protocol,
				tunnel_data_ptr->lepip.ipaddr[0], tunnel_data_ptr->repip.ipaddr[0], 
				ip_gre_tunnel_parm.iph.saddr, ip_gre_tunnel_parm.iph.daddr);
		}

		// Make sure the interface is up
		ret = EIPM_bring_interface_up(tunnel_name);
		if (ret < 0)
		{
			LOG_FORCE(0, "EIPM_check_gre_tunnel_intf, failed to make tunnel(%s) up, ret=%d, errno=%d,(%s)\n",
				tunnel_name, ret,  errno, strerror(errno));
			ret_val = IPM_FAILURE;
		}

		// Update tunnel interface index forcefully
		EIPM_update_tunnel_intf_index(tunnel_data_ptr->id, IPM_ADD_TUNNEL);
	}

	close(inetsocket);
	return ret_val;
}

/**********************************************************************
*
* Name:        EIPM_add_gre_tunnel()
*
* Abstract:    Add GRE tunnel according to input
*
* Parameters:  
*		tunnel_id -  tunnel id
*		ttl - hop limit
*		key - GRE Key for input and output
*		mode - GRE or IPIP
*		local_ip - local end pointer IP 
*		remote_ip - remote end pointer IP
*
* Returns:     IPM_SUCCESS on success.
*              IPM_FAILURE on failure.
*
**********************************************************************/
int EIPM_add_gre_tunnel( 
	unsigned char tunnel_id, unsigned char ttl, 
	unsigned int key, unsigned char mode,
	IPM_IPADDR local_ip, IPM_IPADDR remote_ip)
{
	int ret = -1;
	int inetsocket = -1;
	struct ifreq ifr;
	struct ip_tunnel_parm ip_gre_tunnel_parm;
	char tunnel_name[IFNAMSIZ];
	
	if ( (tunnel_id >= MAX_NUM_PIVOT)
		|| (key >= MAX_NUM_PIVOT)
		|| ( mode != IPPROTO_GRE)
	   )
	{
		LOG_FORCE(0, "EIPM_add_gre_tunnel: invalid tunnel_id(%d) or key(%d) or mode(%d)\n",
			tunnel_id, key, mode);
		return IPM_FAILURE;
	}

	inetsocket = socket(PF_INET, SOCK_DGRAM, 0);
	if (inetsocket < 0)
	{
		LOG_ERROR(0, "EIPM_add_gre_tunnel, failed to create socket, inetsocket=%d, errno=%d, (%s)\n",
			inetsocket, errno, strerror(errno));
		return IPM_FAILURE;
	}

	memset(&ifr, 0, sizeof(ifr));
	memset(&ip_gre_tunnel_parm, 0, sizeof(ip_gre_tunnel_parm));
	memset(tunnel_name, 0, sizeof(tunnel_name));
	snprintf(tunnel_name, sizeof(tunnel_name), "%s%d", PIVOT_PREFIX, tunnel_id);

	// It must gre0
	strncpy(ifr.ifr_name, "gre0", IFNAMSIZ-1);

        ifr.ifr_ifru.ifru_data = (void*)&ip_gre_tunnel_parm;
	strncpy(ip_gre_tunnel_parm.name, tunnel_name, IFNAMSIZ-1);
	ip_gre_tunnel_parm.i_flags = ip_gre_tunnel_parm.i_flags | GRE_KEY;
	ip_gre_tunnel_parm.o_flags = ip_gre_tunnel_parm.o_flags | GRE_KEY;
	ip_gre_tunnel_parm.i_key = htonl(key);
	ip_gre_tunnel_parm.o_key = htonl(key);
	ip_gre_tunnel_parm.iph.ihl = 5;
	ip_gre_tunnel_parm.iph.version = 4;
	ip_gre_tunnel_parm.iph.ttl = ttl;
	ip_gre_tunnel_parm.iph.protocol = mode;
	//ip_tunnel_parm.iph.frag_off = htons(IP_DF);
	ip_gre_tunnel_parm.iph.saddr = local_ip.ipaddr[0];
	ip_gre_tunnel_parm.iph.daddr = remote_ip.ipaddr[0];
	ret = ioctl(inetsocket, SIOCADDTUNNEL, &ifr);
	if (ret < 0)
	{
		LOG_FORCE(0, "EIPM_add_gre_tunnel, failed to add tunnel(%s), ret=%d, errno=%d,(%s)\n",
			tunnel_name, ret,  errno, strerror(errno));
		close(inetsocket);
		return IPM_FAILURE;
	}

	close(inetsocket);
	return IPM_SUCCESS;
}


/**********************************************************************
*
* Name:        EIPM_update_gre_tunnel()
*
* Abstract:    Update GRE tunnel according to input
*
* Parameters:  
*		tunnel_id -  tunnel id
*		ttl - hop limit
*		key - GRE Key for input and output
*		mode - GRE or IPIP
*		local_ip - local end pointer IP 
*		remote_ip - remote end pointer I
*
* Returns:     IPM_SUCCESS on success.
*              IPM_FAILURE on failure.
*
**********************************************************************/
int EIPM_update_gre_tunnel( 
	unsigned char tunnel_id, unsigned char ttl, 
	unsigned int key, unsigned char mode,
	IPM_IPADDR local_ip, IPM_IPADDR remote_ip)
{
	int ret = -1;
	int inetsocket = -1;
	struct ifreq ifr;
	struct ip_tunnel_parm ip_gre_tunnel_parm;
	char tunnel_name[IFNAMSIZ];
	
	if ( (tunnel_id >= MAX_NUM_PIVOT)
		|| (key >= MAX_NUM_PIVOT)
		|| ( mode != IPPROTO_GRE)
	   )
	{
		LOG_FORCE(0, "EIPM_update_gre_tunnel, invalid tunnel_id(%d) or key(%d) or mode(%d)\n",
			tunnel_id, key, mode);
		return IPM_FAILURE;
	}

	inetsocket = socket(PF_INET, SOCK_DGRAM, 0);
	if (inetsocket < 0)
	{
		LOG_ERROR(0, "EIPM_update_gre_tunnel, failed to create socket, inetsocket=%d, errno=%d, (%s)\n",
			inetsocket, errno, strerror(errno));
		return IPM_FAILURE;
	}

	memset(&ifr, 0, sizeof(ifr));
	memset(&ip_gre_tunnel_parm, 0, sizeof(ip_gre_tunnel_parm));
	memset(tunnel_name, 0, sizeof(tunnel_name));

	snprintf(tunnel_name, sizeof(tunnel_name), "%s%d", PIVOT_PREFIX, tunnel_id);
	strncpy(ifr.ifr_name, tunnel_name, IFNAMSIZ-1);

        ifr.ifr_ifru.ifru_data = (void*)&ip_gre_tunnel_parm;
	strncpy(ip_gre_tunnel_parm.name, tunnel_name, IFNAMSIZ-1);
	ip_gre_tunnel_parm.i_flags = ip_gre_tunnel_parm.i_flags | GRE_KEY;
	ip_gre_tunnel_parm.o_flags = ip_gre_tunnel_parm.o_flags | GRE_KEY;
	ip_gre_tunnel_parm.i_key = htonl(key);
	ip_gre_tunnel_parm.o_key = htonl(key);
	ip_gre_tunnel_parm.iph.ihl = 5;
	ip_gre_tunnel_parm.iph.version = 4;
	ip_gre_tunnel_parm.iph.ttl = ttl;
	ip_gre_tunnel_parm.iph.protocol = mode;
	//ip_tunnel_parm.iph.frag_off = htons(IP_DF);
	ip_gre_tunnel_parm.iph.saddr = local_ip.ipaddr[0];
	ip_gre_tunnel_parm.iph.daddr = remote_ip.ipaddr[0];
	ret = ioctl(inetsocket, SIOCCHGTUNNEL, &ifr);
	if (ret < 0)
	{
		LOG_FORCE(0, "EIPM_update_gre_tunnel, failed to add tunnel(%s), ret=%d, errno=%d,(%s)\n",
			tunnel_name, ret,  errno, strerror(errno));
		close(inetsocket);
		return IPM_FAILURE;
	}

	close(inetsocket);
	return IPM_SUCCESS;
}

/**********************************************************************
*
* Name:        EIPM_delete_gre_tunnel()
*
* Abstract:    Delete GRE tunnel interface based on name
*
* Parameters:  
*		tunnel_id -  tunnel id
*
* Returns:     IPM_SUCCESS on success.
*              IPM_FAILURE on failure.
*
**********************************************************************/
int EIPM_delete_gre_tunnel(unsigned char tunnel_id)
{
	int ret = -1;
	int inetsocket = -1;
	struct ifreq ifr;
	struct ip_tunnel_parm ip_gre_tunnel_parm;
	char tunnel_name[IFNAMSIZ];
	
	if (tunnel_id >= MAX_NUM_PIVOT) 
	{
		LOG_ERROR(0, "EIPM_delete_gre_tunnel: invalid tunnel_id(%d)\n", tunnel_id);
		return IPM_FAILURE;
	}

	inetsocket = socket(PF_INET, SOCK_DGRAM, 0);
	if (inetsocket < 0)
	{
		LOG_ERROR(0, "EIPM_delete_gre_tunnel, failed to create socket, inetsocket=%d, errno=%d, (%s)\n",
			inetsocket, errno, strerror(errno));
		return IPM_FAILURE;
	}

	memset(&ifr, 0, sizeof(ifr));
        memset(&ip_gre_tunnel_parm, 0, sizeof(ip_gre_tunnel_parm));
        memset(tunnel_name, 0, sizeof(tunnel_name));
        snprintf(tunnel_name, sizeof(tunnel_name), "%s%d", PIVOT_PREFIX, tunnel_id);

	strncpy(ifr.ifr_name, tunnel_name,  IFNAMSIZ-1);
        ifr.ifr_ifru.ifru_data = (void*)&ip_gre_tunnel_parm;
	strncpy(ip_gre_tunnel_parm.name, tunnel_name, IFNAMSIZ-1);
	ret = ioctl(inetsocket, SIOCDELTUNNEL, &ifr);
	if (ret < 0)
	{
		LOG_FORCE(0, "EIPM_delete_gre_tunnel: failed to delete tunnel(%s), ret=%d, errno=%d,(%s)\n",
			tunnel_name, ret,  errno, strerror(errno));
		close(inetsocket);
		return IPM_FAILURE;
	}

	close(inetsocket);
	return IPM_SUCCESS;
}

/**********************************************************************
 *
 * Name:        EIPM_dump_tunnel_data()
 *
 * Abstract:    dump tunnel data if it has
 *
 * Parameters:  None
 *
 *  Returns:	None
 *
 **********************************************************************/
void EIPM_dump_tunnel_data(void)
{
	if (NULL == EIPM_shm_ptr)
	{
		return;
	}
	int	i = -1;
	int	match_cnt = 0;
	char	local_ip_buf[ IPM_IPMAXSTRSIZE ];
	char	remote_ip_buf[ IPM_IPMAXSTRSIZE ];
	IPM_TUNNEL_DATA *tunnel_data_ptr = NULL;
	EIPM_DATA      *data_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	LOG_FORCE(0, "EIPM tunnel data, total counter = %d\n", data_ptr->tunnel_cnt);
	for ( i = 0, tunnel_data_ptr = &data_ptr->tunnel_data[0];
		i <= MAX_NUM_PIVOT;
		i++, tunnel_data_ptr++)
	{
		// Tunnel id 0 isn't used
		if (0 == tunnel_data_ptr->id)
		{
			continue;
		}

		if (match_cnt == data_ptr->tunnel_cnt)
		{
			// All valid tunnels have been audited
			break;
		}
		// Got valid tunnel
		match_cnt++;

		memset(&local_ip_buf, 0, IPM_IPMAXSTRSIZE);
		memset(&remote_ip_buf, 0, IPM_IPMAXSTRSIZE);
		LOG_FORCE(0, " %d. Tunnel: id=%d, ttl=%d, key=%d, mode=%d, lepip=%s, repip=%s, name=%s\n",
			match_cnt, 
			tunnel_data_ptr->id,
			tunnel_data_ptr->ttl,
			tunnel_data_ptr->key,
			tunnel_data_ptr->mode,
			(tunnel_data_ptr->lepip.addrtype != 0 ? IPM_chkipaddr2p(&tunnel_data_ptr->lepip, local_ip_buf, sizeof(local_ip_buf)) : "empty"),
			(tunnel_data_ptr->repip.addrtype != 0 ? IPM_chkipaddr2p(&tunnel_data_ptr->repip, remote_ip_buf, sizeof(remote_ip_buf)) : "empty"),
			(tunnel_data_ptr->name[0] != 0 ? tunnel_data_ptr->name : "empty")
		)
	}
}

/**********************************************************************
 *
 * Name:        EIPM_update_tunnel_intf_index()
 *
 * Abstract:    Once the pivotX tunnel interface is added or deleted, then the index could be changed
 *		This function will update all subnets under the interface which has tunnel passed
 *
 * Parameters:  
 *		tunnel_id - the tunnel id
 *  Returns:	None
 *
 **********************************************************************/
void EIPM_update_tunnel_intf_index(unsigned char tunnel_id, int isAddTunnel)
{
	if (NULL == EIPM_shm_ptr)
	{
		return;
	}

	if (tunnel_id >= MAX_NUM_PIVOT) 
	{
		LOG_ERROR(0, "EIPM_update_tunnel_intf_index: invalid tunnel_id(%d)\n", tunnel_id);
		return;
	}

	int	intf_cnt = -1;
	int	sub_cnt = -1;
	EIPM_DATA	*data_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	EIPM_INTF	*intf_ptr = NULL;
	EIPM_SUBNET	*subn_ptr = NULL; 	
	char	tunnel_name[MAX_NLEN_DEV];
	int	tunnel_index = -1;
	int inetsocket = -1;

	/*
	 * If isAddTunnel is IPM_ADD_TUNNEL, then the tunnel interface is added.
	 * Try to get the tunnel device index and update it in shared memory
	 */
	if (IPM_ADD_TUNNEL == isAddTunnel)
	{
		inetsocket = socket(PF_INET, SOCK_DGRAM, 0);
		if (inetsocket < 0)
		{
			LOG_FORCE(0, "EIPM_update_tunnel_intf_index: failed to create socket, inetsocket=%d, errno=%d,(%s)\n",
				inetsocket, errno, strerror(errno));
			// It will be updated when the next audit is occured
			return;
		}
		else
		{
			memset(tunnel_name, 0, MAX_NLEN_DEV);
			snprintf(tunnel_name, MAX_NLEN_DEV, "%s%d", PIVOT_PREFIX, tunnel_id);
			tunnel_index = ipm_get_ifindex(inetsocket, tunnel_name);
			if (tunnel_index < 0)
			{
				LOG_FORCE(0, "EIPM_update_tunnel_intf_index: failed to get index of tunnel (%s), ret=%d, errno=%d,(%s)\n",
					tunnel_name, tunnel_index,  errno, strerror(errno));
				return;
			}
		}
	}
	// else it is IPM_DEL_TUNNEL and use -1 to update shared memory because the tunnel is deleted
	
	for ( intf_cnt = 0, intf_ptr = &data_ptr->intf_data[0];
		intf_cnt < data_ptr->intf_cnt;
		intf_cnt++, intf_ptr++)
	{
		if (FALSE == intf_ptr->is_tunnel_intf)
		{
			continue;
		}

		for (sub_cnt = 0, subn_ptr = &intf_ptr->subnet[0];
			sub_cnt < intf_ptr->subnet_cnt;
			sub_cnt++, subn_ptr++)
		{
			subn_ptr->pivot_iface_indx[0][tunnel_id] = tunnel_index;
		}
	}

	if (inetsocket >= 0)
	{
		close(inetsocket);
	}
	return;
}
