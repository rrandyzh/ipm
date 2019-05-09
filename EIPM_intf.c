
/**********************************************************************
 *
 * File:
 *	EIPM_intf.c
 *
 * Functions in this file:
 *	EIPM_base_update()	- Called to provide base info.
 *	EIPM_intf_update()	- Called to provide interface info.
 *	EIPM_arp_update()	- Called to update ARP info.
 *	EIPM_route_update()	- Called to update static route info.
 *	EIPM_proxy_server_update()- Called to update proxy server info.
 *	EIPM_wcnp_update()	- Called to update WCNP IP info
 *
 **********************************************************************/

#include "EIPM_include.h"
#include "EIPM_bfd.h"
#include "nma_route.h"
#include "ipm_util.h"
	


/**********************************************************************
 *
 * Name:	EIPM_base_update()
 *
 * Abstract:	Called when IPM receives a message with data for 
 *		a base interface.
 *
 * Parameters:	msg_ptr - pointer to data message
 *		type    - whether adding or deleting interface
 *		resp    - pointer to text string response to user
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/


int EIPM_base_update( register struct cmd_base_iface *msg_ptr,
                      EIPM_ADD_DEL type, char *resp )

{
	if( type == EIPM_ADD )
	{
	        int 	i;
	        int 	retval;
		EIPM_DATA	*data_ptr;
		EIPM_INTF	*intf_ptr;
		struct ifreq	ifr;
		int		sock;
		int 		intf_idx;
		int		upd_shared_memory = 0;

		INTF_ACTION	intf_action;
		char		*iface0_base_ptr = NULL;
		char		iface0_base[MAX_NLEN_DEV];
		char		*iface1_base_ptr = NULL;
		char		iface1_base[MAX_NLEN_DEV];
		char            lsn0_internalIntf[MAX_NLEN_DEV];
		char            lsn1_internalIntf[MAX_NLEN_DEV];


		if( msg_ptr->subnet_type != IPM_SUBNET_EXTERNAL &&
		    msg_ptr->subnet_type != IPM_SUBNET_BOTH )
		{
			return IPM_SUCCESS;
		}

		/*
		 * Add new interface if needed
		 */

		/* Check for EIPM memory */
		if( EIPM_shm_ptr == NULL )
		{
			snprintf(resp, REPLY_TEXT, 
				"EIPM Base Config Failure: Shared memory null, Iface %s - %s\n", 
				( msg_ptr->base_if[0][0] != 0 ? msg_ptr->base_if[0] : "empty" ),
				( msg_ptr->base_if[1][0] != 0 ? msg_ptr->base_if[1] : "empty" ));

			LOG_ERROR(0, resp);

			return IPM_FAILURE;
		}

		data_ptr = (EIPM_DATA *)EIPM_shm_ptr;

		/* Derive base iface */
		strncpy(iface0_base, msg_ptr->base_if[0], MAX_NLEN_DEV);
		iface0_base_ptr = strtok(iface0_base, ":");

		if( iface0_base_ptr == NULL )
		{
			iface0_base_ptr = iface0_base;
		}

		strncpy(iface1_base, msg_ptr->base_if[1], MAX_NLEN_DEV);
		iface1_base_ptr = strtok(iface1_base, ":");

		if( iface1_base_ptr == NULL )
		{
			iface1_base_ptr = iface1_base;
		}

		for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
		     intf_idx < data_ptr->intf_cnt;
		     intf_idx++, intf_ptr++ )
		{
			upd_shared_memory = 0;
			intf_action = EIPM_intf_match(
					intf_ptr,
					iface0_base_ptr,
					iface1_base_ptr,
					type,
					msg_ptr->redundancy_mode
				);

			switch ( intf_action )
			{
				case INTF_FAILURE:
					snprintf(
						resp, REPLY_TEXT,
						"%s() failure: interface pointer failure\n",
						__FUNCTION__
					);

					return IPM_FAILURE;
				case INTF_CONTINUE:
					continue;
				case INTF_UPD_SHARED_MEMORY:
					upd_shared_memory = 1;
				default:
					/* match */
					if ( ( intf_ptr->lsn0_baseif[0] != 0 && intf_ptr->lsn1_baseif[0] == 0 ) ||
						( intf_ptr->lsn0_baseif[0] == 0 && intf_ptr->lsn1_baseif[0] != 0 ) )
					{
						EIPM_SUBNET	*bfd_subnet_ptr;
						int		bfd_subnet_idx;
						int		none_cnt = 0;
						int		other_cnt = 0;
						int		bfd_cnt = 0;

						for ( bfd_subnet_idx = 0, bfd_subnet_ptr = &intf_ptr->subnet[0];
							bfd_subnet_idx < intf_ptr->subnet_cnt;
							bfd_subnet_idx++, bfd_subnet_ptr++ )
						{
							if ( (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT ||
								 (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD ||
								 (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR )
							{
								bfd_cnt++;
							}
							else if ( (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_NONE ||
							          (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP )
							{
								none_cnt++;
							}
							else
							{
								other_cnt++;
							}
						}

						if ( msg_ptr->redundancy_mode == IPM_RED_NONE || msg_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP )
						{
							if ( bfd_cnt > 0 || other_cnt > 0 )
							{
								/* reset b/c if it is the last interface value will be set */
								upd_shared_memory = 0;
								continue;
							}
						}
						else
						{
							if ( none_cnt > 0 )
							{
								/* reset b/c if it is the last interface value will be set */
								upd_shared_memory = 0;
								continue;
							}
						}
					}

					if ( upd_shared_memory )
					{
						/* switch break */
						break;
					}
					else
					{
						return IPM_SUCCESS;
					}
			} /* switch */

			if ( upd_shared_memory )
			{
				/* for loop break */
				break;
			}
		}

		if( data_ptr->intf_cnt == EIPM_MAX_EXT_SUB )
		{
			snprintf(resp, REPLY_TEXT,
				"EIPM Base Config Failure: Can't add Iface %s/%s, already at Max %d\n",
				( strlen( iface0_base_ptr ) > 0 ? iface0_base_ptr : "empty" ),
				( strlen( iface1_base_ptr ) > 0 ? iface1_base_ptr : "empty" ),
				EIPM_MAX_EXT_SUB
			);

			LOG_ERROR(0, resp);

			return IPM_TOOMUCHBIF;
		}

		if ( !upd_shared_memory )
		{
			/* Add new interface */
			intf_ptr = &data_ptr->intf_data[data_ptr->intf_cnt];

			memset(intf_ptr, 0, sizeof(EIPM_INTF));
		}
		else
		{
			intf_ptr = &data_ptr->intf_data[intf_idx];
		}

		strcpy(intf_ptr->lsn0_baseif, iface0_base_ptr);
		strcpy(intf_ptr->lsn1_baseif, iface1_base_ptr);
		ipm_get_internal_intfs(lsn0_internalIntf, lsn1_internalIntf);
		if ( ( '\0' == lsn0_internalIntf[0] ) && ( '\0' == lsn1_internalIntf[0]) )
		{
			LOG_FORCE( 0,
				"ERROR: Failed to determine internal interfaces (%s - %s).\n",
				lsn0_internalIntf, lsn1_internalIntf);
			return IPM_FAILURE; 
		}

		if ( !upd_shared_memory )
		{
			if ( (strcmp(lsn0_internalIntf, intf_ptr->lsn0_baseif) == 0) &&
				(strcmp(lsn1_internalIntf, intf_ptr->lsn1_baseif) == 0))
			{
				intf_ptr->specData.monitor        = EIPM_MONITOR_ROUTE;
			}
			else 
			{
				intf_ptr->specData.monitor        = EIPM_MONITOR_SNDPKT;
			}
			intf_ptr->specData.msg_rcvd       = FALSE;
			intf_ptr->specData.dir            = LSN02LSN1;
			intf_ptr->specData.state          = NORMAL_STATE;
			intf_ptr->specData.status         = EIPM_ONLINE;
			if ( strlen( iface0_base_ptr ) > 0 )
			{
				intf_ptr->specData.preferred_side = LSN0;
			}
			else
			{
				intf_ptr->specData.preferred_side = LSN1;
			}
			intf_ptr->specData.recovery_state = NULL_REC_STATE;
			intf_ptr->specData.seqno          = 0;
			intf_ptr->specData.counter        = 0;
			intf_ptr->specData.lsn0_arpsock   = -1;
			intf_ptr->specData.lsn1_arpsock   = -1;
			intf_ptr->specData.lsn0_v6arpsock = -1;
			intf_ptr->specData.lsn1_v6arpsock = -1;
			intf_ptr->specData.lsn0_garpsock   = -1;
			intf_ptr->specData.lsn1_garpsock   = -1;
			intf_ptr->specData.lsn0_v6garpsock = -1;
			intf_ptr->specData.lsn1_v6garpsock = -1;
			intf_ptr->specData.baseIntfIdx     = data_ptr->intf_cnt;
			/* Init EIPM pivot sockets when interface is added */
			EIPM_init_pivot_sock(intf_ptr);
		}

		intf_ptr->extnIntfIdx              = -1;

		/* Querying interface information.  */
		sock = socket(PF_INET, SOCK_RAW, htons(ETH_P_IP));

		if( sock < 0 )
		{
			snprintf(resp, REPLY_TEXT, 
				"EIPM Base Config Failure: Failed to open raw socket for interface=%s, errno %d",
				( intf_ptr->lsn0_baseif[0] != 0 ? intf_ptr->lsn0_baseif : intf_ptr->lsn1_baseif ),
				errno
			);

			LOG_ERROR(0, resp);
		
			memset(intf_ptr, 0, sizeof(EIPM_INTF));
		
			return IPM_FAILURE;
		}
	
		/*
		 * Get interface index for LSN0 interface.  Use the
		 * base interface name (all aliases have the same
		 * interface index).
		 */
		if ( strlen( iface0_base_ptr ) > 0 )
		{
			if ( !upd_shared_memory )
			{
				memset(&ifr, 0, sizeof(ifr));

				ifr.ifr_addr.sa_family = PF_INET;
				strncpy(ifr.ifr_name, intf_ptr->lsn0_baseif, IFNAMSIZ-1);

				retval = ioctl(sock, SIOCGIFINDEX, &ifr);

				if( retval < 0 )
				{
					snprintf(resp, REPLY_TEXT, 
						"EIPM Base Config Failure: (SIOCGIFINDEX) failed for interface=%s, retval %d, errno %d",
						intf_ptr->lsn0_baseif, retval, errno);

					LOG_ERROR(0, resp);
		
					/*
					 * Need to clean up this entry since we
					 * are abandoning it.
					 */
					memset(intf_ptr, 0, sizeof(*intf_ptr));

					(void)close(sock);

					return IPM_FAILURE;
				}

				intf_ptr->specData.lsn0_iface_indx = ifr.ifr_ifindex;

				/* Get MAC address */
				retval = ioctl(sock, SIOCGIFHWADDR, &ifr);

				if( retval < 0 )
				{
					snprintf(resp, REPLY_TEXT, 
						"EIPM Base Config Failure: ioctl(SIOCGIFHWADDR) failed for interface=%s, retval %d, errno %d",
						intf_ptr->lsn0_baseif, retval, errno);

					LOG_ERROR(0, resp);
		
					/*
					 * Need to clean up this entry since we
					 * are abandoning it.
					 */
					memset(intf_ptr, 0, sizeof(*intf_ptr));

					(void)close(sock);

					return IPM_FAILURE;
				}
	
				/* Store MAC address. This is the same for all aliases. */
				memcpy(intf_ptr->lsn0_hwaddr,
				       ifr.ifr_ifru.ifru_hwaddr.sa_data,
				       ETH_ALEN);
			}
		}
	
		/*
		 * Get interface index for LSN1 interface.  Use the
		 * base interface name (all aliases have the same
		 * interface index).
		 */
		if ( strlen( iface1_base_ptr ) > 0 )
		{
			memset(&ifr, 0, sizeof(ifr));
			ifr.ifr_addr.sa_family = PF_INET;
			strncpy(ifr.ifr_name, intf_ptr->lsn1_baseif, IFNAMSIZ-1);

			retval = ioctl(sock, SIOCGIFINDEX, &ifr);

			if( retval < 0 )
			{
				snprintf(resp, REPLY_TEXT, 
					"EIPM Base Config Failure: ioctl(SIOCGIFINDEX) failed for interface=%s, retval %d, errno %d",
					intf_ptr->lsn1_baseif, retval, errno);

				LOG_ERROR(0, resp);

				if ( !upd_shared_memory )
				{
					/*
					 * Need to clean up this entry since we
					 * are abandoning it.
					 */
					memset(intf_ptr, 0, sizeof(*intf_ptr));
				}
				else
				{
					memset(intf_ptr->lsn1_baseif, 0, sizeof(intf_ptr->lsn1_baseif));
				}

				(void)close(sock);

				return IPM_FAILURE;
			}

			intf_ptr->specData.lsn1_iface_indx = ifr.ifr_ifindex;

			/* Get MAC address */
			retval = ioctl(sock, SIOCGIFHWADDR, &ifr);

			if( retval < 0 )
			{
				snprintf(resp, REPLY_TEXT, 
					"EIPM Base Config Failure: ioctl(SIOCGIFHWADDR) failed for interface=%s, retval %d, errno %d",
					intf_ptr->lsn1_baseif, retval, errno );

				LOG_ERROR(0, resp);
		
				if ( !upd_shared_memory )
				{
					/*
					 * Need to clean up this entry since we
					 * are abandoning it.
					 */
					memset(intf_ptr, 0, sizeof(*intf_ptr));
				}
				else
				{
					memset(intf_ptr->lsn1_baseif, 0, sizeof(intf_ptr->lsn1_baseif));
					intf_ptr->specData.lsn1_iface_indx = 0;
				}

				close(sock);

				return IPM_FAILURE;
			}
	
			/* Store MAC address. This is the same for all aliases. */
			memcpy(intf_ptr->lsn1_hwaddr,
			       ifr.ifr_ifru.ifru_hwaddr.sa_data,
			       ETH_ALEN);

		}
		close(sock);


		if ( !upd_shared_memory )
		{
			data_ptr->intf_cnt++;
			EIPM_SET_INTF_CHECK_TIMER( &(intf_ptr->specData), EIPM_IP_AUDIT_TIMEOUT );
		}

		return IPM_SUCCESS;
	}
	else /* EIPM_DEL */
	{
		/* 
		 * Look through interface data,
		 * clean up, delete if match found.
		 */
		register EIPM_DATA      *shm_ptr;
		register EIPM_INTF	*interface_ptr;
		register EIPM_INTF	*cur_ptr;
		register EIPM_INTF	*next_ptr;
		register EIPM_SUBNET	*subnet_ptr;
		EIPM_INTF_SPEC          *intfSpecDataP;
		int                     extnIntfIdx;
                int                     retval;
		int			interface_idx;
		int			delete_idx;
		int			subnet_idx;
		char			iface0_base[MAX_NLEN_DEV];
		char			*iface0_base_ptr = NULL;
		char			iface1_base[MAX_NLEN_DEV];
		char			*iface1_base_ptr = NULL;

		/*
		 * Make sure we are attached to shared memory segment.
		 */
		if( EIPM_shm_ptr == NULL )
		{
			ASRT_RPT( ASMISSING_DATA,
			          2,
			          sizeof( EIPM_shm_ptr ),
				  &EIPM_shm_ptr,
				  sizeof( EIPM_shmid ),
				  &EIPM_shmid,
			          "EIPM_base_update(): EIPM not attached to shared memory segment\n" );
		
			return( IPM_FAILURE );
		}

		shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;

		strncpy(iface0_base, msg_ptr->base_if[0], MAX_NLEN_DEV);
		iface0_base_ptr = strtok(iface0_base, ":");

		if( iface0_base_ptr == NULL )
		{
			iface0_base_ptr = iface0_base;
		}

		strncpy(iface1_base, msg_ptr->base_if[1], MAX_NLEN_DEV);
		iface1_base_ptr = strtok(iface1_base, ":");

		if( iface1_base_ptr == NULL )
		{
			iface1_base_ptr = iface1_base;
		}

		/*
		 * Loop through shared segment.
		 */
		for( interface_idx = 0, interface_ptr = &shm_ptr->intf_data[0];
		     interface_idx < shm_ptr->intf_cnt;
		     interface_idx++, interface_ptr++ )
		{
			if ( interface_ptr->lsn0_baseif[0] != 0 && interface_ptr->lsn1_baseif[0] != 0 )
			{
				if ( strlen( iface0_base_ptr ) > 0 && strlen( iface1_base_ptr ) > 0 )
				{
					if ( strcmp( interface_ptr->lsn0_baseif, iface0_base_ptr ) != 0 &&
			   		 	strcmp( interface_ptr->lsn1_baseif, iface1_base_ptr ) != 0 )
					{
						/* interface already exists */
						continue;
					}
				}
				else if ( strlen( iface0_base_ptr ) > 0 )
				{
					if ( interface_ptr->subnet_cnt > 0 )
					{
						/* continue regardless b/c have the bfd subnet if deleting transport */
						continue;
					}
				}
				else
				{
					continue;
				}
			}
			else if ( interface_ptr->lsn0_baseif[0] != 0 && strlen( iface0_base_ptr ) > 0 )
			{
				if ( strcmp( interface_ptr->lsn0_baseif, iface0_base_ptr ) != 0 )
				{
					continue;
				}
			}
			else if ( interface_ptr->lsn1_baseif[0] != 0 && strlen( iface1_base_ptr ) > 0 )
			{
				if ( strlen( iface0_base_ptr ) > 0 && strlen( iface1_base_ptr ) > 0 )
				{
					continue;
				}

				if ( strcmp( interface_ptr->lsn1_baseif, iface1_base_ptr ) != 0 )
				{
					continue;
				}
			}

			/* Delete any corresponding extension interfaces also. */
			extnIntfIdx = 0;
                        intfSpecDataP = &(shm_ptr->extnIntfData[0]);

                        while ( extnIntfIdx < shm_ptr->extnIntfCount )
                        {
                                if ( interface_idx == intfSpecDataP->baseIntfIdx )
                                {
                                        /* Delete the extension/child interface. */
                                        struct cmd_base_iface intfUpdateCmd;

                                        memset( &intfUpdateCmd, 0, sizeof( intfUpdateCmd ) );
                                        intfUpdateCmd.subnet_type = IPM_SUBNET_BOTH;

                                        snprintf( intfUpdateCmd.base_if[0], MAX_NLEN_DEV, "%s%s",
                                                  interface_ptr->lsn0_baseif,
                                                  ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
                                        snprintf( intfUpdateCmd.base_if[1], MAX_NLEN_DEV, "%s%s",
                                                  interface_ptr->lsn1_baseif,
                                                  ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

					intfUpdateCmd.vlanId = intfSpecDataP->vlanId;

                                        retval = EIPM_extnIntfUpdate( &intfUpdateCmd, EIPM_DEL, 
                                                                      resp, interface_idx, extnIntfIdx );


					if ( IPM_SUCCESS == retval )
                                        {
						/* Don't increment the loop index as the count has been reduced. */
                                                intfSpecDataP = &(shm_ptr->extnIntfData[extnIntfIdx]);
                                        }
                                        else
                                        {
                                                extnIntfIdx++;
                                                intfSpecDataP++;
                                        }
                                }
				else
                                {
                                        extnIntfIdx++;
                                        intfSpecDataP++;
                                }
                        }

			/*
			 * Clean up each subnet.
			 */
			for( subnet_idx = 0, subnet_ptr = &interface_ptr->subnet[0];
			     subnet_idx < interface_ptr->subnet_cnt;
			     subnet_idx++, subnet_ptr++ )
			{
 				/* Clear any subnet alarms */
				EIPM_CLEAR_SUBNET_ALARM( interface_ptr, EIPM_BASE_INTF, subnet_idx, EIPM_MAX_ALARM );
			}

 		        /* Clear any interface alarms */
			EIPM_CLEAR_INTF_ALARM( interface_ptr, EIPM_BASE_INTF, EIPM_MAX_ALARM );

			/* Close EIPM pivot opened sockets */
			EIPM_close_pivot_sock(interface_ptr);

			/*
			 * Close all interface sockets.
			 */
			EIPM_close_sock( &(interface_ptr->specData) );

			/*
			 * Collapse entries in the table.
			 */
			shm_ptr->intf_cnt--;

			for( delete_idx = interface_idx,
				 cur_ptr = interface_ptr,
			         next_ptr = &shm_ptr->intf_data[ interface_idx + 1 ];
			     delete_idx < shm_ptr->intf_cnt;
			     delete_idx++, cur_ptr++, next_ptr++ )
			{
				/*
				 * If we get here there
				 * is another entry in
				 * the table.  Move it
				 * to this location.
				 */
				*cur_ptr = *next_ptr;
				cur_ptr->specData.baseIntfIdx = delete_idx;
			}
					
			/*
			 * We have copied all of the
			 * the valid interfaces down.
			 * cur_ptr should be pointing
			 * to the last entry in the
			 * list (it was incremented
			 * once after the last copy
			 * was done, or if there was
			 * only 1 entry it never
			 * moved) which is now invalid.
			 */
			memset( cur_ptr,
			        0,
			        sizeof(EIPM_INTF) );
		}

                EIPM_report_status();
	}

	return( IPM_SUCCESS );

} /* end EIPM_base_update() */

int EIPM_extnIntfUpdate( struct cmd_base_iface *cmdP, 
                           EIPM_ADD_DEL opType,
                           char *respStr,
                           int baseIntfIdx,
			   int inExtnIntfIdx )
{
        EIPM_DATA	*dataP;
	char		lsn0Base[MAX_NLEN_DEV];
        unsigned short  vlanId;
        EIPM_INTF_SPEC  *intfSpecDataP;
        int             extnIntfIdx;
        int             retVal;

        if ( !EIPM_IS_VALID_BASE_INTF_IDX( baseIntfIdx ) )
        {
                snprintf( respStr, REPLY_TEXT, 
			  "EIPM Extn Intf Add/Del Failure - %s/%s Invalid Base interface index: %d.\n", 
			  cmdP->base_if[0], cmdP->base_if[1], baseIntfIdx );
                LOG_ERROR( 0, respStr );

                return IPM_FAILURE;
        }

        dataP = (EIPM_DATA *)EIPM_shm_ptr;

	vlanId = cmdP->vlanId;

        if ( EIPM_ADD == opType )
        {

                EIPM_INTF       *intfDataP;
                struct ifreq	ifReq;
		int		sockDesc;
                
                /* -- Ensure that there's space to add the new extension/child interface. -- */
                if ( EIPM_MAX_EXTN_INTF == dataP->extnIntfCount )
                {
                        snprintf( respStr, REPLY_TEXT,
				  "EIPM Extn Intf Add Failure - %s/%s - Max (%u) extn interfaces already added.\n", 
				  cmdP->base_if[0],
                                  cmdP->base_if[1],
                                  EIPM_MAX_EXTN_INTF );

			LOG_ERROR( 0, respStr );

			return IPM_TOOMUCHBIF;
                }

                /* -- Add the new extension/child interface -- */
                intfDataP = &(dataP->intf_data[baseIntfIdx]);
                intfSpecDataP = &(dataP->extnIntfData[dataP->extnIntfCount]);

                memset( intfSpecDataP, 0, sizeof( *intfSpecDataP ) );
		intfSpecDataP->monitor        = EIPM_MONITOR_IP;
		if (strlen(intfDataP->lsn0_baseif) > 0 && strlen(intfDataP->lsn1_baseif) > 0)
		{
			intfSpecDataP->monitor = EIPM_MONITOR_SNDPKT;
		}
		intfSpecDataP->msg_rcvd       = FALSE;
		intfSpecDataP->dir            = LSN02LSN1;
		intfSpecDataP->state          = NORMAL_STATE;
		intfSpecDataP->status         = EIPM_ONLINE;
		intfSpecDataP->preferred_side = LSN0;
		intfSpecDataP->recovery_state = NULL_REC_STATE;
		intfSpecDataP->seqno          = 0;
		intfSpecDataP->counter        = 0;
		intfSpecDataP->lsn0_arpsock   = -1;
		intfSpecDataP->lsn1_arpsock   = -1;
		intfSpecDataP->lsn0_v6arpsock = -1;
		intfSpecDataP->lsn1_v6arpsock = -1;
		intfSpecDataP->lsn0_garpsock   = -1;
		intfSpecDataP->lsn1_garpsock   = -1;
		intfSpecDataP->lsn0_v6garpsock = -1;
		intfSpecDataP->lsn1_v6garpsock = -1;
                intfSpecDataP->vlanId          = vlanId;
                intfSpecDataP->baseIntfIdx     = baseIntfIdx;

                /* Create raw socket to query the interface information. */
		sockDesc = socket( PF_INET, SOCK_RAW, htons( ETH_P_IP ) );

		if ( sockDesc < 0 )
		{
			snprintf( respStr, REPLY_TEXT, 
				  "EIPM Extn Intf Add Failure - Failed to create raw socket for %s/%s - errno: %d (%s)\n", 
				  cmdP->base_if[0], 
                                  cmdP->base_if[1], 
                                  errno,
				  strerror( errno ) );

			LOG_ERROR( 0, respStr );
		
                        /* Cleanup */
			memset( intfSpecDataP, 0, sizeof( *intfSpecDataP ) );
		
			return IPM_FAILURE;
		}
	
		/*
		 *  Get the interface index for LSN0 interface.  Use the
		 *  base interface name & VLAN (all aliases have the same
		 *  interface index).
		 */
		if (strlen(intfDataP->lsn0_baseif) > 0)
		{
			memset( &ifReq, 0, sizeof( ifReq ) );
			ifReq.ifr_addr.sa_family = PF_INET;
			snprintf( ifReq.ifr_name, sizeof( ifReq.ifr_name ), "%s.%u", 
				intfDataP->lsn0_baseif, vlanId );

			retVal = ioctl( sockDesc, SIOCGIFINDEX, &ifReq );

			if ( retVal < 0 )
			{
				snprintf( respStr, REPLY_TEXT, 
					"EIPM Extn Intf Add Failure - ioctl-SIOCGIFINDEX failed for %s - retVal: %d errno: %d\n", 
					ifReq.ifr_name, retVal, errno );

				LOG_ERROR( 0, respStr );
		
				/* Cleanup */
				memset( intfSpecDataP, 0, sizeof( *intfSpecDataP ) );
				(void)close( sockDesc );

				return IPM_FAILURE;
			}

			intfSpecDataP->lsn0_iface_indx = ifReq.ifr_ifindex;
		}
	
		/*
		 *  Get the interface index for LSN1 interface.  Use the
		 *  base interface name & VLAN (all aliases have the same
		 *  interface index).
		 */
		if (strlen(intfDataP->lsn1_baseif) > 0)
		{
			memset( &ifReq, 0, sizeof( ifReq ) );

			ifReq.ifr_addr.sa_family = PF_INET;
			snprintf( ifReq.ifr_name, sizeof( ifReq.ifr_name ), "%s.%u", 
				intfDataP->lsn1_baseif, vlanId );

			retVal = ioctl( sockDesc, SIOCGIFINDEX, &ifReq );

			if ( retVal < 0 )
			{
				snprintf( respStr, REPLY_TEXT, 
					"EIPM Extn Intf Add Failure - ioctl-SIOCGIFINDEX failed for %s - retVal: %d errno: %d\n", 
					ifReq.ifr_name, retVal, errno );

				LOG_ERROR( 0, respStr );
		
				/* Cleanup */
				memset( intfSpecDataP, 0, sizeof( *intfSpecDataP ) );
				(void)close( sockDesc );

				return IPM_FAILURE;
			}

			intfSpecDataP->lsn1_iface_indx = ifReq.ifr_ifindex;
		}

                /* Done with the socket. Close it. */
		close( sockDesc );

                /* -- Create the ping-pong sockets. -- */
		if (intfSpecDataP->monitor == EIPM_MONITOR_SNDPKT)
		{
			retVal = EIPM_create_intf_sockets( intfSpecDataP, EIPM_EXTN_INTF );
		}

		if ( retVal != IPM_SUCCESS )
		{
			snprintf( respStr, REPLY_TEXT, 
				  "EIPM Extn Intf Add Failure - Failed to create interface sockets for %s/%s\n", 
				  cmdP->base_if[0], cmdP->base_if[1] );

			LOG_ERROR( 0, respStr );

                        /* Cleanup. */
			memset( intfSpecDataP, 0, sizeof( *intfSpecDataP ) );
       
			return IPM_FAILURE;
		}
	
		if ( -1 == intfDataP->extnIntfIdx )
                {
                        intfDataP->extnIntfIdx = 0;
                }

                dataP->extnIntfCount++;

		EIPM_SET_INTF_CHECK_TIMER( intfSpecDataP, 15 );

                return IPM_SUCCESS;

        } /* end 'add extn interface' */
	else if ( EIPM_DEL == opType )
        {

		EIPM_INTF *baseIntfDataP;
		EIPM_INTF_SPEC *currP;
                EIPM_INTF_SPEC *nextP;
                int extnIntfIdx;
                int subnetIdx;
                int deleteIdx;

		if ( ( inExtnIntfIdx != -1 ) 
                     && ( inExtnIntfIdx < (((EIPM_DATA *)EIPM_shm_ptr)->extnIntfCount ) ) )
                {
                        extnIntfIdx = inExtnIntfIdx;
                        intfSpecDataP = &(((EIPM_DATA *)EIPM_shm_ptr)->extnIntfData[extnIntfIdx]);
                }
                else
                {
                        extnIntfIdx = 0;
                        intfSpecDataP = &(((EIPM_DATA *)EIPM_shm_ptr)->extnIntfData[0]);
                }

		for ( ;
		      ( extnIntfIdx < ((EIPM_DATA *)EIPM_shm_ptr)->extnIntfCount );
		      ( extnIntfIdx++, intfSpecDataP++ ) )
		{
                        if (    ( intfSpecDataP->baseIntfIdx != baseIntfIdx ) 
                             || ( intfSpecDataP->vlanId != vlanId ) )
			{
				continue;
			}

			/*
			 *  Clean up alarms for each subnet.
			 */
                        for ( ( subnetIdx = 0 ); 
                              ( subnetIdx < EIPM_MAX_SUBNETS );
                              ( subnetIdx++ ) )
			{
 				/* Clear any subnet alarms */
				EIPM_CLEAR_SUBNET_ALARM( intfSpecDataP, EIPM_EXTN_INTF, subnetIdx, EIPM_MAX_ALARM );
			}

 		        /* Clear any interface alarms */
			EIPM_CLEAR_INTF_ALARM( intfSpecDataP, EIPM_EXTN_INTF, EIPM_MAX_ALARM );

			/*
			 * Close all interface sockets.
			 */
			EIPM_close_sock( intfSpecDataP );

			/*
			 * Collapse entries in the table.
			 */
			((EIPM_DATA *)EIPM_shm_ptr)->extnIntfCount--;

			if ( EIPM_IS_VALID_BASE_INTF_IDX( intfSpecDataP->baseIntfIdx ) )
                        {
                                baseIntfDataP = &(((EIPM_DATA *)EIPM_shm_ptr)->intf_data[baseIntfIdx]);

				if ( baseIntfDataP->extnIntfIdx >= ((EIPM_DATA *)EIPM_shm_ptr)->extnIntfCount )
                                {
                                        baseIntfDataP->extnIntfIdx = 0;
                                }
                        }

			for ( ( deleteIdx = extnIntfIdx,
				currP = intfSpecDataP,
			        nextP = &(((EIPM_DATA *)EIPM_shm_ptr)->extnIntfData[(extnIntfIdx + 1)]) );
			     ( deleteIdx < ((EIPM_DATA *)EIPM_shm_ptr)->extnIntfCount );
			     ( deleteIdx++, currP++, nextP++ ) )
			{
				/*
				 * If we get here there
				 * is another entry in
				 * the table.  Move it
				 * to this location.
				 */
				*currP = *nextP;
			}
					
			/*
			 * We have copied all of the
			 * the valid interfaces down.
			 * cur_ptr should be pointing
			 * to the last entry in the
			 * list (it was incremented
			 * once after the last copy
			 * was done, or if there was
			 * only 1 entry it never
			 * moved) which is now invalid.
			 */
			memset( currP,
			        0,
			        sizeof( EIPM_INTF_SPEC ) );
		}

                EIPM_report_status();

        } /* end 'delete extn interface' */

        return IPM_SUCCESS;

} /* end EIPM_extnIntfUpdate() */


int EIPM_wcnp_update( struct cmd_alias_ip *cmd_alias_ip_ptr, int type, char *resp )
{
EIPM_DATA	*data_ptr;
EIPM_INTF	*intf_ptr;
EIPM_SUBNET	*subnet_ptr;
EIPM_SUBNET	*bfd_subnet_ptr;
EIPM_ROUTES     *route_ptr;
EIPM_IPDATA     *ipdata_ptr;
IPM_IPADDR	ip;
IPM_IPADDR	subnet_mask;
IPM_IPADDR	subnet_base;
int 		intf_idx;
int 		subnet_idx;
int 		ip_idx;
int		retval;
IPM_RETVAL 	ipm_retval;
char		*iface0_base_ptr = NULL;
char		iface0_base[MAX_NLEN_DEV];
char		*iface1_base_ptr = NULL;
char		iface1_base[MAX_NLEN_DEV];
char		ip_addr[IPM_IPMAXSTRSIZE];
int 		cmd_ip_idx;
int 		isAddaction = 0;

	/* Check for EIPM memory */
	if( EIPM_shm_ptr == NULL )
	{
		snprintf(resp, REPLY_TEXT, 
			 "EIPM IP Config Failure: Shared memory null, Iface %s - %s\n", 
			  ( cmd_alias_ip_ptr->alias_t[0].alias_if[0] != 0 ? cmd_alias_ip_ptr->alias_t[0].alias_if : "empty" ),
			  ( cmd_alias_ip_ptr->alias_t[1].alias_if[0] != 0 ? cmd_alias_ip_ptr->alias_t[1].alias_if : "empty" )
			);

		LOG_ERROR(0, resp);

		return IPM_FAILURE;
	}

	if(type == IPM_ADD_WCNP_ACTIVE || type == IPM_DEL_WCNP_ACTIVE || 
		type == IPM_ADD_WCNP_STANDBY || type == IPM_DEL_WCNP_STANDBY)
	{
		//ip string is already checked from ipm_cli side
		if(strcmp(cmd_alias_ip_ptr->alias_t[0].ip, cmd_alias_ip_ptr->alias_t[1].ip) != 0)
		{
			snprintf(resp, REPLY_TEXT,
				 "EIPM IP Config Failure: IP %s - %s, IP on both sides should be the same.\n",
				cmd_alias_ip_ptr->alias_t[0].ip, cmd_alias_ip_ptr->alias_t[1].ip);
			LOG_ERROR(0, resp);
			return IPM_FAILURE;
		}
	}
	else if(type == IPM_ADD_WCNP_FIX || type == IPM_DEL_WCNP_FIX)
	{
		//ip string is already checked from ipm_cli side
		if(strcmp(cmd_alias_ip_ptr->alias_t[0].ip, cmd_alias_ip_ptr->alias_t[1].ip) == 0)
		{
			snprintf(resp, REPLY_TEXT,
					"EIPM IP Config Failure: IP %s - %s, wcnp fix IP on both sides should not be the same.\n",
					cmd_alias_ip_ptr->alias_t[0].ip, cmd_alias_ip_ptr->alias_t[1].ip);
			LOG_ERROR(0, resp);
			return IPM_FAILURE;
		}	
	}
	else
	{
		snprintf(resp, REPLY_TEXT,
			"EIPM_wcnp_update: invalid cmd(%d) \n", type);
		LOG_ERROR(0, resp);
		return IPM_FAILURE;
	}

	if(type == IPM_ADD_WCNP_ACTIVE || type == IPM_ADD_WCNP_STANDBY || type == IPM_ADD_WCNP_FIX)
	{
		//1 stands for add, 0 stands for delete
		isAddaction = 1;

	}
	if( cmd_alias_ip_ptr->alias_t[0].alias_if[0] == 0 || cmd_alias_ip_ptr->alias_t[1].alias_if[0] == 0 )
	{
		snprintf(resp, REPLY_TEXT, 
			 "EIPM IP Config Failure: Iface %s - %s, both Ifaces should be non-empty\n", 
			  ( cmd_alias_ip_ptr->alias_t[0].alias_if[0] != 0 ? cmd_alias_ip_ptr->alias_t[0].alias_if : "empty" ),
			  ( cmd_alias_ip_ptr->alias_t[1].alias_if[0] != 0 ? cmd_alias_ip_ptr->alias_t[1].alias_if : "empty" )
			);
		LOG_ERROR(0, resp);
		return IPM_FAILURE;
	}
	data_ptr = (EIPM_DATA *)EIPM_shm_ptr;

	/* Derive base iface */
	strncpy(iface0_base, cmd_alias_ip_ptr->alias_t[0].alias_if, MAX_NLEN_DEV);
	iface0_base_ptr = strtok(iface0_base, ":");

	if( iface0_base_ptr == NULL )
	{
		iface0_base_ptr = iface0_base;
	}

	strncpy(iface1_base, cmd_alias_ip_ptr->alias_t[1].alias_if, MAX_NLEN_DEV);
	iface1_base_ptr = strtok(iface1_base, ":");

	if( iface1_base_ptr == NULL )
	{
		iface1_base_ptr = iface1_base;
	}

	/* Look for matching interface */
	for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
		intf_idx < data_ptr->intf_cnt;
		intf_idx++, intf_ptr++ )
	{
		if ( intf_ptr->lsn0_baseif[0] != 0 && intf_ptr->lsn1_baseif[0] != 0 )
		{
			if ( strlen( iface0_base_ptr ) > 0 && strlen( iface1_base_ptr ) > 0 )
			{
				if ( (strcmp( intf_ptr->lsn0_baseif, iface0_base_ptr ) == 0) && 
					(strcmp( intf_ptr->lsn1_baseif, iface1_base_ptr ) == 0) )
				{
					break;	
				}
			}
		}
	}
	if (intf_idx ==  data_ptr->intf_cnt)
	{
		//Not found Interface
		snprintf( resp, REPLY_TEXT,
					"EIPM_wcnp_update(): Failed to match Interface %s - %s for %s/%d %s",
					( cmd_alias_ip_ptr->alias_t[0].alias_if[0] != 0 ? cmd_alias_ip_ptr->alias_t[0].alias_if : "empty" ),
					( cmd_alias_ip_ptr->alias_t[1].alias_if[0] != 0 ? cmd_alias_ip_ptr->alias_t[1].alias_if : "empty" ),
					cmd_alias_ip_ptr->alias_t[0].ip,
					cmd_alias_ip_ptr->alias_t[0].prefix,
					( isAddaction == 0 ? "delete" : "add" )
					);

		if(isAddaction == 0)
		{
			//delete action
			LOG_DEBUG(0, resp);
			return IPM_SUCCESS;
		}
		else
		{
			LOG_ERROR(0, resp);
			return IPM_FAILURE;
		}
	}

	/* Found interface match, look for subnet match */
	if(isAddaction)
	{
		//Add action
		if( intf_ptr->subnet_cnt == 0 )
		{
			snprintf(resp, REPLY_TEXT, "%s(): no subnets on %s-%s\n",
					__FUNCTION__,
					( intf_ptr->lsn0_baseif[0] != 0 ? intf_ptr->lsn0_baseif : "empty" ),
					( intf_ptr->lsn1_baseif[0] != 0 ? intf_ptr->lsn1_baseif : "empty" )
			);

			LOG_ERROR(0, resp);
			return IPM_FAILURE;
		}
		/* Schedule configuration check */
		EIPM_CHECK_INTF_CONFIG( &(intf_ptr->specData) );
	}

		
	//for wcnp fixed IP, one ipm_cli command passes two IPs
	//to IPM. cmd_ip_idx is to distinguish fix left and fix right IP.
	// cmd_ip_idx = 0 - fix left IP
	// cmd_ip_idx = 1 - fix right IP
	for (cmd_ip_idx = 0; cmd_ip_idx < 2; cmd_ip_idx++)
	{
		/* Convert IP and subnet mask */
		IPM_ipaddr_init(&ip);
		IPM_ipaddr_init(&subnet_mask);

		ipm_retval = IPM_p2ipaddr(cmd_alias_ip_ptr->alias_t[cmd_ip_idx].ip, &ip);

		if( ipm_retval != IPM_SUCCESS )
		{
			snprintf(resp, REPLY_TEXT, 
				"EIPM IP Config Failure: Failed %d to translate IP %s\n", 
				ipm_retval, cmd_alias_ip_ptr->alias_t[0].ip);

			LOG_ERROR(0, resp);

			return ipm_retval;
		}

		ipm_retval = IPM_ipmkmask(&subnet_mask, ip.addrtype, cmd_alias_ip_ptr->alias_t[cmd_ip_idx].prefix);

		if( ipm_retval != IPM_SUCCESS )
		{
			snprintf(resp, REPLY_TEXT, 
					"EIPM IP Config Failure: Failed %d to create Mask for %s/%d\n",
					ipm_retval, cmd_alias_ip_ptr->alias_t[cmd_ip_idx].ip, cmd_alias_ip_ptr->alias_t[cmd_ip_idx].prefix);

			LOG_ERROR(0, resp);

			return ipm_retval;
		}
		
		IPM_ipaddr_init(&subnet_base);
		IPM_get_subnet(&ip, &subnet_mask, &subnet_base);

		for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
			subnet_idx < intf_ptr->subnet_cnt;
			subnet_idx++, subnet_ptr++ )
		{
			if( IPM_IPCMPADDR(&subnet_ptr->subnet_base, &subnet_base) == IPM_SUCCESS )
			{
				break;
			}
		}

		if (subnet_idx == intf_ptr->subnet_cnt)
		{
			//No subnet match
			snprintf( resp, REPLY_TEXT,
				"EIPM_wcnp_update(): Failed to match subnet %s - %s for %s/%d %s",
				( cmd_alias_ip_ptr->alias_t[0].alias_if[0] != 0 ? cmd_alias_ip_ptr->alias_t[0].alias_if : "empty" ),
				( cmd_alias_ip_ptr->alias_t[1].alias_if[0] != 0 ? cmd_alias_ip_ptr->alias_t[1].alias_if : "empty" ),
				cmd_alias_ip_ptr->alias_t[0].ip,
				cmd_alias_ip_ptr->alias_t[0].prefix,
				( isAddaction == 0 ? "delete" : "add" ) );

			if (isAddaction == 0)
			{
				LOG_DEBUG(0, resp);
				return IPM_SUCCESS;
			}
			else
			{
				LOG_ERROR(0, resp);
				return IPM_FAILURE;
			}
		}

		/* Subnet match, look for IP */
		for( ip_idx = 0, ipdata_ptr = &subnet_ptr->ips[0];
			ip_idx < subnet_ptr->ip_cnt;
			ip_idx++, ipdata_ptr++ )
		{
			if( IPM_IPCMPADDR(&ipdata_ptr->ipaddr, &ip) == IPM_SUCCESS )
			{
				break;
			}
		}

		/* Not found IP */
		if (ip_idx == subnet_ptr->ip_cnt)
		{
			if ( (type == IPM_DEL_WCNP_ACTIVE) ||
				(type == IPM_DEL_WCNP_STANDBY))
			{
				return IPM_SUCCESS;
			}
			else if (type == IPM_DEL_WCNP_FIX)
			{
				if (cmd_ip_idx == 0)
				{
					/*fix left IP not found, try fix right one*/
					continue;
				}
				else
				{
					/*already the last loop*/
					return IPM_SUCCESS;
				}
			}
			else
			{
				/* Add WCNP IP here */
				if( subnet_ptr->ip_cnt < EIPM_MAX_IPS )
				{

					if (( subnet_ptr->ip_cnt == 0 ) &&
					    (( subnet_ptr->subnet_base.addrtype == IPM_IPV4 &&
					      subnet_ptr->prefixlen < 32 ) ||
					    ( subnet_ptr->subnet_base.addrtype == IPM_IPV6 &&
					      subnet_ptr->prefixlen < 128 ))) 
					{
						/* route info */
						route_ptr = &subnet_ptr->routes[0];

						route_ptr->type = EIPM_ROUTE_SUBN;
						route_ptr->dest = subnet_ptr->subnet_base;
						route_ptr->destprefix = subnet_ptr->prefixlen;
						IPM_ipaddr_init(&route_ptr->nexthop);
						IPM_ipaddr_init(&route_ptr->source_ip);
						if( subnet_ptr->subnet_base.addrtype == IPM_IPV4 )
						{
							(void)IPM_p2ipaddr("0.0.0.0", &route_ptr->nexthop);
							(void)IPM_p2ipaddr("0.0.0.0", &route_ptr->source_ip);
						}
						else if( subnet_ptr->subnet_base.addrtype == IPM_IPV6 )
						{
							(void)IPM_p2ipaddr("::", &route_ptr->nexthop);
							(void)IPM_p2ipaddr("::", &route_ptr->source_ip);
						}
			
						subnet_ptr->route_cnt = 1;
					}

					ipdata_ptr = &subnet_ptr->ips[subnet_ptr->ip_cnt];

					memset(ipdata_ptr, 0, sizeof(EIPM_IPDATA));
					if( type == IPM_ADD_WCNP_FIX )
					{
						ipdata_ptr->type = EIPM_IP_WCNP_FIXED; 
					}
					else if ( type == IPM_ADD_WCNP_ACTIVE )
					{
						ipdata_ptr->type = EIPM_IP_WCNP_ACTIVE;
					}
					else
					{
						ipdata_ptr->type = EIPM_IP_WCNP_STANDBY;
					}
					ipdata_ptr->ipaddr = ip;
					strcpy(ipdata_ptr->lsn0_iface, cmd_alias_ip_ptr->alias_t[0].alias_if);
					strcpy(ipdata_ptr->lsn1_iface, cmd_alias_ip_ptr->alias_t[1].alias_if);

					EIPM_set_ip_config_time(ipdata_ptr);

					subnet_ptr->ip_cnt++;

					EIPM_open_garpsock( &(intf_ptr->specData), ip.addrtype );

					//schedule an config check audit
					EIPM_SET_GRAT_ARP( subnet_ptr, subnet_ptr->sub2intf_mapping[0].route_priority );
					EIPM_CHECK_INTF_CONFIG(&(intf_ptr->specData));

					if ( type == IPM_ADD_WCNP_FIX )
					{
						int nl_socket = ipm_open_netlink();
						int temp_retval = IPM_SUCCESS;
						int retval = IPM_SUCCESS;
						if(cmd_ip_idx == 1)
						{
							//All fixed wcnp IP are filled in
#ifndef _VHE
							EIPM_set_wcnp_env();
#endif
						}
						if ( nl_socket < 0 )
						{
							//Assert already written in ipm_open_netlink()
							if( cmd_ip_idx == 0 )
							{
								subnet_ptr->redundancy_mode = IPM_RED_EIPM_WCNP_FIXLEFT;
							}
							else if( cmd_ip_idx == 1 )
							{
								subnet_ptr->redundancy_mode = IPM_RED_EIPM_WCNP_FIXRIGHT;
							}
							return IPM_FAILURE;
						}
						if( cmd_ip_idx == 0 )
						{
							//overwrite subnet type
							subnet_ptr->redundancy_mode = IPM_RED_EIPM_WCNP_FIXLEFT;
							(void) EIPM_ADD_IP( nl_socket, ipdata_ptr->type, &ipdata_ptr->ipaddr,
									subnet_ptr->prefixlen, intf_ptr->specData.lsn0_iface_indx,
									ipdata_ptr->lsn0_iface );
						}
						else if( cmd_ip_idx == 1 )
						{
							//overwrite subnet type
							subnet_ptr->redundancy_mode = IPM_RED_EIPM_WCNP_FIXRIGHT;
							(void) EIPM_ADD_IP( nl_socket, ipdata_ptr->type, &ipdata_ptr->ipaddr,
									subnet_ptr->prefixlen, intf_ptr->specData.lsn1_iface_indx,
									ipdata_ptr->lsn1_iface );
						}

						close(nl_socket);
					}
					else if (  type == IPM_ADD_WCNP_ACTIVE )
					{
						//overwrite subnet type
						subnet_ptr->redundancy_mode = IPM_RED_EIPM_WCNP_ACTIVE;
						int temp_retval = IPM_SUCCESS;
						int retval = IPM_SUCCESS;
						int nl_socket = ipm_open_netlink();
						if ( nl_socket < 0 )
						{
							//Assert already written in ipm_open_netlink()
							return IPM_FAILURE;
						}
						if( subnet_ptr->sub2intf_mapping[0].route_priority == LSN0 )
						{
							(void) EIPM_ADD_IP( nl_socket, ipdata_ptr->type, &ipdata_ptr->ipaddr,
									subnet_ptr->prefixlen, intf_ptr->specData.lsn0_iface_indx,
									ipdata_ptr->lsn0_iface );
						}
						else if( subnet_ptr->sub2intf_mapping[0].route_priority == LSN1 )
						{
							(void) EIPM_ADD_IP( nl_socket, ipdata_ptr->type, &ipdata_ptr->ipaddr,
									subnet_ptr->prefixlen, intf_ptr->specData.lsn1_iface_indx,
									ipdata_ptr->lsn1_iface );
						}
						else
						{
							LOG_ERROR(0, "Error: no data configured on the interface, could not plumb the WCNP_ACTIVE_IP ,  when priority is %d.\n", subnet_ptr->sub2intf_mapping[0].route_priority);
						}

						close(nl_socket);

					}
					else if ( type == IPM_ADD_WCNP_STANDBY )
					{
						subnet_ptr->redundancy_mode = IPM_RED_EIPM_WCNP_STANDBY;
						int temp_retval = IPM_SUCCESS;
						int retval = IPM_SUCCESS;
						int nl_socket = ipm_open_netlink();
						if ( nl_socket < 0 )
						{
							//Assert already written in ipm_open_netlink()
							return IPM_FAILURE;
						}

						//WCNP active IP and standby IP are stored within one interface pair in SHM eth0/eth1
						//but one is configured on one interface(E.G eth0), the other is configured on the other 
						//side(E.G eth1). If route_priority is LSN0, active IP is plumbed on lsn0 side, and standby IP
						// is configured on eth1
						if( subnet_ptr->sub2intf_mapping[0].route_priority == LSN0 )
						{
							(void) EIPM_ADD_IP( nl_socket, ipdata_ptr->type, &ipdata_ptr->ipaddr,
									subnet_ptr->prefixlen, intf_ptr->specData.lsn1_iface_indx,
									ipdata_ptr->lsn1_iface );
						}
						else if( subnet_ptr->sub2intf_mapping[0].route_priority == LSN1 )
						{
							(void) EIPM_ADD_IP( nl_socket, ipdata_ptr->type, &ipdata_ptr->ipaddr,
									subnet_ptr->prefixlen, intf_ptr->specData.lsn0_iface_indx,
									ipdata_ptr->lsn0_iface );
						}
						else
						{
							LOG_ERROR(0, "Error:  no data configured on the interface, could not plumbed the WCNP_STANDBY_IP when priority is %d.\n", subnet_ptr->sub2intf_mapping[0].route_priority);
						}

						close(nl_socket);
					}

				}
				else
				{
					snprintf(resp, REPLY_TEXT, "EIPM_wcnp_update(): Max Number of IPs Reached %d\n", subnet_ptr->ip_cnt);
					LOG_ERROR(0, resp);
					return IPM_FAILURE;
				}
			}
		}
		else
		{

			/* Found IP */
			if ( (type == IPM_ADD_WCNP_ACTIVE) ||
				(type == IPM_ADD_WCNP_STANDBY))
			{
				/* Duplicate action, do nothing */
				return IPM_SUCCESS;
			}
			else if (type == IPM_ADD_WCNP_FIX)
			{
				if (cmd_ip_idx == 0)
				{
					/* IP on left interface found
					 * try the right one */
					continue;
				}
			}
			else 
			{
				/* Attempt to delete IP from interfaces (may not be plumbed),
				* then delete IP from data, collapse IP table 
				*/

				/* Delete IP */
				int nl_socket;
				int del_index;
				nl_socket = ipm_open_netlink();
				if( nl_socket >= 0)
				{
					if( type == IPM_DEL_WCNP_ACTIVE )
					{

						if ( subnet_ptr->sub2intf_mapping[0].route_priority == LSN0 )
						{
							(void)EIPM_DELETE_IP( nl_socket,
								  ipdata_ptr->type,
								  &ipdata_ptr->ipaddr,
								  subnet_ptr->prefixlen,
								  intf_ptr->specData.lsn0_iface_indx,
								  intf_ptr->lsn0_baseif
							);
						}
						else if ( subnet_ptr->sub2intf_mapping[0].route_priority == LSN1 )
						{
							(void)EIPM_DELETE_IP( nl_socket,
								  ipdata_ptr->type,
								  &ipdata_ptr->ipaddr,
								  subnet_ptr->prefixlen,
								  intf_ptr->specData.lsn1_iface_indx,
								  intf_ptr->lsn1_baseif
							);
						}
						else
						{
							LOG_ERROR(0, "Error: no data configured on the interface, could not delete the WCNP_ACTIVE_IP when priority is %d.\n", subnet_ptr->sub2intf_mapping[0].route_priority);
						}
					}
					else if( type == IPM_DEL_WCNP_STANDBY )
					{

						if ( subnet_ptr->sub2intf_mapping[0].route_priority == LSN0 )
						{
							(void)EIPM_DELETE_IP( nl_socket,
								  ipdata_ptr->type,
								  &ipdata_ptr->ipaddr,
								  subnet_ptr->prefixlen,
								  intf_ptr->specData.lsn1_iface_indx,
								  intf_ptr->lsn1_baseif
							);
						}
						else if ( subnet_ptr->sub2intf_mapping[0].route_priority == LSN1 )
						{
							(void)EIPM_DELETE_IP( nl_socket,
								  ipdata_ptr->type,
								  &ipdata_ptr->ipaddr,
								  subnet_ptr->prefixlen,
								  intf_ptr->specData.lsn0_iface_indx,
								  intf_ptr->lsn0_baseif
							);
						}
						else
						{
							LOG_ERROR(0, "Error: no data configured on the interface, could not delete the WCNP_STANDBY_IP,  when priority is %d.\n", subnet_ptr->sub2intf_mapping[0].route_priority);
						}
					}
					else if( type == IPM_DEL_WCNP_FIX )
					{
						if ( cmd_ip_idx == 0 )
						{
							//fix left IP
							(void)EIPM_DELETE_IP( nl_socket,
								  ipdata_ptr->type,
								  &ipdata_ptr->ipaddr,
								  subnet_ptr->prefixlen,
								  intf_ptr->specData.lsn0_iface_indx,
								  intf_ptr->lsn0_baseif
							);
						}
						else if ( cmd_ip_idx == 1 )
						{
							//fix right IP
							(void)EIPM_DELETE_IP( nl_socket,
								  ipdata_ptr->type,
								  &ipdata_ptr->ipaddr,
								  subnet_ptr->prefixlen,
								  intf_ptr->specData.lsn1_iface_indx,
								  intf_ptr->lsn1_baseif
							);
						}
					}
					(void)close(nl_socket);
				}

				EIPM_CLEAR_AND_DELETE_IP_ALARM( intf_ptr, subnet_idx, ip_idx, EIPM_MAX_ALARM );

				subnet_ptr->ip_cnt--;

				for( del_index = ip_idx;
					 del_index < subnet_ptr->ip_cnt;
					 del_index++ )
				{
					subnet_ptr->ips[del_index] = subnet_ptr->ips[del_index + 1];
				}

				/* Clear last IP entry */
				memset(&subnet_ptr->ips[del_index], 0, sizeof(subnet_ptr->ips[0]));

				/* Check for last IP in subnet */
				if( subnet_ptr->ip_cnt == 0 && subnet_ptr->delete_flag == FALSE)
				{

					/* clear the route info */
					route_ptr = &subnet_ptr->routes[0];
					memset(route_ptr, 0, sizeof(EIPM_ROUTES));
					subnet_ptr->route_cnt = 0;

					/* Clear any subnet alarms */
					EIPM_CLEAR_SUBNET_ALARM( intf_ptr, EIPM_BASE_INTF, subnet_idx, EIPM_MAX_ALARM );

					del_index = subnet_idx;
					/* Clear alarm data */
					memset(&intf_ptr->specData.alarm[del_index][0], 0, sizeof(intf_ptr->specData.alarm[0]));
					/* Check for last subnet in interface */
					if( intf_ptr->subnet_cnt == 0 &&
					    eipm_delete_interface_with_no_subnet == TRUE )
					{
					    /* Clear any interface alarms alarms */
					    EIPM_CLEAR_INTF_ALARM( intf_ptr, EIPM_BASE_INTF, EIPM_MAX_ALARM );

					} /* check interface subnet count */
				}
				else if ( subnet_ptr->ip_cnt == 0 && subnet_ptr->delete_flag == TRUE )
				{
					struct cmd_subnet_upd subnet_info;
					char reply_text[REPLY_TEXT];

					memset( &subnet_info, 0, sizeof(subnet_info));

					subnet_info.redundancy_mode = (int) subnet_ptr->redundancy_mode;
					subnet_info.prefix = subnet_ptr->prefixlen;
					IPM_ipaddr2p(&subnet_ptr->subnet_base, subnet_info.subnet_base, IPM_IPMAXSTRSIZE);
					if ( strlen( intf_ptr->lsn0_baseif) > 0 )
					{
						subnet_info.dev_t[0].subnet_type = IPM_SUBNET_EXTERNAL;
						strncpy( subnet_info.dev_t[0].dev_if, intf_ptr->lsn0_baseif, MAX_NLEN_DEV );
					}

					if ( strlen( intf_ptr->lsn1_baseif) > 0 )
					{
						subnet_info.dev_t[1].subnet_type = IPM_SUBNET_EXTERNAL;
						strncpy( subnet_info.dev_t[1].dev_if, intf_ptr->lsn1_baseif, MAX_NLEN_DEV );
					}

					retval = EIPM_subnet_update(&subnet_info, EIPM_DEL, reply_text, NON_CLI_REQUEST);
					if ( retval < 0 )
					{
						/* error is already logged in EIPM_subnet_update */
						return retval;
					}

				} /* check subnet IP count */

				// Schedule configuration check 
				EIPM_CHECK_INTF_CONFIG(&(intf_ptr->specData));

				if( type == IPM_DEL_WCNP_ACTIVE || type == IPM_DEL_WCNP_STANDBY )
				{
					/* Only Fix IP will do another loop */
					break;
				}
			}/* end of else the del IP part*/
		} /* end of else the found IP part */
	}/* end of for (cmd_ip_idx = 0; cmd_ip_idx < 2; cmd_ip_idx++)*/

	return IPM_SUCCESS;
}


/**********************************************************************
 *
 * Name:	EIPM_intf_update()
 *
 * Abstract:	Called when IPM receives a message with data for 
 *		an external interface.
 *
 * Parameters:	msg_ptr - pointer to data message
 *		type    - whether adding or deleting interface
 *		resp    - pointer to text string response to user
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/


int EIPM_intf_update( struct cmd_alias_ip *cmd_alias_ip_ptr,
                      EIPM_ADD_DEL type, 
                      char *resp )
{
EIPM_DATA	*data_ptr;
EIPM_INTF	*intf_ptr;
EIPM_SUBNET	*subnet_ptr;
EIPM_SUBNET	*bfd_subnet_ptr;
EIPM_ROUTES     *route_ptr;
EIPM_IPDATA     *ipdata_ptr;
IPM_IPADDR	ip;
IPM_IPADDR	subnet_mask;
IPM_IPADDR	subnet_base;
int 		intf_idx;
int 		subnet_idx;
int 		ip_idx;
int		retval;
int		bfd_subnet_idx;
IPM_RETVAL 	ipm_retval;
BFD_RETVAL 	bfd_retval;
IPM_RETVAL 	eipm_bfd_retval;
IPM_RETVAL 	eipm_arpndp_retval;
char		*iface0_base_ptr = NULL;
char		iface0_base[MAX_NLEN_DEV];
char		*iface1_base_ptr = NULL;
char		iface1_base[MAX_NLEN_DEV];
char		gateway_addr[IPM_IPMAXSTRSIZE];
char		ip_addr[IPM_IPMAXSTRSIZE];
struct timespec sel_time;


    /* Check for EIPM memory */
    if( EIPM_shm_ptr == NULL )
    {
        snprintf(resp, REPLY_TEXT, 
                 "EIPM IP Config Failure: Shared memory null, Iface %s - %s\n", 
		  ( cmd_alias_ip_ptr->alias_t[0].alias_if[0] != 0 ? cmd_alias_ip_ptr->alias_t[0].alias_if : "empty" ),
                  ( cmd_alias_ip_ptr->alias_t[1].alias_if[0] != 0 ? cmd_alias_ip_ptr->alias_t[1].alias_if : "empty" )
	);

        LOG_ERROR(0, resp);

        return IPM_FAILURE;
    }

    data_ptr = (EIPM_DATA *)EIPM_shm_ptr;

    /* Derive base iface */
    strncpy(iface0_base, cmd_alias_ip_ptr->alias_t[0].alias_if, MAX_NLEN_DEV);
    iface0_base_ptr = strtok(iface0_base, ":");

    if( iface0_base_ptr == NULL )
    {
        iface0_base_ptr = iface0_base;
    }

    strncpy(iface1_base, cmd_alias_ip_ptr->alias_t[1].alias_if, MAX_NLEN_DEV);
    iface1_base_ptr = strtok(iface1_base, ":");

    if( iface1_base_ptr == NULL )
    {
        iface1_base_ptr = iface1_base;
    }

    /* Convert IP and subnet mask */
    IPM_ipaddr_init(&ip);
    IPM_ipaddr_init(&subnet_mask);

    if ( strlen( iface0_base_ptr ) > 0 )
    {
    	ipm_retval = IPM_p2ipaddr(cmd_alias_ip_ptr->alias_t[0].ip, &ip);

    	if( ipm_retval != IPM_SUCCESS )
    	{
        	snprintf(resp, REPLY_TEXT, 
                 	"EIPM IP Config Failure: Failed %d to translate IP %s\n", 
		  	ipm_retval, cmd_alias_ip_ptr->alias_t[0].ip);

        	LOG_ERROR(0, resp);

        	return ipm_retval;
    	}

    	ipm_retval = IPM_ipmkmask(&subnet_mask, ip.addrtype, cmd_alias_ip_ptr->alias_t[0].prefix);

    	if( ipm_retval != IPM_SUCCESS )
    	{
        	snprintf(resp, REPLY_TEXT, 
                 	"EIPM IP Config Failure: Failed %d to create Mask for %s/%d\n",
                  	ipm_retval, cmd_alias_ip_ptr->alias_t[0].ip, cmd_alias_ip_ptr->alias_t[0].prefix);

        	LOG_ERROR(0, resp);

        	return ipm_retval;
    	}
    }
    else
    {
	if ( strlen( iface1_base_ptr ) > 0 )
	{
		ipm_retval = IPM_p2ipaddr(cmd_alias_ip_ptr->alias_t[1].ip, &ip);

		if( ipm_retval != IPM_SUCCESS )
		{
			snprintf(resp, REPLY_TEXT,
				"EIPM IP Config Failure: Failed %d to translate IP %s\n",
				ipm_retval, cmd_alias_ip_ptr->alias_t[1].ip
			);

			LOG_ERROR(0, resp);

			return ipm_retval;
		}

		ipm_retval = IPM_ipmkmask(&subnet_mask, ip.addrtype, cmd_alias_ip_ptr->alias_t[1].prefix);

		if( ipm_retval != IPM_SUCCESS )
		{
			snprintf(resp, REPLY_TEXT,
				"EIPM IP Config Failure: Failed %d to create Mask for %s/%d\n",
				ipm_retval, cmd_alias_ip_ptr->alias_t[1].ip, cmd_alias_ip_ptr->alias_t[1].prefix
			);

			LOG_ERROR(0, resp);

			return ipm_retval;
		}
	}
	else
	{
		snprintf(resp, REPLY_TEXT,
			"EIPM IP Config Failure: no IP specified\n"
		);

		LOG_ERROR(0, resp);

		return IPM_FAILURE;
	}
    }
	

    IPM_ipaddr_init(&subnet_base);

    IPM_get_subnet(&ip, &subnet_mask, &subnet_base);


    /* Other defensive checks, eg. network base, broadcast IP */


    /* Search through existing data looking for a subnet match:
     * If match is found:
     * - If action is delete -> delete IP entry, collapse IP table
     *                          delete of subnet entry will occur when subnet is removed
     * - If action is add -> add/update IP entry
     * If match is not found:
     * - add interface, subnet, IP entry
     */
	
    /* Look for matching interface */
    for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
         intf_idx < data_ptr->intf_cnt;
         intf_idx++, intf_ptr++ )
    {
	if ( intf_ptr->lsn0_baseif[0] != 0 && intf_ptr->lsn1_baseif[0] != 0 )
	{
		if ( strlen( iface0_base_ptr ) > 0 && strlen( iface1_base_ptr ) > 0 )
		{
			if ( (strcmp( intf_ptr->lsn0_baseif, iface0_base_ptr ) != 0) ||
				(strcmp( intf_ptr->lsn1_baseif, iface1_base_ptr ) != 0) )
			{
				continue;
			}
		}
		else if ( strlen( iface0_base_ptr ) > 0 )
		{
			if ( strcmp( intf_ptr->lsn0_baseif, iface0_base_ptr ) != 0 )
			{
				continue;
			}
		}
		else
		{
			continue;
		}
	}
	else if ( intf_ptr->lsn0_baseif[0] != 0 && strlen( iface0_base_ptr ) > 0 )
	{
		if ( strcmp( intf_ptr->lsn0_baseif, iface0_base_ptr ) != 0 )
		{
			continue;
		}
	}
	else if ( intf_ptr->lsn1_baseif[0] != 0 && strlen( iface1_base_ptr ) > 0 )
	{
		if ( strcmp( intf_ptr->lsn1_baseif, iface1_base_ptr ) != 0 )
		{
			continue;
		}
	}
	else
	{
		continue;
	}

        /* Found interface match, look for subnet match */
        if( type == EIPM_ADD )
        {
            if( intf_ptr->subnet_cnt == 0 )
            {
		snprintf(resp, REPLY_TEXT, "%s(): no subnets on %s-%s\n",
			__FUNCTION__,
			( intf_ptr->lsn0_baseif[0] != 0 ? intf_ptr->lsn0_baseif : "empty" ),
			( intf_ptr->lsn1_baseif[0] != 0 ? intf_ptr->lsn1_baseif : "empty" )
		);

		LOG_ERROR(0, resp);

		return IPM_FAILURE;
            }

            /* Schedule configuration check */
	    EIPM_CHECK_INTF_CONFIG( &(intf_ptr->specData) );
        }

        for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
             subnet_idx < intf_ptr->subnet_cnt;
             subnet_idx++, subnet_ptr++ )
        {
            if( IPM_IPCMPADDR(&subnet_ptr->subnet_base, &subnet_base) == IPM_SUCCESS )
            {
                /* Found subnet match, look for IP match */
                for( ip_idx = 0, ipdata_ptr = &subnet_ptr->ips[0];
                     ip_idx < subnet_ptr->ip_cnt;
                     ip_idx++, ipdata_ptr++ )
                {
                    if( IPM_IPCMPADDR(&ipdata_ptr->ipaddr, &ip) == IPM_SUCCESS )
                    {
                        /* Found IP match, handle update action */
                        if( type == EIPM_ADD )
                        {
                            ipdata_ptr->type = EIPM_IP_ALIAS;
			    if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
			    {
				if ( strlen( cmd_alias_ip_ptr->alias_t[0].alias_if ) > 0 && 
				     strlen( cmd_alias_ip_ptr->alias_t[1].alias_if ) > 0 )
				{
					snprintf(
						resp, REPLY_TEXT, "%s(): specified two interfaces %s - %s when need one for redundancy mode [%d]\n",
						__FUNCTION__,
						cmd_alias_ip_ptr->alias_t[0].alias_if,
						cmd_alias_ip_ptr->alias_t[1].alias_if,
						subnet_ptr->redundancy_mode
					);

					LOG_ERROR(0, resp);

					return IPM_FAILURE;
				}
			    }
			    else if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD ||
                                      (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR )
			    {
				if ( (strlen( cmd_alias_ip_ptr->alias_t[0].alias_if ) > 0 && 
					strlen( cmd_alias_ip_ptr->alias_t[1].alias_if ) == 0) ||
					(strlen( cmd_alias_ip_ptr->alias_t[1].alias_if ) > 0 && 
					strlen( cmd_alias_ip_ptr->alias_t[0].alias_if ) == 0) )
			
				{
					snprintf(
						resp, REPLY_TEXT, "%s(): specified single interface %s - %s when need two for redundancy mode [%d]\n",
						__FUNCTION__,
						( strlen( cmd_alias_ip_ptr->alias_t[0].alias_if ) > 0 ? cmd_alias_ip_ptr->alias_t[0].alias_if : "empty" ),
						( strlen( cmd_alias_ip_ptr->alias_t[1].alias_if ) > 0 ? cmd_alias_ip_ptr->alias_t[1].alias_if : "empty" ),
						subnet_ptr->redundancy_mode
					);

					LOG_ERROR(0, resp);

					return IPM_FAILURE;
				}
			    }
                            strcpy(ipdata_ptr->lsn0_iface, cmd_alias_ip_ptr->alias_t[0].alias_if);
                            strcpy(ipdata_ptr->lsn1_iface, cmd_alias_ip_ptr->alias_t[1].alias_if);

			    /* create the bfd session */
			    if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
			    {
				eipm_bfd_retval = EIPM_bfd_admin_change_cfg_sess(
					intf_idx,
					subnet_idx,
					&ip
				    );

				if ( eipm_bfd_retval != IPM_SUCCESS )
				{
					snprintf(
						resp, REPLY_TEXT, "%s(): EIPM_bfd_admin_change_cfg_sess( %d, %d, ... ) failed [%d]\n",
						__FUNCTION__,
						intf_idx,
						subnet_idx,
						eipm_bfd_retval
					);

					LOG_ERROR(0, resp);

					return IPM_FAILURE;
				}
			    }
			    else if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP && ip_idx == 0 )
			    {
				eipm_arpndp_retval = EIPM_arpndp_admin_change_cfg_sess(
					intf_idx,
					subnet_ptr,
					&(subnet_ptr->ips[0].ipaddr)
				    );

				if ( eipm_arpndp_retval != IPM_SUCCESS )
				{
					snprintf(
						resp, REPLY_TEXT, "%s(): EIPM_arpndp_admin_change_cfg_sess( %d, %p, ... ) for subnet_idx (%d) failed [%d]\n",
						__FUNCTION__,
						intf_idx,
						subnet_ptr,
						subnet_idx,
						eipm_arpndp_retval
					);

					LOG_ERROR(0, resp);

					return IPM_FAILURE;
				}
			    }
                        }
                        else if( type == EIPM_DEL )
                        {
                            int nl_socket;
                            int del_index;

                            /* Attempt to delete IP from interfaces (may not be plumbed),
                             * then delete IP from data, collapse IP table 
                             */

                            nl_socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

                            if( nl_socket < 0 )
                            {
                                ASRT_RPT( ASUNEXP_RETURN,
                                          1,
                                          sizeof(*intf_ptr),
                                          intf_ptr,
                                          "EIPM_intf_update: Failed to create routing socket\nretval=%d, errno=0x%x\n",
                                           nl_socket,
                                           errno );
                            }
                            else
                            {
                                struct sockaddr_nl nladdr;

                                nladdr.nl_family = AF_NETLINK;
                                nladdr.nl_pad = 0;
                                nladdr.nl_pid = 0;
                                nladdr.nl_groups = 0;

                                retval = bind(nl_socket, (struct sockaddr *)&nladdr, sizeof(nladdr));

                                if( retval < 0 )
                                {
                                    ASRT_RPT( ASUNEXP_RETURN,
                                              1,
                                              sizeof(*intf_ptr),
                                              intf_ptr,
                                              "EIPM_intf_update: Failed to bind to routing socket\nretval=%d, errno=0x%x\n",
                                               retval,
                                               errno );
                                }
                                else
                                {
					if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
					{
						/* need to call delete */
						(void)EIPM_bfd_admin_destroy_sess(
							intf_idx,
							subnet_idx,
							&ipdata_ptr->ipaddr
						    );
					}
					else if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP && ip_idx == 0 )
					{
						/* Removing the IP used for ARP/NDP session,
						 * use the next available IP or stop the session.
						 */
						if (subnet_ptr->ip_cnt > 1)
						{
							eipm_arpndp_retval = EIPM_arpndp_admin_change_cfg_sess(
								intf_idx,
								subnet_ptr,
								&(subnet_ptr->ips[1].ipaddr)
							    );

							if (eipm_arpndp_retval != ARPNDP_SUCCESS)
							{
								snprintf(
									resp, REPLY_TEXT,
									"%s(): EIPM_arpndp_admin_change_cfg_sess( %d, %p, ... ) for subnet_idx (%d) failed [%d]\n",
									__FUNCTION__,
									intf_idx,
									subnet_ptr,
									subnet_idx,
									eipm_arpndp_retval
								);

								LOG_ERROR(0, resp);

								return IPM_FAILURE;
							}
						}
						else
						{
							EIPM_arpndp_admin_destroy_sess( intf_idx, &(subnet_ptr->gateway) );
						}
					}

					if ( intf_ptr->lsn0_baseif[0] != 0 )
					{
                                    		(void)EIPM_DELETE_IP( nl_socket,
                                                          ipdata_ptr->type,
                                                          &ipdata_ptr->ipaddr,
                                                          subnet_ptr->prefixlen,
                                                          intf_ptr->specData.lsn0_iface_indx,
                                                          intf_ptr->lsn0_baseif
						);
					}

					if ( intf_ptr->lsn1_baseif[0] != 0 )
					{
                                    		(void)EIPM_DELETE_IP( nl_socket,
                                                          ipdata_ptr->type,
                                                          &ipdata_ptr->ipaddr,
                                                          subnet_ptr->prefixlen,
                                                          intf_ptr->specData.lsn1_iface_indx,
                                                          intf_ptr->lsn1_baseif
						);
					}
                                }

                                (void)close(nl_socket);
                            }

			    EIPM_CLEAR_AND_DELETE_IP_ALARM( intf_ptr, subnet_idx, ip_idx, EIPM_MAX_ALARM );

                            subnet_ptr->ip_cnt--;

                            for( del_index = ip_idx;
                                 del_index < subnet_ptr->ip_cnt;
                                 del_index++ )
                            {
                                subnet_ptr->ips[del_index] = subnet_ptr->ips[del_index + 1];
                            }

                            /* Clear last IP entry */
                            memset(&subnet_ptr->ips[del_index], 0, sizeof(subnet_ptr->ips[0]));

                            /* Check for last IP in subnet */
                            if( subnet_ptr->ip_cnt == 0 && subnet_ptr->delete_flag == FALSE)
                            {
				switch((IPM_REDUNDANCY_MODE)subnet_ptr->redundancy_mode)
				{
				case IPM_RED_BFD_TRANSPORT:
				case IPM_RED_EIPM_BFD:
				case IPM_RED_BFD_RSR:
					/* These subnet types have status NULL when
					 * no IP addrs provisioned.
					 */

					subnet_ptr->status = EIPM_STAT_NULL;
					break;

				case IPM_RED_EIPM_ARPNDP:
					subnet_ptr->status = EIPM_STAT_NULL;
					subnet_ptr->arpndp_status = EIPM_STAT_NULL;
					break;

				default:	/* Do Nothing */
					break;

				} /* switch(redundancy_mode) */

				/* clear the route info */
				route_ptr = &subnet_ptr->routes[0];
				memset(route_ptr, 0, sizeof(EIPM_ROUTES));
				subnet_ptr->route_cnt = 0;

				/* Clear any subnet alarms */
				EIPM_CLEAR_SUBNET_ALARM( intf_ptr, EIPM_BASE_INTF, subnet_idx, EIPM_MAX_ALARM );

                                del_index = subnet_idx;
                                /* Clear alarm data */
                                memset(&intf_ptr->specData.alarm[del_index][0], 0, sizeof(intf_ptr->specData.alarm[0]));
                                /* Check for last subnet in interface */
                                if( intf_ptr->subnet_cnt == 0 &&
                                    eipm_delete_interface_with_no_subnet == TRUE )
                                {
				    /* Clear any interface alarms alarms */
				    EIPM_CLEAR_INTF_ALARM( intf_ptr, EIPM_BASE_INTF, EIPM_MAX_ALARM );

                                } /* check interface subnet count */
			    }
			    else if ( subnet_ptr->ip_cnt == 0 && subnet_ptr->delete_flag == TRUE )
			    {
				struct cmd_subnet_upd subnet_info;
				char reply_text[REPLY_TEXT];

				memset( &subnet_info, 0, sizeof(subnet_info));

				subnet_info.redundancy_mode = (int) subnet_ptr->redundancy_mode;
				subnet_info.prefix = subnet_ptr->prefixlen;
				IPM_ipaddr2p(&subnet_ptr->subnet_base, subnet_info.subnet_base, IPM_IPMAXSTRSIZE);
				if ( strlen( intf_ptr->lsn0_baseif) > 0 )
				{
					subnet_info.dev_t[0].subnet_type = IPM_SUBNET_EXTERNAL;
					strncpy( subnet_info.dev_t[0].dev_if, intf_ptr->lsn0_baseif, MAX_NLEN_DEV );
				}

				if ( strlen( intf_ptr->lsn1_baseif) > 0 )
				{
					subnet_info.dev_t[1].subnet_type = IPM_SUBNET_EXTERNAL;
					strncpy( subnet_info.dev_t[1].dev_if, intf_ptr->lsn1_baseif, MAX_NLEN_DEV );
				}

				retval = EIPM_subnet_update(&subnet_info, EIPM_DEL, reply_text, NON_CLI_REQUEST);
				if ( retval < 0 )
				{
					/* error should be logged */
					return retval;
				}

                            } /* check subnet IP count */

			    // Schedule configuration check 
			    EIPM_CHECK_INTF_CONFIG(&(intf_ptr->specData));
                        } /* handle IP action */

                        return IPM_SUCCESS;

                    } /* IP match */

                } /* IP search */

                /* Subnet match, no IP match -> Add IP */
                if( type == EIPM_ADD )
                {
		    if( subnet_ptr->ip_cnt < EIPM_MAX_IPS )
		    {
			if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
			{
				if ( strlen( cmd_alias_ip_ptr->alias_t[0].alias_if ) > 0 && 
					strlen( cmd_alias_ip_ptr->alias_t[1].alias_if ) > 0 )
				{
					snprintf(
						resp, REPLY_TEXT, "%s(): specified two interfaces %s - %s when need one for redundancy mode [%d]\n",
						__FUNCTION__,
						cmd_alias_ip_ptr->alias_t[0].alias_if,
						cmd_alias_ip_ptr->alias_t[1].alias_if,
						subnet_ptr->redundancy_mode
					);

					LOG_ERROR(0, resp);

					return IPM_FAILURE;
				}
			}
			else if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD ||
                                  (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR )
			{
				if ( (strlen( cmd_alias_ip_ptr->alias_t[0].alias_if ) > 0 && 
					strlen( cmd_alias_ip_ptr->alias_t[1].alias_if ) == 0) ||
					(strlen( cmd_alias_ip_ptr->alias_t[1].alias_if ) > 0 && 
					strlen( cmd_alias_ip_ptr->alias_t[0].alias_if ) == 0) )
				{
					snprintf(
						resp, REPLY_TEXT, "%s(): specified single interface %s - %s when need two for redundancy mode [%d]\n",
						__FUNCTION__,
						( strlen( cmd_alias_ip_ptr->alias_t[0].alias_if ) > 0 ? cmd_alias_ip_ptr->alias_t[0].alias_if : "empty" ),
						( strlen( cmd_alias_ip_ptr->alias_t[1].alias_if ) > 0 ? cmd_alias_ip_ptr->alias_t[1].alias_if : "empty" ),
						subnet_ptr->redundancy_mode
					);

					LOG_ERROR(0, resp);

					return IPM_FAILURE;
				}
			}

			if (( subnet_ptr->ip_cnt == 0 ) &&
			    (( subnet_ptr->subnet_base.addrtype == IPM_IPV4 &&
			      subnet_ptr->prefixlen < 32 ) ||
			    ( subnet_ptr->subnet_base.addrtype == IPM_IPV6 &&
			      subnet_ptr->prefixlen < 128 ))) 
			{
				/* route info */
				route_ptr = &subnet_ptr->routes[0];

				route_ptr->type = EIPM_ROUTE_SUBN;
				route_ptr->dest = subnet_ptr->subnet_base;
				route_ptr->destprefix = subnet_ptr->prefixlen;
				IPM_ipaddr_init(&route_ptr->nexthop);
				IPM_ipaddr_init(&route_ptr->source_ip);
				if( subnet_ptr->subnet_base.addrtype == IPM_IPV4 )
				{
					(void)IPM_p2ipaddr("0.0.0.0", &route_ptr->nexthop);
					(void)IPM_p2ipaddr("0.0.0.0", &route_ptr->source_ip);
				}
				else if( subnet_ptr->subnet_base.addrtype == IPM_IPV6 )
				{
					(void)IPM_p2ipaddr("::", &route_ptr->nexthop);
					(void)IPM_p2ipaddr("::", &route_ptr->source_ip);
				}
	
				subnet_ptr->route_cnt = 1;
			}

			if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
			{
				if ( strlen( iface0_base_ptr ) > 0 )
				{
					for ( bfd_subnet_idx = 0, bfd_subnet_ptr = &intf_ptr->subnet[0];
						bfd_subnet_idx < intf_ptr->subnet_cnt;
						bfd_subnet_idx++, bfd_subnet_ptr++ )
					{
						if ( ((IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD ||
                                                      (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR) &&
							subnet_ptr->subnet_base.addrtype == bfd_subnet_ptr->subnet_base.addrtype )
						{
							bfd_subnet_ptr->gateway = subnet_ptr->gateway;
						}
					}
				}
			}
                        ipdata_ptr = &subnet_ptr->ips[subnet_ptr->ip_cnt];

			memset(ipdata_ptr, 0, sizeof(EIPM_IPDATA));
                        ipdata_ptr->type = EIPM_IP_ALIAS;
                        ipdata_ptr->ipaddr = ip;
                        strcpy(ipdata_ptr->lsn0_iface, cmd_alias_ip_ptr->alias_t[0].alias_if);
                        strcpy(ipdata_ptr->lsn1_iface, cmd_alias_ip_ptr->alias_t[1].alias_if);

                        EIPM_set_ip_config_time(ipdata_ptr);

                        subnet_ptr->ip_cnt++;

			EIPM_open_garpsock( &(intf_ptr->specData), ip.addrtype );

			// Trigger to send GARP once this IP is added
			EIPM_SET_GRAT_ARP( subnet_ptr, subnet_ptr->sub2intf_mapping[0].route_priority );

			/* check if BFD session */
			if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
			{
				IPM_REDUNDANCY_MODE eipm_red_mode = IPM_RED_EIPM_BFD;
				for ( bfd_subnet_idx = 0, bfd_subnet_ptr = &intf_ptr->subnet[0];
						bfd_subnet_idx < intf_ptr->subnet_cnt;
						bfd_subnet_idx++, bfd_subnet_ptr++ )
				{
					if ( subnet_ptr->subnet_base.addrtype == bfd_subnet_ptr->subnet_base.addrtype )
					{
						eipm_red_mode = (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode;
						break;
					}
				}

				/* add the bfd sessions */
				eipm_bfd_retval = EIPM_bfd_admin_create_sess(
					intf_idx,
					subnet_idx,
					&ip
					,eipm_red_mode
				    );

				if ( eipm_bfd_retval != IPM_SUCCESS )
				{
					snprintf(
						resp, REPLY_TEXT, "%s(): EIPM_bfd_admin_create_sess( %d, %d, ... ) failed [%d]\n",
						__FUNCTION__,
						intf_idx,
						subnet_idx,
						eipm_bfd_retval
					);

					LOG_ERROR(0, resp);

					return IPM_FAILURE;
				}
			}
			else if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR )
			{
				EIPM_bfd_rsr_svc_sn_trans_sn_chk(
					intf_idx,
					subnet_idx
				    );
			}
			else if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP && subnet_ptr->ip_cnt == 1 )
			{
				eipm_arpndp_retval = EIPM_arpndp_admin_create_sess(
					intf_idx,
					subnet_ptr,
					&(subnet_ptr->ips[0].ipaddr)
				    );

				if ( eipm_arpndp_retval != IPM_SUCCESS )
				{
					snprintf(
						resp, REPLY_TEXT, "%s(): EIPM_arpndp_admin_create_sess( %d, %p, ... ) for subnet_idx (%d) failed [%d]\n",
						__FUNCTION__,
						intf_idx,
						subnet_ptr,
						subnet_idx,
						eipm_arpndp_retval
					);

					LOG_ERROR(0, resp);

					return IPM_FAILURE;
				}

				eipm_arpndp_retval = EIPM_arpndp_start( intf_idx, subnet_idx );

				if ( eipm_arpndp_retval != IPM_SUCCESS )
				{
					snprintf(
						resp, REPLY_TEXT, "%s(): EIPM_arpndp_start( %d, %d ) failed [%d]\n",
						__FUNCTION__,
						intf_idx,
						subnet_idx,
						eipm_arpndp_retval
					);

					LOG_ERROR(0, resp);

					return IPM_FAILURE;
				}
			}

			switch((IPM_REDUNDANCY_MODE)subnet_ptr->redundancy_mode)
			{
			case IPM_RED_BFD_TRANSPORT:	
			case IPM_RED_EIPM_BFD:
			case IPM_RED_BFD_RSR:
				/* These subnet types have status NULL when
				 * no IP addrs provisioned, but OFFLINE when
				 * the first IP addr is provisioned.
				 * Also, each newly provisioned IPs state
				 * should be OFFLINE.
				 */

				ipdata_ptr->state = EIPM_OFFLINE;

				if (subnet_ptr->status == EIPM_STAT_NULL)
				{
					if (subnet_ptr->ip_cnt == 1)
					{
						subnet_ptr->status = ipdata_ptr->state;
					}
					else
					{
						LOG_ERROR( 0,
							"%s(): Subnet intf_idx %d subnet_idx %d has status NULL but ip_cnt %d\n",
							__FUNCTION__,
							intf_idx,
							subnet_idx,
							subnet_ptr->ip_cnt
						);
					}
				}
				break;

			default:	/* Do Nothing */
				break;

			} /* switch(redundancy_mode) */
		    }
  		    else
		    {
		        snprintf(resp, REPLY_TEXT, "EIPM_intf_update(): Max Number of IPs Reached %d\n", 
				 subnet_ptr->ip_cnt);

		        LOG_ERROR(0, resp);
			return IPM_FAILURE;
		    }
                }
                else if( type == EIPM_DEL )
                {
                    snprintf( resp, REPLY_TEXT, 
	                      "EIPM_intf_update(): Failed to find/delete %s/%d on any subnet in %s - %s",
                               cmd_alias_ip_ptr->alias_t[0].ip, 
                               cmd_alias_ip_ptr->alias_t[0].prefix, 
                               ( cmd_alias_ip_ptr->alias_t[0].alias_if[0] != 0 ? cmd_alias_ip_ptr->alias_t[0].alias_if : "empty" ),
                               ( cmd_alias_ip_ptr->alias_t[1].alias_if[0] != 0 ? cmd_alias_ip_ptr->alias_t[1].alias_if : "empty" )
		    );

                    LOG_DEBUG(0, resp);
                }

                return IPM_SUCCESS;

            } /* subnet match */

        } /* subnet search */


    } /* interface search */

    snprintf( resp, REPLY_TEXT,
	"EIPM_intf_update(): Failed to match %s - %s for %s/%d %s",
	( cmd_alias_ip_ptr->alias_t[0].alias_if[0] != 0 ? cmd_alias_ip_ptr->alias_t[0].alias_if : "empty" ),
	( cmd_alias_ip_ptr->alias_t[1].alias_if[0] != 0 ? cmd_alias_ip_ptr->alias_t[1].alias_if : "empty" ),
	cmd_alias_ip_ptr->alias_t[0].ip,
	cmd_alias_ip_ptr->alias_t[0].prefix,
	( type == EIPM_DEL ? "delete" : "add" )
    );

    if ( type == EIPM_ADD )
    {
    	LOG_ERROR(0, resp);

	return IPM_FAILURE;
    }
    else
    {
	LOG_DEBUG(0, resp);

	return IPM_SUCCESS;
    }

}




/**********************************************************************
 *
 * Name:	EIPM_arp_update()
 *
 * Abstract:	Called when IPM receives a message with ARP data for 
 *		an external interface.
 *
 * Parameters:	msg_ptr - pointer to data message
 *		type    - whether adding or deleting ARP data
 *		resp    - pointer to text string response to user
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int EIPM_arp_update( struct cmd_arp_list *cmd_arp_list_ptr, 
                     EIPM_ADD_DEL type,
                     char *resp )
{
EIPM_DATA	*data_ptr;
EIPM_INTF	*intf_ptr;
EIPM_SUBNET	*subnet_ptr;
IPM_IPADDR	arp_ip;
IPM_IPADDR	arp_subnet_mask;
IPM_IPADDR	arp_subnet_base;
int 		intf_idx;
int 		subnet_idx;
IPM_RETVAL 	ipm_retval;
int     iface_flag = 0;
int     iface_add_flag = 0;


    /* Check for EIPM memory */
    if( EIPM_shm_ptr == NULL )
    {
        snprintf(resp, REPLY_TEXT, "EIPM Arp Config Failure: Shared memory null, ArpIP %s\n", 
		 cmd_arp_list_ptr->ip);

        LOG_ERROR(0, resp);

        return IPM_FAILURE;
    }

    data_ptr = (EIPM_DATA *)EIPM_shm_ptr;


    /* Convert ARP IP */
    IPM_ipaddr_init(&arp_ip);
	
    ipm_retval = IPM_p2ipaddr(cmd_arp_list_ptr->ip, &arp_ip);

    if( ipm_retval != IPM_SUCCESS )
    {
        snprintf(resp, REPLY_TEXT, "EIPM Arp Config Failure: Failed %d to translate ArpIP %s\n", 
		 ipm_retval, cmd_arp_list_ptr->ip);

        LOG_ERROR(0, resp);

        return ipm_retval;
    }

    IPM_ipaddr_init(&arp_subnet_mask);

    ipm_retval = IPM_ipmkmask(&arp_subnet_mask, arp_ip.addrtype, cmd_arp_list_ptr->prefix);

    if( ipm_retval != IPM_SUCCESS )
    {
        snprintf(resp, REPLY_TEXT, "EIPM Arp Config Failure: Failed %d to create Mask for %s/%d\n",
                 ipm_retval, cmd_arp_list_ptr->ip, cmd_arp_list_ptr->prefix);

        LOG_ERROR(0, resp);

        return ipm_retval;
    }

    IPM_ipaddr_init(&arp_subnet_base);

    IPM_get_subnet(&arp_ip, &arp_subnet_mask, &arp_subnet_base);

    if ((strlen(cmd_arp_list_ptr->iface[0]) > 0) && (strlen(cmd_arp_list_ptr->iface[1]) > 0))
    {
        iface_flag = 1;
    }

    /* Other defensive checks, eg. network base, broadcast IP ?? */


    /* Search through existing data looking for a subnet match:
     * If match is found:
     * - If action is delete -> delete entry
     * - If action is add -> add/update ARP entry
     * If match is not found:
     * - report error
     */
	
    /* Look through all interfaces */
    for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
         intf_idx < data_ptr->intf_cnt;
         intf_idx++, intf_ptr++ )
    {
        /* Look through all subnets */
        for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
             subnet_idx < intf_ptr->subnet_cnt;
             subnet_idx++, subnet_ptr++ )
        {
            if(( IPM_IPCMPADDR(&subnet_ptr->subnet_base, &arp_subnet_base) == IPM_SUCCESS )
		&& (iface_flag == 0))
            {
                /* Found a match */
                EIPM_ARP_ITEM *arp_item_ptr = &subnet_ptr->arpdata.arp_list[cmd_arp_list_ptr->priority-1];

                arp_item_ptr->lsn0_arprcvd = FALSE;
                arp_item_ptr->lsn1_arprcvd = FALSE;

                if( type == EIPM_ADD )
                {
                    arp_item_ptr->arp_ip = arp_ip;
                }
                else if( type == EIPM_DEL )
                {
                    IPM_ipaddr_init(&arp_item_ptr->arp_ip);
                }

                subnet_ptr->arpdata.cur_index = cmd_arp_list_ptr->priority-1;

		if ( intf_ptr->specData.state != NORMAL_STATE )
 		{
 		    /*
 		     * Clear the ARP counter.  This will cause an ARP to 
 		     * immediately be sent.
 		     */
  		    subnet_ptr->arp_counter = 2;
 		}
 		else
 		{
 		    subnet_ptr->arp_counter = EIPM_ARP_IP_WAIT * EIPM_ARP_CNT_PER_SEC;
 		}

                return IPM_SUCCESS;
            }
           else if ((iface_flag == 1 )
                    && (strcmp(intf_ptr->lsn0_baseif, cmd_arp_list_ptr->iface[0]) == 0)
                    && (strcmp(intf_ptr->lsn1_baseif, cmd_arp_list_ptr->iface[1]) == 0))
            {
                /* Found a match */
                iface_add_flag = 1;
                EIPM_ARP_ITEM *arp_item_ptr = &subnet_ptr->arpdata.arp_list[cmd_arp_list_ptr->priority-1];

                arp_item_ptr->lsn0_arprcvd = FALSE;
                arp_item_ptr->lsn1_arprcvd = FALSE;

                if( type == EIPM_ADD )
                {
                    arp_item_ptr->arp_ip = arp_ip;
                }
                else if( type == EIPM_DEL )
                {
                    IPM_ipaddr_init(&arp_item_ptr->arp_ip);
                }

                subnet_ptr->arpdata.cur_index = cmd_arp_list_ptr->priority-1;

                if( intf_ptr->specData.state != NORMAL_STATE )
                {
                    subnet_ptr->arp_counter = 2;
                }
                else
                {
                    subnet_ptr->arp_counter = EIPM_ARP_IP_WAIT * EIPM_ARP_CNT_PER_SEC;
                }
            }

        }
	if (iface_add_flag == 1) return IPM_SUCCESS;
    }

    snprintf(resp, REPLY_TEXT, "EIPM Arp Config Failure: No subnet match for ARP %s/%d\n",
             cmd_arp_list_ptr->ip, cmd_arp_list_ptr->prefix);


    if( type == EIPM_DEL )
    {
        /* Multiple ARP deletes may occur so only report them at a debug level */
        LOG_DEBUG(0, resp);

        return IPM_SUCCESS;
    }
    else 
    {
        LOG_ERROR(0, resp);

        return IPM_FAILURE;
    }
}




/**********************************************************************
 *
 * Name:	EIPM_route_update()
 *
 * Abstract:	Called when IPM receives a message with data for 
 *		static routes for an external interface
 *
 * Parameters:	msg_ptr - pointer to data message
 *		type    - whether adding or deleting interface
 *		resp    - pointer to text string response to user
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int EIPM_route_update( struct cmd_route_upd *cmd_route_upd_ptr,
		       EIPM_ADD_DEL type, 
		       char *resp )
{
EIPM_DATA	*data_ptr;
EIPM_INTF	*intf_ptr;
EIPM_SUBNET	*subnet_ptr;
EIPM_ROUTES	*route_ptr;
IPM_IPADDR 	dest_mask;
IPM_IPADDR 	dest_base;
IPM_IPADDR	dest_ip;
IPM_IPADDR	nexthop_ip;
IPM_IPADDR	source_ip;
int 		intf_idx;
int 		subnet_idx;
int 		route_idx;
int 		matching_intf_idx;
int 		matching_subnet_idx;
int 		matching_route_idx;
IPM_RETVAL 	ipm_retval;
int		iface_flag = 0;



    /* Check for EIPM memory */
    if( EIPM_shm_ptr == NULL )
    {
        snprintf(resp, REPLY_TEXT, "EIPM Route Config: Shared memory null, DestIP %s\n", 
		 cmd_route_upd_ptr->dest);

        LOG_ERROR(0, resp);

        return IPM_FAILURE;
    }

    data_ptr = (EIPM_DATA *)EIPM_shm_ptr;


    /* Convert Destination IP */
    IPM_ipaddr_init(&dest_ip);
	
    ipm_retval = IPM_p2ipaddr(cmd_route_upd_ptr->dest, &dest_ip);

    if( ipm_retval != IPM_SUCCESS )
    {
        snprintf(resp, REPLY_TEXT, "EIPM Route Config: Failure %d to translate DestIP %s\n", 
		 ipm_retval, cmd_route_upd_ptr->dest);

        LOG_ERROR(0, resp);

        return ipm_retval;
    }

    IPM_ipaddr_init(&dest_mask);

    ipm_retval = IPM_ipmkmask(&dest_mask, 
                               dest_ip.addrtype, 
			       cmd_route_upd_ptr->prefix);

    if( ipm_retval != IPM_SUCCESS )
    {
	snprintf(resp, REPLY_TEXT, 
                 "EIPM Route Config: Failure %d to create Destination Mask for %s from subnet prefix %d\n",
                 ipm_retval, cmd_route_upd_ptr->dest, cmd_route_upd_ptr->prefix);

	LOG_ERROR(0, resp);

	return ipm_retval;
    }

    IPM_ipaddr_init(&dest_base);

    IPM_get_subnet(&dest_ip, &dest_mask, &dest_base);

    /* Conditionally convert NextHop IP */
    IPM_ipaddr_init(&nexthop_ip);

    /* Conditionally convert Source IP */
    IPM_ipaddr_init(&source_ip);

    if( type == EIPM_ADD )
    {
        ipm_retval = IPM_p2ipaddr(cmd_route_upd_ptr->nexthop, &nexthop_ip);

        if( ipm_retval != IPM_SUCCESS )
        {
            snprintf(resp, REPLY_TEXT, "EIPM Route Config: Failure %d to translate NextHopIP %s\n",
		     ipm_retval, cmd_route_upd_ptr->nexthop);

            LOG_ERROR(0, resp);

            return ipm_retval;
        }
        if ((strlen(cmd_route_upd_ptr->iface[0]) > 0) && (strlen(cmd_route_upd_ptr->iface[1]) > 0))
        {
            iface_flag = 1;	
        }

	if ( strlen(cmd_route_upd_ptr->source_ip) > 0 )
	{
		ipm_retval = IPM_p2ipaddr(cmd_route_upd_ptr->source_ip, &source_ip);

		if ( ipm_retval != IPM_SUCCESS )
		{
            		snprintf(resp, REPLY_TEXT,
					"%s: Failure %d to translate Source IP %s\n",
					__FUNCTION__,
					ipm_retval, cmd_route_upd_ptr->source_ip
			);

			LOG_ERROR(0, resp);

            		return ipm_retval;
		}
	}
	else
	{
		if( nexthop_ip.addrtype == IPM_IPV4 )
		{
			(void)IPM_p2ipaddr("0.0.0.0", &source_ip);
		}
		else
		{
			(void)IPM_p2ipaddr("::", &source_ip);
		}

	}
    }

    if (cmd_route_upd_ptr->pivot_id >= MAX_NUM_PIVOT)
    {
        snprintf(resp, REPLY_TEXT,
                "EIPM Route Config: pivot id %d is out of range, max is %d\n",
                cmd_route_upd_ptr->pivot_id, MAX_NUM_PIVOT);
        LOG_ERROR(0, resp);
        return IPM_FAILURE;
    }

    /* Other defensive checks, eg. subnet route ?? */

    /* Search through existing data looking for a match:
     * If DestIP match is found:
     * - If action is delete -> delete entry, collapse table
     * - If action is add -> update entry
     * If DestIP match is not found:
     * - If action is delete -> nothing to do
     * - If action is add -> look for a nextHop subnet match
     *   If a subnet match is found then add new route
     */
    matching_intf_idx = -1;
	
    /* Look through all interfaces */
    for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
         intf_idx < data_ptr->intf_cnt;
         intf_idx++, intf_ptr++ )
    {
	/*
	 * If there are interfaces in command line parameter, then
	 * it must match current interfaces in EIPM_INTF. Otherwise, look up next
	 * matched interfaces
	 */
       if( (iface_flag == 1) &&
            ( (strcmp(intf_ptr->lsn0_baseif, cmd_route_upd_ptr->iface[0]) != 0) &&
              (strcmp(intf_ptr->lsn1_baseif, cmd_route_upd_ptr->iface[1]) != 0)
            )
          )
        {
                continue;
        }

        matching_subnet_idx = -1;

        /* Look through all subnets */
        for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
             subnet_idx < intf_ptr->subnet_cnt;
             subnet_idx++, subnet_ptr++ )
        {
            matching_route_idx = -1;

            /* Look through all routes */
            for( route_idx = 0, route_ptr = &subnet_ptr->routes[0];
                 route_idx < subnet_ptr->route_cnt;
                 route_idx++, route_ptr++ )
            {
                if( cmd_route_upd_ptr->prefix == route_ptr->destprefix && 
                    IPM_IPCMPADDR(&dest_base, &route_ptr->dest) == IPM_SUCCESS &&
		    route_ptr->pivot_id == cmd_route_upd_ptr->pivot_id )
                {
                    /* Found a match */
                    if( type == EIPM_ADD )
                    {
			/* Routes can be added multiple times, just ignore duplicates */
	                if ( ( IPM_IPCMPADDR( &nexthop_ip, &route_ptr->nexthop ) == IPM_SUCCESS &&
				strlen( cmd_route_upd_ptr->source_ip ) == 0 ) ||
				( IPM_IPCMPADDR(&nexthop_ip, &route_ptr->nexthop) == IPM_SUCCESS &&
				strlen( cmd_route_upd_ptr->source_ip ) > 0 &&
				IPM_IPCMPADDR( &source_ip, &route_ptr->source_ip ) == IPM_SUCCESS ) )
			{
			    return IPM_SUCCESS;
			}

	                /* Next, check for nexthop subnet match.
	                 */
	                IPM_IPADDR subnet_mask;
	                IPM_IPADDR nexthop_base;

	                IPM_ipaddr_init(&subnet_mask);

	                ipm_retval = IPM_ipmkmask(&subnet_mask, 
	                                          subnet_ptr->subnet_base.addrtype, 
	                                          subnet_ptr->prefixlen);

	                if( ipm_retval != IPM_SUCCESS )
	                {
	                    snprintf(resp, REPLY_TEXT, 
	                             "EIPM Route Config: Failure %d to create SubnetMask for %s from subnet prefix %d\n",
			              ipm_retval, cmd_route_upd_ptr->nexthop, subnet_ptr->prefixlen);

	                    LOG_ERROR(0, resp);

	                    return ipm_retval;
	                }

	                IPM_ipaddr_init(&nexthop_base);
	                IPM_get_subnet(&nexthop_ip, &subnet_mask, &nexthop_base);

                        matching_route_idx = route_idx;
                        matching_subnet_idx = subnet_idx;
                        matching_intf_idx = intf_idx;

	                if ( ( IPM_IPCMPADDR(&subnet_ptr->subnet_base, &nexthop_base) == IPM_SUCCESS &&
				strlen( cmd_route_upd_ptr->source_ip ) == 0 ) ||
				( IPM_IPCMPADDR(&subnet_ptr->subnet_base, &nexthop_base) == IPM_SUCCESS &&
				strlen( cmd_route_upd_ptr->source_ip ) > 0  &&
				IPM_IPCMPADDR(&route_ptr->source_ip, &source_ip) == IPM_SUCCESS ) )
			{
                            /* Update entry */
                            route_ptr->nexthop = nexthop_ip;

			    EIPM_CHECK_INTF_CONFIG( &(intf_ptr->specData) );
			}
			else
			{
                            EIPM_ROUTES *del_route_ptr;
                            int del_index;
                            char resp_buff[REPLY_TEXT];

                            /* First delete the routing entry from the old subnet
                             * and then it will be added to the new subnet below.
                             */

                            /* Delete entry by collapsing table */
                            subnet_ptr->route_cnt--;

			    route_ptr->pivot_id = 0;

                            for( del_index = route_idx; 
                                 del_index < subnet_ptr->route_cnt; 
                                 del_index++ )
                            {
                                subnet_ptr->routes[del_index] = subnet_ptr->routes[del_index + 1];
                            }

                            /* Clear last entry */
                            del_route_ptr = &subnet_ptr->routes[del_index];

                            memset(del_route_ptr, 0, sizeof(*del_route_ptr));
				
                            /* Now add the new route */
                            (void)EIPM_route_update(cmd_route_upd_ptr,
                                                    EIPM_ADD,
                                                    resp_buff);

			    EIPM_CHECK_INTF_CONFIG( &(intf_ptr->specData) );
                            return IPM_SUCCESS;
                        }
                    }
                    else if( type == EIPM_DEL )
                    {
                        EIPM_ROUTES *del_route_ptr;
                        int del_index;
                        int nl_socket;

                        matching_route_idx = route_idx;
                        matching_subnet_idx = subnet_idx;
                        matching_intf_idx = intf_idx;

                        nl_socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

                        if( nl_socket < 0 )
                        {
                            ASRT_RPT(ASUNEXP_RETURN,
                                     1,
                                     sizeof(*intf_ptr),
                                     intf_ptr,
                                     "EIPM_route_update - failed to create routing socket\nretval=%d, errno=0x%x\n",
                                      nl_socket, errno);
                        }
                        else
                        {
                            struct sockaddr_nl nladdr;
                            int retval;

                            nladdr.nl_family = AF_NETLINK;
                            nladdr.nl_pad = 0;
                            nladdr.nl_pid = 0;
                            nladdr.nl_groups = 0;

                            retval = bind(nl_socket, (struct sockaddr *)&nladdr, sizeof(nladdr));

                            if( retval < 0 )
                            {
                                ASRT_RPT(ASUNEXP_RETURN,
                                         1,
                                         sizeof(*intf_ptr),
                                         intf_ptr,
                                         "EIPM_route_update - bind for routing interface socket failed\nretval=%d, errno=0x%x\n",
                                          retval, errno);
                            }
                            else
                            {
                                (void)nma_route_del(nl_socket,
                                                    intf_ptr->specData.lsn1_iface_indx,
                                                    intf_ptr->lsn1_baseif,
                                                    &route_ptr->dest,
                                                    route_ptr->destprefix,
                                                    (route_ptr->type == EIPM_ROUTE_SUBN) ? NULL : &route_ptr->nexthop);

                                (void)nma_route_del(nl_socket,
                                                    intf_ptr->specData.lsn0_iface_indx,
                                                    intf_ptr->lsn0_baseif,
                                                    &route_ptr->dest,
                                                    route_ptr->destprefix,
                                                    (route_ptr->type == EIPM_ROUTE_SUBN) ? NULL : &route_ptr->nexthop);
                            }

                            (void)close(nl_socket);
                        }

                        /* Delete entry by collapsing table */
                        subnet_ptr->route_cnt--;

			route_ptr->pivot_id = 0;

                        for( del_index = route_idx; 
                             del_index < subnet_ptr->route_cnt; 
                             del_index++ )
                        {
                            subnet_ptr->routes[del_index] = subnet_ptr->routes[del_index + 1];
                        }

                        /* Clear last entry */
                        del_route_ptr = &subnet_ptr->routes[del_index];

                        memset(del_route_ptr, 0, sizeof(*del_route_ptr));
                    }
                }
            }

            if( type == EIPM_ADD && matching_route_idx == -1 )
            {
                /* Didn't find existing route entry,
                 * Check for nexthop subnet match.
                 */
                IPM_IPADDR subnet_mask;
                IPM_IPADDR nexthop_base;
                IPM_IPADDR destbase_base;

                IPM_ipaddr_init(&subnet_mask);

                ipm_retval = IPM_ipmkmask(&subnet_mask, 
                                          subnet_ptr->subnet_base.addrtype, 
                                          subnet_ptr->prefixlen);

                if( ipm_retval != IPM_SUCCESS )
                {
                    snprintf(resp, REPLY_TEXT, 
                             "EIPM Route Config: Failure %d to create SubnetMask for %s from subnet prefix %d\n",
		              ipm_retval, cmd_route_upd_ptr->nexthop, subnet_ptr->prefixlen);

                    LOG_ERROR(0, resp);

                    return ipm_retval;
                }

                IPM_ipaddr_init(&nexthop_base);
                IPM_get_subnet(&nexthop_ip, &subnet_mask, &nexthop_base);

                IPM_ipaddr_init(&destbase_base);
                IPM_get_subnet(&dest_base, &subnet_mask, &destbase_base);

                if( IPM_IPCMPADDR(&subnet_ptr->subnet_base, &nexthop_base) == IPM_SUCCESS  ||
		    IPM_IPCMPADDR(&subnet_ptr->subnet_base, &destbase_base) == IPM_SUCCESS )
                {
                    /*
                     * ipm_cli command does not allow adding a
                     * subnet route so we know this is either a default
                     * route or regular static route.
                     */
		    if( subnet_ptr->route_cnt < EIPM_MAX_ROUTES )
		    {
                        route_ptr = &subnet_ptr->routes[subnet_ptr->route_cnt];

                        route_ptr->type       = (IPM_IPCMPADDR(&subnet_ptr->subnet_base, &destbase_base) == IPM_SUCCESS) ? EIPM_ROUTE_SUBN : EIPM_ROUTE_OTH;
                        route_ptr->dest       = dest_base;
                        route_ptr->destprefix = cmd_route_upd_ptr->prefix;
                        route_ptr->nexthop    = nexthop_ip;
                        route_ptr->source_ip  = source_ip;
			route_ptr->pivot_id = cmd_route_upd_ptr->pivot_id;

                        subnet_ptr->route_cnt++;

			EIPM_CHECK_INTF_CONFIG( &(intf_ptr->specData) );

			if (route_ptr->nexthop.addrtype == IPM_IPV6  &&
			    subnet_ptr->ips[0].ipaddr.addrtype == IPM_IPV6)
			{
			    if( subnet_ptr->sub2intf_mapping[0].route_priority == LSN1 )
			    {   
			    	EIPM_send_neighbor_solicitation( &intf_ptr->specData.lsn1_v6arpsock, 
					intf_ptr->specData.lsn1_iface_indx, 
					intf_ptr->lsn1_baseif, 
					intf_ptr->lsn1_hwaddr, 
					&route_ptr->nexthop, 
					&subnet_ptr->ips[0].ipaddr );
			    }
			    else
			    {
			    	EIPM_send_neighbor_solicitation( &intf_ptr->specData.lsn0_v6arpsock, 
					intf_ptr->specData.lsn0_iface_indx, 
					intf_ptr->lsn0_baseif, 
					intf_ptr->lsn0_hwaddr, 
					&route_ptr->nexthop, 
					&subnet_ptr->ips[0].ipaddr );
 			    }
			}
			// Route has been added and it doesn't need to try more times
			return IPM_SUCCESS;
    		    }
		    else
		    {
		        snprintf(resp, REPLY_TEXT, "EIPM Route Config: Max Number of Routes Reached %d\n", 
				 subnet_ptr->route_cnt);

		        LOG_ERROR(0, resp);
			return IPM_FAILURE;
		    }
                }
            }

        }
    }

    return IPM_SUCCESS;
}










/**********************************************************************
 *
 * Name:        EIPM_proxy_server_update()
 *
 * Abstract:    Called when IPM receives a message with proxy server data
 *
 * Description:    
 *              1) Proxy Server:
 *                 This involves 
 *                 a) setting up the proxy server IP on both internal and 
 *                 external facing interfaces; 
 *                 b) setting up routing; 
 *                 c) enabling forwarding.  
 *                 Once a proxy server is setup, client addresses can be added.
 * 
 *                 A proxy server has the following IP and routing configuration:
 *
 *                 - Proxy server IP and subnet routes are setup on both internal 
 *                 facing interfaces. This allows incomming packets on the external 
 *                 facing interfaces to be routed to the internal network.
 *
 *                 - Proxy server IP will also be setup on a external facing 
 *                 interfaces. No subnet route are added (i.e., use 32 prefix 
 *                 length). This prevents incomming packets on the external facing 
 *                 interfaces to be routed back out on the external facing interfaces.
 *
 *                 A host route will be added to reach the subnet gateway via the 
 *                 customer facing interface.
 *
 *                 - Forwarding will be enabled via sysctl
 *
 *              2) Proxy Client Address:
 *                 The client address will be added to the proxy server's 
 *                 neighbor cache.
 *
 *              3) Proxy Client:
 *                 A proxy client uses IIPM protocol to manage 
 *                 IP/Ethernet connectivity to the proxy server's IP.
 *                 It uses EIPM to manage the routing to the 
 *                 proxy server's IP.
 *
 * Parameters:  msg_ptr - pointer to data message
 *              type    - whether adding or deleting proxy/path data
 *              resp    - pointer to text string response to user
 *
 * Returns:     IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int EIPM_proxy_server_update( struct cmd_proxy_server *cmd_proxy_server_ptr, int type, char *resp )
{
EIPM_DATA	*data_ptr;
EIPM_INTF	*intf_ptr;
EIPM_INTF_SPEC  *intfSpecDataP;
EIPM_INTF_TYPE  intfType;
EIPM_SUBNET	*subnet_ptr;
EIPM_ROUTES     *route_ptr;
EIPM_IPDATA     *ipdata_ptr;
IPM_IPADDR	ip;
IPM_IPADDR	subnet_mask;
IPM_IPADDR	subnet_base;
int 		intf_idx;
int             baseIntfIdx;
char            lsn0_baseIntfNameOnly[MAX_NLEN_DEV];
char            lsn1_baseIntfNameOnly[MAX_NLEN_DEV];
char            *vlanSepP;
int 		subnet_idx;
int 		ip_idx;
int		retval;
IPM_RETVAL 	ipm_retval;
char		*iface0_base_ptr;
char		iface0_base[MAX_NLEN_DEV];
char		*iface1_base_ptr;
char		iface1_base[MAX_NLEN_DEV];
char		ip_iface0_base[MAX_NLEN_DEV];
char		ip_iface1_base[MAX_NLEN_DEV];
unsigned char   pivot_id;
char            *stacked_iface0_ptr;
char            stacked_iface0[MAX_NLEN_DEV];
char            *stacked_iface1_ptr;
char            stacked_iface1[MAX_NLEN_DEV];

/*
 * Store the external vlan id for external interface
 * if this IP is added for base interface, it should
 * be 0 and it is only used for PROXY SERVER IP
 */
uint16_t    vlanId=0;

    /* Check for EIPM memory */
    if( EIPM_shm_ptr == NULL )
    {
        snprintf(resp, REPLY_TEXT, 
                 "EIPM Proxy Server Config Failure: Shared memory null, Iface %s - %s\n", 
		  cmd_proxy_server_ptr->fe_iface[0],
                  cmd_proxy_server_ptr->fe_iface[1]);

        LOG_ERROR(0, resp);

        return IPM_FAILURE;
    }

    data_ptr = (EIPM_DATA *)EIPM_shm_ptr;

    memset(iface0_base, 0, MAX_NLEN_DEV);
    memset(iface1_base, 0, MAX_NLEN_DEV);
    memset(stacked_iface0, 0, MAX_NLEN_DEV);
    memset(stacked_iface1, 0, MAX_NLEN_DEV);

    pivot_id = cmd_proxy_server_ptr->pivot_id;
    if (pivot_id >= MAX_NUM_PIVOT)
    {
        snprintf(resp, REPLY_TEXT,
                "EIPM_proxy_server_update: pivot id %d is out of range, max is %d\n",
		pivot_id, MAX_NUM_PIVOT);

        LOG_ERROR(0, resp);

        return IPM_FAILURE;
    }

    /*
    ** stacked_iface0_ptr and stacked_iface1_ptr point to the stacked iface names without ":", 
    ** for example: eth0.800.7:ABCDE, it is eth0.800.7
    **              eth0.800:ABCDE, it is eth0.800
    ** iface0_base_ptr and iface1_base_ptr point to the base iface name, 
    ** for example: eth0.800.7:ABCDE, it is eth0.800
    **              eth0.800:ABCDE, it is eth0.800
    */ 
    if ((type == IPM_ADD_PROXY_CLIENT) ||
            (type == IPM_DEL_PROXY_CLIENT))
    {
        ipm_checkStackedVLAN(iface0_base,
                        &iface0_base_ptr,
                        stacked_iface0,
                        &stacked_iface0_ptr,
                        cmd_proxy_server_ptr->fe_iface[0]);

        ipm_checkStackedVLAN(iface1_base,
                        &iface1_base_ptr,
                        stacked_iface1,
                        &stacked_iface1_ptr,
                        cmd_proxy_server_ptr->fe_iface[1]);
    }
    else
    {
    /* Derive base iface */
    strncpy(iface0_base, cmd_proxy_server_ptr->fe_iface[0], MAX_NLEN_DEV);
    iface0_base_ptr = strtok(iface0_base, ":");

    if( iface0_base_ptr == NULL )
    {
        iface0_base_ptr = iface0_base;
    }

    stacked_iface0_ptr = iface0_base_ptr;

    strncpy(iface1_base, cmd_proxy_server_ptr->fe_iface[1], MAX_NLEN_DEV);
    iface1_base_ptr = strtok(iface1_base, ":");

    if( iface1_base_ptr == NULL )
    {
        iface1_base_ptr = iface1_base;
    }

    stacked_iface1_ptr = iface1_base_ptr;

    vlanId = cmd_proxy_server_ptr->vlanId;

    }

    /* Get the base interface name only. */
    strncpy( lsn0_baseIntfNameOnly, iface0_base_ptr, ( MAX_NLEN_DEV - 1 ) );

    vlanSepP = strrchr( lsn0_baseIntfNameOnly, '.' );

    if ( vlanSepP != NULL )
    {
        *vlanSepP = '\0';
    }
    
    strncpy( lsn1_baseIntfNameOnly, iface1_base_ptr, ( MAX_NLEN_DEV - 1 ) );

    vlanSepP = strrchr( lsn1_baseIntfNameOnly, '.' );

    if ( vlanSepP != NULL )
    {
        *vlanSepP = '\0';
    }

    /* Convert IP */
    IPM_ipaddr_init(&ip);
	
    ipm_retval = IPM_p2ipaddr(cmd_proxy_server_ptr->ip, &ip);

    if( ipm_retval != IPM_SUCCESS )
    {
        snprintf(resp, REPLY_TEXT, 
                 "EIPM Proxy Server Config Failure: Failed %d to translate IP %s\n", 
		  ipm_retval, cmd_proxy_server_ptr->ip);

        LOG_ERROR(0, resp);

        return ipm_retval;
    }

    IPM_ipaddr_init(&subnet_mask);

    ipm_retval = IPM_ipmkmask(&subnet_mask, ip.addrtype, cmd_proxy_server_ptr->prefix);

    if( ipm_retval != IPM_SUCCESS )
    {
        snprintf(resp, REPLY_TEXT, 
                 "EIPM Proxy Server Config Failure: Failed %d to create Mask for %s/%d\n",
                  ipm_retval, cmd_proxy_server_ptr->ip, cmd_proxy_server_ptr->prefix);

        LOG_ERROR(0, resp);

        return ipm_retval;
    }

    IPM_ipaddr_init(&subnet_base);

    IPM_get_subnet(&ip, &subnet_mask, &subnet_base);


    /* Search through existing data looking for a subnet match:
     * If match is found:
     * - If action is delete -> delete IP entry, collapse IP table
     *                          If no IPs in subnet, delete subnet entry
     *                          If no subnets on interface, delete interface entry
     * - If action is add -> add/update IP entry
     * If match is not found:
     * - add interface, subnet, IP entry
     */
	
    /* Look for matching interface */
    intf_idx = EIPM_findIntf( iface0_base_ptr, iface1_base_ptr, 
                              &intf_ptr, &intfSpecDataP, 
                              &intfType, &baseIntfIdx );

    if ( intf_ptr != NULL )
    {

        /* Found interface match, look for subnet match */
        if( type == IPM_ADD_PROXY_SERVER ||
            type == IPM_ADD_PROXY_CLIENT_ADDR )
        {
	    if(    ( intf_ptr->subnet_cnt == 0 )
                || ( EIPM_EXTN_INTF == intfType ) )
            {
                /* Update sysctl parameters */
		(void)EIPM_set_sysctl_value( iface0_base_ptr, "ipv4", "arp_ignore", 1 );
                (void)EIPM_set_sysctl_value( iface0_base_ptr, "ipv6", "dad_transmits", 0 );
                if (EIPM_GET_PROXY_SERVER_ENABLED() == TRUE)
                {
			(void)EIPM_set_sysctl_value( iface0_base_ptr, "ipv4", "forwarding", 1 );
			(void)EIPM_set_sysctl_value( iface0_base_ptr, "ipv6", "forwarding", 1 );
			(void)EIPM_set_sysctl_value( iface0_base_ptr, "ipv6", "proxy_ndp", 1 );
			(void)EIPM_set_sysctl_value( iface1_base_ptr, "ipv4", "forwarding", 1 );
			(void)EIPM_set_sysctl_value( iface1_base_ptr, "ipv6", "forwarding", 1 );
			(void)EIPM_set_sysctl_value( iface1_base_ptr, "ipv6", "proxy_ndp", 1 );
                }

                (void)EIPM_set_sysctl_value( iface1_base_ptr, "ipv4", "arp_ignore", 1 );
                (void)EIPM_set_sysctl_value( iface1_base_ptr, "ipv6", "dad_transmits", 0 );
            }

            /* Schedule configuration check */
	    EIPM_CHECK_INTF_CONFIG( intfSpecDataP );
        }

        for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
             subnet_idx < intf_ptr->subnet_cnt;
             subnet_idx++, subnet_ptr++ )
        {
            if( IPM_IPCMPADDR(&subnet_ptr->subnet_base, &subnet_base) == IPM_SUCCESS )
            {
                /* Found subnet match, look for IP match */
                for( ip_idx = 0, ipdata_ptr = &subnet_ptr->ips[0];
                     ip_idx < subnet_ptr->ip_cnt;
                     ip_idx++, ipdata_ptr++ )
                {
		    strncpy( ip_iface0_base, ipdata_ptr->lsn0_iface, ( MAX_NLEN_DEV - 1 ) );
		    strtok( ip_iface0_base, ":" );
		    strncpy( ip_iface1_base, ipdata_ptr->lsn1_iface, ( MAX_NLEN_DEV - 1 ) );
		    strtok( ip_iface1_base, ":" );


		    if (    ( IPM_SUCCESS == IPM_IPCMPADDR( &ipdata_ptr->ipaddr, &ip ) )
                         && ( 0 == strcmp( ip_iface0_base, stacked_iface0_ptr ) ) 
                         && ( 0 == strcmp( ip_iface1_base, stacked_iface1_ptr ) )
			 && ( ipdata_ptr->pivot_id == pivot_id ) )
                    {
                        /* Found IP match, handle update action */
                        if( type == IPM_ADD_PROXY_SERVER ||
                            type == IPM_ADD_PROXY_CLIENT ||
                            type == IPM_ADD_PROXY_CLIENT_ADDR )
                        {
                            strcpy(ipdata_ptr->lsn0_iface, cmd_proxy_server_ptr->fe_iface[0]);
                            strcpy(ipdata_ptr->lsn1_iface, cmd_proxy_server_ptr->fe_iface[1]);

                            // For feph service, the IP information will be on both active and standby side.
                            // When switchover, the arpndp session status must be reset to correct one.
                            if ((subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP) &&
                                (ipdata_ptr->type == EIPM_IP_PROXY_SERVER) && (EIPM_BASE_INTF == intfType))
                            {
                                char funcstr[128];
                                IPM_RETVAL eipm_arpndp_retval;

                                if (EIPM_GET_PROXY_SERVER_ENABLED() == TRUE)
                                {
                                    eipm_arpndp_retval = EIPM_arpndp_start(intf_idx, subnet_idx);
                                    snprintf(funcstr, sizeof (funcstr), "%s", "EIPM_arpndp_start");
                                }
                                else
                                {
                                    eipm_arpndp_retval = EIPM_arpndp_stop(intf_idx, subnet_idx);
                                    snprintf(funcstr, sizeof (funcstr), "%s", "EIPM_arpndp_stop");
                                }

                                if (eipm_arpndp_retval != IPM_SUCCESS)
                                {
                                    LOG_FORCE(0, "EIPM_proxy_server_update: Run %s to reset admin status failed for intf %d, subnet %d, ret value %d.",
                                            funcstr, intf_idx, subnet_idx, eipm_arpndp_retval);
                                }
                            }
                        }
                        else if( type == IPM_DEL_PROXY_SERVER ||
                                 type == IPM_DEL_PROXY_CLIENT ||
                                 type == IPM_DEL_PROXY_CLIENT_ADDR )
                        {
                            int nl_socket;
                            int del_index;
			    BOOL delProxyServerOnStackedVlanIntf = FALSE;

                            /* Attempt to delete IP from interfaces (may not be plumbed),
                             * then delete IP from data, collapse IP table 
                             */

			    nl_socket = ipm_open_netlink();
                            if( nl_socket < 0 )
                            {
				//Assert has fired in function ipm_open_netlink()
                                return IPM_FAILURE;
                            }
			    if (    ( pivot_id > 0 ) 
				 && ( IPM_DEL_PROXY_CLIENT_ADDR == type ) )
			    {
				int 		tmpIpIdx;
                                EIPM_IPDATA 	*ipDataP;

				delProxyServerOnStackedVlanIntf = TRUE;

				/* 
				 *  Go thru IPs in this subnet and ensure no other proxyclientaddr 
				 *  exists on this pivot. 
				 */
				for ( ( tmpIpIdx = 0, ipDataP = &subnet_ptr->ips[0] );
                                      ( tmpIpIdx < subnet_ptr->ip_cnt );
                                      ( tmpIpIdx++, ipDataP++ ) )
                                {
                                    if (    ( ip_idx == tmpIpIdx )
					 || ( ipDataP->type != EIPM_IP_PROXY_CLIENT_ADDR ) )
                                    {
                                        continue;
                                    }

                                    if ( ipDataP->pivot_id == pivot_id )
                                    {
                                        delProxyServerOnStackedVlanIntf = FALSE;
                                    }
                                }
			    }

			    if ( TRUE == delProxyServerOnStackedVlanIntf )
                            {
#if defined(_MIPS)
				// This is ATCA environment
				char name_l[MAX_NLEN_DEV];
                                char name_r[MAX_NLEN_DEV];
                                char *colon;
                                memset(name_l, 0, MAX_NLEN_DEV);
                                memset(name_r, 0, MAX_NLEN_DEV);

                                strncpy(name_l, cmd_proxy_server_ptr->be_iface[0], MAX_NLEN_DEV - 1);
                                if ((colon = strchr(name_l, ':')) != NULL)
                                {
                                    *colon = '\0';
                                    snprintf(colon, MAX_NLEN_DEV - strlen(name_l), ".%d", pivot_id);
                                }
                                else
				{
				    snprintf(name_l, MAX_NLEN_DEV, "%s.%d", cmd_proxy_server_ptr->be_iface[0], pivot_id);
				}

				strncpy(name_r, cmd_proxy_server_ptr->be_iface[1], MAX_NLEN_DEV - 1);
                                if ((colon = strchr(name_r, ':')) != NULL)
                                {
                                    *colon = '\0';
                                    snprintf(colon, MAX_NLEN_DEV - strlen(name_r), ".%d", pivot_id);
                                }
                                else
                                {
                                    snprintf(name_r, MAX_NLEN_DEV, "%s.%d", cmd_proxy_server_ptr->be_iface[1], pivot_id);
                                }
#else
				// Virtual enviroment
				char tunnel_name[MAX_NLEN_DEV];
				memset(tunnel_name, 0, MAX_NLEN_DEV);
				snprintf(tunnel_name, MAX_NLEN_DEV, "%s%d", PIVOT_PREFIX, pivot_id);
#endif

                                int ip_index;
                                EIPM_IPDATA *ip_ptr;
                                for( ip_index = 0, ip_ptr = &subnet_ptr->ips[0];
                                        ip_index < subnet_ptr->ip_cnt;
                                        ip_index++, ip_ptr++ )
                                {
                                    if (ip_ptr->type == EIPM_IP_PROXY_SERVER)
                                    {
                                        //delete proxy server IP on stacked vlans
#if defined(_MIPS)
                                        EIPM_configure_ip(nl_socket,
                                                        &ip_ptr->ipaddr,
                                                        subnet_ptr->prefixlen,
                                                        subnet_ptr->pivot_iface_indx[0][pivot_id],
							name_l,
                                                        RTM_DELADDR);

                                        EIPM_configure_ip(nl_socket,
                                                        &ip_ptr->ipaddr,
                                                        subnet_ptr->prefixlen,
                                                        subnet_ptr->pivot_iface_indx[1][pivot_id],
                                                        name_r,
                                                        RTM_DELADDR);
#else
                                        EIPM_configure_ip(nl_socket,
                                                        &ip_ptr->ipaddr,
                                                        subnet_ptr->prefixlen,
                                                        subnet_ptr->pivot_iface_indx[0][pivot_id],
                                                        tunnel_name,
                                                        RTM_DELADDR);
#endif
                                    }
                                }

                                //remove iface index
                                subnet_ptr->pivot_iface_indx[0][pivot_id] = 0;
                                subnet_ptr->pivot_iface_indx[1][pivot_id] = 0;
			    }
			    else if (pivot_id > 0 && type == IPM_DEL_PROXY_CLIENT)
			    {
				char iface[ EI_INTFNAMESIZE ];                
				memset(iface, 0, EI_INTFNAMESIZE);
                                snprintf(iface, EI_INTFNAMESIZE, "%s%d", PIVOT_PREFIX, pivot_id);

                                //pivot
                                (void)EIPM_DELETE_IP( nl_socket,
                                                        ipdata_ptr->type,
                                                        &ipdata_ptr->ipaddr,
                                                        subnet_ptr->prefixlen,
                                                        subnet_ptr->pivot_iface_indx[0][pivot_id],
                                                        iface );
			    }

			    // When deleting proxy server interface eth2.xxx/eht3.xxx, it
			    // should NOT delete proxy server IP from interface eth0.800.x/
			    // eth1.801.x. So it can be deleted when it is base interface
			    // eth2/eth3
			    if ((type == IPM_DEL_PROXY_SERVER)
					&& (intfType == EIPM_BASE_INTF)
				)
                            {
				int i;
				char iface[ EI_INTFNAMESIZE ];
                                char *colon;
				memset(iface, 0, EI_INTFNAMESIZE);

				for (i = 1; i < MAX_NUM_PIVOT; i++)
                                {
                                        //if there is stacked VLAN,
                                        //unplumb proxyserver IP on stacked VLANs
                                        if (subnet_ptr->pivot_cnt[i] <= 0)
                                        {
                                            continue;
                                        }

#if defined(_X86)
					snprintf(iface, EI_INTFNAMESIZE, "%s%d", PIVOT_PREFIX, pivot_id);
					EIPM_configure_ip(nl_socket,
								&ip,
								subnet_ptr->prefixlen,
								subnet_ptr->pivot_iface_indx[0][i],
								iface,
								RTM_DELADDR);
#else
                                        strncpy(iface, cmd_proxy_server_ptr->be_iface[0], EI_INTFNAMESIZE - 1);
                                        if ((colon = strchr(iface, ':')) != NULL)
                                        {
                                            *colon = '\0';
                                            snprintf(colon, EI_INTFNAMESIZE - strlen(iface), ".%d", i);
                                        }
                                        else
                                        {
                                            snprintf(iface, EI_INTFNAMESIZE, "%s.%d", cmd_proxy_server_ptr->be_iface[0], i);
                                        }

                                        EIPM_configure_ip(nl_socket,
                                                                &ip,
                                                                subnet_ptr->prefixlen,
                                                                subnet_ptr->pivot_iface_indx[0][i],
                                                                iface,
                                                                RTM_DELADDR);

                                        strncpy(iface, cmd_proxy_server_ptr->be_iface[1], EI_INTFNAMESIZE - 1);
                                        if ((colon = strchr(iface, ':')) != NULL)
                                        {
					    *colon = '\0';
                                            snprintf(colon, EI_INTFNAMESIZE - strlen(iface), ".%d", i);
                                        }
                                        else
                                        {
                                            snprintf(iface, EI_INTFNAMESIZE, "%s.%d", cmd_proxy_server_ptr->be_iface[1], i);
                                        }

                                        EIPM_configure_ip(nl_socket,
                                                                &ip,
                                                                subnet_ptr->prefixlen,
                                                                subnet_ptr->pivot_iface_indx[1][i],
                                                                iface,
                                                                RTM_DELADDR);
#endif
                                    }
                            }

			    //del ip for proxyclient without pivot or proxyclientaddr/proxyserver
			    if (!(pivot_id > 0 && type == IPM_DEL_PROXY_CLIENT))
			    {
                                    (void)EIPM_DELETE_IP( nl_socket,
                                                          ipdata_ptr->type,
                                                          &ipdata_ptr->ipaddr,
                                                          subnet_ptr->prefixlen,
							  intfSpecDataP->lsn0_iface_indx,
                                                          iface0_base_ptr );

                                    (void)EIPM_DELETE_IP( nl_socket,
                                                          ipdata_ptr->type,
                                                          &ipdata_ptr->ipaddr,
                                                          subnet_ptr->prefixlen,
							  intfSpecDataP->lsn1_iface_indx,
                                                          iface1_base_ptr );

                                    char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
                                    LOG_DEBUG(0, "EIPM_proxy_server_update - Delete IP %s from intf [%s-%s], ip intf: [%s-%s].",
                                            IPM_ipaddr2p(ipdata_ptr, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
                                            iface0_base_ptr, iface1_base_ptr, ipdata_ptr->lsn0_iface, ipdata_ptr->lsn1_iface);

                                    if ((ipdata_ptr->type == EIPM_IP_PROXY_SERVER) && (subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP))
                                    {
                                            LOG_DEBUG(0, "Proxy server IP, %s, on arpndp subnet found, destroy the session.", ipm_ipstr_buf);
                                            EIPM_arpndp_admin_destroy_sess(intf_idx, &(subnet_ptr->gateway));
                                    }
			    }
			    ipm_close_netlink(nl_socket);
			    if (pivot_id > 0)
                            {
                                subnet_ptr->pivot_cnt[pivot_id]--;
                                ipdata_ptr->pivot_id = 0;
                            }

                            subnet_ptr->ip_cnt--;

                            for( del_index = ip_idx;
                                 del_index < subnet_ptr->ip_cnt;
                                 del_index++ )
                            {
                                subnet_ptr->ips[del_index] = subnet_ptr->ips[del_index + 1];
                            }

                            /* Clear last IP entry */
                            memset(&subnet_ptr->ips[del_index], 0, sizeof(subnet_ptr->ips[0]));

			    if (    ( IPM_DEL_PROXY_SERVER == type )
                                 && ( EIPM_EXTN_INTF == intfType ) )
                            {
                                    /* Delete any 'proxyclientaddr's on the extension interface. */
                                    {
                                            int tmpIpIdx;
                                            int tmpRetVal;                                            
                                            EIPM_IPDATA *tmpIpDataP;                                        

                                            /* 
                                             *  Loop thru the IPs in the subnet and issue delete for any 'proxyclientaddr' IPs
                                             *  on a matching intf. 
                                             */
                                            tmpIpIdx = 0;
                                            tmpIpDataP = &(subnet_ptr->ips[0]);
                                            
                                            while( tmpIpIdx < subnet_ptr->ip_cnt )
                                            {
                                                    strncpy( ip_iface0_base, tmpIpDataP->lsn0_iface, ( MAX_NLEN_DEV - 1 ) );
		                                    strtok( ip_iface0_base, ":" );
		                                    strncpy( ip_iface1_base, tmpIpDataP->lsn1_iface, ( MAX_NLEN_DEV - 1 ) );
		                                    strtok( ip_iface1_base, ":" );

                                                    if (    ( EIPM_IP_PROXY_CLIENT_ADDR == tmpIpDataP->type ) 
                                                         && ( 0 == strcmp( ip_iface0_base, stacked_iface0_ptr ) ) 
                                                         && ( 0 == strcmp( ip_iface1_base, stacked_iface1_ptr ) ) )
                                                    {
                                                        struct cmd_proxy_server delProxyClientAddrCmd;

                                                        memset( &delProxyClientAddrCmd, 0, sizeof( delProxyClientAddrCmd ) );
                                                        delProxyClientAddrCmd.prefix = cmd_proxy_server_ptr->prefix;
                                                        IPM_ipaddr2p( &tmpIpDataP->ipaddr, delProxyClientAddrCmd.ip, sizeof( delProxyClientAddrCmd.ip ) );
                                                        strncpy( delProxyClientAddrCmd.fe_iface[0], stacked_iface0_ptr, ( MAX_NLEN_DEV - 1 ) );
                                                        strncpy( delProxyClientAddrCmd.fe_iface[1], stacked_iface1_ptr, ( MAX_NLEN_DEV - 1 ) );
                                                        strncpy( delProxyClientAddrCmd.be_iface[0], "O.0", ( MAX_NLEN_DEV - 1 ) );
                                                        strncpy( delProxyClientAddrCmd.be_iface[1], "O.0", ( MAX_NLEN_DEV - 1 ) );
                                                        delProxyClientAddrCmd.pivot_id = tmpIpDataP->pivot_id;

                                                        tmpRetVal = EIPM_proxy_server_update( &delProxyClientAddrCmd, IPM_DEL_PROXY_CLIENT_ADDR, resp );

                                                        if ( IPM_SUCCESS == tmpRetVal )
                                                        {
                                                                /* Don't increment the index to account for the delete. */
                                                                tmpIpDataP = &(subnet_ptr->ips[tmpIpIdx]);    
                                                        }
                                                        else
                                                        {
                                                                tmpIpIdx++;
                                                                tmpIpDataP++;
                                                        }

                                                    }
                                                    else
                                                    {
                                                            tmpIpIdx++;
                                                            tmpIpDataP++;
                                                    }
                                            }
                                    }
				    
				    /*
				     * Unset the flag to indicate this external interface isn't
				     * on this subnet any more
				     */
				    subnet_ptr->sub2intf_mapping[vlanId].is_intf_configured = 0;

				    /*
				     * There is no Proxy server IP on this subnet 
				     * external interface with vlanId,
				     * so clear alarm if it has. 
				     */
				    int extn_intf_index=-1;
				    EIPM_INTF_SPEC  *intf_spec_ptr=NULL;
				    for ( extn_intf_index=0, 
						intf_spec_ptr=&(data_ptr->extnIntfData[0]);
						extn_intf_index < data_ptr->extnIntfCount;
						extn_intf_index++, intf_spec_ptr++ )
				    {
					if ( (intf_idx != intf_spec_ptr->baseIntfIdx) ||
						(vlanId != intf_spec_ptr->vlanId)
					   )
					{
						continue;
					}
					EIPM_CLEAR_SUBNET_ALARM(intf_spec_ptr, EIPM_EXTN_INTF,
						 subnet_idx, EIPM_MAX_ALARM);
					break;
				    }

                                    /* 
                                     *  Proxyserver has been deleted on the extension interface.
				     *  Delete the extension interface also.
				     *  After feature 80.688, it have to consider one externsion interface 
				     *  is used by other subnet 
                                     */
                                    int subnet_ct = 0;
                                    int ip_ct = 0;
                                    int is_del_extension_intf = 1;
                                    EIPM_SUBNET *temp_subnet_ptr = &intf_ptr->subnet[0];
                                    EIPM_IPDATA *temp_ip_ptr = NULL;
                                    for( ; subnet_ct < intf_ptr->subnet_cnt;
                                             subnet_ct++, temp_subnet_ptr++ )
                                    {
                                        for( ip_ct = 0, temp_ip_ptr = &temp_subnet_ptr->ips[0];
                                                ip_ct < temp_subnet_ptr->ip_cnt;
                                                ip_ct++, temp_ip_ptr++ )
                                        {
                                                /*
                                                 * In order to improve the performance and compare with IP
                                                 * if its type is EIPM_IP_PROXY_SERVER
                                                 */
                                                if ( temp_ip_ptr->type != EIPM_IP_PROXY_SERVER )
                                                {
                                                        continue;
                                                }
                                                if( (strstr(temp_ip_ptr->lsn0_iface, iface0_base_ptr) != NULL) &&
                                                    (strstr(temp_ip_ptr->lsn1_iface, iface1_base_ptr) != NULL)
                                                  )
                                                {
                                                        is_del_extension_intf = 0;
                                                        break;
                                                }
                                        }

                                        // found one IP with this vlan interface
                                        if( is_del_extension_intf == 0 )
                                        {
                                                break;
                                        }
                                    }

                                    if( is_del_extension_intf == 1)
                                    {
                                            struct cmd_base_iface intfUpdateCmd;

                                            memset( &intfUpdateCmd, 0, sizeof( intfUpdateCmd ) );
                                            intfUpdateCmd.subnet_type = IPM_SUBNET_BOTH;

                                            snprintf( intfUpdateCmd.base_if[0], MAX_NLEN_DEV, "%s%s",
                                                      intf_ptr->lsn0_baseif,
                                                      ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
                                            snprintf( intfUpdateCmd.base_if[1], MAX_NLEN_DEV, "%s%s",
                                                      intf_ptr->lsn1_baseif,
                                                      ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

                                            intfUpdateCmd.vlanId = intfSpecDataP->vlanId;

                                            (void)EIPM_extnIntfUpdate( &intfUpdateCmd, EIPM_DEL, 
                                                                       resp, baseIntfIdx, intf_idx );
                                    }



                            }

                            /* Check for last IP in subnet */
                            if( (subnet_ptr->ip_cnt == 0 ) && (subnet_ptr->delete_flag == FALSE))
                            {
				// After the last IP is deleted, reset subnet status to NULL,
				// as the real status can't be detected.
				if (subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP)
				{
					subnet_ptr->status = EIPM_STAT_NULL;
					subnet_ptr->arpndp_status = EIPM_STAT_NULL;
				}

				/* clear the route info */
				route_ptr = &subnet_ptr->routes[0];
				memset(route_ptr, 0, sizeof(EIPM_ROUTES));
				subnet_ptr->route_cnt = 0;

				/* Clear any subnet alarms */
				EIPM_CLEAR_SUBNET_ALARM( intf_ptr, EIPM_BASE_INTF, subnet_idx, EIPM_MAX_ALARM );
				del_index = subnet_idx;


                                /* Clear alarm data */
                                memset(&intf_ptr->specData.alarm[del_index][0], 0, sizeof(intf_ptr->specData.alarm[0]));
                                /* Check for last subnet in interface */
                                if( intf_ptr->subnet_cnt == 0 &&
                                    eipm_delete_interface_with_no_subnet == TRUE )
                                {
				    /* Clear any interface alarms alarms */
				    EIPM_CLEAR_INTF_ALARM( intf_ptr, intfType, EIPM_MAX_ALARM );

                                } /* check interface subnet count */

                            } /* check subnet IP count */
			    else if ( subnet_ptr->ip_cnt == 0 && subnet_ptr->delete_flag == TRUE )
			    {
				struct cmd_subnet_upd subnet_info;
                                char reply_text[REPLY_TEXT];

                                memset( &subnet_info, 0, sizeof(subnet_info));

                                subnet_info.redundancy_mode = (int) subnet_ptr->redundancy_mode;
                                subnet_info.prefix = subnet_ptr->prefixlen;
                                IPM_ipaddr2p(&subnet_ptr->subnet_base, subnet_info.subnet_base, IPM_IPMAXSTRSIZE);
                                if ( strlen( intf_ptr->lsn0_baseif) > 0 )
                                {
                                        subnet_info.dev_t[0].subnet_type = IPM_SUBNET_EXTERNAL;
                                        strncpy( subnet_info.dev_t[0].dev_if, intf_ptr->lsn0_baseif, MAX_NLEN_DEV );
                                }

                                if ( strlen( intf_ptr->lsn1_baseif) > 0 )
                                {
                                        subnet_info.dev_t[1].subnet_type = IPM_SUBNET_EXTERNAL;
                                        strncpy( subnet_info.dev_t[1].dev_if, intf_ptr->lsn1_baseif, MAX_NLEN_DEV );
                                }

                                retval = EIPM_subnet_update(&subnet_info, EIPM_DEL, reply_text, NON_CLI_REQUEST);
                                if ( retval < 0 )
                                {
					char subnet_base_str[IPM_IPMAXSTRSIZE];
                                        LOG_ERROR(0, "EIPM_proxy_server_update: Failed to delete subnet(%s/%d), red_mode(%d), on interface(left(%s) and right(%s)\n", IPM_chkipaddr2p(&(subnet_ptr->subnet_base),subnet_base_str, IPM_IPMAXSTRSIZE), subnet_ptr->prefixlen, subnet_info.redundancy_mode, intf_ptr->lsn0_baseif, intf_ptr->lsn1_baseif);
                                        return retval;
                                }

			    }

                        } /* handle IP action */

                        return IPM_SUCCESS;

                    } /* IP match */

                } /* IP search */

                /* Subnet match, no IP match -> Add IP */
                if( type == IPM_ADD_PROXY_SERVER ||
                    type == IPM_ADD_PROXY_CLIENT ||
                    type == IPM_ADD_PROXY_CLIENT_ADDR )
                {
		    if( subnet_ptr->ip_cnt < EIPM_MAX_IPS )
		    {
                        ipdata_ptr = &subnet_ptr->ips[subnet_ptr->ip_cnt];

                        if( type == IPM_ADD_PROXY_SERVER )
                        {
                            ipdata_ptr->type = EIPM_IP_PROXY_SERVER;
			    int nl_socket = ipm_open_netlink();
                            if (nl_socket < 0)
                            {
                                return IPM_FAILURE;
                            }

                            int i;
			    int temp_pivot_index = -1;
                            char iface[ EI_INTFNAMESIZE ];
                            char *colon;
			    memset(iface, 0, EI_INTFNAMESIZE);
                            for (i = 1; i < MAX_NUM_PIVOT; i++)
                            {
                                //if there is stacked VLAN,
                                //plumb proxyserver IP on stacked VLANs
                                if (subnet_ptr->pivot_cnt[i] <= 0)
                                {
				    continue;
				}

				// Don't add IP when the proxy server isn't ready
				if ( EIPM_GET_PROXY_SERVER_ENABLED() != TRUE )
				{
					continue;
				}
#if defined(_MIPS)
                                strncpy(iface, cmd_proxy_server_ptr->be_iface[0], EI_INTFNAMESIZE - 1);
                                if ((colon = strchr(iface, ':')) != NULL)
                                {
                                    *colon = '\0';
                                    snprintf(colon, EI_INTFNAMESIZE - strlen(iface), ".%d", i);
                                }
                                else
                                {
                                    snprintf(iface, EI_INTFNAMESIZE, "%s.%d", cmd_proxy_server_ptr->be_iface[0], i);
                                }

				EIPM_configure_ip(nl_socket,
							&ip,
							subnet_ptr->prefixlen,
							subnet_ptr->pivot_iface_indx[0][i],
							iface,
							RTM_NEWADDR);

                                strncpy(iface, cmd_proxy_server_ptr->be_iface[1], EI_INTFNAMESIZE - 1);
                                if ((colon = strchr(iface, ':')) != NULL)
                                {
                                    *colon = '\0';
                                    snprintf(colon, EI_INTFNAMESIZE - strlen(iface), ".%d", i);
                                }
                                else
                                {
                                    snprintf(iface, EI_INTFNAMESIZE, "%s.%d", cmd_proxy_server_ptr->be_iface[1], i);
				}
				temp_pivot_index = subnet_ptr->pivot_iface_indx[1][i];
#else
				temp_pivot_index = subnet_ptr->pivot_iface_indx[0][i];
				snprintf(iface, MAX_NLEN_DEV, "%s%d", PIVOT_PREFIX, pivot_id);
#endif

				EIPM_configure_ip(nl_socket,
							&ip,
							subnet_ptr->prefixlen,
							temp_pivot_index,
							iface,
							RTM_NEWADDR);
			    }
                            ipm_close_netlink(nl_socket);
			    // Set the flag to inidcate this interface is in this subnet
			    subnet_ptr->sub2intf_mapping[vlanId].is_intf_configured = 1;
			    subnet_ptr->sub2intf_mapping[vlanId].route_priority = intfSpecDataP->preferred_side;
                        }
                        else if( type == IPM_ADD_PROXY_CLIENT )
                        {
                            ipdata_ptr->type = EIPM_IP_PROXY_CLIENT;

			    if (1 == ipm_isVirtual())
			    {
			    	intf_ptr->is_tunnel_intf = TRUE;
			    }
			    intfSpecDataP->monitor = EIPM_MONITOR_ROUTE;
			    int nl_socket = ipm_open_netlink();
                            if (nl_socket < 0)
                            {
                                return IPM_FAILURE;
                            }

                            if (pivot_id > 0)
                            {
                                char name[MAX_NLEN_DEV];
				memset(name, 0, MAX_NLEN_DEV);
                                snprintf(name, MAX_NLEN_DEV, "%s%d", PIVOT_PREFIX, pivot_id);

                                //Get interface index
                                if (subnet_ptr->pivot_iface_indx[0][pivot_id] <= 0)
                                {
                                    subnet_ptr->pivot_iface_indx[0][pivot_id] = ipm_get_ifindex(inetsocket, name);
                                    if (subnet_ptr->pivot_iface_indx[0][pivot_id] < 0)
                                    {
                                        snprintf(resp, REPLY_TEXT,
                                                "EIPM_proxy_server_update(): failed to get intf\n");
                                        LOG_ERROR(0, resp);
				        ipm_close_netlink(nl_socket);
                                        return IPM_GETIFINDEX;
                                    }
				    if (ipm_isVirtual() != 1)
				    {
					// ATCA platform, attach to pivot
				    if (intfSpecDataP->preferred_side == LSN0)
                                    {
                                        EIPM_attach_pivot(name, stacked_iface0_ptr, stacked_iface1_ptr);
                                    }
                                    else
                                    {
                                        EIPM_attach_pivot(name, stacked_iface1_ptr, stacked_iface0_ptr);
                                    }
				    }
                                    subnet_ptr->pivot_cnt[pivot_id]++;
				}

				(void)EIPM_set_sysctl_value( name, "ipv6", "dad_transmits", 0 );

				//plumb IP on pivot interface
                                (void)EIPM_ADD_IP( nl_socket,
                                                ipdata_ptr->type,
                                                &ip,
                                                subnet_ptr->prefixlen,
                                                subnet_ptr->pivot_iface_indx[0][pivot_id],
                                                name );

				if (subnet_ptr->pivot_act_base[pivot_id] == LSN_NONE)
                                {
                                    subnet_ptr->pivot_act_base[pivot_id] = intfSpecDataP->preferred_side;
                                }

                                ipdata_ptr->pivot_id = pivot_id;
			    }

			    if (pivot_id == 0)
                            {
                                //plumb IP on singly tagged vlan
                                (void)EIPM_ADD_IP( nl_socket,
                                                ipdata_ptr->type,
                                                &ip,
                                                subnet_ptr->prefixlen,
                                                intfSpecDataP->lsn0_iface_indx,
                                                cmd_proxy_server_ptr->fe_iface[0] );

                                //plumb IP on singly tagged vlan
                                (void)EIPM_ADD_IP( nl_socket,
                                                ipdata_ptr->type,
                                                &ip,
                                                subnet_ptr->prefixlen,
                                                intfSpecDataP->lsn1_iface_indx,
                                                cmd_proxy_server_ptr->fe_iface[1] );
                            }
			    ipm_close_netlink(nl_socket);
			    //Add subnet route
			    if ( (pivot_id > 0) && (subnet_ptr->ip_cnt == 0) )
			    {
				route_ptr = &subnet_ptr->routes[subnet_ptr->route_cnt];
				route_ptr->type = EIPM_ROUTE_SUBN;
				route_ptr->dest = subnet_ptr->subnet_base;
				route_ptr->destprefix = subnet_ptr->prefixlen;
				IPM_ipaddr_init(&route_ptr->nexthop);
				if( subnet_ptr->subnet_base.addrtype == IPM_IPV4 )
				{
					(void)IPM_p2ipaddr("0.0.0.0", &route_ptr->nexthop);
				}
				else if( subnet_ptr->subnet_base.addrtype == IPM_IPV6 )
				{
					(void)IPM_p2ipaddr("::", &route_ptr->nexthop);
				}
            			subnet_ptr->route_cnt = subnet_ptr->route_cnt + 1;
            			route_ptr->pivot_id = pivot_id;
        		    }
        		    EIPM_CHECK_INTF_CONFIG( intfSpecDataP );

                        }
                        else
                        {
                            ipdata_ptr->type = EIPM_IP_PROXY_CLIENT_ADDR;
#if defined(_X86)
			    intf_ptr->is_tunnel_intf = TRUE;
#endif


				//if there is stacked VLAN, get interface index and 
				// plumb proxyserver IP if available
				if (pivot_id > 0)
				{
#if defined(_X86)
					// On host with FEPH service
					char tunnel_name[MAX_NLEN_DEV];
					memset(tunnel_name, 0, sizeof(tunnel_name));
					snprintf(tunnel_name, MAX_NLEN_DEV, "%s%d", PIVOT_PREFIX, pivot_id);
					subnet_ptr->pivot_iface_indx[0][pivot_id] = ipm_get_ifindex(inetsocket, tunnel_name);
					if (subnet_ptr->pivot_iface_indx[0][pivot_id] <= 0)
					{
						snprintf(resp, REPLY_TEXT, "EIPM_proxy_server_update(): failed to get pivot interface %s\n", tunnel_name);
						LOG_ERROR(0, resp);
						return IPM_GETIFINDEX;
					}
					(void)EIPM_set_sysctl_value(tunnel_name, "ipv6", "dad_transmits", 0 );
#else
					//this is the first time this inner vlan is set up, get interface index
					char name_l[MAX_NLEN_DEV];
					char name_r[MAX_NLEN_DEV];
					memset(name_l, 0, sizeof(name_l));
					memset(name_r, 0, sizeof(name_r));
					char *colon;
					if (cmd_proxy_server_ptr->be_iface[0][0] != '\0')
					{
						strncpy(name_l, cmd_proxy_server_ptr->be_iface[0], sizeof(name_l)- 1);
						// If the name string includs ":", remove it and add the vlan tag.
						if ((colon = strchr(name_l, ':')) != NULL)
						{
							*colon = '\0';
							ipm_vlan_add(name_l, pivot_id);
							snprintf(colon, MAX_NLEN_DEV - strlen(name_l), ".%d", pivot_id);
						}
						else
						{
							ipm_vlan_add(name_l, pivot_id);
							snprintf(name_l, MAX_NLEN_DEV, "%s.%d", cmd_proxy_server_ptr->be_iface[0], pivot_id);
						}

						if (subnet_ptr->pivot_iface_indx[0][pivot_id] == 0)
						{
							subnet_ptr->pivot_iface_indx[0][pivot_id] = ipm_get_ifindex(inetsocket, name_l);
							if (subnet_ptr->pivot_iface_indx[0][pivot_id] < 0)
							{
								snprintf(resp, REPLY_TEXT, "EIPM_proxy_server_update(): failed to get left intf\n");
								LOG_ERROR(0, resp);
								return IPM_FAILURE;
							}
						}
						(void)EIPM_set_sysctl_value( name_l, "ipv6", "dad_transmits", 0 );
					}

					if (cmd_proxy_server_ptr->be_iface[1][0] != '\0')
					{
						strncpy(name_r, cmd_proxy_server_ptr->be_iface[1], sizeof(name_r) - 1);
						// If the name string includs ":", remove it and add the vlan tag.
						if ((colon = strchr(name_r, ':')) != NULL)
						{
							*colon = '\0';
							ipm_vlan_add(name_r, pivot_id);        
							snprintf(colon, MAX_NLEN_DEV - strlen(name_r), ".%d", pivot_id);
						}
						else
						{
							ipm_vlan_add(name_r, pivot_id);
							snprintf(name_r, MAX_NLEN_DEV, "%s.%d", cmd_proxy_server_ptr->be_iface[1], pivot_id);
						}

						if (subnet_ptr->pivot_iface_indx[1][pivot_id] == 0)
						{
							subnet_ptr->pivot_iface_indx[1][pivot_id] = ipm_get_ifindex(inetsocket, name_r);
							if (subnet_ptr->pivot_iface_indx[1][pivot_id] < 0)
							{
								snprintf(resp, REPLY_TEXT, "EIPM_proxy_server_update(): failed to get right intf\n");
								LOG_ERROR(0, resp);
								return IPM_FAILURE;
							}
						}
						(void)EIPM_set_sysctl_value( name_r, "ipv6", "dad_transmits", 0 );
					}
#endif
                                // Go through the IP of this subnet so that proxyserver ip can plumb on this new stacked VLANs
                                int nl_socket = ipm_open_netlink();
                                if (nl_socket < 0)
                                {
                                    return IPM_FAILURE;
                                }

                                int ip_index;
                                EIPM_IPDATA     *ip_ptr;
                                for( ip_index = 0, ip_ptr = &subnet_ptr->ips[0];
                                        ip_index < subnet_ptr->ip_cnt;
                                        ip_index++, ip_ptr++ )
                                {
                                    if (ip_ptr->type == EIPM_IP_PROXY_SERVER)
                                    {
					// Don't add IP when the proxy server isn't ready
					if ( EIPM_GET_PROXY_SERVER_ENABLED() != TRUE )
					{
						continue;
					}

#if defined(_X86)
					if (tunnel_name[0] != '\0')
					{
						EIPM_configure_ip(nl_socket,
							&ip_ptr->ipaddr,
							subnet_ptr->prefixlen,
							subnet_ptr->pivot_iface_indx[0][pivot_id],
							tunnel_name,
							RTM_NEWADDR);
					}
#else
					if (name_l[0] != '\0')
					{
						EIPM_configure_ip(nl_socket,
							&ip_ptr->ipaddr,
							subnet_ptr->prefixlen,
							subnet_ptr->pivot_iface_indx[0][pivot_id],
							name_l,
							RTM_NEWADDR);
					}
					if (name_r[0] != '\0')
					{
						EIPM_configure_ip(nl_socket,
							&ip_ptr->ipaddr,
							subnet_ptr->prefixlen,
							subnet_ptr->pivot_iface_indx[1][pivot_id],
							name_r,
							RTM_NEWADDR);
					}
#endif
					// Add break here. because there are multiple tuples
					// with the same IP and different VLANs in this subnet'
					// IP data. Since proxy IP is added in eth0.800.x, it 
					// doesn't need adding more than one times
					break;
                                    }
                                }

                                ipdata_ptr->pivot_id = pivot_id;
                                subnet_ptr->pivot_cnt[pivot_id]++;

                                ipm_close_netlink(nl_socket);

#if defined(_MIPS)
				/* Set 'sysctl' 'arp_ignore' parameter for stacked VLAN interfaces. */
                                if ( IPM_IPV4 == subnet_ptr->subnet_base.addrtype )
                                {
                                    if ( TRUE == EIPM_GET_PROXY_SERVER_ENABLED() )
                                    {
                                        if ( IPM_SUCCESS != EIPM_check_sysctl_value( name_l, "ipv4", "arp_ignore", 0 ) )
                                        {
                                            (void)EIPM_set_sysctl_value( name_l, "ipv4", "arp_ignore", 0 );
                                        }

                                        if ( IPM_SUCCESS != EIPM_check_sysctl_value( name_r, "ipv4", "arp_ignore", 0 ) )
                                        {
                                            (void)EIPM_set_sysctl_value( name_r, "ipv4", "arp_ignore", 0 );
                                        }
                                    }
                                    else if ( FALSE == EIPM_GET_PROXY_SERVER_ENABLED() )
                                    {
                                        if ( IPM_SUCCESS != EIPM_check_sysctl_value( name_l, "ipv4", "arp_ignore", 8 ) )
                                        {
                                            (void)EIPM_set_sysctl_value( name_l, "ipv4", "arp_ignore", 8 );
                                        }

                                        if ( IPM_SUCCESS != EIPM_check_sysctl_value( name_r, "ipv4", "arp_ignore", 8 ) )
                                        {
                                            (void)EIPM_set_sysctl_value( name_r, "ipv4", "arp_ignore", 8 );
                                        }
                                    }
                                }
#endif
                            }
                        }
                        ipdata_ptr->ipaddr = ip;
                        strcpy(ipdata_ptr->lsn0_iface, cmd_proxy_server_ptr->fe_iface[0]);
                        strcpy(ipdata_ptr->lsn1_iface, cmd_proxy_server_ptr->fe_iface[1]);

                        EIPM_set_ip_config_time(ipdata_ptr);

                        subnet_ptr->ip_cnt++;

			// If it's a proxy server IP on arpndp subnet, then create arpndp session.
			if ((subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP) &&
				(ipdata_ptr->type == EIPM_IP_PROXY_SERVER) && (EIPM_BASE_INTF == intfType))
			{
				char funcstr[128];
				IPM_RETVAL eipm_arpndp_retval;
  
				eipm_arpndp_retval = EIPM_arpndp_admin_create_sess(
					intf_idx,
					subnet_ptr,
					&(ipdata_ptr->ipaddr));

				if (eipm_arpndp_retval != IPM_SUCCESS)
				{
					snprintf(resp, REPLY_TEXT, "%s(): EIPM_arpndp_admin_create_sess(%d, %p, ... ) for subnet_idx (%d) failed [%d]\n",
						__FUNCTION__,
						intf_idx,
						subnet_ptr,
						subnet_idx,
						eipm_arpndp_retval
						);
					LOG_FORCE(0, resp);

					return IPM_FAILURE;
				}

				// After session creation, it should be started on active side.
				// On standby side, it needs to be stopped as no IP plumbed.
				if (EIPM_GET_PROXY_SERVER_ENABLED() == TRUE)
				{
					eipm_arpndp_retval = EIPM_arpndp_start(intf_idx, subnet_idx);
					snprintf(funcstr, sizeof (funcstr), "%s", "EIPM_arpndp_start");
				}
				else
				{
					eipm_arpndp_retval = EIPM_arpndp_stop(intf_idx, subnet_idx);
					snprintf(funcstr, sizeof (funcstr), "%s", "EIPM_arpndp_stop");
				}

				if (eipm_arpndp_retval != IPM_SUCCESS)
				{
					snprintf(resp, REPLY_TEXT, "%s(): %s (%d, %d ) failed [%d]\n",
						__FUNCTION__,
						funcstr,
						intf_idx,
						subnet_idx,
						eipm_arpndp_retval
						);
					LOG_FORCE(0, resp);

					return IPM_FAILURE;
				}
			}

			if( ipdata_ptr->type != EIPM_IP_PROXY_CLIENT )
			{
			    EIPM_open_garpsock( intfSpecDataP, ip.addrtype );
			}

			/*
			 * Set GARP_ARP for PROXY_CLIENT IP, too. Otherwise, FEPH ARP
			 * cache can't be updated in 10 seconds after IMS service
			 * switchs over
			 */
			if( (ipdata_ptr->type == EIPM_IP_PROXY_CLIENT_ADDR) ||
				(ipdata_ptr->type == EIPM_IP_PROXY_CLIENT)
			   )
			{
			    EIPM_SET_GRAT_ARP( subnet_ptr, subnet_ptr->sub2intf_mapping[0].route_priority );
			}
		    }
  		    else
		    {
		        snprintf(resp, REPLY_TEXT, "EIPM_proxy_server_update(): Max Number of IPs Reached %d\n", 
				 subnet_ptr->ip_cnt);

		        LOG_ERROR(0, resp);
			return IPM_FAILURE;
		    }
                }
                else if( type == IPM_DEL_PROXY_SERVER ||
                         type == IPM_DEL_PROXY_CLIENT ||
                         type == IPM_DEL_PROXY_CLIENT_ADDR )
                {
                    snprintf( resp, REPLY_TEXT, 
	                      "EIPM_proxy_server_update(): Failed to find/delete %s/%d on any subnet in %s - %s",
                               cmd_proxy_server_ptr->ip, 
                               cmd_proxy_server_ptr->prefix, 
                               cmd_proxy_server_ptr->fe_iface[0],
                               cmd_proxy_server_ptr->fe_iface[1] );

                    LOG_DEBUG(0, resp);
                }

                return IPM_SUCCESS;

            } /* subnet match */

        } /* subnet search */

        /*
	 * Interface match and there is no matched subnet
	 */
        snprintf(resp, REPLY_TEXT,
                        "%s: Failed to find subnet %s/%d  in %s - %s. Please add subnet firstly",
                        __FUNCTION__,
                        cmd_proxy_server_ptr->ip,
                        cmd_proxy_server_ptr->prefix,
                        cmd_proxy_server_ptr->fe_iface[0],
                        cmd_proxy_server_ptr->fe_iface[1]
                );

	LOG_FORCE(0, resp);
        if( type == IPM_ADD_PROXY_SERVER ||
            type == IPM_ADD_PROXY_CLIENT ||
            type == IPM_ADD_PROXY_CLIENT_ADDR )
        {
	    LOG_ERROR(0, resp);
	    return IPM_FAILURE;
	}
	else
	{
	    LOG_DEBUG(0, resp);
            return IPM_SUCCESS;
        } 

    } /* end 'matching interface found' */

    if( type == IPM_DEL_PROXY_SERVER ||
        type == IPM_DEL_PROXY_CLIENT ||
        type == IPM_DEL_PROXY_CLIENT_ADDR )
    {
        snprintf( resp, REPLY_TEXT, 
	          "EIPM_proxy_server_update(): Failed to match %s - %s for %s/%d delete",
                   cmd_proxy_server_ptr->fe_iface[0],
                   cmd_proxy_server_ptr->fe_iface[1],
                   cmd_proxy_server_ptr->ip, 
                   cmd_proxy_server_ptr->prefix );

	LOG_DEBUG(0, resp);

        return IPM_SUCCESS;
    }
    else if (  (  ( IPM_ADD_PROXY_CLIENT_ADDR == type ) 
              || ( IPM_ADD_PROXY_SERVER == type ) ) &&
		( EIPM_INVALID_INTF == intfType ) &&
		( baseIntfIdx != -1 ) )
    {
        /* Check if extension/child interface needs to be added. */
        if (    ( EIPM_INVALID_INTF == intfType ) 
             && ( baseIntfIdx != -1 ) )
        {
                /* Base interface was found. Add the extension/child interface. */
                struct cmd_base_iface intfUpdateCmd;

                memset( &intfUpdateCmd, 0, sizeof( intfUpdateCmd ) );
                intfUpdateCmd.subnet_type = IPM_SUBNET_BOTH;

                if (strlen(iface0_base_ptr) > 0)
                {
                        strncpy(intfUpdateCmd.base_if[0], iface0_base_ptr, (MAX_NLEN_DEV - 1));
                }

                if (strlen(iface1_base_ptr) > 0)
                {
                        strncpy(intfUpdateCmd.base_if[1], iface1_base_ptr, (MAX_NLEN_DEV - 1));
                }

                intfUpdateCmd.vlanId = vlanId;

                retval = EIPM_extnIntfUpdate( &intfUpdateCmd, EIPM_ADD, resp, baseIntfIdx, -1 );

                if ( retval != IPM_SUCCESS )
                {
                        LOG_ERROR( 0, resp );

                        return retval;
                }

		if ( IPM_ADD_PROXY_SERVER == type )
		{
			retval = EIPM_proxy_server_update( cmd_proxy_server_ptr, type, resp );

			if ( IPM_SUCCESS == retval )
                        {
                                (void)EIPM_set_sysctl_value(iface0_base_ptr, "ipv4", "arp_ignore", 1);
                                (void)EIPM_set_sysctl_value(iface0_base_ptr, "ipv6", "dad_transmits", 0);
				if (EIPM_GET_PROXY_SERVER_ENABLED() == TRUE)
				{
					(void)EIPM_set_sysctl_value(iface0_base_ptr, "ipv4", "forwarding", 1);
					(void)EIPM_set_sysctl_value(iface0_base_ptr, "ipv6", "forwarding", 1);
					(void)EIPM_set_sysctl_value(iface0_base_ptr, "ipv6", "proxy_ndp", 1);
					(void)EIPM_set_sysctl_value(iface1_base_ptr, "ipv4", "forwarding", 1);
					(void)EIPM_set_sysctl_value(iface1_base_ptr, "ipv6", "forwarding", 1);
					(void)EIPM_set_sysctl_value(iface1_base_ptr, "ipv6", "proxy_ndp", 1);
				}

                                (void)EIPM_set_sysctl_value(iface1_base_ptr, "ipv4", "arp_ignore", 1);
                                (void)EIPM_set_sysctl_value(iface1_base_ptr, "ipv6", "dad_transmits", 0);
			}

			return retval;
		}

                /* Set the interface pointers. */
                intfSpecDataP = &(data_ptr->extnIntfData[( data_ptr->extnIntfCount - 1 )]);
                intf_ptr = &(data_ptr->intf_data[intfSpecDataP->baseIntfIdx]);
                intfType = EIPM_EXTN_INTF;
        }
	else
        {
                snprintf( resp, REPLY_TEXT, 
	                  "EIPM_proxy_server_update(): Could not find interface %s-%s for add of %s/%d. "
                          "Add operation requires that base be present.",
                          cmd_proxy_server_ptr->fe_iface[0],
                          cmd_proxy_server_ptr->fe_iface[1],
                          cmd_proxy_server_ptr->ip, 
                          cmd_proxy_server_ptr->prefix );

	        LOG_DEBUG( 0, resp );

                return IPM_FAILURE;
        }
    }
    else
    {
	/*
	 * No base information match
	 */
	snprintf( resp, REPLY_TEXT,
		"EIPM_proxy_server_update(): Could not find interface %s-%s for add of %s/%d. "
                "Please add base interface first.",
                cmd_proxy_server_ptr->fe_iface[0],
                cmd_proxy_server_ptr->fe_iface[1],
                cmd_proxy_server_ptr->ip,
                cmd_proxy_server_ptr->prefix );
	
	LOG_ERROR( 0, resp );
	LOG_FORCE( 0, resp );
	return IPM_FAILURE;
     }
    return IPM_SUCCESS;
}

/**********************************************************************
 *
 * Name:        EIPM_set_subnet()
 *
 * Abstract:    Called for to set session parameters for the BFD transports
 *
 * Description: For every BFD session IP that is setup, call set the
		BFD session parameters   
**********************************************************************/
int EIPM_set_subnet(
	register struct cmd_subnet_upd *cmd_subnet_upd_ptr,
	char *resp
)
{
	EIPM_DATA	*data_ptr;
	EIPM_INTF	*intf_ptr;
	EIPM_SUBNET	*subnet_ptr;
	EIPM_ROUTES	*route_ptr;
	EIPM_IPDATA	*ipdata_ptr;

	int	retval;
	int	intf_idx;
	int	ip_idx;
	int	subnet_idx;
	int	err_cnt;

	char	iface0_base[MAX_NLEN_DEV];
	char	*iface0_base_ptr;
	char	iface1_base[MAX_NLEN_DEV];
	char	*iface1_base_ptr;
	char	ip_addr[IPM_IPMAXSTRSIZE];

	IPM_REDUNDANCY_MODE redundancy_mode;

	IPM_IPADDR subnet_base;
	IPM_IPADDR subnet_mask;

	IPM_RETVAL eipm_bfd_retval;
	IPM_RETVAL eipm_arpndp_retval;
	IPM_RETVAL ipm_retval;

	memset(ip_addr, 0, sizeof(ip_addr));

	/* check the shared memory */
	if ( EIPM_shm_ptr == NULL )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: Shared memory null for <%s>/<%d>, u[%u] x[%u] y[%u]\n",
			__FUNCTION__,
			cmd_subnet_upd_ptr->subnet_base,
			cmd_subnet_upd_ptr->prefix,
			cmd_subnet_upd_ptr->detection_multiplier,
			cmd_subnet_upd_ptr->desired_min_tx_interval,
			cmd_subnet_upd_ptr->required_min_rx_interval
                );

		LOG_ERROR(0, resp);
		return IPM_FAILURE;
	}

	data_ptr = (EIPM_DATA *) EIPM_shm_ptr;

	/* set the subnet ip address */
	IPM_ipaddr_init(&subnet_base);
	ipm_retval = IPM_p2ipaddr(cmd_subnet_upd_ptr->subnet_base, &subnet_base);
	if ( ipm_retval != IPM_SUCCESS)
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: invalid subnet base IP address %s\n",
			__FUNCTION__,
			cmd_subnet_upd_ptr->subnet_base
		);

		LOG_ERROR(0, resp);
		return ipm_retval;
	}

	/* set the subnet mask */
	IPM_ipaddr_init(&subnet_mask);
	ipm_retval = IPM_ipmkmask( &subnet_mask, subnet_base.addrtype, cmd_subnet_upd_ptr->prefix );
	if ( ipm_retval != IPM_SUCCESS )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: failed to create subnet mask for %s/%d\n",
			__FUNCTION__,
			cmd_subnet_upd_ptr->subnet_base,
			cmd_subnet_upd_ptr->prefix
		);

		LOG_ERROR(0, resp);
		return ipm_retval;;
        }

	/* look for the matching subnet */
	*ip_addr = '\0';
	for ( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
		intf_idx < data_ptr->intf_cnt;
		intf_idx++, intf_ptr++ )
	{
		if (intf_ptr->subnet_cnt == 0 )
		{
			continue;
		}

		for ( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
			subnet_idx < intf_ptr->subnet_cnt;
			subnet_idx++, subnet_ptr++ )
		{
			// Find the matched subnet
			if ((IPM_IPCMPADDR(&subnet_ptr->subnet_base, &subnet_base) != IPM_SUCCESS) ||
				(subnet_ptr->prefixlen != cmd_subnet_upd_ptr->prefix))
			{
				continue;
			}

			EIPM_SUBNET tmp_subnet = *subnet_ptr;

			if (cmd_subnet_upd_ptr->detection_multiplier != 0)
			{
				subnet_ptr->detection_multiplier = cmd_subnet_upd_ptr->detection_multiplier;
			}
			if (cmd_subnet_upd_ptr->desired_min_tx_interval != 0)
			{
				subnet_ptr->desired_min_tx_interval = cmd_subnet_upd_ptr->desired_min_tx_interval;
			}
			if (cmd_subnet_upd_ptr->required_min_rx_interval != 0)
			{
				subnet_ptr->required_min_rx_interval = cmd_subnet_upd_ptr->required_min_rx_interval;
			}

			// 255 is a flag here to indicate the table_number should be kept as previous one.
			if (cmd_subnet_upd_ptr->table_num != 255)
			{
				subnet_ptr->table_num = cmd_subnet_upd_ptr->table_num;
				//Schedule configuration check 
				EIPM_CHECK_INTF_CONFIG(&(intf_ptr->specData));
			}

			if ((IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT)
			{
				for (ip_idx = 0, ipdata_ptr = &subnet_ptr->ips[0];
					ip_idx < subnet_ptr->ip_cnt;
					ip_idx++, ipdata_ptr++)
				{
					eipm_bfd_retval = EIPM_bfd_admin_change_cfg_sess(
								intf_idx,
								subnet_idx,
								&ipdata_ptr->ipaddr
								);

					if (eipm_bfd_retval != IPM_SUCCESS)
					{
						/* revert to original values on failure */
						*subnet_ptr = tmp_subnet;
						snprintf(
							resp, REPLY_TEXT, "%s(): EIPM_bfd_admin_change_cfg_sess( %d, %d, ... ) failed [%d]\n",
							__FUNCTION__,
							intf_idx,
							subnet_idx,
							eipm_bfd_retval
						);

						LOG_ERROR(0, resp);

						return IPM_FAILURE;
					}
				}
			}
			else if ((IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP && subnet_ptr->ip_cnt > 0 )
			{
				eipm_arpndp_retval = EIPM_arpndp_admin_change_cfg_sess(
							intf_idx,
							subnet_ptr,
							&(subnet_ptr->ips[0].ipaddr)
							);

				if (eipm_arpndp_retval != ARPNDP_SUCCESS)
				{
					snprintf(
						resp, REPLY_TEXT,
						"%s(): EIPM_arpndp_admin_change_cfg_sess( %d, %p, ... ) for subnet_idx (%d) failed [%d]\n",
						__FUNCTION__,
						intf_idx,
						subnet_ptr,
						subnet_idx,
						eipm_arpndp_retval
						);

						LOG_ERROR(0, resp);

						return IPM_FAILURE;
				}
			}

			return IPM_SUCCESS;
		} /* subnet loop */
	} /* intf loop */

	return IPM_SUCCESS;
}

/**********************************************************************
 *
 * Name:        EIPM_delete_subnet_route()
 *
 * Abstract:    Delete subnet route before the subnet is deleted
 *
 * Description: 
**********************************************************************/
inline void EIPM_delete_subnet_route(EIPM_INTF *intf_ptr, EIPM_SUBNET * subnet_ptr)
{
	int nl_socket;

	nl_socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if( nl_socket < 0 )
	{
		LOG_ERROR(0, "EIPM_delete_subnet_route: failed to create routing socket \nnl_socket=%d, errno=0x%x\n", nl_socket, errno);
	}
	else
	{
		struct sockaddr_nl nladdr;
		int retval;

		nladdr.nl_family = AF_NETLINK;
		nladdr.nl_pad = 0;
		nladdr.nl_pid = 0;
		nladdr.nl_groups = 0;
		retval = bind(nl_socket, (struct sockaddr *)&nladdr, sizeof(nladdr));
		if( retval < 0 )
		{
			LOG_ERROR(0, "EIPM_delete_subnet_route: failed to bind routing socket \nretval=%d, errno=0x%x\n", retval, errno);	}
		else
		{
			(void)nma_route_del(nl_socket,
						intf_ptr->specData.lsn0_iface_indx,
						intf_ptr->lsn0_baseif,
						&subnet_ptr->subnet_base,
						subnet_ptr->prefixlen,
						NULL);

			(void)nma_route_del(nl_socket,
						intf_ptr->specData.lsn1_iface_indx,
						intf_ptr->lsn1_baseif,
						&subnet_ptr->subnet_base,
						subnet_ptr->prefixlen,
						NULL);
		}
		(void)close(nl_socket);
	}
	
	return;
}

/**********************************************************************
 *
 * Name:        EIPM_update_extern_subnet_alarm_data()
 *
 * Abstract:    Move alarm data per subnet when one base subnet is deleted
 *
 * Description:
**********************************************************************/

void EIPM_update_extern_subnet_alarm_data (
	EIPM_DATA *data_ptr, 
	EIPM_INTF *intf_ptr, int base_interface_index,
	int subnet_index)
{
	EIPM_INTF_SPEC  *intf_spec_ptr;
	int extn_intf_index=-1;
	int del_subnet_index=-1;
	if ( (subnet_index < 0 ) || 
		(subnet_index > EIPM_MAX_SUBNETS) ||
		(base_interface_index < 0) ||
		(base_interface_index > EIPM_MAX_EXT_SUB) ||
		(intf_ptr == NULL) ||
		(data_ptr == NULL)
	   )
	{
		ASRT_RPT( ASBAD_DATA, 0, "Invalid subnet index %d  or base interface index %d or pointer intf_ptr %p or data_ptr %p\n",
			subnet_index, 
			base_interface_index,
			intf_ptr, data_ptr );
		return;
	}

	if (data_ptr->extnIntfCount <= 0 )
	{
		// There is no external interface
		return;
	}

	/*
	 * Find all external interfaces move the alarm data 
	 * sorted by subnet index, then subnet index in alarm data 
	 * of external interface will be consistent with subnet index 
	 * in base interface when this subnet is deleted 
	 */
	for ( extn_intf_index=0, intf_spec_ptr=&(data_ptr->extnIntfData[0]); 
		extn_intf_index < data_ptr->extnIntfCount; 
		extn_intf_index++, intf_spec_ptr++ )
	{
		// Try to clear alarm firstly
		EIPM_CLEAR_SUBNET_ALARM(intf_spec_ptr, EIPM_EXTN_INTF,
			subnet_index, EIPM_MAX_ALARM);

		// Move the alarm data
		for (del_subnet_index=subnet_index;
			del_subnet_index < intf_ptr->subnet_cnt;
			del_subnet_index++)
		{
			memcpy(&(intf_spec_ptr->alarm[del_subnet_index][0]),
				&(intf_spec_ptr->alarm[del_subnet_index+1][0]),
				sizeof(intf_spec_ptr->alarm[0]));
		}
		memset( &(intf_spec_ptr->alarm[del_subnet_index][0]), 0,
			sizeof(intf_spec_ptr->alarm[0]) );
	}
				
	return;
}
/**********************************************************************
 *
 * Name:        EIPM_subnet_update()
 *
 * Abstract:    Called to add/delete subnet
 *
 * Description: 
**********************************************************************/
int EIPM_subnet_update(
        register struct cmd_subnet_upd *cmd_subnet_upd_ptr,
        EIPM_ADD_DEL type,
        char *resp,
	SUBNET_REQUEST request
)
{
	EIPM_DATA	*data_ptr;
	EIPM_INTF	*intf_ptr;
	EIPM_SUBNET	*subnet_ptr;
	EIPM_SUBNET	*bfd_subnet_ptr;
	EIPM_ROUTES	*route_ptr;
	EIPM_IPDATA     *ipdata_ptr;

	int		bfd_cnt = 0;
	int		bfd_subnet_idx;
	int		retval;
	int		del_idx;
	int		intf_idx;
	int		ip_idx;
	int		subnet_idx;
	int		upd_shared_memory;
	int		del_flag = 0;
	int		other_cnt = 0;
	int		none_cnt = 0;

	char		iface0_base[MAX_NLEN_DEV];
	char		*iface0_base_ptr = NULL;
	char		iface1_base[MAX_NLEN_DEV];
	char		*iface1_base_ptr = NULL;
	char		gateway_addr[IPM_IPMAXSTRSIZE];
	char		ip_addr[IPM_IPMAXSTRSIZE];

	IPM_REDUNDANCY_MODE redundancy_mode;

        IPM_IPADDR subnet_base;
        IPM_IPADDR subnet_mask;
        IPM_IPADDR gateway;

	IPM_RETVAL eipm_bfd_retval;
	IPM_RETVAL eipm_arpndp_retval;
        IPM_RETVAL ipm_retval;

	INTF_ACTION intf_action;

	if ( type == EIPM_DEL )
	{
		del_flag = 1;
	}

	if ( (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_INVALID && !del_flag )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: invalid redundancy mode %d\n",
			__FUNCTION__,
			cmd_subnet_upd_ptr->redundancy_mode
		);
		
		LOG_ERROR(0, resp);
		return IPM_INVALIDPARAMETER;
	}

	if ( request == INVALID_REQUEST )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: invalid subnet request %d\n",
			__FUNCTION__,
			request
		);

		LOG_ERROR(0, resp);
		return IPM_INVALIDPARAMETER;
	}

	if (
		(IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT &&
		( (strlen(cmd_subnet_upd_ptr->dev_t[0].dev_if) == 0) && 
		(strlen(cmd_subnet_upd_ptr->dev_t[1].dev_if) == 0) )
	)
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: interface not specified for redundant mode[%d], left iface[%s], right iface[%s], <%s>/<%d> gateway %s\n",
			__FUNCTION__,
			cmd_subnet_upd_ptr->redundancy_mode,
			( cmd_subnet_upd_ptr->dev_t[0].dev_if[0] != 0 ? cmd_subnet_upd_ptr->dev_t[0].dev_if : "empty" ),
			( cmd_subnet_upd_ptr->dev_t[1].dev_if[0] != 0 ? cmd_subnet_upd_ptr->dev_t[1].dev_if : "empty" ),
			cmd_subnet_upd_ptr->subnet_base,
			cmd_subnet_upd_ptr->prefix,
			( cmd_subnet_upd_ptr->gateway[0] != 0 ? cmd_subnet_upd_ptr->gateway : "empty" )
		);
		
		LOG_ERROR(0, resp);
		return IPM_INVALIDPARAMETER;
	}

	/* For now return success for the option of none and iipm. */
	/* Currently only consider the eipm-acm and eipm-bfd. */
	if ( (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_IIPM )
	{
		//subnet on beph interface is within iipm mode, make DAD "0" on those intfs
		(void)EIPM_set_sysctl_value(cmd_subnet_upd_ptr->dev_t[0].dev_if, "ipv6", "dad_transmits", 0);
		(void)EIPM_set_sysctl_value(cmd_subnet_upd_ptr->dev_t[1].dev_if, "ipv6", "dad_transmits", 0);
		return IPM_SUCCESS;
	}

	/* check if the interfaces are associated with external subnet */
	if ( cmd_subnet_upd_ptr->dev_t[0].dev_if[0] != 0 &&  
	     cmd_subnet_upd_ptr->dev_t[1].dev_if[0] != 0 )
	{
		if ( (cmd_subnet_upd_ptr->dev_t[0].subnet_type != IPM_SUBNET_EXTERNAL) &&
	    	 (cmd_subnet_upd_ptr->dev_t[1].subnet_type != IPM_SUBNET_EXTERNAL) )	
		{
			snprintf(
				resp, REPLY_TEXT,
				"%s() failure: %s and %s interfaces are not external\n",
				__FUNCTION__,
				cmd_subnet_upd_ptr->dev_t[0].dev_if,
				cmd_subnet_upd_ptr->dev_t[1].dev_if
			);

			LOG_ERROR(0, resp);
			return IPM_INVALIDPARAMETER;
		}
	}
	
	if ( cmd_subnet_upd_ptr->dev_t[0].dev_if[0] != 0 && cmd_subnet_upd_ptr->dev_t[0].subnet_type != IPM_SUBNET_EXTERNAL )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: %s interface is not external\n",
			__FUNCTION__,
			cmd_subnet_upd_ptr->dev_t[0].dev_if
		);

		LOG_ERROR(0, resp);
		return IPM_INVALIDPARAMETER;
	}

	if ( cmd_subnet_upd_ptr->dev_t[1].dev_if[0] != 0 && cmd_subnet_upd_ptr->dev_t[1].subnet_type != IPM_SUBNET_EXTERNAL )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: %s interface is not external\n",
			__FUNCTION__,
			cmd_subnet_upd_ptr->dev_t[1].dev_if
		);

		LOG_ERROR(0, resp);
		return IPM_INVALIDPARAMETER;
	}

	/* check the shared memory */
	if ( EIPM_shm_ptr == NULL )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: Shared memory null, left iface [%s], right iface [%s], <%s>/<%d> gateway %s\n",
			__FUNCTION__,
			( cmd_subnet_upd_ptr->dev_t[0].dev_if[0] != 0 ? cmd_subnet_upd_ptr->dev_t[0].dev_if : "empty" ),
			( cmd_subnet_upd_ptr->dev_t[1].dev_if[0] != 0 ? cmd_subnet_upd_ptr->dev_t[1].dev_if : "empty" ),
			cmd_subnet_upd_ptr->subnet_base,
			cmd_subnet_upd_ptr->prefix,
			( cmd_subnet_upd_ptr->gateway[0] != 0 ? cmd_subnet_upd_ptr->gateway : "empty" )
		);

		LOG_ERROR(0, resp);
		return IPM_FAILURE;
	}
	
	data_ptr = (EIPM_DATA *) EIPM_shm_ptr;

	/* derive base iface in case has :; shouldn't but backup in case */
	strncpy(iface0_base, cmd_subnet_upd_ptr->dev_t[0].dev_if, MAX_NLEN_DEV);
	iface0_base_ptr = strtok(iface0_base, ":");

	if (iface0_base_ptr == NULL)
	{
		iface0_base_ptr = iface0_base;
	}

	strncpy(iface1_base, cmd_subnet_upd_ptr->dev_t[1].dev_if, MAX_NLEN_DEV);
	iface1_base_ptr = strtok(iface1_base, ":");

	if (iface1_base_ptr == NULL)
	{
		iface1_base_ptr = iface1_base;
	}
	
	/* set the subnet ip address */
	IPM_ipaddr_init(&subnet_base);
	ipm_retval = IPM_p2ipaddr(cmd_subnet_upd_ptr->subnet_base, &subnet_base);
	if ( ipm_retval != IPM_SUCCESS )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: invalid subnet base IP address %s\n",
			__FUNCTION__,
			cmd_subnet_upd_ptr->subnet_base
		);

		LOG_ERROR(0, resp);
		return ipm_retval;;
	}

	/* set the subnet mask */
	IPM_ipaddr_init(&subnet_mask);
	ipm_retval = IPM_ipmkmask( &subnet_mask, subnet_base.addrtype, cmd_subnet_upd_ptr->prefix );
	if ( ipm_retval != IPM_SUCCESS )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: failed to create subnet mask for %s/%d\n",
			__FUNCTION__,
			cmd_subnet_upd_ptr->subnet_base,
			cmd_subnet_upd_ptr->prefix
		);

		LOG_ERROR(0, resp);
		return ipm_retval;;
	}

	/* set the gateway */
	IPM_ipaddr_init(&gateway);
	if ( cmd_subnet_upd_ptr->gateway[0] != 0 )
	{
		ipm_retval = IPM_p2ipaddr(cmd_subnet_upd_ptr->gateway, &gateway);
		if ( ipm_retval != IPM_SUCCESS )
		{
			snprintf(
				resp, REPLY_TEXT,
				"%s() failure: invalid gateway IP address %s\n",
				__FUNCTION__,
				cmd_subnet_upd_ptr->gateway
			);

			LOG_ERROR(0, resp);
			return ipm_retval;
		}
	}

	/* look if the matching subnet information is there for an interface */
	for ( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
		intf_idx < data_ptr->intf_cnt;
		intf_idx++, intf_ptr++ )
	{
		upd_shared_memory = 0;
		intf_action = EIPM_intf_match(
				intf_ptr,
				iface0_base_ptr,
				iface1_base_ptr,
				type,
				(IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode
		);

		switch( intf_action )
		{
			case INTF_CONTINUE:
				continue;
			case INTF_UPD_SHARED_MEMORY:
				upd_shared_memory = 1;
				break;
			case INTF_FAILURE:
				snprintf(
					resp, REPLY_TEXT,
					"%s() failure: interface pointer failure\n",
					__FUNCTION__
				);
				return IPM_FAILURE;
			default:
				/* match */
				break;
		}

		/* Found interface match, look for subnet match */
		if( type == EIPM_ADD )
		{
			if( intf_ptr->subnet_cnt == 0 )
			{
				/* Update sysctl parameters */
				(void)EIPM_set_sysctl_value(intf_ptr->lsn0_baseif, "ipv4", "arp_ignore", 1);

				(void)EIPM_set_sysctl_value(intf_ptr->lsn0_baseif, "ipv6", "dad_transmits", 0);

				(void)EIPM_set_sysctl_value(intf_ptr->lsn1_baseif, "ipv4", "arp_ignore", 1);

				(void)EIPM_set_sysctl_value(intf_ptr->lsn1_baseif, "ipv6", "dad_transmits", 0);
			}

			/* Schedule configuration check */
			EIPM_CHECK_INTF_CONFIG( &(intf_ptr->specData) );

			/* update the shared memory with the second interface if necessary; this applies for bfd */
			if ( upd_shared_memory )
			{
				struct cmd_base_iface base_iface;

				memset(&base_iface, 0, sizeof(base_iface));

				base_iface.subnet_type = IPM_SUBNET_EXTERNAL;
				base_iface.redundancy_mode = cmd_subnet_upd_ptr->redundancy_mode;

				strncpy(base_iface.base_if[0], cmd_subnet_upd_ptr->dev_t[0].dev_if, MAX_NLEN_DEV);
				strncpy(base_iface.base_if[1], cmd_subnet_upd_ptr->dev_t[1].dev_if, MAX_NLEN_DEV);

				retval = EIPM_base_update(&base_iface, EIPM_ADD, resp);
				if ( retval != IPM_SUCCESS )
				{
					snprintf(
						resp, REPLY_TEXT,
						"%s() failure: Failed to add base interface %s - %s for %s/%d\n",
						__FUNCTION__,
						( strlen( iface0_base_ptr ) > 0 ? cmd_subnet_upd_ptr->dev_t[0].dev_if : "empty" ),
						( strlen( iface1_base_ptr ) > 0 ? cmd_subnet_upd_ptr->dev_t[1].dev_if : "empty" ),
						cmd_subnet_upd_ptr->subnet_base,
						cmd_subnet_upd_ptr->prefix
					);

					LOG_ERROR(0, resp);
					return retval;
				}
			}
		}

		for ( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
		      subnet_idx < intf_ptr->subnet_cnt;
		      subnet_idx++, subnet_ptr++ )
		{
			if ( IPM_IPCMPADDR(&subnet_ptr->subnet_base, &subnet_base) == IPM_SUCCESS )
			{
				if ( subnet_ptr->prefixlen == cmd_subnet_upd_ptr->prefix )
				{
					if ( type == EIPM_ADD )
					{ 
						/* flag to indicate the session parameters were updated */
						int session_upd_flag = 0;

						/* Skip redundancy mode check for a subnet with the type "eipm_wcnp":  */
						/* There are 5 redundancy modes in ipm for WCNP subnets, but all modes */
						/* use one unified subnet type "eipm_wcnp".  The default mode is       */
						/* IPM_REDUNDANCY_MODE and ipm would overwrite the mode according to   */
						/* the IP type when a related WCNP IP is added.*/
						if ( (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode != IPM_RED_EIPM_WCNP_SERVICE )
						{
							if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode != (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode )
							{
								snprintf(
									resp, REPLY_TEXT,
									"%s() failure: Failed to match redundancy mode %d with new redundancy mode %d for subnet %s/%d\n",
									__FUNCTION__,
									subnet_ptr->redundancy_mode,
									cmd_subnet_upd_ptr->redundancy_mode,
									cmd_subnet_upd_ptr->subnet_base,
									cmd_subnet_upd_ptr->prefix
								);

								LOG_ERROR(0, resp);
								return IPM_FAILURE;
							}
						}
						/* update the gw and redundancy mode */
						if ( strlen(cmd_subnet_upd_ptr->gateway) > 0 )
						{
							if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
							{
								if ( IPM_IPCMPADDR(&subnet_ptr->gateway, &gateway ) != IPM_SUCCESS )
								{
									memset(gateway_addr, 0, sizeof(gateway_addr));
									IPM_ipaddr2p(&subnet_ptr->gateway, gateway_addr, IPM_IPMAXSTRSIZE);

									snprintf(
										resp, REPLY_TEXT,
										"%s() failure: Failed to match subnet gateway %s with new gateway %s for subnet %s/%d\n",
										__FUNCTION__,
										gateway_addr,
										cmd_subnet_upd_ptr->gateway,
										cmd_subnet_upd_ptr->subnet_base,
										cmd_subnet_upd_ptr->prefix
									);

									LOG_ERROR(0, resp);
									return IPM_FAILURE;
								} 
							}
							subnet_ptr->gateway = gateway;
						}

						if ( cmd_subnet_upd_ptr->detection_multiplier > 0 )
						{
							if ( subnet_ptr->detection_multiplier != cmd_subnet_upd_ptr->detection_multiplier )
							{
								session_upd_flag = 1;
							}

							subnet_ptr->detection_multiplier = cmd_subnet_upd_ptr->detection_multiplier;
						}

						if ( cmd_subnet_upd_ptr->desired_min_tx_interval > 0 )
						{
							if ( subnet_ptr->desired_min_tx_interval != cmd_subnet_upd_ptr->desired_min_tx_interval )
							{
								session_upd_flag = 1;
							}

							subnet_ptr->desired_min_tx_interval = cmd_subnet_upd_ptr->desired_min_tx_interval;
						}

						if ( cmd_subnet_upd_ptr->required_min_rx_interval > 0 )
						{
							if ( subnet_ptr->required_min_rx_interval != cmd_subnet_upd_ptr->required_min_rx_interval )
							{
								session_upd_flag = 1;
							}

							subnet_ptr->required_min_rx_interval = cmd_subnet_upd_ptr->required_min_rx_interval;
						}


						/* if session parameter change
						   loop through the subnet bfd session IPs 
						   and call BFD API to update values */
						if ( session_upd_flag &&
						     (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
						{
							int		ip_idx;
							int		error_cnt = 0;
							EIPM_IPDATA	*ipdata_ptr;

							for (ip_idx = 0, ipdata_ptr = &subnet_ptr->ips[0];
								ip_idx < subnet_ptr->ip_cnt;
								ip_idx++, ipdata_ptr++ )
							{
								eipm_bfd_retval = EIPM_bfd_admin_change_cfg_sess(
										intf_idx,
										subnet_idx,
										&ipdata_ptr->ipaddr
					    			    );

								if ( eipm_bfd_retval != IPM_SUCCESS )
								{
									snprintf(
										resp, REPLY_TEXT, "%s(): EIPM_bfd_admin_change_cfg_sess( %d, %d, ... ) failed [%d]\n",
										__FUNCTION__,
										intf_idx,
										subnet_idx,
										eipm_bfd_retval
									);

									LOG_ERROR(0, resp);
									error_cnt++;
								}
							}

							if ( error_cnt )
							{
								return IPM_FAILURE;
							}
						} /* update session and it is bfd transport */

						else if ( session_upd_flag &&
						          (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP &&
						          subnet_ptr->ip_cnt > 0 )
						{
							eipm_arpndp_retval = EIPM_arpndp_admin_change_cfg_sess(
										intf_idx,
										subnet_ptr,
										&(subnet_ptr->ips[0].ipaddr)
										);

							if (eipm_arpndp_retval != ARPNDP_SUCCESS)
							{
								snprintf(
									resp, REPLY_TEXT,
									"%s(): EIPM_arpndp_admin_change_cfg_sess( %d, %p, ... ) for subnet_idx (%d) failed [%d]\n",
									__FUNCTION__,
									intf_idx,
									subnet_ptr,
									subnet_idx,
									eipm_arpndp_retval
									);

									LOG_ERROR(0, resp);

									return IPM_FAILURE;
							}
						} /* update session for eipm_arpndp redundancy mode */
					} /* add end */
					else /* delete case for subnet match */
					{
						IPM_REDUNDANCY_MODE	subnet_redundancy_mode;
						IPM_IPADDRTYPE		subnet_type;

						if ( (request == CLI_REQUEST) && (subnet_ptr->ip_cnt > 0) )
						{
							subnet_ptr->delete_flag = TRUE;
							return IPM_SUCCESS;
						}


						subnet_redundancy_mode = (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode;
						subnet_type	= subnet_ptr->subnet_base.addrtype;

						/* clear any subnet alarms */
						EIPM_CLEAR_SUBNET_ALARM( intf_ptr, EIPM_BASE_INTF, subnet_idx, EIPM_MAX_ALARM );

						// Clean any possible rule information for this subnet before clean subnet
						EIPM_clean_subnet_rule(subnet_ptr);

						// Delete subnet route in OS before the subnet is deleted in IPM shared memory
						EIPM_delete_subnet_route(intf_ptr, subnet_ptr);
						/* delete the subnet */
						intf_ptr->subnet_cnt--;

						/* clear the subnet */ 
						for( del_idx = subnet_idx;
						     del_idx < intf_ptr->subnet_cnt;
						     del_idx++ )
						{
							intf_ptr->subnet[del_idx] = intf_ptr->subnet[del_idx+1];
							memcpy(&intf_ptr->specData.alarm[del_idx][0], &intf_ptr->specData.alarm[del_idx + 1][0], sizeof(intf_ptr->specData.alarm[0]));

						}
						memset(&intf_ptr->subnet[del_idx], 0, sizeof(intf_ptr->subnet[0]));

						/* clear alarm data */
						memset(&intf_ptr->specData.alarm[del_idx][0], 0, sizeof(intf_ptr->specData.alarm[0]));
						/*
						 * Update subnet index in external interface
						 * for alarm data
						 * /
						EIPM_update_extern_subnet_alarm_data(data_ptr,
							intf_ptr, intf_idx, subnet_idx);

						/* check if subnet is BFD transport if so then update the BFD subnet with gateway */
						if ( subnet_redundancy_mode == IPM_RED_BFD_TRANSPORT )
						{
							int idx = 0;
							EIPM_SUBNET *bfd_subnet_ptr;

							if ( strlen(iface0_base_ptr ) > 0 )
							{
								/* check if bfd transports or subnets */
								for ( idx = 0, bfd_subnet_ptr = &intf_ptr->subnet[0];
									idx < intf_ptr->subnet_cnt;
									idx++, bfd_subnet_ptr++ )
								{
									if ( ((IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD ||
                                                                              (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR) &&
										bfd_subnet_ptr->subnet_base.addrtype == subnet_type )
									{
										memset(&bfd_subnet_ptr->gateway, 0, sizeof(IPM_IPADDR));
									}
								}
							}
						}

						if ( intf_ptr->subnet_cnt == 0 && subnet_redundancy_mode == IPM_RED_EIPM_ACM )
						{
							/*
							 * Without any subnets, offline becomes degraded.
							 */
							if( intf_ptr->specData.status == EIPM_OFFLINE )
							{
								char linebuf[FSALARM_UTEXT_BUFFSZ];

								intf_ptr->specData.status = EIPM_DEGRADED;

								/*
								 * There are no next hop alarms need to re-issue the
								 * link failure alarm.
								 */
								if( intf_ptr->specData.dir == LSN02LSN1 )
								{
									sprintf( linebuf,
										"%s() Lost connectivity between %s and %s",
										__FUNCTION__,
										( intf_ptr->lsn0_baseif[0] != 0 ? intf_ptr->lsn0_baseif : "empty" ),
										( intf_ptr->lsn1_baseif[0] != 0 ? intf_ptr->lsn1_baseif : "empty" )
									);
								}
								else
								{
									sprintf( linebuf,
										"%s() Lost connectivity between %s and %s",
										__FUNCTION__,
										( intf_ptr->lsn1_baseif[0] != 0 ? intf_ptr->lsn1_baseif : "empty" ),
										( intf_ptr->lsn0_baseif[0] != 0 ? intf_ptr->lsn0_baseif : "empty" )
									);
								}

								EIPM_SEND_INTF_ALARM( EIPM_LNK_FAIL,
									1,
									intf_ptr,
	                                                                EIPM_BASE_INTF,
									FSAS_major,
									( intf_ptr->lsn0_baseif[0] != 0  ? intf_ptr->lsn0_baseif : "empty" ),
									linebuf );
							} /* EIPM offline */
						} /* ACM redundancy */

						if ( intf_ptr->subnet_cnt == 0 )
						{
							/* Clear any interface alarms alarms */
							EIPM_CLEAR_INTF_ALARM( intf_ptr, EIPM_BASE_INTF, EIPM_MAX_ALARM );

							/*
							 * Close all interface sockets.
							 */
							EIPM_close_sock( &(intf_ptr->specData ));

							/* Delete interface, collapse interface table */
							data_ptr->intf_cnt--;

							for( del_idx = intf_idx;
							     del_idx < data_ptr->intf_cnt;
							     del_idx++ )
							{
								data_ptr->intf_data[del_idx] = data_ptr->intf_data[del_idx + 1];
								data_ptr->intf_data[del_idx].specData.baseIntfIdx = del_idx;
							}

							/* Clear last interface entry */
							memset(&data_ptr->intf_data[del_idx], 0, sizeof(data_ptr->intf_data[0]));
						}
						else
						{
							if ( strlen( iface0_base_ptr ) > 0 && strlen( iface1_base_ptr ) > 0 )
							{
								if ( intf_ptr->lsn0_baseif[0] != 0 && intf_ptr->lsn1_baseif[0] != 0 )
								{
									int num_transports = 0;
									int num_subnets = 0;
									int idx = 0;

									/* check if bfd transports or subnets */
									for ( idx = 0, subnet_ptr = &intf_ptr->subnet[0];
										idx < intf_ptr->subnet_cnt;
										idx++, subnet_ptr++ )
									{
										if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
										{
											num_transports++;
										}
										else
										{
											num_subnets++;
										}
									}

									/* update shared memory */
									if ( !num_subnets && num_transports )
									{
										memset(intf_ptr->lsn1_baseif, 0, sizeof(intf_ptr->lsn1_baseif));
									}
								}
							}
						}
					} /* end delete case */

					return IPM_SUCCESS;
				} /* subnet prefix match */
			} /* subnet match */
		} /* search subnet */

		/* need to associate now depending on type of redundancy */
		/* interface match but no subnet */
		if ( type == EIPM_ADD )
		{
			none_cnt = 0;
			other_cnt = 0;
			bfd_cnt = 0;

			/* check if BFD then no other subnets can be configured */
			for ( bfd_subnet_idx = 0, bfd_subnet_ptr = &intf_ptr->subnet[0];
				bfd_subnet_idx < intf_ptr->subnet_cnt;
				bfd_subnet_idx++, bfd_subnet_ptr++ )
			{
				if ( (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT ||
					(IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD || 
					(IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR )
				{
					bfd_cnt++;
				}
				else if ( (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_NONE ||
				          (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP )
				{
					none_cnt++;
				}
				else
				{
					other_cnt++;
				}
			}

			if ( (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_NONE ||
			     (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP )
			{
				if ( bfd_cnt > 0 || other_cnt > 0 )
				{
					/* continue looking for interface b/c this has bfd configured */
					continue;
				}
			}

			if ( ( (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT ||
				(IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_EIPM_BFD ||
				(IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_BFD_RSR ) &&
				none_cnt )
			{
				/* continue looking for interface b/c have none subnes configured */
				continue;
			}

			if ( ( (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT ||
				(IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_EIPM_BFD ||
				(IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_BFD_RSR) &&
				other_cnt )
			{
				/* error, cannot have bfd subnets or transports on the interface since have non-bfd subnets */
				snprintf(
					resp, REPLY_TEXT,
					"%s() failure: non-bfd subnets configured on %s - %s, cannot insert %s/%d with redundancy mode [%d]\n",
					__FUNCTION__,
					( strlen( intf_ptr->lsn0_baseif ) > 0 ? intf_ptr->lsn0_baseif : "empty" ),
					( strlen( intf_ptr->lsn1_baseif ) > 0 ? intf_ptr->lsn1_baseif : "empty" ),
					cmd_subnet_upd_ptr->subnet_base,
					cmd_subnet_upd_ptr->prefix,
					cmd_subnet_upd_ptr->redundancy_mode
				);

				LOG_ERROR(0, resp);
				return IPM_FAILURE;
			}

			if ( (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode != IPM_RED_BFD_TRANSPORT &&
				(IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode != IPM_RED_EIPM_BFD &&
				(IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode != IPM_RED_BFD_RSR &&
				bfd_cnt )
			{
				/* error, cannot have other subnets on the interface since have bfd subnets or transports */
				snprintf(
					resp, REPLY_TEXT,
					"%s() failure: bfd subnets configured on %s - %s, cannot insert %s/%d with redundancy mode [%d]\n",
					__FUNCTION__,
					( strlen( intf_ptr->lsn0_baseif ) > 0 ? intf_ptr->lsn0_baseif : "empty" ),
					( strlen( intf_ptr->lsn1_baseif ) > 0 ? intf_ptr->lsn1_baseif : "empty" ),
					cmd_subnet_upd_ptr->subnet_base,
					cmd_subnet_upd_ptr->prefix,
					cmd_subnet_upd_ptr->redundancy_mode
				);

				LOG_ERROR(0, resp);
				return IPM_FAILURE;
			}

			/*
			 * Check whether the Max number of subnet is reached
			 */
			if( intf_ptr->subnet_cnt >= EIPM_MAX_SUBNETS )
			{
				snprintf(resp, REPLY_TEXT,
					"%s() failure: The EIPM subnet limitation(%d) is reached\n",
				__FUNCTION__, EIPM_MAX_SUBNETS);
				ASRT_RPT( ASBAD_DATA, 0, "The EIPM subnet limitation(%d) is reached", EIPM_MAX_SUBNETS);
				return IPM_FAILURE;
			}

			/* subnet info */
			subnet_ptr = &intf_ptr->subnet[intf_ptr->subnet_cnt];

			memset(subnet_ptr, 0, sizeof(*subnet_ptr)); 

			subnet_ptr->redundancy_mode = cmd_subnet_upd_ptr->redundancy_mode;

			switch( subnet_ptr->redundancy_mode )
			{
			case IPM_RED_BFD_TRANSPORT:
			case IPM_RED_EIPM_BFD:	
			case IPM_RED_BFD_RSR:		
				subnet_ptr->status = EIPM_STAT_NULL;
				break;

			case IPM_RED_NONE:
			case IPM_RED_EIPM_ARPNDP:
				subnet_ptr->status = EIPM_STAT_NULL;
				intf_ptr->specData.status = EIPM_STAT_NULL;
				break;

			default:
				subnet_ptr->status = EIPM_ONLINE;
			}

			subnet_ptr->bfd_status			= EIPM_STAT_NULL;
			subnet_ptr->arpndp_status		= EIPM_STAT_NULL;
			subnet_ptr->miss_tran			= FALSE;
			subnet_ptr->subnet_base			= subnet_base;
			subnet_ptr->prefixlen			= cmd_subnet_upd_ptr->prefix;
			subnet_ptr->gateway			= gateway;
			subnet_ptr->detection_multiplier	= cmd_subnet_upd_ptr->detection_multiplier;
			subnet_ptr->desired_min_tx_interval	= cmd_subnet_upd_ptr->desired_min_tx_interval;
			subnet_ptr->required_min_rx_interval	= cmd_subnet_upd_ptr->required_min_rx_interval;
			subnet_ptr->table_num 			= cmd_subnet_upd_ptr->table_num;

			intf_ptr->subnet_cnt++;

			// Init subnet to interface mapping data
			int v_idx=0;
			// Always set is_intf_configured is 1 for base interface
			subnet_ptr->sub2intf_mapping[v_idx].is_intf_configured = 1;
			subnet_ptr->sub2intf_mapping[v_idx].route_priority = LSN0;
			for (v_idx=1; v_idx < EIPM_MAX_VLANS; v_idx++)
			{
				subnet_ptr->sub2intf_mapping[v_idx].is_intf_configured = 0;
				subnet_ptr->sub2intf_mapping[v_idx].route_priority = LSN0;
			}

			EIPM_open_garpsock( &(intf_ptr->specData), subnet_ptr->subnet_base.addrtype );
    			EIPM_update_subnet_route_priority( &intf_ptr->specData, subnet_ptr, intf_ptr->specData.preferred_side );

			/* check if bfd transport or bfd subnet to update gateway */
			if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
			{
				if ( strlen( iface0_base_ptr ) > 0 )
				{
					for ( bfd_subnet_idx = 0, bfd_subnet_ptr = &intf_ptr->subnet[0];
						bfd_subnet_idx < intf_ptr->subnet_cnt;
						bfd_subnet_idx++, bfd_subnet_ptr++ )
					{
						if ( ((IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD ||
                                                      (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR ) &&
							subnet_ptr->subnet_base.addrtype == bfd_subnet_ptr->subnet_base.addrtype )
						{
							bfd_subnet_ptr->gateway = subnet_ptr->gateway;
						}
					}
				}
			}
			else if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD ||
                                  (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR )
			{
				for ( bfd_subnet_idx = 0, bfd_subnet_ptr = &intf_ptr->subnet[0];
					bfd_subnet_idx < intf_ptr->subnet_cnt;
					bfd_subnet_idx++, bfd_subnet_ptr++ )
				{
					if ( (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT &&
						subnet_ptr->subnet_base.addrtype == bfd_subnet_ptr->subnet_base.addrtype )
					{
						if ( subnet_ptr->ip_cnt > 0 )
						{
							subnet_ptr->gateway = bfd_subnet_ptr->gateway;
						}
						break;
					}
				}
			}

			/* ARP info */
			memset(&subnet_ptr->arpdata, 0, sizeof(subnet_ptr->arpdata));

			if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_EIPM_ACM )
			{
				subnet_ptr->arp_counter = EIPM_ARP_IP_WAIT * EIPM_ARP_CNT_PER_SEC;
			}

			return IPM_SUCCESS;
		}
		else
		{
			if ( strlen( iface0_base_ptr ) > 0 && strlen( iface1_base_ptr ) == 0 )
			{
				/* continue looking for interface if have specified a left interface w/o iface1 for NONE */
				continue;
			}

			if ( strlen( iface1_base_ptr ) > 0 && strlen( iface0_base_ptr ) == 0 )
			{
				/* continue looking for interface if have specified a right interface w/o iface0 for NONE */
				continue;
			}
		}
	} /* interface search and found */

	/* if delete and come here, need return success */
	if ( type == EIPM_DEL )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: left interface [%s], right interface [%s], %s/%d no match\n",
			__FUNCTION__,
			( strlen( iface0_base_ptr ) > 0 ? cmd_subnet_upd_ptr->dev_t[0].dev_if : "empty" ),
			( strlen( iface1_base_ptr ) > 0 ? cmd_subnet_upd_ptr->dev_t[1].dev_if : "empty" ),
			cmd_subnet_upd_ptr->subnet_base,
			cmd_subnet_upd_ptr->prefix
		);

		LOG_DEBUG(0, resp);
		return IPM_SUCCESS;
	}
	
	/* add the interface */
	struct cmd_base_iface base_iface;

	memset(&base_iface, 0, sizeof(base_iface));

	base_iface.subnet_type = IPM_SUBNET_EXTERNAL;
	base_iface.redundancy_mode = cmd_subnet_upd_ptr->redundancy_mode;

	strncpy(base_iface.base_if[0], cmd_subnet_upd_ptr->dev_t[0].dev_if, MAX_NLEN_DEV);
	strncpy(base_iface.base_if[1], cmd_subnet_upd_ptr->dev_t[1].dev_if, MAX_NLEN_DEV);

	retval = EIPM_base_update(&base_iface, EIPM_ADD, resp);
	if ( retval != IPM_SUCCESS )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: Failed to add base interface %s - %s for %s/%d\n",
			__FUNCTION__,
			( strlen( iface0_base_ptr ) > 0 ? cmd_subnet_upd_ptr->dev_t[0].dev_if : "empty" ),
			( strlen( iface1_base_ptr ) > 0 ? cmd_subnet_upd_ptr->dev_t[1].dev_if : "empty" ),
			cmd_subnet_upd_ptr->subnet_base,
			cmd_subnet_upd_ptr->prefix
		);

		LOG_ERROR(0, resp);
		return retval;
	}
	
	/* Add new interface */
	intf_ptr = &data_ptr->intf_data[data_ptr->intf_cnt-1];

	/*
	 * Create ping-pong sockets for non-bfd/non-wcnp subnet or sessions.
	 */
	if ( (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_EIPM_ACM )
	{
		retval = EIPM_create_intf_sockets( intf_ptr, EIPM_BASE_INTF );
		if( retval != IPM_SUCCESS )
		{
			snprintf(resp, REPLY_TEXT, 
				"%s(): Creating monitor sockets failed for interface=%s",
				__FUNCTION__,
				intf_ptr->lsn0_baseif
			);

			LOG_ERROR(0, resp);

			/*
			 * Need to clean up this entry since we
			 * are abandoning it.
			 */
			memset(intf_ptr, 0, sizeof(EIPM_INTF));
      
			data_ptr->intf_cnt--;
			return IPM_FAILURE;
		}
	}
	else if ( (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_NONE ||
	          (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP )
	{
		intf_ptr->specData.monitor = EIPM_MONITOR_IP;
	}
	else if ( (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_ACTIVE ||
		  (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_STANDBY || 
		  (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_SERVICE || 
		  (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_FIXLEFT || 
		  (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_FIXRIGHT )
	{
		intf_ptr->specData.monitor = EIPM_MONITOR_WCNP;
	}
	else
	{
		intf_ptr->specData.monitor = EIPM_MONITOR_BFD;
	}

	/* subnet info */
	subnet_ptr = &intf_ptr->subnet[0];

	memset(subnet_ptr, 0, sizeof(*subnet_ptr));

	subnet_ptr->redundancy_mode = cmd_subnet_upd_ptr->redundancy_mode;

	switch( subnet_ptr->redundancy_mode )
	{
	case IPM_RED_BFD_TRANSPORT:	
	case IPM_RED_EIPM_BFD:		
	case IPM_RED_BFD_RSR:		
		subnet_ptr->status = EIPM_STAT_NULL;
		break;

	case IPM_RED_NONE:
	case IPM_RED_EIPM_ARPNDP:
		subnet_ptr->status = EIPM_STAT_NULL;
		intf_ptr->specData.status = EIPM_STAT_NULL;
		break;

	default:
		subnet_ptr->status = EIPM_ONLINE;
	}

	subnet_ptr->bfd_status			= EIPM_STAT_NULL;
	subnet_ptr->arpndp_status		= EIPM_STAT_NULL;
	subnet_ptr->miss_tran			= FALSE;
	subnet_ptr->subnet_base			= subnet_base;
	subnet_ptr->prefixlen			= cmd_subnet_upd_ptr->prefix;
	subnet_ptr->gateway			= gateway;
	subnet_ptr->detection_multiplier	= cmd_subnet_upd_ptr->detection_multiplier;
	subnet_ptr->desired_min_tx_interval	= cmd_subnet_upd_ptr->desired_min_tx_interval;
	subnet_ptr->required_min_rx_interval	= cmd_subnet_upd_ptr->required_min_rx_interval;
	subnet_ptr->table_num 			= cmd_subnet_upd_ptr->table_num;

	intf_ptr->subnet_cnt = 1;

	// Init subnet to interface mapping data
	int v_idx=0;

	// Always set is_intf_configured is 1 for base interface
	subnet_ptr->sub2intf_mapping[v_idx].is_intf_configured = 1;
	subnet_ptr->sub2intf_mapping[v_idx].route_priority = LSN0;
	for (v_idx=1; v_idx < EIPM_MAX_VLANS; v_idx++)
	{
		subnet_ptr->sub2intf_mapping[v_idx].is_intf_configured = 0;
		subnet_ptr->sub2intf_mapping[v_idx].route_priority = LSN0;
	}

	EIPM_open_garpsock( &(intf_ptr->specData), subnet_ptr->subnet_base.addrtype );
	EIPM_update_subnet_route_priority( &intf_ptr->specData, subnet_ptr, intf_ptr->specData.preferred_side );

	/* check if bfd transport or bfd subnet to update gateway */
	if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
	{
		if ( strlen (iface0_base_ptr ) > 0 )
		{
			for ( bfd_subnet_idx = 0, bfd_subnet_ptr = &intf_ptr->subnet[0];
				bfd_subnet_idx < intf_ptr->subnet_cnt;
				bfd_subnet_idx++, bfd_subnet_ptr++ )
			{
				if ( ( (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD ||
                                       (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR ) &&

					subnet_ptr->subnet_base.addrtype == bfd_subnet_ptr->subnet_base.addrtype )
				{
					bfd_subnet_ptr->gateway = subnet_ptr->gateway;
				}
			}
		}
	}
	else if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD ||
                  (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR )
	{
		for ( bfd_subnet_idx = 0, bfd_subnet_ptr = &intf_ptr->subnet[0];
			bfd_subnet_idx < intf_ptr->subnet_cnt;
			bfd_subnet_idx++, bfd_subnet_ptr++ )
		{
			if ( (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT &&
				subnet_ptr->subnet_base.addrtype == bfd_subnet_ptr->subnet_base.addrtype )
			{
				if ( subnet_ptr->ip_cnt > 0 )
				{
					subnet_ptr->gateway = bfd_subnet_ptr->gateway;
				}
				break;
			}
		}
	}

	/* ARP Info */
	memset(&subnet_ptr->arpdata, 0, sizeof(subnet_ptr->arpdata));
	if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_EIPM_ACM )
	{
		subnet_ptr->arp_counter = EIPM_ARP_IP_WAIT * EIPM_ARP_CNT_PER_SEC;
	}
	
	/* Update sysctl parameters */
	(void)EIPM_set_sysctl_value(iface0_base_ptr, "ipv4", "arp_ignore", 1);

	(void)EIPM_set_sysctl_value(iface0_base_ptr, "ipv6", "dad_transmits", 0);

	(void)EIPM_set_sysctl_value(iface1_base_ptr, "ipv4", "arp_ignore", 1);

	(void)EIPM_set_sysctl_value(iface1_base_ptr, "ipv6", "dad_transmits", 0);

	/* Schedule configuration check */
	EIPM_CHECK_INTF_CONFIG( &(intf_ptr->specData) );

	return IPM_SUCCESS;
}

/**********************************************************************
 *
 * Name:        EIPM_dump_session()
 *
 * Abstract:    Called to dump the session information
 *
 * Description: 
**********************************************************************/
int EIPM_dump_session(
        struct cmd_ipm_admin *cmd_ipm_admin_ptr,
        char *resp
)
{
	EIPM_DATA	*data_ptr;
	EIPM_INTF	*intf_ptr;
	EIPM_SUBNET	*subnet_ptr;
	EIPM_IPDATA     *ipdata_ptr;

	int		check_gateway = 0;
	int		check_ip = 0;
	int		error_cnt = 0;

	int		intf_idx;
	int		ip_idx;
	int		retval;
	int		subnet_idx;

        IPM_RETVAL ipm_retval;

        IPM_IPADDR ip;
        IPM_IPADDR subnet_mask;
        IPM_IPADDR subnet_base;
        IPM_IPADDR gateway;

	/* check the shared memory */
	if ( EIPM_shm_ptr == NULL )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: Shared memory null\n",
			__FUNCTION__
		);

		LOG_ERROR(0, resp);
		return IPM_FAILURE;
	}
	
	data_ptr = (EIPM_DATA *) EIPM_shm_ptr;

	/* set the ip address */
	if ( cmd_ipm_admin_ptr->ip[0] != 0 )
	{
		IPM_ipaddr_init(&ip);
		ipm_retval = IPM_p2ipaddr(cmd_ipm_admin_ptr->ip, &ip);
		if ( ipm_retval != IPM_SUCCESS )
		{
			snprintf(
				resp, REPLY_TEXT,
				"%s() failure: invalid IP address %s\n",
				__FUNCTION__,
				cmd_ipm_admin_ptr->ip
			);

			LOG_ERROR(0, resp);
			return ipm_retval;;
		}

		check_ip = 1;
	}

	/* set the gateway */
	if ( cmd_ipm_admin_ptr->gateway[0] != 0 )
	{
		IPM_ipaddr_init(&gateway);
		if ( cmd_ipm_admin_ptr->gateway[0] != 0 )
		{
			ipm_retval = IPM_p2ipaddr(cmd_ipm_admin_ptr->gateway, &gateway);
			if ( ipm_retval != IPM_SUCCESS )
			{
				snprintf(
					resp, REPLY_TEXT,
					"%s() failure: invalid gateway IP address %s\n",
					__FUNCTION__,
					cmd_ipm_admin_ptr->gateway
				);

				LOG_ERROR(0, resp);
				return ipm_retval;
			}
		}

		check_gateway = 1;
	}

	/* confirm that if check ip that gateway is specified */
	if ( check_ip && !check_gateway )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: invalid option, specified ip %s but not gateway\n",
			__FUNCTION__,
			cmd_ipm_admin_ptr->ip
		);

		LOG_ERROR(0, resp);
		return IPM_FAILURE;
	}

	/* confirm that if check gateway that the ip is specified */
	if ( !check_ip && check_gateway )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: invalid option, specified gateway %s but not ip\n",
			__FUNCTION__,
			cmd_ipm_admin_ptr->gateway
		);

		LOG_ERROR(0, resp);
		return IPM_FAILURE;
	}

    	for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
		intf_idx < data_ptr->intf_cnt;
		intf_idx++, intf_ptr++ )
	{
		for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
			subnet_idx < intf_ptr->subnet_cnt;
			subnet_idx++, subnet_ptr++ )
		{
			IPM_RETVAL	eipm_retval = IPM_SUCCESS;
			bool		found_ip = FALSE;

			if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
			{
				eipm_retval = EIPM_bfd_dump_sessions(
							intf_ptr,
							subnet_idx,
							&subnet_ptr->subnet_base,
							&ip,
							&gateway,
							check_ip,
							&found_ip
			 				);
			}
			else if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP )
			{
				eipm_retval = EIPM_arpndp_dump_sessions(
							intf_ptr,
							subnet_idx,
							&subnet_ptr->subnet_base,
							&ip,
							&gateway,
							check_ip,
							&found_ip
			 				);
			}
			else
			{
				continue;
			}

			if (found_ip == TRUE)
			{
				/* Optimization: we found the IP address we
				 * were looking for so break out of the loops.
				 */
				return IPM_SUCCESS;
			}

			if (eipm_retval != IPM_SUCCESS)
			{
				error_cnt++;
			}

		} /* for loop for subnet search */
	} /* for loop for interface */

	if ( error_cnt )
	{
		LOG_ERROR(
			0,
			"%s() - has failures\n",
			__FUNCTION__
		);

		return IPM_FAILURE;
	}

	return IPM_SUCCESS;
}

/**********************************************************************
 *
 * Name:        EIPM_set_session()
 *
 * Abstract:    Called to set the session information
 *
 * Description: 
**********************************************************************/
int EIPM_set_session(
        register struct cmd_ipm_admin *cmd_ipm_admin_ptr,
        char *resp
)
{
	EIPM_DATA	*data_ptr;
	EIPM_INTF	*intf_ptr;
	EIPM_SUBNET	*subnet_ptr;
	EIPM_IPDATA     *ipdata_ptr;

	int		check_gateway = 0;
	int		check_ip = 0;
	int		error_cnt = 0;

	int		intf_idx;
	int		ip_idx;
	int		retval;
	int		subnet_idx;

        IPM_RETVAL eipm_bfd_retval;
        IPM_RETVAL eipm_arpndp_retval;
        IPM_RETVAL ipm_retval;

        IPM_IPADDR ip;
        IPM_IPADDR subnet_base;
        IPM_IPADDR gateway;

	ARPNDP_ADMIN_STATE arpndp_admin;

	/* check the shared memory */
	if ( EIPM_shm_ptr == NULL )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: Shared memory null\n",
			__FUNCTION__
		);

		LOG_ERROR(0, resp);
		return IPM_FAILURE;
	}
	
	data_ptr = (EIPM_DATA *) EIPM_shm_ptr;

	/* set the ip address */
	if ( cmd_ipm_admin_ptr->ip[0] != 0 )
	{
		IPM_ipaddr_init(&ip);
		ipm_retval = IPM_p2ipaddr(cmd_ipm_admin_ptr->ip, &ip);
		if ( ipm_retval != IPM_SUCCESS )
		{
			snprintf(
				resp, REPLY_TEXT,
				"%s() failure: invalid IP address %s\n",
				__FUNCTION__,
				cmd_ipm_admin_ptr->ip
			);

			LOG_ERROR(0, resp);
			return ipm_retval;;
		}
	}
	else
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: IP address not specified\n",
			__FUNCTION__
		);

		LOG_ERROR(0, resp);
		return IPM_FAILURE;
	}

	if ( EIPM_bfd_admin_state_valid(cmd_ipm_admin_ptr->state) == FALSE )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: invalid session state [%d]\n",
			__FUNCTION__,
			cmd_ipm_admin_ptr->state
		);

		LOG_ERROR(0, resp);
		return IPM_FAILURE;
	}

	/* set the gateway */
	if ( cmd_ipm_admin_ptr->gateway[0] != 0 )
	{
		IPM_ipaddr_init(&gateway);
		if ( cmd_ipm_admin_ptr->gateway[0] != 0 )
		{
			ipm_retval = IPM_p2ipaddr(cmd_ipm_admin_ptr->gateway, &gateway);
			if ( ipm_retval != IPM_SUCCESS )
			{
				snprintf(
					resp, REPLY_TEXT,
					"%s() failure: invalid gateway IP address %s\n",
					__FUNCTION__,
					cmd_ipm_admin_ptr->gateway
				);

				LOG_ERROR(0, resp);
				return ipm_retval;
			}
		}
	}
	else
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: gateway IP address not specified\n",
			__FUNCTION__
		);

		LOG_ERROR(0, resp);
		return IPM_FAILURE;
	}

    	for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
		intf_idx < data_ptr->intf_cnt;
		intf_idx++, intf_ptr++ )
	{
		for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
			subnet_idx < intf_ptr->subnet_cnt;
			subnet_idx++, subnet_ptr++ )
		{
			if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode != IPM_RED_BFD_TRANSPORT )
			{
				if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP )
				{
					if( IPM_IPCMPADDR(&subnet_ptr->gateway, &gateway) != IPM_SUCCESS )
					{
						continue;
					}

					if( subnet_ptr->ip_cnt == 0 || IPM_IPCMPADDR(&(subnet_ptr->ips[0].ipaddr), &ip) != IPM_SUCCESS )
					{
						continue;
					}

					if ( cmd_ipm_admin_ptr->state == BFD_ADMIN_STATE_DOWN )
					{
						arpndp_admin = ARPNDP_ADMIN_STATE_DOWN;
					}
					else
					{
						arpndp_admin = ARPNDP_ADMIN_STATE_UP;
					}

					eipm_arpndp_retval = EIPM_arpndp_admin_set_state_sess(
									intf_idx,
									&subnet_ptr->gateway,
									&(subnet_ptr->ips[0].ipaddr),
									arpndp_admin
									);

					if ( eipm_arpndp_retval != IPM_SUCCESS )
					{
						snprintf(
							resp, REPLY_TEXT, "%s(): EIPM_arpndp_admin_set_state_sess( %d, %d, %d, ... ) failed [%d]\n",
							__FUNCTION__,
							intf_idx,
							subnet_idx,
							arpndp_admin,
							eipm_arpndp_retval
						);

						LOG_ERROR(0, resp);

						return IPM_FAILURE;
					}
					else
					{
						subnet_ptr->ips[0].state = (int) cmd_ipm_admin_ptr->state;

						return IPM_SUCCESS;
					}
				}

				continue;
			}

			if( IPM_IPCMPADDR(&subnet_ptr->gateway, &gateway) != IPM_SUCCESS )
			{
				continue;
			} /* subnet and gateway mis-match */

			/* bfd_rsr not allowed to enable or disable session */
			if (EIPM_is_bfd_trans_rsr_svc_sn(intf_idx, subnet_idx) == IPM_SUCCESS)
			{
				snprintf(
					resp, REPLY_TEXT,
					"%s() failure: cannot change admin state for bfd rsr\n",
					__FUNCTION__
				);

				LOG_ERROR(0, resp);
				return IPM_FAILURE;				
			}

			/* dump the information for the ips associated w/ this subnet */
			for ( ip_idx = 0, ipdata_ptr = &subnet_ptr->ips[0];
				ip_idx < subnet_ptr->ip_cnt;
				ip_idx++, ipdata_ptr++ )
			{
				/* ip match */
				if( IPM_IPCMPADDR(&ipdata_ptr->ipaddr, &ip) != IPM_SUCCESS )
				{
					continue;
				}

				eipm_bfd_retval = EIPM_bfd_admin_set_state_sess(
					intf_idx,
					subnet_idx,
					ipdata_ptr,
					(BFD_ADMIN_STATE) cmd_ipm_admin_ptr->state
				    );

				if ( eipm_bfd_retval != IPM_SUCCESS )
				{
					snprintf(
						resp, REPLY_TEXT, "%s(): EIPM_bfd_admin_set_state_sess( %d, %d, %d, ... ) failed [%d]\n",
						__FUNCTION__,
						intf_idx,
						subnet_idx,
						cmd_ipm_admin_ptr->state,
						eipm_bfd_retval
					);

					LOG_ERROR(0, resp);

					return IPM_FAILURE;
				}
				else
				{
					ipdata_ptr->state = (int) cmd_ipm_admin_ptr->state;

					return IPM_SUCCESS;
				}
			}
		} /* for loop for subnet search */
	} /* for loop for interface */

	/* This means that no match was found */
	snprintf(
		resp, REPLY_TEXT,
		"%s() - no match for ip %s, gateway %s\n",
		__FUNCTION__,
		cmd_ipm_admin_ptr->ip,
		cmd_ipm_admin_ptr->gateway
	);

	LOG_ERROR(0, resp);

	return IPM_FAILURE;
}

/**********************************************************************
 *
 * Name:        EIPM_intf_match()
 *
 * Abstract:    match the interface 
 *
 * Description: 
**********************************************************************/
INTF_ACTION EIPM_intf_match(
	EIPM_INTF *intf_ptr,
	char *iface0_base_ptr,
	char *iface1_base_ptr,
	EIPM_ADD_DEL type,
	IPM_REDUNDANCY_MODE mode
)
{
	if ( intf_ptr == NULL )
	{
		LOG_ERROR(
			0,
			"%s() failure: intf_ptr is null\n",
			__FUNCTION__
		);

		return INTF_FAILURE;
	}

	if ( intf_ptr->lsn0_baseif[0] != 0 && intf_ptr->lsn1_baseif[0] != 0 )
	{
		if ( strlen( iface0_base_ptr ) > 0 && strlen( iface1_base_ptr ) > 0 )
		{
			if ( (strcmp( intf_ptr->lsn0_baseif, iface0_base_ptr ) != 0) ||
	   		 (strcmp( intf_ptr->lsn1_baseif, iface1_base_ptr ) != 0) )
			{
				return INTF_CONTINUE;
			}
		}
		else if ( strlen( iface0_base_ptr ) > 0 )
		{
			if ( strcmp( intf_ptr->lsn0_baseif, iface0_base_ptr ) != 0 )
			{
				return INTF_CONTINUE;
			}

			if ( type == EIPM_ADD )
			{
				if ( mode == IPM_RED_NONE || mode == IPM_RED_EIPM_ARPNDP )
				{
					return INTF_CONTINUE;
				}
			}
		}
		else
		{
			return INTF_CONTINUE;
		}
	}
	else if ( intf_ptr->lsn0_baseif[0] != 0 && strlen( iface0_base_ptr ) > 0 )
	{
		if ( strcmp( intf_ptr->lsn0_baseif, iface0_base_ptr ) != 0 )
		{
			return INTF_CONTINUE;
		}

		if ( strlen( iface0_base_ptr ) > 0 && strlen( iface1_base_ptr ) > 0 )
		{
			return INTF_UPD_SHARED_MEMORY;
		}
	}
	else if ( intf_ptr->lsn1_baseif[0] != 0 && strlen( iface1_base_ptr ) > 0 )
	{
		if ( strlen( iface0_base_ptr ) > 0 && strlen( iface1_base_ptr ) > 0 )
		{
			return INTF_CONTINUE;
		}

		if ( strcmp( intf_ptr->lsn1_baseif, iface1_base_ptr ) != 0 )
		{
			return INTF_CONTINUE;
		}
	}
	else
	{
		return INTF_CONTINUE;
	}

	return INTF_MATCH;
}

/**********************************************************************
 *
 * Name:        EIPM_clean_subnet_rule()
 *
 * Abstract:    This function will be called when delete subnet. It is used to
 *		delete all rule information related to this subnet.
 *
 * Parameters:  subnet_ptr - pointer to the subnet to be deleted
 *
 * Returns:     IPM_SUCCESS - rule info is deleted successfully
 *              IPM_FAILURE - some error occurred.
 *
 **********************************************************************/
int EIPM_clean_subnet_rule(EIPM_SUBNET *subnet_ptr)
{
	int retval;
	int n, i;
	struct sockaddr_nl nladdr;
	IPM_RULETBL rule_tbl;
	IPM_RTTBL route_tbl;

	retval = EIPM_read_rules(&rule_tbl);
	if (retval < 0)
	{
		LOG_FORCE(NMA_OROUTE, "EIPM_clean_subnet_rule: failed to read rule for clean.\n");
		return ( IPM_FAILURE);
	}

	for (n = 0; n < rule_tbl.rule_cnt; n++)
	{
		if ((IPM_IPCMPADDR(&subnet_ptr->subnet_base, &rule_tbl.rule_entry[n].srcip) == IPM_SUCCESS) &&
			(subnet_ptr->prefixlen == rule_tbl.rule_entry[n].prefix))
		{
			if (subnet_ptr->table_num == rule_tbl.rule_entry[n].table_num)
			{
				EIPM_read_rttable(&route_tbl, subnet_ptr->table_num);
				for (i = 0; i < route_tbl.route_cnt; i++)
				{
					ipm_route_mgr(EIPM_DEL, &route_tbl.route_table[i], subnet_ptr->table_num);
				}
			}
			// Delete any rule for this subnet
			ipm_rule_mgr(EIPM_DEL, &rule_tbl.rule_entry[n]);
		}
	}

	return IPM_SUCCESS;
}

/**********************************************************************
 *
 * Name:	EIPM_cmd_tunnel_update()
 *
 * Abstract:	Called when IPM receives a message with data for 
 *		a tunnel.
 *
 * Parameters:	msg_ptr - pointer to data message
 *		type    - whether adding or deleting tunnel 
 *		resp    - pointer to text string response to user
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/


int EIPM_cmd_tunnel_update( struct cmd_tunnel_upd *cmd_tunnel_ptr,
                      int type, 
                      char *resp )
{

	EIPM_DATA	*data_ptr;
	IPM_TUNNEL_DATA	*tunnel_ptr;
	IPM_IPADDR	leip;
	IPM_IPADDR	reip;
	char		tunnel_name[MAX_NLEN_DEV];
	int		retval = -1;


	/* Check for EIPM memory */
	if ( (NULL == cmd_tunnel_ptr) || (NULL == resp) )
	{
		LOG_FORCE(0, "EIPM_cmd_tunnel_update: cmd_tunnel_ptr(%p) or resp(%p) is NULL\n", 
			cmd_tunnel_ptr, resp);
		return IPM_FAILURE;
	}

	if ( (IPM_ADD_TUNNEL != type) && (IPM_DEL_TUNNEL != type) )
	{
		snprintf(resp, REPLY_TEXT, 
			"EIPM_cmd_tunnel_update: the type (%d) should be ADD_TUNNEL or DEL_TUNNEL\n", type);
		LOG_FORCE(0, resp);
		return IPM_FAILURE;
	}

	if (NULL == EIPM_shm_ptr)
	{
		snprintf(resp, REPLY_TEXT, 
			"EIPM_cmd_tunnel_update: EIPM Shared memory is null, the passed tunnel name %s\n", 
			cmd_tunnel_ptr->name[0] == 0 ? "NULL"	: cmd_tunnel_ptr->name);
		LOG_FORCE(0, resp);
		return IPM_FAILURE;
	}

	if ( (0 == cmd_tunnel_ptr->id) || (cmd_tunnel_ptr->id >= MAX_NUM_PIVOT) )
	{
		snprintf(resp, REPLY_TEXT,
			"EIPM_cmd_tunnel_update: invalid tunnel id (%d)\n", cmd_tunnel_ptr->id);
		LOG_FORCE(0, resp);
		return IPM_FAILURE;
	}

	if (cmd_tunnel_ptr->key != cmd_tunnel_ptr->id)
	{
		snprintf(resp, REPLY_TEXT,
			"EIPM_cmd_tunnel_update: The key(%d) must be the same as the id (%d)\n", cmd_tunnel_ptr->key, cmd_tunnel_ptr->id);
		LOG_FORCE(0, resp);
		return IPM_FAILURE;
	}

	if (0 == cmd_tunnel_ptr->ttl)
	{
		snprintf(resp, REPLY_TEXT,
			"EIPM_cmd_tunnel_update: The ttl should be greater than 0 \n");
		LOG_FORCE(0, resp);
		return IPM_FAILURE;
	}

	if (0 == cmd_tunnel_ptr->name[0])
	{
		snprintf(resp, REPLY_TEXT, "EIPM_cmd_tunnel_update: tunnel name is empty \n");
		LOG_FORCE(0, resp);
		return IPM_FAILURE;		
	}

	// Get the tunnel local endpoint IP
	IPM_ipaddr_init(&leip);
	retval = IPM_p2ipaddr(cmd_tunnel_ptr->lepip, &leip);
	if(retval != IPM_SUCCESS)
	{
		snprintf(resp, REPLY_TEXT,
			"EIPM_cmd_tunnel_update: invalid local endpoint address %s", cmd_tunnel_ptr->lepip);	
		LOG_FORCE(0, resp);
		return IPM_FAILURE;			
	}

	// Get the tunnel remote endpoint IP
	IPM_ipaddr_init(&reip);
	retval = IPM_p2ipaddr(cmd_tunnel_ptr->repip, &reip);
	if(retval != IPM_SUCCESS)
	{
		snprintf(resp, REPLY_TEXT,
			"EIPM_tunnel_update failure: invalid remote endpoint address %s", cmd_tunnel_ptr->repip);
		LOG_FORCE(0, resp);
		return IPM_FAILURE;			
	}	

	data_ptr = (EIPM_DATA *)EIPM_shm_ptr;
	tunnel_ptr = &(data_ptr->tunnel_data[cmd_tunnel_ptr->id]);
	if (0 == tunnel_ptr->id)
	{
		// There is no the related data in shared memory
		if (IPM_ADD_TUNNEL == type)
		{
			// Update shared memory
			bzero(tunnel_ptr, sizeof(IPM_TUNNEL_DATA));
			tunnel_ptr->id = cmd_tunnel_ptr->id;
			tunnel_ptr->ttl = cmd_tunnel_ptr->ttl;
			tunnel_ptr->mode = IPPROTO_GRE;
			tunnel_ptr->key = cmd_tunnel_ptr->key;
			strncpy(tunnel_ptr->name, cmd_tunnel_ptr->name, MAX_NLEN_DEV-1);
			tunnel_ptr->lepip = leip;
			tunnel_ptr->repip = reip;
			data_ptr->tunnel_cnt++;
			LOG_OTHER(0, "EIPM_tunnel_update:  tunnel_ptr->id=%d, data_ptr->tunnel_cnt=%d is added\n",
				tunnel_ptr->id, data_ptr->tunnel_cnt);
			/*
			 * Add this tunnel into system and ignore the return value
			 * Interface audit will add it again if it is failed 
			 */
			EIPM_add_gre_tunnel(tunnel_ptr->id,
				tunnel_ptr->ttl,
				tunnel_ptr->key,
				tunnel_ptr->mode,
				tunnel_ptr->lepip,
				tunnel_ptr->repip);
			EIPM_bring_interface_up(tunnel_ptr->name);
			return IPM_SUCCESS;
		}
		else
		{
			// Return success because it could trigger multiple deletion
			return IPM_SUCCESS;
		}
	}
	else if (tunnel_ptr->id == cmd_tunnel_ptr->id)	
	{
		// The related data is existed in shared memory
		if (IPM_ADD_TUNNEL == type)
		{
			/*
			 * Reset the value in shared memory 
			 * It will modify this tunnel once there is a paramter change
			 */
			tunnel_ptr->ttl = cmd_tunnel_ptr->ttl;
			tunnel_ptr->mode = IPPROTO_GRE;
			tunnel_ptr->key = cmd_tunnel_ptr->key;
			strncpy(tunnel_ptr->name, cmd_tunnel_ptr->name, MAX_NLEN_DEV-1);
			tunnel_ptr->lepip = leip;
			tunnel_ptr->repip = reip;

			// Call update function if there is parameter change
			if ( (tunnel_ptr->ttl != cmd_tunnel_ptr->ttl)
				|| (tunnel_ptr->key != cmd_tunnel_ptr->key)
				|| (tunnel_ptr->lepip.ipaddr[0] != leip.ipaddr[0])
				|| (tunnel_ptr->repip.ipaddr[0] != reip.ipaddr[0])
			   )
			{
				EIPM_update_gre_tunnel(tunnel_ptr->id,
					tunnel_ptr->ttl,
					tunnel_ptr->key,
					tunnel_ptr->mode,
					tunnel_ptr->lepip,
					tunnel_ptr->repip);
			}

			// Return success because it could trigger multiple adds
			return IPM_SUCCESS;
		}
		else 
		{
			/*
			 * Delete it from system. If it is failed, then it will be removed again when adding it
			 * Also, it doesn't hurt even if it is existed there
			 */
			EIPM_delete_gre_tunnel(tunnel_ptr->id);

			// Update this tunnel interface index in shared memory data
			EIPM_update_tunnel_intf_index(tunnel_ptr->id, IPM_DEL_TUNNEL);

			// reset shared memory data
			bzero(tunnel_ptr, sizeof(IPM_TUNNEL_DATA));
			if (data_ptr->tunnel_cnt > 0)
			{
				data_ptr->tunnel_cnt--;
			}

			LOG_OTHER(0, "EIPM_tunnel_update:  tunnel_ptr->id=%d, data_ptr->tunnel_cnt=%d is deleted\n",
				tunnel_ptr->id, data_ptr->tunnel_cnt);
			return IPM_SUCCESS;
		}
	}
	else 
	{
		// The wrong data
		snprintf(resp, REPLY_TEXT,
			"EIPM_tunnel_update failure: inconsistant tunnel id(%d) in shared memory and the passed id(%d)", 
			tunnel_ptr->id, cmd_tunnel_ptr->id);
		LOG_FORCE(0, resp);
		return IPM_FAILURE;			
	}

	return IPM_SUCCESS;
}
