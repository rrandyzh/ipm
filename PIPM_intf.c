/**********************************************************************
 *
 * File:
 *	PIPM_intf.c
 *
 * Functions in this file:
 *	PIPM_base_update()	- Called to provide base info.
 *      PIPM_extnIntfUpdate     - Add/delete an extension interface.
 *	PIPM_cmd_route_update()	- Called to update route info.
 *	PIPM_cmd_path_update() - Called to update path info.
 *
 **********************************************************************/

#include "PIPM_include.h"

/**********************************************************************
 *
 * Name:	PIPM_base_update()
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

int PIPM_base_update( struct cmd_base_iface *msg_ptr, int type, char *resp )
{
        if( PIPM_IS_ADD_TYPE( type ) )
	{
	        int 	i;
	        int 	retval;
		int	upd_shared_memory = 0;
		INTF_ACTION	intf_action;
		PIPM_DATA	*data_ptr;
		PIPM_INTF	*intf_ptr;
		struct ifreq	ifr;
		int		sock;
		int 		intf_idx;
		char		*iface0_base_ptr;
		char		iface0_base[MAX_NLEN_DEV];
		char		*iface1_base_ptr;
		char		iface1_base[MAX_NLEN_DEV];

		/*
		 * Add new interface if needed
		 */

		/* Check for PIPM memory */
		if( PIPM_shm_ptr == NULL )
		{
			snprintf(resp, REPLY_TEXT, 
				"PIPM Base Config Failure: Shared memory null, Iface %s - %s\n", 
				msg_ptr->base_if[0],
				msg_ptr->base_if[1]);

			LOG_ERROR(0, resp);

			return IPM_FAILURE;
		}

		data_ptr = (PIPM_DATA *)PIPM_shm_ptr;

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
			intf_action = PIPM_intf_match(
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
						PIPM_SUBNET	*bfd_subnet_ptr;
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

		if( data_ptr->intf_cnt == PIPM_MAX_INTF )
		{
			snprintf(resp, REPLY_TEXT,
				"PIPM Base Config Failure: Can't add Iface %s/%s, already at Max %d\n",
				( strlen( iface0_base_ptr ) > 0 ? iface0_base_ptr : "empty" ),
				( strlen( iface1_base_ptr ) > 0 ? iface1_base_ptr : "empty" ),
				PIPM_MAX_INTF
			);

			LOG_ERROR(0, resp);

			return IPM_TOOMUCHBIF;
		}

		if ( !upd_shared_memory )
		{
			/* Add new interface */
			intf_ptr = &data_ptr->intf_data[data_ptr->intf_cnt];

			memset(intf_ptr, 0, sizeof(*intf_ptr));
		}
		else
		{
			intf_ptr = &data_ptr->intf_data[intf_idx];
		}

		if( msg_ptr->subnet_type == IPM_SUBNET_INTERNAL )
		{
			intf_ptr->type = PIPM_INTERNAL_INTF;
		}
		else
		{
			intf_ptr->type = PIPM_EXTERNAL_INTF;
		}

		strcpy(intf_ptr->lsn0_baseif, iface0_base_ptr);
		strcpy(intf_ptr->lsn1_baseif, iface1_base_ptr);

		if ( !upd_shared_memory )
		{
			intf_ptr->specData.lsn0_arpsock   = -1;
			intf_ptr->specData.lsn1_arpsock   = -1;
			intf_ptr->specData.lsn0_v6arpsock = -1;
			intf_ptr->specData.lsn1_v6arpsock = -1;
		intf_ptr->specData.baseIntfIdx = data_ptr->intf_cnt;
		}
		intf_ptr->startExtnIntfIdx = -1;

		/* Querying interface information.  */
		sock = socket(PF_INET, SOCK_RAW, htons(ETH_P_IP));

		if( sock < 0 )
		{
			snprintf(resp, REPLY_TEXT, 
				"PIPM Base Config Failure: Failed to open raw socket for interface=%s, errno %d",
				intf_ptr->lsn0_baseif, errno );

			LOG_ERROR(0, resp);
		
			memset(intf_ptr, 0, sizeof(*intf_ptr));
		
			return IPM_FAILURE;
		}
	
		if( strlen(intf_ptr->lsn0_baseif) > 0 )
		{
			if ( !upd_shared_memory )
			{
				/*
				 * Get interface index for LSN0 interface.  Use the
				 * base interface name (all aliases have the same
				 * interface index).
				 */
				memset(&ifr, 0, sizeof(ifr));

				ifr.ifr_addr.sa_family = PF_INET;
				strcpy(ifr.ifr_name, intf_ptr->lsn0_baseif);

				retval = ioctl(sock, SIOCGIFINDEX, &ifr);

				if( retval < 0 )
				{
					snprintf(resp, REPLY_TEXT, 
						"PIPM Base Config Failure: (SIOCGIFINDEX) failed for interface=%s, retval %d, errno %d",
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
						"PIPM Base Config Failure: ioctl(SIOCGIFHWADDR) failed for interface=%s, retval %d, errno %d",
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
			} /* !upd_shared_memory */

		}

		if( strlen(intf_ptr->lsn1_baseif) > 0 )
		{
			/*
			 * Get interface index for LSN1 interface.  Use the
			 * base interface name (all aliases have the same
			 * interface index).
			 */
			memset(&ifr, 0, sizeof(ifr));
			ifr.ifr_addr.sa_family = PF_INET;
			strcpy(ifr.ifr_name, intf_ptr->lsn1_baseif);

			retval = ioctl(sock, SIOCGIFINDEX, &ifr);

			if( retval < 0 )
			{
				snprintf(resp, REPLY_TEXT, 
					"PIPM Base Config Failure: ioctl(SIOCGIFINDEX) failed for interface=%s, retval %d, errno %d",
					intf_ptr->lsn1_baseif, retval, errno);

				LOG_ERROR(0, resp);
		
				/*
				 * Need to clean up this entry since we
				 * are abandoning it.
				 */
				memset(intf_ptr, 0, sizeof(*intf_ptr));

				(void)close(sock);

				return IPM_FAILURE;
			}

			intf_ptr->specData.lsn1_iface_indx = ifr.ifr_ifindex;
	
			/* Get MAC address */
			retval = ioctl(sock, SIOCGIFHWADDR, &ifr);

			if( retval < 0 )
			{
				snprintf(resp, REPLY_TEXT, 
					"PIPM Base Config Failure: ioctl(SIOCGIFHWADDR) failed for interface=%s, retval %d, errno %d",
					intf_ptr->lsn1_baseif, retval, errno );
	
				LOG_ERROR(0, resp);
		
				/*
				 * Need to clean up this entry since we
				 * are abandoning it.
				 */
				memset(intf_ptr, 0, sizeof(*intf_ptr));

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
		}

		return IPM_SUCCESS;
	}
	else /* PIPM_DEL */
	{
		/* 
		 * Look through interface data,
		 * clean up, delete if match found.
		 */
		register PIPM_DATA      *shm_ptr;
		register PIPM_INTF	*interface_ptr;
		register PIPM_INTF	*cur_ptr;
		register PIPM_INTF	*next_ptr;
		register PIPM_SUBNET	*subnet_ptr;
		PIPM_INTF_SPEC          *intfSpecDataP;
		int			interface_idx;
		int			delete_idx;
		int			subnet_idx;
		int                     extnIntfIdx;
                int                     retval;

		/*
		 * Make sure we are attached to shared memory segment.
		 */
		if( PIPM_shm_ptr == NULL )
		{
			ASRT_RPT( ASMISSING_DATA,
			          2,
			          sizeof( PIPM_shm_ptr ),
				  &PIPM_shm_ptr,
				  sizeof( PIPM_shmid ),
				  &PIPM_shmid,
			          "PIPM_base_update(): PIPM not attached to shared memory segment\n" );
		
			return( IPM_FAILURE );
		}

		shm_ptr = (PIPM_DATA *)PIPM_shm_ptr;

		/*
		 * Loop through shared segment.
		 */
		for( interface_idx = 0, interface_ptr = &shm_ptr->intf_data[0];
		     interface_idx < shm_ptr->intf_cnt;
		     interface_idx++, interface_ptr++ )
		{
			/* if interface still has subnets continue */
			if ( interface_ptr->subnet_cnt > 0 )
			{
				continue;
			}

			if ( interface_ptr->lsn0_baseif[0] != 0 && interface_ptr->lsn1_baseif[0] != 0 )
			{
				if ( msg_ptr->base_if[0][0] != 0 && msg_ptr->base_if[1][0] != 0 )
				{
					if ( strcmp(msg_ptr->base_if[0], interface_ptr->lsn0_baseif) != 0 &&
			    			strcmp(msg_ptr->base_if[1], interface_ptr->lsn1_baseif) != 0 )
					{
						/* interface doesn't match */
						continue;
					}
				}
				else if ( msg_ptr->base_if[0][0] != 0 )
				{
					/* continue b/c have the bfd subnet if deleting transport */
					continue;
				}
				else
				{
					continue;
				}
			}
			else if ( interface_ptr->lsn0_baseif[0] != 0 && msg_ptr->base_if[0][0] != 0 )
			{
				if ( strcmp( interface_ptr->lsn0_baseif, msg_ptr->base_if[0] ) != 0 )
				{
					continue;
				}
			}
			else if ( interface_ptr->lsn1_baseif[0] != 0 && msg_ptr->base_if[1][0] != 0 )
			{
				if ( msg_ptr->base_if[0][0] != 0 && msg_ptr->base_if[1][0] != 0 )
				{
					continue;
				}

				if ( strcmp( interface_ptr->lsn1_baseif, msg_ptr->base_if[1] ) != 0 )
				{
					continue;
				}
			}

			/* Remove corresponding extension interfaces as well. */
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

                                        retval = PIPM_extnIntfUpdate( &intfUpdateCmd, type, 
                                                                      resp, interface_idx, extnIntfIdx );

					if ( IPM_SUCCESS == retval )
                                        {
						/* Don't increment the loop index as the count has reduced. */
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
			 * Close all interface sockets.
			 */
			if ( interface_ptr->specData.lsn1_arpsock >= 0 )
			{
				(void)close( interface_ptr->specData.lsn1_arpsock );
				interface_ptr->specData.lsn1_arpsock = -1;
			}

			if ( interface_ptr->specData.lsn0_arpsock >= 0 )
			{
				(void)close( interface_ptr->specData.lsn0_arpsock );
				interface_ptr->specData.lsn0_arpsock = -1;
			}

			if ( interface_ptr->specData.lsn1_v6arpsock >= 0 )
			{
				(void)close( interface_ptr->specData.lsn1_v6arpsock );
				interface_ptr->specData.lsn1_v6arpsock = -1;
			}

			if ( interface_ptr->specData.lsn0_v6arpsock >= 0 )
			{
				(void)close( interface_ptr->specData.lsn0_v6arpsock );
				interface_ptr->specData.lsn0_v6arpsock = -1;
			}

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
			        sizeof(*cur_ptr) );
			cur_ptr->startExtnIntfIdx = -1;
		}
	}

	return( IPM_SUCCESS );

} /* end PIPM_base_update() */

int PIPM_extnIntfUpdate( struct cmd_base_iface *cmdP,
                         int opType,
                         char *respStr,
                         int baseIntfIdx,
			 int inExtnIntfIdx )
{

        PIPM_DATA	*dataP;
	char		lsn0Base[MAX_NLEN_DEV];
	char		lsn1Base[MAX_NLEN_DEV];
        unsigned short  vlanId;
        PIPM_INTF_SPEC  *intfSpecDataP;
        int             extnIntfIdx;
        char            *vlanSepP;

        if ( !PIPM_IS_VALID_BASE_INTF_IDX( baseIntfIdx ) )
        {
                snprintf( respStr, REPLY_TEXT, 
			  "PIPM Extn Intf Add/Del Failure - %s/%s Invalid Base interface index: %d.\n", 
			  cmdP->base_if[0], cmdP->base_if[1], baseIntfIdx );
                LOG_ERROR( 0, respStr );

                return IPM_FAILURE;
        }

        dataP = (PIPM_DATA *)PIPM_shm_ptr;
        
	memset(lsn0Base, 0, sizeof (lsn0Base));
	memset(lsn1Base, 0, sizeof (lsn1Base));

	/* Get the VLAN. */
	if (strlen(cmdP->base_if[0]) > 0)
	{
		strncpy(lsn0Base, cmdP->base_if[0], (MAX_NLEN_DEV - 1));
		vlanSepP = strrchr(lsn0Base, '.');
		if (vlanSepP != NULL)
		{
			*vlanSepP = '\0';
		}
	}

	if (strlen(cmdP->base_if[1]) > 0)
	{
		strncpy(lsn1Base, cmdP->base_if[1], (MAX_NLEN_DEV - 1));
		vlanSepP = strrchr(lsn1Base, '.');
		if(vlanSepP != NULL)
		{
			*vlanSepP = '\0';
		}
	}

	vlanId = cmdP->vlanId;

        if ( PIPM_IS_ADD_TYPE( opType ) )
        {

                PIPM_INTF       *intfDataP;
                int             retVal;
                struct ifreq	ifReq;
		int		sockDesc;

                /* -- Ensure that there's space to add the new extn interface. -- */
                if ( PIPM_MAX_EXTN_INTF == dataP->extnIntfCount )
                {
                        snprintf( respStr, REPLY_TEXT,
				  "PIPM Extn Intf Add Failure - %s/%s - Max (%u) extn interfaces already added.\n", 
				  cmdP->base_if[0],
                                  cmdP->base_if[1],
                                  PIPM_MAX_EXTN_INTF );

			LOG_ERROR( 0, respStr );

			return IPM_TOOMUCHBIF;
                }



                /* -- Add the new extn interface -- */
                intfDataP = &(dataP->intf_data[baseIntfIdx]);
                intfSpecDataP = &(dataP->extnIntfData[dataP->extnIntfCount]);


                memset( intfSpecDataP, 0, sizeof( *intfSpecDataP ) );
		intfSpecDataP->lsn0_arpsock   = -1;
		intfSpecDataP->lsn1_arpsock   = -1;
		intfSpecDataP->lsn0_v6arpsock = -1;
		intfSpecDataP->lsn1_v6arpsock = -1;
                intfSpecDataP->baseIntfIdx    = baseIntfIdx;
                intfSpecDataP->vlanId         = vlanId;

                /* Create raw socket to query the interface information. */
		sockDesc = socket( PF_INET, SOCK_RAW, htons( ETH_P_IP ) );

		if ( sockDesc < 0 )
		{
			snprintf( respStr, REPLY_TEXT, 
				  "PIPM Extn Intf Add Failure - Failed to create raw socket for %s/%s - errno: %d\n", 
				  cmdP->base_if[0], 
                                  cmdP->base_if[1], 
                                  errno );

			LOG_ERROR( 0, respStr );
		
                        /* Cleanup */
			memset( intfSpecDataP, 0, sizeof( *intfSpecDataP ) );
		
			return IPM_FAILURE;
		}

                if ( strlen( intfDataP->lsn0_baseif ) > 0 )
                {
                        
                        memset( &ifReq, 0, sizeof( ifReq ) );

		        ifReq.ifr_addr.sa_family = PF_INET;
                        snprintf( ifReq.ifr_name, sizeof( ifReq.ifr_name ), "%s%s", 
                                  intfDataP->lsn0_baseif, ipm_getVLANStr( vlanId, TRUE ) );

		        retVal = ioctl( sockDesc, SIOCGIFINDEX, &ifReq );

		        if ( retVal < 0 )
		        {
			        snprintf( respStr, REPLY_TEXT, 
				          "PIPM Extn Intf Add Failure - ioctl-SIOCGIFINDEX failed for %s - retVal: %d errno: %d\n", 
                                          ifReq.ifr_name, retVal, errno );

			        LOG_ERROR( 0, respStr );
		
                                /* Cleanup */
			        memset( intfSpecDataP, 0, sizeof( *intfSpecDataP ) );
			        (void)close( sockDesc );

			        return IPM_FAILURE;
		        }

		        intfSpecDataP->lsn0_iface_indx = ifReq.ifr_ifindex;

                } /* end 'query LSN0 interface info'. */

                if ( strlen( intfDataP->lsn1_baseif ) > 0 )
                {
                        
                        memset( &ifReq, 0, sizeof( ifReq ) );

		        ifReq.ifr_addr.sa_family = PF_INET;
                        snprintf( ifReq.ifr_name, sizeof( ifReq.ifr_name ), "%s%s", 
                                  intfDataP->lsn1_baseif, ipm_getVLANStr( vlanId, TRUE ) );

		        retVal = ioctl( sockDesc, SIOCGIFINDEX, &ifReq );

		        if ( retVal < 0 )
		        {
			        snprintf( respStr, REPLY_TEXT, 
				          "PIPM Extn Intf Add Failure - ioctl-SIOCGIFINDEX failed for %s - retVal: %d errno: %d\n", 
                                          ifReq.ifr_name, retVal, errno );

			        LOG_ERROR( 0, respStr );
		
                                /* Cleanup */
			        memset( intfSpecDataP, 0, sizeof( *intfSpecDataP ) );
			        (void)close( sockDesc );

			        return IPM_FAILURE;
		        }

		        intfSpecDataP->lsn1_iface_indx = ifReq.ifr_ifindex;

                } /* end 'query LSN1 interface info'. */

		/* Done with the socket. Close it. */
        	close( sockDesc );

		intfDataP->startExtnIntfIdx = 0;
                dataP->extnIntfCount++;

		return IPM_SUCCESS;

        } /* end 'add extn interface' */
        else
        {

                PIPM_INTF_SPEC  *currP;
                PIPM_INTF_SPEC  *nextP;
                int             delIdx;
		int             extnIntfIdx;

                if (    ( inExtnIntfIdx != -1 ) 
                     && ( inExtnIntfIdx < dataP->extnIntfCount ) )
                {
                        extnIntfIdx = inExtnIntfIdx;
                        intfSpecDataP = &(dataP->extnIntfData[extnIntfIdx]);
                }
                else
                {
                        extnIntfIdx = 0;
                        intfSpecDataP = &(dataP->extnIntfData[0]);
                }

		for ( ;
                      ( extnIntfIdx < dataP->extnIntfCount );
                      ( extnIntfIdx++, intfSpecDataP++ ) )
                {
			if ( !PIPM_IS_VALID_BASE_INTF_IDX( intfSpecDataP->baseIntfIdx ) )
                        {
                                ASRT_RPT( ASBAD_DATA, 0, "extnIntfIdx: %d Invalid base interface index %d (count: %d).\n",
                                          extnIntfIdx, intfSpecDataP->baseIntfIdx, dataP->extnIntfCount );

                                continue;
                        }

                        if (    ( intfSpecDataP->vlanId != vlanId ) 
                             || ( strcmp( lsn0Base, (dataP->intf_data[intfSpecDataP->baseIntfIdx]).lsn0_baseif ) != 0 ) 
                             || ( strcmp( lsn1Base, (dataP->intf_data[intfSpecDataP->baseIntfIdx]).lsn1_baseif ) != 0 ) )
                        {
                                continue;
                        }

                        /* Close the interface sockets. */
                        if ( intfSpecDataP->lsn1_arpsock >= 0 )
			{
				(void)close( intfSpecDataP->lsn1_arpsock );
				intfSpecDataP->lsn1_arpsock = -1;
			}

			if ( intfSpecDataP->lsn0_arpsock >= 0 )
			{
				(void)close( intfSpecDataP->lsn0_arpsock );
				intfSpecDataP->lsn0_arpsock = -1;
			}

			if ( intfSpecDataP->lsn1_v6arpsock >= 0 )
			{
				(void)close( intfSpecDataP->lsn1_v6arpsock );
				intfSpecDataP->lsn1_v6arpsock = -1;
			}

			if ( intfSpecDataP->lsn0_v6arpsock >= 0 )
			{
				(void)close( intfSpecDataP->lsn0_v6arpsock );
				intfSpecDataP->lsn0_v6arpsock = -1;
			}

			dataP->extnIntfCount--;

                        /* Collapse entries in the table -- will need to change the logic below to make this more efficient. */
			for ( ( delIdx = extnIntfIdx, currP = intfSpecDataP, nextP = &(dataP->extnIntfData[( extnIntfIdx + 1 )]) );
			      ( delIdx < dataP->extnIntfCount );
			      ( delIdx++, currP++, nextP++ ) )
			{
				/*
				 *  If we get here there is another entry in  the table.  
                                 *  Move it to this location.
				 */
				*currP = *nextP;
			}

                        /*
			 *  We have copied all of the the valid interfaces down.
			 *  'currP' should be pointing to the last entry in the
			 *  list (it was incremented once after the last copy
			 *  was done, or if there was only 1 entry it never
			 *  moved) which is now invalid.
			 */
			memset( currP, 0, sizeof( *currP ) );

                        break;
                } /* 'extn interfaces' loop */

        } /* end 'delete extn interface' */

        return IPM_SUCCESS;

} /* end PIPM_extnIntfUpdate() */


/**********************************************************************
 *
 * Name:        PIPM_cmd_path_update()
 *
 * Abstract:    Called when IPM receives a message with path server data
 *
 * Description:    
 *              1) Proxy Server:
 *                 This involves 
 *                 a) setting up as necessary two interface structures for one for the 
 *                 internal facing interfaces and one for external facing interfaces.
 *
 *              2) Proxy Client Address:
 *                 Update the client address in the appropriate internal facing
 *		   interface structure.
 *
 *              3) Proxy Client:
 *		   Next phase.
 *
 * Parameters:  msg_ptr - pointer to data message
 *              type    - whether adding or deleting proxy/path data
 *              resp    - pointer to text string response to user
 *
 * Returns:     IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int PIPM_cmd_path_update( void *cmd_ptr, int type, char *resp )
{
PIPM_DATA	*data_ptr;
PIPM_INTF	*intf_ptr;
PIPM_INTF	*tmp_intf_ptr;
PIPM_INTF_SPEC  *intfSpecDataP;
PIPM_SUBNET	*subnet_ptr;
PIPM_SUBNET	*bfd_subnet_ptr;
PIPM_INTF	*bfd_intf_ptr;
PIPM_PATH   	*path_ptr;
PIPM_PATH   	*cur_path_ptr;
IPM_IPADDR	ip;
IPM_IPADDR	subnet_mask;
IPM_IPADDR	subnet_base;
IPM_IPADDR	gateway_ip;
struct cmd_proxy_server	cmd_path;
struct cmd_proxy_server	*cmd_path_ptr;
int 		intf_idx;
int 		tmp_intf_idx;
int 		subnet_idx;
int 		path_idx;
int 		arp_resp_ip_idx;
int		ret;
IPM_RETVAL 	ipm_retval;
char		*iface0_base_ptr;
char		iface0_base[MAX_NLEN_DEV];
char		*iface1_base_ptr;
char		iface1_base[MAX_NLEN_DEV];
int 		matching_intf_idx = -1;
int 		matching_subnet_idx = -1;
int 		matching_path_idx = -1;
int 		matching_arp_resp_ip_idx = -1;
int		num_intf;
int		i;
int		intf_type;
int		bfd_subnet_idx;
int		path_found=0;
BOOL 		bContIntfScan = TRUE;
unsigned short  vlanId = 0;
int		baseIntfIdx;
PIPM_INTF_TYPE_EXT intfTypeExt;
unsigned char   inner_vlan;
IPM_IPADDR      intFloatIp;

    /* Check for PIPM memory */
    if( PIPM_shm_ptr == NULL )
    {
        snprintf(resp, REPLY_TEXT, 
                 "PIPM Path Update Config Failure: Shared memory null\n" );

        LOG_ERROR(0, resp);

        return IPM_FAILURE;
    }

    IPM_ipaddr_init(&gateway_ip);

    cmd_path_ptr = &cmd_path;

    switch( type )
    {
    case IPM_ADD_PROXY_SERVER:
    case IPM_DEL_PROXY_SERVER:
	memcpy(&cmd_path, cmd_ptr, sizeof(cmd_path));

	/* Note interface type will be set later */

	break;

    case IPM_ADD_PROXY_CLIENT_ADDR:
    case IPM_DEL_PROXY_CLIENT_ADDR:
	memcpy(&cmd_path, cmd_ptr, sizeof(cmd_path));
        intf_type = IPM_SUBNET_INTERNAL;
	break;

    case IPM_ADD_PATH:
    case IPM_DEL_PATH:
    {
	struct cmd_proxy_path	*cmd_proxy_path_ptr;

	memset( &cmd_path,
		        0,
		        sizeof(cmd_path) );

	cmd_proxy_path_ptr = (struct cmd_proxy_path *)cmd_ptr;

	cmd_path.prefix = cmd_proxy_path_ptr->prefix;
	memcpy( &cmd_path.ip, &cmd_proxy_path_ptr->ip, sizeof(cmd_path.ip));
	strncpy( &cmd_path.be_iface[0][0], &cmd_proxy_path_ptr->iface[0][0], MAX_NLEN_DEV);
	strncpy( &cmd_path.be_iface[1][0], &cmd_proxy_path_ptr->iface[1][0], MAX_NLEN_DEV);

        intf_type = IPM_SUBNET_INTERNAL;
    }
	break;

    case IPM_ADD_EXT_ALIAS:
    case IPM_ADD_INT_ALIAS:
    case IPM_DEL_EXT_ALIAS:
    case IPM_DEL_INT_ALIAS:
    {
	struct cmd_alias_ip	*cmd_alias_ip_ptr;

	memset( &cmd_path,
		        0,
		        sizeof(cmd_path) );

	cmd_alias_ip_ptr = (struct cmd_alias_ip *)cmd_ptr;

	strncpy( &cmd_path.be_iface[0][0], cmd_alias_ip_ptr->alias_t[0].alias_if, MAX_NLEN_DEV);
	strncpy( &cmd_path.be_iface[1][0], cmd_alias_ip_ptr->alias_t[1].alias_if, MAX_NLEN_DEV);

	if( strlen(&cmd_path.be_iface[0][0]) > 0 )
	{
	    cmd_path.prefix = cmd_alias_ip_ptr->alias_t[0].prefix;
	    memcpy( &cmd_path.ip, &cmd_alias_ip_ptr->alias_t[0].ip, sizeof(cmd_path.ip));
	    intf_type = cmd_alias_ip_ptr->alias_t[0].subnet_type;
	}
	else
	{
	    cmd_path.prefix = cmd_alias_ip_ptr->alias_t[1].prefix;
	    memcpy( &cmd_path.ip, &cmd_alias_ip_ptr->alias_t[1].ip, sizeof(cmd_path.ip));
	    intf_type = cmd_alias_ip_ptr->alias_t[1].subnet_type;
	}

        if( strlen(cmd_alias_ip_ptr->gateway) > 0 )
        {
            ipm_retval = IPM_p2ipaddr(cmd_alias_ip_ptr->gateway, &gateway_ip);

            if( ipm_retval != IPM_SUCCESS )
            {
                snprintf(resp, REPLY_TEXT, 
                         "PIPM Path Config Failure: Failed %d to translate Gateway IP %s\n", 
                          ipm_retval, cmd_alias_ip_ptr->gateway);

                LOG_ERROR(0, resp);

                return ipm_retval;
            }
        }
    }
	break;

    default:
        snprintf(resp, REPLY_TEXT, 
                 "PIPM Config Failure: Invalid command type %d\n", 
		  type);

        LOG_ERROR(0, resp);

        return IPM_FAILURE;
	break;
    }

    data_ptr = (PIPM_DATA *)PIPM_shm_ptr;

    /* Convert IP */
    IPM_ipaddr_init(&ip);
	
    ipm_retval = IPM_p2ipaddr(cmd_path_ptr->ip, &ip);

    if( ipm_retval != IPM_SUCCESS )
    {
        snprintf(resp, REPLY_TEXT, 
                 "PIPM Path Config Failure: Failed %d to translate IP %s\n", 
		  ipm_retval, cmd_path_ptr->ip);

        LOG_ERROR(0, resp);

        return ipm_retval;
    }

    if (strlen(cmd_path_ptr->intFloatIp))
    {
        ipm_retval = IPM_p2ipaddr(cmd_path_ptr->intFloatIp, &intFloatIp);

        if( ipm_retval != IPM_SUCCESS )
        {
            snprintf(resp, REPLY_TEXT,
                    "PIPM Path Config Failure: Failed %d to translate IP %s\n",
                    ipm_retval, cmd_path_ptr->intFloatIp);
            LOG_ERROR(0, resp);
            return ipm_retval;
        }
    }
    else
    {
        IPM_ipaddr_init(&intFloatIp);
    }
    IPM_ipaddr_init(&subnet_mask);

    ipm_retval = IPM_ipmkmask(&subnet_mask, ip.addrtype, cmd_path_ptr->prefix);

    if( ipm_retval != IPM_SUCCESS )
    {
        snprintf(resp, REPLY_TEXT, 
                 "PIPM Path Config Failure: Failed %d to create Mask for %s/%d\n",
                  ipm_retval, cmd_path_ptr->ip, cmd_path_ptr->prefix);

        LOG_ERROR(0, resp);

        return ipm_retval;
    }

    IPM_ipaddr_init(&subnet_base);

    IPM_get_subnet(&ip, &subnet_mask, &subnet_base);

    if (((IPM_ADD_PROXY_SERVER == type)
            || (IPM_DEL_PROXY_SERVER == type))
            || (((IPM_ADD_PROXY_CLIENT_ADDR == type)
            || (IPM_DEL_PROXY_CLIENT_ADDR == type))
            && (vlanId != 0)))
    {
	num_intf = 2;	
    }
    else 
    {
	num_intf = 1;	
    }

    /* Initialize Look for matching interface */
    for( i = 0; i < num_intf; i++ )
    {
	bContIntfScan = FALSE;
	inner_vlan = 0;

	if( i == 0 )
	{
	    
	    if( type == IPM_ADD_PROXY_SERVER ||
	        type == IPM_DEL_PROXY_SERVER )
	    {
	        intf_type = IPM_SUBNET_INTERNAL;
	    }

	    inner_vlan = cmd_path_ptr->pivot_id;
            if (inner_vlan >= MAX_NUM_PIVOT)
            {
                snprintf(resp, REPLY_TEXT,
                        "PIPM_cmd_path_update: inner vlan %d is out of range\n", inner_vlan);
                LOG_ERROR(0, resp);
                return IPM_FAILURE;
            }

	    /* Derive base iface */
	    strncpy(iface0_base, cmd_path_ptr->be_iface[0], MAX_NLEN_DEV);
	    iface0_base_ptr = strtok(iface0_base, ":");

	    if( iface0_base_ptr == NULL )
	    {
	        iface0_base_ptr = iface0_base;
	    }

	    strncpy(iface1_base, cmd_path_ptr->be_iface[1], MAX_NLEN_DEV);
	    iface1_base_ptr = strtok(iface1_base, ":");

	    if( iface1_base_ptr == NULL )
	    {
	        iface1_base_ptr = iface1_base;
	    }
	}
	else
	{
	    char *vlanSepP;

	    if( type == IPM_ADD_PROXY_SERVER ||
	        type == IPM_DEL_PROXY_SERVER )
	    {
	        intf_type = IPM_SUBNET_EXTERNAL;
	    }

	    /* Derive base iface */
	    strncpy(iface0_base, cmd_path_ptr->fe_iface[0], MAX_NLEN_DEV);
	    iface0_base_ptr = strtok(iface0_base, ":");

	    if( iface0_base_ptr == NULL )
	    {
	        iface0_base_ptr = iface0_base;
	    }

	    strncpy(iface1_base, cmd_path_ptr->fe_iface[1], MAX_NLEN_DEV);
	    iface1_base_ptr = strtok(iface1_base, ":");

	    if( iface1_base_ptr == NULL )
	    {
	        iface1_base_ptr = iface1_base;
	    }

	    /* Also, determine the VLAN Id if it exists. */
	    if ((IPM_SUBNET_EXTERNAL == intf_type)
	            || ((IPM_ADD_PROXY_CLIENT_ADDR == type)
	            || (IPM_DEL_PROXY_CLIENT_ADDR == type)))
	    {
	        vlanId = cmd_path_ptr->vlanId;
	    }

	}

        /* Search through existing data looking for a subnet match:
         * If match is found:
         * - If action is delete -> delete IP entry, collapse IP table
         *                          If no IPs in subnet, delete subnet entry
         *                          If no subnets on interface, delete interface entry
         * - If action is add -> add/update IP entry
         * If match is not found:
         * - add interface, subnet, path entry
         */
	
	matching_intf_idx = -1;
	
        /* Look for matching interface */
        for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
             intf_idx < data_ptr->intf_cnt;
             intf_idx++, intf_ptr++ )
        {
	    tmp_intf_idx = PIPM_findIntf( iface0_base_ptr, iface1_base_ptr,
                                      &tmp_intf_ptr, &intfSpecDataP,
                                      &intfTypeExt, &baseIntfIdx );

	    if ( (tmp_intf_ptr == NULL)
		  && ((baseIntfIdx == -1) ||
			type == IPM_ADD_EXT_ALIAS ||
			type == IPM_DEL_EXT_ALIAS )
		 )
	    {
		// NO base and extention inferface are found in PIPM data
		intfTypeExt = PIPM_BASE_INTF;
	        baseIntfIdx = intf_idx;
		tmp_intf_idx = intf_idx;

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
	    }
	    else if ( (baseIntfIdx != -1)
			&& (IPM_ADD_PROXY_SERVER == type)
			&& (intfTypeExt == PIPM_INVALID_INTF)
			&& (intfSpecDataP == NULL)
		     )
	   {
		// Found base interface and add extension interface
		struct cmd_base_iface intfUpdateCmd;
		memset( &intfUpdateCmd, 0, sizeof( intfUpdateCmd ) );
		intfUpdateCmd.subnet_type = IPM_SUBNET_EXTERNAL;
		strncpy( intfUpdateCmd.base_if[0], iface0_base_ptr, ( MAX_NLEN_DEV - 1 ) );
		strncpy( intfUpdateCmd.base_if[1], iface1_base_ptr, ( MAX_NLEN_DEV - 1 ) );
		intfUpdateCmd.vlanId = vlanId;
		ret = PIPM_extnIntfUpdate( &intfUpdateCmd, type, resp, baseIntfIdx, -1 );
		if ( ret != IPM_SUCCESS )
		{
			return ret;
		}

		// set data
		tmp_intf_idx = PIPM_findIntf( iface0_base_ptr, iface1_base_ptr,&tmp_intf_ptr,
				&intfSpecDataP,&intfTypeExt, &baseIntfIdx );
		if( (tmp_intf_idx == -1) || (tmp_intf_ptr == NULL) )
		{
			LOG_ERROR( 0, "(%s) Failed to find interface, tmp_intf_idx (%d), tmp_intf_ptr(%p)\n", (char *)(__func__), tmp_intf_idx, tmp_intf_ptr);
			return (IPM_FAILURE);
		}
		intf_ptr = tmp_intf_ptr;
	    }
	    else if ( (baseIntfIdx != -1)
			&& ( (IPM_DEL_PROXY_SERVER == type)
				|| (IPM_DEL_PROXY_CLIENT_ADDR == type)
		            )
			&& (intfTypeExt == PIPM_INVALID_INTF)
			&& (intfSpecDataP == NULL)
		    )
	    {
		// PIPM data and path data have been deleted in first loop
		continue;
	    }
	    else
	    {
		if ( tmp_intf_ptr == NULL )
		{
			LOG_ERROR( 0, "(%s) NULL tmp_intf_ptr pointer\n", (char *)(__func__));
			return (IPM_FAILURE);
		}
		intf_ptr = tmp_intf_ptr;

	    }

	    matching_intf_idx = baseIntfIdx;


	    matching_subnet_idx = -1;
			    		
            for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
                 subnet_idx < intf_ptr->subnet_cnt;
                 subnet_idx++, subnet_ptr++ )
            {
						
                if( IPM_IPCMPADDR(&subnet_ptr->subnet_base, &subnet_base) == IPM_SUCCESS )
                {
                    matching_subnet_idx = subnet_idx;

                    if( PIPM_IS_ADD_TYPE( type ) && 
			PIPM_IS_LOCAL_IP_TYPE( type ) )
    		    {
			matching_arp_resp_ip_idx = -1;

			for( arp_resp_ip_idx = 0;
			     arp_resp_ip_idx < subnet_ptr->arp_resp_ip_cnt;
			     arp_resp_ip_idx++ )
			{
			    if( IPM_IPCMPADDR(&subnet_ptr->arp_resp_ip[arp_resp_ip_idx], &ip) == IPM_SUCCESS )
			    {
				matching_arp_resp_ip_idx = arp_resp_ip_idx;
			    }

			}
			if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
			{
				if ( strlen( iface0_base_ptr ) > 0 &&
					strlen( iface1_base_ptr ) > 0 )
				{
					snprintf(
						resp, REPLY_TEXT, "%s(): specified two interfaces %s - %s when need one for redundancy mode [%d]\n",
						__FUNCTION__,
						( strlen( iface0_base_ptr ) > 0 ? iface0_base_ptr : "empty" ),
						( strlen( iface1_base_ptr ) > 0 ? iface1_base_ptr : "empty" ),
						subnet_ptr->redundancy_mode
					);

					LOG_ERROR(0, resp);

					return IPM_FAILURE;
				}
			}
			else if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD || 
                                  (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR )
			{
				if ( (strlen( iface0_base_ptr ) > 0 &&
					strlen( iface1_base_ptr ) == 0) ||
					(strlen( iface0_base_ptr ) > 0 &&
					strlen( iface1_base_ptr ) == 0) )
				{
					snprintf(
						resp, REPLY_TEXT, "%s(): specified single interface %s - %s when need two for redundancy mode [%d]\n",
						__FUNCTION__,
						( strlen( iface0_base_ptr ) > 0 ? iface0_base_ptr : "empty" ),
						( strlen( iface1_base_ptr ) > 0 ? iface1_base_ptr : "empty" ),
						subnet_ptr->redundancy_mode
					);
					LOG_ERROR(0, resp);
					return IPM_FAILURE;
				}
			}
			if( matching_arp_resp_ip_idx == -1 )
			{
			    if( subnet_ptr->arp_resp_ip_cnt < PIPM_ARP_RESP_IP_CNT_MAX )
			    {
				if ( subnet_ptr->arp_resp_ip_cnt == 0 &&
					(IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
				{
					path_ptr = &subnet_ptr->path[0];

					memset(path_ptr, 0, sizeof(*path_ptr));

					path_ptr->type		= PIPM_GATEWAY_PATH;
					path_ptr->dest		= subnet_ptr->subnet_base;
					path_ptr->destprefix	= subnet_ptr->prefixlen;
					path_ptr->nexthop	= subnet_ptr->gateway;

					subnet_ptr->path_cnt	= 1;

					if ( strlen( iface0_base_ptr ) > 0 )
					{
						for ( bfd_subnet_idx = 0, bfd_subnet_ptr = &intf_ptr->subnet[0];
                        				bfd_subnet_idx < intf_ptr->subnet_cnt;
                        				bfd_subnet_idx++, bfd_subnet_ptr++ )
						{
							if (( (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD || 
                                                              (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR ) &&
								subnet_ptr->subnet_base.addrtype == bfd_subnet_ptr->subnet_base.addrtype )
							{
								bfd_subnet_ptr->gateway = subnet_ptr->gateway;
								(void) PIPM_update_subnet_ip( bfd_subnet_ptr, intf_ptr );
							}
						}
					}
					else if ( strlen( iface1_base_ptr ) > 0 )
					{
						ret = PIPM_find_prim_bfd( subnet_ptr, intf_ptr, &bfd_subnet_ptr, &bfd_intf_ptr );

						if( ret == IPM_SUCCESS && bfd_subnet_ptr != NULL && bfd_intf_ptr != NULL )
						{
							ret = PIPM_send_ipmsgpath_update( PIPM_UPDATE_PATH,
											  (uint32_t)0,
											  &bfd_subnet_ptr->path[0],
											  bfd_subnet_ptr,
											  bfd_intf_ptr,
											  PIPM_BASE_INTF );
							if( ret != IPM_SUCCESS )
							{
								LOG_ERROR( 0, "Error: PIPM_send_ipmsgpath_update failed ret [%d]", ret );
							}
						}
					}

					ret = PIPM_send_ipmsgpath_update( PIPM_ADD_PATH, 
 									 (uint32_t)0, 
									 path_ptr, 
									 subnet_ptr, 
									 intf_ptr, 
									 PIPM_BASE_INTF );

					if( ret != IPM_SUCCESS )
					{
						LOG_ERROR( 0, "Error: PIPM_send_ipmsgpath_update failed ret [%d]", ret );
					}
				}
				else if ( subnet_ptr->arp_resp_ip_cnt == 0 &&
					  (pipm_l2_path_enable == TRUE) &&
					  IPM_IPADDR_ISUNSPECIFIED(&gateway_ip)  &&
					  ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_NONE ||
					    (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP ) )
				{
					path_ptr = &subnet_ptr->path[0];

					memset(path_ptr, 0, sizeof(*path_ptr));

					path_ptr->type		= PIPM_L2_PATH;
					path_ptr->dest		= subnet_ptr->subnet_base;
					path_ptr->destprefix	= subnet_ptr->prefixlen;
					path_ptr->nexthop	= subnet_ptr->subnet_base;

					// Socket will be created when send ARP/NS
					path_ptr->lsn0_arpsock = -1;
					path_ptr->lsn1_arpsock = -1;

					// Since it is base external interface, so take base interface index
					path_ptr->lsn0_iface_indx = intf_ptr->specData.lsn0_iface_indx;
					if (path_ptr->lsn0_iface_indx < 0)
					{
						snprintf(resp, REPLY_TEXT, "PIPM Path Config: Failed to get lsn0_iface_indx\n");
						LOG_FORCE(0, resp);
						return IPM_FAILURE;
					}

					path_ptr->lsn1_iface_indx = intf_ptr->specData.lsn1_iface_indx;
					if (path_ptr->lsn1_iface_indx < 0)
					{
						snprintf(resp, REPLY_TEXT, "PIPM Path Config: Failed to get lsn1_iface_indx\n");
						LOG_FORCE(0, resp);
						return IPM_FAILURE;
					}

					subnet_ptr->path_cnt	= 1;

					ret = PIPM_send_ipmsgpath_update( PIPM_ADD_PATH, 
 									 (uint32_t)0, 
									 path_ptr, 
									 subnet_ptr, 
									 intf_ptr, 
									 PIPM_BASE_INTF );

					if( ret != IPM_SUCCESS )
					{
						LOG_ERROR( 0, "Error: PIPM_send_ipmsgpath_update failed ret [%d]", ret );
					}
				}

				subnet_ptr->arp_resp_ip[subnet_ptr->arp_resp_ip_cnt] = ip;
				subnet_ptr->arp_resp_ip_cnt++;
				path_ptr = &subnet_ptr->path[subnet_ptr->path_cnt];
				memset(path_ptr, 0, sizeof(*path_ptr));

				if ( !IPM_IPADDR_ISUNSPECIFIED(&gateway_ip) )
				{
					path_found = 0;
					for( path_idx = 0, cur_path_ptr = &subnet_ptr->path[0];
						path_idx < subnet_ptr->path_cnt;
						path_idx++, cur_path_ptr++ )
					{
						if ( cur_path_ptr->type == PIPM_GATEWAY_PATH )
						{
							if ( cur_path_ptr->dest.addrtype == gateway_ip.addrtype &&
								IPM_IPCMPADDR(&cur_path_ptr->nexthop, &gateway_ip) == IPM_SUCCESS &&
								cur_path_ptr->destprefix == 0 )
							{
								path_found = 1;
								break;
							}
						}
					}

					if ( !path_found )
					{
						path_ptr->type = PIPM_GATEWAY_PATH;
						IPM_ipaddr_init(&path_ptr->dest);
						path_ptr->dest.addrtype = gateway_ip.addrtype;
						path_ptr->destprefix = 0;
						path_ptr->nexthop = gateway_ip;
						subnet_ptr->path_cnt++;
#if defined (_X86)

						/*
						 * For X86 platform, it has to update kernel module ippathmgt.ko 
						 * paths array MAC per path referesh since there is no patch available.
						 * After multi-subnet, for base external interface, it needs more
						 * socket.
						 * Initialize path socket and interface index
						 * 
						 */
						if ( vlanId == 0)
						{
							// Socket will be created when send ARP/NS
							path_ptr->lsn0_arpsock = -1;
							path_ptr->lsn1_arpsock = -1;

							// Since it is base external interface, so take base interface index
							path_ptr->lsn0_iface_indx = intf_ptr->specData.lsn0_iface_indx;
							if (path_ptr->lsn0_iface_indx < 0)
							{
								snprintf(resp, REPLY_TEXT, "PIPM Path Config: Failed to get lsn0_iface_indx\n");
								LOG_FORCE(0, resp);
								return IPM_FAILURE;
							}

							path_ptr->lsn1_iface_indx = intf_ptr->specData.lsn1_iface_indx;
							if (path_ptr->lsn1_iface_indx < 0)
							{
								snprintf(resp, REPLY_TEXT, "PIPM Path Config: Failed to get lsn0_iface_indx\n");
								LOG_FORCE(0, resp);
								return IPM_FAILURE;
							}

						}
#endif

						ret = PIPM_path_update( PIPM_ADD_PATH, path_ptr, subnet_ptr, intf_ptr, PIPM_BASE_INTF );
						if ( ret != IPM_SUCCESS )
						{
							LOG_ERROR(0, "Eror: PIPM_path_update failed ret [%d]\n", ret );
						}
					}
				}	

				if ( PIPM_BASE_INTF == intfTypeExt )
                                {
                                        ret = PIPM_send_ipmsg( PIPM_ADD_IP, &ip, subnet_ptr, 
                                                               intf_ptr, intfTypeExt );
                                }
                                else
                                {
                                        ret = PIPM_send_ipmsg( PIPM_ADD_IP, &ip, subnet_ptr, 
                                                               intfSpecDataP, intfTypeExt );
                                }

			        if( ret != IPM_SUCCESS )
			        {
			            LOG_ERROR( 0, "Error: PIPM_send_ipmsg failed ret [%d]", ret );
			        }
			    }
			}
			if (num_intf == 1)
			{
				// Return when it isn't proxy server or no special handling
				// needed
				return (IPM_SUCCESS);
			}
		    }
		    else if(    !PIPM_IS_ADD_TYPE( type ) 
                             && PIPM_IS_LOCAL_IP_TYPE( type )  
                             && PIPM_BASE_INTF == intfTypeExt )
		    {
			PIPM_SUBNET	*cur_ptr;
			PIPM_SUBNET	*next_ptr;
			int		delete_idx;

			matching_arp_resp_ip_idx = -1;

			for( arp_resp_ip_idx = 0;
			     arp_resp_ip_idx < subnet_ptr->arp_resp_ip_cnt;
			     arp_resp_ip_idx++ )
			{
			    if( IPM_IPCMPADDR(&subnet_ptr->arp_resp_ip[arp_resp_ip_idx], &ip) == IPM_SUCCESS )
			    {
				matching_arp_resp_ip_idx = arp_resp_ip_idx;
			    }
			}
		
			if( matching_arp_resp_ip_idx != -1 )
			{
			    ret = PIPM_send_ipmsg( PIPM_DEL_IP, &ip, subnet_ptr, 
                                                   ( ( PIPM_BASE_INTF == intfTypeExt ) ? intf_ptr : intfSpecDataP ),
                                                   intfTypeExt );

			    if( ret != IPM_SUCCESS )
			    {
			        LOG_ERROR( 0, "Error: PIPM_send_ipmsg failed ret [%d]", ret );
		            }

			    /* Take care of the match on last or the only entry */
			    if( matching_arp_resp_ip_idx == (subnet_ptr->arp_resp_ip_cnt - 1) ||
				subnet_ptr->arp_resp_ip_cnt == 1 )
			    {
				IPM_ipaddr_init(&subnet_ptr->arp_resp_ip[matching_arp_resp_ip_idx]);
			    } 
			    else
			    {
				/* Copy the last entry to this spot */
				subnet_ptr->arp_resp_ip[matching_arp_resp_ip_idx] = 
					subnet_ptr->arp_resp_ip[subnet_ptr->arp_resp_ip_cnt - 1];
			    }

			    subnet_ptr->arp_resp_ip_cnt--;
			    subnet_ptr->arp_resp_ip_indx = 0;
			}
			else 
			{
			    if( matching_arp_resp_ip_idx == -1 )
			    {
	                        snprintf(resp, REPLY_TEXT,
				   "PIPM_cmd_path_update(): Failed to find/delete local ip %s/%d any path in %s - %s",
	                           cmd_path_ptr->ip, 
	                           cmd_path_ptr->prefix, 
				   ( strlen( iface0_base_ptr ) > 0 ? iface0_base_ptr : "empty" ),
				   ( strlen( iface1_base_ptr ) > 0 ? iface1_base_ptr : "empty" )
				);

				LOG_DEBUG(0, resp);
			    }
			}
			if( subnet_ptr->arp_resp_ip_cnt == 0 && subnet_ptr->delete_flag == FALSE )
			{

			    /* Remove any remaining paths before removing the subnet */
                            for( path_idx = 0, path_ptr = &subnet_ptr->path[0];
                             	 path_idx < subnet_ptr->path_cnt;
                             	 path_idx++, path_ptr++ )
	                    {
				/*
				 * There is No route entry in /proc/ippathmgt/v4nexthop or v6nexthop
				 * for path type as PIPM_PROXY_PATH. So skip it here, too
				 */
                                if( (path_ptr->type != PIPM_GATEWAY_PATH) && (path_ptr->type != PIPM_PROXY_PATH) )
                                {
			            ret = PIPM_send_routemsg( PIPM_DEL_ROUTE, path_ptr, intf_ptr );
                                    if( ret != IPM_SUCCESS )
                                    {
				        LOG_ERROR( 0, "Error: PIPM_send_routemsg failed ret [%d]", ret );
 				    }
 				}


				if ( path_ptr->vlanId > 0 )
                                {
                                        char tmp_iface_0[MAX_NLEN_DEV], tmp_iface_1[MAX_NLEN_DEV];
                                        PIPM_INTF *tmpIntfDataP;
                                        PIPM_INTF_SPEC *tmpIntfSpecDataP;
                                        int tmpBaseIntfIdx;
                                        PIPM_INTF_TYPE_EXT tmpIntfTypeExt;

                                        snprintf( tmp_iface_0, MAX_NLEN_DEV, "%s%s", intf_ptr->lsn0_baseif,
                                                  ipm_getVLANStr( path_ptr->vlanId, TRUE ) );
                                        snprintf( tmp_iface_1, MAX_NLEN_DEV, "%s%s", intf_ptr->lsn1_baseif,
                                                  ipm_getVLANStr( path_ptr->vlanId, TRUE ) );

                                        (void)PIPM_findIntf( tmp_iface_0, tmp_iface_1,
                                                             &tmpIntfDataP, &tmpIntfSpecDataP,
                                                             &tmpIntfTypeExt, &tmpBaseIntfIdx );

                                        if ( intfSpecDataP != NULL && PIPM_EXTN_INTF == tmpIntfTypeExt )
                                        {
                                                ret = PIPM_send_ipmsgpath_update( PIPM_DEL_PATH, 
                                                                                  (uint32_t)0, 
                                                                                  path_ptr, 
                                                                                  subnet_ptr,
                                                                                  tmpIntfSpecDataP, 
                                                                                  tmpIntfTypeExt );
                                        }
                                        else
                                        {
                                                LOG_ERROR( 0, "ERROR-%s: tmp_iface_0: %s tmp_iface_1: %s path_ptr: vlanId: %u tmpIntfTypeExt: %u\n",
                                                           (char *)(__func__), tmp_iface_0, tmp_iface_1, path_ptr->vlanId, tmpIntfTypeExt );
                                        }
                                }
                                else
                                {
                                        ret = PIPM_send_ipmsgpath_update( PIPM_DEL_PATH, 
                                                                         (uint32_t)0, 
                                                                         path_ptr, 
                                                                         subnet_ptr,
                                                                         ( ( PIPM_BASE_INTF == intfTypeExt ) ? intf_ptr : intfSpecDataP ),
                                                                         intfTypeExt );
                                }

				if( ret != IPM_SUCCESS )
				{
				    LOG_ERROR( 0, "Error: PIPM_send_ipmsgpath_update failed ret [%d]", ret );
				}

				if (path_ptr->lsn0_arpsock >= 0)
                                {
                                    close(path_ptr->lsn0_arpsock);
                                }
                                if (path_ptr->lsn1_arpsock >= 0)
                                {
                                    close(path_ptr->lsn1_arpsock);
                                }

			    	memset(path_ptr, 0, sizeof(*path_ptr));
				path_ptr->lsn0_arpsock = -1;
				path_ptr->lsn1_arpsock = -1;
                                path_ptr->lsn0_iface_indx = -1;
                                path_ptr->lsn1_iface_indx = -1;
			    }

			    subnet_ptr->path_cnt = 0;

			}
			else if ( subnet_ptr->arp_resp_ip_cnt == 0 && subnet_ptr->delete_flag == TRUE )
			{
				struct cmd_subnet_upd subnet_info;
				char reply_text[REPLY_TEXT];

				memset( &subnet_info, 0, sizeof(subnet_info));
				subnet_info.redundancy_mode = (int) subnet_ptr->redundancy_mode;
				subnet_info.prefix = subnet_ptr->prefixlen;
				IPM_ipaddr2p(&subnet_ptr->subnet_base, subnet_info.subnet_base, IPM_IPMAXSTRSIZE);

				if ( strlen( intf_ptr->lsn0_baseif ) > 0 )
				{
					subnet_info.dev_t[0].subnet_type = intf_type;
					strncpy( subnet_info.dev_t[0].dev_if, intf_ptr->lsn0_baseif, MAX_NLEN_DEV );
				}

				if ( strlen( intf_ptr->lsn1_baseif ) > 0 )
				{
					subnet_info.dev_t[1].subnet_type = intf_type;
					strncpy( subnet_info.dev_t[1].dev_if, intf_ptr->lsn1_baseif, MAX_NLEN_DEV );
				}
				
				ret = PIPM_cmd_subnet_update(&subnet_info, (intf_type == IPM_SUBNET_INTERNAL ? IPM_DEL_INT_SUBNET : IPM_DEL_EXT_SUBNET), reply_text, NON_CLI_REQUEST);

				if ( ret < 0 )
				{
					/* already log error in PIPM_cmd_subnet_update */
					return ret;
				}
			}
   		    }
		    else if (    ( IPM_DEL_PROXY_SERVER == type ) 
                              && ( PIPM_EXTN_INTF == intfTypeExt ) 
                              && ( vlanId > 0 ) )
                    {
                            /* 
                             *  Proxyserver delete on an extension interface. 
                             *  Need to delete path from linux kernel.
                             */
			    for ( ( path_idx = 0 );
                                  ( path_idx < subnet_ptr->path_cnt ); )
                            {

				path_ptr = &(subnet_ptr->path[path_idx]);

                                /* 
                                 *  Find a "route path" that matches the VLAN id.
                                 *  Delete this path from PIPM's data and the kernel as well.
                                 *  Note we cannot match on "dest" or "nexthop" IP as these
                                 *  are different from the proxyserver IP.
                                 *  AIM does not issue a "route delete" command, hence we
                                 *  handle the deletion of the path in the proxyserver delete.
                                 */
				if (    ( 0 == path_ptr->vlanId ) 
                                     || ( path_ptr->vlanId != vlanId ) )
                                {
					path_idx++;
                                        continue;
                                }

                                /* Found the path. Delete it from the kernel first and then IPM's data. */
                                PIPM_PATH *del_path_ptr;
		                int del_index;

	                        matching_path_idx = path_idx;
		                matching_subnet_idx = subnet_idx;
				matching_intf_idx = baseIntfIdx;

  	                        /* Delete entry by collapsing table */
		                subnet_ptr->path_cnt--;

				if ( PIPM_ROUTE_PATH == path_ptr->type )
                                {
				ret = PIPM_send_ipmsgpath_update( PIPM_DEL_PATH, (uint32_t)0, 
                                                                  path_ptr, 
                                                                  subnet_ptr,
                                                                  intfSpecDataP, 
                                                                  intfTypeExt );

				    if ( ret != IPM_SUCCESS )
				    {
				        LOG_ERROR( 0, "Error: PIPM_send_ipmsgpath_update failed ret [%d]", ret );
				    }
				}

				if ( path_ptr->lsn0_arpsock >= 0 )
                                {
                                    close( path_ptr->lsn0_arpsock );
                                    path_ptr->lsn0_arpsock = -1;
                                }
                                if ( path_ptr->lsn1_arpsock >= 0 )
                                {
                                    close( path_ptr->lsn1_arpsock );
                                    path_ptr->lsn1_arpsock = -1;
                                }
                                path_ptr->lsn0_iface_indx = -1;
                                path_ptr->lsn1_iface_indx = -1;

	                        for( del_index = path_idx; 
	                             del_index < subnet_ptr->path_cnt; 
	                             del_index++ )
	                        {
	                            subnet_ptr->path[del_index] = subnet_ptr->path[del_index + 1];
	                        }

	                        /* Clear last entry */
	                        del_path_ptr = &subnet_ptr->path[del_index];

	                        memset( del_path_ptr, 0, sizeof( *del_path_ptr ) );

				/* continue without incrementing index */

                    	    } /* end 'path loop' */

			    if ( 0 == subnet_ptr->path_cnt )
                            {
                                /* No more paths in this subnet. Reset the 'startPathIdx'. */
                                intfSpecDataP->startPathIdx = 0;

                                if ( ( intfSpecDataP->startSubnetIdx + 1 ) >= intf_ptr->subnet_cnt )
                                {
                                    intfSpecDataP->startSubnetIdx = 0; 
                                }
                                else
                                {
                                    intfSpecDataP->startSubnetIdx++;        
                                }
                            }
                            else
                            {
                                if ( intfSpecDataP->startPathIdx >= subnet_ptr->path_cnt )
                                {
                                        /* Reset to start at beginning. */
                                        intfSpecDataP->startPathIdx = 0;
                                }
                            }

			    /* Deleted the proxyserver (route path) for VLAN interface. Delete the interface also. */
			    /* After feature 80.688, multiple IP subnets, it must be check whether
			     * there are other subnet use this Vlan before deleting extension 
			     * interface
			     */
			    int	subnet_ct = 0;
			    int path_ct = 0;
			    int is_del_extension_intf = 1;
			    PIPM_SUBNET *temp_subnet_ptr = &intf_ptr->subnet[0];
			    PIPM_PATH *temp_path_ptr = NULL;
			    if( intf_ptr->type == PIPM_INTERNAL_INTF )
			    {
				is_del_extension_intf = 0;
			    }
			    else
			    {
				for( ; subnet_ct < intf_ptr->subnet_cnt;
					subnet_ct++, temp_subnet_ptr++ )
				{
					for( path_ct = 0, temp_path_ptr = &temp_subnet_ptr->path[0];
						path_ct < temp_subnet_ptr->path_cnt;
						path_ct++, temp_path_ptr++ )
					{
						if( temp_path_ptr->vlanId == vlanId )
						{
							is_del_extension_intf = 0;
							break;
						}
					}
					if( is_del_extension_intf == 0 )
					{
						break;
					}
				}
			    }
			
			    if( is_del_extension_intf == 1 )
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

                                (void)PIPM_extnIntfUpdate( &intfUpdateCmd, type, 
                                                           resp, baseIntfIdx, tmp_intf_idx );
                            }
                    }
		    else 
		    {
		        matching_path_idx = -1;
				
                        /* Found subnet match, look for path match */
                        for( path_idx = 0, path_ptr = &subnet_ptr->path[0];
                             path_idx < subnet_ptr->path_cnt;
                             path_idx++, path_ptr++ )
                        {

				if (    ( IPM_SUCCESS == IPM_IPCMPADDR( &path_ptr->nexthop, &ip ) ) 
                                     && ( vlanId == path_ptr->vlanId ) 
				     && ( path_ptr->inner_vlan == inner_vlan) )
		                {
		            	    matching_path_idx = path_idx;

		                    /* Found a match */
                        	    if( PIPM_IS_ADD_TYPE( type ) )
		                    {
					/* Paths can be added multiple times, just ignore duplicates */

					if (    ( 0 == i )
                                             && ( strchr( cmd_path_ptr->fe_iface[0], '.' ) ) )
                                        {
                                            bContIntfScan = TRUE;
                                            break;
                                        }
                                        else
					{
					    return IPM_SUCCESS;
					}
				    }
		                    else 
		                    {
		                        PIPM_PATH *del_path_ptr;
		                        int del_index;

	                                matching_path_idx = path_idx;
		                        matching_subnet_idx = subnet_idx;
					matching_intf_idx = baseIntfIdx;

  	                                /* Delete entry by collapsing table */
		                        subnet_ptr->path_cnt--;

					ret = PIPM_send_ipmsgpath_update( PIPM_DEL_PATH,
                                                                          (uint32_t)0,
                                                                          path_ptr,
                                                                          subnet_ptr, 
                                                                          ( ( PIPM_BASE_INTF == intfTypeExt ) ? intf_ptr : intfSpecDataP ),
                                                                          intfTypeExt );

				        if( ret != IPM_SUCCESS )
				        {
				            LOG_ERROR( 0, "Error: PIPM_send_ipmsgpath_update failed ret [%d]", ret );
				        }

					if (path_ptr->lsn0_arpsock >= 0)
                                        {
                                            close(path_ptr->lsn0_arpsock);
                                            path_ptr->lsn0_arpsock = -1;
                                        }
                                        if (path_ptr->lsn1_arpsock >= 0)
                                        {
                                            close(path_ptr->lsn1_arpsock);
                                            path_ptr->lsn1_arpsock = -1;
                                        }
                                        path_ptr->lsn0_iface_indx = -1;
                                        path_ptr->lsn1_iface_indx = -1;

	                                for( del_index = path_idx; 
	                                     del_index < subnet_ptr->path_cnt; 
	                                     del_index++ )
	                                {
	                                    subnet_ptr->path[del_index] = subnet_ptr->path[del_index + 1];
	                                }

	                                /* Clear last entry */
	                                del_path_ptr = &subnet_ptr->path[del_index];

	                                memset(del_path_ptr, 0, sizeof(*del_path_ptr));

	                            } /* end of if IPM_DEL_PATH */

	                        } /* end of path match */

                        } /* end of path search */

			if ( TRUE == bContIntfScan )
                        {
                                break;
                        }

	                /* Subnet match, no Path match -> Add Path */
	                if( (matching_path_idx < 0)
			     && ( !PIPM_IS_LOCAL_IP_TYPE(type) 
				   && PIPM_IS_ADD_TYPE(type)
				 )
			     && (0 == i)
			)
	                {
			    // Process paths for eth0.800/eth1.801 interface 
	                    path_ptr = &(subnet_ptr->path[subnet_ptr->path_cnt]);

			    memset(path_ptr, 0, sizeof(*path_ptr));

			    path_ptr->lsn0_arpsock = -1;
                            path_ptr->lsn1_arpsock = -1;
                            path_ptr->lsn0_iface_indx = -1;
                            path_ptr->lsn1_iface_indx = -1;
                            path_ptr->inner_vlan = inner_vlan;
                            path_ptr->intFloatIP = intFloatIp;

			    if( PIPM_IS_PROXY_TYPE( type ) )
			    {
	                        path_ptr->type = PIPM_PROXY_PATH;
			    }
			    else
			    {
	                        path_ptr->type = PIPM_ROUTE_PATH;
			    }

                            /* Querying interface information.  */
                            if (inner_vlan > 0)
                            {
#if defined (_X86)
				/*
				 * If it is VMM-HI or cloud env, then it will send ARP
				 * from based interface, so set base interface index
				 */
				if (PIPM_PROXY_PATH == path_ptr->type)
				{
					path_ptr->lsn0_iface_indx = intf_ptr->specData.lsn0_iface_indx;
					path_ptr->lsn1_iface_indx = intf_ptr->specData.lsn1_iface_indx;
				}
				else
#endif
				{

                                char name[MAX_NLEN_DEV];
                                char *colon;
                                if (cmd_path_ptr->be_iface[0][0] != '\0')
                                {
                                        strcpy(name, cmd_path_ptr->be_iface[0]);
                                        if ((colon = strchr(name, ':')) != NULL)
                                        {
                                                *colon = '\0';
                                                sprintf(colon, ".%d", inner_vlan);
                                        }
                                        else
                                        {
                                                sprintf(name, "%s.%d", cmd_path_ptr->be_iface[0], inner_vlan);
                                        }

                                        path_ptr->lsn0_iface_indx = ipm_get_ifindex(inetsocket, name);
                                        if (path_ptr->lsn0_iface_indx < 0)
                                        {
                                                LOG_ERROR(0, "PIPM_cmd_path_update(): failed to get left intf.");
                                                return IPM_FAILURE;
                                        }
                                }

                                if (cmd_path_ptr->be_iface[1][0] != '\0')
                                {
                                        strcpy(name, cmd_path_ptr->be_iface[1]);
                                        if ((colon = strchr(name, ':')) != NULL)
                                        {
                                                *colon = '\0';
                                                sprintf(colon, ".%d", inner_vlan);
                                        }
                                        else
                                        {
                                                sprintf(name, "%s.%d", cmd_path_ptr->be_iface[1], inner_vlan);
                                        }

                                        path_ptr->lsn1_iface_indx = ipm_get_ifindex(inetsocket, name);
                                        if (path_ptr->lsn1_iface_indx < 0)
                                        {
                                                LOG_ERROR(0, "PIPM_cmd_path_update(): failed to get intf.");
                                                return IPM_FAILURE;
                                        }
                                }
				}
                            }
			    else if (pipm_l2_path_enable == TRUE)
			    {
#if defined (_X86)
				/*
				 * For X86 platform, it has to update kernel module ippathmgt.ko 
				 * paths array MAC per path referesh since there is no patch available.
				 * After multi-subnet, for base external interface, it needs more
				 * socket.
				 * Initialize path socket and interface index
				 * 
				 */
				if ( vlanId == 0)
				{
					// Socket will be created when send ARP/NS
					path_ptr->lsn0_arpsock = -1;
					path_ptr->lsn1_arpsock = -1;

					// Since it is base external interface, so take base interface index
					path_ptr->lsn0_iface_indx = intf_ptr->specData.lsn0_iface_indx;
					if (path_ptr->lsn0_iface_indx < 0)
					{
						snprintf(resp, REPLY_TEXT, "PIPM Path Config: Failed to get lsn0_iface_indx\n");
						LOG_FORCE(0, resp);
						return IPM_FAILURE;
					}
					path_ptr->lsn1_iface_indx = intf_ptr->specData.lsn1_iface_indx;
					if (path_ptr->lsn1_iface_indx < 0)
					{
						snprintf(resp, REPLY_TEXT, "PIPM Path Config: Failed to get lsn1_iface_indx\n");
						LOG_FORCE(0, resp);
						return IPM_FAILURE;
					}
				}
#endif
			    }

			    path_ptr->dest = ip;
			    path_ptr->nexthop = ip;
	
			    if( ip.addrtype == IPM_IPV6 )
			    {
				path_ptr->destprefix = 128;
			    }
			    else
			    {
				path_ptr->destprefix = 32;
			    }
	

			    /* Set the VLAN Id. */
                            path_ptr->vlanId = vlanId;

	                    subnet_ptr->path_cnt++;


			    ret = PIPM_path_update( PIPM_ADD_PATH, path_ptr, subnet_ptr, 
                                                  ( ( PIPM_BASE_INTF == intfTypeExt) ? intf_ptr : intfSpecDataP ),
					        intfTypeExt );

			    if( ret != IPM_SUCCESS )
			    {
			    	LOG_ERROR( 0, "Error: PIPM_path_update failed ret [%d]", ret );
			    }
	                }
	                else if( matching_path_idx < 0  &&
			         ( !PIPM_IS_ADD_TYPE( type ) && 
				   !PIPM_IS_LOCAL_IP_TYPE( type ) ))

	                {
	                    snprintf(resp, REPLY_TEXT,
				       "PIPM_cmd_path_update(): Failed to find/delete %s/%d any path in %s - %s",
	                               cmd_path_ptr->ip, 
	                               cmd_path_ptr->prefix, 
	                               ( strlen( iface0_base_ptr ) > 0 ? iface0_base_ptr : "empty" ),
	                               ( strlen( iface1_base_ptr ) > 0 ? iface1_base_ptr : "empty" )
			    );

			    LOG_DEBUG(0, resp);
	                }

                    } /* end else path */
							
                } /* subnet match */
		
            } /* end subnet search */

	    if ( TRUE == bContIntfScan )
            {
                continue;
            }
		
	    if ( matching_subnet_idx < 0 ) 
	    {
		char ip_addr[IPM_IPMAXSTRSIZE];

		snprintf(resp, REPLY_TEXT,
			"%s: Failed to find subnet %s/%d any path in %s - %s to %s",
			__FUNCTION__,
            		cmd_path_ptr->ip, 
                	cmd_path_ptr->prefix, 
			( strlen( iface0_base_ptr ) > 0 ? iface0_base_ptr : "empty" ),
			( strlen( iface1_base_ptr ) > 0 ? iface1_base_ptr : "empty" ),
			( PIPM_IS_ADD_TYPE( type ) ? "add" : "delete" )
	    	);

		if ( PIPM_IS_ADD_TYPE( type ) )
		{
			LOG_ERROR(0, resp);

			return IPM_FAILURE;
		}
		else
		{
			LOG_DEBUG(0, resp);
		}
	    }
	
        } /* end interface match */
	
    } /* end number of interfaces */

    return IPM_SUCCESS;
}

/**********************************************************************
 *
 * Name:	PIPM_cmd_route_update()
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

int PIPM_cmd_route_update( struct cmd_route_upd *cmd_route_upd_ptr, int type, char *resp )
{
PIPM_DATA	*data_ptr;
PIPM_INTF	*intf_ptr;
PIPM_SUBNET	*subnet_ptr;
PIPM_PATH	*path_ptr;
IPM_IPADDR 	dest_mask;
IPM_IPADDR 	dest_base;
IPM_IPADDR	dest_ip;
IPM_IPADDR	nexthop_ip;
int 		intf_idx;
int 		subnet_idx;
int 		path_idx;
int 		matching_intf_idx;
int 		matching_subnet_idx;
int 		matching_path_idx;
IPM_RETVAL 	ipm_retval;
IPM_IPADDR	ip;
int		ret;
unsigned short  vlanId = 0;
char            lsn0_baseif[MAX_NLEN_DEV];
char            lsn1_baseif[MAX_NLEN_DEV];
char            lsn0_if[MAX_NLEN_DEV];
char            lsn1_if[MAX_NLEN_DEV];

    if( pipm_enable == FALSE )
    {
	return IPM_SUCCESS;
    }

    /* Check for PIPM memory */
    if( PIPM_shm_ptr == NULL )
    {
        snprintf(resp, REPLY_TEXT, "PIPM Route Config: Shared memory null, DestIP %s\n", 
		 cmd_route_upd_ptr->dest);

        LOG_ERROR(0, resp);

        return IPM_FAILURE;
    }

    data_ptr = (PIPM_DATA *)PIPM_shm_ptr;

    /* Convert Destination IP */
    IPM_ipaddr_init(&dest_ip);
	
    ipm_retval = IPM_p2ipaddr(cmd_route_upd_ptr->dest, &dest_ip);

    if( ipm_retval != IPM_SUCCESS )
    {
        snprintf(resp, REPLY_TEXT, "PIPM Route Config: Failure %d to translate DestIP %s\n", 
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
                 "PIPM Route Config: Failure %d to create Destination Mask for %s from subnet prefix %d\n",
                 ipm_retval, cmd_route_upd_ptr->dest, cmd_route_upd_ptr->prefix);

	LOG_ERROR(0, resp);

	return ipm_retval;
    }

    IPM_ipaddr_init(&dest_base);

    IPM_get_subnet(&dest_ip, &dest_mask, &dest_base);

    /* Conditionally convert NextHop IP */
    IPM_ipaddr_init(&nexthop_ip);

    if( type == IPM_ADD_ROUTE )
    {
        ipm_retval = IPM_p2ipaddr(cmd_route_upd_ptr->nexthop, &nexthop_ip);

        if( ipm_retval != IPM_SUCCESS )
        {
            snprintf(resp, REPLY_TEXT, "PIPM Route Config: Failure %d to translate NextHopIP %s\n",
		     ipm_retval, cmd_route_upd_ptr->nexthop);

            LOG_ERROR(0, resp);

            return ipm_retval;
        }
    }

    vlanId = cmd_route_upd_ptr->vlanId;
    
    memset(lsn0_if, 0, sizeof(lsn0_if));
    memset(lsn1_if, 0, sizeof(lsn1_if));

    if ((vlanId > 0) && (0 == cmd_route_upd_ptr->pivot_id) && (strlen(cmd_route_upd_ptr->iface[0]) > 0))
    {
        char vlanstr[8];
        strncpy(lsn0_if, cmd_route_upd_ptr->iface[0], sizeof(lsn0_if)-1);
        sprintf(vlanstr, ".%d", vlanId);
        strtok(lsn0_if, ":");

        int dff = strlen(lsn0_if) - strlen(vlanstr);

        if (strcmp(&(lsn0_if[dff]), vlanstr) != 0)
        {
            snprintf(resp, REPLY_TEXT, "PIPM Route Config: vlan ID verification on intf failed, intf: %s; vlan: %d\n",
                    lsn0_if, vlanId);
            LOG_ERROR(0, resp);
            return IPM_FAILURE;
        }
    }

    if ((vlanId > 0) && (0 == cmd_route_upd_ptr->pivot_id) && (strlen(cmd_route_upd_ptr->iface[1]) > 0))
    {
        char vlanstr[8];
        strncpy(lsn1_if, cmd_route_upd_ptr->iface[1], sizeof(lsn1_if)-1);
        sprintf(vlanstr, ".%d", vlanId);
        strtok(lsn1_if, ":");

        int dff = strlen(lsn1_if) - strlen(vlanstr);

        if (strcmp(&(lsn1_if[dff]), vlanstr) != 0)
        {
            snprintf(resp, REPLY_TEXT, "PIPM Route Config: vlan ID verification on intf failed, intf: %s; vlan: %d\n",
                    lsn1_if, vlanId);
            LOG_ERROR(0, resp);
            return IPM_FAILURE;
        }
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
	/* Routes go on External interfaces only */	
	if( intf_ptr->type == PIPM_INTERNAL_INTF )
	{
		continue;
	}

        matching_intf_idx = intf_idx;

        matching_subnet_idx = -1;

        /* Look through all subnets */
        for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
             subnet_idx < intf_ptr->subnet_cnt;
             subnet_idx++, subnet_ptr++ )
        {
	
       	    matching_path_idx = -1;

            /* Look through all paths */
            for( path_idx = 0, path_ptr = &subnet_ptr->path[0];
                 path_idx < subnet_ptr->path_cnt;
                 path_idx++, path_ptr++ )
            {
		if (    ( PIPM_ROUTE_PATH == path_ptr->type ) 
                     && ( cmd_route_upd_ptr->prefix == path_ptr->destprefix ) 
                     && ( IPM_SUCCESS == IPM_IPCMPADDR( &dest_base, &(path_ptr->dest) ) )  
                     && ( path_ptr->vlanId == vlanId ) )
                {
            	    matching_path_idx = path_idx;

                    /* Found a match */
                    if( type == IPM_ADD_ROUTE )
                    {
			/* Paths can be added multiple times, just ignore duplicates */
			if ( IPM_SUCCESS == IPM_IPCMPADDR( &nexthop_ip, &path_ptr->nexthop ) )
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
	                             "PIPM Path Config: Failure %d to create SubnetMask for %s from subnet prefix %d\n",
			              ipm_retval, cmd_route_upd_ptr->nexthop, subnet_ptr->prefixlen);

	                    LOG_ERROR(0, resp);

	                    return ipm_retval;
	                }

	                IPM_ipaddr_init(&nexthop_base);
	                IPM_get_subnet(&nexthop_ip, &subnet_mask, &nexthop_base);

                        matching_path_idx = path_idx;
                        matching_subnet_idx = subnet_idx;
                        matching_intf_idx = intf_idx;

	                if( IPM_IPCMPADDR(&subnet_ptr->subnet_base, &nexthop_base) == IPM_SUCCESS )
			{
			    
			    ret = PIPM_path_update( PIPM_DEL_PATH, path_ptr, subnet_ptr, intf_ptr,
						    PIPM_BASE_INTF );
			    if( ret != IPM_SUCCESS )
			    {
				LOG_ERROR( 0, "Error: PIPM_path_update failed ret [%d]", ret );
			    }

			    ret = PIPM_send_routemsg( PIPM_DEL_ROUTE, path_ptr, intf_ptr );
			    if( ret != IPM_SUCCESS )
		            {
			        LOG_ERROR( 0, "Error: PIPM_send_routemsg failed ret [%d]", ret );
		    	    }

                            /* Update entry */
                            path_ptr->nexthop = nexthop_ip;

			    ret = PIPM_path_update( PIPM_ADD_PATH, path_ptr, subnet_ptr, intf_ptr,
						    PIPM_BASE_INTF );
			    if( ret != IPM_SUCCESS )
			    {
				LOG_ERROR( 0, "Error: PIPM_path_update failed ret [%d]", ret );
			    }

			    ret = PIPM_send_routemsg( PIPM_ADD_ROUTE, path_ptr, intf_ptr );
			    if( ret != IPM_SUCCESS )
		            {
			        LOG_ERROR( 0, "Error: PIPM_send_routemsg failed ret [%d]", ret );
		    	    }
			}
			else
			{
                            PIPM_PATH *del_path_ptr;
                            int del_index;
                            char resp_buff[REPLY_TEXT];

                            /* First delete the routing entry from the old subnet
                             * and then it will be added to the new subnet below.
                             */

			    ret = PIPM_send_routemsg( PIPM_DEL_ROUTE, path_ptr, intf_ptr );
			    if( ret != IPM_SUCCESS )
		            {
			        LOG_ERROR( 0, "Error: PIPM_send_routemsg failed ret [%d]", ret );
		    	    }

                            /* Delete entry by collapsing table */
                            subnet_ptr->path_cnt--;

			    if( subnet_ptr->path_cnt == 0 )
			    {
			        ret = PIPM_path_update( PIPM_DEL_PATH, path_ptr, subnet_ptr, intf_ptr,
							PIPM_BASE_INTF );
			        if( ret != IPM_SUCCESS )
			        {
			            LOG_ERROR( 0, "Error: PIPM_path_update failed ret [%d]", ret );
			        }
			    }
                            for( del_index = path_idx; 
                                 del_index < subnet_ptr->path_cnt; 
                                 del_index++ )
                            {
                                subnet_ptr->path[del_index] = subnet_ptr->path[del_index + 1];
                            }

                            /* Clear last entry */
                            del_path_ptr = &subnet_ptr->path[del_index];

#if defined (_X86)
			// see more comment on adding route path below
			if ( vlanId == 0 )
			{
				if (del_path_ptr->lsn0_arpsock >= 0)
				{
					close(del_path_ptr->lsn0_arpsock);
				}
				if (del_path_ptr->lsn1_arpsock >= 0)
				{
					close(del_path_ptr->lsn1_arpsock);
				}
			}
#endif
                            memset(del_path_ptr, 0, sizeof(*del_path_ptr));
				
#if defined (_X86)
			if ( vlanId == 0 )
			{
				del_path_ptr->lsn0_arpsock = -1;
				del_path_ptr->lsn1_arpsock = -1;
				del_path_ptr->lsn0_iface_indx = -1;
				del_path_ptr->lsn1_iface_indx = -1;
			}
#endif
                            /* Now add the new route */
                            (void)PIPM_cmd_route_update(cmd_route_upd_ptr,
                                                    IPM_ADD_ROUTE,
                                                    resp_buff);

                            return IPM_SUCCESS;
                        }
                    }
                    else if( type == IPM_DEL_ROUTE )
                    {
                        PIPM_PATH *del_path_ptr;
                        int del_index;

                        matching_path_idx = path_idx;
                        matching_subnet_idx = subnet_idx;
                        matching_intf_idx = intf_idx;

			ret = PIPM_send_routemsg( PIPM_DEL_ROUTE, &subnet_ptr->path[path_idx], intf_ptr );
			if( ret != IPM_SUCCESS )
		        {
			    LOG_ERROR( 0, "Error: PIPM_send_routemsg failed ret [%d]", ret );
		    	}

                        /* Delete entry by collapsing table */
                        subnet_ptr->path_cnt--;

			if ( subnet_ptr->path[path_idx].vlanId > 0 )
                        {
                                /* Send deletion of path for the extension interface. */
                                int extnIntfIdx;
                                PIPM_INTF_SPEC *intfSpecDataP;                                

                                /* Need to speed up the search with use of bitmap arrays. */
                                for ( ( extnIntfIdx = 0, intfSpecDataP = &(data_ptr->extnIntfData[0]));
				      ( extnIntfIdx < data_ptr->extnIntfCount ); 
				      ( extnIntfIdx++, intfSpecDataP++ ) )
				{
				        if (    ( intfSpecDataP->baseIntfIdx == intf_idx )	
                                             && ( intfSpecDataP->vlanId == subnet_ptr->path[path_idx].vlanId )   )
				        {
				                /* Send path delete for this interface. */
					        ret = PIPM_path_update( PIPM_DEL_PATH, &subnet_ptr->path[path_idx], subnet_ptr, 
                                                                        intfSpecDataP, PIPM_EXTN_INTF );

                                                if ( ret != IPM_SUCCESS )
                                                {
                                                        char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
                                                        LOG_ERROR( 0, "ERROR-%s: Failed to delete path: %d dest: %s nextHop: %s\n",
                                                                   (char *)(__func__), path_idx,
                                                                   IPM_ipaddr2p( &subnet_ptr->path[path_idx].dest, ipm_ipstr_buf, sizeof( ipm_ipstr_buf ) ),
                                                                   IPM_ipaddr2p( &subnet_ptr->path[path_idx].nexthop, ipm_ipstr_buf, sizeof( ipm_ipstr_buf ) ) );
                                                }
				        }
				}
                        }                       
			else if ( subnet_ptr->path_cnt == 0 )
			{
			    ret = PIPM_path_update( PIPM_DEL_PATH, &subnet_ptr->path[path_idx], subnet_ptr, 
						    intf_ptr, PIPM_BASE_INTF );
			    if( ret != IPM_SUCCESS )
			    {
			        LOG_ERROR( 0, "Error: PIPM_path_update failed ret [%d]", ret );
			    }
			}

                        for( del_index = path_idx; 
                             del_index < subnet_ptr->path_cnt; 
                             del_index++ )
                        {
                            subnet_ptr->path[del_index] = subnet_ptr->path[del_index + 1];
                        }

                        /* Clear last entry */
                        del_path_ptr = &subnet_ptr->path[del_index];

#if defined (_X86)
			// see more comment on adding route path below
			if ( vlanId == 0 )
			{
				if (del_path_ptr->lsn0_arpsock >= 0)
				{
					close(del_path_ptr->lsn0_arpsock);
				}
				if (del_path_ptr->lsn1_arpsock >= 0)
				{
					close(del_path_ptr->lsn1_arpsock);
				}
			}
#endif
                        memset(del_path_ptr, 0, sizeof(*del_path_ptr));

#if defined (_X86)
			if ( vlanId == 0 )
			{
				del_path_ptr->lsn0_arpsock = -1;
				del_path_ptr->lsn1_arpsock = -1;
				del_path_ptr->lsn0_iface_indx = -1;
				del_path_ptr->lsn1_iface_indx = -1;
			}
#endif
                    } /* end of if IPM_DEL_ROUTE */

                } /* end of path match */

	    } /* end of path search */	    
				
	    if( type == IPM_ADD_ROUTE && matching_path_idx == -1 )
            {
                /* Didn't find existing path entry,
                 * Check for nexthop subnet match.
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
                             "PIPM Path Config: Failure %d to create SubnetMask for %s from subnet prefix %d\n",
		              ipm_retval, cmd_route_upd_ptr->nexthop, subnet_ptr->prefixlen);

                    LOG_ERROR(0, resp);

                    return ipm_retval;
                }

                IPM_ipaddr_init(&nexthop_base);
                IPM_get_subnet(&nexthop_ip, &subnet_mask, &nexthop_base);

                if( IPM_IPCMPADDR(&subnet_ptr->subnet_base, &nexthop_base) == IPM_SUCCESS )
                {
                    /*
                     * ipm_cli command does not allow adding a
                     * subnet route so we know this is either a default
                     * route or regular static route.
                     */
		    if( subnet_ptr->path_cnt < PIPM_MAX_PATH )
		    {
			PIPM_INTF_TYPE_EXT      intfType;
                        PIPM_INTF               *tmpIntfP;
                        PIPM_INTF_SPEC          *intfSpecDataP;
                        int                     baseIntfIdx;

                        path_ptr = &(subnet_ptr->path[subnet_ptr->path_cnt]);

                        path_ptr->type       = PIPM_ROUTE_PATH;
                        path_ptr->dest       = dest_base;
                        path_ptr->destprefix = cmd_route_upd_ptr->prefix;
                        path_ptr->nexthop    = nexthop_ip;
			path_ptr->vlanId     = vlanId;

			if ( vlanId > 0 )
                        {
                                if ( PIPM_findIntf( lsn0_if, lsn1_if, &tmpIntfP, &intfSpecDataP, &intfType, &baseIntfIdx ) < 0 )
                                {
                                        LOG_FORCE( 0, "ERROR(%s): Failed to find extension interface for vlanId %u\n",
                                                   (char *)(__func__), vlanId );

                                        return IPM_FAILURE;
                                }

                                if ( ( intfType != PIPM_EXTN_INTF ) || ( NULL == intfSpecDataP ) )
                                {
                                        LOG_FORCE( 0, "ERROR(%s): Invalid interface type %u or intfSpecDataP %p for vlanId %u\n",
                                                   (char *)(__func__), intfType, intfSpecDataP, vlanId );

                                        return IPM_FAILURE;
                                }
                        }

#if defined (_X86)
			/*
			 * For X86 platform, it has to update kernel module ippathmgt.ko 
			 * paths array MAC per path referesh since there is no patch available.
			 * After multi-subnet, for base external interface, it needs more
			 * socket.
			 * Initialize path socket and interface index
			 * 
			 */
			// Socket will be created when send ARP/NS
			path_ptr->lsn0_arpsock = -1;
			path_ptr->lsn1_arpsock = -1;

			if (vlanId == 0)
			{
				// Since it is base external interface, so take base interface index
				path_ptr->lsn0_iface_indx = intf_ptr->specData.lsn0_iface_indx;
				path_ptr->lsn1_iface_indx = intf_ptr->specData.lsn1_iface_indx;
			}
			else if (vlanId > 0)
			{
				// For extension interface, use the intf index in extension spec data.
				path_ptr->lsn0_iface_indx = intfSpecDataP->lsn0_iface_indx;
				path_ptr->lsn1_iface_indx = intfSpecDataP->lsn1_iface_indx;
			}

			if ((path_ptr->lsn0_iface_indx < 0) && (path_ptr->lsn1_iface_indx < 0))
			{
				snprintf(resp, REPLY_TEXT, "PIPM Path Config: Failed to get lsn0_iface_indx and lsn1_iface_indx\n");
				LOG_FORCE(0, resp);
				return IPM_FAILURE;
			}
#endif
			/*
			 *  Since data is pre-cached on standby, paths on the extension interfaces have
			 *  already been added. Hence, path count is not zero when base path is to be
			 *  added.
			 */
			if ( !IPM_IPADDR_ISUNSPECIFIED( &(path_ptr->dest)) )
			{

			    if ( vlanId > 0 )
                            {
                                ret = PIPM_path_update( PIPM_ADD_PATH, path_ptr, subnet_ptr, intfSpecDataP, 
						        PIPM_EXTN_INTF );
                            }
                            else
                            {
			        ret = PIPM_path_update( PIPM_ADD_PATH, path_ptr, subnet_ptr, intf_ptr,
						        PIPM_BASE_INTF );
                            }
			    if( ret != IPM_SUCCESS )
		            {
			        LOG_ERROR( 0, "Error: PIPM_path_update failed ret [%d]", ret );
		    	    }
			}

                        subnet_ptr->path_cnt++;

			ret = PIPM_send_routemsg( PIPM_ADD_ROUTE, path_ptr, intf_ptr );
			if( ret != IPM_SUCCESS )
		        {
			    LOG_ERROR( 0, "Error: PIPM_send_routemsg failed ret [%d]", ret );
		    	}
    		    }
		    else
		    {
		        snprintf(resp, REPLY_TEXT, "PIPM Path Config: Max Number of Paths Reached %d\n", 
				 subnet_ptr->path_cnt);

		        LOG_ERROR(0, resp);
			return IPM_FAILURE;
		    }

                } /* end subnet match */

            } /* end IPM_ADD_ROUTE */

        } /* end subnet search */

    } /* end interface  search */

    return IPM_SUCCESS;
}

/**********************************************************************
 *
 * Name:	PIPM_cmd_subnet_update()
 *
 * Abstract:	
 *
 **********************************************************************/
int PIPM_cmd_subnet_update(
	struct cmd_subnet_upd *cmd_subnet_upd_ptr,
	int type,
	char *resp,
	SUBNET_REQUEST request
)
{
	PIPM_DATA	*data_ptr;
	PIPM_INTF	*intf_ptr;
	PIPM_PATH	*path_ptr;
	PIPM_SUBNET	*cur_ptr;
	PIPM_SUBNET	*next_ptr;
	PIPM_SUBNET	*subnet_ptr;
	PIPM_INTF	*bfd_intf_ptr;
	PIPM_SUBNET	*bfd_subnet_ptr;

	IPM_IPADDR	*arp_ptr;
	IPM_IPADDR	subnet_mask;
	IPM_IPADDR	subnet_base;
	IPM_IPADDR	gateway;

	INTF_ACTION	intf_action;
	IPM_RETVAL	ipm_retval;

	char		*iface0_base_ptr = NULL;
	char		*iface1_base_ptr = NULL;
	char		iface0_base[MAX_NLEN_DEV];
	char		iface1_base[MAX_NLEN_DEV];
	char		gateway_addr[IPM_IPMAXSTRSIZE];

	int		delete_idx;
	int		intf_idx;
	int		intf_type;
	int		path_idx;
	int		ret;
	int		subnet_idx;
	int		upd_shared_memory = 0;
	int		bfd_subnet_idx;
	int		del_flag = 0;
	int		pipm_type;
	int		none_cnt;
	int		other_cnt;
	int		bfd_cnt;

	if( pipm_enable == FALSE )
	{
		return IPM_SUCCESS;
	}
	
	if ( type != IPM_ADD_EXT_SUBNET &&
		type != IPM_DEL_EXT_SUBNET &&
		type != IPM_ADD_INT_SUBNET &&
		type != IPM_DEL_INT_SUBNET )
	{
		return IPM_INVALIDPARAMETER;
	}

	if ( type == IPM_ADD_EXT_SUBNET || type == IPM_DEL_EXT_SUBNET )
	{
		intf_type = IPM_SUBNET_EXTERNAL;
	}
	else
	{
		intf_type = IPM_SUBNET_INTERNAL;
	}

	if ( type == IPM_DEL_EXT_SUBNET || type == IPM_DEL_INT_SUBNET )
	{
		del_flag = 1;
	}

	if ( (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_INVALID && !del_flag )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s failure: invalid redundancy mode %d\n",
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
			"%s failure: invalid subnet request %d\n",
			__FUNCTION__,
			request
                );

                LOG_ERROR(0, resp);
                return IPM_INVALIDPARAMETER;
	}

	if ( cmd_subnet_upd_ptr->dev_t[0].dev_if[0] != 0 )
	{
		if ( !(cmd_subnet_upd_ptr->dev_t[1].subnet_type == IPM_SUBNET_EXTERNAL ||
			cmd_subnet_upd_ptr->dev_t[1].subnet_type == IPM_SUBNET_INTERNAL) )
		{
			snprintf(
				resp, REPLY_TEXT,
				"%s failure: %s interface is not external or internal\n",
				__FUNCTION__,
				cmd_subnet_upd_ptr->dev_t[1].dev_if
			);

			LOG_ERROR(0, resp);
			return IPM_INVALIDPARAMETER;
		}
	}

	strncpy(iface0_base, cmd_subnet_upd_ptr->dev_t[0].dev_if, MAX_NLEN_DEV);
	iface0_base_ptr = strtok(iface0_base, ":");
	if ( iface0_base_ptr == NULL )
	{
		iface0_base_ptr = iface0_base;
	}

	if ( cmd_subnet_upd_ptr->dev_t[1].dev_if[0] != 0 )
	{
		if ( !(cmd_subnet_upd_ptr->dev_t[1].subnet_type == IPM_SUBNET_EXTERNAL ||
			cmd_subnet_upd_ptr->dev_t[1].subnet_type == IPM_SUBNET_INTERNAL) )
		{
			snprintf(
				resp, REPLY_TEXT,
				"%s failure: %s interface is not external or internal\n",
				__FUNCTION__,
				cmd_subnet_upd_ptr->dev_t[1].dev_if
			);

			LOG_ERROR(0, resp);
			return IPM_INVALIDPARAMETER;
		}
	}

	strncpy(iface1_base, cmd_subnet_upd_ptr->dev_t[1].dev_if, MAX_NLEN_DEV);
	iface1_base_ptr = strtok(iface1_base, ":");
	if ( iface1_base_ptr == NULL )
	{
		iface1_base_ptr = iface1_base;
	}
	
	/* Check for PIPM memory */
	if( PIPM_shm_ptr == NULL )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s failure: Shared memory null, <%s>/<%d> gateway %s primary iface %s secondary iface %s\n",
			__FUNCTION__,
			cmd_subnet_upd_ptr->subnet_base,
                        cmd_subnet_upd_ptr->prefix,
                        ( cmd_subnet_upd_ptr->gateway[0] != 0 ? cmd_subnet_upd_ptr->gateway : "empty" ),
                        ( cmd_subnet_upd_ptr->dev_t[0].dev_if[0] != 0 ? cmd_subnet_upd_ptr->dev_t[0].dev_if : "empty" ),
                        ( cmd_subnet_upd_ptr->dev_t[1].dev_if[0] != 0 ? cmd_subnet_upd_ptr->dev_t[1].dev_if : "empty" )
		);

		LOG_ERROR(0, resp);

		return IPM_FAILURE;
	}

	data_ptr = (PIPM_DATA *)PIPM_shm_ptr;

	/* subnet base ip */
	IPM_ipaddr_init(&subnet_base);
	ipm_retval = IPM_p2ipaddr(cmd_subnet_upd_ptr->subnet_base, &subnet_base);
	if ( ipm_retval != IPM_SUCCESS )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s failure: invalid subnet base IP address %s\n",
			__FUNCTION__,
			cmd_subnet_upd_ptr->subnet_base
		);

		LOG_ERROR(0, resp);
		return ipm_retval;
	}

	/* subnet mask */
	IPM_ipaddr_init(&subnet_mask);
	ipm_retval = IPM_ipmkmask( &subnet_mask, subnet_base.addrtype, cmd_subnet_upd_ptr->prefix );
	if ( ipm_retval != IPM_SUCCESS )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s failure: failed to create subnet mask for %s/%d\n",
			__FUNCTION__,
			cmd_subnet_upd_ptr->subnet_base,
			cmd_subnet_upd_ptr->prefix
		);

		LOG_ERROR(0, resp);
		return ipm_retval;
	}

	/* gateway */
	IPM_ipaddr_init(&gateway);
	if ( cmd_subnet_upd_ptr->gateway[0] != 0 )
	{
		ipm_retval = IPM_p2ipaddr(cmd_subnet_upd_ptr->gateway, &gateway);
		if ( ipm_retval != IPM_SUCCESS )
		{
			snprintf(
				resp, REPLY_TEXT,
				"%s failure: invalid gateway IP address %s\n",
				__FUNCTION__,
				cmd_subnet_upd_ptr->gateway
			);

			LOG_ERROR(0, resp);
			return ipm_retval;
                }
	}

	/* look for matching interface */
	for (	intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
		intf_idx < data_ptr->intf_cnt;
		intf_idx++, intf_ptr++ )
	{
		upd_shared_memory = 0;
		intf_action = PIPM_intf_match(
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
	
		for ( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
			subnet_idx < intf_ptr->subnet_cnt;
			subnet_idx++, subnet_ptr++ )
 	       {
			if ( IPM_IPCMPADDR(&subnet_ptr->subnet_base, &subnet_base) == IPM_SUCCESS )
			{
				if ( subnet_ptr->prefixlen == cmd_subnet_upd_ptr->prefix )
				{
					if ( type == IPM_ADD_EXT_SUBNET || type == IPM_ADD_INT_SUBNET )
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

						if ( strlen(cmd_subnet_upd_ptr->gateway) > 0 )
						{
							if ( IPM_IPCMPADDR(&subnet_ptr->gateway, &gateway ) != IPM_SUCCESS )
							{
								memset(gateway_addr, 0, sizeof(gateway_addr));
								IPM_ipaddr2p(&subnet_ptr->gateway, gateway_addr, IPM_IPMAXSTRSIZE);

								snprintf( resp, REPLY_TEXT,
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
						subnet_ptr->gateway 		= gateway;
						subnet_ptr->redundancy_mode	= cmd_subnet_upd_ptr->redundancy_mode;

						if ( upd_shared_memory )
						{
							/* base interface */
							struct cmd_base_iface base_iface;

							memset(&base_iface, 0, sizeof(base_iface));

							strncpy(base_iface.base_if[0], iface0_base_ptr, MAX_NLEN_DEV);
							strncpy(base_iface.base_if[1], iface1_base_ptr, MAX_NLEN_DEV);

							base_iface.subnet_type = intf_type;
							base_iface.redundancy_mode = (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode;

							pipm_type = ( type == IPM_ADD_EXT_SUBNET ? IPM_ADD_EXT_ALIAS : IPM_ADD_INT_ALIAS );
							ret = PIPM_base_update(&base_iface, pipm_type, resp);

							if ( ret != IPM_SUCCESS )
							{
								snprintf(resp, REPLY_TEXT,
									"%s failed: Failed to add base interface for lsn0 %s lsn1 %s for %s/%d, gateway %s\n",
									__FUNCTION__,
									( strlen( iface0_base_ptr ) > 0 ? iface0_base_ptr : "empty" ),
									( strlen( iface1_base_ptr ) > 0 ? iface1_base_ptr : "empty" ),
									cmd_subnet_upd_ptr->subnet_base,
									cmd_subnet_upd_ptr->prefix,
									( cmd_subnet_upd_ptr->gateway[0] != 0 ? cmd_subnet_upd_ptr->gateway : "empty" )
								);

								LOG_DEBUG(0, resp);

								return ret;
							}
						} /* update shared memory */
					}
					else
					{
						IPM_REDUNDANCY_MODE redundancy_mode = IPM_RED_INVALID;

						if ( request == CLI_REQUEST  && subnet_ptr->arp_resp_ip_cnt > 0)
						{
							subnet_ptr->delete_flag = TRUE;
							return IPM_SUCCESS;
						}


						/* remove any remaining paths before removing the subnet */
						for ( path_idx = 0, path_ptr = &subnet_ptr->path[0];
							path_idx < subnet_ptr->path_cnt;
							path_idx++, path_ptr++ )
						{
							if( (path_ptr->type != PIPM_GATEWAY_PATH) && (path_ptr->type != PIPM_PROXY_PATH) )
							{
								ret = PIPM_send_routemsg( PIPM_DEL_ROUTE, path_ptr, intf_ptr );
								if( ret != IPM_SUCCESS )
								{
									LOG_ERROR( 0, "Error: PIPM_send_routemsg failed ret [%d]", ret );
								}
							}
	
							ret = PIPM_send_ipmsgpath_update( PIPM_DEL_PATH, 
											  (uint32_t)0, 
											  path_ptr,
											  subnet_ptr, 
											  intf_ptr,
											  PIPM_BASE_INTF  );

							if( ret != IPM_SUCCESS )
							{
								LOG_ERROR( 0, "Error: PIPM_send_ipmsgpath_update failed ret [%d]", ret );
							}

#if defined (_X86)
							if ( path_ptr->vlanId == 0 )
							{
								if (path_ptr->lsn0_arpsock >= 0)
								{
									close(path_ptr->lsn0_arpsock);
								}
								if (path_ptr->lsn1_arpsock >= 0)
								{
									close(path_ptr->lsn1_arpsock);
								}
							}
#endif
							memset(path_ptr, 0, sizeof(*path_ptr));

#if defined (_X86)
							if ( path_ptr->vlanId == 0 )
							{
								path_ptr->lsn0_arpsock = -1;
								path_ptr->lsn1_arpsock = -1;
								path_ptr->lsn0_iface_indx = -1;
								path_ptr->lsn1_iface_indx = -1;
							}
#endif
						}

						subnet_ptr->path_cnt = 0;
						
						/* remove the subnet information */
						intf_ptr->subnet_cnt--;
						redundancy_mode = (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode;
						for ( delete_idx = subnet_idx, cur_ptr = subnet_ptr,
							next_ptr = &intf_ptr->subnet[subnet_idx + 1];
							delete_idx < intf_ptr->subnet_cnt;
							delete_idx++, cur_ptr++, next_ptr++ )
						{
							*cur_ptr = *next_ptr;
						}

						memset( cur_ptr, 0, sizeof(*cur_ptr) );

						if ( redundancy_mode == IPM_RED_BFD_TRANSPORT )
						{
							int idx = 0;

							if ( strlen(iface0_base_ptr ) > 0 )
							{
								/* check if bfd transports or subnets */
								for ( idx = 0, bfd_subnet_ptr = &intf_ptr->subnet[0];
									idx < intf_ptr->subnet_cnt;
									idx++, bfd_subnet_ptr++ )
								{
									if ( ( (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD ||
                                                                               (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR ) &&
										bfd_subnet_ptr->subnet_base.addrtype == subnet_ptr->subnet_base.addrtype )
									{
										memset(&bfd_subnet_ptr->gateway, 0, sizeof(IPM_IPADDR));
									}
								}
							}
						}

						if ( intf_ptr->subnet_cnt == 0 )
						{
							/* remove the interface */
							struct cmd_base_iface base_iface;

							memset(&base_iface, 0, sizeof(base_iface));

							strncpy(base_iface.base_if[0], iface0_base_ptr, MAX_NLEN_DEV);
							strncpy(base_iface.base_if[1], iface1_base_ptr, MAX_NLEN_DEV);

							base_iface.subnet_type = intf_type;
							base_iface.redundancy_mode = redundancy_mode;

							pipm_type = ( type == IPM_DEL_EXT_SUBNET ? IPM_DEL_EXT_ALIAS : IPM_DEL_INT_ALIAS );
							ret = PIPM_base_update(&base_iface, pipm_type, resp);

							if ( ret != IPM_SUCCESS )
							{
								snprintf(resp, REPLY_TEXT,
									"%s(): Failed to delete base lsn0 %s, lsn1 %s for %s/%d",
									__FUNCTION__,
									( strlen( iface0_base_ptr ) > 0 ? iface0_base_ptr : "empty" ),
									( strlen( iface1_base_ptr ) > 0 ? iface1_base_ptr : "empty" ),
									cmd_subnet_upd_ptr->subnet_base,
									cmd_subnet_upd_ptr->prefix
								);

								LOG_DEBUG(0, resp);

								return ret;
							}
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

										/* update shared memory */
										if ( !num_subnets && num_transports )
										{
											memset(intf_ptr->lsn1_baseif, 0, sizeof(intf_ptr->lsn1_baseif));
										}
									} /* loop through subnets on interface */
								} /* if interface has duplex interface */
							}  /* check if last duplex interface to delete */
						}
					} /* delete case */

					return IPM_SUCCESS;
				} /* subnet prefix match */
			} /* subnet base match */
		} /* search for subnet match */

		/* no match for subnet */
		if ( type == IPM_ADD_EXT_SUBNET || type == IPM_ADD_INT_SUBNET )
		{
			none_cnt = 0;
			other_cnt = 0;
			bfd_cnt = 0;
	
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
				(IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode == IPM_RED_BFD_RSR ) &&
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

			if( intf_ptr->subnet_cnt >= PIPM_MAX_SUBNETS )
			{
				snprintf(resp, REPLY_TEXT,
					"%s() failure: The PIPM subnet limitation(%d) is reached\n",
					__FUNCTION__, PIPM_MAX_SUBNETS);
				ASRT_RPT( ASBAD_DATA, 0, "The PIPM subnet limitation(%d) is reached", PIPM_MAX_SUBNETS);
				return IPM_FAILURE;
			}

			/* subnet info */
			subnet_ptr = &intf_ptr->subnet[intf_ptr->subnet_cnt];

			memset(subnet_ptr, 0, sizeof(*subnet_ptr));

			subnet_ptr->subnet_base			= subnet_base;
			subnet_ptr->prefixlen			= cmd_subnet_upd_ptr->prefix;
			subnet_ptr->path_cnt			= 0;
			subnet_ptr->gateway			= gateway;
			subnet_ptr->redundancy_mode		= cmd_subnet_upd_ptr->redundancy_mode;
			subnet_ptr->arp_resp_ip_indx		= 0;
			if(intf_type == IPM_SUBNET_EXTERNAL)
			{
				subnet_ptr->table_num		= cmd_subnet_upd_ptr->table_num;
			}

			intf_ptr->subnet_cnt++;

			PIPM_open_arpsock( &(intf_ptr->specData), subnet_ptr->subnet_base.addrtype );

			if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
			{
				if ( strlen( iface0_base_ptr ) > 0 )
				{
					for ( bfd_subnet_idx = 0, bfd_subnet_ptr = &intf_ptr->subnet[0];
                        			bfd_subnet_idx < intf_ptr->subnet_cnt;
                        			bfd_subnet_idx++, bfd_subnet_ptr++ )
					{
						if ( ( (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD || 
                                                       (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR ) &&
							subnet_ptr->subnet_base.addrtype == bfd_subnet_ptr->subnet_base.addrtype )
						{
							bfd_subnet_ptr->gateway = gateway;
							(void) PIPM_update_subnet_ip( bfd_subnet_ptr, intf_ptr );
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
						if ( bfd_subnet_ptr->arp_resp_ip_cnt > 0 )
						{
							subnet_ptr->gateway = bfd_subnet_ptr->gateway;

							ret = PIPM_send_ipmsgpath_update( PIPM_UPDATE_PATH, 
											  (uint32_t)0, 
											  &bfd_subnet_ptr->path[0],
											  bfd_subnet_ptr, 
											  intf_ptr,
											  PIPM_BASE_INTF  );
							if( ret != IPM_SUCCESS )
							{
								LOG_ERROR( 0, "Error: PIPM_send_ipmsgpath_update failed ret [%d]", ret );
							}
						}
						break;
					}
				}
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
	} /* interface search */

	/* if delete and come here, need return success */
	if ( type == IPM_DEL_EXT_SUBNET  || type == IPM_DEL_INT_SUBNET )
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s() failure: lsn0 interface [%s], lsn1 interface [%s], %s/%d no match",
			__FUNCTION__,
			( strlen( iface0_base_ptr ) > 0 ? cmd_subnet_upd_ptr->dev_t[0].dev_if : "empty" ),
			( strlen( iface1_base_ptr ) > 0 ? cmd_subnet_upd_ptr->dev_t[1].dev_if : "empty" ),
			cmd_subnet_upd_ptr->subnet_base,
			cmd_subnet_upd_ptr->prefix
		);

		LOG_DEBUG(0, resp);
		return IPM_SUCCESS;
	}

	/* no interface match */
	/* base interface */
	struct cmd_base_iface base_iface;

	memset(&base_iface, 0, sizeof(base_iface));

	strncpy(base_iface.base_if[0], iface0_base_ptr, MAX_NLEN_DEV);
	strncpy(base_iface.base_if[1], iface1_base_ptr, MAX_NLEN_DEV);

	base_iface.subnet_type = intf_type;
	base_iface.redundancy_mode = (IPM_REDUNDANCY_MODE) cmd_subnet_upd_ptr->redundancy_mode;

	pipm_type = ( type == IPM_ADD_EXT_SUBNET ? IPM_ADD_EXT_ALIAS : IPM_ADD_INT_ALIAS );
	ret = PIPM_base_update(&base_iface, pipm_type, resp);

	if ( ret != IPM_SUCCESS )
	{
		snprintf(resp, REPLY_TEXT,
			"%s failure: failed to add base lsn0 %s, lsn1 %s for %s/%d, gateway %s",
			__FUNCTION__,
			( strlen( iface0_base_ptr ) > 0 ? iface0_base_ptr : "empty" ),
			( strlen( iface1_base_ptr ) > 0 ? iface1_base_ptr : "empty" ),
			cmd_subnet_upd_ptr->subnet_base,
			cmd_subnet_upd_ptr->prefix,
			( cmd_subnet_upd_ptr->gateway[0] != 0 ? cmd_subnet_upd_ptr->gateway : "empty" )
		);

		LOG_DEBUG(0, resp);

		return ret;
	}

	/* subnet info */
	subnet_ptr = &intf_ptr->subnet[0];

	memset(subnet_ptr, 0, sizeof(*subnet_ptr));

	subnet_ptr->subnet_base		= subnet_base;
	subnet_ptr->prefixlen		= cmd_subnet_upd_ptr->prefix;
	subnet_ptr->path_cnt		= 0;
	subnet_ptr->gateway		= gateway;
	subnet_ptr->redundancy_mode	= cmd_subnet_upd_ptr->redundancy_mode;
	if(intf_type == IPM_SUBNET_EXTERNAL)
	{
		subnet_ptr->table_num	= cmd_subnet_upd_ptr->table_num;
	}

	intf_ptr->subnet_cnt            = 1;

	PIPM_open_arpsock( &(intf_ptr->specData), subnet_ptr->subnet_base.addrtype );

	/* path info for bfd transport */
	if ( (IPM_REDUNDANCY_MODE) subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
	{
		if ( strlen( iface0_base_ptr ) > 0 )
		{
			for ( bfd_subnet_idx = 0, bfd_subnet_ptr = &intf_ptr->subnet[0];
                		bfd_subnet_idx < intf_ptr->subnet_cnt;
                        	bfd_subnet_idx++, bfd_subnet_ptr++ )
			{
				if ( ( (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD ||
                                       (IPM_REDUNDANCY_MODE) bfd_subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR) &&

					subnet_ptr->subnet_base.addrtype == bfd_subnet_ptr->subnet_base.addrtype )
				{
					bfd_subnet_ptr->gateway = gateway;
					(void) PIPM_update_subnet_ip( bfd_subnet_ptr, intf_ptr );
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
				if ( bfd_subnet_ptr->arp_resp_ip_cnt > 0 )
				{
					subnet_ptr->gateway = bfd_subnet_ptr->gateway;

					ret = PIPM_send_ipmsgpath_update( PIPM_UPDATE_PATH,
									  (uint32_t)0, 
									  &bfd_subnet_ptr->path[0],
									  bfd_subnet_ptr, 
									  intf_ptr,
									  PIPM_BASE_INTF  );
					if( ret != IPM_SUCCESS )
					{
						LOG_ERROR( 0, "Error: PIPM_send_ipmsgpath_update failed ret [%d]", ret );
					}
				}
				break;
			}
		}
	}

	return IPM_SUCCESS;
}

/**********************************************************************
 *
 * Name:        PIPM_intf_match()
 *
 * Abstract:    match the interface
 *
 * Description:
**********************************************************************/
INTF_ACTION PIPM_intf_match(
	PIPM_INTF *intf_ptr,
	char *iface0_base_ptr,
	char *iface1_base_ptr,
	int type,
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

			if ( type == IPM_ADD_EXT_SUBNET || type == IPM_ADD_INT_SUBNET )
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
 * Name:        PIPM_set_subnet()
 *
 * Abstract:    Update table number value and notify path module
 *		the updated spbr on/off flag
 *
 * Description:
**********************************************************************/
int PIPM_set_subnet(
	struct cmd_subnet_upd * cmd_subnet_upd_ptr,
	char *resp
)
{
	PIPM_DATA 	*data_ptr;
	PIPM_INTF	*intf_ptr;
	PIPM_SUBNET	*subnet_ptr;
	IPM_IPADDR	subnet_mask;
	IPM_IPADDR	subnet_base;
	IPM_RETVAL	ipm_retval;
	int		retval;


	int		intf_idx;
	int		subnet_idx;

	if(PIPM_shm_ptr ==  NULL)
	{
		snprintf(
			resp, REPLY_TEXT,
			"%s failure: Shared memory null, <%s>/<%d> primary iface %s secondary iface %s\n",
			__FUNCTION__,
			cmd_subnet_upd_ptr->subnet_base,
                        cmd_subnet_upd_ptr->prefix,
                        ( cmd_subnet_upd_ptr->dev_t[0].dev_if[0] != 0 ? cmd_subnet_upd_ptr->dev_t[0].dev_if : "empty" ),
                        ( cmd_subnet_upd_ptr->dev_t[1].dev_if[0] != 0 ? cmd_subnet_upd_ptr->dev_t[1].dev_if : "empty" )
		);

		LOG_ERROR(0, resp);

		return IPM_FAILURE;
	}

	data_ptr = (PIPM_DATA *) PIPM_shm_ptr;

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

	for(intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
		intf_idx < data_ptr->intf_cnt;
		intf_idx++, intf_ptr++)
	{

		if(intf_ptr->subnet_cnt == 0 || PIPM_INTERNAL_INTF == intf_ptr->type)
		{
			//Only external interfaces support SBPR 
			continue;
		}

		for(subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
			subnet_idx < intf_ptr->subnet_cnt;
			subnet_idx++, subnet_ptr++)
		{
			if((IPM_IPCMPADDR(&subnet_ptr->subnet_base, &subnet_base) != IPM_SUCCESS) ||
				(subnet_ptr->prefixlen != cmd_subnet_upd_ptr->prefix))
			{
				continue;
			}
			//find the matched subnet
			//table number 255 means NO need to update table number
			if(cmd_subnet_upd_ptr->table_num != 255 &&
				subnet_ptr->table_num != cmd_subnet_upd_ptr->table_num)
			{
				subnet_ptr->table_num = cmd_subnet_upd_ptr->table_num;
				retval = PIPM_update_subnet_ip(subnet_ptr, intf_ptr);
				if(retval != IPM_SUCCESS)
				{
					snprintf(resp, REPLY_TEXT,
						"%s(): PIPM_update_subnet_ip failed [%d]\n",
						__FUNCTION__, retval);
					LOG_FORCE(0, resp);
					return retval;
				}
			}
			return IPM_SUCCESS;
		}
	}

	return IPM_SUCCESS;

}
