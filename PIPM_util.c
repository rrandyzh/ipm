/**********************************************************************
 *
 * File:
 *	PIPM_util.c
 *
 * Functions in this file:
 *	PIPM_dumpshm()      - Go through internal data and log it.
 *	PIPM_path_update()  - Called when an operation on a path opertion is
 *	PIPM_send_routemsg() - Called for a route operation
 *	PIPM_send_ipmsg()    - Called for a ip operation
 *	PIPM_send_ipmsgpath_update()  - Format a message to send to 
 *					the IP Message Path Kernel Module
 *	PIPM_openippathmgt() - open a fd for ip path management kernel module
 *	PIPM_sendIPMKpathmgt() - Send a message to the IP Message Path Kernel Module
 *	PIPM_process_route_update() - process route updates
 *      PIPM_findIntf - Searches for a matching inteface.
 *
 **********************************************************************/

#if defined (_X86)
#define _GNU_SOURCE
#include <netinet/in.h>
#endif

#include "PIPM_include.h"
#include <fcntl.h>

/**********************************************************************
 *
 * Name:	PIPM_dumpshm()
 *
 * Abstract:	Loop through all data that has been provisioned
 *		and log it.
 *
 * Parameters:	None
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int PIPM_dumpshm( )
{
	register PIPM_INTF	*data_ptr;
	register PIPM_SUBNET	*subn_ptr;
	char			prt_line[300];
	char			prt_buf[300 * PIPM_PRT_LINES];
	char			ipbuf[ IPM_IPMAXSTRSIZE ];
	char			ipbuf2[ IPM_IPMAXSTRSIZE ];
	char			ipbuf3[ IPM_IPMAXSTRSIZE ];
	int			intf;
	int			subn;
	int			path_cnt;
	int			arp_resp_ip_cnt;
	int			cnt_to_prt;
	int                     pipm_size=0;
	
	/*
	 * Make sure we are attached to shared memory segment.
	 */
	if( PIPM_shm_ptr == NULL )
	{
		/*
		 * Fire an assert.
		 */
		ASRT_RPT( ASMISSING_DATA,
		          2,
		          sizeof( PIPM_shm_ptr ),
			  &PIPM_shm_ptr,
			  sizeof( PIPM_shmid ),
			  &PIPM_shmid,
		          "PIPM_dumpshm: PIPM not attached to shared memory segment\n" );
		
		return( IPM_FAILURE );
	}
	
	pipm_size = sizeof(PIPM_DATA)/(1024*1024);
	LOG_FORCE(0, "PIPM_dumpshm: the size of PIPM_DATA:(%d)M\n",pipm_size);

	LOG_FORCE( 0,
       	         "PIPM - Interface data dump, intf cnt %d\n",
	         ((PIPM_DATA *)PIPM_shm_ptr)->intf_cnt );

	memset( &ipbuf, 0, sizeof(ipbuf) );
	memset( &ipbuf2, 0, sizeof(ipbuf2) );

	LOG_FORCE( 0,
       	         "PIPM - L2 path enable = %d\n", pipm_l2_path_enable );

	/*
	 * Loop through shared segment.
	 */
	for( intf = 0, data_ptr = &((PIPM_DATA *)PIPM_shm_ptr)->intf_data[ 0 ];
	     intf < ((PIPM_DATA *)PIPM_shm_ptr)->intf_cnt; 
	     intf++, data_ptr++ )
	{
		/*
		 * Print out data for this interface.
		 */
		LOG_FORCE( 0,
	       	         "PIPM - Interface data dump, intf %d, type %d Name %s-%s\n, subnet_cnt=%d\n",
		         intf,
			 data_ptr->type,
		         data_ptr->lsn0_baseif,
		         data_ptr->lsn1_baseif,
		         data_ptr->subnet_cnt );
		
			
		/*
		 * Now loop through all of the subnets on this
		 * interface and print that data.
		 */
		for( subn = 0, subn_ptr = &(data_ptr->subnet[0]);
		     subn < data_ptr->subnet_cnt;
		     subn++, subn_ptr++ )
		{
			/*
			 * Print out the high level data for this
			 * subnet.
			 */
			LOG_FORCE( 0,
		       	         "PIPM - Intf %d, subnet %d, subnet=%s/%d, delete_flag(%d)\narp_resp_ip_cnt=%d path_cnt=%d, table_num=%d\n",
			         intf,
			         subn,
				 IPM_chkipaddr2p(&subn_ptr->subnet_base, ipbuf, sizeof(ipbuf)),
			         subn_ptr->prefixlen,
				 subn_ptr->delete_flag,
				 subn_ptr->arp_resp_ip_cnt,
			         subn_ptr->path_cnt,
				 subn_ptr->table_num );
		

			for( arp_resp_ip_cnt = 0; arp_resp_ip_cnt < subn_ptr->arp_resp_ip_cnt; arp_resp_ip_cnt++ )
			{
				LOG_FORCE( 0,
			       	         "PIPM - arp response ip [%d] = %s\n",
					 arp_resp_ip_cnt,
					 IPM_chkipaddr2p(&(subn_ptr->arp_resp_ip[arp_resp_ip_cnt]), ipbuf, sizeof(ipbuf)));
			}

			/*
			 * Loop to print all of the IPs on this subnet.
			 */
			cnt_to_prt = -1;
			for( path_cnt = 0; path_cnt < subn_ptr->path_cnt; path_cnt++ )
			{
 				/*
				 * Buffer PIPM_PRT_LINES lines of IP
				 * data before printing.
				 */

				sprintf( prt_line,
                                         "PIPM - Intf %d, subnet %d, path %d, type=%d\n" 
					 "\tlsn0_arpsock=%d, lsn1_arpsock=%d, lsn0_iface_indx=%d, lsn1_iface_indx=%d, inner vlan=%d, vlanId=%d\n"
					 "\tdest=%s/%d,\tnexthop=%s,\tintFloatIP=%s\n",
				         intf,
				         subn,
				         path_cnt,
					 subn_ptr->path[path_cnt].type,
					 subn_ptr->path[path_cnt].lsn0_arpsock,
					 subn_ptr->path[path_cnt].lsn1_arpsock,
					 subn_ptr->path[path_cnt].lsn0_iface_indx,
					 subn_ptr->path[path_cnt].lsn1_iface_indx,
					subn_ptr->path[path_cnt].inner_vlan,
					 subn_ptr->path[path_cnt].vlanId,
					 IPM_chkipaddr2p(&subn_ptr->path[path_cnt].dest, ipbuf, sizeof(ipbuf)),
					 subn_ptr->path[path_cnt].destprefix,
					 IPM_chkipaddr2p(&subn_ptr->path[path_cnt].nexthop, ipbuf2, sizeof(ipbuf2)),
					IPM_chkipaddr2p(&subn_ptr->path[path_cnt].intFloatIP, ipbuf3, sizeof(ipbuf3)));
				
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
				
				if( cnt_to_prt >= (PIPM_PRT_LINES - 1) )
				{
					/*
					 * We have accumulated
					 * PIPM_PRT_LINES in the buffer.
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
			
		} /* end 'for each subnet' */
		
	} /* end 'for each interface' */

	/* Temorary: Dump all the extension interfaces' data as well. */
        if ( ((PIPM_DATA *)PIPM_shm_ptr)->extnIntfCount > 0 )
        {
               PIPM_dumpExtnIntfData( 0, ((PIPM_DATA *)PIPM_shm_ptr)->extnIntfCount ); 
        }
	
	return( IPM_SUCCESS );
}

#define PIPM_LINE_BUFF_SIZE     60

/**********************************************************************
 *
 * Name:	PIPM_dumpExtnIntfData.
 *
 * Abstract:	Logs extension interfaces' data for the specified range.
 *
 * Parameters:	minIdx - Lower value of the range to log.
 *              maxIdx - Upper value of the range to log.
 *
 * Returns:	None.
 *
 **********************************************************************/

void PIPM_dumpExtnIntfData( int minIdx, int maxIdx )
{

        PIPM_DATA       *dataP;
        PIPM_INTF       *intfDataP;
        PIPM_INTF_SPEC  *intfSpecDataP;
        char            logBuff[UMAX_LOG_SIZE];
        char            lineBuff[PIPM_LINE_BUFF_SIZE];
        char            *logBuffPosP;
        char            intfStatusStr[20];
        char		lsnSideStr[20];

        if ( NULL == PIPM_shm_ptr )
	{
		ASRT_RPT( ASMISSING_DATA,
		          2,
		          sizeof( PIPM_shm_ptr ),
			  &PIPM_shm_ptr,
			  sizeof( PIPM_shmid ),
			  &PIPM_shmid,
		          "PIPM not attached to shared memory segment\n",
                          (char *)(__func__) );
		
		return;
	}

        dataP = (PIPM_DATA *)PIPM_shm_ptr;
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
                                "### PIPM EXTN INTF DUMP (%d thru %d, Count: %d) ###\n\n",
                                minIdx, maxIdx, dataP->extnIntfCount );

        /* -- Log the extension interfaces' data. -- */
        for ( ( intfSpecDataP = &(dataP->extnIntfData[minIdx]) );
              ( minIdx <= maxIdx );
              ( minIdx++, intfSpecDataP++ )  )
        {
                if ( !PIPM_IS_VALID_BASE_INTF_IDX( intfSpecDataP->baseIntfIdx ) )
                {
                        intfDataP = NULL;
                }
                else
                {
                        intfDataP = &(dataP->intf_data[intfSpecDataP->baseIntfIdx]);
                }

                if ( PIPM_LINE_BUFF_SIZE > ( UMAX_LOG_SIZE - ( logBuffPosP - logBuff - 1 ) ) )
                {
                        /* Reached the buffer limit. Log whatever's in it first. */
                        LOG_FORCE( 0, logBuff );

                        /* Reset the buffer and position pointer. */
                        logBuff[0] = '\0';
                        logBuffPosP = logBuff;
                }

                logBuffPosP += snprintf( logBuffPosP, PIPM_LINE_BUFF_SIZE,
                                         "Idx: %d BaseIdx: %d Name: %s%s-%s%s\n",
                                         minIdx,
                                         intfSpecDataP->baseIntfIdx,
                                         ( intfDataP ? intfDataP->lsn0_baseif : "ERR" ),
                                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
                                         ( intfDataP ? intfDataP->lsn1_baseif : "ERR" ),
                                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

        } /* end 'extension interfaces loop' */

	LOG_FORCE( 0, logBuff );

} /* end 'PIPM_dumpExtnIntfData' */

/**********************************************************************
 *
 * Name:        PIPM_get_extension_interface_index()
 *
 * Abstract:    Get externsion interface index by base interface index and vlan Id
 *
 * Parameters:  baseIntfIdx   -  base interface index
 *              vlanId    - vlan id
 *
 * Returns:     >=0 - the good extension interface index, -1 - failed
 *
 **********************************************************************/
int PIPM_get_extension_interface(short baseIntfIdx, unsigned short vlanId)
{
	PIPM_DATA       *dataP;
	PIPM_INTF_SPEC  *intfSpecDataP;
	int             extnIntfIdx;
	dataP = (PIPM_DATA *)PIPM_shm_ptr;
	if ( dataP  == NULL )
	{
		LOG_FORCE( 0, "PIPM_get_extension_interface, PIPM_shm_ptr is NULL\n");
		return (-1);
	}

	if ( !PIPM_IS_VALID_BASE_INTF_IDX( baseIntfIdx ) )
	{
		LOG_FORCE( 0, "PIPM_get_extension_interface, invalid baseIntfIdx(%d)\n", baseIntfIdx);
		return (-1);
	}	

	if ( ( vlanId < 1) || ( vlanId > 4095 ) )
	{
		LOG_FORCE( 0, "PIPM_get_extension_interface, invalid vlanId(%d)\n", vlanId);
		return (-1);
	}	
	
	for ( extnIntfIdx = 0, intfSpecDataP = &(dataP->extnIntfData[0]);
		extnIntfIdx < dataP->extnIntfCount;
		extnIntfIdx++, intfSpecDataP++ )
	{
		if ( ( intfSpecDataP->baseIntfIdx == baseIntfIdx ) &&
			( intfSpecDataP->vlanId == vlanId ) )
		{
			return (extnIntfIdx);
		}
	}
	LOG_FORCE( 0, "PIPM_get_extension_interface, Failed to find externsion interface index by baseIntfIdx(%d) and vlanId(%d)\n", baseIntfIdx, vlanId);
	return (-1);
}

/**********************************************************************
 *
 * Name:	PIPM_path_update()
 *
 * Abstract:	Called when a change in the path data occurs.
 *
 * Parameters:	action   - whether adding or deleting 
 *		resp    - pointer to text string response to user
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int PIPM_path_update( PIPM_PATH_ACTION action, PIPM_PATH *path_ptr, PIPM_SUBNET *subnet_ptr, 
		      void *intfDataP, PIPM_INTF_TYPE_EXT intfTypeExt)
{
	PIPM_INTF *intf_ptr;
        PIPM_INTF_SPEC *intfSpecDataP;
	int ret;
	EIPM_NET act_intf;
	unsigned short vlanId=0;

	if( pipm_enable == FALSE )
	{
		return IPM_SUCCESS;
	}

	PIPM_SET_INTF_PTRS( intfDataP, intfTypeExt , intf_ptr, intfSpecDataP );

	if ( NULL == intf_ptr )
        {
                return IPM_FAILURE;
        }

	if ( intfTypeExt == PIPM_EXTN_INTF )
	{
		 vlanId = intfSpecDataP->vlanId;
	}


	ret = PIPM_send_ipmsgpath_update( action, 
                                          PIPM_NULL_PATH_INTF, 
                                          path_ptr, 
                                          subnet_ptr,
                                          ( ( PIPM_BASE_INTF == intfTypeExt ) ? intf_ptr : intfSpecDataP ),
                                          intfTypeExt );

	if( ret != IPM_SUCCESS )
	{
	    LOG_ERROR( 0, "Error: PIPM_path_update failed ret [%d]", ret );
	    path_ptr->resend_path_cnt = PIPM_RETRY_PATH_SEND_CNT;
	}
	
        if( action == PIPM_ADD_PATH ||
            action == PIPM_REFRESH_PATH )
	{
            /*
             * Set resending counter for this path and it will be
             * reset to 0 once ARP/NS is sent successfully
             * Otherwise, it will re-try to send ARP/NS for this path
             * after resend_path_cnt is decreased into 1
             */
            path_ptr->resend_path_cnt = PIPM_RETRY_PATH_SEND_CNT;

            /*
  	     * For external paths, only send ARP/NS out only the active interface.
	     * For internal paths, send on both interfaces.
 	     */
	    if( intf_ptr->type == PIPM_EXTERNAL_INTF )
	    {
		if( subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD ||
                    subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR )
		{
		    return IPM_SUCCESS;
		}
		else if ( subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
		{
		    if( strlen(intf_ptr->lsn0_baseif) > 0 )
		    {
			act_intf = LSN0;
		    }
		    else if( strlen(intf_ptr->lsn1_baseif) > 0 )
		    {
			act_intf = LSN1;				
		    }
		    else
		    {
			act_intf = LSN_NONE;
		    }
		}
		else
		{
		    ret = EIPM_get_intf_to_nexthop( intf_ptr->lsn0_baseif, 
						    intf_ptr->lsn1_baseif, 
						    &path_ptr->nexthop, 
						    &act_intf,
						    vlanId);
		
		    if( ret != IPM_SUCCESS )
		    {
		        LOG_ERROR( 0,
			      	   "PIPM_sendIPMKpathmgt: EIPM_get_intf_to_nexthop failed ret=%d\n", ret );
		        act_intf = LSN_NONE;
		    }
		    else
		    {
			switch ( act_intf )
			{
			case LSN0:
			case LSN1:
			    break;
	
		        default:
			    LOG_ERROR( 0,
			  	       "PIPM_sendIPMKpathmgt: EIPM_get_intf_to_nexthop retured invalid act_intf = %d\n", act_intf );
			    act_intf = LSN_NONE;
			    break;
			}			
		    }
		}
	    }
	    else
	    {
		act_intf = LSN_BOTH;
	    }

	    /* 
	     * The following code sends APR/NS to IMS to update internal path MAC
	     * or to Nexthop(gateway) to update external path MAC
	     * For Internal path, it will send ARP/NS on both interfaces
	     * For External path, it only send ARP/NS on active interface
	     * Internal path:
	     *	Interface:
	     *		for pivot, eth0.x/eth1.x or eth0.800.x/eth1.800.x
	     *		for tunnel, eth0/eth1 or eth0.800/eth1.801
	     *	Dst IP:
	     *		for pivot, it is the IMS published NI 
	     *		for tunnel, it is the IMS internal float IP
	     *  Src IP: 
	     *		for pivot, it is the FEPH published NI 
	     *		for tunnel, it is the FEPH internal float IP
	     * External path:
	     *	Interface:
	     *		for pivot, eth2/eth3 or eth2.300/eth2.300
	     *		for tunnel, eth2/eth3 or eth2.300/eth2.300
	     *	Dst IP:
	     *		it is the nexthop(gateway)
	     *  Src IP: 
	     *		it is FEPH published NI
	     */
	    IPM_IPADDR tmp_dst_ip;
	    IPM_IPADDR tmp_src_ip;
#if defined (_X86)
	    // For  internal PROXY path, it has to change src and dst IP
	    if (PIPM_PROXY_PATH == path_ptr->type)
	    {
		IPM_GET_TUNNEL_ENDPOINT_IPS(path_ptr->inner_vlan, tmp_src_ip, tmp_dst_ip);
		if ( (IPM_IPBADVER == tmp_src_ip.addrtype) || 
			(IPM_IPBADVER == tmp_dst_ip.addrtype) )
		{
			LOG_ERROR(0, "PIPM_path_update: Failed to get src or dst IP for Proxy path\n");
			return  IPM_FAILURE;
		}
	    }
	    else
#endif
	    {
		tmp_dst_ip = path_ptr->nexthop;
		tmp_src_ip = subnet_ptr->arp_resp_ip[subnet_ptr->arp_resp_ip_indx];
	    }

	    if( subnet_ptr->arp_resp_ip[0].addrtype == IPM_IPV4 )
	    {
                if( strlen(intf_ptr->lsn0_baseif) > 0 &&
		    ( act_intf == LSN0 || 
		      act_intf == LSN_BOTH ) )
                {
#if defined (_X86)
		    if (path_ptr->vlanId == 0)
#else
		    if (path_ptr->inner_vlan > 0)
#endif
                    {
                        if(path_ptr->lsn0_arpsock < 0)
                        {
                            path_ptr->lsn0_arpsock = EIPM_create_arp_socket( LSN0,
									IPM_IPV4,
									path_ptr->lsn0_iface_indx,
								   	ARPOP_REQUEST );
                        }
                        LOG_DEBUG( 0,
                                "PIPM_sendIPMKpathmgt: EIPM_sendARP IPv4 LSN0 indx=%d",
                                path_ptr->lsn0_iface_indx );

                        ret = EIPM_sendARP( path_ptr->lsn0_arpsock,
                                                intf_ptr->lsn0_hwaddr,
                                                &(tmp_src_ip),
                                                &(tmp_dst_ip),
                                                path_ptr->lsn0_iface_indx,
                                                ARPOP_REQUEST );

                        if( ret == IPM_SUCCESS )
                        {
                            path_ptr->resend_path_cnt = 0;
                        }
                    }
                    else
                    {
		    if ( intfSpecDataP->lsn0_arpsock < 0 )
                    {
                        intfSpecDataP->lsn0_arpsock = EIPM_create_arp_socket( LSN0, 
                                                                              IPM_IPV4, 
                                                                              intfSpecDataP->lsn0_iface_indx, 
                                                                              ARPOP_REQUEST );
                    }

		    LOG_DEBUG( 0,
		      	       "PIPM_sendIPMKpathmgt: EIPM_sendARP IPv4 LSN0 indx=%d", 
			       intfSpecDataP->lsn0_iface_indx );

                    ret = EIPM_sendARP( intfSpecDataP->lsn0_arpsock,
                                        intf_ptr->lsn0_hwaddr,
                                        &(subnet_ptr->arp_resp_ip[subnet_ptr->arp_resp_ip_indx]),
                                        &path_ptr->nexthop,
                                        intfSpecDataP->lsn0_iface_indx,
                                        ARPOP_REQUEST );

                    if( ret == IPM_SUCCESS )
                    {
                        path_ptr->resend_path_cnt = 0;
		        if ( intf_ptr->startExtnIntfIdx != -1 )
                        {
                        	pipm_path_ops_count++;
                        }
		    }
		    }
                }

                if( strlen(intf_ptr->lsn1_baseif) > 0 &&
		    ( act_intf == LSN1 || 
		      act_intf == LSN_BOTH ) )
                {
#if defined (_X86)
		    if (path_ptr->vlanId == 0)
#else
		    if (path_ptr->inner_vlan > 0)
#endif
                    {
                        if(path_ptr->lsn1_arpsock < 0)
                        {
                            path_ptr->lsn1_arpsock = EIPM_create_arp_socket( LSN1,
									IPM_IPV4,
                                                        		path_ptr->lsn1_iface_indx,
                                                        		ARPOP_REQUEST );
                        }
                        LOG_DEBUG( 0,
                                "PIPM_sendIPMKpathmgt: EIPM_sendARP IPv4 LSN1 indx=%d",
                                path_ptr->lsn1_iface_indx );

                        ret = EIPM_sendARP( path_ptr->lsn1_arpsock,
                                                intf_ptr->lsn1_hwaddr,
                                                &(tmp_src_ip),
                                                &(tmp_dst_ip),
                                                path_ptr->lsn1_iface_indx,
                                                ARPOP_REQUEST );

                        if( ret == IPM_SUCCESS )
                        {
                            path_ptr->resend_path_cnt = 0;
                        }
                    }
                    else
                    {
		    if ( intfSpecDataP->lsn1_arpsock < 0 )
                    {
                        intfSpecDataP->lsn1_arpsock = EIPM_create_arp_socket( LSN1, 
                                                                              IPM_IPV4, 
                                                                              intfSpecDataP->lsn1_iface_indx, 
                                                                              ARPOP_REQUEST );
                    }

		    LOG_DEBUG( 0,
		      	       "PIPM_sendIPMKpathmgt: EIPM_sendARP IPv4 LSN1 indx=%d", 
			       intfSpecDataP->lsn1_iface_indx );

                    ret = EIPM_sendARP( intfSpecDataP->lsn1_arpsock,
                                        intf_ptr->lsn1_hwaddr,
                                        &(subnet_ptr->arp_resp_ip[subnet_ptr->arp_resp_ip_indx]),
                                        &path_ptr->nexthop,
                                        intfSpecDataP->lsn1_iface_indx,
                                        ARPOP_REQUEST );

                    if( ret == IPM_SUCCESS )
                    {
                        path_ptr->resend_path_cnt = 0;
		        if ( intf_ptr->startExtnIntfIdx != -1 )
                        {
                        	pipm_path_ops_count++;
                        }
		    }
                }
                }
       	    }
	    else if( subnet_ptr->arp_resp_ip[0].addrtype == IPM_IPV6 )
	    {
                if( strlen(intf_ptr->lsn0_baseif) > 0 &&
		    ( act_intf == LSN0 || 
		      act_intf == LSN_BOTH ) )
                {
#if defined (_X86)
		    if (path_ptr->vlanId == 0)
#else
		    if (path_ptr->inner_vlan > 0)
#endif
                    {
#if defined (_X86)
			// Virtual environment and send ARP by internal floating IP
			if (PIPM_PROXY_PATH == path_ptr->type)
			{
			if(path_ptr->lsn0_arpsock < 0)
			{
				path_ptr->lsn0_arpsock = EIPM_create_arp_socket( LSN0,
								IPM_IPV4,
								path_ptr->lsn0_iface_indx,
								ARPOP_REQUEST);
			}
                        LOG_DEBUG( 0,
                                "PIPM_path_update: send ARP for IPv6 path on LSN0 indx=%d",
                                path_ptr->lsn0_iface_indx );
			ret = EIPM_sendARP( path_ptr->lsn0_arpsock,
				intf_ptr->lsn0_hwaddr,
				&(tmp_src_ip),
				&(tmp_dst_ip),
				path_ptr->lsn0_iface_indx,
				ARPOP_REQUEST);
			}
			else
#endif
			{ // ATCA pivot driver environment
                        if(path_ptr->lsn0_arpsock < 0)
                        {
                            path_ptr->lsn0_arpsock = EIPM_create_arp_socket( LSN0,
                                                        		IPM_IPV6,
                                                        		path_ptr->lsn0_iface_indx,
                                                        		ND_NEIGHBOR_SOLICIT );
                        }
                        LOG_DEBUG( 0,
                                "PIPM_sendIPMKpathmgt: EIPM_sendARP IPv4 LSN0 indx=%d",
                                path_ptr->lsn0_iface_indx );

                        ret = EIPM_sendARP( path_ptr->lsn0_arpsock,
                                                intf_ptr->lsn0_hwaddr,
                                                &(subnet_ptr->arp_resp_ip[subnet_ptr->arp_resp_ip_indx]),
                                                &path_ptr->nexthop,
                                                path_ptr->lsn0_iface_indx,
                                                ND_NEIGHBOR_SOLICIT );

			}
                        if( ret == IPM_SUCCESS )
                        {
                            path_ptr->resend_path_cnt = 0;
                        }
                    }
                    else
                    {
		    if ( intfSpecDataP->lsn0_v6arpsock < 0 )
                    {
                        intfSpecDataP->lsn0_v6arpsock = EIPM_create_arp_socket( LSN0, 
                                                                                IPM_IPV6, 
                                                                                intfSpecDataP->lsn0_iface_indx, 
                                                                                ND_NEIGHBOR_SOLICIT );
                    }
		
		    LOG_DEBUG( 0,
		      	       "PIPM_sendIPMKpathmgt: EIPM_sendARP IPv6 LSN0 indx=%d", 
			       intfSpecDataP->lsn0_iface_indx );

                    ret = EIPM_sendARP( intfSpecDataP->lsn0_v6arpsock,
                                        intf_ptr->lsn0_hwaddr,
                                        &(subnet_ptr->arp_resp_ip[subnet_ptr->arp_resp_ip_indx]),
                                        &path_ptr->nexthop,
                                        intfSpecDataP->lsn0_iface_indx,
                                        ND_NEIGHBOR_SOLICIT );

                    if( ret == IPM_SUCCESS )
                    {
                        path_ptr->resend_path_cnt = 0;
                    }
		    }
                }

                if( strlen(intf_ptr->lsn1_baseif) > 0 &&
		    ( act_intf == LSN1 || 
		      act_intf == LSN_BOTH ) )
                {
#if defined (_X86)
		    if (path_ptr->vlanId == 0)
#else
		    if (path_ptr->inner_vlan > 0)
#endif
                    {
#if defined (_X86)
			// Virtual environment and send ARP by internal floating IP
			if (PIPM_PROXY_PATH == path_ptr->type)
			{
			if(path_ptr->lsn1_arpsock < 0)
			{
				path_ptr->lsn1_arpsock = EIPM_create_arp_socket( LSN1,
								IPM_IPV4,
								path_ptr->lsn1_iface_indx,
								ARPOP_REQUEST);
			}
                        LOG_DEBUG( 0,
                                "PIPM_path_update: send ARP for IPv6 path on LSN1 indx=%d",
                                path_ptr->lsn1_iface_indx );
			ret = EIPM_sendARP( path_ptr->lsn1_arpsock,
				intf_ptr->lsn1_hwaddr,
				&(tmp_src_ip),
				&(tmp_dst_ip),
				path_ptr->lsn1_iface_indx,
				ARPOP_REQUEST);
			}
			else
#endif
			{ // ATCA pivot driver environment
                        if(path_ptr->lsn1_arpsock < 0)
                        {
                            path_ptr->lsn1_arpsock = EIPM_create_arp_socket( LSN1,
                                                        		IPM_IPV6,
                                                        		path_ptr->lsn1_iface_indx,
                                                        		ND_NEIGHBOR_SOLICIT );
                        }
                        LOG_DEBUG( 0,
                                "PIPM_sendIPMKpathmgt: EIPM_sendARP IPv4 LSN1 indx=%d",
                                path_ptr->lsn1_iface_indx );

                        ret = EIPM_sendARP( path_ptr->lsn1_arpsock,
                                                intf_ptr->lsn1_hwaddr,
                                                &(subnet_ptr->arp_resp_ip[subnet_ptr->arp_resp_ip_indx]),
                                                &path_ptr->nexthop,
                                                path_ptr->lsn1_iface_indx,
                                                ND_NEIGHBOR_SOLICIT );

			}
                        if( ret == IPM_SUCCESS )
                        {
                            path_ptr->resend_path_cnt = 0;
                        }
                    }
                    else
                    {
		    if ( intfSpecDataP->lsn1_v6arpsock < 0 )
                    {
                        intfSpecDataP->lsn1_v6arpsock = EIPM_create_arp_socket( LSN1, 
                                                                                IPM_IPV6, 
                                                                                intfSpecDataP->lsn1_iface_indx, 
                                                                                ND_NEIGHBOR_SOLICIT );
                    }

		    LOG_DEBUG( 0,
		      	       "PIPM_sendIPMKpathmgt: EIPM_sendARP IPv6 LSN1 indx=%d", 
			       intfSpecDataP->lsn1_iface_indx );
                    

                    ret = EIPM_sendARP( intfSpecDataP->lsn1_v6arpsock,
                                        intf_ptr->lsn1_hwaddr,
                                        &(subnet_ptr->arp_resp_ip[subnet_ptr->arp_resp_ip_indx]),
                                        &path_ptr->nexthop,
                                        intfSpecDataP->lsn1_iface_indx,
                                        ND_NEIGHBOR_SOLICIT );

                    if( ret == IPM_SUCCESS )
                    {
                        path_ptr->resend_path_cnt = 0;
                    }
		}
                }
            }
	    /* 
	     * Don't expect a ARP response from a L2 path or an 
	     * internal gateway path.
	     */
	    if( path_ptr->type == PIPM_L2_PATH )
	    {
#if defined (_X86)
	       path_ptr->is_arp_sent = 0;
#endif
               path_ptr->resend_path_cnt = 0;
	    }

	    if( intf_ptr->type == PIPM_INTERNAL_INTF &&
	        path_ptr->type == PIPM_GATEWAY_PATH )
	    {
#if defined (_X86)
	        path_ptr->is_arp_sent = 0;
#endif
		path_ptr->resend_path_cnt = 0;
	    }

	    if( subnet_ptr->arp_resp_ip_cnt < 0 || 
	        subnet_ptr->arp_resp_ip_cnt > PIPM_ARP_RESP_IP_CNT_MAX)
	    {
		LOG_ERROR( 0,
                           "PIPM_path_update: Out of Range arp_resp_ip_cnt=%d",
                            subnet_ptr->arp_resp_ip_cnt );				

    	        subnet_ptr->arp_resp_ip_cnt = 0;
		IPM_ipaddr_init(&(subnet_ptr->arp_resp_ip[0]));
	    }

	    if( subnet_ptr->arp_resp_ip_indx > PIPM_ARP_RESP_IP_CNT_MAX)
	    {
		LOG_ERROR( 0,
                           "PIPM_path_update: Out of Range arp_resp_ip_indx=%d",
                            subnet_ptr->arp_resp_ip_indx );				

	    	subnet_ptr->arp_resp_ip_indx = 0;
	    }

  	    if( subnet_ptr->arp_resp_ip_cnt > 1 )
            {
	        uint8_t cnt = 0;
	        uint8_t new_indx;
	        bool logged_error = FALSE;

  	        new_indx = (subnet_ptr->arp_resp_ip_indx + 1) % subnet_ptr->arp_resp_ip_cnt;

	        while( IPM_IPADDR_ISUNSPECIFIED( &(subnet_ptr->arp_resp_ip[new_indx]) ) &&
		       (cnt < subnet_ptr->arp_resp_ip_cnt) )
	        {
  	            new_indx = (new_indx + 1) % subnet_ptr->arp_resp_ip_cnt;

		    cnt++;

		    if( logged_error == FALSE )
		    {
                        LOG_ERROR( 0,
                                   "PIPM_path_update: IPM_IPADDR_ISUNSPECIFIED indx=%d arp_resp_ip_cnt=%d arp_resp_ip_indx=%d",
                                   new_indx, subnet_ptr->arp_resp_ip_cnt, subnet_ptr->arp_resp_ip_indx );	
		        logged_error = TRUE;
		    }
	        }

	        if( cnt < subnet_ptr->arp_resp_ip_cnt )
	        {
		    subnet_ptr->arp_resp_ip_indx = new_indx;
	        }
		else
		{
		    subnet_ptr->arp_resp_ip_indx = 0;
		}
	    }
	    else 
	    {
		subnet_ptr->arp_resp_ip_indx = 0;
	    }
	}

	return( IPM_SUCCESS );

} /* end PIPM_path_update() */

/**********************************************************************
 *
 * Name:	PIPM_send_routemsg()
 *
 * Abstract:	Send a update to the IP Message Path Kernel Module
 *
 * Parameters:	net   	  - which network LSN0, LSN1
 *              addr_type - IPv4 or IPv6
 *              data_ptr  - pointer to interface data
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/
int PIPM_send_routemsg( PIPM_ROUTE_ACTION action, PIPM_PATH *path_ptr, PIPM_INTF *intf_ptr )
{
#ifndef _VHE
	PIPMK_ROUTE_MSG		route_msg;
	int			ret;
	uint32_t		msg_type;
	char			ipbuf[ IPM_IPMAXSTRSIZE ];
	char			**intf_to_nexthop_ptr;

	memset(&route_msg,0,sizeof(route_msg));

	switch( action )
	{
	case PIPM_ADD_ROUTE:
		msg_type = IPMK_ROUTEADD;
		break;

	case PIPM_DEL_ROUTE:
		msg_type = IPMK_ROUTEDEL;
		break;

	case PIPM_REFRESH_ROUTE:
		msg_type = IPMK_ROUTEREFRESH;
		break;

	default:
		LOG_ERROR( 0, "Error: PIPM_send_routemsg Invalid action [%d]", action );
		return IPM_FAILURE;
	}

	route_msg.dest_af = (path_ptr->dest.addrtype == IPM_IPV4 ) ? AF_INET : AF_INET6;
	IPM_ipaddr2in( &path_ptr->dest, &route_msg.dest_ip );

	route_msg.dest_prefix = path_ptr->destprefix;

	route_msg.nexthop_af = (path_ptr->nexthop.addrtype == IPM_IPV4 ) ? AF_INET : AF_INET6;
	IPM_ipaddr2in( &path_ptr->nexthop, &route_msg.nexthop );


	LOG_DEBUG( 0,
       	 	"PIPM_sendIPMKpathmgt msg type %d dest ip %s dest prefix %d nexthop ip %s\n",
		msg_type,
		IPM_chkipaddr2p(&path_ptr->dest, ipbuf, sizeof(ipbuf)),
		route_msg.dest_prefix,
		IPM_chkipaddr2p(&path_ptr->nexthop, ipbuf, sizeof(ipbuf)) );

	ret = PIPM_sendIPMKpathmgt( &route_msg, msg_type, sizeof(route_msg) );
	if( ret != 0 )
	{
		 LOG_ERROR( 0, "Error: PIPM_send_routemsg failed ret [%d]", ret );
		return IPM_FAILURE;
	}

#endif
	return IPM_SUCCESS;
}

/**********************************************************************
 *
 * Name:	PIPM_send_ipmsg()
 *
 * Abstract:	Send a update to the IP Message Path Kernel Module
 *
 * Parameters:	action - Add/Delete/Refresh action to take on specified IP.
 *              ip_ptr - IP address info.
 *              subnet_ptr - Subnet info.
 *              intfDataP - Base/extension interface data.
 *              intfTypeExt - Identifies the base/extension interface.
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/
int PIPM_send_ipmsg( PIPM_IP_ACTION action, IPM_IPADDR *ip_ptr, PIPM_SUBNET *subnet_ptr, 
                     void *intfDataP, PIPM_INTF_TYPE_EXT intfTypeExt )
{
#ifndef _VHE
	PIPM_INTF               *intf_ptr;
        PIPM_INTF_SPEC          *intfSpecDataP;
	PIPMK_IP_MSG		ip_msg;
	PIPM_PATH		*path_ptr;
	int			path_idx;
	int			ret;
	uint32_t		msg_type;
	char			ipbuf[ IPM_IPMAXSTRSIZE ];
	char			**intf_to_nexthop_ptr;
	uint16_t 		vlanId = 0;

	PIPM_SET_INTF_PTRS( intfDataP, intfTypeExt, intf_ptr, intfSpecDataP );

        if ( NULL == intf_ptr )
        {
                return IPM_FAILURE;
        }

	if (intfTypeExt == PIPM_EXTN_INTF)
	{
		vlanId = intfSpecDataP->vlanId;
	}

	memset(&ip_msg,0,sizeof(ip_msg));

	switch( action )
	{
	case PIPM_ADD_IP:
		msg_type = IPMK_IPADD;
		break;

	case PIPM_DEL_IP:
		msg_type = IPMK_IPDEL;
		break;

	case PIPM_REFRESH_IP:
		msg_type = IPMK_IPREFRESH;
		break;

	default:
		LOG_ERROR( 0, "Error: PIPM_send_ipmsg Invalid action [%d]", action );
		return IPM_FAILURE;
	}

	switch( intf_ptr->type )
	{
	case PIPM_INTERNAL_INTF:
		ip_msg.direction = IPMK_TO_INTERNAL;
		break;

	case PIPM_EXTERNAL_INTF:
		ip_msg.direction = IPMK_TO_EXTERNAL;
		break;

	default:
		LOG_ERROR( 0, "Error: PIPM_send_ipmsg Invalid interface type [%d]", intf_ptr->type );
		return IPM_FAILURE;
	}

	ip_msg.af = (ip_ptr->addrtype == IPM_IPV4 ) ? AF_INET : AF_INET6;
	IPM_ipaddr2in( ip_ptr, &ip_msg.local_ip );
	ip_msg.prefix_len = subnet_ptr->prefixlen;
	if( subnet_ptr->table_num > 0 && subnet_ptr->table_num < 255)
	{
		ip_msg.sbpr = 1;
	}
	else
	{
		ip_msg.sbpr = 0;
	}

	if (strlen(intf_ptr->lsn0_baseif) > 0)
	{
		snprintf( &ip_msg.iface[0][0], MAX_NLEN_DEV, "%s%s",
			intf_ptr->lsn0_baseif, ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
	}
	if (strlen(intf_ptr->lsn1_baseif) > 0)
	{
		snprintf( &ip_msg.iface[1][0], MAX_NLEN_DEV, "%s%s",
			intf_ptr->lsn1_baseif, ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
	}

	ip_msg.ext_vlan = vlanId;

	for( path_idx = 0, path_ptr = &subnet_ptr->path[0];
	     path_idx < subnet_ptr->path_cnt;
	     path_idx++, path_ptr++ )
	{
		if ( PIPM_GATEWAY_PATH == path_ptr->type )
		{
			IPM_ipaddr2in( &path_ptr->nexthop, &ip_msg.gateway_ip );
			break;
		}
	}

	if ( ( subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD ||
		subnet_ptr->redundancy_mode == IPM_RED_EIPM_ACM ||
		subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP ||
		subnet_ptr->redundancy_mode == IPM_RED_NONE ||
               subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR ) &&
	     !IPM_IPADDR_ISUNSPECIFIED(&subnet_ptr->gateway) )
	{
		IPM_ipaddr2in( &subnet_ptr->gateway, &ip_msg.gateway_ip );
	}

	LOG_DEBUG( 0,
       	 	"PIPM_sendIPMKpathmgt msg type %d dir %d ip %s iface0 %s iface1 %s vlanId %d\n",
		msg_type,
		ip_msg.direction,
		IPM_chkipaddr2p(ip_ptr, ipbuf, sizeof(ipbuf)),
		&ip_msg.iface[0][0],
		&ip_msg.iface[1][0],
		ip_msg.ext_vlan);

	ret = PIPM_sendIPMKpathmgt( &ip_msg, msg_type, sizeof(ip_msg) );
	if( ret != 0 )
	{
		 LOG_ERROR( 0, "Error: PIPM_send_ipmsg failed ret [%d]", ret );
		return IPM_FAILURE;
	}

#endif
	return IPM_SUCCESS;
}

#if defined (_X86)
/**********************************************************************
 *
 * Name:        PIPM_process_arp_na_per_interface()
 *
 * Abstract:    Get dst interface MAC address from ARP or NA 
 * 		and store it in path if it is gotten
 *
 * Parameters:  path_ptr - IPM user space PATH data
 *              left_right_interface - the processed interface
 *              intfDataP - Base/extension interface data.
 *              subnet_ptr - The subnet of current path
 *              intfTypeExt - Identifies the base/extension interface.
 *
 * Returns:     IPM_SUCCESS: Get the valid MAC address
 *		IPM_FAILURE: Doesn't get valid MAC address
 *
 **********************************************************************/
int PIPM_process_arp_na_per_interface (
	PIPM_PATH *path_ptr,
	int cur_interface,
	void *intfDataP,
	PIPM_SUBNET *subnet_ptr,
	PIPM_INTF_TYPE_EXT intfTypeExt
				  )
{
	int ret_val=IPM_SUCCESS; 
#ifndef _VHE
	
	PIPM_INTF *intf_ptr;
	PIPM_INTF_SPEC *intfSpecDataP;
	unsigned int validResMsgCount=0; // Increase 1 once get valid remote MAC
	unsigned int totalResMsgCount=0; // Increase 1 once get one message in this socket

	if ( (NULL == path_ptr) ||
		(NULL == intfDataP) ||
		(NULL == subnet_ptr) )
	{
		LOG_ERROR( 0, "PIPM_process_arp_na_per_interface: ERROR: NULL pointer, path_ptr(%p), intfDataP(%p) or subnet_ptr (%p)\n", path_ptr, intfDataP, subnet_ptr); 
		return (IPM_FAILURE);
	}

	// Set interface pointer
	PIPM_SET_INTF_PTRS( intfDataP, intfTypeExt, intf_ptr, intfSpecDataP );
	if ( NULL == intf_ptr )
	{
		LOG_ERROR( 0, "PIPM_process_arp_na_per_interface: ERROR: Can't get pointer intf_ptr from intfDataP(%p)\n", intfDataP); 
		return IPM_FAILURE;
	}

	if ( (path_ptr->nexthop.addrtype != IPM_IPV4) &&
		(path_ptr->nexthop.addrtype != IPM_IPV6) )
	{
		LOG_ERROR( 0, "PIPM_process_arp_na_per_interface: ERROR: path IP version isn't correct (%d)\n", path_ptr->nexthop.addrtype);
		return IPM_FAILURE;
	}

	if ( (cur_interface != 0) &&
		(cur_interface != 1))
	{
		LOG_ERROR( 0, "PIPM_process_arp_na_per_interface: ERROR: Invalid active interface (%d)\n", cur_interface);
		return IPM_FAILURE;
	}

	// Get active interface socket
	int *arp_sock_ptr = NULL;
	unsigned char * local_mac_ptr = NULL;
	unsigned char * remote_mac_ptr = NULL;
	IPM_IPADDR * local_arp_ip_ptr = NULL;
	IPM_IPADDR * remote_arp_ip_ptr = NULL;
	int interface_index = -1;

	/*
	 * Set the correct local and remote arp IPs
	 */
	if (PIPM_PROXY_PATH == path_ptr->type)
	{
		// Get local and remote tunnel IP
		IPM_GET_TUNNEL_ENDPOINTS_POINTER(path_ptr->inner_vlan,
			local_arp_ip_ptr, remote_arp_ip_ptr);
		if ( (NULL == local_arp_ip_ptr) || (NULL == remote_arp_ip_ptr) )
		{
			LOG_DEBUG(0, "PIPM_process_arp_na_per_interface: ERROR: failed to get local and remote tunnel IPs from tunnel data\n");
			return IPM_FAILURE;
		}
	}
	else
	{
		local_arp_ip_ptr = &(subnet_ptr->arp_resp_ip[0]);
		remote_arp_ip_ptr = &(path_ptr->nexthop);
	}

	if ( 0 == cur_interface )
	{
		if ( path_ptr->vlanId == 0 )
		{
			// For internal path, path socket is used
			arp_sock_ptr = &(path_ptr->lsn0_arpsock);
			interface_index = path_ptr->lsn0_iface_indx;
		}
		else
		{
			// For extention path, interface socket is used
			if ( IPM_IPV4 == path_ptr->nexthop.addrtype )
			{
				arp_sock_ptr = &(intfSpecDataP->lsn0_arpsock);
			}
			else
			{
				arp_sock_ptr = &(intfSpecDataP->lsn0_v6arpsock);
			}
			interface_index = intfSpecDataP->lsn0_iface_indx;
		}

		local_mac_ptr = intf_ptr->lsn0_hwaddr;
		remote_mac_ptr = &(path_ptr->remote_mac[0][0]);
		memset(remote_mac_ptr, 0, ETH_ALEN);
	}
	else if ( 1 == cur_interface )
	{
		if ( path_ptr->vlanId == 0 )
		{
			// For internal path, path socket is used
			arp_sock_ptr = &(path_ptr->lsn1_arpsock);
			interface_index = path_ptr->lsn1_iface_indx;
		}
		else
		{
			// For extention path, interface socket is used
			if ( IPM_IPV4 == path_ptr->nexthop.addrtype )
			{
				arp_sock_ptr = &(intfSpecDataP->lsn1_arpsock);
			}
			else
			{
				arp_sock_ptr = &(intfSpecDataP->lsn1_v6arpsock);
			}
			interface_index = intfSpecDataP->lsn1_iface_indx;
		}
		local_mac_ptr = intf_ptr->lsn1_hwaddr;
		remote_mac_ptr = &(path_ptr->remote_mac[1][0]);
		memset(remote_mac_ptr, 0, ETH_ALEN);
	}

	if ( (-1 == *arp_sock_ptr) ||
		(-1 == interface_index) ) 
	{
		LOG_DEBUG( 0, "PIPM_process_arp_na_per_interface: ERROR: Invalid sock (%d) or interface index(%d)\n", *arp_sock_ptr, interface_index);
		return IPM_FAILURE;
	}
		
	LOG_DEBUG( 0, "PIPM_process_arp_na_per_interface: INFO: path IP Version(%d), path Socket(%d), innerVlan(%d), current_interface(%d), interface_index(%d), local_mac(%x:%x:%x:%x:%x:%x), local_ip(%x:%x:%x:%x), remote_ip(%x:%x:%x:%x)\n", 
		path_ptr->nexthop.addrtype,
		*arp_sock_ptr,
		path_ptr->inner_vlan,
		cur_interface,
		interface_index,
		*local_mac_ptr,
		*(local_mac_ptr+1),
		*(local_mac_ptr+2),
		*(local_mac_ptr+3),
		*(local_mac_ptr+4),
		*(local_mac_ptr+5),
		local_arp_ip_ptr->ipaddr[0],
		local_arp_ip_ptr->ipaddr[1],
		local_arp_ip_ptr->ipaddr[2],
		local_arp_ip_ptr->ipaddr[3],
		remote_arp_ip_ptr->ipaddr[0],
		remote_arp_ip_ptr->ipaddr[1],
		remote_arp_ip_ptr->ipaddr[2],
		remote_arp_ip_ptr->ipaddr[3]);
	
	
	bool recv_empty = FALSE;
	int flags = MSG_DONTWAIT;
	char buffer[ ARP_RCV_SIZE ];
	int msg_len=0;
	bool is_bad_socket = FALSE; 
	ret_val = IPM_FAILURE; 
	uint8_t	i;
	bool found = FALSE;
	IPM_IPADDR ip_addr;

	/* 
	 * After replacing pivot driver with tunnel, for PROXY IPv6 path,
	 * the path MAC is gotten from ARP response
	 */
	if ( (IPM_IPV4 == path_ptr->nexthop.addrtype)
		|| (PIPM_PROXY_PATH == path_ptr->type) && (IPM_IPV6 == path_ptr->nexthop.addrtype) )
	{
		struct sockaddr_ll from;
		int sockad_len = sizeof(from);

		while ( FALSE == recv_empty )
		{
		// Don't block if there is no data in the socket
		msg_len = recvfrom(*arp_sock_ptr,
				   buffer,
				   ARP_RCV_SIZE,
				   flags, 
				   (struct sockaddr *)&from, 
				   &sockad_len); 
		LOG_DEBUG( 0, "PIPM_process_arp_na_per_interface: INFO: IPV4: got msg_len=%d\n", msg_len);
		if ( msg_len < 0 )
		{
			if ( EAGAIN == errno )
			{
				LOG_DEBUG( 0, "PIPM_process_arp_na_per_interface: INFO: IPV4 Got nothing\n");
				// Break out of loop
				recv_empty = TRUE;
			}
			else if ( EINTR == errno )
			{
				continue;
			}
			else
			{

				// It will take care later
				is_bad_socket = TRUE;
				recv_empty = TRUE;
			}	
		
		}
		else if ( msg_len == 0 )
		{
			// No message 
			LOG_DEBUG( 0, "PIPM_process_arp_na_per_interface: INFO: IPV4: msg_len is 0\n");
			recv_empty = TRUE;

			// If this isn't first time, then it could  get message before
			if ( validResMsgCount > 0 )
			{
				// Got the MAC address
				ret_val = IPM_SUCCESS;
			}
		}
		else
		{
			// Got the ARP message and verify it 
			struct arp_pkt *arpPktPtr = (struct arp_pkt *)buffer;
			/* 
			 * Verify 
			 * it is ARPOP_REPLY
			 * local Mac is equal to target Mac
			 * local IP is equal to target IP
			 * remote IP is equal to source IP
			 */
			totalResMsgCount++;
			found = FALSE;
			if ( (ARPOP_REPLY == ntohs(arpPktPtr->arp.ea_hdr.ar_op)) ||
			     (ARPOP_REQUEST == ntohs(arpPktPtr->arp.ea_hdr.ar_op)))
			{

				// GARP
				if ( ( (ARPOP_REPLY == ntohs(arpPktPtr->arp.ea_hdr.ar_op)) || (ARPOP_REQUEST == ntohs(arpPktPtr->arp.ea_hdr.ar_op)) )
					&& (0 == memcmp(&(remote_arp_ip_ptr->ipaddr[0]), arpPktPtr->arp.arp_spa, sizeof(remote_arp_ip_ptr->ipaddr[0]))) 
					&& (0 == memcmp(&(remote_arp_ip_ptr->ipaddr[0]), arpPktPtr->arp.arp_tpa, sizeof(remote_arp_ip_ptr->ipaddr[0])))
				   )
				{
					found = TRUE;
				}

				// ARP response
				if(PIPM_PROXY_PATH == path_ptr->type)
				{
					/*
					 * After tunnel feature, there is no ARP response IP array
					 * It has to process this kind of path in different condition
					 */
					if ( (ARPOP_REPLY == ntohs(arpPktPtr->arp.ea_hdr.ar_op))
						&& (0 == memcmp(local_mac_ptr, arpPktPtr->arp.arp_tha, ETH_ALEN))
						&& (0 == memcmp(&(local_arp_ip_ptr->ipaddr[0]), arpPktPtr->arp.arp_tpa, sizeof(local_arp_ip_ptr->ipaddr[0])))
						&& (0 == memcmp(&(remote_arp_ip_ptr->ipaddr[0]), arpPktPtr->arp.arp_spa, sizeof(remote_arp_ip_ptr->ipaddr[0])))
					   )
					{
						found = TRUE;
					}
				}
				else
				{
				IPM_in2ipaddr(&arpPktPtr->arp.arp_tpa, sizeof(arpPktPtr->arp.arp_tpa), &ip_addr);

				if ( (ARPOP_REPLY == ntohs(arpPktPtr->arp.ea_hdr.ar_op)) &&
				     (0 == memcmp(local_mac_ptr, arpPktPtr->arp.arp_tha, ETH_ALEN)) &&
				     (0 == memcmp(&remote_arp_ip_ptr->ipaddr[0], arpPktPtr->arp.arp_spa, sizeof(remote_arp_ip_ptr->ipaddr[0]))))
				{
				    	for( i = 0; i < subnet_ptr->arp_resp_ip_cnt; i++ )
					{
						if( IPM_IPCMPADDR(&(subnet_ptr->arp_resp_ip[i]), &ip_addr) == IPM_SUCCESS )
						{
							found = TRUE;
							break;
						}
				  	}

				}
				}

				if( found == TRUE )
				{
					// Got one expect ARP reply
					validResMsgCount++;

					/*
					 * Update the MAC in message sending to kernel
					 * Use the MAC of last ARP message if there are more expect ARP reply 
					 */
					memcpy(remote_mac_ptr, arpPktPtr->arp.arp_sha, ETH_ALEN);
					// It doesn't need to set ret_val because it will be set when there is no message
				}

				IPM_in2ipaddr(&arpPktPtr->arp.arp_spa, sizeof(arpPktPtr->arp.arp_spa), &ip_addr);

				if( pipm_l2_path_enable == TRUE &&
				    found == FALSE &&
				    IPM_IPCMPADDRPFLEN(&(subnet_ptr->arp_resp_ip[0]), &ip_addr, subnet_ptr->prefixlen) == IPM_SUCCESS )
				{
					int ret;
					
					// Send mac address update
					if ( 0 == cur_interface )
					{
						ret = PIPM_send_macmsg( PIPM_UPDATE_MAC, &ip_addr, &arpPktPtr->arp.arp_sha, intf_ptr->lsn0_baseif );
					}
					else
					{
						ret = PIPM_send_macmsg( PIPM_UPDATE_MAC, &ip_addr, &arpPktPtr->arp.arp_sha, intf_ptr->lsn1_baseif );
					}

					if ( ret != IPM_SUCCESS )
					{
						LOG_ERROR( 0, "Error: PIPM_send_macmsg failed ret = %d\n", ret_val );
					}
				}
			}

		}
		}
		LOG_OTHER( 0, "PIPM_process_arp_na_per_interface: INFO: IPV4: validResMsgCount(%d) and totalResMsgCount(%d), current_interface(%d) and MAC(%x:%x:%x:%x:%x:%x)\n", 
			validResMsgCount, totalResMsgCount, cur_interface,
			path_ptr->remote_mac[cur_interface][0],
			path_ptr->remote_mac[cur_interface][1],
			path_ptr->remote_mac[cur_interface][2],
			path_ptr->remote_mac[cur_interface][3],
			path_ptr->remote_mac[cur_interface][4],
			path_ptr->remote_mac[cur_interface][5]
			);
	}

	if ( (IPM_IPV6 == path_ptr->nexthop.addrtype) && (path_ptr->type != PIPM_PROXY_PATH) )
	{
		unsigned int totalvlaidContrlMsgCount = 0;
		struct msghdr recv_msg_hdr;
		struct iovec iov;
		char cmsg[ARP_RCV_SIZE];
		struct cmsghdr *cmsg_hdr_ptr;
		struct in6_pktinfo *pkt_info_ptr;
		struct sockaddr_in6 ipv6_addr;
		struct nd_neighbor_advert *ndp_msg_na_ptr;
		uint8_t	i;
		IPM_IPADDR ip_addr;		

		// Control message header which include in6_pktinfo
		cmsg_hdr_ptr = (struct cmsghdr *)&cmsg;

		// Initialize received buffer which store the option part of NA
		memset((void *) &iov, 0, sizeof(iov));
		iov.iov_base = &buffer;
		iov.iov_len = sizeof(buffer);
		
		// Initialize received message header
		recv_msg_hdr.msg_iov = &iov;
		recv_msg_hdr.msg_iovlen = 1;
		recv_msg_hdr.msg_flags = 0;
		recv_msg_hdr.msg_control = (char *)cmsg_hdr_ptr;
		recv_msg_hdr.msg_controllen = sizeof(cmsg);
		recv_msg_hdr.msg_name = (void*)&ipv6_addr;
		recv_msg_hdr.msg_namelen = sizeof(ipv6_addr);

		memset( buffer, 0, ARP_RCV_SIZE );
		memset( cmsg, 0, sizeof(cmsg) );
		memset( &ipv6_addr, 0, sizeof(struct sockaddr_in6) );
		recv_empty = FALSE;
		is_bad_socket = FALSE;
		validResMsgCount=0;
		totalResMsgCount=0;

		while ( FALSE == recv_empty ) 
		{
		bool found = FALSE;
		bool l2_found = FALSE;

		msg_len = recvmsg (*arp_sock_ptr, &recv_msg_hdr, flags );
		LOG_DEBUG( 0, "PIPM_process_arp_na_per_interface: INFO: IPM_IPV6: got msg_len=%d\n", msg_len);

		if ( msg_len < 0 )
		{
			if ( EAGAIN == errno )
			{
				LOG_DEBUG( 0, "PIPM_process_arp_na_per_interface: INFO: IPV6: Got nothing\n");
				recv_empty = TRUE;
			}
			else if ( EINTR == errno )
			{
				continue;
			}
			else
			{
				is_bad_socket = TRUE;
				recv_empty = TRUE;
			}
		}
		else if ( msg_len == 0 )
		{
			LOG_DEBUG( 0, "PIPM_process_arp_na_per_interface: INFO: IPV6: msg_len is 0 \n");
			recv_empty = TRUE;
			if ( validResMsgCount > 0 )
			{
				// Got the MAC address
				ret_val = IPM_SUCCESS;
			}

		}
		else
		{
			// Got ICMP6 message
			if ( 0 == recv_msg_hdr.msg_controllen )
			{
				recv_empty = TRUE;
				LOG_DEBUG( 0, "PIPM_process_arp_na_per_interface: ERROR: IPV6: recv_msg_hdr.msg_controllen is 0\n");
				continue;
			}

			totalResMsgCount++;
			// Go through all comtrol messages, however, it should only one Control message
			for ( cmsg_hdr_ptr = CMSG_FIRSTHDR (&recv_msg_hdr); 
				cmsg_hdr_ptr != NULL;
				cmsg_hdr_ptr = CMSG_NXTHDR (&recv_msg_hdr, cmsg_hdr_ptr) )

	 		{
				totalvlaidContrlMsgCount++;
				if ( (cmsg_hdr_ptr->cmsg_level != SOL_IPV6) ||
					(cmsg_hdr_ptr->cmsg_type != IPV6_PKTINFO))
				{
					LOG_DEBUG( 0, "PIPM_process_arp_na_per_interface: INFO: IPV6: not expect control message level(%d) and type(%d)\n", cmsg_hdr_ptr->cmsg_level, cmsg_hdr_ptr->cmsg_type);
					continue;
				}

				// Verify whether it is expect control message
				pkt_info_ptr = (struct in6_pktinfo *) CMSG_DATA (cmsg_hdr_ptr);
				if ( (pkt_info_ptr->ipi6_ifindex != (unsigned int)interface_index))
				{
					LOG_ERROR( 0, "PIPM_process_arp_na_per_interface: INFO: IPV6: not expect interface_index(%d) in in6_pktinfo and local interface index(%d)\n",
						pkt_info_ptr->ipi6_ifindex,
						interface_index
						);
					continue;
				}


				ndp_msg_na_ptr = (struct nd_neighbor_advert *) &buffer[0];
				if (ndp_msg_na_ptr->nd_na_hdr.icmp6_type != ND_NEIGHBOR_ADVERT) 
				{
					LOG_ERROR( 0, "PIPM_process_arp_na_per_interface: INFO: IPV6: not expect icmp6 type(%d) in nd_neighbor_advert and expect icmp6_type(%d)\n", 
						ndp_msg_na_ptr->nd_na_hdr.icmp6_type,
						ND_NEIGHBOR_ADVERT
						);
					continue;
				}

				IPM_in2ipaddr(&pkt_info_ptr->ipi6_addr, sizeof(pkt_info_ptr->ipi6_addr), &ip_addr);

				if ( memcmp(&ndp_msg_na_ptr->nd_na_target, remote_arp_ip_ptr->ipaddr, sizeof(remote_arp_ip_ptr->ipaddr)) == 0 )
				{
				    	for( i = 0; i < subnet_ptr->arp_resp_ip_cnt; i++ )
					{
						if ( IPM_IPCMPADDR(&(subnet_ptr->arp_resp_ip[i]), &ip_addr) == IPM_SUCCESS ) 
						{
							found = TRUE;
							break;
						}
				  	}

				}

				IPM_in2ipaddr(&ndp_msg_na_ptr->nd_na_target, sizeof(ndp_msg_na_ptr->nd_na_target), &ip_addr);

				if ( pipm_l2_path_enable == TRUE &&
				     found == FALSE &&
				     IPM_IPCMPADDRPFLEN(&(subnet_ptr->arp_resp_ip[0]), &ip_addr, subnet_ptr->prefixlen) == IPM_SUCCESS )
				{
					l2_found = TRUE;
				}

				if ( found == FALSE &&
				     l2_found == FALSE )
				{
					LOG_OTHER( 0, "PIPM_process_arp_na_per_interface: INFO: IPV6: not expect local IP(%x:%x:%x:%x) in in6_pktinfo and local IP(%x:%x:%x:%x)\n",
						pkt_info_ptr->ipi6_addr.s6_addr32[0],
						pkt_info_ptr->ipi6_addr.s6_addr32[1],
						pkt_info_ptr->ipi6_addr.s6_addr32[2],
						pkt_info_ptr->ipi6_addr.s6_addr32[3],
						local_arp_ip_ptr->ipaddr[0],
						local_arp_ip_ptr->ipaddr[1],
						local_arp_ip_ptr->ipaddr[2],
						local_arp_ip_ptr->ipaddr[3]
						);
					continue;
				}
				// Process option part
				struct nd_opt_hdr *opt_ptr = NULL;
				char *tmp_ptr = NULL;
				opt_ptr = (struct nd_opt_hdr *) (&buffer[0] + sizeof(struct nd_neighbor_advert));
				unsigned int total_option_len = msg_len - sizeof(struct nd_neighbor_advert);
				unsigned int each_option_len = 0;
				uint8_t remote_mac[ETH_ALEN];
				
        			if ( (total_option_len <= 0) || (NULL == opt_ptr))
				{
					LOG_DEBUG( 0, "PIPM_process_arp_na_per_interface: INFO: IPV6: No option in IMCP6 message, the total msg_len(%d) and NA message len(%d)\n", msg_len, sizeof(struct nd_neighbor_advert));
					continue;
				}
				bool is_get_remote_mac = FALSE;	
				while ( total_option_len )
				{
					if ( (TRUE == is_get_remote_mac) || (NULL == opt_ptr) )
					{
						// break out once it has gotten remote MAC or NULL opt_ptr
						break;
					}
					each_option_len =  opt_ptr->nd_opt_len << 3;
					if ( (total_option_len < each_option_len) || (0 == each_option_len) )
					{
						LOG_DEBUG( 0, "PIPM_process_arp_na_per_interface: INFO: IPV6: invalid total_option_len(%d) or each_option_len(%d)\n", total_option_len, each_option_len);
						break;
					}
					LOG_DEBUG( 0, "PIPM_process_arp_na_per_interface: INFO: IPV6: the total_option_len(%d) and  each_option_len(%d)\n", total_option_len, each_option_len);
					switch (opt_ptr->nd_opt_type)
					{
					case ND_OPT_TARGET_LINKADDR:
						tmp_ptr = (char*)opt_ptr + 2; 
						memcpy(&remote_mac, tmp_ptr, ETH_ALEN);
						if ( found == TRUE )
						{
							validResMsgCount++;
							memcpy(remote_mac_ptr, &remote_mac, ETH_ALEN);
						}
						is_get_remote_mac = TRUE;
						break;
					default:
						// This isn't target Mac type option and try next one
						break;
					}
					total_option_len = total_option_len - each_option_len;
					opt_ptr = (struct nd_opt_hdr *) (((char *) opt_ptr) + each_option_len);
				}
				if ( is_get_remote_mac == TRUE &&
				     l2_found == TRUE )
				{
					int ret;

					// Send mac address update
					if ( 0 == cur_interface )
					{
						ret = PIPM_send_macmsg( PIPM_UPDATE_MAC, &ip_addr, &remote_mac, intf_ptr->lsn0_baseif );
					}
					else
					{
						ret = PIPM_send_macmsg( PIPM_UPDATE_MAC, &ip_addr, &remote_mac, intf_ptr->lsn1_baseif );
					}

					if ( ret != IPM_SUCCESS )
					{
						LOG_ERROR( 0, "Error: PIPM_send_macmsg for IPv6 failed ret = %d\n", ret_val );
					}
				}
			} // The end of for 
		} // The end of got ICMP6 message
		} // The end of while
		LOG_OTHER( 0, "PIPM_process_arp_na_per_interface: INFO: IPV6: validResMsgCount(%d) , totalvlaidContrlMsgCount(%d) and totalResMsgCount(%d), curr_interface(%d) and MAC(%x:%x:%x:%x:%x:%x)\n", 
			validResMsgCount, totalvlaidContrlMsgCount, totalResMsgCount,
			cur_interface,
			path_ptr->remote_mac[cur_interface][0],
			path_ptr->remote_mac[cur_interface][1],
			path_ptr->remote_mac[cur_interface][2],
			path_ptr->remote_mac[cur_interface][3],
			path_ptr->remote_mac[cur_interface][4],
			path_ptr->remote_mac[cur_interface][5]
			);
	} // The end of IPV6

	if ( TRUE == is_bad_socket )
	{
		int bad_socket = *arp_sock_ptr;
		// Close the bad socket
		(void) close(bad_socket);
		
		// Create new socket
		EIPM_NET lsn_x = LSN_NONE;
		IPM_IPADDRTYPE ip_type = IPM_IPBADVER;
		int arp_op_type = -1;
		if ( 0 == cur_interface )
		{
			lsn_x = LSN0;
		}
		else
		{
			lsn_x = LSN1;
		}
		if ( IPM_IPV4 == path_ptr->nexthop.addrtype )
		{
			ip_type = IPM_IPV4;
			arp_op_type = ARPOP_REQUEST;
		}
		else
		{
			ip_type = IPM_IPV6;
			arp_op_type = ND_NEIGHBOR_SOLICIT;
		}
		*arp_sock_ptr = EIPM_create_arp_socket( lsn_x, ip_type, interface_index, arp_op_type);
		LOG_DEBUG( 0, "PIPM_process_arp_na_per_interface: INFO: old socket(%d), new socket(%d)\n", bad_socket, *arp_sock_ptr); 

	}
        if ( validResMsgCount > 0 )
        {
                // Got the MAC address
                ret_val = IPM_SUCCESS;
        }

#endif
	return (ret_val);
}

/**********************************************************************
 *
 * Name:        PIPM_process_arp_na_per_path()
 *
 * Abstract:    Process ARP or NA for the path
 *
 * Parameters:  path_ptr - IPM user space PATH data
 *              intfDataP - Base/extension interface data.
 *              subnet_ptr - The subnet of current path
 *              intfTypeExt - Identifies the base/extension interface.
 *
 * Returns:     IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/
int PIPM_process_arp_na_per_path (
        PIPM_PATH *path_ptr,
        void *intfDataP,
        PIPM_SUBNET *subnet_ptr,
        PIPM_INTF_TYPE_EXT intfTypeExt
                                  )
{
        int ret_val=IPM_SUCCESS;
#ifndef _VHE
	ret_val=IPM_FAILURE;
	int ret_val_l=IPM_FAILURE;
	int ret_val_r=IPM_FAILURE;

	// Process left interface
	if( path_ptr->lsn0_iface_indx > 0 )
	{
		ret_val_l = PIPM_process_arp_na_per_interface (path_ptr, 0, intfDataP, subnet_ptr, intfTypeExt);
	}

	// Process right interface
	if( path_ptr->lsn1_iface_indx > 0 )
	{
		ret_val_r = PIPM_process_arp_na_per_interface (path_ptr, 1, intfDataP, subnet_ptr, intfTypeExt);
	}
	if ( (ret_val_l == IPM_SUCCESS) || (ret_val_r == IPM_SUCCESS) )
	{
		ret_val = IPM_SUCCESS;
	}
#endif
        return (ret_val);
}

#endif

/**********************************************************************
 *
 * Name:	PIPM_send_ipmsgpath_update()
 *
 * Abstract:	Send a update to the IP Message Path Kernel Module
 *
 * Parameters:	action - Action to take on specified path.
 *              act_intf - Identifies the path on LSN0/LSN1.
 *              path_ptr - Path info,
 *              intfDataP - Base/extension interface data.
 *              intfTypeExt - Identifies the base/extension interface.
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/
int PIPM_send_ipmsgpath_update( PIPM_PATH_ACTION action
                                ,PIPM_PATH_INTF act_intf 
                                ,PIPM_PATH *path_ptr
                                ,PIPM_SUBNET *subnet_ptr 
                                ,void *intfDataP 
                                ,PIPM_INTF_TYPE_EXT intfTypeExt )
{
#ifndef _VHE
	PIPM_INTF               *intf_ptr;
        PIPM_INTF_SPEC          *intfSpecDataP;
	IPMK_PATH_MSG		path;
	int			ret;
	uint32_t		msg_type;
	char			ipbuf[ IPM_IPMAXSTRSIZE ];
	char			**intf_to_nexthop_ptr;
	PIPM_PATH		*sec_path_ptr;
	unsigned short          vlanId=0;

	PIPM_SET_INTF_PTRS( intfDataP, intfTypeExt, intf_ptr, intfSpecDataP );

        if ( NULL == intf_ptr )
        {
                return IPM_FAILURE;
        }

	if ( intfTypeExt == PIPM_EXTN_INTF )
	{
		vlanId = intfSpecDataP->vlanId;
	}
	memset(&path,0,sizeof(path));

	switch( action )
	{
	case PIPM_ADD_PATH:
		msg_type = IPMK_PATHADD;
		break;

	case PIPM_DEL_PATH:
		msg_type = IPMK_PATHDEL;
		break;

	case PIPM_REFRESH_PATH:
		msg_type = IPMK_PATHREFRESH;
		break;

	case PIPM_UPDATE_PATH:
		msg_type = IPMK_PATHUPDATE;
		break;

	default:
		LOG_ERROR( 0, "Error: PIPM_send_ipmsgpath_update Invalid action [%d]", action );
		return IPM_FAILURE;
	}

	switch( intf_ptr->type )
	{
	case PIPM_INTERNAL_INTF:
		path.direction = IPMK_TO_INTERNAL;
		break;

	case PIPM_EXTERNAL_INTF:
		path.direction = IPMK_TO_EXTERNAL;
		break;

	default:
		LOG_ERROR( 0, "Error: PIPM_send_ipmsgpath_update Invalid interface type [%d]", intf_ptr->type );
		return IPM_FAILURE;
	}

	switch( subnet_ptr->redundancy_mode )
	{
	case IPM_RED_BFD_TRANSPORT:
	case IPM_RED_BFD_RSR:
	case IPM_RED_EIPM_BFD:
		if( path_ptr->nexthop.addrtype == IPM_IPV4 )
		{
			path.prefix_len = 32;
		}
		else
		{
			path.prefix_len = 128;
		}
		break;
	default:
		if( pipm_l2_path_enable == TRUE )
		{
			path.prefix_len = subnet_ptr->prefixlen;
		}
		else
		{
			if( path_ptr->nexthop.addrtype == IPM_IPV4 )
			{
				path.prefix_len = 32;
			}
			else
			{
				path.prefix_len = 128;
			}
		}
		break;
	}

	path.af = (path_ptr->nexthop.addrtype == IPM_IPV4 ) ? AF_INET : AF_INET6;
	IPM_ipaddr2in( &path_ptr->nexthop, &path.dest_ip[0] );
	IPM_ipaddr2in( &path_ptr->nexthop, &path.dest_ip[1] );

	if( (subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT) &&
	    (strlen(intf_ptr->lsn0_baseif) != 0) &&
	    (action != PIPM_DEL_PATH) )
	{
		/* primary BFD transport path, search for corresponding secondary path */
		sec_path_ptr = PIPM_find_sec_bfdpath(path_ptr, subnet_ptr, intf_ptr);

		if (sec_path_ptr != NULL)
		{
			IPM_ipaddr2in( &sec_path_ptr->nexthop, &path.dest_ip[1] );
		}
	}

	if( strlen(intf_ptr->lsn1_baseif) == 0 )
	{
		act_intf = PIPM_LSN0_PATH;
	}
	else if( strlen(intf_ptr->lsn0_baseif) == 0 )
	{
		act_intf = PIPM_LSN1_PATH;
	}

	switch( act_intf )
	{
	case PIPM_LSN0_PATH:
		path.act_int = 0;
		break;

	case PIPM_LSN1_PATH:
		path.act_int = 1;
		break;

	default:

		if ( msg_type != IPMK_PATHDEL )
		{
			/* Derive the status */
			if( intf_ptr->type == PIPM_EXTERNAL_INTF )
			{
				EIPM_NET act_intf;

				ret = EIPM_get_intf_to_nexthop( intf_ptr->lsn0_baseif, intf_ptr->lsn1_baseif, &path_ptr->nexthop, &act_intf, vlanId );
				if( ret != IPM_SUCCESS )
				{
					LOG_ERROR( 0,
				       	 	"PIPM_sendIPMKpathmgt: EIPM_get_intf_to_nexthop failed ret=%d\n", ret );

					return IPM_FAILURE;
				}

				switch ( act_intf )
				{
			 	case LSN0:
					path.act_int = 0;
					break;
			
			 	case LSN1:
					path.act_int = 1;
					break;

				default:
					LOG_ERROR( 0,
				       	 	"PIPM_sendIPMKpathmgt: EIPM_get_intf_to_nexthop invalid act intf %d\n", act_intf );
					return IPM_FAILURE;
				}
			}
			else
			{
				unsigned char act_intf;

				if (path_ptr->inner_vlan > 0)
				{
					ret = ipm_get_intf_to_nexthop( intf_ptr->lsn0_baseif, intf_ptr->lsn1_baseif, &path_ptr->intFloatIP, &act_intf );
				}
				else
				{
					ret = ipm_get_intf_to_nexthop( intf_ptr->lsn0_baseif, intf_ptr->lsn1_baseif, &path_ptr->nexthop, &act_intf );
				}
				if( ret != IPM_SUCCESS )
				{
					LOG_ERROR( 0,
				       	 	"PIPM_sendIPMKpathmgt: ipm_get_intf_to_nexthop failed ret=%d\n", ret );

					return IPM_FAILURE;
				}

				switch ( act_intf )
				{
		 		case LINK_0:
					path.act_int = 0;
					break;
			
		 		case LINK_1:
					path.act_int = 1;
					break;

				default:
					LOG_ERROR( 0,
				       	 	"PIPM_sendIPMKpathmgt: ipm_get_intf_to_nexthop invalid act intf %d\n", act_intf );
					return IPM_FAILURE;
				}
			}
		}
			if (path_ptr->inner_vlan > 0)
			{
				ret = ipm_get_intf_to_nexthop( intf_ptr->lsn0_baseif, intf_ptr->lsn1_baseif, &path_ptr->intFloatIP, &act_intf );
			}
			else
			{
				ret = ipm_get_intf_to_nexthop( intf_ptr->lsn0_baseif, intf_ptr->lsn1_baseif, &path_ptr->nexthop, &act_intf );
			}
		break;
	}

	//intfSpecDataP->vlanId and path_ptr->inner_vlan will never > 0 at the same time,
        //because they are from different interfaces.
#if defined (_X86)
	/*
	 * For virtual Env, there isn't the interface like:
	 * eth0.x/eth1.x or eth0.800.x/eth1.801.x, so remove inner VLAN
	 */
	if (strlen(intf_ptr->lsn0_baseif) > 0)
	{
		snprintf( &path.iface[0][0], MAX_NLEN_DEV, "%s%s",
			intf_ptr->lsn0_baseif,
			ipm_getVLANStr( intfSpecDataP->vlanId, TRUE )
			);
	}

	if (strlen(intf_ptr->lsn1_baseif) > 0)
	{
		snprintf( &path.iface[1][0], MAX_NLEN_DEV, "%s%s",
			intf_ptr->lsn1_baseif,
			ipm_getVLANStr( intfSpecDataP->vlanId, TRUE )
			);
	}
#else

	if (strlen(intf_ptr->lsn0_baseif) > 0)
	{
		snprintf( &path.iface[0][0], MAX_NLEN_DEV, "%s%s%s",
			intf_ptr->lsn0_baseif,
			ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
			ipm_getVLANStr(path_ptr->inner_vlan, TRUE) );
	}
	if (strlen(intf_ptr->lsn1_baseif) > 0)
	{
		snprintf( &path.iface[1][0], MAX_NLEN_DEV, "%s%s%s",
			intf_ptr->lsn1_baseif,
			ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
			ipm_getVLANStr(path_ptr->inner_vlan, TRUE) );
	}
#endif

	path.inner_vlan = path_ptr->inner_vlan;

	path.ext_vlan = vlanId;

#if defined (_X86)
	// Get MAC address of active interface if it is IPMK_PATHREFRESH
	if ( IPMK_PATHREFRESH == msg_type)
	{
		memcpy(path.mac_addr, path_ptr->remote_mac[0], ETH_ALEN);
		memcpy(path.mac_addr1, path_ptr->remote_mac[1], ETH_ALEN);
		LOG_DEBUG( 0, "PIPM_sendIPMKpathmgt: active interface(%d), kernel path mac0(%x:%x:%x:%x:%x:%x), kernel path mac1(%x:%x:%x:%x:%x:%x), user path mac0(%x:%x:%x:%x:%x:%x), user path mac1(%x:%x:%x:%x:%x:%x)\n",
			path.act_int,
			path.mac_addr[0],
			path.mac_addr[1],
			path.mac_addr[2],
			path.mac_addr[3],
			path.mac_addr[4],
			path.mac_addr[5],
			path.mac_addr1[0],
			path.mac_addr1[1],
			path.mac_addr1[2],
			path.mac_addr1[3],
			path.mac_addr1[4],
			path.mac_addr1[5],
			path_ptr->remote_mac[0][0],
			path_ptr->remote_mac[0][1],
			path_ptr->remote_mac[0][2],
			path_ptr->remote_mac[0][3],
			path_ptr->remote_mac[0][4],
			path_ptr->remote_mac[0][5],
			path_ptr->remote_mac[1][0],
			path_ptr->remote_mac[1][1],
			path_ptr->remote_mac[1][2],
			path_ptr->remote_mac[1][3],
			path_ptr->remote_mac[1][4],
			path_ptr->remote_mac[1][5]
		);
	}
#endif

	LOG_DEBUG( 0,
       	 	"PIPM_sendIPMKpathmgt msg type %d dir %d act %d dest ip %s iface 0 %s iface 1 %s\n",
		msg_type,
		path.direction,
		path.act_int,
		IPM_chkipaddr2p(&path_ptr->nexthop, ipbuf, sizeof(ipbuf)),
		&path.iface[0][0],
		&path.iface[1][0] );

	ret = PIPM_sendIPMKpathmgt( &path, msg_type, sizeof(path) );
	if( ret != 0 )
	{
		 LOG_ERROR( 0, "Error: PIPM_send_ipmsgpath_update failed ret [%d]", ret );
		return IPM_FAILURE;
	}

#endif
	return IPM_SUCCESS;
}

/**********************************************************************
 *
 * Name:	PIPM_openippathmgt()
 *
 * Abstract:	open 
 *
 * Parameters:	None
 *
 * Returns:	valid fd or -1 in the case of a failure
 *
 **********************************************************************/

static int      ipm_fd = -1;

int PIPM_openippathmgt()
{
	if( ipm_fd == -1 )
	{
		ipm_fd = open("/dev/ippathmgt", O_WRONLY);
		if( ipm_fd == -1 )
		{
			LOG_ERROR( 0,
			       	 "Error: PIPM_openippathmgt - failed %d\n", ipm_fd );
			return -1;
		}
	}

	return ipm_fd;
}

/**********************************************************************
 *
 * Name:	PIPM_sendIPMKpathmgt()
 *
 * Abstract:	Send a message to the IP Message Path Kernel Module
 *
 * Parameters:	None
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int PIPM_sendIPMKpathmgt(void *msg, uint32_t msg_type, uint32_t len)
{
#ifndef _VHE
	LCPDEV_data_t 	data;
	size_t		n;
	
	if( pipm_enable == FALSE )
	{
		return IPM_SUCCESS;
	}

	ipm_fd = PIPM_openippathmgt();
	if( ipm_fd == -1 )
	{
		LOG_ERROR( 0,
		       	 "Error: PIPM_openippathmgt - failed %d\n", ipm_fd );
		return IPM_FAILURE;
	}

  	memset( &data, 0 , sizeof(data) );

	data.mode = LCPDEV_othr;
	data.tag = msg_type;
	data.len = len;
	if( len > 0 )
	{
		memcpy(&data.val, msg, data.len);
	}

  	n = write(ipm_fd, (char*)&data, sizeof(data) );
	if( n != sizeof(data) )
	{
		LOG_ERROR( 0,
		       	 "Error: PIPM_sendIPMKpathmgt - write failed msg_type=%d errno=%d (%s)\n", 
			msg_type, errno, strerror(errno) );

		close( ipm_fd );
		ipm_fd = -1;

		return IPM_FAILURE;
	}

	LOG_DEBUG( 0,
	       	 "PIPM_sendIPMKpathmgt - write n=%d size=%d\n", n, data.len );

#endif
	return IPM_SUCCESS;
}

/**********************************************************************
 *
 * Name:	PIPM_process_route_update
 *
 * Abstract:	Process route updates
 *
 * Parameters:	action     - add/delete
 *              ifname     - interface name ptr for route 
 *              vlanId     - VLAN Id on external interface.
 *              dest_ip    - destination ptr
 *		prefixlen  - destination prefix length
 *		nexthop_ip - next hop ip ptr
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/
int PIPM_process_route_update(PIPM_ROUTE_ACTION action, char *ifname, unsigned short vlanId, IPM_IPADDR *dest_ip, int prefixlen, IPM_IPADDR *nexthop_ip)
{
PIPM_DATA 	*data_ptr;
PIPM_INTF 	*intf_ptr;
PIPM_SUBNET 	*subnet_ptr;
PIPM_PATH 	*path_ptr;
int 		intf_idx;
int 		subnet_idx;
int 		path_idx;
int 		ret;
uint32_t	act_intf;
PIPM_PATH_INTF	path_interface;
char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
char ipm_ipstr_buf1[IPM_IPMAXSTRSIZE];

	LOG_OTHER( EIPM_LOG_ROUTECFG,
                   "PIPM_process_route_update: action %d ifname %s vlan %u dest_ip %s prefixlen %d nexthop ip %s\n",
			action,
			(( ifname == NULL ) ? "null" : ifname ),
			vlanId,
			(((dest_ip == NULL) || ((dest_ip != NULL) && (dest_ip->addrtype != IPM_IPV4) && (dest_ip->addrtype != IPM_IPV6))) ? "Null or Invalid IP type" : IPM_ipaddr2p( dest_ip, ipm_ipstr_buf, sizeof(ipm_ipstr_buf))),
			prefixlen,
			(((nexthop_ip == NULL) || ((nexthop_ip != NULL) && (nexthop_ip->addrtype != IPM_IPV4) && (nexthop_ip->addrtype != IPM_IPV6))) ? "Null or Invalid IP" : IPM_ipaddr2p( nexthop_ip, ipm_ipstr_buf1, sizeof(ipm_ipstr_buf1))));

    if( pipm_enable == FALSE )
    {
	return IPM_SUCCESS;
    }

    if( action != PIPM_ADD_ROUTE &&
	action != PIPM_UPDATE_SUBNET_ROUTE && 
	action != PIPM_DEL_ROUTE )
    {
	/* no work to do */
        LOG_ERROR(0, "PIPM_process_route_update: invalid action %d\n", action );
	return IPM_FAILURE;
    }

    if( ifname == NULL &&
	action == PIPM_ADD_ROUTE )
    {
	LOG_ERROR(0, "PIPM_process_route_update: ifname null\n" );
	return IPM_FAILURE;
    }

    if( dest_ip == NULL )
    {
	LOG_ERROR(0, "PIPM_process_route_update: dest_ip null\n" );
	return IPM_FAILURE;
    }

    /* Don't take action on subnet route changes */
    if( nexthop_ip == NULL && 
        action == PIPM_ADD_ROUTE )
    {
	return IPM_SUCCESS;
    }

    if( PIPM_shm_ptr == NULL )
    {
	LOG_ERROR(0, "PIPM_route_update: Shared memory null\n" );
	return IPM_FAILURE;
    }

    data_ptr = (PIPM_DATA *)PIPM_shm_ptr;

    /* Look through all interfaces */
    for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
         intf_idx < data_ptr->intf_cnt;
         intf_idx++, intf_ptr++ )
    {

	if( action == PIPM_ADD_ROUTE )
	{
	    if( strcmp(intf_ptr->lsn0_baseif, ifname) != 0 &&
		strcmp(intf_ptr->lsn1_baseif, ifname) != 0 )
	    {
		continue;
	    }
	}

	/* Look through all subnets */
	for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
	     subnet_idx < intf_ptr->subnet_cnt;
	     subnet_idx++, subnet_ptr++ )
	{

	    /* Look through all paths */
	    for( path_idx = 0, path_ptr = &subnet_ptr->path[0];
	         path_idx < subnet_ptr->path_cnt;
		 path_idx++, path_ptr++ )
	    {

                if((path_ptr->inner_vlan == 0) &&
		   (( dest_ip != NULL &&
		     IPM_IPCMPADDR(dest_ip, &path_ptr->dest) == IPM_SUCCESS &&
		     !IPM_IPADDR_ISUNSPECIFIED(dest_ip) ) ||
                   ( nexthop_ip != NULL &&
		     IPM_IPCMPADDR(nexthop_ip, &path_ptr->nexthop) == IPM_SUCCESS &&
		     !IPM_IPADDR_ISUNSPECIFIED(nexthop_ip) )))
		{
		    if( intf_ptr->type == PIPM_INTERNAL_INTF )
		    {
		        if( action == PIPM_ADD_ROUTE )
		        {
			    if( strcmp(intf_ptr->lsn0_baseif, ifname) == 0 )
			    {
			        path_interface = PIPM_LSN0_PATH;
		       	    }
			    else if( strcmp(intf_ptr->lsn1_baseif, ifname) == 0 )
			    {
			        path_interface = PIPM_LSN1_PATH;
			    }
			    else 
			    {
			        LOG_ERROR(0, "PIPM_process_route_update: no interface match %s\n", ifname );
			        return IPM_FAILURE;
			    }
		        }
		        else if( action == PIPM_DEL_ROUTE )
		        {
		            path_interface = PIPM_LSN0_PATH;
		        }
		    }
		    else
		    {
			if ( ( 0 == vlanId )
			     && ( PIPM_DEL_ROUTE == action ) )
			{
				/* Get the VLAN id from the interface name if any. */
				char *vlanSepP;
				char intfName[MAX_NLEN_DEV];

				strncpy( intfName, ifname, ( MAX_NLEN_DEV - 1) );

				vlanSepP = strchr( intfName, '.' );

				if ( vlanSepP != NULL )
			 	{
					errno = 0;
					vlanId = strtoul( (vlanSepP + 1), NULL, 10 );

					if ( errno != 0 )
					{
						/* Error occurred. */
						vlanId = 0;
					} 
				}
			}

                        if ( vlanId != path_ptr->vlanId )
                        {
                                /* check for the next path. */
                                continue;
                        }

			path_interface = PIPM_NULL_PATH_INTF;
		    }

		    if ( vlanId > 0 )
                    {
                            /* Need to find the extension interface that matches this interface index. */
                            int extnIntfIdx;
                            PIPM_INTF_SPEC *intfSpecDataP;

                            for ( ( extnIntfIdx = 0, intfSpecDataP = &(data_ptr->extnIntfData[0]) );
                                  ( extnIntfIdx < data_ptr->extnIntfCount );
                                  ( extnIntfIdx++, intfSpecDataP++ ) )
                            {
                                    if (    ( vlanId == intfSpecDataP->vlanId )
                                         && ( intfSpecDataP->baseIntfIdx == intf_idx ) )
                                    {
                                            ret = PIPM_send_ipmsgpath_update( PIPM_UPDATE_PATH, 
                                                                              path_interface, 
                                                                              path_ptr, 
                                                                              subnet_ptr,
                                                                              intfSpecDataP, 
                                                                              PIPM_EXTN_INTF );

                                            return IPM_SUCCESS;
                                    }
                            }

			    ret = IPM_SUCCESS;
                    }
                    else
                    {
		        ret = PIPM_send_ipmsgpath_update( PIPM_UPDATE_PATH, 
							  path_interface, 
							  path_ptr, 
							  subnet_ptr,
							  intf_ptr, 
							  PIPM_BASE_INTF );
                    }

		    if( ret != IPM_SUCCESS )
		    {
		        LOG_ERROR(0, "PIPM_process_route_update: PIPM_send_ipmsgpath_update ret %d\n", ret );
		    }

		    /* Found a match return */
		    return IPM_SUCCESS;
		}
		else if((path_ptr->inner_vlan > 0) &&
                        ( dest_ip != NULL &&
                        	IPM_IPCMPADDR(dest_ip, &path_ptr->intFloatIP) == IPM_SUCCESS &&
                        	!IPM_IPADDR_ISUNSPECIFIED(dest_ip) ) ||
                        ( nexthop_ip != NULL &&
                        	IPM_IPCMPADDR(nexthop_ip, &path_ptr->intFloatIP) == IPM_SUCCESS &&
                        	!IPM_IPADDR_ISUNSPECIFIED(nexthop_ip) ))
                {
                    //update stacked VLAN interface
                    if( intf_ptr->type == PIPM_INTERNAL_INTF )
                    {
                        if( action == PIPM_ADD_ROUTE )
                        {
                            if( strcmp(intf_ptr->lsn0_baseif, ifname) == 0 )
                            {
                                path_interface = PIPM_LSN0_PATH;
                            }
                            else if( strcmp(intf_ptr->lsn1_baseif, ifname) == 0 )
                            {
                                path_interface = PIPM_LSN1_PATH;
                            }
                            else
                            {
                                LOG_ERROR(0, "PIPM_process_route_update: no interface match %s\n", ifname );
                                return IPM_FAILURE;
                            }
                        }
                        else if( action == PIPM_DEL_ROUTE )
                        {
                            path_interface = PIPM_LSN0_PATH;
                        }
                    }
                    else
                    {
                        path_interface = PIPM_NULL_PATH_INTF;
		    }

		    ret = PIPM_send_ipmsgpath_update( PIPM_UPDATE_PATH, 
		    		    		      path_interface, 
		    		    		      path_ptr, 
		    		    		      subnet_ptr, 
		    		    		      intf_ptr, 
		    		    		      PIPM_BASE_INTF );
                    if( ret != IPM_SUCCESS )
                    {
                        LOG_ERROR(0, "PIPM_process_route_update: PIPM_send_ipmsgpath_update ret %d\n", ret );
                    }
		}
	    }
	}
    }

    /* no match */
    return IPM_SUCCESS;
}

/**********************************************************************
 *
 * Name:       PIPM_findIntf 
 *
 * Abstract: 
 *     Searches for a matching interface.
 *
 * Parameters:
 *     lsn0_intfName - LSN0 interface name (can be untagged/tagged).
 *     lsn1_intfName - LSN1 interface name (can be untagged/tagged).
 *     intfDataP - Set to the matching base interface.
 *     intfSpecDataP - Set to the matching base/extension interface.
 *     intfTypeExt - Set to the matching interface type or set to invalid type is
 *                   no matching interface found.
 *     baseIntfIdx - Set to index of matching base interface. Set to -1 on no match.
 *
 * Returns: 
 *     Returns the index of the matching base/extension interface or -1 on no match.
 *
 **********************************************************************/

int PIPM_findIntf( char *lsn0_intfName, char *lsn1_intfName,
                   PIPM_INTF **intfDataP, PIPM_INTF_SPEC **intfSpecDataP, 
                   PIPM_INTF_TYPE_EXT *intfTypeExt, int *baseIntfIdx )
{

        PIPM_DATA       *dataP;
        int 		intfIdx;
        char            lsn0IntfName[MAX_NLEN_DEV];
        char            lsn1IntfName[MAX_NLEN_DEV];
        
        *baseIntfIdx = -1;
        *intfDataP = NULL;
        *intfSpecDataP = NULL;

        dataP = (PIPM_DATA *)PIPM_shm_ptr;
        *intfTypeExt = PIPM_INVALID_INTF;

	memset(lsn0IntfName, 0, MAX_NLEN_DEV);
	memset(lsn1IntfName, 0, MAX_NLEN_DEV);

        /* Search the base/parent interface data first for a matching interface. */
        for ( ( intfIdx = 0, (*intfDataP) = &(dataP->intf_data[0]) );
              ( intfIdx < dataP->intf_cnt );
              ( intfIdx++, (*intfDataP)++ ) )
        {
                if (    ( 0 == strcmp( (*intfDataP)->lsn0_baseif, lsn0_intfName ) )
                     && ( 0 == strcmp( (*intfDataP)->lsn1_baseif, lsn1_intfName ) ) )
                {
                        /* Exact match. Found the interface. */
                        *intfSpecDataP = &((*intfDataP)->specData);
                        *intfTypeExt = PIPM_BASE_INTF;
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
        for ( ( intfIdx = 0, (*intfSpecDataP) = &(dataP->extnIntfData[0]) );
              ( intfIdx < dataP->extnIntfCount );
              ( intfIdx++, (*intfSpecDataP)++ ) )
        {
                if ( !PIPM_IS_VALID_BASE_INTF_IDX( (*intfSpecDataP)->baseIntfIdx ) )
                {
                        /* Invalid base interface index. Assert and continue. */
                        ASRT_RPT( ASBAD_DATA, 0, "Invalid base interface index %d (count: %d).\n",
                                  (*intfSpecDataP)->baseIntfIdx, ((PIPM_DATA *)PIPM_shm_ptr)->intf_cnt );
                        continue;
                }

                if (    ( *baseIntfIdx != (*intfSpecDataP)->baseIntfIdx ) 
                     && ( *baseIntfIdx != -1 ) )
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
                        *intfTypeExt = PIPM_EXTN_INTF;
                        *baseIntfIdx = (*intfSpecDataP)->baseIntfIdx;

                        return intfIdx;
                }
        } /* end 'extension interfaces loop' */

        *intfDataP = NULL;
        *intfSpecDataP = NULL;

        return -1;

} /* end PIPM_findIntf() */

/**********************************************************************
 *
 * Name:	PIPM_find_sec_bfdpath()
 *
 * Abstract:	For a given primary BFD transport path, find corresponding
 *		secondary BFD transport path.
 *
 * Parameters:	path_ptr	- pointer to primary BFD transport path
 *		subnet_ptr	- pointer to PIPM subnet data structure
 *				  containing primary BFD transposrt path
 *		intf_ptr	- pointer to PIPM interface data structure
 *				  containing primary BFD transport path
 *
 * Returns:	pointer to secondary BFD transport path, or NULL if not found
 *
 **********************************************************************/

PIPM_PATH* PIPM_find_sec_bfdpath( PIPM_PATH *path_ptr, PIPM_SUBNET *subnet_ptr, PIPM_INTF *intf_ptr)
{
	PIPM_DATA 	*data_p;
	PIPM_INTF 	*intf_p;
	PIPM_SUBNET 	*subnet_p;
	PIPM_PATH 	*path_p;
	int		intf_idx;
	int		subnet_idx;
	int		path_idx;
	bool		found_bfdsn = FALSE;

	if( path_ptr == NULL || subnet_ptr == NULL || intf_ptr == NULL )
	{
		LOG_ERROR( 0, "%s invalid input: path_ptr=%p, subnet_ptr=%p, intf_ptr=%p\n",
			   __FUNCTION__, path_ptr, subnet_ptr, intf_ptr );
		return (NULL);
	}

	if( (subnet_ptr->redundancy_mode != IPM_RED_BFD_TRANSPORT) ||
	    (strlen(intf_ptr->lsn0_baseif) == 0) ||
	    (strlen(intf_ptr->lsn1_baseif) == 0) )
	{
		return (NULL);
	}

	/* Verify there is at least one BFD subnet has been assigned to this interface */
	for( subnet_idx = 0, subnet_p = &intf_ptr->subnet[0];
	     subnet_idx < intf_ptr->subnet_cnt;
	     subnet_idx++, subnet_p++ )
	{
		if( ( (subnet_p->redundancy_mode == IPM_RED_EIPM_BFD) ||
                      (subnet_p->redundancy_mode == IPM_RED_BFD_RSR) ) &&
		    (subnet_p->subnet_base.addrtype == subnet_ptr->subnet_base.addrtype) )
		{
			found_bfdsn = TRUE;
			break;
		}
	}

	if (found_bfdsn == FALSE)
	{
		return (NULL);
	}

	if( PIPM_shm_ptr == NULL )
	{
		LOG_ERROR(0, "%s failure: Shared memory null\n", __FUNCTION__);
		return (NULL);
	}

	data_p = (PIPM_DATA *)PIPM_shm_ptr;

	for( intf_idx = 0, intf_p = &data_p->intf_data[0];
	     intf_idx < data_p->intf_cnt;
	     intf_idx++, intf_p++ )
	{
		if( (intf_p == intf_ptr) ||
		    (intf_p->type != intf_ptr->type) ||
		    (strlen(intf_p->lsn0_baseif) != 0) ||
		    (strlen(intf_p->lsn1_baseif) == 0) ||
		    (strcmp(intf_p->lsn1_baseif, intf_ptr->lsn1_baseif) != 0) )
		{
			continue;
		}

		for( subnet_idx = 0, subnet_p = &intf_p->subnet[0];
		     subnet_idx < intf_p->subnet_cnt;
		     subnet_idx++, subnet_p++ )
		{
			if( (subnet_p->redundancy_mode != IPM_RED_BFD_TRANSPORT) ||
			    (subnet_p->subnet_base.addrtype != subnet_ptr->subnet_base.addrtype) )
			{
				continue;
			}

			for( path_idx = 0, path_p = &subnet_p->path[0];
			     path_idx < subnet_p->path_cnt;
			     path_idx++, path_p++ )
			{
				if (!IPM_IPADDR_ISUNSPECIFIED(&path_p->nexthop))
				{
					return (path_p);
				}
			}
		}
	}

	return (NULL);
}

/**********************************************************************
 *
 * Name:	PIPM_find_prim_bfd()
 *
 * Abstract:	For a given secondary BFD transport data, find corresponding
 *		primary BFD transport data.
 *
 * Parameters:	sec_subnet_ptr	- pointer to secondary BFD transport PIPM subnet data
 *		sec_intf_ptr	- pointer to secondary BFD transport PIPM interface data
 *		prim_subnet_p	- pointer to primary BFD transport PIPM subnet data
 *		prim_intf_p	- pointer to primary BFD transport PIPM interface data
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int PIPM_find_prim_bfd( PIPM_SUBNET *sec_subnet_ptr, PIPM_INTF *sec_intf_ptr,
			PIPM_SUBNET **prim_subnet_p, PIPM_INTF **prim_intf_p )
{
	PIPM_DATA 	*data_ptr;
	PIPM_INTF 	*intf_ptr;
	PIPM_SUBNET 	*subnet_ptr;
	PIPM_PATH 	*path_ptr;
	int		intf_idx;
	int		subnet_idx;
	int		path_idx;

	if( sec_subnet_ptr == NULL || sec_intf_ptr == NULL || 
	    prim_subnet_p == NULL || prim_intf_p == NULL )
	{
		LOG_ERROR( 0, "%s invalid input: sec_subnet_ptr=%p, sec_intf_ptr=%p, prim_subnet_p=%p, prim_intf_p=%p\n",
			   __FUNCTION__, sec_subnet_ptr, sec_intf_ptr, prim_subnet_p, prim_intf_p );
		return (IPM_FAILURE);
	}

	*prim_subnet_p = NULL;
	*prim_intf_p = NULL;

	if( (sec_subnet_ptr->redundancy_mode != IPM_RED_BFD_TRANSPORT) ||
	    (strlen(sec_intf_ptr->lsn0_baseif) > 0) ||
	    (strlen(sec_intf_ptr->lsn1_baseif) == 0) )
	{
		return (IPM_FAILURE);
	}

	if( PIPM_shm_ptr == NULL )
	{
		LOG_ERROR(0, "%s failure: Shared memory null\n", __FUNCTION__);
		return (IPM_FAILURE);
	}

	data_ptr = (PIPM_DATA *)PIPM_shm_ptr;

	for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
	     intf_idx < data_ptr->intf_cnt;
	     intf_idx++, intf_ptr++ )
	{
		if( (intf_ptr == sec_intf_ptr) ||
		    (intf_ptr->type != sec_intf_ptr->type) ||
		    (strlen(intf_ptr->lsn0_baseif) == 0) ||
		    (strlen(intf_ptr->lsn1_baseif) == 0) ||
		    (strcmp(intf_ptr->lsn1_baseif, sec_intf_ptr->lsn1_baseif) != 0) )
		{
			continue;
		}

		for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
		     subnet_idx < intf_ptr->subnet_cnt;
		     subnet_idx++, subnet_ptr++ )
		{
			if( (subnet_ptr->redundancy_mode != IPM_RED_BFD_TRANSPORT) ||
			    (subnet_ptr->subnet_base.addrtype != sec_subnet_ptr->subnet_base.addrtype) )
			{
				continue;
			}

			for( path_idx = 0, path_ptr = &subnet_ptr->path[0];
			     path_idx < subnet_ptr->path_cnt;
			     path_idx++, path_ptr++ )
			{
				if (!IPM_IPADDR_ISUNSPECIFIED(&path_ptr->nexthop))
				{
					*prim_subnet_p = subnet_ptr;
					*prim_intf_p = intf_ptr;
					return (IPM_SUCCESS);
				}
			}
		}
	}

	return (IPM_FAILURE);
}

/**********************************************************************
 *
 * Name:	PIPM_update_subnet_ip()
 *
 * Abstract:	Send update to kernel for all local IPs in a subnet.
 *
 * Parameters:	subnet_ptr	- pointer to PIPM subnet data structure
 *		intf_ptr	- pointer to PIPM interface data structure
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int PIPM_update_subnet_ip( PIPM_SUBNET *subnet_ptr, PIPM_INTF *intf_ptr )
{
	int	arp_resp_ip_idx;
	int	ret;

	if( subnet_ptr == NULL || intf_ptr == NULL )
	{
		LOG_ERROR( 0, "%s invalid input: subnet_ptr=%p, intf_ptr=%p\n",
			   __FUNCTION__, subnet_ptr, intf_ptr );
		return (IPM_FAILURE);
	}

	for( arp_resp_ip_idx = 0; arp_resp_ip_idx < subnet_ptr->arp_resp_ip_cnt; arp_resp_ip_idx++ )
	{
		ret = PIPM_send_ipmsg(  PIPM_ADD_IP, 
					&(subnet_ptr->arp_resp_ip[arp_resp_ip_idx]), 
					subnet_ptr, 
					intf_ptr, 
					PIPM_BASE_INTF );

		if( ret != IPM_SUCCESS )
		{
			LOG_ERROR( 0, "Error: PIPM_send_ipmsg failed ret [%d]", ret );
		}
	}  

	return (IPM_SUCCESS);
}

/**********************************************************************
 *
 * Name:	PIPM_open_arpsock()
 *
 * Abstract:	Open arp sockets if needed
 *
 * Parameters:	intfSpecDataP - Pointer to interface specific data.
 *           :  addr_type - IP address type.
 *
 * Returns:	None
 *
 **********************************************************************/

void
PIPM_open_arpsock( PIPM_INTF_SPEC *intfSpecDataP, IPM_IPADDRTYPE addr_type )
{
	if( addr_type == IPM_IPV6 )
	{
		if(( intfSpecDataP->lsn0_v6arpsock < 0 ) &&
		   ( intfSpecDataP->lsn0_iface_indx > 0 ))  
		{
			intfSpecDataP->lsn0_v6arpsock =
			        EIPM_create_arp_socket( LSN0, IPM_IPV6, intfSpecDataP->lsn0_iface_indx, ND_NEIGHBOR_SOLICIT );
		}					

		if(( intfSpecDataP->lsn1_v6arpsock < 0 ) &&
		   ( intfSpecDataP->lsn1_iface_indx > 0 ))
		{
			intfSpecDataP->lsn1_v6arpsock =
			        EIPM_create_arp_socket( LSN1, IPM_IPV6, intfSpecDataP->lsn1_iface_indx, ND_NEIGHBOR_SOLICIT );
		}
	}
	else if( addr_type == IPM_IPV4 )
	{
		if(( intfSpecDataP->lsn0_arpsock < 0 ) &&
		   ( intfSpecDataP->lsn0_iface_indx > 0 ))
		{
			intfSpecDataP->lsn0_arpsock =
			        EIPM_create_arp_socket( LSN0, IPM_IPV4, intfSpecDataP->lsn0_iface_indx, ARPOP_REQUEST );
		}					

		if(( intfSpecDataP->lsn1_arpsock < 0 ) &&
		   ( intfSpecDataP->lsn1_iface_indx > 0 ))
		{
			intfSpecDataP->lsn1_arpsock =
			        EIPM_create_arp_socket( LSN1, IPM_IPV4, intfSpecDataP->lsn1_iface_indx, ARPOP_REQUEST );
		}
	}
	else
	{
		LOG_ERROR( 0,
		       	 "Error: PIPM_open_arpsock - invalid address type=%d\n",
			 addr_type );
	}
	return;
}

/**********************************************************************
 *
 * Name      : PIPM_resetAllPathUpdateCounters.
 *
 * Abstract  : Resets the path update counters for base interfaces.
 *
 * Parameters: None.
 *
 * Returns   : None
 *
 **********************************************************************/

void PIPM_resetAllPathUpdateCounters()
{

        int             i;
        PIPM_INTF       *data_ptr;

        for ( ( i = 0, data_ptr = &(((PIPM_DATA *)PIPM_shm_ptr)->intf_data[0]) );
	      ( i < ((PIPM_DATA *)(PIPM_shm_ptr))->intf_cnt ); 
              ( i++, data_ptr++ ) )
        {

                /* Force the path counter to zero so all paths are refreshed and ARPs are sent out. */
		PIPM_SET_PATH_TIMER( data_ptr, 0 );

        } /* end 'base interfaces loop' */

} /* end 'PIPM_resetAllPathUpdateCounters' */
#if defined (_X86) && !defined(_VHE)
/**********************************************************************
 *
 * Name:        PIPM_add_arpndp_socket()
 *
 * Abstract:    Add Path ARP and NDP sockets to the read list for processing
 *
 * Parameters:  fd_set - FD set pointer
 *              max_socket - max socket pointer
 *
 * Returns:     none
 *
 **********************************************************************/

void PIPM_add_arp_ndp_socket(fd_set *read_sock_set, int *max_sock)
{
	
	register PIPM_INTF	*data_ptr;
	register PIPM_INTF_SPEC *intfSpecDataP;
	PIPM_DATA               *dataP;
	int			i;
	void			*intfDataP = NULL;
	PIPM_SUBNET 		*subnet_ptr = NULL;
	int             	subnet_idx = 0;
	PIPM_PATH 		*path_ptr = NULL;
	int             	path_idx = 0;

	if( pipm_l2_path_enable == FALSE )
	{
		return;
	}

	if( PIPM_shm_ptr == NULL )
	{
		LOG_FORCE( 0, "Error: PIPM_add_arp_ndp_socket - shared memory segment not attached, shmid=%x\n", PIPM_shmid );
		return;
	}
	dataP = (PIPM_DATA *)PIPM_shm_ptr;

	/*
	 * Loop all paths of all interfaces and add them to the read socket set.
	 */
        for ( ( i = 0, data_ptr = &(dataP->intf_data[0]) );
	      ( i < dataP->intf_cnt ); 
              ( i++, data_ptr++ ) )
	{
		if ( data_ptr->type == PIPM_INTERNAL_INTF )
		{
			continue;
		}

		for ( ( subnet_idx = 0, subnet_ptr = &(data_ptr->subnet[0]) );	
			( subnet_idx < data_ptr->subnet_cnt );
			( subnet_idx++, subnet_ptr++ ) )
		{
			for ( ( path_idx = 0, path_ptr = &subnet_ptr->path[0] );
				( path_idx < subnet_ptr->path_cnt );
				( path_idx++, path_ptr++ ) )
			{
				if ( path_ptr->vlanId == 0 )
				{
					if( path_ptr->lsn0_arpsock >= 0 )
					{
						FD_SET( path_ptr->lsn0_arpsock, read_sock_set);
	
						if (path_ptr->lsn0_arpsock > *max_sock)
						{
							*max_sock = path_ptr->lsn0_arpsock;
						}
					}

					if( path_ptr->lsn1_arpsock >= 0 )
					{
						FD_SET( path_ptr->lsn1_arpsock, read_sock_set);
	
						if (path_ptr->lsn1_arpsock > *max_sock)
						{
							*max_sock = path_ptr->lsn1_arpsock;
						}
					}
				}
			}
		}
	}

	return;
}

/**********************************************************************
 *
 * Name:        PIPM_process_arpndp_socket()
 *
 * Abstract:    Determine the ARP and NDP sockets for processing
 *
 * Parameters:  fd_set - FD set pointer
 *
 * Returns:     none
 *
 **********************************************************************/

void PIPM_process_arpndp_socket(fd_set *read_sock_set)
{
	
	register PIPM_INTF	*data_ptr;
	PIPM_DATA               *dataP;
	int			i;
	void			*intfDataP = NULL;
	PIPM_SUBNET 		*subnet_ptr = NULL;
	int             	subnet_idx = 0;
	PIPM_PATH 		*path_ptr = NULL;
	int             	path_idx = 0;
	int			ret;
	PIPM_INTF_TYPE_EXT	intfTypeExt;

	if( pipm_l2_path_enable == FALSE )
	{
		return;
	}

	if( PIPM_shm_ptr == NULL )
	{
		LOG_FORCE( 0, "Error: PIPM_process_arpndp_socket - shared memory segment not attached, shmid=%x\n", PIPM_shmid );
		return;
	}
	dataP = (PIPM_DATA *)PIPM_shm_ptr;

	/*
	 * Loop all paths of all interfaces to try to get MAC from ARP/NS
	 * response message. It shouldn't take much long here because 
	 * the is_arp_sent is 0 in lots of time. Path referesh logical will
	 * control the ARP/NS sending
	 */
        for ( ( i = 0, data_ptr = &(dataP->intf_data[0]) );
	      ( i < dataP->intf_cnt ); 
              ( i++, data_ptr++ ) )
	{
		for ( ( subnet_idx = 0, subnet_ptr = &(data_ptr->subnet[0]) );	
			( subnet_idx < data_ptr->subnet_cnt );
			( subnet_idx++, subnet_ptr++ ) )
		{
			for ( ( path_idx = 0, path_ptr = &subnet_ptr->path[0] );
				( path_idx < subnet_ptr->path_cnt );
				( path_idx++, path_ptr++ ) )
			{
				if ( path_ptr->vlanId == 0 )
				{
					if (!((( path_ptr->lsn0_arpsock >= 0 ) &&
					      ( FD_ISSET( path_ptr->lsn0_arpsock, read_sock_set))) ||
					     (( path_ptr->lsn1_arpsock >= 0 ) &&
					      ( FD_ISSET( path_ptr->lsn1_arpsock, read_sock_set)))))
					{	
						continue;
					}

					intfTypeExt = PIPM_BASE_INTF;
					intfDataP = (void *)data_ptr;
				}
				else
				{
					continue;
				}

				ret = PIPM_process_arp_na_per_path( path_ptr, intfDataP, subnet_ptr, intfTypeExt);
				if ( ret  == IPM_SUCCESS )
				{
					ret = PIPM_send_ipmsgpath_update(PIPM_REFRESH_PATH, 
						PIPM_NULL_PATH_INTF, path_ptr, subnet_ptr, intfDataP, intfTypeExt);
					if ( ret  != IPM_SUCCESS )
					{
						LOG_FORCE(0, "PIPM_process_arpndp_socket: PIPM_send_ipmsgpath_update Failed ret=%d\n", ret);
					}
					else
					{
						LOG_OTHER(0, "PIPM_process_arpndp_socket: update MAC\n");
					}
					// Set it as 0 because this path's MAC has been updated
			 		path_ptr->is_arp_sent = 0;

					//reset path MAC before sending ARP/NS
					memset(&(path_ptr->remote_mac[0][0]), 0, ETH_ALEN);
					memset(&(path_ptr->remote_mac[1][0]), 0, ETH_ALEN);
				}
			}
		}
	}

	return;
}

/**********************************************************************
 *
 * Name:	PIPM_send_macmsg()
 *
 * Abstract:	Send a MAC update to the IP Message Path Kernel Module
 *
 * Parameters:	action - Update MAC address
 *              ip_ptr - IP address info.
 *              mac_addr_ptr - MAC Address 
 *              intf_ptr - Interface name 
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/
int PIPM_send_macmsg( PIPM_MAC_ACTION action, IPM_IPADDR *ip_ptr, unsigned char *mac_addr_ptr, char *intf_ptr )
{
	IPMK_MACADDR_MSG	mac_msg;
	int			ret;
	uint32_t		msg_type;
	char			ipbuf[ IPM_IPMAXSTRSIZE ];

	memset(&mac_msg,0,sizeof(mac_msg));

	switch( action )
	{
	case PIPM_UPDATE_MAC:
		msg_type = IPMK_PIPM_MACADDRUPDATE;
		break;

	default:
		LOG_ERROR( 0, "Error: PIPM_send_macmsg Invalid action [%d]", action );
		return IPM_FAILURE;
	}

	mac_msg.af = (ip_ptr->addrtype == IPM_IPV4 ) ? AF_INET : AF_INET6;
	IPM_ipaddr2in( ip_ptr, &mac_msg.dest_ip );

	snprintf( &mac_msg.recv_iface[0], MAX_NLEN_DEV, "%s",
                  intf_ptr );

	memcpy(mac_msg.mac_addr, mac_addr_ptr, ETH_ALEN);

	LOG_OTHER( 0,
       	 	"PIPM_sendIPMKpathmgt msg type %d ip %s iface %s mac (%x:%x:%x:%x:%x:%x)\n",
		msg_type,
		IPM_chkipaddr2p(ip_ptr, ipbuf, sizeof(ipbuf)),
		&mac_msg.recv_iface[0],
		mac_msg.mac_addr[0],
		mac_msg.mac_addr[1],
		mac_msg.mac_addr[2],
		mac_msg.mac_addr[3],
		mac_msg.mac_addr[4],
		mac_msg.mac_addr[5] );

	ret = PIPM_sendIPMKpathmgt( &mac_msg, msg_type, sizeof(mac_msg) );
	if( ret != 0 )
	{
		 LOG_ERROR( 0, "Error: PIPM_send_macmsg failed ret [%d]", ret );
		return IPM_FAILURE;
	}

	return IPM_SUCCESS;
}

/**********************************************************************
 *
 * Name:	PIPM_send_l2_pathmsg()
 *
 * Abstract:	Send a update to the IP Message Path Kernel Module
 *
 * Parameters:	action - alw/inh l2 path
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/
int PIPM_send_l2_pathmsg( PIPM_L2_PATH_ACTION action )
{
	int			ret;
	uint32_t		msg_type;

	switch( action )
	{
	case PIPM_ALW_L2_PATH:
		msg_type = IPMK_ALW_L2_PATH;
		break;

	case PIPM_INH_L2_PATH:
		msg_type = IPMK_INH_L2_PATH;
		break;

	default:
		LOG_ERROR( 0, "Error: PIPM_send_l2_pathmsg Invalid action [%d]", action );
		return IPM_FAILURE;
	}

	LOG_DEBUG( 0,
       	 	"PIPM_sendIPMKpathmgt: msg type %d\n",
		msg_type );

	ret = PIPM_sendIPMKpathmgt( (void *)0, msg_type, 0 );
	if( ret != 0 )
	{
		 LOG_ERROR( 0, "Error: PIPM_send_l2_pathmgt failed ret [%d]", ret );
		return IPM_FAILURE;
	}

	return IPM_SUCCESS;
}

#endif
