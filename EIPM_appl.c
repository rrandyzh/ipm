/**********************************************************************
 *
 * File:
 *	EIPM_appl.c
 *
 * Functions in this file:
 *      EIPM_acmIntfTimeout        - Takes action on the specified interface every tick.
 *	EIPM_timeout()		- Timer routine (called every 50 msec)
 *	EIPM_acm_timeout()	- ACM-specific timer processing.
 *	EIPM_timeout_postprocess() - Common timer processing after
 *				  protocol-specific work is done.
 *	EIPM_send_packet()	- Send a ping-pong packet
 *	EIPM_acm_state_routine() - EIPM ACM protocol state machine
 *	EIPM_action()		- Called when in ACTION state.
 *	EIPM_grat_arp_all()	- Send gratuitous ARP to all.
 *	EIPM_grat_arp()		- Send gratuitous ARP.
 *	EIPM_grat_arp6()	- Send IPv6 version of GARP.
 *	EIPM_next_arp()		- Determine next ARP to send.
 *	EIPM_sendARP()		- Send ARP/neighbor solication request.
 *	EIPM_proxy_path()	- Send ARP/neighbor solication request for proxy/path.
 *
 **********************************************************************/

#if defined (_X86)
#define _GNU_SOURCE
#include <netinet/in.h>
#endif
	
#include "EIPM_include.h"
#include "EIPM_bfd.h"
	
/**********************************************************************
 *
 * Name:	EIPM_acmIntfTimeout
 *
 * Abstract:	
 *     Determines what actions need to be taken for the specified interface
 *     on each timer tick (currently 50 msec).
 *
 * Parameters:
 *     intfDataP - Base/extension interface data pointer.
 *                 Type: EIPM_INTF/EIPM_INTF_SPEC
 *     intfType - Identifies the interface as base/extension.
 *     intfDataIdx - Index of the base/extension interface in the data.
 *
 * Returns:
 *     IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int EIPM_acmIntfTimeout( void *intfDataP, EIPM_INTF_TYPE intfType, int i )
{

        register EIPM_INTF	*data_ptr;
        register EIPM_INTF_SPEC *intfSpecDataP;
	struct pkt_hdr		*hdr_ptr;
	struct sockaddr_ll	from;
	char			buffer[ MAX_RCV_SIZE ];
	char			linebuf[ 256 ];
	char			errdev[ EI_INTFNAMESIZE ];
	int			socket;
	int			sockad_len;
	int			msg_len;
	int			flags;
	int			retval;
	unsigned short		checksum;

	int tmp_msg_len;
	char tmp_buffer[ MAX_RCV_SIZE ];
	int msg_cnt;
	int src_intf;
	unsigned char src_mac[6];
	unsigned char dst_mac[6];

        EIPM_SET_INTF_PTRS( intfDataP, intfType, data_ptr, intfSpecDataP );

        if ( NULL == data_ptr )
        {
                return IPM_FAILURE;
        }

        
        /*
         * See if we should start monitoring - we cannot start 
	 * monitoring until all of the data has arrived.
	 * If not just skip it.
	 */
	if( intfSpecDataP->monitor == EIPM_MONITOR_SNDPKT )
	{		
		/*
		 * On odd tick counts we transmit messages, on even
		 * tick counts we look for received packets on
		 * the interface we sent to last time.
		 */
		if( (EIPM_tick_cnt & 1) == 0 )
		{
			/*
			 * Even tick count.  Look for received
			 * packets.
			 */
			/* DBG */
			LOG_DEBUG( 0,
			           "EIPM - EIPM_acmIntfTimeout() - receive for interface %s%s-%s%s\n",
			           data_ptr->lsn0_baseif,
                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
			           data_ptr->lsn1_baseif,
                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

                        /*
		 	 * Figure out the destination socket based on the
			 * direction we were sending.
			 */
			if( intfSpecDataP->dir == LSN02LSN1 )
			{
				socket = intfSpecDataP->lsn1_socket;
				src_intf = intfSpecDataP->lsn0_iface_indx;
				memcpy(src_mac, data_ptr->lsn0_hwaddr, 6);
				memcpy(dst_mac, data_ptr->lsn1_hwaddr, 6);
			}
			else
			{
				socket = intfSpecDataP->lsn0_socket;
				src_intf = intfSpecDataP->lsn1_iface_indx;
				memcpy(src_mac, data_ptr->lsn1_hwaddr, 6);
				memcpy(dst_mac, data_ptr->lsn0_hwaddr, 6);
			}
			
			/*
			 * We cannot block if there is no data in
			 * the socket.
			 */
			flags = MSG_DONTWAIT;
			sockad_len = sizeof( from );

			// This is to handle the case that there are many response in socket due to some reason.
			// For this case, only the last one will be treated as valid.
			msg_len = -1;
			msg_cnt = 0;
			tmp_msg_len = -1;
			do
			{
				tmp_msg_len = recvfrom(socket, tmp_buffer, MAX_RCV_SIZE, flags, (struct sockaddr *) &from, &sockad_len);
				// msg_len and buffer is used to keep the last valid one
				if (tmp_msg_len > 0)
				{
					struct pkt_hdr * hdr_ptr = (struct pkt_hdr *) tmp_buffer;
					// Only the packet with correct destination MAC is checked. In promiscuous mode, it
					// may receive the packet from other balde. If this wrong packet is the last one, the
					// pingpong packet verification on local host will be affected.
					if (memcmp(dst_mac, hdr_ptr->eth_hdr.h_dest, ETH_ALEN) == 0)
					{
						msg_len = tmp_msg_len;
						memcpy(buffer, tmp_buffer, msg_len);
					}
					else
					{
						unsigned char dst_mac[6];
						memcpy(dst_mac, hdr_ptr->eth_hdr.h_dest, ETH_ALEN);
						LOG_DEBUG(0, "PingPong packet has wrong DST MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
								dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
					}
				}
				// To avoid the tight loop, only first 10 packet will be handled.
				msg_cnt++;
			} while ((tmp_msg_len > 0) && (msg_cnt < 10));

			if (msg_cnt > 2)
			{
				LOG_ERROR(0, "Warning: %d packets found in the socket, only the last one will be verified.", msg_cnt-1);
			}
			
			if ( msg_len < 0)
			{
				if( errno == EAGAIN )
				{
					/* DBG */
					 LOG_DEBUG( 0,
				                   "EIPM - EIPM_acmIntfTimeout - recvfrom - nothing in socket, iface=%s%s-%s%s\n",
					           data_ptr->lsn0_baseif,
                                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
					           data_ptr->lsn1_baseif,
                                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
				}
				else if( errno == EINTR )
				{
					LOG_DEBUG( 0,
				                   "EIPM - EIPM_acmIntftimeout - recvfrom - interrupted, iface=%s%s-%s%s\n",
				                   data_ptr->lsn0_baseif,
                                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
				                   data_ptr->lsn1_baseif,
                                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
				}
				else
				{
					LOG_ERROR( 0,
				                   "Error: EIPM - EIPM_acmIntfTimeout - recvfrom returned error, iface=%s%s, socket=%d, retVal=%d, errno=0x%x\n",
				  	           data_ptr->lsn0_baseif, 
                                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE),
                                                   socket, msg_len, errno );

					(void)close(intfSpecDataP->lsn0_socket);
					(void)close(intfSpecDataP->lsn1_socket);

					retval = EIPM_create_intf_sockets( intfDataP, intfType );

					if( retval != IPM_SUCCESS )
					{
						LOG_ERROR( 0, 
						           "Error: EIPM_acmIntfTimeout() - Creating monitor sockets failed for interface=%s%s\n",
						           data_ptr->lsn0_baseif, ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
					}

					/*
					 * Continue on anyway.
					 */
				}
				
				/*
				 * Either way there was no data in
				 * the socket.
				 */
				intfSpecDataP->msg_rcvd = FALSE;
					
			}
			else
			{
				// Received a message, get a pointer to the buffer.
				struct eipm_packet *pkt_ptr = (struct eipm_packet *) &buffer; 

				if (EIPM_chk_pipong_packet(src_intf, src_mac, pkt_ptr) == 0)
				{
					LOG_DEBUG( 0,
					           "EIPM - EIPM_acmIntfTimeout - Received packet %d between %s%s - %s%s dir %d\n",
					            pkt_ptr->seqno,
					            data_ptr->lsn0_baseif,
                                                    ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
					            data_ptr->lsn1_baseif,
                                                    ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
					            intfSpecDataP->dir );

					/*
					 * Valid message received.
					 */
					intfSpecDataP->msg_rcvd = TRUE;
				
					if( intfSpecDataP->dir == LSN02LSN1 )
					{
						if( intfSpecDataP->lsn1_rcv_seqno > 0 &&
						    intfSpecDataP->lsn1_rcv_seqno + 2 != pkt_ptr->seqno )
						{
							intfSpecDataP->lsn1_sequence_error_count++;

							sprintf( linebuf,
						         	 "EIPM - EIPM_acmIntfTimeout - Received out of sequence packet %d, expected %d between %s%s -> %s%s\n",
							         pkt_ptr->seqno,
							         intfSpecDataP->lsn0_rcv_seqno + 2,
							         data_ptr->lsn1_baseif,
                                                                 ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
							         data_ptr->lsn0_baseif,
                                                                 ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

							LOG_ERROR( 0, 
								   linebuf );
						}

						intfSpecDataP->lsn1_rcv_seqno = pkt_ptr->seqno;
					}
					else
					{
						if( intfSpecDataP->lsn0_rcv_seqno > 0 &&
						    intfSpecDataP->lsn0_rcv_seqno + 2 != pkt_ptr->seqno )
						{
							intfSpecDataP->lsn0_sequence_error_count++;

							sprintf( linebuf,
						         	 "EIPM - EIPM_acmIntfTimeout - Received out of sequence packet %d, expected %d between %s%s -> %s%s\n",
							         pkt_ptr->seqno,
							         intfSpecDataP->lsn0_rcv_seqno + 2,
							         data_ptr->lsn1_baseif,
                                                                 ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
							         data_ptr->lsn0_baseif,
                                                                 ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

							LOG_ERROR( 0, linebuf );
						}

						intfSpecDataP->lsn0_rcv_seqno = pkt_ptr->seqno;
					}
				}
				else
				{
					sprintf( linebuf,
				                 "EIPM - EIPM_acmIntfTimeout - Received corrupted packet between %s%s-%s%s, dir=%d\n",
				                 data_ptr->lsn0_baseif,
                                                 ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
				                 data_ptr->lsn1_baseif,
                                                 ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
				                 intfSpecDataP->dir );
					
					LOG_ERROR( 0,
					         linebuf );
					
					if( intfSpecDataP->dir == LSN02LSN1 )
					{
						strcpy( errdev, data_ptr->lsn1_baseif );
                                                intfSpecDataP->lsn1_corrupt_packet_count++;
					}
					else
					{
						strcpy( errdev, data_ptr->lsn0_baseif );
                                                intfSpecDataP->lsn0_corrupt_packet_count++;
					}
				}
			}

			/*
			 * Call function to execute state machine
			 * based on whether or not a message was
			 * received.
			 */
			retval = EIPM_acm_state_routine( intfDataP, intfType, i );
			
			if( retval != IPM_SUCCESS )
			{
				LOG_ERROR( 0,
			                   "Error: EIPM_acmIntfTimeout - EIPM_state_routine returned error, iface=%s%s, retVal=%d\n",
				           data_ptr->lsn0_baseif, 
                                           ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ), 
                                           retval );
			}

                        if( EIPM_GET_REPORT_STATUS_TIMER(intfSpecDataP) > 0 )
                        {
                                EIPM_GET_REPORT_STATUS_TIMER(intfSpecDataP)--;
                        }

                        if( EIPM_GET_REPORT_STATUS_TIMER(intfSpecDataP) == 0 )
                        {
                                EIPM_report_status();

                                EIPM_SET_REPORT_STATUS_TIMER(intfSpecDataP, EIPM_REPORT_STATUS_INTERVAL);
                        }
		}
		else
		{
			/* DBG */
			LOG_DEBUG( 0,
		 	           "EIPM - EIPM_acmIntfTimeout() - transmit for interface: %s%s-%s%s\n",
		 	           data_ptr->lsn0_baseif,
                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
		 	           data_ptr->lsn1_baseif,
                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
			
			/*
			 * This is an odd tick count.
			 * Send a message for the interface.
			 */
			EIPM_send_packet( intfDataP, intfType );

			if( EIPM_GET_PROXY_PATH_TIMER(data_ptr) > 0 )
                        {
                                EIPM_GET_PROXY_PATH_TIMER(data_ptr)--;

                        }

                        if( EIPM_GET_PROXY_PATH_TIMER(data_ptr) == 0 )
                        {
				//send out arp/ipv6 neighbor discover-solicitation request
                                EIPM_proxy_path(intfDataP, intfType);
                                EIPM_SET_PROXY_PATH_TIMER(data_ptr,
                                        (nma_ctx.b.proxy_path_timer * 1000)/(nma_ctx.b.psupervision));
                        }
		}		

	} /* end 'monitor=EIPM_MONITOR_SNDPKT' */

        if (( intfSpecDataP->monitor != EIPM_MONITOR_BFD )
		&& (intfSpecDataP->monitor != EIPM_MONITOR_WCNP))
        {
		/* Ignore any failures */
		(void)EIPM_timeout_postprocess( intfDataP, intfType );
	}

        return( IPM_SUCCESS );

} /* end 'EIPM_acmIntfTimeout' */



/**********************************************************************
 *
 * Name:	EIPM_timeout()
 *
 * Abstract:	Determines what actions need to be taken on each
 *		timer tick (currently 50 msec).
 *
 * Parameters:	None
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/


int EIPM_timeout( )

{
	int			retval, tmp_retval;
	
	/*
	 * Make sure we are attached to shared memory segment.
	 */
	if( EIPM_shm_ptr == NULL )
	{
		LOG_ERROR( 0,
	       	 "Error: EIPM - shared memory segment not attached, shmid=%x\n", EIPM_shmid );
		return( IPM_FAILURE );
	}
	
	/*
	 * If data has not been initialized then there is nothing
	 * to do.
	 */
	if( ((EIPM_DATA *)EIPM_shm_ptr)->intf_cnt == 0 )
	{
		LOG_DEBUG( 0,
	       	 "EIPM - EIPM_timeout() nothing to do\n" );
		return( IPM_SUCCESS );
	}
	
	/*
	 * Shared memory segment is initialized.
	 */
	
	/* Inform the EIPM log throttling code that this
	 * funtion has been called.
	 */
	EIPM_THROT_TICK();

	/* Call the protocol-specific (e.g. ACM and/or BFD, or WCNP)
	 * function(s) to process the timeout occurrence.
	 */
#ifndef _VHE
	EIPM_wcnp_tout();
#endif

	retval = EIPM_acm_timeout();

	tmp_retval = EIPM_bfd_tout();

	if (retval == IPM_SUCCESS)
	{
		retval = tmp_retval;
	}

	tmp_retval = EIPM_arpndp_tout();

	if (retval == IPM_SUCCESS)
	{
		retval = tmp_retval;
	}

	return retval;

}

void EIPM_audit_all_syctl()
{
	register EIPM_INTF	*data_ptr;
	register EIPM_INTF_SPEC	*intfSpecDataP;
	int			i;
	int			extnIntfIndex = 0;
	
	/*
	 * Loop through shared data.
	 */
	for( i = 0, data_ptr = &((EIPM_DATA *)EIPM_shm_ptr)->intf_data[ 0 ];
	     i < ((EIPM_DATA *)EIPM_shm_ptr)->intf_cnt; 
             i++, data_ptr++ )
	{
				 				
                (void)EIPM_check_sysctl_parameters( data_ptr, EIPM_BASE_INTF );
                /* Process ALL corresponding extension/child interface, if any, as well. */

                for ( ( intfSpecDataP = &(((EIPM_DATA *)EIPM_shm_ptr)->extnIntfData[extnIntfIndex]) ); 
                      ( extnIntfIndex < ((EIPM_DATA *)EIPM_shm_ptr)->extnIntfCount );
                      ( extnIntfIndex++, intfSpecDataP++ ) )
                {
                     if ( intfSpecDataP->baseIntfIdx == i )
                           (void)EIPM_check_sysctl_parameters( intfSpecDataP, EIPM_EXTN_INTF );                      

                } /* end 'extension interfaces scan' */

	} /* end 'for each monitored interface' */

	return;
}

int EIPM_acm_timeout()
{
	/* Keep track of how many times this function has been called
	 * since the last time this variable got reset to zero. This
	 * allows the main timeout function to be called every X ms
	 * but subordinate protocol-specific functions like this one
	 * to get called every Y ms where Y is a multiple of X.
	 */
	static int		num_timeouts = 0;

	register EIPM_INTF	*data_ptr;
	register EIPM_INTF_SPEC	*intfSpecDataP;
	int			i;
	int			extnIntfIndex;
        unsigned short          extnIntfMaxScan = 2;
        BOOL                    bExtnIntfMonitored = FALSE;
        int                     numExtnIntfsToScan;

	/* This function gets called every 5ms but only needs to
	 * act every 50ms (at time of writing - check current values).
	 */
	num_timeouts++;

	if ( num_timeouts >= (EIPM_ACM_INTERVAL_TIMER/EIPM_INTERVAL_TIMER) )
	{
		num_timeouts = 0;
	}
	else
	{
		return IPM_SUCCESS;
	}

	/*
	 * On odd tick counts we transmit messages, on even
	 * tick counts we look for received packets on
	 * the interface we sent to last time.
	 */
	++EIPM_tick_cnt;
	
	/*
	 * Loop through shared data.
	 */
	for( i = 0, data_ptr = &((EIPM_DATA *)EIPM_shm_ptr)->intf_data[ 0 ];
	     i < ((EIPM_DATA *)EIPM_shm_ptr)->intf_cnt; 
             i++, data_ptr++ )
	{

                (void)EIPM_acmIntfTimeout( data_ptr, EIPM_BASE_INTF, i );        

		if ( -1 == data_ptr->extnIntfIdx )
                {
                        continue;
                }

                /* Process a corresponding extension/child interface, if any, as well. */
                extnIntfIndex = data_ptr->extnIntfIdx;
                numExtnIntfsToScan = ((EIPM_DATA *)EIPM_shm_ptr)->extnIntfCount;

                if (    ( extnIntfIndex < 0 ) 
                     || (    ( extnIntfIndex != 0 ) 
                          && ( extnIntfIndex >= numExtnIntfsToScan ) ) )
                {
                        ASRT_RPT( ASBAD_DATA, 0, "baseIntfIdx: %d Invalid extension interface index: %d\n",
                                  i, extnIntfIndex );
                        extnIntfIndex = data_ptr->extnIntfIdx = 0;
                }

                /*
                 *  If the scan of the extension/child interfaces begins at index other than 0,
                 *  the scan needs to be done in 2 parts:
                 *  - current index to the max configured interfaces; and
                 *  - index 0 to current index.
                 */
                while ( extnIntfMaxScan != 0 )
                {

                        for ( ( intfSpecDataP = &(((EIPM_DATA *)EIPM_shm_ptr)->extnIntfData[extnIntfIndex]) ); 
                              ( extnIntfIndex < numExtnIntfsToScan );
                              ( extnIntfIndex++, intfSpecDataP++ ) )
                        {
                                if ( intfSpecDataP->baseIntfIdx == i )
                                {
                                        (void)EIPM_acmIntfTimeout( intfSpecDataP, EIPM_EXTN_INTF, extnIntfIndex );
                                        extnIntfIndex++;

					if ( 0 == ( EIPM_tick_cnt & 1 ) )
                                        {
                                                if ( extnIntfIndex == ((EIPM_DATA *)EIPM_shm_ptr)->extnIntfCount )
                                                {
                                                        /* Reset 'extnIntfIdx' to start from the beginning. */
                                                        data_ptr->extnIntfIdx = 0;
                                                }
                                                else
                                                {
                                                        data_ptr->extnIntfIdx = extnIntfIndex;
                                                }
                                        }

                                        bExtnIntfMonitored = TRUE;

                                        break;
                                }
                        }

                        /* 
                         *  Done if ...
                         *      - Extension interface was monitored.
                         *      - Extension interface was not monitored, but scan began at beginning of array and no
                         *        extension interface matching the base interface was found.
                         */
                        if (    ( TRUE == bExtnIntfMonitored ) 
                             || ( 0 == data_ptr->extnIntfIdx ) )
                        {
                                /* Done. */
                                break;
                        }

                        /* First scan didn't start at the beginning of the array. Continue the scan from the beginning of the array. */
                        extnIntfIndex = 0;
                        numExtnIntfsToScan = data_ptr->extnIntfIdx;
                        extnIntfMaxScan--;

                } /* end 'extension interfaces scan' */

	} /* end 'for each monitored interface' */

	return IPM_SUCCESS;

} /* EIPM_acm_timeout() */

int EIPM_timeout_postprocess( register void *intfDataP, EIPM_INTF_TYPE intfType )
{
	    int			intf_idx;
	    int			retval;
	    uint16_t vlanId=0;
	    register EIPM_INTF	*data_ptr;
            register EIPM_INTF_SPEC *intfSpecDataP;

	    EIPM_SET_INTF_PTRS( intfDataP, intfType, data_ptr, intfSpecDataP );

            if ( NULL == data_ptr )
            {
                return IPM_FAILURE;
            }

	    if ( intfType == EIPM_EXTN_INTF )
	    {
		vlanId = intfSpecDataP->vlanId;
	    }

	intf_idx = intfSpecDataP->baseIntfIdx;
	    if ( intfSpecDataP->monitor != EIPM_MONITOR_NULL )
	    {
		if ( EIPM_GET_INTF_CHECK_DISABLE( intfSpecDataP ) == FALSE )
		{
			EIPM_SUBNET *subnet_ptr;
			int subnet_idx;

			if ( EIPM_GET_INTF_CHECK_TIMER( intfSpecDataP ) > 0 )
			{
				EIPM_GET_INTF_CHECK_TIMER( intfSpecDataP )--;
			}

			if (    ( intfSpecDataP->preferred_side_update == TRUE )
			     && ( intfSpecDataP->status == EIPM_ONLINE ) )
			{
				char preferred_side_str[16];

				EIPM_network2str( intfSpecDataP->preferred_side, preferred_side_str );

				EIPM_check_route_priority( data_ptr , vlanId);
				(void)EIPM_check_intf( data_ptr );

				EIPM_check_ip_plumbing( intfDataP, intfType );

				EIPM_check_sysctl_parameters( intfDataP, intfType );

			        EIPM_check_routes( intfDataP, intfType );

				for( subnet_idx = 0, subnet_ptr = &data_ptr->subnet[0];
				     subnet_idx < data_ptr->subnet_cnt;
				     subnet_idx++, subnet_ptr++ )
				{
					EIPM_SET_GRAT_ARP( subnet_ptr, intfSpecDataP->preferred_side );

                                        // IPv6 just plumbed on LSN1, so let it finish tentative state
                                        // also skew them a bit
                                        if( subnet_ptr->ips[0].ipaddr.addrtype == IPM_IPV6 )
                                        {
                                                EIPM_GET_GRAT_ARP_CNT(subnet_ptr) -= data_ptr->subnet_cnt;
                                                EIPM_GET_GRAT_ARP_CNT(subnet_ptr) += subnet_idx;
                                        }
				}

				EIPM_GET_INTF_CHECK_TIMER(intfSpecDataP)++;

				intfSpecDataP->preferred_side_update = FALSE;

				LOG_FORCE( 0,
				           "EIPM - EIPM_intfTimeout - Updated Preferred Side to %s for %s%s - %s%s\n",
					   preferred_side_str,
					   data_ptr->lsn0_baseif,
                                           ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
					   data_ptr->lsn1_baseif,
                                           ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
			}

			if (EIPM_GET_INTF_CHECK_TIMER(intfSpecDataP) == 0)
			{
				int ret_ip = IPM_SUCCESS;
				int ret_rt = IPM_SUCCESS;
				int ret_if = IPM_SUCCESS;

				EIPM_check_sysctl_parameters(intfDataP, intfType);

				(void) EIPM_bfd_audit();

				ret_if = EIPM_check_intf(data_ptr);
				ret_ip = EIPM_check_ip_plumbing(intfDataP, intfType);
				ret_rt = EIPM_check_routes(intfDataP, intfType);

				if ( (ret_if == IPM_SUCCESS) && 
					(IPM_SUCCESS == ret_ip) && (IPM_SUCCESS == ret_rt) )
				{
					EIPM_SET_INTF_CHECK_TIMER(intfSpecDataP, 15);
				}
				else
				{
					EIPM_SET_INTF_CHECK_TIMER(intfSpecDataP, 1);
				}

			}

			for( subnet_idx = 0, subnet_ptr = &data_ptr->subnet[0];
			     subnet_idx < data_ptr->subnet_cnt;
			     subnet_idx++, subnet_ptr++ )
			{
				if (subnet_ptr->ip_cnt == 0)
				{
					continue;
				}
				if( IS_EIPM_READY_TO_SEND_GARP(subnet_ptr) )
				{

					retval = EIPM_grat_arp( intfDataP, intfType, EIPM_GET_GRAT_ARP( subnet_ptr ), subnet_ptr );

					if( (retval != IPM_SUCCESS) && 
					    (retval != IPM_IP_TENTATIVE) )
					{
						char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];

						/* Function already asserted.  */
						LOG_ERROR( EIPM_LOG_ARP,
							   "EIPM_intfTimeout - gratuitous ARP failed, iface %s%s, subnet %s/%d\n",
							   ( EIPM_GET_GRAT_ARP( subnet_ptr ) == LSN1 ) ? data_ptr->lsn1_baseif : data_ptr->lsn0_baseif,
                                                           ( ( EIPM_GET_GRAT_ARP( subnet_ptr ) == LSN1 ) 
                                                             ? ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) 
                                                             : ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) ),
							   IPM_ipaddr2p( &(subnet_ptr->subnet_base), ipm_ipstr_buf, sizeof( ipm_ipstr_buf ) ),
							   subnet_ptr->prefixlen );
						{
						 	char tmp_ipdata_str[EIPM_IPDATA_STR_SIZE];
						 	char tmp_subnet_str[EIPM_SUBNET_STR_SIZE];
						 	char tmp_intf_str[EIPM_INTF_STR_SIZE];
						
							if (subnet_ptr->ip_cnt > 0)
							{
								EIPM_IPDATA2STR(&(subnet_ptr->ips[0]), tmp_ipdata_str);
							}
							else
							{
								sprintf(tmp_ipdata_str,"ip_cnt=%d",subnet_ptr->ip_cnt);
							}

							EIPM_SUBNET2STR(subnet_ptr, tmp_subnet_str, vlanId);
							EIPM_INTF2STR(data_ptr, tmp_intf_str);
						
							LOG_ERROR( EIPM_LOG_ARP,
								"%s - GARP fail intf_idx %d subnet_idx %d EIPM_IPDATA ip[0] info: %s",
								__FUNCTION__,
								intf_idx,
								subnet_idx,
								tmp_ipdata_str
							    );
						
							LOG_ERROR( EIPM_LOG_ARP,
								"%s - GARP fail intf_idx %d subnet_idx %d EIPM_SUBNET info: %s",
								__FUNCTION__,
								intf_idx,
								subnet_idx,
								tmp_subnet_str
							    );
						
							LOG_ERROR( EIPM_LOG_ARP,
								"%s - GARP fail intf_idx %d subnet_idx %d EIPM_INTF info: %s",
								__FUNCTION__,
								intf_idx,
								subnet_idx,
								tmp_intf_str
							    );
						}
					}
					/*
					 * If the IP is tentative try again at the next interval.
					 */
					if( retval != IPM_IP_TENTATIVE )
					{
						/* 
						 * Decrement the counter to determine if/when to send 
						 * the next garp. 
						 */
						EIPM_DEC_GRAT_ARP_CNT(subnet_ptr);
					}
				}
				else
				{
					/* 
					 * Decrement the counter to determine if/when to send 
					 * the next garp.
					 */
					EIPM_DEC_GRAT_ARP_CNT(subnet_ptr);
				}						
			}
		}

		if ( EIPM_GET_REPORT_STATUS_TIMER( &(data_ptr->specData) ) > 0 )
		{
			EIPM_GET_REPORT_STATUS_TIMER( &(data_ptr->specData) )--;
		}

		if ( EIPM_GET_REPORT_STATUS_TIMER( &(data_ptr->specData) ) == 0 )
		{
			EIPM_report_status();
			EIPM_SET_REPORT_STATUS_TIMER( &(data_ptr->specData), EIPM_REPORT_STATUS_INTERVAL );
		}

	    }
	
	return( IPM_SUCCESS );
}



/**********************************************************************
 *
 * Name:	EIPM_send_packet()
 *
 * Abstract:	Called to send a ping-pong packet to the other
 *		interface.
 *
 * Parameters:	intfDataP - pointer to per-interface data
 *              intfType - Interface type.
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int EIPM_send_packet( register void *intfDataP, EIPM_INTF_TYPE intfType )
{
	
	register EIPM_INTF      *data_ptr;
        register EIPM_INTF_SPEC *intfSpecDataP;
	struct pkt_hdr		*hdr_ptr;
	struct sockaddr		from;
	struct in_addr 		ipm_ipv4_buf;
	int			snd_len;
		
	/*
	 * Calling function needs to make sure we are
	 * attached to the shared memory segment and that
	 * it is valid.
	 */

	EIPM_SET_INTF_PTRS( intfDataP, intfType, data_ptr, intfSpecDataP );

	if ( NULL == data_ptr )
        {
                return IPM_FAILURE;
        }


	/* Fill in the remaining message data.  Note that 
	 * unchanging fields are filled in at init time.
	 *
	 * Get a pointer to the message header.
	 */
	hdr_ptr = &EIPM_pkt.hdr;
	
	/*
 	 * Fill in Ethernet header.  Need to fill in MAC addresses
 	 * based on the direction we are sending.
	 */
	hdr_ptr->eth_hdr.h_proto = htons( eipm_proid );
	
	if ( intfSpecDataP->dir == LSN02LSN1 )
	{
		memcpy( hdr_ptr->eth_hdr.h_dest,
		        data_ptr->lsn1_hwaddr,
		        ETH_ALEN );
		memcpy( hdr_ptr->eth_hdr.h_source,
		        data_ptr->lsn0_hwaddr,
		        ETH_ALEN );
		
		EIPM_pkt.seqno = intfSpecDataP->seqno;
		EIPM_pkt.srcintf = intfSpecDataP->lsn0_iface_indx;

		if( eipm_debug == 2 )
		{
			EIPM_pkt.seqno -= 1;
		}

		/*
		 * Fill in the data.  Put the direction sent
		 * in the message.
		 */
		sprintf( EIPM_pkt.data, "Testing interface %s%s-%s%s, seqno=%ld",
		         data_ptr->lsn0_baseif,
                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
		         data_ptr->lsn1_baseif,
                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
		         intfSpecDataP->seqno++ );
	}
	else
	{
		memcpy( hdr_ptr->eth_hdr.h_dest,
		        data_ptr->lsn0_hwaddr,
		        ETH_ALEN );
		memcpy( hdr_ptr->eth_hdr.h_source,
		        data_ptr->lsn1_hwaddr,
		        ETH_ALEN );
		
		EIPM_pkt.seqno = intfSpecDataP->seqno;
		EIPM_pkt.srcintf = intfSpecDataP->lsn1_iface_indx;

		if( eipm_debug == 2 )
		{
			EIPM_pkt.seqno -= 1;
		}

		/*
		 * Fill in the data.  Put the direction sent
		 * in the message.
		 */
		sprintf( EIPM_pkt.data, "Testing interface %s%s-%s%s, seqno=%ld",
		         data_ptr->lsn1_baseif,
                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
		         data_ptr->lsn0_baseif,
                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
		         intfSpecDataP->seqno++ );
	}
	
	/*
	 * Finish filling in the header.  The data to be sent includes
	 * the header, source interface, check sum and user string.
	 */
	snd_len = sizeof (struct eipmhdr) + sizeof (uint32_t) + sizeof (unsigned long) +strlen(EIPM_pkt.data);
	hdr_ptr->eipm_hdr.len = htons( snd_len );
	
	/*
	 * Checksum includes header and data.
	 */
	hdr_ptr->eipm_hdr.check = 0;
	hdr_ptr->eipm_hdr.check = ipcksm( (unsigned short *)&hdr_ptr->eipm_hdr,
	                                 snd_len );

	if( eipm_debug == 1 )
	{
		sprintf( EIPM_pkt.data, "Messing interface %s%s-%s%s, seqno=%ld",
		         data_ptr->lsn1_baseif,
                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
		         data_ptr->lsn0_baseif,
                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
		         intfSpecDataP->seqno - 1 );
	}
	/*
	 * Get length of entire packet for socket.
	 */
	PKT_SIZE( snd_len );
	
	/*
	 * Something I found indicated you should fill in the
	 * hardware address and length in the sockaddr_ll
	 * structure for sending, although when I tested it
	 * worked without that.  I think bind() is filling that
	 * in.  Keep in mind.
	 */
	
	/*
	 * Now send the message based on the direction we should
	 * send this time.
	 */
	if ( intfSpecDataP->dir == LSN02LSN1 )
	{
		/*
		 * The "to" parameter here looks backwards (seems it
		 * should be lsn1_sll), but if we flip them the packets
		 * no longer work...
		 */
		if( sendto( intfSpecDataP->lsn0_socket,
		            &EIPM_pkt,
		            snd_len,
		            0,
		            (struct sockaddr *)&intfSpecDataP->lsn0_sll,
		            sizeof( struct sockaddr_ll ) ) < 0 )
		{
			/*
			 * sendto() failed - sigh.
			 */
			LOG_ERROR( 0,
				 "Error: EIPM - sendto failed for interface %s%s, errno=%d, sock=%d, len=%d\nsize=%d, sll.family=%d, sll.proto=%d, sll.ifindx=%d\nsll.hatype=%d, sll.halen=%d, sll.pkttype=%d, sll.addr=%X %X %X %X %X %X %X %X\n",
				 data_ptr->lsn0_baseif,
				 ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
				 errno,
				 intfSpecDataP->lsn0_socket,
				 snd_len,
				 sizeof( struct sockaddr_ll ),
				 intfSpecDataP->lsn0_sll.sll_family,
				 intfSpecDataP->lsn0_sll.sll_protocol,
				 intfSpecDataP->lsn0_sll.sll_ifindex,
				 intfSpecDataP->lsn0_sll.sll_hatype,
				 intfSpecDataP->lsn0_sll.sll_halen,
				 intfSpecDataP->lsn0_sll.sll_pkttype,
				 intfSpecDataP->lsn0_sll.sll_addr[0],
				 intfSpecDataP->lsn0_sll.sll_addr[1],
				 intfSpecDataP->lsn0_sll.sll_addr[2],
				 intfSpecDataP->lsn0_sll.sll_addr[3],
				 intfSpecDataP->lsn0_sll.sll_addr[4],
				 intfSpecDataP->lsn0_sll.sll_addr[5],
				 intfSpecDataP->lsn0_sll.sll_addr[6],
				 intfSpecDataP->lsn0_sll.sll_addr[7] );

			if( errno == EAGAIN ||
			    errno == EINTR )
			{
				LOG_DEBUG( 0,
					   "EIPM - sendto - interrupted, iface=%s%s-%s%s, errno %d\n",
					   data_ptr->lsn0_baseif,
                                           ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
					   data_ptr->lsn1_baseif,
                                           ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
					   errno );	
			}
			else
			{
				int retval;
				(void)close( intfSpecDataP->lsn0_socket );
				(void)close( intfSpecDataP->lsn1_socket );

				retval = EIPM_create_intf_sockets( intfDataP, intfType );

				if( retval != IPM_SUCCESS )
				{
					LOG_ERROR( 0, 
						   "Error: EIPM_send_packet() : Creating monitor sockets failed for interface=%s%s",
						   data_ptr->lsn0_baseif,
                                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
				}
			}

			return( IPM_FAILURE );
	        }

	}
	else
	{
		/*
		 * The "to" parameter here looks backwards (seems it
		 * should be lsn0_sll), but if we flip them the packets
		 * no longer work...
		 */
		if( sendto( intfSpecDataP->lsn1_socket,
		            &EIPM_pkt,
		            snd_len,
		            0,
		            (struct sockaddr *)&intfSpecDataP->lsn1_sll,
		            sizeof( struct sockaddr_ll ) ) < 0 )
		{
			/*
			 * sendto() failed - sigh.
			 */
			LOG_ERROR( 0,
				 "Error: EIPM - sendto failed for interface %s%s, errno=%d, sock=%d, len=%d\nsize=%d, sll.family=%d, sll.proto=%d, sll.ifindx=%d\nsll.hatype=%d, sll.halen=%d, sll.pkttype=%d, sll.addr=%X %X %X %X %X %X %X %X\n",
				 data_ptr->lsn1_baseif,
				 ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
				 errno,
				 intfSpecDataP->lsn1_socket,
				 snd_len,
				 sizeof( struct sockaddr_ll ),
				 intfSpecDataP->lsn1_sll.sll_family,
				 intfSpecDataP->lsn1_sll.sll_protocol,
				 intfSpecDataP->lsn1_sll.sll_ifindex,
				 intfSpecDataP->lsn1_sll.sll_hatype,
				 intfSpecDataP->lsn1_sll.sll_halen,
				 intfSpecDataP->lsn1_sll.sll_pkttype,
				 intfSpecDataP->lsn1_sll.sll_addr[0],
				 intfSpecDataP->lsn1_sll.sll_addr[1],
				 intfSpecDataP->lsn1_sll.sll_addr[2],
				 intfSpecDataP->lsn1_sll.sll_addr[3],
				 intfSpecDataP->lsn1_sll.sll_addr[4],
				 intfSpecDataP->lsn1_sll.sll_addr[5],
				 intfSpecDataP->lsn1_sll.sll_addr[6],
				 intfSpecDataP->lsn1_sll.sll_addr[7] );
			
			return( IPM_FAILURE );
	        }

	}
	

	return( IPM_SUCCESS );
}
	

#ifdef USINGSELECT

int EIPM_rcv_msg( int desc )

{
	register EIPM_INTF	*data_ptr;
	struct sockaddr_ll	from;
	char			buffer[ MAX_RCV_SIZE ];
	int			socket;
	int			msg_len;
	int			sockad_len;
	int			index;
	bool			toss;
		
	toss = FALSE;

	/*
	 * Make sure we are attached to shared memory segment.
	 */
	if( EIPM_shm_ptr == NULL )
	{
		LOG_ERROR( 0,
	       	 "Error: EIPM - shared memory segment not attached, shmid=%x\n", EIPM_shmid );
		return( IPM_FAILURE );
	}
	
	/*
	 * Make sure data is initialized.
	 */
	if( ((EIPM_DATA *)EIPM_shm_ptr)->valid != TRUE )
	{
		LOG_ERROR( 0,
	       	 "Error: EIPM - shared memory segment not initialized\n" );
		return( IPM_FAILURE );
	}
	
	/*
	 * Read interface data index from socket descriptor array.
	 */
	index = IPM_skt_desc[ desc ].index;
	
	LOG_DEBUG( 0,
       	 	"EIPM_rcv_msg() for desc=%d, index=%d\n", desc, index );

	/*
	 * Validate index.
	 */
	if( (index < 0) || (index >= EIPM_MAX_EXT_SUB) )
	{
		LOG_ERROR( 0,
	       	 "Error: EIPM - data index out of range (%d)\n", index );
		return( IPM_FAILURE );
	}
	
	data_ptr = &((EIPM_DATA *)EIPM_shm_ptr)->intf_data[ index ];


	/*
	 * Socket could match either socket descriptor for this
	 * interface - figure out which one.
	 */
	if ( data_ptr->specData.lsn0_socket == IPM_skt_desc[ desc ].desc )
	{
		/*
		 * Ponder - check if we should have received data
		 * on this socket based on the direction we were
		 * sending.
		 */
		socket = data_ptr->specData.lsn0_socket;
		
		if ( data_ptr->specData.dir != LSN12LSN0 )
		{
			/*
			 * We don't expect a message in this socket
			 * at this time - toss it.
			 */
			LOG_ERROR( 0,
			       	 "EIPM - received msg in wrong socket for %s\n",
				 data_ptr->lsn0_baseif );
				
			/*
			 * Not an error, but toss the frame (we
			 * still need to pull it out of the socket).
			 */
			toss = TRUE;
			
	        }
		
	}
	else if ( data_ptr->specData.lsn1_socket == IPM_skt_desc[ desc ].desc )
	{
		/*
		 * Ponder - check if we should have received data
		 * on this socket based on the direction we were
		 * sending.
		 */
		socket = data_ptr->specData.lsn1_socket;
		
		if ( data_ptr->specData.dir != LSN02LSN1 )
		{
			/*
			 * We don't expect a message in this socket
			 * at this time - toss it.
			 */
			LOG_ERROR( 0,
			       	 "EIPM - received msg in wrong socket for %s\n",
				 data_ptr->lsn1_baseif );
				
			/*
			 * Not an error, but toss the frame (we
			 * still need to pull it out of the socket).
			 */
			toss = TRUE;
	        }
	}
	else
	{
		/*
		 * No match - data must be hosed.
		 */
		LOG_ERROR( 0,
		       	 "Error: EIPM - index (%d) in IPM_skt_desk[] is invalid, desc=%d\n",
			 index, desc );
			
			return( IPM_FAILURE );
	}
	
	sockad_len = sizeof( from );
	msg_len = recvfrom( socket,
	                    buffer,
	                    MAX_RCV_SIZE,
	                    0,
	                    (struct sockaddr *)&from,
	                    &sockad_len);
	
	if ( msg_len < 0)
	{
		LOG_ERROR( 0,
		       	 "Error: EIPM_rcv_msg - recvfrom() failed, retval=%d, errno=0x%x\n",
			 msg_len, errno );
			
		return( IPM_FAILURE );
	}
	
	/* DBG */
	LOG_DEBUG( 0,
	         "EIPM - Received packet \"%s\" between %s-%s, dir=%d\n",
	         buffer+ALL_HDR_SIZE,
	         data_ptr->lsn0_baseif,
	         data_ptr->lsn1_baseif,
	         data_ptr->specData.dir );
			
	/*
	 * Mark that we received a message for this interface,
	 * if it is valid.
	 */
	if( toss != TRUE )
	{
		data_ptr->specData.msg_rcvd = TRUE;
	}
	
	return( IPM_SUCCESS );
}
#endif




/**********************************************************************
 *
 * Name:	EIPM_acm_state_routine()
 *
 * Abstract:	Code for EIPM ping-pong state machine
 *
 * Parameters:	intfDataP - pointer to per-interface data
 *              intfType - Interface type.
 *		index    - index of per-interface data
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int EIPM_state_routine( register void *intfDataP, EIPM_INTF_TYPE intfType, int index )
{
	/* Remove this intermediate step later */
	return EIPM_acm_state_routine(intfDataP,intfType,index);
}

int EIPM_acm_state_routine( register void *intfDataP, EIPM_INTF_TYPE intfType, int index )
{
	register EIPM_INTF      *data_ptr;
        register EIPM_INTF_SPEC *intfSpecDataP;
	char	linebuf[ 256 ];
	int	retval;
	int	i;
	int subn;

	EIPM_SET_INTF_PTRS( intfDataP, intfType, data_ptr, intfSpecDataP );

	if ( NULL == data_ptr )
        {
                return IPM_FAILURE;
        }
	
	
	/*
	 * Check if we received our message on the other
	 * interface last time we sent it.
	 */
	if ( intfSpecDataP->msg_rcvd == TRUE )
	{
		/*
		 * Switch so we send the other direction
		 * on the next send.
		 */
		SWITCH_DIR( intfSpecDataP->dir );
		
		/*
		 * Clear the message received flag.
		 */
		intfSpecDataP->msg_rcvd = FALSE;
		
		/*
		 * See if we need to perform a different
		 * action based on the current state.
		 */
		switch ( intfSpecDataP->state )
		{
		case NORMAL_STATE:
			
			/*
			 * Things are working as expected.
			 */
			if ( intfSpecDataP->recovery_state == NULL_REC_STATE )
			{
				intfSpecDataP->recovery_state = ARP_START;
			}

			retval = EIPM_action( intfDataP, intfType );

			if( retval != IPM_SUCCESS )
			{
				LOG_ERROR( 0,
					   "Error: EIPM_action() failed - retval=%d\n",
					    retval );
			}
			break;
			
			
		case DETECTION_STATE:
			
			/*
			 * We received a message before 
			 * leaving the DETECTION state,
			 * so go back to normal (must have
			 * been a glitch).  Print a log
			 * message.
			 */
			LOG_OTHER( 0,
				   "EIPM Connectivity restored - %s%s <-> %s%s : detection -> normal",
				   data_ptr->lsn0_baseif,
				   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
				   data_ptr->lsn1_baseif,
			           ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
			
			intfSpecDataP->state = NORMAL_STATE;
			break;
			
		case ACTION_STATE:

			// Check to make sure we've received messages in each direction before going on to
			// the soak state for soaking.
			if (++intfSpecDataP->counter >= 2)
			{
				// We have received enough messages, which means the connectivity is restored.
				// Get rid of ARP sockets for this interface.
				if (intfSpecDataP->lsn1_arpsock >= 0)
				{
					(void) close(intfSpecDataP->lsn1_arpsock);
				}
				intfSpecDataP->lsn1_arpsock = -1;

				if (intfSpecDataP->lsn1_v6arpsock >= 0)
				{
					(void) close(intfSpecDataP->lsn1_v6arpsock);
				}
				intfSpecDataP->lsn1_v6arpsock = -1;

				// Clean up other ARP data.
				intfSpecDataP->recovery_state = NULL_REC_STATE;

				// Change to RESTORE state to be soaking for specified time.
				// Initialize counter to for soaking counting.
				// Initialize soak_err_counter to start counting error time.
				intfSpecDataP->state = SOAK_STATE;
				intfSpecDataP->counter = 0;
				intfSpecDataP->soak_err_counter = 0;

				// Status is set to SOAKING. The routing update will be deferred till the status
				// is back to online.
				intfSpecDataP->status = EIPM_SOAKING;

				// The connectivity is restored, clear the alarms fired previously first.
				EIPM_CLEAR_ALL_ALARMS(intfDataP, intfType);

			}

			break;

		case SOAK_STATE:

			// counter is 0 means it's just come from action state.
			if (intfSpecDataP->counter == 0)
			{
				LOG_FORCE(0, "EIPM Connectivity recovery - %s%s <-> %s%s : failed -> soaking",
					data_ptr->lsn0_baseif,
					ipm_getVLANStr(intfSpecDataP->vlanId, TRUE),
					data_ptr->lsn1_baseif,
					ipm_getVLANStr(intfSpecDataP->vlanId, TRUE));

				// Fire new warning alarm to indicate the interface is in soaking state.
				EIPM_SEND_INTF_ALARM(EIPM_STATE_CHG,
					1,
					intfDataP,
					intfType,
					FSAS_warning,
					data_ptr->lsn0_baseif,
					"The interface is in soaking state.");
			}

			if (++intfSpecDataP->counter >= ((EIPM_DATA *) EIPM_shm_ptr)->soak_timer * PINGPONG_TICK)
			{
				intfSpecDataP->state = RESTORE_STATE;
			}

			break;

		case RESTORE_STATE:

			// We have received the requisite number of consecutive messages in the 
			// restore state. Print a log message and move back to the normal state.
			LOG_FORCE(0, "EIPM Connectivity restored - %s%s <-> %s%s : soaking -> normal",
				data_ptr->lsn0_baseif,
				ipm_getVLANStr(intfSpecDataP->vlanId, TRUE),
				data_ptr->lsn1_baseif,
				ipm_getVLANStr(intfSpecDataP->vlanId, TRUE));

			intfSpecDataP->state = NORMAL_STATE;

			// Status goes back to ONLINE.
			intfSpecDataP->status = EIPM_ONLINE;

			for (subn = 0; subn < data_ptr->subnet_cnt; subn++)
			{
				data_ptr->subnet[subn].status = EIPM_ONLINE;
				EIPM_update_subnet_route_priority(intfSpecDataP, &data_ptr->subnet[subn], LSN0);
			}

			EIPM_CHECK_INTF_CONFIG(intfSpecDataP);

			// Clear all interface alarms including the one for soaking
			EIPM_CLEAR_ALL_ALARMS(intfDataP, intfType);

			break;

		case SOAK_AUXOP:

			// Receiving pingpong packet with this state means the error within soak interval
			// does not exceed the 0.01% threshold, then back to restore state.
			LOG_FORCE(0, "EIPM Connectivity restored - %s%s <-> %s%s : %dms interrupted.",
				data_ptr->lsn0_baseif,
				ipm_getVLANStr(intfSpecDataP->vlanId, TRUE),
				data_ptr->lsn1_baseif,
				ipm_getVLANStr(intfSpecDataP->vlanId, TRUE),
				intfSpecDataP->soak_err_counter * 100);

			// Clear all alarms as the connectivity is restored.
			EIPM_CLEAR_ALL_ALARMS(intfDataP, intfType);

			// Fire the soaking alarm again.
			EIPM_SEND_INTF_ALARM(EIPM_STATE_CHG,
				1,
				intfDataP,
				intfType,
				FSAS_warning,
				data_ptr->lsn0_baseif,
				"The interface is in soaking state.");

			intfSpecDataP->state = SOAK_STATE;
			intfSpecDataP->status = EIPM_SOAKING;

			break;

		default:
			LOG_ERROR( 0,
			           "Error: EIPM - Invalid state %d, entry=%d\n", 
				   intfSpecDataP->state, index );
			
			return( IPM_FAILURE );
		
		} /* end 'switch on state' */
	}
	else
	{
		/*
		 * We did not receive a message for this
		 * interface - something is (or continues
		 * to be) wrong.
		 */
		switch ( intfSpecDataP->state )
		{
		case NORMAL_STATE:
			
			/*
			 * First indication of a problem.
			 * Move to the detection state and
			 * start the counter.
			 */
			
			intfSpecDataP->state = DETECTION_STATE;
			intfSpecDataP->counter = 1;
			
			LOG_OTHER( 0,
				   "EIPM Connectivity failure  - %s%s  -> %s%s : normal    -> detection",
				   (intfSpecDataP->dir == LSN02LSN1) ? data_ptr->lsn0_baseif : data_ptr->lsn1_baseif,
                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
				   (intfSpecDataP->dir == LSN02LSN1) ? data_ptr->lsn1_baseif : data_ptr->lsn0_baseif,
                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
			
			SWITCH_DIR( intfSpecDataP->dir );

			break;
			
			
		case DETECTION_STATE:
			
			/*
			 * We have previously started looking
			 * for a problem on this interface.
			 * See if we have gone over threshold
			 * to move to the ACTION state.
			 */
			if ( ++intfSpecDataP->counter >= DETECT_THRESH )
			{
				/*
				 * We have failed the requisite
				 * number of consecutive messages.
				 * Print a log message and
				 * move to the ACTION state.
				 */
				LOG_FORCE( 0,
					   "EIPM Connectivity failed   - %s%s <-> %s%s : detection -> failed",
					   data_ptr->lsn0_baseif,
                                           ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
					   data_ptr->lsn1_baseif,
                                           ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
				
				intfSpecDataP->state = ACTION_STATE;
				intfSpecDataP->counter = 0;
				
				/*
				 * We have lost connectivity to the
				 * other interface.  Therefore mark
				 * the state degraded now.  Also raise
				 * the alarm now.  The other
				 * option would be to wait until
				 * after we ARP, but a) we know there
				 * is a problem at this point - ARP
				 * success may just allow us to recover,
				 * and b) we continue to ARP, so we would
				 * do it more than once.
				 */
				intfSpecDataP->status = EIPM_DEGRADED;

				intfSpecDataP->preferred_side = LSN0;

				EIPM_CHECK_INTF_CONFIG( intfSpecDataP );
				
				if ( intfSpecDataP->dir == LSN02LSN1 )
				{
					sprintf( linebuf,
					         "Lost connectivity between %s%s and %s%s",
						 data_ptr->lsn0_baseif,
                                                 ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
						 data_ptr->lsn1_baseif,
                                                 ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
				}
				else
				{
					sprintf( linebuf,
					         "Lost connectivity between %s%s and %s%s",
						 data_ptr->lsn1_baseif,
                                                 ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
						 data_ptr->lsn0_baseif,
                                                 ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
				}
				
				EIPM_SEND_INTF_ALARM( EIPM_LNK_FAIL,
						      1,
						      intfDataP,
                                                      intfType,
				                      FSAS_major,
						      data_ptr->lsn0_baseif,
				                      linebuf );
						
				/*
				 * Now we switch the sending
				 * direction - we send in both
				 * directions while in the
				 * action state.
				 */
				SWITCH_DIR( intfSpecDataP->dir );
				
				/*
				 * Ensure IP addresses are installed on both
				 * interfaces.
				 */
				EIPM_check_ip_plumbing( intfDataP, intfType );

				/*
				 * Set up for doing recovery.
				 */
				intfSpecDataP->recovery_state = ARP_START;
				
				retval = EIPM_action( intfDataP, intfType );
				
				if( retval != IPM_SUCCESS )
				{
					LOG_ERROR( 0,
				                 "Error: EIPM_action() failed - retval=%d\n",
						 retval );
						
					return( IPM_FAILURE );
				}
			}
			else
			{
				/*
				 * We have not exceed threshold.
				 */
				SWITCH_DIR( intfSpecDataP->dir );
			}
			break;
			
		case ACTION_STATE:
			
			intfSpecDataP->counter = 0;

			/*
			 * Interface is still down.
			 * Need to call recovery code.
			 */
			retval = EIPM_action( intfDataP, intfType );
			
			if( retval != IPM_SUCCESS )
			{
				LOG_ERROR( 0,
			                 "Error: EIPM_action() failed - retval=%d\n",
					 retval );
					
				return( IPM_FAILURE );
			}
			
			/*
			 * Switch so we send the other direction
			 * on the next send.
			 */
			SWITCH_DIR( intfSpecDataP->dir );
			
			break;
			
		case SOAK_STATE:
			// PingPong packet is lost again during soaking.Set up for doing recovery.
			// We have to back through the ARP_START state to get things set back up
			// again.
			intfSpecDataP->recovery_state = ARP_START;

			// Ensure IP addresses are installed on both interfaces.
			EIPM_check_ip_plumbing(intfDataP, intfType);

			retval = EIPM_action(intfDataP, intfType);

			if (retval != IPM_SUCCESS)
			{
				LOG_ERROR(0, "Error: EIPM_action() failed - retval=%d\n", retval);

				return ( IPM_FAILURE);
			}

			SWITCH_DIR(intfSpecDataP->dir);

			// Change state to SOAK_AUXOP to do EIPM_action continuously. 
			// Meantime, check if the error counter is within threshold.
			intfSpecDataP->state = SOAK_AUXOP;

			break;

		case RESTORE_STATE:

			// PingPong packet is lost again during soaking.Set up for doing recovery.
			// We have to back through the ARP_START state to get things set back up
			// again.
			intfSpecDataP->recovery_state = ARP_START;

			// Ensure IP addresses are installed on both interfaces.
			EIPM_check_ip_plumbing(intfDataP, intfType);

			retval = EIPM_action(intfDataP, intfType);

			if (retval != IPM_SUCCESS)
			{
				LOG_ERROR(0, "Error: EIPM_action() failed - retval=%d\n", retval);

				return ( IPM_FAILURE);
			}

			SWITCH_DIR(intfSpecDataP->dir);

			// Change state to ACTION_STATE to do EIPM_action for error handling. 
			intfSpecDataP->state = ACTION_STATE;

			break;

		case SOAK_AUXOP:

			retval = EIPM_action(intfDataP, intfType);

			if (retval != IPM_SUCCESS)
			{
				LOG_ERROR(0, "Error: EIPM_action() failed - retval=%d\n", retval);
				return ( IPM_FAILURE);
			}

			SWITCH_DIR(intfSpecDataP->dir);

			// Check if ping-pong failure exceeds the 0.01% of total soaking time.
			// If so, back to ACTION_STATE again and abort the soak interval.
			if (++intfSpecDataP->soak_err_counter > ((EIPM_DATA *) EIPM_shm_ptr)->soak_timer/10000 * PINGPONG_TICK)
			{
				LOG_FORCE(0, "EIPM Connectivity failed   - %s%s  -> %s%s : soaking -> failed",
					(intfSpecDataP->dir == LSN02LSN1) ? data_ptr->lsn0_baseif : data_ptr->lsn1_baseif,
					ipm_getVLANStr(intfSpecDataP->vlanId, TRUE),
					(intfSpecDataP->dir == LSN02LSN1) ? data_ptr->lsn1_baseif : data_ptr->lsn0_baseif,
					ipm_getVLANStr(intfSpecDataP->vlanId, TRUE));

				intfSpecDataP->state = ACTION_STATE;
				intfSpecDataP->counter = 0;
				intfSpecDataP->soak_err_counter = 0;
				intfSpecDataP->status = EIPM_DEGRADED;

				// Clear all interface alarms fired previously. 
				EIPM_CLEAR_ALL_ALARMS(intfDataP, intfType);

				// Ping-pong packet is interrupted again, re-fire interface alarms.
				sprintf(linebuf, "Failed again during soaking between %s%s <-> %s%s",
					data_ptr->lsn0_baseif, ipm_getVLANStr(intfSpecDataP->vlanId, TRUE),
					data_ptr->lsn1_baseif, ipm_getVLANStr(intfSpecDataP->vlanId, TRUE));

				EIPM_SEND_INTF_ALARM( EIPM_LNK_FAIL,
							1,
							intfDataP,
							intfType,
							FSAS_major,
							data_ptr->lsn0_baseif,
							linebuf );
			}

			break;
			
		default:
			LOG_ERROR( 0,
			           "Error: EIPM - Invalid state %d, entry=%d\n", 
				   intfSpecDataP->state, index );
			
			return( IPM_FAILURE );
		
		} /* end 'switch on state' */

	} /* end 'if/else msg received' */
	
	return( IPM_SUCCESS );
	
} /* end func EIPM_acm_state_routine() */		




/**********************************************************************
 *
 * Name:	EIPM_action()
 *
 * Abstract:	Called when in ACTION state to send/receive ARP packets
 *
 * Parameters:	intfDataP - pointer to per-interface data
 *              intfType - Interface type.
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/


int EIPM_action( register void *intfDataP, EIPM_INTF_TYPE intfType )
{
	register EIPM_INTF      *data_ptr;
        register EIPM_INTF_SPEC *intfSpecDataP;
	register EIPM_ARPLIST	*arp_ptr;
	struct arp_pkt		*msg_ptr;
	EIPM_SUBNET 		*subnet_ptr;
 	struct sockaddr_ll	from;
	struct arp_pkt		arp;
	struct sockaddr_ll	haddr;
	char			buffer[ ARP_RCV_SIZE ];
	char 			arplistbuf[256]; 
	char 			ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
	struct in_addr 		ipm_ipv4_buf;
	struct in6_addr 	ipm_ipv6_buf;
	char			linebuf[ 256 ];
	int			retval;
	int			msg_len;
	int			sockad_len;
	int			flags;
	int			subn;
	int			i;
	int			count;
	bool 			append_comma;
	bool			recv_empty;
	bool			all_subnet_offline;	
	bool			all_subnet_online;		
	bool                    cleared_ipv4_lsn0_arp_rcv_que;
	bool                    cleared_ipv4_lsn1_arp_rcv_que;
	bool                    cleared_ipv6_lsn0_arp_rcv_que;
	bool                    cleared_ipv6_lsn1_arp_rcv_que;
	/*
	 * The vlanId is 0 for base interface
	 * It will get from EIPM_INTF_SPEC for external interface
	 */
	uint16_t		vlanId=0;

	if ( FALSE == EIPM_GET_PROXY_SERVER_ENABLED() )
        {
                return IPM_SUCCESS;
        }


	arp_ptr = NULL;

	EIPM_SET_INTF_PTRS( intfDataP, intfType, data_ptr, intfSpecDataP );

	if ( NULL == data_ptr )
        {
                return IPM_FAILURE;
        }

	// Get VLAN id if it it is external interface
	if ( intfType == EIPM_EXTN_INTF )
	{
		vlanId = intfSpecDataP->vlanId;
	}

	/*
	 * Determine what state we are in.  Then take any 
	 * action necessary based on that state.
	 */
	switch ( intfSpecDataP->recovery_state )
	{
	case ARP_START:
		/*
		 * Need to start sending ARPs to the list of 
		 * devices we have been given.  Begin with the
		 * first subnet that has ARP data.  We go through
		 * 1 ARP address in each subnet so that we find
		 * problems (and switch routing if necessary) in
		 * the minimum amount of time.  
		 * 
		 * One would expect the first subnet to have 
		 * ARP data, but we cannot assume that.  Find
		 * the first subnet that has data (we should not
		 * have started monitoring if we had no ARP data).
		 * 
		 * We also don't force the ARP entries to be added
		 * in priority order (although we really don't
		 * anticipate more than 1 per subnet), but we need
		 * find the first valid one for each subnet.
		 */

		LOG_OTHER( EIPM_LOG_ARP,
                           "EIPM Action ARP START %s%s - %s%s state %d\n",
                            data_ptr->lsn0_baseif,
                            ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
                            data_ptr->lsn1_baseif,
                            ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
                            intfSpecDataP->state );

		for( subn = 0;
		     subn < data_ptr->subnet_cnt;
		     subn++ )
		{
			if (data_ptr->subnet[subn].ip_cnt <= 0)
			{
				continue;
			}
			
			if (intfType == EIPM_EXTN_INTF &&
				data_ptr->subnet[subn].sub2intf_mapping[vlanId].is_intf_configured == 0)
			{
				/*
				 * skip the subnet  because this subnet's IP
				 * isn't plumbed in this external interface
				 */
				continue;
			}

			arp_ptr = &(data_ptr->subnet[subn].arpdata);

			if ( intfSpecDataP->state != NORMAL_STATE )
			{
				/*
				 * Clear the ARP counter.  This will cause an ARP to 
				 * immediately be sent.
				 */
				data_ptr->subnet[subn].arp_counter  = 0;
				data_ptr->subnet[subn].arp_degrade_counter = eipm_arp_sent_degraded + 1;
			}
			else
			{
				data_ptr->subnet[subn].arp_counter  = EIPM_ARP_IP_WAIT * EIPM_ARP_CNT_PER_SEC;
				data_ptr->subnet[subn].arp_degrade_counter = 0;
			}

			data_ptr->subnet[subn].arp_failure_count  = 0;

			/*
			 * Clear the GARP sent flag.  This will cause an GARP to 
			 * be immediately sent once a ARP response is received.
			 */
			data_ptr->subnet[subn].force_grat_arp = FALSE;

			/*
			 * Set the subnet status to online initially.
			 */
			data_ptr->subnet[subn].status = EIPM_ONLINE;

			/*
			 * Set the subnet priority LSN0 initially.
			 */
			EIPM_update_subnet_route_priority( intfSpecDataP, &data_ptr->subnet[subn], LSN0 );

			/*
			 * Initialize the ARP index to start at the highest priority ARP ip.
			 */
			arp_ptr->cur_index = 0;

			/* 
			 * Loop to find the first valid ARP IP.
			 */
			for( i = 0; i < MAX_ARP_ENTRIES; i++ )
			{
				if(( arp_ptr->arp_list[i].arp_ip.addrtype == IPM_IPV4 ) ||
				   ( arp_ptr->arp_list[i].arp_ip.addrtype == IPM_IPV6 ))
				{
					arp_ptr->cur_index = i;
					break;
				}
			}

		} /* end 'for loop on subnets' */
				
		/*
		 * Switch to ARP_SEND state and start sending
		 * ARPs.
		 */
		intfSpecDataP->recovery_state = ARP_SEND;
		
		/***********
		 * Intentional Fall Through
		 * 
		 * Set up data here, fall into next case to 
		 * start sending.
		 **********/
		
	case ARP_SEND:
		
		cleared_ipv4_lsn0_arp_rcv_que = FALSE;
		cleared_ipv4_lsn1_arp_rcv_que = FALSE;
		cleared_ipv6_lsn0_arp_rcv_que = FALSE;
		cleared_ipv6_lsn1_arp_rcv_que = FALSE;
		/*
		 * An ARP will be sent out for each subnet on the initial interface 
		 * failure.  Subsequent ARPs will be sent out as needed.
		 */
		for( subn = 0;
		     subn < data_ptr->subnet_cnt;
		     subn++ )
		{	
                    char ipstr_buf1[IPM_IPMAXSTRSIZE];
                    char ipstr_buf2[IPM_IPMAXSTRSIZE];

                        subnet_ptr = &(data_ptr->subnet[subn]);


			/*
			 * Verify that there are IP present prior to 
			 * attempting to send an ARP.
			 */
			if (subnet_ptr->ip_cnt == 0)
			{
				continue;
			}

			if (intfType == EIPM_EXTN_INTF &&
				data_ptr->subnet[subn].sub2intf_mapping[vlanId].is_intf_configured == 0)
			{
				continue;
			}
			/*
			 * Setup arp_ptr to start with the first subnet. 
			 */
			arp_ptr = &(data_ptr->subnet[subn].arpdata);
		
			/*
			 * The ARP counter is used to determine how
			 * long to wait before sending an ARP.
			 */
			if( data_ptr->subnet[subn].arp_counter > 0 )
			{
				data_ptr->subnet[subn].arp_counter--;

				/*
				 * Not time to send.
				 */
				continue;
			}
		
			/*
			 * Clear the ARP received flag.
			 */
			arp_ptr->arp_list[arp_ptr->cur_index].lsn0_arprcvd = FALSE;
			arp_ptr->arp_list[arp_ptr->cur_index].lsn1_arprcvd = FALSE;

			LOG_OTHER( EIPM_LOG_ARP,
				   "EIPM Action ARP SEND %s%s - %s%s state %d, sub_idx %d, subnet_base %s, arp_cur_idx %d, arp_dest %s\n",
				    data_ptr->lsn0_baseif,
				    ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
				    data_ptr->lsn1_baseif,
				    ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
				    intfSpecDataP->state,
				    subn,
				    IPM_ipaddr2p(&(subnet_ptr->subnet_base), ipstr_buf1, sizeof(ipstr_buf1)),
				    arp_ptr->cur_index,
				    IPM_ipaddr2p(&(arp_ptr->arp_list[arp_ptr->cur_index].arp_ip), ipstr_buf2, sizeof(ipstr_buf2)) );

			/*
			 * Check what type of ARP to send.
			 */
	 		if( arp_ptr->arp_list[arp_ptr->cur_index].arp_ip.addrtype == IPM_IPV4 )
			{
				if (    ( intfSpecDataP->state != NORMAL_STATE )
                                     || ( intfSpecDataP->preferred_side == LSN0 ) )
				{
					/*
					 * Create/send ARP packet for LSN0.
					 *
					 */
					if ( intfSpecDataP->lsn0_arpsock < 0 )
					{
						intfSpecDataP->lsn0_arpsock =
						        EIPM_create_arp_socket( LSN0, IPM_IPV4, intfSpecDataP->lsn0_iface_indx, ARPOP_REQUEST );
	
					}
					else if( cleared_ipv4_lsn0_arp_rcv_que == FALSE )
					{
						/* Clear ARP receive queue */

						memset( buffer, 0, ARP_RCV_SIZE );
						memset( &from, 0, sizeof( from ) );
			
						cleared_ipv4_lsn0_arp_rcv_que = TRUE;
						recv_empty = FALSE;
						count = 0;

						while( (recv_empty == FALSE) )
						{
							/*
							 * We cannot block if there is no data in
							 * the socket.
							 */
							flags = MSG_DONTWAIT;
							sockad_len = sizeof( from );
				
							msg_len = recvfrom( intfSpecDataP->lsn0_arpsock,
							                    buffer,
							                    ARP_RCV_SIZE,
							                    flags,
							                    (struct sockaddr *)&from,
							                    &sockad_len);
				
							LOG_DEBUG( 0,
							         "EIPM_action - msg_len=%d\n", msg_len );
						
							if ( msg_len < 0)
							{
								if( errno == EAGAIN )
								{
									/*
									 * Nothing received for LSN0.
									 */
									LOG_DEBUG( EIPM_LOG_ARP,
									         "EIPM_action - ARP send LSN0 - nothing in socket, count=%d\n",
									         count );
						
									/*
									 * Cannot clear ARP received
									 * flag here because we loop
									 * again to verify the socket
									 * is empty after a valid 
									 * reception.
									 */
									
									/*
									 * Break out of loop.
									 */
									recv_empty = TRUE;
								}
								else if( errno == EINTR )
								{
									continue;
								}
								else
								{
									LOG_ERROR( 0,
									       	 "Error: EIPM_action - recvfrom() failed, retval=%d, LSN0 V4 arp sock=%d errno=0x%x\n",
										 msg_len, intfSpecDataP->lsn0_arpsock, errno );
							
									recv_empty = TRUE;

									(void)close( intfSpecDataP->lsn0_arpsock );

									intfSpecDataP->lsn0_arpsock = EIPM_create_arp_socket( LSN0, IPM_IPV4, intfSpecDataP->lsn0_iface_indx, ARPOP_REQUEST );
								
								}
							}
							else if( msg_len == 0 )
							{
								/*
								 * Apparently no message.
								 */
								recv_empty = TRUE;
							}
							else
							{
								/*
								 * Message received
								 */
								LOG_DEBUG( EIPM_LOG_ARP,
								       	 "EIPM_action - LSN0, ar_op=%d, ntohs(ar_op)=%d, ARPOP_REPLY=%d\n",
									 ((struct arp_pkt *)buffer)->arp.ea_hdr.ar_op,
									 ntohs( ((struct arp_pkt *)buffer)->arp.ea_hdr.ar_op ),
									ARPOP_REPLY );
							}
				
						} /* while( (recv_empty == FALSE) */
					}
		
					EIPM_sendARP(intfSpecDataP->lsn0_arpsock,
						     data_ptr->lsn0_hwaddr,
						     EIPM_getSrcIPAddrForARP( intfSpecDataP, &(data_ptr->subnet[subn]) ),
						     &(arp_ptr->arp_list[arp_ptr->cur_index].arp_ip),
						     intfSpecDataP->lsn0_iface_indx,
						     ARPOP_REQUEST);
				}
				else if ( intfSpecDataP->lsn0_arpsock >= 0 )
                                {
                                        (void)close( intfSpecDataP->lsn0_arpsock );
                                	intfSpecDataP->lsn0_arpsock = -1;
                                }


				if (    ( intfSpecDataP->state != NORMAL_STATE )
                                     || ( intfSpecDataP->preferred_side == LSN1 ) )
				{
					/*
					 * Create/send ARP packet for LSN1.
					 *
					 */
				
					if ( intfSpecDataP->lsn1_arpsock < 0 )
					{
						intfSpecDataP->lsn1_arpsock =
						        EIPM_create_arp_socket( LSN1, IPM_IPV4, intfSpecDataP->lsn1_iface_indx, ARPOP_REQUEST );
	
					}
					else if( cleared_ipv4_lsn1_arp_rcv_que == FALSE )
					{
						/* Clear ARP receive queue */

						memset( buffer, 0, ARP_RCV_SIZE );
						memset( &from, 0, sizeof( from ) );
			
						cleared_ipv4_lsn1_arp_rcv_que = TRUE;
						recv_empty = FALSE;
						count = 0;

						while( (recv_empty == FALSE) )
						{
							/*
							 * We cannot block if there is no data in
							 * the socket.
							 */
							flags = MSG_DONTWAIT;
							sockad_len = sizeof( from );
				
							msg_len = recvfrom( intfSpecDataP->lsn1_arpsock,
							                    buffer,
							                    ARP_RCV_SIZE,
				       			             flags,
							                    (struct sockaddr *)&from,
							                    &sockad_len);
				
							LOG_DEBUG( 0,
							         "EIPM_action - msg_len=%d\n", msg_len );
						
							if ( msg_len < 0)
							{
								if( errno == EAGAIN )
								{
									/*
									 * Nothing received for LSN1.
									 */
									LOG_DEBUG( EIPM_LOG_ARP,
									         "EIPM_action - ARP send LSN1 - nothing in socket, count=%d\n",
									         count );
						
									/*
									 * Cannot clear ARP received
									 * flag here because we loop
									 * again to verify the socket
									 * is empty after a valid 
									 * reception.
									 */
						
									/*
									 * Break out of loop.
									 */
									recv_empty = TRUE;
								}
								else if( errno == EINTR )
								{
									continue;
								}
								else
								{
									LOG_ERROR( 0,
									       	 "Error: EIPM_action - recvfrom() failed, retval=%d, LSN1 V4 arp sock=%d errno=0x%x\n",
										 msg_len, intfSpecDataP->lsn1_arpsock, errno );
							
									recv_empty = TRUE;

									(void)close( intfSpecDataP->lsn1_arpsock );

									intfSpecDataP->lsn1_arpsock = EIPM_create_arp_socket( LSN1, IPM_IPV4, intfSpecDataP->lsn1_iface_indx, ARPOP_REQUEST );
								}
							}
							else if( msg_len == 0 )
							{
								/*
								 * Apparently no message.
								 */
								recv_empty = TRUE;
							}
							else
							{
								/*
								 * Message received
								 */
								LOG_DEBUG( 0,
								       	 "EIPM_action - LSN1, ar_op=%d, ntohs(ar_op)=%d, ARPOP_REPLY=%d\n",
									 ((struct arp_pkt *)buffer)->arp.ea_hdr.ar_op,
									 ntohs( ((struct arp_pkt *)buffer)->arp.ea_hdr.ar_op ),
									ARPOP_REPLY );
				
							}
				
						} /* while( (recv_empty == FALSE) */
					}
			
					EIPM_sendARP(intfSpecDataP->lsn1_arpsock,
						     data_ptr->lsn1_hwaddr,
						     EIPM_getSrcIPAddrForARP( intfSpecDataP, &(data_ptr->subnet[subn]) ),
						     &(arp_ptr->arp_list[arp_ptr->cur_index].arp_ip),
						     intfSpecDataP->lsn1_iface_indx,
						     ARPOP_REQUEST);
				}
				else if( intfSpecDataP->lsn1_arpsock >= 0 )
                                {
                                        (void)close( intfSpecDataP->lsn1_arpsock );
                                	intfSpecDataP->lsn1_arpsock = -1;
                                }
			}
	 		else if( arp_ptr->arp_list[arp_ptr->cur_index].arp_ip.addrtype == IPM_IPV6 )
			{
				if (    ( intfSpecDataP->state != NORMAL_STATE )
                                     || ( intfSpecDataP->preferred_side == LSN0 ) )
				{
					/*
					 * Create/send IPv6 "ARP" packet this is neighbor 
					 * solicitation packet.
					 *
					 */
	
					if ( intfSpecDataP->lsn0_v6arpsock < 0 )
					{
						intfSpecDataP->lsn0_v6arpsock =
						        EIPM_create_arp_socket( LSN0, IPM_IPV6, intfSpecDataP->lsn0_iface_indx, ND_NEIGHBOR_SOLICIT );
	
					}
					else if( cleared_ipv6_lsn0_arp_rcv_que == FALSE )
					{
						/* Clear ARP receive queue */

						struct msghdr		recv_msg;
						struct iovec		iov;
						char			cmsg[256];
						int			nr;
						struct cmsghdr		*cmsgptr;
						struct in6_pktinfo	*pktinfoptr;	
						struct sockaddr_in6	addr;
			
						cmsgptr = (struct cmsghdr *)&cmsg;

						/* initialize receive buffer */
						memset((void *) &iov, 0, sizeof(iov));
						iov.iov_base = &buffer;
						iov.iov_len = sizeof(buffer);

						recv_msg.msg_iov = &iov;
						recv_msg.msg_iovlen = 1;
						recv_msg.msg_flags = 0;

						recv_msg.msg_control = (char *)cmsgptr;
						recv_msg.msg_controllen = sizeof(cmsg);
						recv_msg.msg_name = (void*)&addr;
						recv_msg.msg_namelen = sizeof(addr);

						/*
						 * Check to see if we got a reply.
						 * We cannot block if there is no data in
						 * the socket.  On the other hand we could see
						 * multiple ARP replies (e.g. the kernel
						 * decided to ARP something else in the same
						 * subnet) and we want to throw them away.
						 */
						memset( buffer, 0, ARP_RCV_SIZE );
						memset( cmsg, 0, sizeof(cmsg) );
						memset( &from, 0, sizeof( from ) );
			
						cleared_ipv6_lsn0_arp_rcv_que = TRUE;
						recv_empty = FALSE;
						count = 0;
						while( recv_empty == FALSE )
						{
							/*
							 * We cannot block if there is no data in
							 * the socket.
							 */
							flags = MSG_DONTWAIT;
				
							msg_len = recvmsg( intfSpecDataP->lsn0_v6arpsock, 
										&recv_msg, flags );
				
							LOG_DEBUG( 0,
							         "EIPM_action - msg_len=%d\n", msg_len );
						
							if ( msg_len < 0)
							{
								if( errno == EAGAIN )
								{
									/*
									 * Nothing received for LSN0.
									 */
									LOG_DEBUG( EIPM_LOG_ARP,
									         "EIPM_action - ARP send LSN0 - nothing in socket, count=%d\n",
									         count );
						
									/*
									 * Cannot clear ARP received
									 * flag here because we loop
									 * again to verify the socket
									 * is empty after a valid 
									 * reception.
									 */
									
									/*
									 * Break out of loop.
									 */
									recv_empty = TRUE;
								}
								else if( errno == EINTR )
								{
									continue;
								}
								else
								{
									LOG_ERROR( 0,
									       	 "Error: EIPM_action - recvmsg() failed, retval=%d, LSN0 V6 arp sock=%d errno=0x%x\n",
										 msg_len, intfSpecDataP->lsn0_v6arpsock, errno );
							
									recv_empty = TRUE;

									(void)close( intfSpecDataP->lsn0_v6arpsock );
									intfSpecDataP->lsn0_v6arpsock =
								        EIPM_create_arp_socket( LSN0, IPM_IPV6, intfSpecDataP->lsn0_iface_indx, ND_NEIGHBOR_SOLICIT );
								
								}
							}
							else if( msg_len == 0 )
							{
								/*
								 * Apparently no message.
								 */
								recv_empty = TRUE;
							}
							else
							{
								LOG_DEBUG( EIPM_LOG_ARP,
								       	 "EIPM_action - Received ARP reply on LSN0\n cmsg_type=%d,\n iface=%s\n",
									 cmsgptr->cmsg_type, 
									 data_ptr->lsn0_baseif );
							}
							
						} /* while( recv_empty == FALSE ) */
					}
	
					int ret_lsn0_v6 = 
					EIPM_sendARP(intfSpecDataP->lsn0_v6arpsock,
       	                                         data_ptr->lsn0_hwaddr,
						 EIPM_getSrcIPAddrForARP( intfSpecDataP, &(data_ptr->subnet[subn]) ),
       	                                         &(arp_ptr->arp_list[arp_ptr->cur_index].arp_ip),
       	                                         intfSpecDataP->lsn0_iface_indx,
       	                                         ND_NEIGHBOR_SOLICIT);
					if ( (IPM_RETVAL) ret_lsn0_v6 == IPM_SENDING_NS_FAILURE )
					{
						LOG_ERROR( 0, "Error: EIPM_action: Failed to send NS on LSN0 and current socket (%d) will be closed\n", intfSpecDataP->lsn0_v6arpsock);
						(void)close( intfSpecDataP->lsn0_v6arpsock );
						intfSpecDataP->lsn0_v6arpsock = -1;
					}
				}					
				else if ( intfSpecDataP->lsn0_v6arpsock >= 0 )
                                {
                                        (void)close( intfSpecDataP->lsn0_v6arpsock );
                                	intfSpecDataP->lsn0_v6arpsock = -1;
                                }

				if (    ( intfSpecDataP->state != NORMAL_STATE )
                                     || ( intfSpecDataP->preferred_side == LSN1 ) )
				{
					/*
					 * Create/send ARP packet for LSN1.
					 *
					 */
	

					if ( intfSpecDataP->lsn1_v6arpsock < 0 )
					{
						intfSpecDataP->lsn1_v6arpsock =
						        EIPM_create_arp_socket( LSN1, IPM_IPV6, intfSpecDataP->lsn1_iface_indx, ND_NEIGHBOR_SOLICIT );

					}
					else if( cleared_ipv6_lsn1_arp_rcv_que == FALSE )
					{
						/* Clear ARP receive queue */

						struct msghdr		recv_msg;
						struct iovec		iov;
						char			cmsg[256];
						int			nr;
						struct cmsghdr		*cmsgptr;
						struct in6_pktinfo	*pktinfoptr;	
						struct sockaddr_in6	addr;
			
						cmsgptr = (struct cmsghdr *)&cmsg;

						/* initialize receive buffer */
						memset((void *) &iov, 0, sizeof(iov));
						iov.iov_base = &buffer;
						iov.iov_len = sizeof(buffer);

						recv_msg.msg_iov = &iov;
						recv_msg.msg_iovlen = 1;
						recv_msg.msg_flags = 0;

						recv_msg.msg_control = (char *)cmsgptr;
						recv_msg.msg_controllen = sizeof(cmsg);
						recv_msg.msg_name = (void*)&addr;
						recv_msg.msg_namelen = sizeof(addr);

						/*
						 * Check to see if we got a reply.
						 * We cannot block if there is no data in
						 * the socket.  On the other hand we could see
						 * multiple ARP replies (e.g. the kernel
						 * decided to ARP something else in the same
						 * subnet) and we want to throw them away.
						 */
						memset( buffer, 0, ARP_RCV_SIZE );
						memset( cmsg, 0, sizeof(cmsg) );
						memset( &from, 0, sizeof( from ) );
			
						cleared_ipv6_lsn1_arp_rcv_que = TRUE;
						recv_empty = FALSE;
						count = 0;
						while( recv_empty == FALSE )
						{
							/*
							 * We cannot block if there is no data in
							 * the socket.
							 */
							flags = MSG_DONTWAIT;
				
							msg_len = recvmsg( intfSpecDataP->lsn1_v6arpsock, 
										&recv_msg, flags );
				
							LOG_DEBUG( 0,
							         "EIPM_action - msg_len=%d\n", msg_len );
						
							if ( msg_len < 0)
							{
								if( errno == EAGAIN )
								{
									/*
									 * Nothing received for LSN1.
									 */
									LOG_DEBUG( EIPM_LOG_ARP,
									         "EIPM_action - ARP send LSN1 - nothing in socket, count=%d\n",
									         count );
						
									/*
									 * Cannot clear ARP received
									 * flag here because we loop
									 * again to verify the socket
									 * is empty after a valid 
									 * reception.
									 */
						
									/*
									 * Break out of loop.
									 */
									recv_empty = TRUE;
								}
								else if( errno == EINTR )
								{
									continue;
								}
								else
								{
									LOG_ERROR( 0,
									       	 "Error: EIPM_action - recvmsg() failed, retval=%d, LSN1 V6 arp sock=%d errno=0x%x\n",
										 msg_len, intfSpecDataP->lsn1_v6arpsock, errno );
							
									recv_empty = TRUE;

									(void)close( intfSpecDataP->lsn1_v6arpsock );
									intfSpecDataP->lsn1_v6arpsock =
								        EIPM_create_arp_socket( LSN1, IPM_IPV6, intfSpecDataP->lsn1_iface_indx, ND_NEIGHBOR_SOLICIT );
								
								}
							}
							else if( msg_len == 0 )
							{
								/*
								 * Apparently no message.
								 */
								recv_empty = TRUE;
							}
							else
							{
								LOG_DEBUG( EIPM_LOG_ARP,
								       	 "EIPM_action - Received ARP reply on LSN1\n cmsg_type=%d,\n iface=%s\n",
									 cmsgptr->cmsg_type, 
									 data_ptr->lsn1_baseif );
							}
				
						} /* while( recv_empty == FALSE ) */
					}

					int ret_lsn1_v6 =
					EIPM_sendARP(intfSpecDataP->lsn1_v6arpsock,
						     data_ptr->lsn1_hwaddr,
						     EIPM_getSrcIPAddrForARP( intfSpecDataP, &(data_ptr->subnet[subn]) ),
						     &(arp_ptr->arp_list[arp_ptr->cur_index].arp_ip),
						     intfSpecDataP->lsn1_iface_indx,
						     ND_NEIGHBOR_SOLICIT);
					if ( (IPM_RETVAL) ret_lsn1_v6 == IPM_SENDING_NS_FAILURE )
					{
						LOG_ERROR( 0, "Error: EIPM_action: Failed to send NS on LSN1 and current socket (%d) will be closed\n", intfSpecDataP->lsn1_v6arpsock);
						(void)close( intfSpecDataP->lsn1_v6arpsock );
						intfSpecDataP->lsn1_v6arpsock = -1;
					}
				}
				else if ( intfSpecDataP->lsn1_v6arpsock >= 0 )
                                {
                                        (void)close( intfSpecDataP->lsn1_v6arpsock );
                                	intfSpecDataP->lsn1_v6arpsock = -1;
                                }
			}
	 		else 
			{
				/*
				 * No valid arp entry set a timer.
				 */
				data_ptr->subnet[subn].arp_counter = EIPM_ARP_IP_WAIT * EIPM_ARP_CNT_PER_SEC;
			}

			/*
			 * Set state to ARP_RECEIVE since we are now waiting
			 * for a response.
			 */
			intfSpecDataP->recovery_state = ARP_RECEIVE;
		}
		
		break;
		
	case ARP_RECEIVE:
		
		for( subn = 0;
		     subn < data_ptr->subnet_cnt;
		     subn++ )
		{	
			if (intfType == EIPM_EXTN_INTF &&
				data_ptr->subnet[subn].sub2intf_mapping[vlanId].is_intf_configured == 0)
			{
				continue;
			}

			/*
			 * The ARP counter is used to determine how
			 * long to wait before sending an ARP.  Don't 
			 * decrement to 0 otherwise an ARP may no longer
			 * be sent.
			 */
			if( data_ptr->subnet[subn].arp_counter > 1 )
			{
				data_ptr->subnet[subn].arp_counter--;
			}
		}

		/* 
		 * Check for ARP replies on all open sockets.
		 */
		if ( intfSpecDataP->lsn0_arpsock >= 0 )
		{
			/*
			 * Check to see if we got a reply.
			 * We cannot block if there is no data in
			 * the socket.  On the other hand we could see
			 * multiple ARP replies (e.g. the kernel
			 * decided to ARP something else in the same
			 * subnet) and we want to throw them away.
			 */
			memset( buffer, 0, ARP_RCV_SIZE );
			memset( &from, 0, sizeof( from ) );
			
			recv_empty = FALSE;
			count = 0;
			while( (recv_empty == FALSE) )
			{
				/*
				 * We cannot block if there is no data in
				 * the socket.
				 */
				flags = MSG_DONTWAIT;
				sockad_len = sizeof( from );
				
				msg_len = recvfrom( intfSpecDataP->lsn0_arpsock,
				                    buffer,
				                    ARP_RCV_SIZE,
				                    flags,
				                    (struct sockaddr *)&from,
				                    &sockad_len);
				
				LOG_DEBUG( 0,
				         "EIPM_action - msg_len=%d\n", msg_len );
						
				if ( msg_len < 0)
				{
					if( errno == EAGAIN )
					{
						/*
						 * Nothing received for LSN0.
						 */
						/* DBG */
						LOG_DEBUG( EIPM_LOG_ARP,
						         "EIPM_action - ARP receive LSN0 - nothing in socket, count=%d\n",
						         count );
						
						/*
						 * Cannot clear ARP received
						 * flag here because we loop
						 * again to verify the socket
						 * is empty after a valid 
						 * reception.
						 */
						
						/*
						 * Break out of loop.
						 */
						recv_empty = TRUE;
					}
					else if( errno == EINTR )
					{
						continue;
					}
					else
					{
						LOG_ERROR( 0,
						       	 "Error: EIPM_action - recvfrom() failed, retval=%d, LSN0 V4 arp sock=%d errno=0x%x\n",
							 msg_len, intfSpecDataP->lsn0_arpsock, errno );
							
						recv_empty = TRUE;
						(void)close( intfSpecDataP->lsn0_arpsock );
						intfSpecDataP->lsn0_arpsock = -1;
					}
				}
				else if( msg_len == 0 )
				{
					/*
					 * Apparently no message.
					 */
					recv_empty = TRUE;
				}
				else
				{
					/*
					 * Message received
					 */
					LOG_DEBUG( EIPM_LOG_ARP,
					       	 "EIPM_action - LSN0, ar_op=%d, ntohs(ar_op)=%d, ARPOP_REPLY=%d\n",
						 ((struct arp_pkt *)buffer)->arp.ea_hdr.ar_op,
						 ntohs( ((struct arp_pkt *)buffer)->arp.ea_hdr.ar_op ),
						ARPOP_REPLY );
				
					/*
					 * Verify that this is an ARP reply,
					 * and also make sure the response is
					 * from the IP address that we ARPed.
					 * Since the socket is bound to the
					 * protocol we could receive other ARP
					 * responses.  As long as the response
					 * we get is from the address we ARPed we
					 * don't care who made the ARP request.
					 * Since the ARP address is stored in
					 * an array it is not in network order.
					 */
					msg_ptr = (struct arp_pkt *)buffer;
				
					LOG_OTHER( EIPM_LOG_ARP,
					       	 "EIPM_action - Received ARP reply on LSN0\nar_op=%d, ntohs(ar_op)=%d,\n msgsrc_ip=%d.%d.%d.%d\nmunged src_ip=0x%x, iface=%s%s\n",
						 msg_ptr->arp.ea_hdr.ar_op,
						 ntohs(msg_ptr->arp.ea_hdr.ar_op),
						 msg_ptr->arp.arp_spa[0],
						 msg_ptr->arp.arp_spa[1],
						 msg_ptr->arp.arp_spa[2],
						 msg_ptr->arp.arp_spa[3],
						 *(uint32_t *)&msg_ptr->arp.arp_spa,
						 data_ptr->lsn0_baseif,
						 ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

					if( (ntohs(msg_ptr->arp.ea_hdr.ar_op) ==
					                          ARPOP_REPLY) )
					{
						/*
						 * Check if the IP in the received ARP reply matches 
						 * the current ARP IP on any subnet.
						 */
						for( subn = 0;
						     subn < data_ptr->subnet_cnt;
						     subn++ )
						{
							if (data_ptr->subnet[subn].ip_cnt <= 0)
							{
								continue;
							}
							if (intfType == EIPM_EXTN_INTF &&
								data_ptr->subnet[subn].sub2intf_mapping[vlanId].is_intf_configured == 0)
							{
								continue;
							}
							arp_ptr = &(data_ptr->subnet[subn].arpdata);

							if( arp_ptr->arp_list[arp_ptr->cur_index].arp_ip.addrtype == IPM_IPV4 )
							{

								IPM_ipaddr2in( &(arp_ptr->arp_list[arp_ptr->cur_index].arp_ip), &ipm_ipv4_buf );
								if( (*(uint32_t *)&msg_ptr->arp.arp_spa ==
								        ipm_ipv4_buf.s_addr) )
								{
									LOG_DEBUG( EIPM_LOG_ARP,
										   "EIPM Action ARP RECV IPv4 reply on LSN0, iface %s%s\n",
										   data_ptr->lsn0_baseif,
                                                                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

									/*
									 * Set ARP received flag.
									 */
									arp_ptr->arp_list[arp_ptr->cur_index].lsn0_arprcvd
									    = TRUE;
								}
							}
						}
					}
				}
				
			} /* end check on return from recvfrom() */
			
			if( count >= 10 )
			{
				LOG_DEBUG( EIPM_LOG_ARP,
				       	   "EIPM_action - Received more than 10 ARP replies on LSN0, iface=%s%s\n",
					   data_ptr->lsn1_baseif,
                                           ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
				
				/*
				 * Not a fatal error - just continue.
				 */
			}
		
		}
		if ( intfSpecDataP->lsn0_v6arpsock >= 0 )
		{
			struct msghdr		recv_msg;
			struct iovec		iov;
			char			cmsg[256];
			int			nr;
			struct cmsghdr		*cmsgptr;
			struct in6_pktinfo	*pktinfoptr;	
			struct sockaddr_in6	addr;
			
			cmsgptr = (struct cmsghdr *)&cmsg;

			/* initialize receive buffer */
			memset((void *) &iov, 0, sizeof(iov));
			iov.iov_base = &buffer;
			iov.iov_len = sizeof(buffer);

			recv_msg.msg_iov = &iov;
			recv_msg.msg_iovlen = 1;
			recv_msg.msg_flags = 0;

			recv_msg.msg_control = (char *)cmsgptr;
			recv_msg.msg_controllen = sizeof(cmsg);
			recv_msg.msg_name = (void*)&addr;
			recv_msg.msg_namelen = sizeof(addr);

			/*
			 * Check to see if we got a reply.
			 * We cannot block if there is no data in
			 * the socket.  On the other hand we could see
			 * multiple ARP replies (e.g. the kernel
			 * decided to ARP something else in the same
			 * subnet) and we want to throw them away.
			 */
			memset( buffer, 0, ARP_RCV_SIZE );
			memset( cmsg, 0, sizeof(cmsg) );
			memset( &from, 0, sizeof( from ) );
			
			recv_empty = FALSE;
			count = 0;
			while( recv_empty == FALSE )
			{
				/*
				 * We cannot block if there is no data in
				 * the socket.
				 */
				flags = MSG_DONTWAIT;
				
				msg_len = recvmsg( intfSpecDataP->lsn0_v6arpsock, 
							&recv_msg, flags );
				
				LOG_DEBUG( 0,
				         "EIPM_action - msg_len=%d\n", msg_len );
						
				if ( msg_len < 0)
				{
					if( errno == EAGAIN )
					{
						/*
						 * Nothing received for LSN0.
						 */
						/* DBG */
						LOG_DEBUG( EIPM_LOG_ARP,
						         "EIPM_action - ARP receive LSN0 - nothing in socket, count=%d\n",
						         count );
						
						/*
						 * Cannot clear ARP received
						 * flag here because we loop
						 * again to verify the socket
						 * is empty after a valid 
						 * reception.
						 */
						
						/*
						 * Break out of loop.
						 */
						recv_empty = TRUE;
					}
					else if( errno == EINTR )
					{
						continue;
					}
					else
					{
						LOG_ERROR( 0,
						       	 "Error: EIPM_action - recvmsg() failed, retval=%d, LSN0 V6 arp sock=%d errno=0x%x\n",
							 msg_len, intfSpecDataP->lsn0_v6arpsock, errno );
							
						recv_empty = TRUE;
						(void)close( intfSpecDataP->lsn0_v6arpsock );
						intfSpecDataP->lsn0_v6arpsock = -1;
					}
				}
				else if( msg_len == 0 )
				{
					/*
					 * Apparently no message.
					 */
					recv_empty = TRUE;
				}
				else
				{
					LOG_DEBUG( EIPM_LOG_ARP,
					       	   "EIPM_action - Received ARP reply on LSN0\n cmsg_type=%d,\n iface=%s%s\n",
						   cmsgptr->cmsg_type, 
						   data_ptr->lsn0_baseif,
                                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

					if( cmsgptr->cmsg_type == IPV6_PKTINFO )
					{
						pktinfoptr = (struct in6_pktinfo *) CMSG_DATA(cmsgptr);

						LOG_OTHER( EIPM_LOG_ARP,
							   "EIPM_action - Received ARP reply on LSN0\n intf=%d, ip=%s\niface_index=%d\n",
							   pktinfoptr->ipi6_ifindex,
							   inet_ntop( AF_INET6, &pktinfoptr->ipi6_addr, ipm_ipstr_buf, 
							              sizeof( ipm_ipstr_buf ) ),
							   intfSpecDataP->lsn0_iface_indx );

						if ( pktinfoptr->ipi6_ifindex == intfSpecDataP->lsn0_iface_indx )
						
						{

							struct nd_neighbor_advert *na;

							na = (struct nd_neighbor_advert *)&buffer;

							LOG_DEBUG( EIPM_LOG_ARP,
							       	 "EIPM_action - Received ARP reply on LSN0\n nd_na_type=%d,\ntarget_ip=%s iface=%s%s\n",
								 na->nd_na_type, 
								 inet_ntop(AF_INET6, &na->nd_na_target, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
								 data_ptr->lsn0_baseif,
                                                                 ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
		
							if( na->nd_na_type == ND_NEIGHBOR_ADVERT ) 
							{

								/*
								 * Check if the IP in the received ARP reply matches 
								 * the current ARP IP on any subnet.
								 */
								for( subn = 0;
								     subn < data_ptr->subnet_cnt;
								     subn++ )
								{
									if (data_ptr->subnet[subn].ip_cnt <= 0)
									{
										continue;
									}
									if (intfType == EIPM_EXTN_INTF &&
										data_ptr->subnet[subn].sub2intf_mapping[vlanId].is_intf_configured == 0)
									{
										continue;
									}
									arp_ptr = &(data_ptr->subnet[subn].arpdata);

									if( arp_ptr->arp_list[arp_ptr->cur_index].arp_ip.addrtype == IPM_IPV6 )
									{
										IPM_ipaddr2in( &(arp_ptr->arp_list[arp_ptr->cur_index].arp_ip), &ipm_ipv6_buf );
										if( (memcmp(&na->nd_na_target, &ipm_ipv6_buf, sizeof(struct in6_addr) ) == 0) )
										{
											LOG_DEBUG( EIPM_LOG_ARP,
												   "EIPM Action ARP RECV IPv6 reply on LSN0, iface %s%s\n",
												   data_ptr->lsn0_baseif,
                                                                                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );



											/*
											 * Set ARP received flag.
											 */
											arp_ptr->arp_list[arp_ptr->cur_index].lsn0_arprcvd
											    = TRUE;
										}
									}
								}					
							}
						}
					}
				}
				
			} /* end check on return from recvfrom() */
		
			if( count >= 10 )
			{
				LOG_DEBUG( EIPM_LOG_ARP,
				       	   "EIPM_action - Received more than 10 ARP replies on LSN0, iface=%s%s\n",
					   data_ptr->lsn0_baseif,
                                           ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
				
				/*
				 * Not a fatal error - just continue.
				 */
			}
		}

		if ( intfSpecDataP->lsn1_arpsock >= 0 )
		{
			/*
			 * Check to see if we got a reply.
			 * We cannot block if there is no data in
			 * the socket.  On the other hand we could see
			 * multiple ARP replies (e.g. the kernel
			 * decided to ARP something else in the same
			 * subnet) and we want to throw them away.
			 */
			memset( buffer, 0, ARP_RCV_SIZE );
			memset( &from, 0, sizeof( from ) );
			
			recv_empty = FALSE;
			count = 0;
			while( (recv_empty == FALSE) )
			{
				/*
				 * We cannot block if there is no data in
				 * the socket.
				 */
				flags = MSG_DONTWAIT;
				sockad_len = sizeof( from );
				
				msg_len = recvfrom( intfSpecDataP->lsn1_arpsock,
				                    buffer,
				                    ARP_RCV_SIZE,
				                    flags,
				                    (struct sockaddr *)&from,
				                    &sockad_len);
				
				LOG_DEBUG( 0,
				         "EIPM_action - msg_len=%d\n", msg_len );
						
				if ( msg_len < 0)
				{
					if( errno == EAGAIN )
					{
						/*
						 * Nothing received for LSN1.
						 */
						/* DBG */
						LOG_DEBUG( EIPM_LOG_ARP,
						         "EIPM_action - ARP receive LSN1 - nothing in socket, count=%d\n",
						         count );
						
						/*
						 * Cannot clear ARP received
						 * flag here because we loop
						 * again to verify the socket
						 * is empty after a valid 
						 * reception.
						 */
						
						/*
						 * Break out of loop.
						 */
						recv_empty = TRUE;
					}
					else if( errno == EINTR )
					{
						continue;
					}
					else
					{
						LOG_ERROR( 0,
						       	 "Error: EIPM_action - recvfrom() failed, retval=%d, LSN1 V4 arp sock=%d errno=0x%x\n",
							 msg_len, intfSpecDataP->lsn1_arpsock, errno );
							
						recv_empty = TRUE;
						(void)close( intfSpecDataP->lsn1_arpsock );
						intfSpecDataP->lsn1_arpsock = -1;
					}
				}
				else if( msg_len == 0 )
				{
					/*
					 * Apparently no message.
					 */
					recv_empty = TRUE;
				}
				else
				{
					/*
					 * Message received
					 */
					LOG_DEBUG( 0,
					       	 "EIPM_action - LSN1, ar_op=%d, ntohs(ar_op)=%d, ARPOP_REPLY=%d\n",
						 ((struct arp_pkt *)buffer)->arp.ea_hdr.ar_op,
						 ntohs( ((struct arp_pkt *)buffer)->arp.ea_hdr.ar_op ),
						ARPOP_REPLY );
				
					/*
					 * Verify that this is an ARP reply,
					 * and also make sure the response is
					 * from the IP address that we ARPed.
					 * Since the socket is bound to the
					 * protocol we could receive other ARP
					 * responses.  As long as the response
					 * we get is from the address we ARPed we
					 * don't care who made the ARP request.
					 * Since the ARP address is stored in
					 * an array it is not in network order.
					 */
					msg_ptr = (struct arp_pkt *)buffer;
				
					LOG_OTHER( EIPM_LOG_ARP,
					 "EIPM_action - Received ARP reply on LSN1\nar_op=%d, ntohs(ar_op)=%d,\nmsgsrc_ip=%d.%d.%d.%d\nmunged src_ip=0x%x, iface=%s%s\n",
					 msg_ptr->arp.ea_hdr.ar_op,
					 ntohs(msg_ptr->arp.ea_hdr.ar_op),
					 msg_ptr->arp.arp_spa[0],
					 msg_ptr->arp.arp_spa[1],
					 msg_ptr->arp.arp_spa[2],
					 msg_ptr->arp.arp_spa[3],
					 *(uint32_t *)&msg_ptr->arp.arp_spa,
					 data_ptr->lsn1_baseif,
                                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

					if( (ntohs(msg_ptr->arp.ea_hdr.ar_op) ==
					                          ARPOP_REPLY) )
					{
						/*
						 * Check if the IP in the received ARP reply matches 
						 * the current ARP IP on any subnet.
						 */
						for( subn = 0;
						     subn < data_ptr->subnet_cnt;
						     subn++ )
						{
							if (data_ptr->subnet[subn].ip_cnt <= 0)
							{
								continue;
							}
							if (intfType == EIPM_EXTN_INTF &&
								data_ptr->subnet[subn].sub2intf_mapping[vlanId].is_intf_configured == 0)
							{
								continue;
							}
							arp_ptr = &(data_ptr->subnet[subn].arpdata);

							if( arp_ptr->arp_list[arp_ptr->cur_index].arp_ip.addrtype == IPM_IPV4 )
							{
								IPM_ipaddr2in( &(arp_ptr->arp_list[arp_ptr->cur_index].arp_ip), &ipm_ipv4_buf );
								if( (*(uint32_t *)&msg_ptr->arp.arp_spa ==
								        ipm_ipv4_buf.s_addr) )
								{
									LOG_DEBUG( EIPM_LOG_ARP,
										   "EIPM Action ARP RECV IPv4 reply on LSN1, iface %s%s\n",
										   data_ptr->lsn1_baseif,
                                                                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
	
									/*
									 * Set ARP received flag.
									 */
									arp_ptr->arp_list[arp_ptr->cur_index].lsn1_arprcvd
									    = TRUE;
								}
							}
						}
					}
				}
				
			} /* end check on return from recvfrom() */
			
			if( count >= 10 )
			{
				LOG_DEBUG( EIPM_LOG_ARP,
				       	   "EIPM_action - Received more than 10 ARP replies on LSN1, iface=%s%s\n",
					   data_ptr->lsn1_baseif,
                                           ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
				
				/*
				 * Not a fatal error - just continue.
				 */
			}
		
		}

		if ( intfSpecDataP->lsn1_v6arpsock >= 0 )
		{
			struct msghdr		recv_msg;
			struct iovec		iov;
			char			cmsg[256];
			int			nr;
			struct cmsghdr		*cmsgptr;
			struct in6_pktinfo	*pktinfoptr;	
			struct sockaddr_in6	addr;
			
			cmsgptr = (struct cmsghdr *)&cmsg;

			/* initialize receive buffer */
			memset((void *) &iov, 0, sizeof(iov));
			iov.iov_base = &buffer;
			iov.iov_len = sizeof(buffer);

			recv_msg.msg_iov = &iov;
			recv_msg.msg_iovlen = 1;
			recv_msg.msg_flags = 0;

			recv_msg.msg_control = (char *)cmsgptr;
			recv_msg.msg_controllen = sizeof(cmsg);
			recv_msg.msg_name = (void*)&addr;
			recv_msg.msg_namelen = sizeof(addr);

			/*
			 * Check to see if we got a reply.
			 * We cannot block if there is no data in
			 * the socket.  On the other hand we could see
			 * multiple ARP replies (e.g. the kernel
			 * decided to ARP something else in the same
			 * subnet) and we want to throw them away.
			 */
			memset( buffer, 0, ARP_RCV_SIZE );
			memset( cmsg, 0, sizeof(cmsg) );
			memset( &from, 0, sizeof( from ) );
			
			recv_empty = FALSE;
			count = 0;
			while( recv_empty == FALSE )
			{
				/*
				 * We cannot block if there is no data in
				 * the socket.
				 */
				flags = MSG_DONTWAIT;
				
				msg_len = recvmsg( intfSpecDataP->lsn1_v6arpsock, 
							&recv_msg, flags );
				
				LOG_DEBUG( 0,
				         "EIPM_action - msg_len=%d\n", msg_len );
						
				if ( msg_len < 0)
				{
					if( errno == EAGAIN )
					{
						/*
						 * Nothing received for LSN1.
						 */
						/* DBG */
						LOG_DEBUG( EIPM_LOG_ARP,
						         "EIPM_action - ARP receive LSN1 - nothing in socket, count=%d\n",
						         count );
						
						/*
						 * Cannot clear ARP received
						 * flag here because we loop
						 * again to verify the socket
						 * is empty after a valid 
						 * reception.
						 */
						
						/*
						 * Break out of loop.
						 */
						recv_empty = TRUE;
					}
					else if( errno == EINTR )
					{
						continue;
					}
					else
					{
						LOG_ERROR( 0,
						       	 "Error: EIPM_action - recvmsg() failed, retval=%d, LSN1 V6 arp sock=%d errno=0x%x\n",
							 msg_len, intfSpecDataP->lsn1_v6arpsock, errno );
							
						recv_empty = TRUE;
						(void)close( intfSpecDataP->lsn1_v6arpsock );
						intfSpecDataP->lsn1_v6arpsock = -1;
					}
				}
				else if( msg_len == 0 )
				{
					/*
					 * Apparently no message.
					 */
					recv_empty = TRUE;
				}
				else
				{
					LOG_DEBUG( EIPM_LOG_ARP,
					       	   "EIPM_action - Received ARP reply on LSN1\n cmsg_type=%d,\n iface=%s%s\n",
						   cmsgptr->cmsg_type, 
						   data_ptr->lsn1_baseif,
                                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

					if( cmsgptr->cmsg_type == IPV6_PKTINFO )
					{
						pktinfoptr = (struct in6_pktinfo *) CMSG_DATA(cmsgptr);

						LOG_OTHER( EIPM_LOG_ARP,
						       	 "EIPM_action - Received ARP reply on LSN1\n intf=%d, ip=%s\niface_index=%d\n",
							 pktinfoptr->ipi6_ifindex, 
							 inet_ntop(AF_INET6, &pktinfoptr->ipi6_addr, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
							 intfSpecDataP->lsn1_iface_indx );

						if ( pktinfoptr->ipi6_ifindex == intfSpecDataP->lsn1_iface_indx )
						{
							struct nd_neighbor_advert *na;

							na = (struct nd_neighbor_advert *)&buffer;

							LOG_DEBUG( EIPM_LOG_ARP,
							       	   "EIPM_action - Received ARP reply on LSN1\n nd_na_type=%d,\ntarget_ip=%s iface=%s%s\n",
								   na->nd_na_type, 
								   inet_ntop(AF_INET6, &na->nd_na_target, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
								   data_ptr->lsn1_baseif,
                                                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
		
							if( na->nd_na_type == ND_NEIGHBOR_ADVERT ) 
							{

								/*
								 * Check if the IP in the received ARP reply matches 
								 * the current ARP IP on any subnet.
								 */
								for( subn = 0;
								     subn < data_ptr->subnet_cnt;
								     subn++ )
								{
									if (data_ptr->subnet[subn].ip_cnt <= 0)
									{
										continue;
									}
									if (intfType == EIPM_EXTN_INTF &&
										data_ptr->subnet[subn].sub2intf_mapping[vlanId].is_intf_configured == 0)
									{
										continue;
									}
									arp_ptr = &(data_ptr->subnet[subn].arpdata);

									if( arp_ptr->arp_list[arp_ptr->cur_index].arp_ip.addrtype == IPM_IPV6 )
									{
										IPM_ipaddr2in( &(arp_ptr->arp_list[arp_ptr->cur_index].arp_ip), &ipm_ipv6_buf );
										if( (memcmp(&na->nd_na_target, &ipm_ipv6_buf, sizeof(struct in6_addr) ) == 0) )
										{
											LOG_DEBUG( EIPM_LOG_ARP,
												   "EIPM Action ARP RECV IPv6 reply on LSN1, iface %s%s\n",
												   data_ptr->lsn1_baseif,
                                                                                                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
		
												/*
												 * Set ARP received flag.
												 */
												arp_ptr->arp_list[arp_ptr->cur_index].lsn1_arprcvd
												    = TRUE;
										}
									}
								}					
							}
						}
					}
				}
				
			} /* end check on return from recvfrom() */
		
			if( count >= 10 )
			{
				LOG_DEBUG( EIPM_LOG_ARP,
				       	   "EIPM_action - Received more than 10 ARP replies on LSN1, iface=%s%s\n",
					   data_ptr->lsn1_baseif,
                                           ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
				
				/*
				 * Not a fatal error - just continue.
				 */
			}
		}

		/*
		 * Now update to the next ARP entry for each subnet.
		 * Since we don't force an ARP entry for each
		 * priority we have to find the next valid one.
		 */
		EIPM_STATUS pre_subnet_status = EIPM_STAT_NULL;
		for( subn = 0;
		     subn < data_ptr->subnet_cnt;
		     subn++ )
		{
			subnet_ptr = &(data_ptr->subnet[subn]);

			if (subnet_ptr->ip_cnt <= 0)
			{
				continue;
			}

			if (intfType == EIPM_EXTN_INTF &&
				subnet_ptr->sub2intf_mapping[vlanId].is_intf_configured == 0)
			{
				continue;
			}

			// Save the subnet status before it is updated
			pre_subnet_status = subnet_ptr->status;

			arp_ptr = &(subnet_ptr->arpdata);

			LOG_OTHER( EIPM_LOG_ARP,
				   "EIPM Action ARP RECV %s%s - %s%s state %d, sub_idx %d, arp_cur_idx %d, lsn0_arprcvd %d, lsn1_arprcvd %d\n",
				    data_ptr->lsn0_baseif,
				    ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
				    data_ptr->lsn1_baseif,
				    ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
				    intfSpecDataP->state,
				    subn,
				    arp_ptr->cur_index,
				    arp_ptr->arp_list[arp_ptr->cur_index].lsn0_arprcvd,
				    arp_ptr->arp_list[arp_ptr->cur_index].lsn1_arprcvd );

			/*
			 * If we received any ARP response for this address
			 * then make our routing decision.  We only check
			 * additional addresses in the ARP list if we
			 * get no responses.
			 */
			if( (arp_ptr->arp_list[arp_ptr->cur_index].lsn0_arprcvd == TRUE) ||
			    (arp_ptr->arp_list[arp_ptr->cur_index].lsn1_arprcvd == TRUE) )
			{
				subnet_ptr->arp_failure_count = 0;

				/*
				 * Track routing priority when in a failure condition
				 */
				if( arp_ptr->arp_list[arp_ptr->cur_index].lsn0_arprcvd == TRUE )
				{
					if( subnet_ptr->sub2intf_mapping[vlanId].route_priority != LSN0 )
					{
						subnet_ptr->force_grat_arp = FALSE;
						subnet_ptr->arp_degrade_counter = eipm_arp_sent_degraded + 1;
					}
					EIPM_update_subnet_route_priority( intfSpecDataP, subnet_ptr, LSN0 );
				}
				else
				{
					if( subnet_ptr->sub2intf_mapping[vlanId].route_priority != LSN1 )
					{
						subnet_ptr->force_grat_arp = FALSE;
						subnet_ptr->arp_degrade_counter = eipm_arp_sent_degraded + 1;
					}
					EIPM_update_subnet_route_priority( intfSpecDataP, subnet_ptr, LSN1 );
				}
				/*
				 * Ensure a GARP is sent when the first response is received from the
				 * next hop. 
				 */
				if( subnet_ptr->force_grat_arp == FALSE )
				{
					subnet_ptr->force_grat_arp = TRUE;
					
					if( arp_ptr->arp_list[arp_ptr->cur_index].lsn0_arprcvd == TRUE )
					{
						EIPM_SET_GRAT_ARP( subnet_ptr, LSN0 );
					}
					else
					{
						EIPM_SET_GRAT_ARP( subnet_ptr, LSN1 );
					}
				}


				if ( intfSpecDataP->state != NORMAL_STATE )
				{
					EIPM_CHECK_INTF_CONFIG( intfSpecDataP );
				}

				/*
				 * If we previously had lost connectivity on
				 * both interfaces and raised a critical alarm
				 * we now need to lower it back to major.
				 * We just need to re-send the alarm
				 * with the new priority, we don't need to
				 * clear the critical and raise the major.
				 */
				if( subnet_ptr->status == EIPM_OFFLINE )
				{
					subnet_ptr->status = EIPM_ONLINE;

					/* 
					 * Clear the next hop alarm.
					 */
					EIPM_CLEAR_SUBNET_ALARM( intfDataP,
                                                                 intfType,
							   	 subn,
							         EIPM_NEXTHOP_FAIL );
				}
			}
			else if( (arp_ptr->arp_list[arp_ptr->cur_index].lsn0_arprcvd == FALSE) &&
				 (arp_ptr->arp_list[arp_ptr->cur_index].lsn1_arprcvd == FALSE) )
			{
				subnet_ptr->arp_failure_count++;

				if (    ( intfSpecDataP->state == NORMAL_STATE )
                                     && ( subnet_ptr->arp_failure_count < ARP_FAILURE_THRESH ) )
				{
					continue;
				}

				if(( subnet_ptr->status != EIPM_OFFLINE ) &&
				   ( data_ptr->subnet[subn].arp_counter <= 0 ))
				{
					/*
					 * We did not receive a response on either interface from the 
					 * current target in the ARP list.  Check if there are other
					 * targets to try.  If not, declare a critical alarm.
					 */

		                        /* Construct arplistbuf */
		                        char arplistbuf[256] = ""; 
		                        bool append_comma = FALSE;
		                        bool found_arpip = FALSE;
					bool send_alarm = TRUE;

		                        for( i=0; send_alarm==TRUE && i<MAX_ARP_ENTRIES; i++ )
					{
		                                EIPM_ARP_ITEM   *arp_item_ptr =
	                                                &data_ptr->subnet[subn].arpdata.arp_list[i];
		
		                                if( arp_item_ptr->arp_ip.addrtype == IPM_IPV4 ||
						    arp_item_ptr->arp_ip.addrtype == IPM_IPV6 )
		                                {
				                        found_arpip = TRUE;

							/*
			 				 * Check if there are more IPs in the 
							 * ARP list to try.  If so, hold off
							 * sending an alarm.
							 */
							if( i > arp_ptr->cur_index )
							{
								send_alarm = FALSE;
								break;
							}
		                                        if( append_comma == TRUE )
		                                        {
		                                                strcat( arplistbuf, "," );
		                                        }
		                                        /* Append this ARP ip to the buf */
		                                        strcat( arplistbuf, IPM_ipaddr2p(&(arp_item_ptr->arp_ip), ipm_ipstr_buf, sizeof(ipm_ipstr_buf)) );
		                                        append_comma = TRUE;
		                                }
		                        }

					if( send_alarm == TRUE )
					{
				                if( found_arpip == TRUE )
						{
							if ( intfSpecDataP->state != NORMAL_STATE )
							{
								sprintf( linebuf,
									 "Lost connectivity on %s%s and %s%s to all Next Hop IPs: %s",
									 data_ptr->lsn0_baseif,
                                                                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
									 data_ptr->lsn1_baseif,
                                                                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
									 arplistbuf );
							}
							else if ( intfSpecDataP->preferred_side == LSN1 )
							{
								sprintf( linebuf,
									 "Lost connectivity on %s%s to all Next Hop IPs: %s",
									 data_ptr->lsn1_baseif,
                                                                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
									 arplistbuf );
							}
							else 
							{
								sprintf( linebuf,
									 "Lost connectivity on %s%s to all Next Hop IPs: %s",
									 data_ptr->lsn0_baseif,
                                                                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
									 arplistbuf );
							}
						}
						else
						{
							if ( intfSpecDataP->state != NORMAL_STATE )
							{
								sprintf( linebuf,
									 "Lost connectivity on %s%s and %s%s No Next Hop IPs configured",
									 data_ptr->lsn0_baseif,
                                                                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
									 data_ptr->lsn1_baseif,
                                                                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
							}
							else if ( intfSpecDataP->preferred_side == LSN1 )
							{
								sprintf( linebuf,
									 "Lost connectivity on %s%s No Next Hop IPs configured",
									 data_ptr->lsn1_baseif,
                                                                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
							}
							else 
							{
								sprintf( linebuf,
									"Lost connectivity on %s%s No Next Hop IPs configured",
									data_ptr->lsn0_baseif,
                                                                        ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
							}
						}

						/*
						 * There are no more IPs in the ARP list to try.
						 * Update the status to offline.
						 */
						subnet_ptr->status = EIPM_OFFLINE;

			                        EIPM_SEND_SUBNET_ALARM( EIPM_NEXTHOP_FAIL,
									1,
									intfDataP,
                                                                        intfType,
								        subn,
			                                                FSAS_critical,
			                                                data_ptr->lsn0_baseif,
			                                                linebuf );
			
					}
							
				} /* end if/else on ARP replies received */			
			}

			// Compare the old and new subnet status to see if a ping cmd should be issued
			// For IPv6, if a duplex failure occurs, the neigh entry can't be back to REACHABLE after recovery
			// By test, a ping cmd can fix the issue.
			if ((subnet_ptr->status != EIPM_OFFLINE) && (pre_subnet_status != subnet_ptr->status))
			{
				neigh_ping6(data_ptr, subnet_ptr, intfSpecDataP->vlanId);
			}
		}

		if ( intfSpecDataP->state == NORMAL_STATE )
		{
			/*
			 * Call function to update data for
			 * next ARP to send.
			 */
			EIPM_next_arp( data_ptr );
		
			/*
			 * We have switched routing if necessary.
			 * Continue sending ARPs to see if we get
			 * a response.  
			 */
			intfSpecDataP->recovery_state = ARP_SEND;
		
			break;
		}

		/*
		 * Determine if all subnets are offline or online.
		 */
		for( all_subnet_offline = TRUE, 
		     all_subnet_online = TRUE,
		     subn = 0;
		     subn < data_ptr->subnet_cnt;
		     subn++ )
		{
			if( data_ptr->subnet[subn].ip_cnt <= 0)
			{
				continue;
			}
			if( data_ptr->subnet[subn].status == EIPM_ONLINE )
			{
				all_subnet_offline = FALSE;

				/*
				 * Need to update the status to degraded.
				 */
				intfSpecDataP->status = EIPM_DEGRADED;
			}
			else
			{
				all_subnet_online = FALSE;
			}
		}

		if( all_subnet_offline == TRUE )
		{
			/*
			 * Need to update the status to offline.
			 */
			intfSpecDataP->status = EIPM_OFFLINE;

			EIPM_SET_REPORT_STATUS_TIMER( intfSpecDataP, 0 );
		} 
		else if ( all_subnet_online == TRUE )
		{
			/*
			 * There are no next hop alarms need to re-issue the
			 * link failure alarm.
			 */
			if ( intfSpecDataP->dir == LSN02LSN1 )
			{
				sprintf( linebuf,
				         "Lost connectivity between %s%s and %s%s",
					 data_ptr->lsn0_baseif,
                                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
					 data_ptr->lsn1_baseif,
                                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
			}
			else
			{
				sprintf( linebuf,
				         "Lost connectivity between %s%s and %s%s",
					 data_ptr->lsn1_baseif,
                                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
					 data_ptr->lsn0_baseif,
                                         ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
			}
					
			EIPM_SEND_INTF_ALARM( EIPM_LNK_FAIL,
					      1,
					      intfDataP,
                                              intfType,
			                      FSAS_major,
					      data_ptr->lsn0_baseif,
			                      linebuf );
		}

		/*
		 * Call function to update data for
		 * next ARP to send.
		 */
		EIPM_next_arp( data_ptr );
		
		/*
		 * We have switched routing if necessary.
		 * Continue sending ARPs to see if we get
		 * a response.  
		 */
		intfSpecDataP->recovery_state = ARP_SEND;
		
		break;
		
	default:
		ASRT_RPT( ASUNEXPECTEDVAL,
		          2,
		          100,
			  &data_ptr->subnet[0],
			  100,
			  &data_ptr->subnet[0].routes[0],
			  "Error: EIPM_action - recovery state is invalid.\niface=%s%s-%s%s, state=%d\n",
		          data_ptr->lsn0_baseif,
			  ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
		          data_ptr->lsn1_baseif,
			  ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
		          intfSpecDataP->recovery_state );
			  
		break;


	} /* end 'switch on recovery state' */
	
	return( IPM_SUCCESS );
	
} /* end func EIPM_action() */		

/**********************************************************************
 *
 * Name:        EIPM_get_proxy_client_socket()
 *
 * Abstract:	Get socket according to the information in the subnet of this IP
 *		Notes: Caller must make sure the pointer is valid
 *
 * Returns:	TURE or FALSE
 *
 *
 ***********************************************************************/
BOOL EIPM_get_proxy_client_socket( 
	unsigned char pivot_num,
	int  intf_index, 
	int * arp_socket_num, 
	EIPM_NET intf,
	IPM_IPADDRTYPE ip_version,
	int arp_op_req,
	EIPM_INTF *data_ptr
)
{
	if( (pivot_num == 0) || (pivot_num >= MAX_NUM_PIVOT) )
	{
		LOG_ERROR( EIPM_LOG_ARP, "Error: EIPM_get_proxy_client_socket - Invalid pivot_num (%d)\n", pivot_num);
		return (FALSE);
	}

	if( intf_index <= 0 )
	{
		LOG_ERROR( EIPM_LOG_ARP, "Error: EIPM_get_proxy_client_socket - Invalid interface index (%d)\n", intf_index);
		return (FALSE);
	}

	if( arp_socket_num == NULL )
	{
		LOG_ERROR( EIPM_LOG_ARP, "Error: EIPM_get_proxy_client_socket - Invalid pointer arp_socket_num (%p)\n", arp_socket_num);
		return (FALSE);
	}

	if( data_ptr == NULL )
	{
		LOG_ERROR( EIPM_LOG_ARP, "Error: EIPM_get_proxy_client_socket - Invalid pointer data_ptr (%p)\n", data_ptr);
		*arp_socket_num = -1;
		return (FALSE);
	}

	if( (ip_version != IPM_IPV4) && (ip_version != IPM_IPV6) )
	{
		LOG_ERROR( EIPM_LOG_ARP, "Error: EIPM_get_proxy_client_socket - Invalid ip_version (%d)\n", ip_version);
		*arp_socket_num = -1;
		return (FALSE);
	}

	if( (arp_op_req != ND_NEIGHBOR_ADVERT) && (arp_op_req != ND_NEIGHBOR_SOLICIT)
		&& (arp_op_req != ARPOP_REQUEST) && (arp_op_req != ARPOP_REPLY) )
	{
		LOG_ERROR( EIPM_LOG_ARP, "Error: EIPM_get_proxy_client_socket - Invalid arp_op_req (%d)\n", arp_op_req);
		*arp_socket_num = -1;
		return (FALSE);
	}

	if (ip_version == IPM_IPV4)
	{
		// 0 can't be ARP socket, so it must be > 0
		if ( data_ptr->eipm_pivot[pivot_num].ipv4_garp_socket > 0 )
		{
			*arp_socket_num = data_ptr->eipm_pivot[pivot_num].ipv4_garp_socket;
			return (TRUE);
		}
		// else continue to create it
	}
	else 
	{
		//IPM_IPV6
		if ( arp_op_req == ND_NEIGHBOR_ADVERT )
		{
			if ( data_ptr->eipm_pivot[pivot_num].ipv6_na_garp_socket > 0 )
			{
				*arp_socket_num = data_ptr->eipm_pivot[pivot_num].ipv6_na_garp_socket;
				return (TRUE);
			}
			// else continue to create it
		}
		else
		{
			// ND_NEIGHBOR_SOLICIT
			if ( data_ptr->eipm_pivot[pivot_num].ipv6_ns_garp_socket > 0 )
			{
				*arp_socket_num = data_ptr->eipm_pivot[pivot_num].ipv6_ns_garp_socket;
				return (TRUE);
			}
			// else continue to create it
		}
	}

	*arp_socket_num = EIPM_create_arp_socket(intf, ip_version, intf_index, arp_op_req);
	if( *arp_socket_num < 0 )
	{
		LOG_ERROR( EIPM_LOG_ARP, "Error: EIPM_get_proxy_client_socket - Failed to get GARP socket (%d)\n", *arp_socket_num);
		return (FALSE);
	}
	else
	{
		// Store socket into EIPM shared memory
		if (ip_version == IPM_IPV4)
		{
			data_ptr->eipm_pivot[pivot_num].ipv4_garp_socket = *arp_socket_num;
		}
		else
		{
			// IPM_IPV6
			if ( arp_op_req == ND_NEIGHBOR_ADVERT )
			{
				data_ptr->eipm_pivot[pivot_num].ipv6_na_garp_socket = *arp_socket_num;
			}
			else
			{
				// ND_NEIGHBOR_SOLICIT
				data_ptr->eipm_pivot[pivot_num].ipv6_ns_garp_socket = *arp_socket_num;
			}
		}
		return (TRUE);
	}
}

/**********************************************************************
 *
 * Name:        EIPM_close_proxy_client_socket()
 *
 * Abstract:	Close socket according to the information provided
 *		This function is called only when it is failed to 
 *		send GARP
 *
 * Returns:	void
 *
 *
 ***********************************************************************/
void EIPM_close_proxy_client_socket(
	unsigned char pivot_num, 
	IPM_IPADDRTYPE ip_version, 
	int arp_op_req, 
	EIPM_INTF * data_ptr
)
{

	if( (pivot_num == 0) || (pivot_num >= MAX_NUM_PIVOT) )
	{
		LOG_ERROR( EIPM_LOG_ARP, "Error: EIPM_close_proxy_client_socket - Invalid pivot_num (%d)\n", pivot_num);
		return;
	}

	if( data_ptr == NULL )
	{
		LOG_ERROR( EIPM_LOG_ARP, "Error: EIPM_close_proxy_client_socket - Invalid pointer data_ptr (%p)\n", data_ptr);
		return;
	}

	if( (ip_version != IPM_IPV4) && (ip_version != IPM_IPV6) )
	{
		LOG_ERROR( EIPM_LOG_ARP, "Error: EIPM_close_proxy_client_socket - Invalid ip_version (%d)\n", ip_version);
                return;
	} 

	if( (arp_op_req != ND_NEIGHBOR_ADVERT) && (arp_op_req != ND_NEIGHBOR_SOLICIT)
		&& (arp_op_req != ARPOP_REQUEST) && (arp_op_req != ARPOP_REPLY) )
	{
		LOG_ERROR( EIPM_LOG_ARP, "Error: EIPM_close_proxy_client_socket - Invalid arp_op_req (%d)\n", arp_op_req);
		return;
	}

	// Check whether the socket is created before
	if (ip_version == IPM_IPV4)
	{
		if ( data_ptr->eipm_pivot[pivot_num].ipv4_garp_socket > 0 )
		{
			close(data_ptr->eipm_pivot[pivot_num].ipv4_garp_socket);
			data_ptr->eipm_pivot[pivot_num].ipv4_garp_socket = -1;
		}
	}
	else 
	{
		//IPM_IPV6 
		if ( arp_op_req == ND_NEIGHBOR_ADVERT )
		{
			if ( data_ptr->eipm_pivot[pivot_num].ipv6_na_garp_socket > 0 )
			{
				close(data_ptr->eipm_pivot[pivot_num].ipv6_na_garp_socket);
				data_ptr->eipm_pivot[pivot_num].ipv6_na_garp_socket = -1;
			}
		}
		else 
		{
			// ND_NEIGHBOR_SOLICIT
			if ( data_ptr->eipm_pivot[pivot_num].ipv6_ns_garp_socket > 0 )
			{
				close(data_ptr->eipm_pivot[pivot_num].ipv6_ns_garp_socket);
				data_ptr->eipm_pivot[pivot_num].ipv6_ns_garp_socket = -1;
			}
		}
	}
	return;
}


/**********************************************************************
 *
 * Name:	EIPM_grat_arp()
 *
 * Abstract:	Called after routing is updated so we receive
 * 		packets on the correct interface.
 *
 * Parameters:	intfDataP - pointer to base/extension interface data.
 *           :              Type: EIPM_INTF/EIPM_INTF_SPEC
 *           :  intfType - Identifies the interface as base/extension.
 *		intf     - interface to send on.
 *		subn     - which subnet on this interface
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int EIPM_grat_arp( register void *intfDataP, EIPM_INTF_TYPE intfType, EIPM_NET intf, EIPM_SUBNET *subnet_ptr )

{
	register                EIPM_INTF *data_ptr;
        register                EIPM_INTF_SPEC *intfSpecDataP;
        int	                intf_idx;
	char *			mac_ptr;
	char *			iface_name_ptr;
	struct arp_pkt		arp;
	struct sockaddr_ll	haddr;
	struct in_addr 		ipm_ipv4_buf;
	char 			ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
	int			arpsock;
	int			ifindex;
	int			tmp_retval;
	int			retval;
	int			i;
	char                    ip_lsn0IntfStr[MAX_NLEN_DEV];
        char                    ip_lsn1IntfStr[MAX_NLEN_DEV];
        char                    lsn_intfStr[MAX_NLEN_DEV];
	BOOL                    is_proxy_client_ip = FALSE;
	int                     proxy_client_arp_sock = -1;
	int                     proxy_client_arp_ifindex = -1;
	BOOL 			ret_val = FALSE;

        EIPM_SET_INTF_PTRS( intfDataP, intfType, data_ptr, intfSpecDataP );

        if ( NULL == data_ptr )
        {
                return IPM_FAILURE;
        }
	intf_idx = intfSpecDataP->baseIntfIdx;

	if (subnet_ptr->ip_cnt < 1)
	{
		/* Do not attempt to ARP until at least one IP addr
		 * is configured.
		 */
		EIPM_GET_GRAT_ARP_CNT(subnet_ptr) = 0;
		EIPM_SET_GRAT_ARP(subnet_ptr, LSN_NONE);

		return IPM_SUCCESS;
	}

	switch( intf )
	{
	case LSN0:
	case LSN1:
		break;

	case LSN_BOTH:
		retval     = EIPM_grat_arp( intfDataP, intfType, LSN0, subnet_ptr );
		tmp_retval = EIPM_grat_arp( intfDataP, intfType, LSN1, subnet_ptr );

		if (retval == IPM_SUCCESS)
		{
			retval = tmp_retval;
		}

		return retval;
		break;

	default:
		return( IPM_SUCCESS );
	}

	if( subnet_ptr->ips[0].ipaddr.addrtype == IPM_IPV6 )
	{

		return EIPM_grat_arp6( intfDataP, intfType, intf, subnet_ptr );
	}
	else if( subnet_ptr->ips[0].ipaddr.addrtype != IPM_IPV4 )
	{
		int	tmp_sn_idx;
		int	subnet_idx = -1;

		for ( tmp_sn_idx=0;
			(tmp_sn_idx <= data_ptr->subnet_cnt) &&
				(subnet_idx == -1);
			tmp_sn_idx++ )
		{
			if ( &(data_ptr->subnet[tmp_sn_idx]) == subnet_ptr)
			{
				subnet_idx = tmp_sn_idx;
			}
		}

		ASRT_RPT( ASUNEXPECTEDVAL,
		          2,
		          sizeof(*data_ptr),
			  data_ptr,
			  sizeof(*subnet_ptr),
			  subnet_ptr,
			"Error: %s - invalid address type %d.\nintf=%d, intf_idx=%d, subnet_idx=%d\n",			  
			__FUNCTION__,
			subnet_ptr->ips[0].ipaddr.addrtype,
			intf,
			intf_idx,
			subnet_idx
		    );

		return( IPM_FAILURE );
	}


	if( intf == LSN0 )
	{
		ifindex = intfSpecDataP->lsn0_iface_indx;

		/*
		 * While we are here save other items we need
		 * to know for LSN0.
		 */
		mac_ptr        = data_ptr->lsn0_hwaddr;
		iface_name_ptr = data_ptr->lsn0_baseif;

		if( intfSpecDataP->lsn0_garpsock < 0 )
		{
			intfSpecDataP->lsn0_garpsock = 
			        EIPM_create_arp_socket( LSN0, IPM_IPV4, intfSpecDataP->lsn0_iface_indx, ARPOP_REPLY );
		}
		arpsock = intfSpecDataP->lsn0_garpsock;
	}
	else
	{
		ifindex = intfSpecDataP->lsn1_iface_indx;

		/*
		 * While we are here save other items we need
		 * to know for LSN1.
		 */
		mac_ptr        = data_ptr->lsn1_hwaddr;
		iface_name_ptr = data_ptr->lsn1_baseif;

		if( intfSpecDataP->lsn1_garpsock < 0 )
		{
			intfSpecDataP->lsn1_garpsock = 
			        EIPM_create_arp_socket( LSN1, IPM_IPV4, intfSpecDataP->lsn1_iface_indx, ARPOP_REPLY );
		}
		arpsock = intfSpecDataP->lsn1_garpsock;
	}
	

	snprintf( lsn_intfStr, MAX_NLEN_DEV, "%s%s", 
                  iface_name_ptr,
                  ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
	
	/*
	 * We need to send a gratuitous ARP for all of the IP
	 * addresses assigned to this subnet.
	 * 1) There are two kinds of IP stored in EIPM shared memory on host with FEPH service
	 *    EIPM_IP_PROXY_SERVER, it is FEPH IP which is invisible for outside and
	 *        It doesn't matter whether sending GARP or not
	 *    EIPM_IP_PROXY_CLIENT_ADDR, it is IMS published NI and GARP is sent to external gateway
	 * 2) On the host with IMS service, it sends GARP to host with FEPH service
	 *    with ip type EIPM_IP_PROXY_CLIENT on interface eth0.X/eth1.X or eth0.800.X/eth1.801.X or
	 *    sends GARP to others on interface eth0.400/eth1.401 with IP type EIPM_IP_ALIAS
	 * 3) After using tunnel to replace pivot driver, the GARP from IMS to FEPH is on eth0/eth1 or
	 *    eth0.800/eth1.801 and the IP is changed into internal floating service IP
         * Notes: iface_name_ptr is interface, such as, eth0.800/eth1.801, or eth2/eth3
         *        lsn_intfStr is for eth2/eth3, it could be eth2.X/eth3.X, eth0/eth1 or eth0.800/eth1.800
         *        ip_lsn0IntfStr:  on FEPH, eth2:YBAAA-eth3:YBAAA, or eth2.800:YBAAA-eth3.800:YBAAA,
         *                         on IMS, eth0.600:YFAAA-eth1.601:YFAAA, eth0.800.7:4FAAA-eth1.801.7:4FAAA
         */
        IPM_IPADDR tmp_src_ip;
        IPM_IPADDR tmp_dst_ip;

	for( i = 0; i < subnet_ptr->ip_cnt; i++ )
	{
		is_proxy_client_ip = FALSE;
		strncpy( ip_lsn0IntfStr, subnet_ptr->ips[i].lsn0_iface, ( MAX_NLEN_DEV - 1 ) );
                strtok( ip_lsn0IntfStr, ":" );
                strncpy( ip_lsn1IntfStr, subnet_ptr->ips[i].lsn1_iface, ( MAX_NLEN_DEV - 1 ) );
                strtok( ip_lsn1IntfStr, ":" );

                if (    ( strcmp( ip_lsn0IntfStr, lsn_intfStr ) != 0 ) 
                     && ( strcmp( ip_lsn1IntfStr, lsn_intfStr ) != 0 ) )
                {
			if ( (subnet_ptr->ips[i].type == EIPM_IP_PROXY_CLIENT) &&
				( (strstr(ip_lsn0IntfStr, lsn_intfStr) != NULL) ||
					(strstr(ip_lsn1IntfStr, lsn_intfStr) != NULL) ) )
			{
				is_proxy_client_ip = TRUE;
			}
			else
			{
                        	continue;
			}
                }
		
		/*
		 * If it is virtual, then it will be HP guest or cloud ENV and
		 * use IMS internal floating IP as source IP, otherwise, use 
		 * published NI
		 */
		if ((ipm_isVirtual() == 1) && (is_proxy_client_ip == TRUE))
		{
			IPM_GET_TUNNEL_ENDPOINT_IPS(subnet_ptr->ips[i].pivot_id,
				tmp_src_ip, tmp_dst_ip);
			if (IPM_IPBADVER == tmp_src_ip.addrtype)
			{
				LOG_ERROR( 0, "Error: EIPM_grat_arp - Failed to get IMS internal IP with pivot_id=%d\n", subnet_ptr->ips[i].pivot_id);
				continue;
			}
		}
		else
		{
			tmp_src_ip = subnet_ptr->ips[i].ipaddr;
		}

		// Get ifindex and socket if it is proxy client IP 
		if ( (is_proxy_client_ip == TRUE) && (ipm_isVirtual() != 1) )
		{
			proxy_client_arp_ifindex = subnet_ptr->pivot_iface_indx[0][subnet_ptr->ips[i].pivot_id];
			ret_val = EIPM_get_proxy_client_socket(subnet_ptr->ips[i].pivot_id,
					proxy_client_arp_ifindex, &proxy_client_arp_sock,
					intf, IPM_IPV4, ARPOP_REQUEST, data_ptr);

			if( ret_val == FALSE )
			{
				continue;
			}

			retval = EIPM_sendARP( proxy_client_arp_sock, mac_ptr, &(tmp_src_ip), 
					&(tmp_src_ip), proxy_client_arp_ifindex, ARPOP_REQUEST );
		}
		else
		{
			retval = EIPM_sendARP( arpsock, mac_ptr, &(tmp_src_ip),
					&(tmp_src_ip), ifindex, ARPOP_REQUEST );
		}
		
		if( retval < 0 )
		{
			LOG_ERROR( EIPM_LOG_ARP,
				"Error: EIPM_grat_arp - sending gratuitous ARP failed\nIP=%s, iface=%s retval=%d, errno=%d\n",
				IPM_ipaddr2p(&(tmp_src_ip), ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
				lsn_intfStr, retval, errno );
			if( (is_proxy_client_ip == TRUE) && (ipm_isVirtual() != 1) )
			{
				EIPM_close_proxy_client_socket( subnet_ptr->ips[i].pivot_id, IPM_IPV4, ARPOP_REQUEST, data_ptr );
                                proxy_client_arp_sock = -1;
			}
			else
			{
				/*
				 * Another option would be to try remaining
				 * IP addresses.  Current decision is to
				 * give up.
				 */
				if( intf == LSN0 )
				{
					intfSpecDataP->lsn0_garpsock = -1;
				}
				else
				{
					intfSpecDataP->lsn1_garpsock = -1;
				}
				close( arpsock );
			}
			return( IPM_FAILURE );
		}

		if( (is_proxy_client_ip == TRUE) && (ipm_isVirtual() != 1) )
		{
			retval = EIPM_sendARP( proxy_client_arp_sock, mac_ptr, &(tmp_src_ip), 
					&(tmp_src_ip), proxy_client_arp_ifindex, ARPOP_REPLY );
		}
		else
		{
			retval = EIPM_sendARP( arpsock, mac_ptr, &(tmp_src_ip),
					&(tmp_src_ip), ifindex, ARPOP_REPLY );
		}

		if( retval < 0 )
		{
			LOG_ERROR( EIPM_LOG_ARP,
				"Error: EIPM_grat_arp - sending gratuitous ARP failed\nIP=%s, iface=%s retval=%d, errno=%d\n",
				IPM_ipaddr2p(&(tmp_src_ip), ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
				lsn_intfStr, retval, errno );
			if(  (is_proxy_client_ip == TRUE) && (ipm_isVirtual() != 1) )
			{
				EIPM_close_proxy_client_socket( subnet_ptr->ips[i].pivot_id, IPM_IPV4, ARPOP_REQUEST, data_ptr );
                                proxy_client_arp_sock = -1;
			}
			else
			{
				/*
				 * Another option would be to try remaining
				 * IP addresses.  Current decision is to
				 * give up.
				 */
				if( intf == LSN0 )
				{
					intfSpecDataP->lsn0_garpsock = -1;
				}
				else
				{
					intfSpecDataP->lsn1_garpsock = -1;
				}
				close( arpsock );
			}
			
			return( IPM_FAILURE );
		}

	}
		
	LOG_OTHER( EIPM_LOG_ARP,
	       	 "EIPM_grat_arp - Sent gratuitous ARP on iface=%s\n",
		 iface_name_ptr );
	
	return( IPM_SUCCESS );
		
} /* end EIPM_grat_arp() */


/**********************************************************************
 *
 * Name:	EIPM_grat_arp6()
 *
 * Abstract:	Provides IPv6 like "GARP" and is called after routing 
 *		is updated so we receive packets on the correct interface.
 *
 * Parameters:	intfDataP - pointer to base/extension interface data.
 *                          Type: EIPM_INTF/EIPM_INTF_SPEC.
 *              intfType - identifies the interface as base/extension.
 *		intf     - interface to send on.
 *		subn     - which subnet on this interface
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int EIPM_grat_arp6( register void *intfDataP, EIPM_INTF_TYPE intfType, EIPM_NET intf,  EIPM_SUBNET *subnet_ptr )

{
	register                EIPM_INTF *data_ptr;
        register                EIPM_INTF_SPEC *intfSpecDataP;
        int	                intf_idx;
	char *			mac_ptr;
	char *			iface_name_ptr;
	char 			ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
	int			ifindex;
	struct arp6_pkt		arp;
	struct sockaddr_in6	saddr;
	int			arpsock;
	int			retval;
	int			i;
	struct sockaddr_in6 	whereto;
	struct in6_pktinfo	pktinfo;	
	struct msghdr 		msg;
	char 			pktbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	struct cmsghdr 		*cmptr;
	struct iovec 		iov[1];
	struct in6_pktinfo 	*pktinfo_ptr;
	char                    ip_lsn0IntfStr[MAX_NLEN_DEV];
        char                    ip_lsn1IntfStr[MAX_NLEN_DEV];
        char                    lsn_intfStr[MAX_NLEN_DEV];
	BOOL                    is_proxy_client_ip = FALSE;
	int                     proxy_client_arp_sock = -1;
	int                     proxy_client_arp_ifindex = -1;
	BOOL 			ret_val = FALSE;

        EIPM_SET_INTF_PTRS( intfDataP, intfType, data_ptr, intfSpecDataP );

        if ( NULL == data_ptr )
        {
                return IPM_FAILURE;
        }
	intf_idx = intfSpecDataP->baseIntfIdx;

	switch( intf )
	{
	case LSN0:
	case LSN1:
		break;

	default:
		return( IPM_SUCCESS );
	}

	/*
	 * We need to send a gratuitous ARP for all of the IP
	 * addresses assigned to this subnet.
	 */
	if( subnet_ptr->ips[0].ipaddr.addrtype != IPM_IPV6 )
	{
		int	tmp_sn_idx;
		int	subnet_idx = -1;

		for ( tmp_sn_idx=0;
			(tmp_sn_idx <= data_ptr->subnet_cnt) &&
				(subnet_idx == -1);
			tmp_sn_idx++ )
		{
			if ( &(data_ptr->subnet[tmp_sn_idx]) == subnet_ptr)
			{
				subnet_idx = tmp_sn_idx;
			}
		}

		ASRT_RPT( ASUNEXPECTEDVAL,
		          2,
		          sizeof(*data_ptr),
			  data_ptr,
			  sizeof(*subnet_ptr),
			  subnet_ptr,
			"Error: %s - invalid address type %d.\nintf=%d, intf_idx=%d, subnet_idx=%d\n",			  
			__FUNCTION__,
			subnet_ptr->ips[0].ipaddr.addrtype,
			intf,
			intf_idx,
			subnet_idx
		    );

		return( IPM_FAILURE );
	}

	/* 
	 * Do not send a GARP if any IP address is in the tentative state as
	 * this will cause it to stay in the tenatative state.
	 */
	if( EIPM_check_ip_tentative( intfDataP, intfType, subnet_ptr ) == IPM_FAILURE )
	{
		LOG_OTHER( 0,
		       	 "EIPM_grat_arp6 - IP in tentative state\n"
			 );

		return( IPM_IP_TENTATIVE );
	}

	
	if( intf == LSN0 )
	{
		ifindex = intfSpecDataP->lsn0_iface_indx;
		
		/*
		 * While we are here save other items we need
		 * to know for LSN0.
		 */
		mac_ptr        = data_ptr->lsn0_hwaddr;
		iface_name_ptr = data_ptr->lsn0_baseif;

		if ( intfSpecDataP->lsn0_v6garpsock < 0 )
		{
			intfSpecDataP->lsn0_v6garpsock = 
				EIPM_create_arp_socket( LSN0, IPM_IPV6, intfSpecDataP->lsn0_iface_indx, ND_NEIGHBOR_ADVERT );
		}
		arpsock = intfSpecDataP->lsn0_v6garpsock;
	}
	else
	{
		ifindex = intfSpecDataP->lsn1_iface_indx;
	
		/*
		 * While we are here save other items we need
		 * to know for LSN1.
		 */
		mac_ptr        = data_ptr->lsn1_hwaddr;
		iface_name_ptr = data_ptr->lsn1_baseif;

		if( intfSpecDataP->lsn1_v6garpsock < 0 )
		{
			intfSpecDataP->lsn1_v6garpsock = 
				EIPM_create_arp_socket( LSN1, IPM_IPV6, intfSpecDataP->lsn1_iface_indx, ND_NEIGHBOR_ADVERT );
		}
		arpsock = intfSpecDataP->lsn1_v6garpsock;
	}
	
	if( arpsock < 0 )
        {
                LOG_ERROR( EIPM_LOG_ARP,
                         "Error: EIPM_grat_arp6 - creating ARP socket failed\nretval=%d, errno=0x%x\n",
                         arpsock, errno );

                return( IPM_FAILURE );
        }

	snprintf( lsn_intfStr, MAX_NLEN_DEV, "%s%s", 
                  iface_name_ptr,
                  ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

	/*
	 * Send a "GARP" neighbor advertisements for all IP addresses on the subnet.
 	 */
	IPM_IPADDR tmp_src_ip;
	IPM_IPADDR tmp_dst_ip;
	for( i = 0; i < subnet_ptr->ip_cnt; i++ )
	{
		is_proxy_client_ip = FALSE;
		strncpy( ip_lsn0IntfStr, subnet_ptr->ips[i].lsn0_iface, ( MAX_NLEN_DEV - 1 ) );
                strtok( ip_lsn0IntfStr, ":" );
                strncpy( ip_lsn1IntfStr, subnet_ptr->ips[i].lsn1_iface, ( MAX_NLEN_DEV - 1 ) );
                strtok( ip_lsn1IntfStr, ":" );

                if (    ( strcmp( ip_lsn0IntfStr, lsn_intfStr ) != 0 ) 
                     && ( strcmp( ip_lsn1IntfStr, lsn_intfStr ) != 0 ) )
                {
			if ( (subnet_ptr->ips[i].type == EIPM_IP_PROXY_CLIENT) &&
				( (strstr(ip_lsn0IntfStr, lsn_intfStr) != NULL) ||
					(strstr(ip_lsn1IntfStr, lsn_intfStr) != NULL) ) )
			{
				is_proxy_client_ip = TRUE;
			}
			else
			{
				continue;
			}
                }

		if ((ipm_isVirtual() == 1) && (is_proxy_client_ip == TRUE))
		{
			IPM_GET_TUNNEL_ENDPOINT_IPS(subnet_ptr->ips[i].pivot_id,
				tmp_src_ip, tmp_dst_ip);
			if (IPM_IPBADVER == tmp_src_ip.addrtype)
			{
				 LOG_ERROR( 0, "Error: EIPM_grat_arp6 - Failed to get IMS internal IP with pivot_id=%d\n", subnet_ptr->ips[i].pivot_id);
				continue;
			}
		}
		else
		{
			tmp_src_ip = subnet_ptr->ips[i].ipaddr;
		}

		// Get ifindex and socket if it is proxy client IP
		if( is_proxy_client_ip == TRUE )
		{
			if (ipm_isVirtual() != 1)
			{
				// ATCA platform
				proxy_client_arp_ifindex = subnet_ptr->pivot_iface_indx[0][subnet_ptr->ips[i].pivot_id];
				ret_val = EIPM_get_proxy_client_socket(subnet_ptr->ips[i].pivot_id,
                                        proxy_client_arp_ifindex, &proxy_client_arp_sock,
					intf, IPM_IPV6, ND_NEIGHBOR_ADVERT, data_ptr);
				if( ret_val == FALSE )
				{
					continue;
				}
			
				retval = EIPM_sendARP( proxy_client_arp_sock, mac_ptr, 
					&(tmp_src_ip),&(tmp_src_ip),
					proxy_client_arp_ifindex, ND_NEIGHBOR_ADVERT );
			}
			else
			{
				/*
				 * Virtual environment, it will use interface IPv4 GARP socket and
				 * use internal floating IP sending GARP
				 */
				int tmp_arp_sock = -1;
				if ( intf == LSN0)
				{
					if( intfSpecDataP->lsn0_garpsock < 0 )
					{
						intfSpecDataP->lsn0_garpsock = EIPM_create_arp_socket( LSN0, IPM_IPV4, 
							intfSpecDataP->lsn0_iface_indx, ARPOP_REPLY );
					}
					tmp_arp_sock = intfSpecDataP->lsn0_garpsock;
				}
				else
				{
					if( intfSpecDataP->lsn1_garpsock < 0 )
					{
						intfSpecDataP->lsn1_garpsock = EIPM_create_arp_socket( LSN1, IPM_IPV4,
							intfSpecDataP->lsn1_iface_indx, ARPOP_REPLY );
					}
					tmp_arp_sock = intfSpecDataP->lsn1_garpsock;
				}
				if (tmp_arp_sock < 0)
				{
				 	LOG_ERROR( 0, "EIPM_grat_arp6 - Failed to get GARP socket, arp_sock=%d\n", tmp_arp_sock);
					continue;
				}
				retval = EIPM_sendARP( tmp_arp_sock, mac_ptr, &(tmp_src_ip),&(tmp_src_ip), ifindex, ARPOP_REPLY);
			}
		}
		else
		{
			retval = EIPM_sendARP( arpsock, mac_ptr, &(tmp_src_ip),
                       	         &(tmp_src_ip), ifindex, ND_NEIGHBOR_ADVERT );
		}

		if( retval < 0 )
		{
			if( is_proxy_client_ip == TRUE )
			{
				if (ipm_isVirtual() != 1)
				{
				LOG_ERROR( EIPM_LOG_ARP,
					 "Error: EIPM_grat_arp6 - sending gratuitous ARP failed\nIP=%s, iface=%s-%s retval=%d, errno=%d\n",
					IPM_ipaddr2p( (&tmp_src_ip), ipm_ipstr_buf, sizeof(ipm_ipstr_buf) ),
					ip_lsn0IntfStr, ip_lsn1IntfStr, retval, errno);
				EIPM_close_proxy_client_socket( subnet_ptr->ips[i].pivot_id, IPM_IPV6, ND_NEIGHBOR_ADVERT, data_ptr );
                                proxy_client_arp_sock = -1;
				}
				else
				{
					LOG_ERROR( EIPM_LOG_ARP,
						 "Error: EIPM_grat_arp6 - sending gratuitous ARP failed\nIP=%s, iface=%s-%s retval=%d, errno=%d\n",
						IPM_ipaddr2p( &tmp_src_ip, ipm_ipstr_buf, sizeof(ipm_ipstr_buf) ),
						data_ptr->lsn0_baseif, data_ptr->lsn0_baseif,  retval, errno);
					if( intf == LSN0 )
					{
						close(intfSpecDataP->lsn0_garpsock);
						intfSpecDataP->lsn0_garpsock = -1;
					}
					else
					{
						close(intfSpecDataP->lsn1_garpsock);
						intfSpecDataP->lsn1_garpsock = -1;
					}
				}
			}
			else
			{
				LOG_ERROR( EIPM_LOG_ARP,
					 "Error: EIPM_grat_arp6 - sending gratuitous ARP failed\nIP=%s, iface=%s retval=%d, errno=%d\n",
					 IPM_ipaddr2p( &(subnet_ptr->ips[i].ipaddr), ipm_ipstr_buf, sizeof(ipm_ipstr_buf) ),
					 lsn_intfStr,
					 retval,
					 errno );
			
				/*
				 * Another option would be to try remaining
				 * IP addresses.  Current decision is to
				 * give up. 
				 */
				if( intf == LSN0 )
				{
					intfSpecDataP->lsn0_v6garpsock = -1;
				}
				else
				{
					intfSpecDataP->lsn1_v6garpsock = -1;
				}
			}
			close( arpsock );
		
			return( IPM_FAILURE );
		}

		if( is_proxy_client_ip == TRUE )
		{
			if (ipm_isVirtual() != 1)
			{
			LOG_OTHER( EIPM_LOG_ARP,
				"EIPM_grat_arp6 - Sent GARP to %s on if_index=%d iface=%s-%s\n",
				IPM_ipaddr2p( (&tmp_src_ip), ipm_ipstr_buf, sizeof(ipm_ipstr_buf) ),
				proxy_client_arp_ifindex,
				ip_lsn0IntfStr, ip_lsn1IntfStr);
			}
			else
			{
				LOG_OTHER( EIPM_LOG_ARP,
					"EIPM_grat_arp6 - Sent GARP to %s on if_index=%d iface=%s-%s\n",
					IPM_ipaddr2p( &(tmp_src_ip), ipm_ipstr_buf, sizeof(ipm_ipstr_buf) ),
					ifindex, data_ptr->lsn0_baseif, data_ptr->lsn1_baseif);
			}
		}
		else
		{
			LOG_OTHER( EIPM_LOG_ARP,
				 "EIPM_grat_arp6 - Sent GARP to %s on if_index=%d iface=%s\n",
				 IPM_ipaddr2p( (&subnet_ptr->ips[i].ipaddr), ipm_ipstr_buf, sizeof(ipm_ipstr_buf) ),
				 ifindex,
				 lsn_intfStr );
		}
		
		// Sending NS to FEPH to get IMS neigh cache updated after sending NA
		if( (is_proxy_client_ip == TRUE) && (ipm_isVirtual() != 1) )
		{
			char ipm_ipstr_buf2[IPM_IPMAXSTRSIZE];
			int ns_sock_2_feph = -1;
			int ns_ifindex_2_feph = -1;
			int route_idx;
			EIPM_ROUTES *route_ptr;
			ret_val = FALSE;
			IPM_IPADDR destIP;
			BOOL is_found_dest = FALSE;
		
			// Check SPBR firstly
			if( subnet_ptr->table_num > 0 )
			{
				// SPBR
				if( !IPM_IPADDR_ISUNSPECIFIED(&(subnet_ptr->gateway)) )
				{
					destIP = subnet_ptr->gateway;
					is_found_dest = TRUE;
				}
			}

			// Search destination IP 
			if( is_found_dest == FALSE )
			{
				// Not SPBR, try defaut or static route
			for( route_idx = 0, route_ptr = &subnet_ptr->routes[0];
				route_idx < subnet_ptr->route_cnt;
				route_idx++, route_ptr++ )
			{
				if( (subnet_ptr->ips[i].pivot_id == route_ptr->pivot_id) &&
					(route_ptr->type == EIPM_ROUTE_OTH))
				{
					destIP = route_ptr->nexthop;
					is_found_dest = TRUE;
					break;
				}
			}
			}

			if( is_found_dest == TRUE )
			{
				ns_ifindex_2_feph = subnet_ptr->pivot_iface_indx[0][subnet_ptr->ips[i].pivot_id];
				ret_val = EIPM_get_proxy_client_socket(subnet_ptr->ips[i].pivot_id,
						ns_ifindex_2_feph, &ns_sock_2_feph, intf, IPM_IPV6, ND_NEIGHBOR_SOLICIT, data_ptr);
				if( ret_val == TRUE )
				{ 
					// Sending NS
					retval = EIPM_sendARP( ns_sock_2_feph, mac_ptr,
						&(subnet_ptr->ips[i].ipaddr), &(destIP),
						ns_ifindex_2_feph, ND_NEIGHBOR_SOLICIT);
					if( retval < 0  )
					{
						LOG_ERROR( EIPM_LOG_ARP, "Error: EIPM_grat_arp6 - sending NS failed\n IMS IP (%s) and destination Ip (%s)\n",
							IPM_ipaddr2p( (&subnet_ptr->ips[i].ipaddr), ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
							IPM_ipaddr2p( (&destIP), ipm_ipstr_buf2, sizeof(ipm_ipstr_buf2)));
						// Set send_grat_arp_cnt as 5 and let it triggers again in 250ms
						EIPM_GET_GRAT_ARP_CNT((subnet_ptr)) = 5;
						EIPM_GET_GRAT_ARP((subnet_ptr)) = intf;
						// Close the socket if it is failed to send NS
						EIPM_close_proxy_client_socket( subnet_ptr->ips[i].pivot_id, IPM_IPV6, ND_NEIGHBOR_SOLICIT, data_ptr );
                                                ns_sock_2_feph = -1;
					}
				}
			}
		}
	}
	
	return( IPM_SUCCESS );
		
} /* end EIPM_grat_arp6() */



/**********************************************************************
 *
 * Name:	EIPM_next_arp()
 *
 * Abstract:	Called to update subnet/arp indices to point
 *		to next ARP to be sent.
 *
 * Parameters:	data_ptr - pointer to per-interface data
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

void EIPM_next_arp( register EIPM_INTF *data_ptr )

{
	register EIPM_ARPLIST	*arp_ptr;
	struct in_addr 		ipm_ipv4_buf;
	char 			ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
	int			subn;
	int			i;
	bool			fnd_new;
	
	/*
	 * We go through 1 ARP address in each subnet so that
	 * we get all subnets moved (if necessary) ASAP.  On
	 * later passes we will use the next ARP address in
	 * each subnet, etc.
	 */
		
	/*
	 * Now update to the next ARP entry for each subnet.
	 * Since we don't force an ARP entry for each
	 * priority we have to find the next valid one.
	 */
	for( subn = 0;
	     subn < data_ptr->subnet_cnt;
	     subn++ )
	{
		if (data_ptr->subnet[subn].ip_cnt <= 0)
		{
			continue;
		}
		/*
		 * Update the arp counters for those at 0 and 
		 * skip the ones that are still counting down.
		 */
		if( data_ptr->subnet[subn].arp_counter > 0 )
		{
			continue;
		}

		arp_ptr = &(data_ptr->subnet[subn].arpdata);
		fnd_new = FALSE;

		if( (arp_ptr->arp_list[arp_ptr->cur_index].lsn0_arprcvd == FALSE) &&
		    (arp_ptr->arp_list[arp_ptr->cur_index].lsn1_arprcvd == FALSE) )
		{
			/*
			 * No arp target has responded
			 */
			if ( data_ptr->specData.state == NORMAL_STATE )
			{
				data_ptr->subnet[subn].arp_counter = EIPM_ARP_DELAY_DEGRADED * EIPM_ARP_CNT_PER_SEC;
			}
			else
			{
				data_ptr->subnet[subn].arp_counter = EIPM_ARP_DELAY_OFFLINE * EIPM_ARP_CNT_PER_SEC;
			}

			/*
			 * Loop through remaining list of ARP
			 * entries to find the next valid one.
			 */
			for( i = arp_ptr->cur_index + 1;
			     i < MAX_ARP_ENTRIES;
			     i++ )
			{
				/*
				 * Find the next valid ARP
				 * entry.
				 */
				if( arp_ptr->arp_list[i].arp_ip.addrtype == IPM_IPV4 ||
				    arp_ptr->arp_list[i].arp_ip.addrtype == IPM_IPV6 )
				{
					/*
					 * This is it.
					 */
					arp_ptr->cur_index = i;
					fnd_new = TRUE;
					break;
				}
			}
			
			/*
			 * If we did not find a match we
			 * have to search again from 0 up
			 * to (and including) the current index.
			 * There may only be 1 entry for this
			 * subnet.
			 */
			if( fnd_new == FALSE )
			{
				for( i = 0;
				     i <= arp_ptr->cur_index;
				     i++ )
				{
					/*
					 * Is the ARP entry valid?
					 */
					if( arp_ptr->arp_list[i].arp_ip.addrtype == IPM_IPV4 ||
					    arp_ptr->arp_list[i].arp_ip.addrtype == IPM_IPV6 )
					{
						/*
						 * This is it.
						 */
						arp_ptr->cur_index = i;
						fnd_new = TRUE;
						break;
					}
				}
			}
		}		
		else
		{
			/*
			 * At least one arp target has responded, so continue to
			 * to send arp 3times within 3 s and then at a slower rate (akin to arp cache timeout).
			 */
			if ( data_ptr->specData.state == NORMAL_STATE )
			{
				data_ptr->subnet[subn].arp_counter = eipm_arp_delay_degraded * EIPM_ARP_CNT_PER_SEC;
			}
			else
			{
				if (data_ptr->subnet[subn].arp_degrade_counter > 0)
				{
					data_ptr->subnet[subn].arp_degrade_counter--;
				}
				if (data_ptr->subnet[subn].arp_degrade_counter > 0)
				{
					data_ptr->subnet[subn].arp_counter = EIPM_ARP_CNT_PER_SEC;
				}
				else
				{
					data_ptr->subnet[subn].arp_counter = eipm_arp_delay_degraded * EIPM_ARP_CNT_PER_SEC;
				}
			}
		}

	} /* end 'for subnet loop' */
	
	/*
	 * Else the next subne is valid.  We should be pointing to
	 * the correct ARP entry (set when we started ARPing).
	 */
	
	return;
	
} /* end EIPM_next_arp() */




/**********************************************************************
 *
 * Name:        EIPM_grat_arp_all()
 *
 * Abstract:    Send gratuitous ARP for all managed subnets
 *
 * Parameters:  None
 *
 * Returns:     IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/

int EIPM_grat_arp_all()
{
	register EIPM_DATA	*data_ptr;
	register EIPM_INTF	*intf_ptr;
	register EIPM_SUBNET	*subnet_ptr;
	int			intf;
	int			subn;
	int			retval;
	int			tmp_retval;
	
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
		          "EIPM_grat_arp_all: EIPM not attached to shared memory segment\n" );
		
		return( IPM_FAILURE);
	}
	
	/*
	 * If data has not been initialized then there is nothing
	 * to do.
	 */
	data_ptr = (EIPM_DATA *)EIPM_shm_ptr;

	retval = IPM_SUCCESS;
	
	/*
	 * Loop through shared segment.
	 */
	for( intf = 0, intf_ptr = &(data_ptr->intf_data[ 0 ]);
             intf < data_ptr->intf_cnt; 
             intf++, intf_ptr++ )
	{
		/*
		 * Sanity check state
		 */
		switch( intf_ptr->specData.state )
		{
		case NORMAL_STATE:
		case ACTION_STATE:
			break;

		case NULL_STATE:
		case DETECTION_STATE:
		case RESTORE_STATE:
			
		default:
			continue;
		}
		
		/*
		 * Loop through all of the subnets on this
		 * interface and send gratuitous ARPs.
		 */
		for( subn = 0, subnet_ptr = &(intf_ptr->subnet[subn]);
		     subn < intf_ptr->subnet_cnt;
		     subn++, subnet_ptr++ )
		{
			tmp_retval = EIPM_grat_arp( intf_ptr, EIPM_BASE_INTF, subnet_ptr->sub2intf_mapping[0].route_priority, subnet_ptr );
 
			if( tmp_retval != IPM_SUCCESS )
			{
				/*
				 * Function already asserted.
				 */
				char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
				char routing_priority_str[16];
				EIPM_network2str(subnet_ptr->sub2intf_mapping[0].route_priority, routing_priority_str);
				LOG_ERROR( EIPM_LOG_ARP, "Error: EIPM_grat_arp_all - gratuitous ARP failed, iface=%s, subnet=%s/%d\n",
					routing_priority_str,
					IPM_ipaddr2p(&subnet_ptr->subnet_base, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
					subnet_ptr->prefixlen );
			}

		} /* end 'for each subnet' */
		
	} /* end 'for each interface' */
	
	return( retval );
}

/**********************************************************************
 *
 * Name:        EIPM_sendARP()
 *
 * Abstract:    Called to send ARP packets
 *
 * Parameters:  sockfd - socket fd used to send ARP
 *              lsn_hwaddr - hardware addr of sending LSN
 *              src - source IP
 *              dst - destination IP
 *              ifindex - interface index
 *              arpop - arp operation code
 *
 * Returns:     IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/


int EIPM_sendARP( int sockfd, unsigned char *lsn_hwaddr,
                IPM_IPADDR *src, IPM_IPADDR *dst, int ifindex, int arpop )

{
        char	ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
        char	ipm_ipstr_buf2[IPM_IPMAXSTRSIZE];
        int 	retval;

	if ( FALSE == EIPM_GET_PROXY_SERVER_ENABLED() )
        {
                return IPM_SUCCESS;
        }

        if ( sockfd < 0 )
        {
                LOG_ERROR( 0, "Error: EIPM_sendARP - Invalid sock fd [%d]", sockfd );
                return IPM_FAILURE;
        }

        if ( lsn_hwaddr == NULL )
        {
                LOG_ERROR( 0, "Error: EIPM_sendARP - lsn_hwaddr is NULL" );
                return IPM_FAILURE;
        }

        if ( dst == NULL )
        {
                LOG_ERROR( 0, "Error: EIPM_sendARP - invalid pointer - dst addr is NULL" );
                return IPM_FAILURE;
        }

	if ( NULL == src )
        {
                LOG_ERROR( 0,
                           "ERROR(%s) - Source address is NULL.\n",
                           (char *)(__func__) );
                return IPM_FAILURE;
        }

        /*
         * Check what type of ARP to send.
         */
        if( dst->addrtype == IPM_IPV4 )
        {
                struct arp_pkt          arp;
                struct sockaddr_ll      haddr;
                struct in_addr          ipm_ipv4_buf;
		int			sd;
		int			on;
		struct sockaddr_in	sa;
		struct ifreq		ifr;
		
		sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
		if (sd < 0)
		{
			LOG_ERROR(0, "socket failed, errno=%d\n", errno);
	                return IPM_FAILURE;
		}

		ifr.ifr_ifindex = ifindex;
	
		/* Get MAC address */
		retval = ioctl(sd, SIOCGIFNAME, &ifr);
		if( retval < 0 )
		{
			LOG_OTHER(EIPM_LOG_ARP, 
				"EIPM sendARP Failure: ioctl(SIOCGIFNAME) failed for interface=%d, retval %d, errno %d",
				ifindex, retval, errno);
		}		

		retval = setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, ifr.ifr_name, strlen(ifr.ifr_name)+1);
		if (retval != 0)
		{
			LOG_OTHER(EIPM_LOG_ARP, "SO_BINDTODEVICE failed, errno=%d\n", errno);
		}
		
		on = 1;
		retval = setsockopt(sd, SOL_SOCKET, SO_DONTROUTE, (char*)&on, sizeof(on));
		if (retval != 0)
		{
			LOG_OTHER(EIPM_LOG_ARP, "SO_DONTROUTE failed, errno=%d\n", errno);
		}

		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_port = htons(1025);
		
		IPM_ipaddr2in( dst, &sa.sin_addr );
		retval = connect(sd, (struct sockaddr*)&sa, sizeof(sa));
		if (retval != 0)
		{
			LOG_OTHER(EIPM_LOG_ARP, "connect failed, errno=%d ifindex=%d ip=%s \n", 
				errno, ifindex,	IPM_ipaddr2p( dst, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)) );
		}

		(void)close(sd);

                /*
                 * Create/send ARP packet for LSN.
                 *
                 * Zero out structure and create header.
                 */
                memset( &arp, 0, ARP_PKT_SIZE );

                memcpy( arp.eth_hdr.h_source, lsn_hwaddr, ETH_ALEN );
                memset( arp.eth_hdr.h_dest, 0xff, ETH_ALEN );
                arp.eth_hdr.h_proto = htons( ETH_P_ARP );

                /*
                 * Create ARP message.  
                 */
                arp.arp.ea_hdr.ar_hrd = htons( ARPHRD_ETHER );
                arp.arp.ea_hdr.ar_pro = htons( ETH_P_IP );
                arp.arp.ea_hdr.ar_hln = ETH_ALEN;
                arp.arp.ea_hdr.ar_pln = 4;
                arp.arp.ea_hdr.ar_op = htons( arpop );

                memcpy( arp.arp.arp_sha, lsn_hwaddr, ETH_ALEN );

                IPM_ipaddr2in( src, &ipm_ipv4_buf );
                *(uint32_t *)&arp.arp.arp_spa = ipm_ipv4_buf.s_addr;

                memset( arp.arp.arp_tha, 0xFF, ETH_ALEN );

                IPM_ipaddr2in( dst, &ipm_ipv4_buf );
                *(uint32_t *)&arp.arp.arp_tpa = ipm_ipv4_buf.s_addr;

                /*
                 * Initialize sockaddr structure.
                 */
                memset( &haddr, 0, sizeof( haddr ) );
                haddr.sll_family  = AF_PACKET;
                haddr.sll_ifindex = ifindex;
                haddr.sll_hatype  = ARPHRD_ETHER;
                haddr.sll_pkttype = PACKET_OTHERHOST;
                haddr.sll_halen   = ETH_ALEN;

                retval = sendto( sockfd,
                                 &arp,
                                 ARP_PKT_SIZE,
                                 0,
                                 (struct sockaddr*)&haddr,
                                 sizeof(haddr) );
                if( retval < 0 )
                {
                        LOG_ERROR( EIPM_LOG_ARP,
                                 "Error: EIPM_sendARP - sending ARP request failed - mac =%x:%x:%x:%x:%x:%x, retval=%d\nerrno=%d, sock=%d, len=%d, size=%d\nsll.family=%d, sll.proto=%d, sll.ifindx=%d\nsll.hatype=%d, sll.halen=%d, sll.pkttype=%d, sll.addr=%X %X %X %X %X %X %X %X\n",
                                 lsn_hwaddr[0],
                                 lsn_hwaddr[1],
                                 lsn_hwaddr[2],
                                 lsn_hwaddr[3],
                                 lsn_hwaddr[4],
                                 lsn_hwaddr[5],
                                 retval,
                                 errno,
                                 sockfd,
                                 ARP_PKT_SIZE,
                                 sizeof( haddr ),
                                 haddr.sll_family,
                                 haddr.sll_protocol,
                                 haddr.sll_ifindex,
                                 haddr.sll_hatype,
                                 haddr.sll_halen,
                                 haddr.sll_pkttype,
                                 haddr.sll_addr[0],
                                 haddr.sll_addr[1],
                                 haddr.sll_addr[2],
                                 haddr.sll_addr[3],
                                 haddr.sll_addr[4],
                                 haddr.sll_addr[5],
                                 haddr.sll_addr[6],
                                 haddr.sll_addr[7] );

                        return IPM_FAILURE;
                }

		LOG_OTHER( EIPM_LOG_ARP,
                           "EIPM_sendARP - sending ARP op %d - mac = %x:%x:%x:%x:%x:%x ifindex=%d src ip=%s, dst ip=%s\n",
				arpop,				
                                lsn_hwaddr[0],
                                lsn_hwaddr[1],
                                lsn_hwaddr[2],
                                lsn_hwaddr[3],
                                lsn_hwaddr[4],
                                lsn_hwaddr[5],
				ifindex,
				(( src == NULL ) ? "null" : IPM_ipaddr2p( src, ipm_ipstr_buf, sizeof(ipm_ipstr_buf))),
				IPM_ipaddr2p( dst, ipm_ipstr_buf2, sizeof(ipm_ipstr_buf2)) );

        }
        else if( dst->addrtype == IPM_IPV6 )
        {
            if ( arpop == ND_NEIGHBOR_SOLICIT )
	    {
                struct arp6_pkt         arp6;
                struct in6_addr         ip6;
                struct sockaddr_in6     whereto;
                struct in6_pktinfo      pktinfo;
                struct msghdr           msg;
                char                    pktbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
                struct cmsghdr          *cmptr;
                struct iovec            iov[1];
                struct in6_pktinfo      *pktinfo_ptr;
		int			sd;
		int			on;
		struct sockaddr_in6	sa6;
		struct ifreq		ifr;
		
		sd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);
		if (sd < 0)
		{
			LOG_ERROR( 0, "socket failed, errno=%d\n", errno);
			return IPM_FAILURE;
		}

		ifr.ifr_ifindex = ifindex;
	
		/* Get MAC address */
		retval = ioctl(sd, SIOCGIFNAME, &ifr);
		if( retval < 0 )
		{
			LOG_OTHER(EIPM_LOG_ARP, 
				"EIPM sendARP Failure: ioctl(SIOCGIFNAME) failed for interface=%d, retval %d, errno %d",
				ifindex, retval, errno);
		}		

		retval = setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, ifr.ifr_name, strlen(ifr.ifr_name)+1);
		if (retval != 0)
		{
			LOG_OTHER(EIPM_LOG_ARP, "SO_BINDTODEVICE failed, errno=%d\n", errno);
		}
		
		on = 1;
		retval = setsockopt(sd, SOL_SOCKET, SO_DONTROUTE, (char*)&on, sizeof(on));
		if (retval != 0)
		{
			LOG_OTHER(EIPM_LOG_ARP, "SO_DONTROUTE failed, errno=%d\n", errno);
		}

		memset(&sa6, 0, sizeof(sa6));
		sa6.sin6_family = AF_INET6;
		sa6.sin6_port = htons(1025);
		
		IPM_ipaddr2in( dst, &sa6.sin6_addr );
		retval = connect(sd, (struct sockaddr*)&sa6, sizeof(sa6));
		if (retval != 0)
		{
			LOG_OTHER(EIPM_LOG_ARP, "connect failed, errno=%d ifindex=%d ip=%s \n", 
				errno, ifindex,	IPM_ipaddr2p( dst, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)) );
		}

		(void)close(sd);

                /*
                 * Create/send IPv6 "ARP" packet this is neighbor 
                 * solicitation packet.
                 *
                 * Zero out structure and create header.
                 */
                memset( &arp6, 0, sizeof(struct arp6_pkt) );

                arp6.na.nd_na_type = arpop;
                arp6.na.nd_na_code = 0;
                arp6.na.nd_na_cksum = 0;
		/*
                 * Fill in the target address
                 */
                IPM_ipaddr2in( dst, &(arp6.na.nd_na_target) );

                arp6.opt_hdr.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
                arp6.opt_hdr.nd_opt_len = (ETH_ALEN + sizeof(struct nd_opt_hdr))/8;

                memcpy( arp6.hw_addr, lsn_hwaddr, ETH_ALEN );

                memset( &whereto, 0, sizeof( whereto) );
                whereto.sin6_family = AF_INET6;
                whereto.sin6_port = 0;

                if ( arpop == ND_NEIGHBOR_ADVERT )
                {
                        inet_pton( AF_INET6, ALL_NODES_MULTICAST_ADDR, &whereto.sin6_addr );
                        arp6.na.nd_na_flags_reserved = ND_NA_FLAG_OVERRIDE;
                }

                if ( arpop == ND_NEIGHBOR_SOLICIT )
                {
                        EIPM_get_solicited_node_multicast_addr( arp6.na.nd_na_target, &whereto.sin6_addr);
                }
		
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
                if( src == NULL )
                {
                        //src is empty, let OS select one for us.
                        pktinfo_ptr->ipi6_addr = in6addr_any;
                }
                else
                {
                        IPM_ipaddr2in( src, &(pktinfo_ptr->ipi6_addr) );
                }
                pktinfo_ptr->ipi6_ifindex = ifindex;

                retval = sendmsg( sockfd, &msg, 0 );

                if( retval < 0 )
                {
                        LOG_ERROR( 0,
                                 "Error: EIPM_sendARP - sending neighbor solication request failed - LSN=%s, retval=%d\nerrno=%d, sock=%d ifindex=%d\narp ip=%s\n",
                                 lsn_hwaddr,
                                 retval,
                                 errno,
                                 sockfd,
                                 pktinfo_ptr->ipi6_ifindex,
                                 IPM_ipaddr2p(dst, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)) );

                        return IPM_SENDING_NS_FAILURE;
                }

		LOG_OTHER( EIPM_LOG_ARP,
                           "EIPM_sendARP - sending NS op %d - mac = %x:%x:%x:%x:%x:%x ifindex=%x src ip=%s, dst ip=%s\n",
				arpop,				
                                lsn_hwaddr[0],
                                lsn_hwaddr[1],
                                lsn_hwaddr[2],
                                lsn_hwaddr[3],
                                lsn_hwaddr[4],
                                lsn_hwaddr[5],
				ifindex,
				(( src == NULL ) ? "null" : IPM_ipaddr2p( src, ipm_ipstr_buf, sizeof(ipm_ipstr_buf))),
				IPM_ipaddr2p( dst, ipm_ipstr_buf2, sizeof(ipm_ipstr_buf2)) );

        }
	else
	{
		struct nd_opt_hdr *opthdr;
		unsigned char *dll;
		struct sockaddr_in6 whereto;
		struct sockaddr_ll haddr;
		struct eth_arp6_pkt arp6;
		char name_buffer[1024];    

		/*
	         * Fill in haddr structure for use in sending.
	         */
	        memset(&haddr, 0, sizeof(struct sockaddr_ll));
	        haddr.sll_family   = PF_PACKET;
	        haddr.sll_protocol = htons( IPPROTO_ICMPV6 );
		haddr.sll_ifindex = ifindex;	

		memset((char *)&arp6, 0, sizeof(arp6));

	        memset( &whereto, 0, sizeof(whereto) );
		whereto.sin6_port = htons(IPPROTO_ICMPV6);
		whereto.sin6_family = AF_INET6;

		inet_pton( AF_INET6, ALL_NODES_MULTICAST_ADDR, &whereto.sin6_addr );

		memcpy( arp6.nd.na.eth_hdr.h_source, lsn_hwaddr, ETH_ALEN );

		arp6.nd.na.eth_hdr.h_dest[0] = 0x33;
		arp6.nd.na.eth_hdr.h_dest[1] = 0x33;
		arp6.nd.na.eth_hdr.h_dest[2] = 0x00;
		arp6.nd.na.eth_hdr.h_dest[3] = 0x00;
		arp6.nd.na.eth_hdr.h_dest[4] = 0x00;
		arp6.nd.na.eth_hdr.h_dest[5] = 0x01;
		arp6.nd.na.eth_hdr.h_proto = htons( ETH_P_IPV6 );

		arp6.nd.na.ipv6_hdr.ip6_flow = 0;
		arp6.nd.na.ipv6_hdr.ip6_vfc = 0x60;
		arp6.nd.na.ipv6_hdr.ip6_plen  = htons(0x20);
		arp6.nd.na.ipv6_hdr.ip6_nxt  = 0x3a;
		arp6.nd.na.ipv6_hdr.ip6_hlim  = 0xff;
	        IPM_ipaddr2in( src, &(arp6.nd.na.ipv6_hdr.ip6_src) );
		memcpy(&(arp6.nd.na.ipv6_hdr.ip6_dst), &(whereto.sin6_addr), sizeof(arp6.nd.na.ipv6_hdr.ip6_dst));

		arp6.nd.na.na.nd_na_type = ND_NEIGHBOR_ADVERT;
		arp6.nd.na.na.nd_na_code = 0;

		arp6.nd.na.na.nd_na_flags_reserved = ND_NA_FLAG_OVERRIDE;
	        IPM_ipaddr2in( dst, &(arp6.nd.na.na.nd_na_target) );
	
		opthdr = (struct nd_opt_hdr *)&arp6.nd.na.opt_hdr;
		opthdr->nd_opt_type = ND_OPT_TARGET_LINKADDR;
		opthdr->nd_opt_len = (ETH_ALEN + sizeof(struct nd_opt_hdr))/8;
		
		dll = arp6.nd.na.dll;
		memcpy( dll, lsn_hwaddr, ETH_ALEN );

		arp6.nd.na.na.nd_na_cksum = 0;

		arp6.nd.na.na.nd_na_cksum = ipv6cksm( &arp6.nd.na.ipv6_hdr.ip6_src, 
						      (sizeof(struct nd_neighbor_advert)+40), 
						      arp6.nd.na.ipv6_hdr.ip6_nxt, 
						      (sizeof(struct nd_neighbor_advert)+8) );

	 	retval = sendto( sockfd,
				 (char *)&(arp6.nd.na), 
				 sizeof(arp6.nd.na), 
				 0,
				 (struct sockaddr *) &haddr, 
				 sizeof(haddr) );

	        if( retval < 0 )
	        {
			LOG_ERROR( 0,
	                           "Error: EIPM_sendARP - sending ND op %d request failed - retval=%d\nerrno=%d, sock=%d ifindex=%d\narp ip=%s\n",
				   arpop,
	                           retval,
	                           errno,
	                           sockfd,
	                           ifindex,
	                           IPM_ipaddr2p(dst, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)) );

	                    return IPM_FAILURE;
		}

		LOG_OTHER( EIPM_LOG_ARP,
	                   "EIPM_sendARP - sending ND op %d - mac = %x:%x:%x:%x:%x:%x ifindex=%x src ip=%s, dst ip=%s\n",
			    arpop,				
	                    lsn_hwaddr[0],
	                    lsn_hwaddr[1],
	                    lsn_hwaddr[2],
	                    lsn_hwaddr[3],
	                    lsn_hwaddr[4],
	                    lsn_hwaddr[5],
			    ifindex,
			    (( src == NULL ) ? "null" : IPM_ipaddr2p( src, ipm_ipstr_buf, sizeof(ipm_ipstr_buf))),
			    IPM_ipaddr2p( dst, ipm_ipstr_buf2, sizeof(ipm_ipstr_buf2)) );

	    }
	}

        return IPM_SUCCESS;

}

/**********************************************************************
 *
 * Name:        EIPM_proxy_path()
 *
 * Abstract:    Called to send ARP packets to proxy/path
 *
 * Parameters:  intfDataP - pointer of EIPM_INTF
 *              intfType - Interface type.
 *
 * Returns:     void
 *
 **********************************************************************/
void EIPM_proxy_path( void *intfDataP, EIPM_INTF_TYPE intfType )
{
	EIPM_INTF       *data_ptr;
        EIPM_INTF_SPEC  *intfSpecDataP;
	EIPM_SUBNET *subnet_ptr;
	int subnet_idx;
        int i;

	return;
	
	if ( NULL == intfDataP )
        {
                ASRT_RPT( ASRTBADPARAM, 0, "EIPM_proxy_path: NULL input pointer.\n" );
                return;
        }

	EIPM_SET_INTF_PTRS( intfDataP, intfType, data_ptr, intfSpecDataP );

	if ( NULL == data_ptr )
        {
                return;
        }

	// Look through all subnets
	for( subnet_idx = 0, subnet_ptr = &data_ptr->subnet[0];
	     subnet_idx < data_ptr->subnet_cnt;
	     subnet_idx++, subnet_ptr++ )
	{
		EIPM_IPDATA *ip_ptr;
		int ip_idx;


		// Look through all IPs
		for( ip_idx = 0, ip_ptr = &subnet_ptr->ips[0];
		     ip_idx < subnet_ptr->ip_cnt;
		     ip_idx++, ip_ptr++ )
		{
			if( ip_ptr->type != EIPM_IP_PROXY_CLIENT_ADDR )
			{
				continue;
			}

			if( ip_ptr->ipaddr.addrtype == IPM_IPV4 )
			{
				// Create/send ARP packet for LSN0.
				if ( intfSpecDataP->lsn0_arpsock < 0 )
				{
					intfSpecDataP->lsn0_arpsock =
						EIPM_create_arp_socket( LSN0, IPM_IPV4, intfSpecDataP->lsn0_iface_indx, ARPOP_REQUEST );
				}

				EIPM_sendARP(intfSpecDataP->lsn0_arpsock,
					     data_ptr->lsn0_hwaddr,
					     &(ip_ptr->ipaddr),
					     &(ip_ptr->ipaddr),
					     intfSpecDataP->lsn0_iface_indx,
					     ARPOP_REQUEST);

				// Create/send ARP packet for LSN1.
				if ( intfSpecDataP->lsn1_arpsock < 0 )
				{
					intfSpecDataP->lsn1_arpsock =
						EIPM_create_arp_socket( LSN1, IPM_IPV4, intfSpecDataP->lsn1_iface_indx, ARPOP_REQUEST );
				}

				EIPM_sendARP(intfSpecDataP->lsn1_arpsock,
					     data_ptr->lsn1_hwaddr,
					     &(ip_ptr->ipaddr),
					     &(ip_ptr->ipaddr),
					     intfSpecDataP->lsn1_iface_indx,
					     ARPOP_REQUEST);
			}
			else if( ip_ptr->ipaddr.addrtype == IPM_IPV6 )
			{
				// Create/send ARP packet for LSN0.
				if ( intfSpecDataP->lsn0_v6arpsock < 0 )
				{
					intfSpecDataP->lsn0_v6arpsock =
						EIPM_create_arp_socket( LSN0, IPM_IPV6, intfSpecDataP->lsn0_iface_indx, ND_NEIGHBOR_SOLICIT );
				}

				EIPM_sendARP(intfSpecDataP->lsn0_v6arpsock,
					     data_ptr->lsn0_hwaddr,
					     &(ip_ptr->ipaddr),
					     &(ip_ptr->ipaddr),
					     intfSpecDataP->lsn0_iface_indx,
					     ND_NEIGHBOR_SOLICIT);

				// Create/send ARP packet for LSN1.
				if ( intfSpecDataP->lsn1_v6arpsock < 0 )
				{
					intfSpecDataP->lsn1_v6arpsock =
						EIPM_create_arp_socket( LSN1, IPM_IPV6, intfSpecDataP->lsn1_iface_indx, ND_NEIGHBOR_SOLICIT );
				}

				EIPM_sendARP(intfSpecDataP->lsn1_v6arpsock,
					     data_ptr->lsn1_hwaddr,
					     &(ip_ptr->ipaddr),
					     &(ip_ptr->ipaddr),
					     intfSpecDataP->lsn1_iface_indx,
					     ND_NEIGHBOR_SOLICIT);
			}

		} // Look through all IPs

	} // Look through all subnets





        return;
}

/*
 *  Function: EIPM_getSrcIPAddrForARP.
 *  Input   : intfSpecDataP - Pointer to interface specific data.
 *          : subnetDataP - Pointer to subnet data.
 *  Output  : Returns an IP to be used in the source field of ARP request.
 *  Desc.   : Deterimes the IP to be used in source field of ARP request.
 */
IPM_IPADDR *EIPM_getSrcIPAddrForARP( EIPM_INTF_SPEC *intfSpecDataP, EIPM_SUBNET *subnetDataP )
{

	EIPM_INTF               *baseIntfDataP = NULL;
        int                     ipIdx;
        EIPM_IPDATA             *ipDataP;

	if ( 0 == subnetDataP->ip_cnt )
	{
		return NULL;
	}

	if ( EIPM_IS_VALID_BASE_INTF_IDX( intfSpecDataP->baseIntfIdx ) )
        {
                baseIntfDataP = &(((EIPM_DATA *)EIPM_shm_ptr)->intf_data[intfSpecDataP->baseIntfIdx]);
        }

	if (    (    ( baseIntfDataP != NULL )
                  && ( -1 == baseIntfDataP->extnIntfIdx ) 
		  && ( -1 == EIPM_GET_PROXY_SERVER_ENABLED() ) )
             || ( EIPM_IP_PROXY_SERVER == subnetDataP->ips[0].type ) )
        {
                /* Return the IP at index 0. */
                return &(subnetDataP->ips[0].ipaddr);
        }

	if ( 1 == subnetDataP->ip_cnt )
	{
		return NULL;
	}

        /*
         *  With speedup, IPs are provisioned on the standby side as well.
         *  The proxyserver IP on the base interface is only provisioned when
         *  the standby side goes active. Hence, check the last entry to see
         *  if it is of type proxyserver.
         */
        if ( EIPM_IP_PROXY_SERVER == subnetDataP->ips[( subnetDataP->ip_cnt - 1 )].type )
        {
                /* Return the last IP. */
                return &(subnetDataP->ips[( subnetDataP->ip_cnt - 1 )].ipaddr);
        }

        for ( ( ipIdx = 1, ipDataP = &(subnetDataP->ips[1]) );
              ( ipIdx < ( subnetDataP->ip_cnt - 1 ) );
              ( ipIdx++, ipDataP++ ) )
        {

                /* Search for IP of type 'proxy server' and matching interface. */
                if ( ipDataP->type != EIPM_IP_PROXY_SERVER )
                {
                        continue;
                }

                return &(ipDataP->ipaddr);

        } /* End 'subnet IPs loop' */

        return NULL;

} /* End 'EIPM_getSrcIPAddrForARP' */

/*
 *  Function: neigh_ping6.
 *  Desc.   : Issue a ping6 to subnet gateway on the routing interface.
 */
void neigh_ping6(EIPM_INTF *data_ptr, EIPM_SUBNET *subnet_ptr, uint16_t vlanId)
{
	char gateway_buf[ IPM_IPMAXSTRSIZE ];
	char ping_cmd[256];
	IPM_chkipaddr2p(&subnet_ptr->gateway, gateway_buf, sizeof (gateway_buf));
	int is_run_ping = 0;

	if (subnet_ptr->gateway.addrtype == IPM_IPV6)
	{
		if (subnet_ptr->sub2intf_mapping[vlanId].route_priority == LSN0)
		{
			sprintf(ping_cmd, "/usr/sbin/ping6 -I %s -c 1 %s 2>&1 &", data_ptr->lsn0_baseif, gateway_buf);
			is_run_ping = 1;
		}
		else if (subnet_ptr->sub2intf_mapping[vlanId].route_priority == LSN1)
		{
			sprintf(ping_cmd, "/usr/sbin/ping6 -I %s -c 1 %s 2>&1 &", data_ptr->lsn1_baseif, gateway_buf);
			is_run_ping = 1;
		}
	}

	if (is_run_ping == 1)
	{
		if (system(ping_cmd) != 0)
		{
			LOG_OTHER(0, "neigh_ping6: Failed to run command (%s)\n", ping_cmd);
		}
	}

}

