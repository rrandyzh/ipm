/**********************************************************************
 *
 * File:
 *	EIPM_init.c
 *
 * Functions in this file:
 *	EIPM_init()                - init at process startup
 *      EIPM_intfStartup           - Init of specific interface on process restart.
 *	EIPM_startup()             - init for process restart
 *	EIPM_shutdown()            - shutdown for process inhibit
 *	EIPM_create_intf_sockets() - Create RAW sockets for ping-pong
 *
 **********************************************************************/

	
#include "EIPM_include.h"
#include "EIPM_bfd.h"
	

/*
 * Define global data.
 */
int			EIPM_tick_cnt;  /* Entry counter */
key_t			EIPM_shmkey;	/* Shared memory key */
int			EIPM_shmid;	/* Shared memory ID */
char			*EIPM_shm_ptr;	/* Pointer to shared memory */
struct eipm_packet	EIPM_pkt;

/**********************************************************************
 *
 * Name:	EIPM_init()
 *
 * Abstract:	Init global data, message buffers, and attach
 *		to or create shared memory segment.
 *
 * Parameters:	None
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE 
 *
 **********************************************************************/

int EIPM_init( )

{
	register EIPM_DATA	*data_ptr;
	register EIPM_INTF	*intf_ptr;
	register EIPM_INTF_SPEC	*intfSpecP;
	int			i;
	int			shmid;
	

	/*
 	 * Initialize Global Data
	 */
	
	/* Initialize tick counter. */
	EIPM_tick_cnt = 0;
	
	/*		
	 * Initialize the message buffer.  A large part of
	 * it will always be the same - no sense filling
	 * out that same info for several interfaces every
	 * 100 msec.
	 */
	bzero(&EIPM_pkt, sizeof( EIPM_pkt ));
	
	
	/*
	 * Try to get the shared memory segment.  If it fails
	 * then this is the first time this process has been
	 * started (since a reboot), and we have to create it
	 * and wait for info on interfaces to monitor.  All other
	 * failures are fatal.
	 *
	 * We'll name our shared memory segment "EIPM".
	 */
	EIPM_shmkey  = EIPM_SHM_KEY;
	EIPM_shm_ptr = NULL;
	
	/*
	 * Try to get the shared memory segment assuming it exists.
	 */
	if( (shmid = shmget( EIPM_shmkey, EIPM_SHMSIZ, 0 ) ) < 0 )
	{
		LOG_DEBUG( 0,
		       	 "Error: EIPM_init() - Cannot open existing shared memory segment.\nWill try create, shmid=0x%x, errno=%d\n",
		         shmid, errno );
			
		/*
		 * Initial shmget() failed - try to create the segment.
		 */
		if ((shmid = shmget( EIPM_shmkey,
		                     EIPM_SHMSIZ,
		                     (IPC_CREAT | IPC_EXCL | 0644) ) ) < 0 )
		{
			/*
			 * Still failed - we are hosed.
			 */
			LOG_ERROR( 0,
		       	 "Error: EIPM_init() - Cannot open shared memory segment\n" );
			
			/*
			 * Alarm?
			 */
			return( IPM_FAILURE);
		}

		/*
		 * It worked.  Copy shared memory ID.
		 */
		EIPM_shmid = shmid;
			
		/* 
		 * Log a message that we are starting.
		 */
		LOG_DEBUG( 0,
		       	 "EIPM - shared memory segment does not exist, assuming initial process startup\n" );
		
		/*
		 * Attach to shared memory.
		 */
		if ((EIPM_shm_ptr = shmat(EIPM_shmid, NULL, 0)) == (char *) -1) {
			LOG_ERROR( 0,
			       	 "Error: EIPM_init() - Cannot attach to shared memory segment, errno=0x%x\n",
			         errno );
			/*
			 * Alarm?
			 */
			return( IPM_FAILURE);
		}
		
		/*
		 * Man page says shared memory is zeroed, but does
		 * not seem to be...
		 */
		bzero( EIPM_shm_ptr, EIPM_SHMSIZ );

		data_ptr = (EIPM_DATA *)EIPM_shm_ptr;

		data_ptr->soak_timer = DFT_SOAK_TIME;

		/*
		 * Initialize any non-zero values
		 */
                for( i = 0, intf_ptr = &data_ptr->intf_data[ 0 ];
                     i < EIPM_MAX_EXT_SUB;
                     i++, intf_ptr++ )
                {

			intf_ptr->extnIntfIdx = -1;
			intf_ptr->specData.baseIntfIdx = i;
			EIPM_INIT_INTF_SPEC_NZ_DATA( &(intf_ptr->specData), i, intf_ptr );
			EIPM_SET_REPORT_STATUS_TIMER( &(intf_ptr->specData), EIPM_REPORT_STATUS_INTERVAL );
			EIPM_init_pivot_sock(intf_ptr);
                }

		EIPM_SET_PROXY_SERVER_ENABLED( -1 );


		/* Initialize the data for the extension/child interfaces. */
                for ( ( i = 0, intfSpecP = &(data_ptr->extnIntfData[0]) ); 
                      ( i < EIPM_MAX_EXTN_INTF ); 
                      ( i++, intfSpecP++ ) )
                {
			intfSpecP->baseIntfIdx = -1;
                        EIPM_INIT_INTF_SPEC_NZ_DATA_EXTN( intfSpecP, -1 );
	                EIPM_SET_REPORT_STATUS_TIMER( intfSpecP, EIPM_REPORT_STATUS_INTERVAL );
                }
		
		/* Got new shared memory so init all of it for BFD. */
		(void)EIPM_bfd_fsm_start();

		/*
		 * We are done until we get a message to do something.
		 */
		return( IPM_SUCCESS );

	}
	else
	{
		/*
		 * shmget() worked - that indicates the shared
		 * memory segment already existed.
		 *
		 * Copy shared memory ID.
		 */
		EIPM_shmid = shmid;
			
		/*
		 * Process restart - re-attach to shared
		 * memory and continue on.
		 */
		if( (EIPM_shm_ptr = shmat(EIPM_shmid, NULL, 0)) == (char *) -1)
		{
			LOG_ERROR( 0,
		       	 "Error: EIPM_init() - Cannot attach to shared memory segment, errno=0x%x\n",
			         errno );
			/*
			 * Alarm?
			 */
			return( IPM_FAILURE);
		}

                data_ptr = (EIPM_DATA *)EIPM_shm_ptr;

                /*
                 * Initialize any non-zero values
                 */

		data_ptr->last_rpt_status = EIPM_STAT_NULL;
		data_ptr->last_rpt_time = 0;

                for( i = 0, intf_ptr = &data_ptr->intf_data[ 0 ];
                     i < EIPM_MAX_EXT_SUB;
                     i++, intf_ptr++ )
                {
			intf_ptr->specData.baseIntfIdx = i;
			intf_ptr->specData.recovery_state = NULL_REC_STATE;
                        EIPM_INIT_INTF_SPEC_NZ_DATA( &(intf_ptr->specData), i, intf_ptr );
			EIPM_init_pivot_sock(intf_ptr);
                }

		/* Initialize the data for the extension interfaces. */
                for ( ( i = 0, intfSpecP = &(data_ptr->extnIntfData[0]) ); 
                      ( i < EIPM_MAX_EXTN_INTF ); 
                      ( i++, intfSpecP++ ) )
                {
			intfSpecP->recovery_state = NULL_REC_STATE;
                        EIPM_INIT_INTF_SPEC_NZ_DATA_EXTN( intfSpecP, -1 );
                }
		
		/*
		 * Call function to log the data we have.  The only
		 * failure from EIPM_dumpshm() is that EIPM_shm_ptr
		 * is not set, and we just set it.
		 */
		(void)EIPM_dumpshm();
		
		/* Reusing shared memory from before so init some
		 * but not all of it for BFD.
		 */
		(void)EIPM_bfd_fsm_restart();

		/*
		 * Things that need to cleaned up since we are
		 * restarting (re-creating sockets, for example)
		 * are covered in EIPM_startup().
		 */
		
		return( IPM_SUCCESS );
		
	}
	
	return( IPM_SUCCESS );
}
	
/**********************************************************************
 *
 * Name:	EIPM_intfStartup
 *
 * Abstract:
 *     Called on process restart to setup sockets for the specified interface.
 *
 * Parameters:
 *     intfDataP - Points to base/extension interface.
 *                 Type: EIPM_INTF/EIPM_INTF_SPEC 
 *     intfType - Identifies the interface as base/extension.
 *     intfDataIdx - The index into the base/extension interface data.
 *
 * Returns:
 *     IPM_SUCCESS or IPM_FAILURE  
 *
 **********************************************************************/

int EIPM_intfStartup( register void *intfDataP, EIPM_INTF_TYPE intfType, int intfDataIdx )
{
        register EIPM_INTF              *data_ptr;
        register EIPM_INTF_SPEC         *intfSpecDataP;
	int			        subn;
	int			        retval;
#ifdef USINGSELECT
	int			        desc;
#endif

        EIPM_SET_INTF_PTRS( intfDataP, intfType, data_ptr, intfSpecDataP );

        if ( NULL == data_ptr )
        {
		return IPM_FAILURE;
        }

	/*
	 *  Create the interface sockets.
	 */
	retval = EIPM_create_intf_sockets( intfDataP, intfType );
		
	if ( retval != IPM_SUCCESS )
	{
		LOG_ERROR( 0,
		           "Error: EIPM - creating sockets for index=%d interface=%s%s/%s%s type=%u failed, retval=%d\n",
			   intfDataIdx,
			   data_ptr->lsn0_baseif,
                           ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
			   data_ptr->lsn1_baseif,
                           ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
			   intfType,
			   retval );
			
		return IPM_FAILURE;
	} 

	intfSpecDataP->seqno = 0;
	intfSpecDataP->lsn0_rcv_seqno = 0;
	intfSpecDataP->lsn1_rcv_seqno = 0;
	intfSpecDataP->lsn0_corrupt_packet_count = 0;
	intfSpecDataP->lsn1_corrupt_packet_count = 0;
	intfSpecDataP->lsn0_sequence_error_count = 0;
	intfSpecDataP->lsn1_sequence_error_count = 0;

	/* Trigger IP/Route check.  */
	EIPM_CHECK_INTF_CONFIG( intfSpecDataP );
		
	/*
	 * If this interface is in the action state
	 * re-create the ARP sockets.
	 */
	if ( intfSpecDataP->state == ACTION_STATE )
	{

		/*
		 * If recovery was in progress then we
		 * were stable.  Otherwise we don't really
		 * know what we were doing so start
		 * over.
		 */
		if ( intfSpecDataP->recovery_state != REC_IN_PROG )
		{
			/*
			 * Since we don't know where we were
			 * re-initialize data and start over
			 * sending ARPs.  We have to loop 
			 * through all the subnets that
			 * are assigned to this interface.
			 */
			for ( subn = 0;
			      subn < data_ptr->subnet_cnt;
			      subn++ )
			{					
				data_ptr->subnet[subn].arpdata.cur_index = 0;
			}
				
			/*
			 *  Set to ARP_START state so we start
			 *  sending ARPs.
			 */
			intfSpecDataP->recovery_state = ARP_START;
		}
			
	} /* end 'if state == ACTION_STATE' */
		
#ifdef USINGSELECT
	/*
	 * Update the list of monitored descriptors
	 * (for select).  Have to find the first opening
	 * in the list.
	 */
	for ( desc = 0; desc < IPM_MAX_DESCR; ++desc )
	{
		if ( IPM_skt_desc[desc].valid != TRUE )
		{
			/*
			 * Found an empty one.
			 */
			break;
		}
	}
		
	if ( desc == IPM_MAX_DESCR )
	{
		/*
		 * No empty entries!!!
		 */
		LOG_ERROR( 0,
		       	   "Error: EIPM - no empty slots in socket descriptor list, desc=%d\n",
			   desc );
		return IPM_FAILURE;	
	}
		
	/*
	 *  Here we have an empty slot
	 */
	IPM_skt_desc[ desc ].valid = TRUE;
	IPM_skt_desc[ desc ].desc  = intfSpecDataP->lsn0_socket;
	IPM_skt_desc[ desc ].index = i;
		
	/*
	 *  Next slot should be empty too - make sure.
	 */
	++desc;
	if (    ( desc == IPM_MAX_DESCR )
	     || ( IPM_skt_desc[desc].valid != FALSE ) )
	{
		/*
		 *  List is corrupted or full!!!
		 */
		LOG_ERROR( 0,
			   "Error: EIPM - corrupted or full socket descriptor list, desc=%d\n",
			   desc );
		return IPM_FAILURE;			
	}
		
	/*
	 *  Second slot is empty.
	 */
	IPM_skt_desc[ desc ].valid = TRUE;
	IPM_skt_desc[ desc ].desc  = intfSpecDataP->lsn1_socket;
	IPM_skt_desc[ desc ].index = i;
#endif /* #ifdef USINGSELECT */

        return IPM_SUCCESS;

} /* end EIPM_intfStartup */


/**********************************************************************
 *
 * Name:	EIPM_startup()
 *
 * Abstract:	Called on process restart (when we know interfaces
 *		we are monitoring) to set sockets back up
 *
 * Parameters:	None
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE  
 *
 **********************************************************************/

int EIPM_startup( )

{
	register EIPM_INTF	*data_ptr;
	register EIPM_INTF_SPEC         *intfSpecDataP;
	int			i;
	int			retval;
	
	/*
	 * Only start up if EIPM is enabled.
	 */
	if( eipm_enable == FALSE )
	{
		return( IPM_SUCCESS );
	}

	/*
	 * Make sure we are attached to shared memory segment.
	 */
	if( EIPM_shm_ptr == NULL )
	{
		LOG_ERROR( 0,
	       	 "Error: EIPM - shared memory segment not attached, shmid=%x\n", EIPM_shmid );
		return( IPM_FAILURE);
	}
	
	/*
	 * If data has not been initialized then there is nothing
	 * to do.
	 */
	if( ((EIPM_DATA *)EIPM_shm_ptr)->intf_cnt == 0 )
	{
		LOG_DEBUG( 0,
	       	 "EIPM - EIPM_startup() nothing to do\n" );
		return( IPM_SUCCESS );
	}
	
	/*
	 * Shared memory segment is initialized.  Start up any
	 * interfaces that need to be monitored.
	 *
	 * Loop through shared data.
	 */
	for( i = 0, data_ptr = &((EIPM_DATA *)EIPM_shm_ptr)->intf_data[ 0 ];
	     i < ((EIPM_DATA *)EIPM_shm_ptr)->intf_cnt; 
	     i++, data_ptr++ )
	{
		retval = EIPM_intfStartup( data_ptr, EIPM_BASE_INTF, i );

		if ( retval != IPM_SUCCESS )
                {
                        return retval;
                }
	}

	/* Startup the extension/child interfaces also. */
	for ( ( i = 0, intfSpecDataP = &(((EIPM_DATA *)EIPM_shm_ptr)->extnIntfData[0]) );
              ( i < ((EIPM_DATA *)EIPM_shm_ptr)->extnIntfCount );
              ( i++, intfSpecDataP++ ) )
        {
                retval = EIPM_intfStartup( intfSpecDataP, EIPM_EXTN_INTF, i );

                if ( retval != IPM_SUCCESS )
                {
                        return retval;
                }
        }
	
	return( IPM_SUCCESS );

} /* end EIPM_startup() */




/**********************************************************************
 *
 * Name:	EIPM_shutdown()
 *
 * Abstract:	Shut down EIPM functionality
 *
 * Parameters:	None
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE 
 *
 **********************************************************************/

int EIPM_shutdown( )

{
	register EIPM_INTF	*data_ptr;
	register EIPM_INTF_SPEC	*intfSpecDataP;
	int			i;
	
	/*
	 * Make sure we are attached to shared memory segment.
	 */
	if( EIPM_shm_ptr == NULL )
	{
		LOG_ERROR( 0,
	       	 "Error: EIPM - shared memory segment not attached, shmid=%x\n", EIPM_shmid );
		return( IPM_FAILURE);
	}
	
	/*
	 * Shared memory segment is initialized.  Shut down any
	 * interfaces that are monitored.
	 *
	 * Loop through shared data.
	 */
	for( i = 0, data_ptr = &((EIPM_DATA *)EIPM_shm_ptr)->intf_data[ 0 ];
	     i < ((EIPM_DATA *)EIPM_shm_ptr)->intf_cnt; 
	     i++, data_ptr++ )
	{
		/*
		 * Valid data item - close all sockets.
		 */
		EIPM_close_sock( &(data_ptr->specData) );
	}

	for ( ( i = 0, intfSpecDataP = &(((EIPM_DATA *)EIPM_shm_ptr)->extnIntfData[0]) );
	      ( i < ((EIPM_DATA *)EIPM_shm_ptr)->extnIntfCount ); 
	      ( i++, intfSpecDataP++ ) )
	{
		/*
		 *  Valid data item - close all sockets.
		 */
		EIPM_close_sock( intfSpecDataP );
	}
	
	return( IPM_SUCCESS );

} /* end EIPM_shutdown() */




/**********************************************************************
 *
 * Name:	EIPM_create_intf_sockets()
 *
 * Abstract:	Creates RAW sockets for sending ping-pong
 *		packets back and forth between the 2 interfaces
 *		used for the external subnet.
 *
 * Parameters:	intfDataP - Pointer to base/extension interface's data.
 *                          Type: EIPM_INTF/EIPM_INTF_SPEC
 *              intfType - Interface type.
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE 
 *
 **********************************************************************/

int EIPM_create_intf_sockets( register void *intfDataP, EIPM_INTF_TYPE intfType )
{
	register EIPM_INTF      *data_ptr;
        register EIPM_INTF_SPEC *intfSpecDataP;
	struct sockaddr_in	sin;
	struct ifreq		ifr;
	int			sock;
	int			sock_lsn0, sock_lsn1;
	int			retval;
	int			optval;
	int			i;
	
	/*
	 * Only open sockets if EIPM is enabled.
	 */
	if( eipm_enable == FALSE )
	{
		return( IPM_SUCCESS );
	}

	EIPM_SET_INTF_PTRS( intfDataP, intfType, data_ptr, intfSpecDataP );

	if ( NULL == data_ptr )
        {
                return IPM_FAILURE;
        }

	/*
 	 * Only create interface sockets for a redundancy mode of ACM.
	 */
	for (i = 0; i < data_ptr->subnet_cnt; i++)
	{
		if (data_ptr->subnet[i].redundancy_mode != IPM_RED_EIPM_ACM)
		{
			return IPM_SUCCESS;
		}
	}

	/*
	 * Debug.  Use the 0 interface entry (that is what we are
	 * running off of).
	 */
	LOG_DEBUG( 0,
	       	  "EIPM_create_intf_sockets - interface=%s%s/%s%s\n",
	          data_ptr->lsn0_baseif,
                  ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
	          data_ptr->lsn1_baseif,
                  ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

	intfSpecDataP->lsn0_socket = -1;
	intfSpecDataP->lsn1_socket = -1;

	/*
	 * Open an IP socket for querying interface information.
	 */
	sock = socket( PF_INET, SOCK_RAW, htons(ETH_P_IP) );
	if( sock < 0 )
	{
		LOG_ERROR( 0,
	                "Error: EIPM_create_intf_sockets() - Cannot open socket, errno=0x%x\n",
		         errno );
		
		return( IPM_FAILURE);
	}
	
	/*
	 * Get interface index for LSN0 interface.  We have
	 * to get these again on the off chance someone added
	 * a new interface script and did a network restart.
	 * Someone should catch this and tell us, but...
	 * It doesn't matter if we use the base interface or
	 * one of the aliases - it is the same index.
	 */
	memset( &ifr, 0, sizeof(ifr) );
	ifr.ifr_addr.sa_family = PF_INET;
	snprintf( ifr.ifr_name, sizeof( ifr.ifr_name ), "%s%s", 
                  data_ptr->lsn0_baseif, ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

	retval = ioctl( sock, SIOCGIFINDEX, &ifr );
	if( retval < 0 )
	{
		LOG_ERROR( 0,
		        "Error: EIPM_create_intf_sockets() - SIOCGIFINDEX ioctl failed, retval=%d, errno=0x%x\n",
		         retval, errno );
		
		close( sock );

		return( IPM_FAILURE);
        }
	intfSpecDataP->lsn0_iface_indx = ifr.ifr_ifindex;
	
	/*
	 * Get interface index for LSN1 interface.
	 */
	snprintf( ifr.ifr_name, sizeof( ifr.ifr_name ), "%s%s", 
                  data_ptr->lsn1_baseif, ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

	retval = ioctl( sock, SIOCGIFINDEX, &ifr );
	if( retval < 0 )
	{
		LOG_ERROR( 0,
		        "Error: EIPM_create_intf_sockets() - SIOCGIFINDEX ioctl failed, retval=%d, errno=0x%x\n",
		         retval, errno );
		
		close( sock );

		return( IPM_FAILURE);
        }
	intfSpecDataP->lsn1_iface_indx = ifr.ifr_ifindex;
	
	/*
	 * We are done with the socket used to query.
	 */
	close( sock );
	
	/*
	 * Open raw packet socket for LSN0 interface.  To be
	 * able to specify the Ethernet header we have to open
	 * a raw socket.
	 */
	sock_lsn0 = socket(PF_PACKET, SOCK_RAW, htons(eipm_proid));

	if( sock_lsn0 < 0 )
	{
		LOG_ERROR( 0,
	       	 "Error: EIPM - LSN0 socket create for %s failed, ret=%x, errno=0x%x\n",
		 data_ptr->lsn0_baseif, sock_lsn0, errno );

		return( IPM_FAILURE);
 	}
	
	/*
	 * Open a socket for LSN1 interface.
	 */
	sock_lsn1 = socket(PF_PACKET, SOCK_RAW, htons(eipm_proid));

	if( sock_lsn1 < 0 )
	{
		LOG_ERROR( 0,
	       	 "Error: EIPM - LSN1 socket create for %s failed, ret=%x, errno=0x%x\n",
		 data_ptr->lsn1_baseif, sock_lsn1, errno );

		close( sock_lsn0 );

		return( IPM_FAILURE);
 	}
	
	/*
	 * Bind LSN0 socket to the Ethernet device
	 */
	memset( &(intfSpecDataP->lsn0_sll), 0, sizeof( struct sockaddr_ll ) );
	intfSpecDataP->lsn0_sll.sll_family   = PF_PACKET;
	intfSpecDataP->lsn0_sll.sll_protocol = htons( eipm_proid );
	intfSpecDataP->lsn0_sll.sll_ifindex  = intfSpecDataP->lsn0_iface_indx;
	
	retval = bind( sock_lsn0,
	               (struct sockaddr *)&intfSpecDataP->lsn0_sll,
	               sizeof( struct sockaddr_ll ) );
	
	if( retval < 0 )
	{
		LOG_ERROR( 0,
	       	 "Error: EIPM - LSN0 socket bind to %s failed, ret=%x, errno=0x%x\n",
		 data_ptr->lsn0_baseif, sock_lsn0, errno );

		close( sock_lsn0 );
		close( sock_lsn1 );

		return( IPM_FAILURE);
	}
	
	/*
	 * Fill in remaining fields of sockaddr_ll.  These are
	 * not required for binding.  According to the man page
	 * sll_hatype only has a value from if_arp.h, so assume
	 * it is only needed for ARP packets.
	 */
	intfSpecDataP->lsn0_sll.sll_pkttype = PACKET_OTHERHOST;
	intfSpecDataP->lsn0_sll.sll_halen   = ETH_ALEN;
	
	/*
	 * Bind LSN1 socket to the Ethernet device
	 */
	memset( &(intfSpecDataP->lsn1_sll), 0, sizeof( struct sockaddr_ll ) );
	intfSpecDataP->lsn1_sll.sll_family   = PF_PACKET;
	intfSpecDataP->lsn1_sll.sll_protocol = htons( eipm_proid );
	intfSpecDataP->lsn1_sll.sll_ifindex  = intfSpecDataP->lsn1_iface_indx;
	
	retval = bind( sock_lsn1,
	               (struct sockaddr *)&intfSpecDataP->lsn1_sll,
	               sizeof( struct sockaddr_ll ) );

	if( retval < 0 )
	{
		LOG_ERROR( 0,
	       	 "Error: EIPM - LSN1 socket bind to %s failed, ret=%x, errno=0x%x\n",
		 data_ptr->lsn1_baseif, sock_lsn1, errno );

		close( sock_lsn0 );
		close( sock_lsn1 );

		return( IPM_FAILURE);
        }

	/*
	 * Fill in remaining fields of sockaddr_ll.  These are
	 * not required for binding.  According to the manpage
	 * sll_hatype only has a value from if_arp.h, so assume
	 * it is only needed for ARP packets.
	 */
	intfSpecDataP->lsn1_sll.sll_pkttype = PACKET_OTHERHOST;
	intfSpecDataP->lsn1_sll.sll_halen   = ETH_ALEN;
	
	/*
 	 * Now save the socket descriptors created.
	 */
	intfSpecDataP->lsn0_socket = sock_lsn0;
	intfSpecDataP->lsn1_socket = sock_lsn1;

	LOG_DEBUG( 0,
	       	  "EIPM_create_intf_sockets - interface=%s%s/%s%s, socket %d/%d\n",
	          data_ptr->lsn0_baseif,
                  ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
	          data_ptr->lsn1_baseif,
                  ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
	          intfSpecDataP->lsn0_socket,
	          intfSpecDataP->lsn1_socket );


	return( IPM_SUCCESS );
} /* end EIPM_create_intf_sockets() */
