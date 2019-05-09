/**********************************************************************
 *
 * File:
 *	PIPM_init.c
 *
 * Functions in this file:
 *	PIPM_init()                - init at process startup
 *	PIPM_startup()             - init for process restart
 *	PIPM_shutdown()            - shutdown for process inhibit
 *
 **********************************************************************/

#include "PIPM_include.h"

/*
 * Define global data.
 */
key_t			PIPM_shmkey;	/* Shared memory key */
int			PIPM_shmid;	/* Shared memory ID */
char			*PIPM_shm_ptr;	/* Pointer to shared memory */

/**********************************************************************
 *
 * Name:	PIPM_init()
 *
 * Abstract:	Init global data, message buffers, and attach
 *		to or create shared memory segment.
 *
 * Parameters:	None
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE 
 *
 **********************************************************************/

int PIPM_init( )

{
	PIPM_DATA	*data_ptr;
	PIPM_INTF	*intf_ptr;
	PIPM_INTF_SPEC  *intfSpecDataP;
	int		i;
	int		m, n;
	int		shmid;
	
	/*
 	 * Initialize Global Data
	 */
	
	/*
	 * Try to get the shared memory segment.  If it fails
	 * then this is the first time this process has been
	 * started (since a reboot), and we have to create it
	 * and wait for info on interfaces to monitor.  All other
	 * failures are fatal.
	 *
	 * We'll name our shared memory segment "PIPM".
	 */
	PIPM_shmkey  = PIPM_SHM_KEY;
	PIPM_shm_ptr = NULL;
	
	/*
	 * Try to get the shared memory segment assuming it exists.
	 */
	if( (shmid = shmget( PIPM_shmkey, PIPM_SHMSIZ, 0 ) ) < 0 )
	{
		LOG_DEBUG( 0,
		       	 "Error: PIPM_init() - Cannot open existing shared memory segment.\nWill try create, shmid=0x%x, errno=%d\n",
		         shmid, errno );
			
		/*
		 * Initial shmget() failed - try to create the segment.
		 */
		if ((shmid = shmget( PIPM_shmkey,
		                     PIPM_SHMSIZ,
		                     (IPC_CREAT | IPC_EXCL | 0644) ) ) < 0 )
		{
			/*
			 * Still failed - we are hosed.
			 */
			LOG_DEBUG( 0,
		       	 "Error: PIPM_init() - Cannot open shared memory segment\n" );
			
			/*
			 * Alarm?
			 */
			return( IPM_FAILURE);
		}

		/*
		 * It worked.  Copy shared memory ID.
		 */
		PIPM_shmid = shmid;
			
		/* 
		 * Log a message that we are starting.
		 */
		LOG_DEBUG( 0,
		       	 "PIPM - shared memory segment does not exist, assuming initial process startup\n" );
		
		/*
		 * Attach to shared memory.
		 */
		if ((PIPM_shm_ptr = shmat(PIPM_shmid, NULL, 0)) == (char *) -1) {
			LOG_ERROR( 0,
			       	 "Error: PIPM_init() - Cannot attach to shared memory segment, errno=0x%x\n",
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
		bzero( PIPM_shm_ptr, PIPM_SHMSIZ );

		data_ptr = (PIPM_DATA *)PIPM_shm_ptr;

		/*
		 * Initialize any non-zero values
		 */
                for( i = 0, intf_ptr = &data_ptr->intf_data[ 0 ];
                     i < PIPM_MAX_INTF;
                     i++, intf_ptr++ )
                {
			intf_ptr->startExtnIntfIdx = -1;
			intf_ptr->specData.lsn0_arpsock = -1;
			intf_ptr->specData.lsn1_arpsock = -1;
			intf_ptr->specData.lsn0_v6arpsock = -1;
			intf_ptr->specData.lsn1_v6arpsock = -1;
                        intf_ptr->specData.baseIntfIdx = i;
			for (m=0; m<PIPM_MAX_SUBNETS; m++)
			{
				for (n=0; n<PIPM_MAX_PATH; n++)
				{
					intf_ptr->subnet[m].path[n].lsn0_arpsock = -1;
					intf_ptr->subnet[m].path[n].lsn1_arpsock = -1;
				}
			}
                }

		for ( ( i = 0, intfSpecDataP = &(data_ptr->extnIntfData[0]) );
                      ( i < PIPM_MAX_EXTN_INTF );
                      ( i++, intfSpecDataP++ ) )
                {
			intfSpecDataP->lsn0_arpsock = -1;
			intfSpecDataP->lsn1_arpsock = -1;
			intfSpecDataP->lsn0_v6arpsock = -1;
			intfSpecDataP->lsn1_v6arpsock = -1;
                        intfSpecDataP->baseIntfIdx = -1;
                }
		
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
		PIPM_shmid = shmid;
			
		/*
		 * Process restart - re-attach to shared
		 * memory and continue on.
		 */
		if( (PIPM_shm_ptr = shmat(PIPM_shmid, NULL, 0)) == (char *) -1)
		{
			LOG_ERROR( 0,
		       	 "Error: PIPM_init() - Cannot attach to shared memory segment, errno=0x%x\n",
			         errno );
			return( IPM_FAILURE);
		}

		data_ptr = (PIPM_DATA *)PIPM_shm_ptr;
		
		/*
		 * Initialize any non-zero values
		 */
                for( i = 0, intf_ptr = &data_ptr->intf_data[ 0 ];
                     i < PIPM_MAX_INTF;
                     i++, intf_ptr++ )
                {
			intf_ptr->startExtnIntfIdx = -1;
			intf_ptr->specData.lsn0_arpsock = -1;
			intf_ptr->specData.lsn1_arpsock = -1;
			intf_ptr->specData.lsn0_v6arpsock = -1;
			intf_ptr->specData.lsn1_v6arpsock = -1;
                        intf_ptr->specData.baseIntfIdx = i;
			for (m=0; m<PIPM_MAX_SUBNETS; m++)
			{
				for (n=0; n<PIPM_MAX_PATH; n++)
				{
					intf_ptr->subnet[m].path[n].lsn0_arpsock = -1;
					intf_ptr->subnet[m].path[n].lsn1_arpsock = -1;
				}
			}
                }

		for ( ( i = 0, intfSpecDataP = &(data_ptr->extnIntfData[0]) );
                      ( i < PIPM_MAX_EXTN_INTF );
                      ( i++, intfSpecDataP++ ) )
                {
			intfSpecDataP->lsn0_arpsock = -1;
			intfSpecDataP->lsn1_arpsock = -1;
			intfSpecDataP->lsn0_v6arpsock = -1;
			intfSpecDataP->lsn1_v6arpsock = -1;
                }
		data_ptr->startBaseIntfIdx = 0;
		
		/*
		 * Call function to log the data we have.  The only
		 * failure from PIPM_dumpshm() is that PIPM_shm_ptr
		 * is not set, and we just set it.
		 */
		(void)PIPM_dumpshm();
		
		/*
		 * Things that need to cleaned up since we are
		 * restarting (re-creating sockets, for example)
		 * are covered in PIPM_startup().
		 */
		
		return( IPM_SUCCESS );
		
	}
	
	return( IPM_SUCCESS );
}
	


/**********************************************************************
 *
 * Name:	PIPM_startup()
 *
 * Abstract:	Called on process restart (when we know interfaces
 *		we are monitoring) to set sockets back up
 *
 * Parameters:	None
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE  
 *
 **********************************************************************/

int PIPM_startup( )

{
	register PIPM_INTF	*data_ptr;
	int			i;
	
	/*
	 * Only start up if PIPM is enabled.
	 */
	if( pipm_enable == FALSE )
	{
		return( IPM_SUCCESS );
	}

	/*
	 * Make sure we are attached to shared memory segment.
	 */
	if( PIPM_shm_ptr == NULL )
	{
		LOG_ERROR( 0,
	       	 "Error: PIPM - shared memory segment not attached, shmid=%x\n", PIPM_shmid );
		return( IPM_FAILURE);
	}
	
	/*
	 * If data has not been initialized then there is nothing
	 * to do.
	 */
	if( ((PIPM_DATA *)PIPM_shm_ptr)->intf_cnt == 0 )
	{
		LOG_DEBUG( 0,
	       	 "PIPM - PIPM_startup() nothing to do\n" );
		return( IPM_SUCCESS );
	}
	
	return( IPM_SUCCESS );

} /* end PIPM_startup() */


/**********************************************************************
 *
 * Name:	PIPM_shutdown()
 *
 * Abstract:	Shut down PIPM functionality
 *
 * Parameters:	None
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE 
 *
 **********************************************************************/

int PIPM_shutdown( )

{
	register PIPM_INTF	*data_ptr;
	PIPM_INTF_SPEC          *intfSpecDataP;
	int			i;
	
	/*
	 * Make sure we are attached to shared memory segment.
	 */
	if( PIPM_shm_ptr == NULL )
	{
		LOG_ERROR( 0,
	       	 "Error: PIPM - shared memory segment not attached, shmid=%x\n", PIPM_shmid );
		return( IPM_FAILURE);
	}
	
	/*
	 * Shared memory segment is initialized.  Shut down any
	 * interfaces that are monitored.
	 *
	 * Loop through shared data.
	 */
	for( i = 0, data_ptr = &((PIPM_DATA *)PIPM_shm_ptr)->intf_data[ 0 ];
	     i < ((PIPM_DATA *)PIPM_shm_ptr)->intf_cnt; 
	     i++, data_ptr++ )
	{
		/*
		 * Valid data item - close all sockets.
		 */
		if ( data_ptr->specData.lsn1_arpsock >= 0 )
		{
			(void)close( data_ptr->specData.lsn1_arpsock );
			data_ptr->specData.lsn1_arpsock = -1;
		}

		if ( data_ptr->specData.lsn0_arpsock >= 0 )
		{
			(void)close( data_ptr->specData.lsn0_arpsock );
			data_ptr->specData.lsn0_arpsock = -1;
		}

		if ( data_ptr->specData.lsn1_v6arpsock >= 0 )
		{
			(void)close( data_ptr->specData.lsn1_v6arpsock );
			data_ptr->specData.lsn1_v6arpsock = -1;
		}

		if ( data_ptr->specData.lsn0_v6arpsock >= 0 )
		{
			(void)close( data_ptr->specData.lsn0_v6arpsock );
			data_ptr->specData.lsn0_v6arpsock = -1;
		}
	}

	for ( ( i = 0, intfSpecDataP = &(((PIPM_DATA *)PIPM_shm_ptr)->extnIntfData[0]) ); 
              ( i < ((PIPM_DATA *)PIPM_shm_ptr)->extnIntfCount );
              ( i++, intfSpecDataP++ ) )
        {
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
        }
	
	return( IPM_SUCCESS );

} /* end PIPM_shutdown() */

