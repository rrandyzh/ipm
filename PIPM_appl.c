/**********************************************************************
 *
 * File:
 *	PIPM_appl.c
 *
 * Functions in this file:
 *	PIPM_timeout()		- Timer routine (called every 50 msec)
 *	PIPM_path_refresh()	- Periodic refresh of Path
 *	PIPM_path_resend()	- Resend Path
 *
 **********************************************************************/

#if defined (_X86)
#define _GNU_SOURCE
#include <netinet/in.h>
#endif

	
#include "PIPM_include.h"

/* Global variable tracking number of PIPM path operations per tick. */
int  pipm_path_ops_count = 0;

/**********************************************************************
 *
 * Name:        PIPM_update_path_mac()
 *
 * Abstract:    Called to update MAC in kernel module path array
 *
 * Parameters:  void
 *
 * Returns:     IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/
#if defined (_X86)
int PIPM_update_path_mac(void)
{
	
	register PIPM_INTF	*data_ptr;
	register PIPM_INTF_SPEC *intfSpecDataP;
	PIPM_DATA               *dataP;
	int			extnIntfIndex = -1;
	int			i;
	int			ret = IPM_FAILURE;
	void			*intfDataP = NULL;
	PIPM_SUBNET 		*subnet_ptr = NULL;
	int             	subnet_idx = 0;
	PIPM_PATH 		*path_ptr = NULL;
	int             	path_idx = 0;
	PIPM_INTF_TYPE_EXT 	intfTypeExt = PIPM_INVALID_INTF;

	if( PIPM_shm_ptr == NULL )
	{
		LOG_FORCE( 0, "Error: PIPM_update_path_mac - shared memory segment not attached, shmid=%x\n", PIPM_shmid );
		return( IPM_FAILURE );
	}
	dataP = (PIPM_DATA *)PIPM_shm_ptr;

	/*
	 * Loop all paths of all interfaces to try to get MAC address
	 * from ARP/GARP/NA message
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
				/*
				 * After introducing tunnel feature, is_arp_sent is deleted
				 * because the is_arp_sent is set per 30 seconds, it will delay GARP
				 * processing. For example, IMS will send GARP once it switches over.
				 * However, it can add condition if you want to skip some path as below
				 * 	if path_ptr->type == PIPM_XXX_PATH, then continue
				 * Notes: It also change the log level in case log flood occurred
				if ( path_ptr->is_arp_sent == 0 )
				{
					continue;
				}
				*/
				if ( path_ptr->vlanId == 0 )
				{
					intfTypeExt = PIPM_BASE_INTF;
					intfDataP = (void *)data_ptr;
				}
				else 
				{
					intfTypeExt = PIPM_EXTN_INTF;
					extnIntfIndex = PIPM_get_extension_interface(i, path_ptr->vlanId);
					if ( -1 == extnIntfIndex )
					{
						//Failed to find externtion interface
						continue;
					}
					intfDataP = (void *)&(dataP->extnIntfData[extnIntfIndex]);	
				}
				ret = PIPM_process_arp_na_per_path( path_ptr, intfDataP, subnet_ptr, intfTypeExt);
				if ( ret  == IPM_SUCCESS )
				{
					ret = PIPM_send_ipmsgpath_update(PIPM_REFRESH_PATH, 
						PIPM_NULL_PATH_INTF, path_ptr, subnet_ptr, intfDataP, intfTypeExt);
					if ( ret  != IPM_SUCCESS )
					{
						LOG_ERROR(0, "PIPM_update_path_mac: Failed to update MAC\n");
					}
					else
					{
						LOG_OTHER(0, "PIPM_update_path_mac: update MAC successfully\n");
					}
					// Set it as 0 because this path's MAC has been updated
			 		path_ptr->is_arp_sent = 0;

					//reset path MAC before sending ARP/NS
					memset(&(path_ptr->remote_mac[0][0]), 0, ETH_ALEN);
					memset(&(path_ptr->remote_mac[1][0]), 0, ETH_ALEN);
				}
				else
				{
					LOG_DEBUG(0, "PIPM_update_path_mac: PIPM_update_path_mac: return failed when calling PIPM_process_arp_na_per_path, ret=%d\n", ret);
				}
			}
		}

	}
	return IPM_SUCCESS;

}
#endif

/**********************************************************************
 *
 * Name:	PIPM_timeout()
 *
 * Abstract:	Determines what actions need to be taken on each
 *		timer tick (currently 50 msec).
 *
 * Parameters:	None
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 *
 **********************************************************************/


int PIPM_timeout( )

{
	register PIPM_INTF	*data_ptr;
	register PIPM_INTF_SPEC *intfSpecDataP;
	PIPM_DATA               *dataP;
	int			extnIntfIndex = 0;
	int			i;

	if ( FALSE == EIPM_GET_PROXY_SERVER_ENABLED() )
        {
                return IPM_SUCCESS;
        }
	
	/*
	 * Make sure we are attached to shared memory segment.
	 */
	if( PIPM_shm_ptr == NULL )
	{
		LOG_ERROR( 0,
	       	 "Error: PIPM - shared memory segment not attached, shmid=%x\n", PIPM_shmid );
		return( IPM_FAILURE );
	}

	dataP = (PIPM_DATA *)PIPM_shm_ptr;
	
	/*
	 * If data has not been initialized then there is nothing
	 * to do.
	 */
	if ( 0 == dataP->intf_cnt )
	{
		LOG_DEBUG( 0,
	       	 "PIPM - PIPM_timeout() nothing to do\n" );
		return( IPM_SUCCESS );
	}
	
	/*
	 * Shared memory segment is initialized.
	 */
	
#if defined (_X86)
        /*
         * Since it can't add patch for x86 platform for MAC notification,
         * for example, if nieghbour status is reachable, then kernel doesn't
         * notify registered call back function. So it has to get MAC from
         * ARP/NS response for this situation and update MAC of Kernel
         * Module ippathmgt.ko path array
         */
        // Ignore return value
        PIPM_update_path_mac();
#endif

	/*  
         *  Loop through the base interfaces twice. Cover internal interfaces and
         *  external interfaces with no corresponding extension interfaces first.
         */

        /* -- First scan -- */
        for ( ( i = 0, data_ptr = &(dataP->intf_data[0]) );
	      ( i < dataP->intf_cnt ); 
              ( i++, data_ptr++ ) )
        {
                
                if ( data_ptr->startExtnIntfIdx != -1 )
                {
                        continue;
                }

                if ( PIPM_GET_PATH_TIMER( data_ptr ) > 0 )
		{
			PIPM_GET_PATH_TIMER( data_ptr )--;
		}

		if ( 0 == PIPM_GET_PATH_TIMER( data_ptr ) )
		{
			/* send out arp/ipv6 neighbor discover-solicitation request */
			PIPM_path_refresh( data_ptr, PIPM_BASE_INTF );
			PIPM_SET_PATH_TIMER( data_ptr, pipm_path_refresh_time );
		}

		PIPM_path_resend( data_ptr );

        } /* end 'base interfaces loop' */

        /* -- Second scan -- */
        if ( dataP->extnIntfCount > 0 )
        {
                
                int extnIntfIdx = 0;
                PIPM_INTF_SPEC *intfSpecDataP;
                static unsigned int counter = 0;

                pipm_path_ops_count = 0;

                for ( ( i = dataP->startBaseIntfIdx, 
                        data_ptr = &(dataP->intf_data[dataP->startBaseIntfIdx]) );
	              ( i < dataP->intf_cnt ); 
                      ( i++, data_ptr++ ) )
                {

                        if ( -1 == data_ptr->startExtnIntfIdx )
                        {
                                continue;
                        }

                        if ( PIPM_GET_PATH_TIMER( data_ptr ) > 0 )
		        {
			        PIPM_GET_PATH_TIMER( data_ptr )--;
		        }

                        if ( 0 == PIPM_GET_PATH_TIMER( data_ptr ) )
                        {
                                PIPM_SET_PATH_TIMER( data_ptr, pipm_path_refresh_time );

                                if ( 0 == data_ptr->startExtnIntfIdx )
                                {
                                        /* Extension interface paths have also been updated. Now reset. */
                                        data_ptr->specData.bAllPathsUpdated = FALSE;

                                        for ( ( extnIntfIdx = 0,
                                                intfSpecDataP = &(dataP->extnIntfData[0]) );
                                              ( extnIntfIdx < dataP->extnIntfCount );
                                              ( extnIntfIdx++, intfSpecDataP++ ) )
                                        {
                                                intfSpecDataP->bAllPathsUpdated = FALSE;
                                        }
                                }
                        }

                        /* -- Refresh the base interface paths -- */
                        if ( FALSE == data_ptr->specData.bAllPathsUpdated )
                        {
                                PIPM_path_refresh( data_ptr, PIPM_BASE_INTF );
                        }

                        if ( pipm_path_ops_count >= PIPM_MAX_PATH_OPS_PER_TICK )
                        {
                                break;
                        }

                        /* -- Refresh the paths for the extension interfaces. -- */
                        for ( ( extnIntfIdx = data_ptr->startExtnIntfIdx,
                                intfSpecDataP = &(dataP->extnIntfData[data_ptr->startExtnIntfIdx]) );
                              ( extnIntfIdx < dataP->extnIntfCount );
                              ( extnIntfIdx++, intfSpecDataP++ ) )
                        {
                                if ( intfSpecDataP->baseIntfIdx != i )
                                {
                                        continue;
                                }

                                if ( FALSE == intfSpecDataP->bAllPathsUpdated )
                                {
                                        PIPM_path_refresh( intfSpecDataP, PIPM_EXTN_INTF );

                                        if ( pipm_path_ops_count >= PIPM_MAX_PATH_OPS_PER_TICK )
                                        {
                                                break;
                                        }
                                }
                        }

                        if ( extnIntfIdx == dataP->extnIntfCount )
                        {
                                data_ptr->startExtnIntfIdx = 0; 
                        }
                        else
                        {
                                if ( TRUE == intfSpecDataP->bAllPathsUpdated )
                                {
                                        /* All paths refreshed for the current extension interface. */
                                        if ( ( extnIntfIdx + 1 ) == dataP->extnIntfCount )
                                        {
                                                /* All extension interfaces paths refreshed. */
                                                data_ptr->startExtnIntfIdx = 0;
                                        }
                                        else
                                        {
                                                /* Set the extension interface index to start in the next tick. */
                                                data_ptr->startExtnIntfIdx = ( extnIntfIdx + 1 );
                                        }
                                }
                                else
                                {
                                        /* All paths NOT refreshed for the current extension interface. */
                                        data_ptr->startExtnIntfIdx = extnIntfIdx;
                                }
                        }

                        if ( pipm_path_ops_count >= PIPM_MAX_PATH_OPS_PER_TICK )
                        {
                                break;
                        }
                        
                } /* end 'base interfaces loop' */

                if ( pipm_path_ops_count >= PIPM_MAX_PATH_OPS_PER_TICK )
                {
                        if ( i == dataP->intf_cnt )
                        {
                                dataP->startBaseIntfIdx = 0;
                        }
                        else
                        {
                                if ( 0 == data_ptr->startExtnIntfIdx )
                                {
                                        if ( ( i + 1 ) == dataP->intf_cnt )
                                        {
                                                dataP->startBaseIntfIdx = 0; 
                                        }
                                        else
                                        {
                                                dataP->startBaseIntfIdx = ( i + 1 );
                                        }
                                }
                        }
                }
                else if ( i == dataP->intf_cnt )
                {
                        dataP->startBaseIntfIdx = 0;
                }

        } /* end 'extension interfaces present' */
	
	return( IPM_SUCCESS );
}

/**********************************************************************
 *
 * Name:        PIPM_path_refresh()
 *
 * Abstract:    Called to send ARP packets to path
 *
 * Parameters:  intfDataP - Base/extension interface data pointer.
 *                          Type: PIPM_INTF/PIPM_INTF_SPEC.
 *           :  intfTypeExt - Indicates if interface is base/extension.
 *
 * Returns:     void
 *
 **********************************************************************/
void PIPM_path_refresh( void *intfDataP, PIPM_INTF_TYPE_EXT intfTypeExt )
{
	PIPM_INTF       *data_ptr;
        PIPM_INTF_SPEC  *intfSpecDataP;
	PIPM_PATH 	*path_ptr;
	PIPM_SUBNET 	*subnet_ptr;
	int 		path_idx;
	int 		subnet_idx;
        int 		ret;

        PIPM_SET_INTF_PTRS( intfDataP, intfTypeExt, data_ptr, intfSpecDataP );


        if( data_ptr == NULL )
        {
                ASRT_RPT( ASRTBADPARAM, 0, "PIPM_path_refresh: NULL input pointer.\n" );
                return;
        }


	for ( ( subnet_idx = intfSpecDataP->startSubnetIdx, subnet_ptr = &(data_ptr->subnet[intfSpecDataP->startSubnetIdx]) ); 
              ( subnet_idx < data_ptr->subnet_cnt );
              ( subnet_idx++, subnet_ptr++ ) )
        {

          
                for ( ( path_idx = intfSpecDataP->startPathIdx, path_ptr = &subnet_ptr->path[intfSpecDataP->startPathIdx] );
                      ( path_idx < subnet_ptr->path_cnt );
                      ( path_idx++, path_ptr++ ) )
                {

                        if ( intfSpecDataP->vlanId == path_ptr->vlanId )
                        {

                                ret = PIPM_path_update( PIPM_REFRESH_PATH, path_ptr, subnet_ptr, 
                                                        intfDataP, intfTypeExt );

			        if( ret != IPM_SUCCESS )
		                {
			                LOG_ERROR( 0, "Error: PIPM_path_update failed ret [%d]", ret );
		    	        }
                                else if ( data_ptr->startExtnIntfIdx != -1 )
                                {
                                        if ( pipm_path_ops_count >= PIPM_MAX_PATH_OPS_PER_TICK )
                                        {
                                                /* Done for path updates for this tick. */
                                                break;
                                        }
                                }

                        } /* end 'vlanId match' */

                } /* end 'path loop' */
                
                if (    ( data_ptr->startExtnIntfIdx != -1 ) 
                     && ( subnet_ptr->path_cnt > 0 ) )
                {
                        if ( pipm_path_ops_count >= PIPM_MAX_PATH_OPS_PER_TICK )
                        {
                                /* Reached limit for path refresh operations per tick. */

                                if ( ( path_idx + 1 ) == subnet_ptr->path_cnt )
                                {
                                        /* All paths refreshed for this subnet. */
                                        intfSpecDataP->startPathIdx = 0;

                                        if ( ( subnet_idx + 1 ) == data_ptr->subnet_cnt )
                                        {
                                                /* All paths for all subnets for this interface refreshed. */
                                                intfSpecDataP->startSubnetIdx = 0;
                                                intfSpecDataP->bAllPathsUpdated = TRUE;
                                        }
                                        else
                                        {
                                                /* Set the subnet index to start at in the next tick. */
                                                intfSpecDataP->startSubnetIdx = subnet_idx + 1;
                                        }
                                }
                                else
                                {
                                        /* Set the path index to start at in the next tick. */
                                        intfSpecDataP->startPathIdx = path_idx + 1;
                                }

                                return;
                        }
                        else if ( path_idx == subnet_ptr->path_cnt )
                        {
                                /* All paths refreshed for this subnet. */
                                intfSpecDataP->startPathIdx = 0;
                                
                                if ( ( subnet_idx + 1 ) == data_ptr->subnet_cnt )
                                {
                                        /* All paths for all subnets for this interface refreshed. */
                                        intfSpecDataP->startSubnetIdx = 0;
                                        intfSpecDataP->bAllPathsUpdated = TRUE;
                                }
                                else
                                {
                                        /* Set the subnet index to start at in the next tick. */
                                        intfSpecDataP->startSubnetIdx = subnet_idx + 1;
                                }       
                        }
                }

        } /* end 'subnet loop' */

        if ( data_ptr->startExtnIntfIdx != -1 )
        {
                if ( subnet_idx == data_ptr->subnet_cnt ) 
                {
                        /* All paths for all subnets for this interface refreshed. */
                        intfSpecDataP->startSubnetIdx = 0;
                        intfSpecDataP->bAllPathsUpdated = TRUE;
                }
        }

	return;
}

/**********************************************************************
 *
 * Name:        PIPM_path_resend()
 *
 * Abstract:    Called to resend ARP packets to path
 *
 * Parameters:  data_ptr - pointer of PIPM_INTF
 *
 * Returns:     void
 *
 **********************************************************************/
void PIPM_path_resend( PIPM_INTF *data_ptr )
{
	PIPM_PATH 	*path_ptr;
	PIPM_SUBNET 	*subnet_ptr;
	int 		path_idx;
	int 		subnet_idx;
        int 		ret;

        if( data_ptr == NULL )
        {
                ASRT_RPT( ASRTBADPARAM, 0, "PIPM_path_refresh: NULL input pointer.\n" );
                return;
        }

	// Look through all subnets
	for( subnet_idx = 0, subnet_ptr = &data_ptr->subnet[0];
	     subnet_idx < data_ptr->subnet_cnt;
	     subnet_idx++, subnet_ptr++ )
	{
		PIPM_PATH *path_ptr;
		int path_idx;

		// Look through all IPs
		for( path_idx = 0, path_ptr = &subnet_ptr->path[0];
		     path_idx < subnet_ptr->path_cnt;
		     path_idx++, path_ptr++ )
		{
			if( path_ptr->resend_path_cnt > 0 )
			{	path_ptr->resend_path_cnt--;
			}

			if( path_ptr->resend_path_cnt == 1 )
			{
			    ret = PIPM_path_update( PIPM_REFRESH_PATH, path_ptr, subnet_ptr, data_ptr,
						    PIPM_BASE_INTF );
			    if( ret != IPM_SUCCESS )
		            {
			        LOG_ERROR( 0, "Error: PIPM_path_update failed ret [%d]", ret );
		    	    }
			}
		}
	}
	return;
}

