/**********************************************************************
 *
 * File:
 *      EIPM_ipcfg.c
 *
 * Functions in this file:
 *      EIPM_check_ip_plumbing() - Check configured IPs vs EIPM data
 *      EIPM_read_iptable()      - Read current IP table
 *      EIPM_configure_ip()      - Configure (aka Add/Delete) an IP
 *      EIPM_read_arptable()     - Read current ARP table
 *      EIPM_configure_ip_neighbor() - Configure (aka Add/Delete) an IP Neighbor
 *      EIPM_add_attribute()     - IP utility used for netlink msg
 *      EIPM_check_ip_tentative() - Check for IPv6 address in tentative state
 *
 **********************************************************************/

#include "EIPM_include.h"
#include "nma_route.h"
#include "EIPM_bfd.h"


unsigned int IPM_ip_seq;


/**********************************************************************
 *
 * Name:        EIPM_check_ip_plumbing()
 *
 * Abstract:    Compare EIPM IP data vs configured IPs, adjust plumbing as needed.
 *
 * Parameters:  intfDataP - pointer to base/extension interface data.
 *                          Type: EIPM_INTF/EIPM_INTF_SPEC
 *              intfType - identifies the interface as base/extension.
 *
 * Returns:     IPM_SUCCESS - IP handling was successful
 *              IPM_FAILURE - some error occurred.
 *
 **********************************************************************/

int
EIPM_check_ip_plumbing( void *intfDataP, EIPM_INTF_TYPE intfType )
{
EIPM_INTF *intf_ptr;
EIPM_INTF_SPEC *intfSpecDataP;
bool found_entry;
EIPM_SUBNET_TYPE eipm_subnet_type;
char plumbed_interface_name[16];
struct sockaddr_nl nladdr;
IPM_IPTBL ip_tbl;
EIPM_SUBNET *subnet_ptr;
EIPM_NET plumbed_interface;
int nl_socket;
int subnet_idx;
int temp_retval;
int retval;
bool read_ipv4_table = FALSE;
bool read_ipv6_table = FALSE;
bool read_arpv4_table = FALSE;
bool read_arpv6_table = FALSE;
char ip_lsn0IntfStr[MAX_NLEN_DEV];
char lsn0IntfStr[MAX_NLEN_DEV];
char interface_status[16];
IPM_IPTBL proxyclient_ip_tbl;
IPM_IPTBL *proxyclient_ip_tbl_ptr;
IPM_IPTBL proxyclientaddr_ip_tbl;
IPM_IPTBL *proxyclientaddr_ip_tbl_ptr;
IPM_IPTBL ip_tbl1;
bool read_ipv4_proxyclientaddr_table = FALSE;
bool read_ipv6_proxyclientaddr_table = FALSE;

proxyclient_ip_tbl_ptr = NULL;
memset(&proxyclient_ip_tbl, 0, sizeof(IPM_IPTBL));
memset(&ip_tbl1, 0, sizeof(IPM_IPTBL));
memset(&proxyclientaddr_ip_tbl, 0, sizeof(IPM_IPTBL));

    EIPM_SET_INTF_PTRS( intfDataP, intfType, intf_ptr, intfSpecDataP );

    if ( NULL == intf_ptr )
    {
        return IPM_FAILURE;
    }

    snprintf( lsn0IntfStr, sizeof( lsn0IntfStr ), "%s%s",
              intf_ptr->lsn0_baseif, ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

    /*
     * Based on interface state data (ie. ping-pong status),
     * plumb IPs on left or both interface(s)
     */
    switch ( intfSpecDataP->status )
    {
    case EIPM_ONLINE:
	if ( intfSpecDataP->preferred_side == LSN1 )
        {
            plumbed_interface = LSN_BOTH;
        }
        else
        {
            plumbed_interface = LSN0;
        }
        break;

    default:
        plumbed_interface = LSN_BOTH;
        break;
    }

    /* Overwrite the above ACM-based plumbed_interface
     * assignment if necessary.
     */
    if (( intfSpecDataP->monitor == EIPM_MONITOR_BFD ) ||
        ( intfSpecDataP->monitor == EIPM_MONITOR_IP ))
    {
	if ( (intfSpecDataP->lsn0_iface_indx > 0) &&
	     (intfSpecDataP->lsn1_iface_indx > 0) )
	{
		plumbed_interface = LSN_BOTH;
	}
	else if (intfSpecDataP->lsn0_iface_indx > 0)
	{
		plumbed_interface = LSN0;
	}
	else if (intfSpecDataP->lsn1_iface_indx > 0)
	{
		plumbed_interface = LSN1;
	}

    } /* if ( intfSpecDataP->monitor == EIPM_MONITOR_BFD ) */

    EIPM_network2str(plumbed_interface,plumbed_interface_name);

    EIPM_status2str( intfSpecDataP->status, interface_status );

    LOG_OTHER(EIPM_LOG_IPCHK,
	       "EIPM_check_ip_plumbing: Check Iface %s%s-%s%s Status %s State %d Plumb %s\n",
               intf_ptr->lsn0_baseif,
	       ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
               intf_ptr->lsn1_baseif,
	       ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
               interface_status,
	       intfSpecDataP->state,
               plumbed_interface_name );

    nl_socket = socket( PF_NETLINK, SOCK_RAW, NETLINK_ROUTE );

    if( nl_socket < 0 )
    {
        ASRT_RPT( ASUNEXP_RETURN,
                  1,
                  sizeof(*intf_ptr),
                  intf_ptr,
                  "EIPM_check_ip_plumbing: Failed to create routing socket\nretval=%d, errno=0x%x\n",
                   nl_socket,
                   errno );

        return( IPM_FAILURE );
    }

    /*
     * Fill in the sockaddr structure for bind().
     * From the netlink man page:
     * "There are two ways to assign nl_pid to a netlink socket.
     * If the application sets nl_pid before calling bind(2),
     * then it is up to the application to make sure that nl_pid
     * is unique.  If the application sets it to 0, the kernel
     * takes care of assigning it."
     * Since both IIPM and EIPM could be binding let the kernel
     * assign it.
     */
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pad = 0;
    nladdr.nl_pid = 0;
    nladdr.nl_groups = 0;

    retval = bind( nl_socket, (struct sockaddr *)&nladdr, sizeof( nladdr ) );

    if( retval < 0 )
    {
        ASRT_RPT( ASUNEXP_RETURN,
                  1,
                  sizeof(*intf_ptr),
                  intf_ptr,
                  "EIPM_check_ip_plumbing: Failed to bind to routing socket\nretval=%d, errno=0x%x\n",
                   retval, 
                   errno );

        (void)close( nl_socket );

        return( IPM_FAILURE );
    }

    memset(&ip_tbl, 0, sizeof(IPM_IPTBL));

    retval = IPM_SUCCESS;
    temp_retval = IPM_SUCCESS;

    /* Look through all subnets */
    for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
         subnet_idx < intf_ptr->subnet_cnt;
         subnet_idx++, subnet_ptr++ )
    {
        EIPM_IPDATA *ip_ptr;
        EIPM_TABLE_ENTRY *ip_tbl_ptr;
        int ip_idx;
        int ip_tbl_idx;

	/* Check whether or not this subnet uses BFD for redundancy.
	 * If it does then the historical ACM-based plumbing rules 
	 * (e.g. always plumb on LSN0) do not apply (e.g. for a Right
	 * BFD Transport subnet we only plumb on LSN1).
	 */
	if ( (subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD) ||
	     (subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT) ||
	     (subnet_ptr->redundancy_mode == IPM_RED_NONE) ||
	     (subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP) ||
             (subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR ))
	{
		/* This is a BFD Service or BFD Transport subnet */
		eipm_subnet_type = EIPM_BFD_SUBNET;
	}
	else if ( subnet_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_FIXLEFT ||
		  subnet_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_FIXRIGHT ||
		  subnet_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_SERVICE ||
		  subnet_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_ACTIVE ||
		  subnet_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_STANDBY )
	{
		eipm_subnet_type = EIPM_WCNP_SUBNET;
	}
	else
	{
		/* This is neither a BFD Service nor a BFD Transport subnet */
		eipm_subnet_type = EIPM_ACM_SUBNET;
	}

        /* Look through all IPs */
        for( ip_idx = 0, ip_ptr = &subnet_ptr->ips[0];
             ip_idx < subnet_ptr->ip_cnt;
             ip_idx++, ip_ptr++ )
        {
            // This check is added for pivot associated interface, e.g, eth0.800.x
            // It will prevent IP being added on such interface.
            char lsn0_iIntf[MAX_NLEN_DEV];
            char lsn1_iIntf[MAX_NLEN_DEV];

            ipm_get_internal_intfs(lsn0_iIntf, lsn1_iIntf);

            strncpy(ip_lsn0IntfStr, ip_ptr->lsn0_iface, (MAX_NLEN_DEV - 1));
            strtok(ip_lsn0IntfStr, ":");

            if ((strstr(ip_lsn0IntfStr, lsn0_iIntf) != NULL) && (ip_lsn0IntfStr[strlen(lsn0_iIntf)] == '.'))
            {
                ip_lsn0IntfStr[strlen(lsn0_iIntf)] = '\0';
            }

            /* It is debatable if this check should even have been
               put in the code.  It seems to break the VLAN checks
               and doesn't let IPM plumb all the necessary IPs, so
               not sure what "CI comment" provided this logic; maybe
               the feature dependency was not known, this prevents 
               a SERVICE from going to the active state, since AIM
               the service checks to make sure every IP is plumbed
               before going active.*/
            /*Since the scope of the original change is not specific
              remove the check for a BFD subnet - later on the check
              might need/should be generically for all subnet 
              types.  Maybe not for the "pivot" driver, on eth0.800/eth1.801*/
            /*OK latest update is that extension interfaces should 
              basically skip this part of the intf/IP audit! Otherwise, 
              External Malban Based VLAN will NOT work for ACM monitoring 
              modes.  Probably could remove the EIPM_ACM_SUBNET eipm_subnet_type check now, but
              leaving it since BFD, MultiHoming, Sngle Homing never has not 
              been tested (may never be tested) with EXTN interface types  */
            if ( (strcmp( ip_lsn0IntfStr, lsn0IntfStr ) != 0) && eipm_subnet_type == EIPM_ACM_SUBNET && intfType == EIPM_EXTN_INTF)
            {
                continue;
            }

            switch( ip_ptr->type )
            {
            case EIPM_IP_WCNP_FIXED:
            case EIPM_IP_ALIAS:
            case EIPM_IP_WCNP_ACTIVE:
            case EIPM_IP_WCNP_STANDBY:
            case EIPM_IP_PROXY_SERVER:
	    case EIPM_IP_PROXY_CLIENT:
                if( ip_ptr->ipaddr.addrtype == IPM_IPV4 &&
                    read_ipv4_table == FALSE )
                {
                    if (ip_ptr->type == EIPM_IP_PROXY_CLIENT)
                    {
                        if (ip_ptr->pivot_id > 0)
                        {
                            proxyclient_ip_tbl_ptr = &proxyclient_ip_tbl;
                        }
                        else
                        {
                            break;
                        }
                    }

                    if( EIPM_read_iptable( nl_socket, AF_INET, intfDataP, intfType, &ip_tbl, proxyclient_ip_tbl_ptr ) == IPM_SUCCESS )
                    {    
                        read_ipv4_table = TRUE;
                    }
                    else
                    {
                        ASRT_RPT( ASUNEXP_RETURN,
                                  2,
                                  sizeof(*intf_ptr),
                                  intf_ptr,
                                  sizeof(ip_tbl),
                                  &ip_tbl,
                                  "EIPM_check_ip_plumbing: Failed to read IPv4 table\n" );
                    }
                }
                else if( ip_ptr->ipaddr.addrtype == IPM_IPV6 &&
                         read_ipv6_table == FALSE )
                {
                    if (ip_ptr->type == EIPM_IP_PROXY_CLIENT)
                    {
                        if (ip_ptr->pivot_id > 0)
                        {
                            proxyclient_ip_tbl_ptr = &proxyclient_ip_tbl;
                        }
                        else
                        {
                            break;
                        }
                    }

                    if( EIPM_read_iptable( nl_socket, AF_INET6, intfDataP, intfType, &ip_tbl, proxyclient_ip_tbl_ptr ) == IPM_SUCCESS )
                    {    
                        read_ipv6_table = TRUE;
                    }
                    else
                    {
                        ASRT_RPT( ASUNEXP_RETURN,
                                  2,
                                  sizeof(*intf_ptr),
                                  intf_ptr,
                                  sizeof(ip_tbl),
                                  &ip_tbl,
                                  "EIPM_check_ip_plumbing: Failed to read IPv6 table\n" );
                    }
                }
                break;

            case EIPM_IP_PROXY_CLIENT_ADDR:

		//read ARP table to audit IP neighbor
                if( ip_ptr->ipaddr.addrtype == IPM_IPV4 &&
                    read_arpv4_table == FALSE )
                {
		    if( EIPM_read_arptable( nl_socket, AF_INET, intfDataP, intfType, &ip_tbl ) == IPM_SUCCESS )
                    {    
                        read_arpv4_table = TRUE;
                    }
                    else
                    {
                        ASRT_RPT( ASUNEXP_RETURN,
                                  2,
                                  sizeof(*intf_ptr),
                                  intf_ptr,
                                  sizeof(ip_tbl),
                                  &ip_tbl,
                                  "EIPM_check_ip_plumbing: Failed to read ARPv4 table\n" );
                    }
                }
                else if( ip_ptr->ipaddr.addrtype == IPM_IPV6 &&
                         read_arpv6_table == FALSE )
                {
		    if( EIPM_read_arptable( nl_socket, AF_INET6, intfDataP, intfType, &ip_tbl ) == IPM_SUCCESS )
                    {    
                        read_arpv6_table = TRUE;
                    }
                    else
                    {
                        ASRT_RPT( ASUNEXP_RETURN,
                                  2,
                                  sizeof(*intf_ptr),
                                  intf_ptr,
                                  sizeof(ip_tbl),
                                  &ip_tbl,
                                  "EIPM_check_ip_plumbing: Failed to read ARPv6 table\n" );
                    }
                }

		//read IP table to audit proxy_client_address IP
                if( ip_ptr->ipaddr.addrtype == IPM_IPV4 &&
                    read_ipv4_proxyclientaddr_table == FALSE )
                {

                    if( EIPM_read_iptable( nl_socket, AF_INET, intfDataP, intfType, &ip_tbl1, &proxyclientaddr_ip_tbl ) == IPM_SUCCESS )
                    {    
                        read_ipv4_proxyclientaddr_table = TRUE;
                    }
                    else
                    {
                        ASRT_RPT( ASUNEXP_RETURN,
                                  2,
                                  sizeof(*intf_ptr),
                                  intf_ptr,
                                  sizeof(ip_tbl),
                                  &ip_tbl,
                                  "EIPM_check_ip_plumbing: Failed to read IPv4 table\n" );
                    }
                }
                else if( ip_ptr->ipaddr.addrtype == IPM_IPV6 &&
                         read_ipv6_proxyclientaddr_table == FALSE )
                {

                    if( EIPM_read_iptable( nl_socket, AF_INET6, intfDataP, intfType, &ip_tbl1, &proxyclientaddr_ip_tbl ) == IPM_SUCCESS )
                    {    
                        read_ipv6_proxyclientaddr_table = TRUE;
                    }
                    else
                    {
                        ASRT_RPT( ASUNEXP_RETURN,
                                  2,
                                  sizeof(*intf_ptr),
                                  intf_ptr,
                                  sizeof(ip_tbl),
                                  &ip_tbl,
                                  "EIPM_check_ip_plumbing: Failed to read IPv6 table\n" );
                    }
                }
                break;

            default:
                continue;
            } /* end 'read of IP/ARP tables from linux' */

	    if (ip_ptr->type == EIPM_IP_PROXY_CLIENT)
            {
                /* Look for entry in table */
                for( ip_tbl_idx = 0, ip_tbl_ptr = &proxyclient_ip_tbl.ip_table[0];
                        ip_tbl_idx < proxyclient_ip_tbl.ip_cnt;
                        ip_tbl_idx++, ip_tbl_ptr++ )
                {
                    if( IPM_IPCMPADDR(&ip_ptr->ipaddr, &ip_tbl_ptr->ipaddr) == IPM_SUCCESS &&
                            subnet_ptr->pivot_iface_indx[0][ip_ptr->pivot_id] == ip_tbl_ptr->lsnA_idx)
                    {
                        break;
                    }
                }

                /* No entry in table */
                if( ip_tbl_idx == proxyclient_ip_tbl.ip_cnt )
                {
                    if (ip_ptr->pivot_id > 0)
                    {
                        //plumb on pivot interface
                        char name[EI_INTFNAMESIZE];
                        sprintf(name, "%s%d", PIVOT_PREFIX, ip_ptr->pivot_id);
                        retval = EIPM_ADD_IP( nl_socket,
                                		ip_ptr->type,
						&ip_ptr->ipaddr,
                                                subnet_ptr->prefixlen,
                                                subnet_ptr->pivot_iface_indx[0][ip_ptr->pivot_id],
                                                name );

                        EIPM_set_ip_config_time(ip_ptr);
                    }
                }
		continue;
            }
	    else if ( ip_ptr->type == EIPM_IP_PROXY_CLIENT_ADDR )
	    {
		/*
		 * Audit PROXY SERVER IP on pivot interface on host with FEPH service
		 * for virtual environment
		 * It can remove code in else section if pivot driver isn't supported
		 */
		if (ipm_isVirtual() == 1)
		{
			bool audit_proxyclientaddr = TRUE;
			int proxyclientaddr_idx;
			EIPM_IPDATA * proxyclientaddr_ptr;
			EIPM_IPDATA  proxyclientaddr;
			char Tunnel_interface[MAX_NLEN_DEV];
			int  proxyclientaddr_intf_idx = -1;
			char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
			
			memset(ipm_ipstr_buf, 0, sizeof(ipm_ipstr_buf));
			memset(Tunnel_interface, 0, sizeof(Tunnel_interface));
			memset(&proxyclientaddr, 0, sizeof(proxyclientaddr));
	
			memcpy(&proxyclientaddr, ip_ptr, sizeof(proxyclientaddr));
			if (proxyclientaddr.pivot_id > 0)
			{
				snprintf(Tunnel_interface, MAX_NLEN_DEV, 
					"%s%d", PIVOT_PREFIX, proxyclientaddr.pivot_id);
				proxyclientaddr_intf_idx = ipm_get_ifindex(inetsocket, Tunnel_interface);
				if (proxyclientaddr_intf_idx < 0)
				{
					LOG_FORCE(0, "Error: proxyclientaddr_intf_idx(%d) is less than 0 for interface(%s) when audit IP (%s)\n",
						proxyclientaddr_intf_idx, Tunnel_interface,
						IPM_ipaddr2p(&proxyclientaddr.ipaddr, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)));
					audit_proxyclientaddr = FALSE;
				}		
			}
			else
			{
				LOG_FORCE(0, "Error:  proxyclientaddr pivot_id is %d, should be larger than 0, skip audit this IP(%s)\n", 
					proxyclientaddr.pivot_id,
					IPM_ipaddr2p(&proxyclientaddr.ipaddr, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)));
				audit_proxyclientaddr = FALSE;
			}
			
			// Find the proxy server IP
			for( proxyclientaddr_idx = 0, proxyclientaddr_ptr = &subnet_ptr->ips[0];
				proxyclientaddr_idx < subnet_ptr->ip_cnt;
				proxyclientaddr_idx++, proxyclientaddr_ptr++ )
			{
				if (EIPM_IP_PROXY_SERVER == proxyclientaddr_ptr->type)
				{
					memcpy(&proxyclientaddr.ipaddr, &proxyclientaddr_ptr->ipaddr, 
						sizeof(IPM_IPADDR));
					break;
				}
			}
			if (proxyclientaddr_idx == subnet_ptr->ip_cnt)
			{
				LOG_ERROR(0, "Error: no proxy server IP in access subnet, skip audit this IP %s for interface (%s)\n",
					IPM_ipaddr2p(&proxyclientaddr.ipaddr, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
					Tunnel_interface);
				audit_proxyclientaddr = FALSE;
			}

			if (FALSE == EIPM_GET_PROXY_SERVER_ENABLED())
			{
				// Don't add IP on standby side
				audit_proxyclientaddr = FALSE;
			}

			// Try to add this IP
			if (TRUE == audit_proxyclientaddr)
			{
				for (ip_tbl_idx = 0, ip_tbl_ptr = &proxyclientaddr_ip_tbl.ip_table[0];
					ip_tbl_idx < proxyclientaddr_ip_tbl.ip_cnt;
					ip_tbl_idx++, ip_tbl_ptr++)
				{
					if ((IPM_SUCCESS == IPM_IPCMPADDR(&proxyclientaddr.ipaddr, &ip_tbl_ptr->ipaddr))
						&& (proxyclientaddr_intf_idx == ip_tbl_ptr->lsnA_idx)
					   )
					{
						break;
					}
				}

				if (ip_tbl_idx == proxyclientaddr_ip_tbl.ip_cnt)
				{
					// It doesn't find this IP
					EIPM_configure_ip(nl_socket, &(proxyclientaddr.ipaddr), subnet_ptr->prefixlen,
						proxyclientaddr_intf_idx, Tunnel_interface, RTM_NEWADDR);
				}
			}
		}
		else
		{
		//audit the proxy client addr IP here
		//note: EIPM_acm_ipcfg_check_sn is still executed 
		//to audit ip neighbour/arp table for EIPM_IP_PROXY_CLIENT_ADDR

		bool audit_proxyclietaddr = TRUE;
		int proxyclientaddr_idx;
		EIPM_IPDATA * proxyclientaddr_ptr;
		EIPM_IPDATA  proxyclientaddr;
		char            lsn0_internalIntf[MAX_NLEN_DEV];
		char            lsn1_internalIntf[MAX_NLEN_DEV];
		int proxyclientaddr_lsn0_idx = -1;
		int proxyclientaddr_lsn1_idx = -1;
		char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
		memset(ipm_ipstr_buf, 0, sizeof(ipm_ipstr_buf));
		
		memset(lsn0_internalIntf, 0, sizeof(lsn0_internalIntf));
		memset(lsn1_internalIntf, 0, sizeof(lsn1_internalIntf));
		memset(&proxyclientaddr,  0, sizeof(proxyclientaddr));

		//populate proxyclientaddr
		//1) interfaces: replace external interface with internal interface
		//From OS layer, EIPM_IP_PROXY_CLIENT_ADDR IP is added in internal interfaces
		//E.G eth0.800.4/eth1.801.4
		//2) IP address: replace EIPM_IP_PROXY_CLIENT_ADDR with EIPM_IP_PROXY_SERVER IP
		//For EIPM_IP_PROXY_CLIENT_ADDR IP, IPM store beph IP,
		//But OS store feph IP(proxy server IP), we need to replace the audit subject from 
		// beph IP to feph IP 

		//interface replacement
		ipm_get_internal_intfs(lsn0_internalIntf, lsn1_internalIntf);
		memcpy(&proxyclientaddr, ip_ptr, sizeof(proxyclientaddr));
		if(proxyclientaddr.pivot_id > 0)
		{
			if ((lsn0_internalIntf[0] != '\0') && (proxyclientaddr.lsn0_iface[0] != '\0'))
			{
				snprintf(proxyclientaddr.lsn0_iface, MAX_NLEN_DEV, "%s.%d", lsn0_internalIntf, proxyclientaddr.pivot_id);
			}
			if ((lsn1_internalIntf[0] != '\0') && (proxyclientaddr.lsn1_iface[0] != '\0'))
			{
				snprintf(proxyclientaddr.lsn1_iface, MAX_NLEN_DEV, "%s.%d", lsn1_internalIntf, proxyclientaddr.pivot_id);
			}
		}
		else
		{
			LOG_ERROR(0, "Error: proxyclientaddr pivot_id is %d, should be larger than 0, skip audit this IP\n", proxyclientaddr.pivot_id);
			audit_proxyclietaddr = FALSE;
		}
		if (proxyclientaddr.lsn0_iface[0] != '\0')
		{
			proxyclientaddr_lsn0_idx = ipm_get_ifindex(inetsocket, proxyclientaddr.lsn0_iface);
			if(proxyclientaddr_lsn0_idx == -1)
			{
				LOG_ERROR(0, "Error: proxyclientaddr_lsn0_idx is -1\n");
			}
		}
                
		if (proxyclientaddr.lsn1_iface[0] != '\0') 
		{
			proxyclientaddr_lsn1_idx = ipm_get_ifindex(inetsocket, proxyclientaddr.lsn1_iface);
			if(proxyclientaddr_lsn1_idx == -1)
			{
				LOG_ERROR(0, "Error: proxyclientaddr_lsn1_idx is -1\n");
			}
		}

		if ((proxyclientaddr_lsn0_idx == -1) && (proxyclientaddr_lsn1_idx == -1))
		{
			audit_proxyclietaddr = FALSE;
		}


		//IP replacement
		for( proxyclientaddr_idx = 0, proxyclientaddr_ptr = &subnet_ptr->ips[0];
		     proxyclientaddr_idx < subnet_ptr->ip_cnt;
		     proxyclientaddr_idx++, proxyclientaddr_ptr++ )
		{
			if( proxyclientaddr_ptr->type == EIPM_IP_PROXY_SERVER )
			{ 
				//found the proxy server IP address
				memcpy(&proxyclientaddr.ipaddr, &proxyclientaddr_ptr->ipaddr, sizeof(IPM_IPADDR));
				break;
			}
		}

		if( proxyclientaddr_idx == subnet_ptr->ip_cnt )
		{
			LOG_ERROR(0, "Error: no proxy server IP in access subnet, skip audit this IP %s\n", 
					IPM_ipaddr2p(&proxyclientaddr.ipaddr, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)));
			audit_proxyclietaddr = FALSE;
		}

		//audit this IP
		if(audit_proxyclietaddr)
		{
			//check if this IP is in OS entry
			//note: proxyclientaddr_ip_tbl only has lsnA populated, so only compare lsnA_idx
			bool lsn0_match = FALSE;
			bool lsn1_match = FALSE;

			for( ip_tbl_idx = 0, ip_tbl_ptr = &proxyclientaddr_ip_tbl.ip_table[0];
				ip_tbl_idx < proxyclientaddr_ip_tbl.ip_cnt;
				ip_tbl_idx++, ip_tbl_ptr++ )
			{
				
			    if( IPM_IPCMPADDR(&proxyclientaddr.ipaddr, &ip_tbl_ptr->ipaddr) == IPM_SUCCESS )
			    {
				    //found this IP, check the inteface match
			        if( lsn0_match == FALSE && proxyclientaddr_lsn0_idx == ip_tbl_ptr->lsnA_idx  )
				{
					lsn0_match = TRUE;
				}
			        if( lsn1_match == FALSE && proxyclientaddr_lsn1_idx == ip_tbl_ptr->lsnA_idx  )
				{
					lsn1_match = TRUE;
				}

				if(( IS_DUPLEX_MODE && lsn0_match == TRUE && lsn1_match == TRUE ) ||
                                       ((IS_SIMPLEX_MODE) && ((lsn0_match == TRUE) || (lsn1_match == TRUE))) )
			       {
					LOG_OTHER(0, "Found IP %s in OS", IPM_ipaddr2p(&proxyclientaddr.ipaddr, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)));
					break;
			       }
			    }
			}

			    if( ip_tbl_idx == proxyclientaddr_ip_tbl.ip_cnt )
			    {
				/* No entry in table */
				/* don't audit from standby side now */
				if ( EIPM_GET_PROXY_SERVER_ENABLED() == FALSE)
				{
				     audit_proxyclietaddr = FALSE;
				}

				if(audit_proxyclietaddr)
				{
					LOG_OTHER(0, " Add proxy_client_address on lsn0: ipaddr is %s, subnet_ptr->prefixlen is %d, proxyclientaddr.lsn0_iface is %s, proxyclientaddr_lsn0_idx is %d, sn1_iface is %s, proxyclientaddr_lsn1_idx is %d \n",
						IPM_ipaddr2p(&proxyclientaddr.ipaddr, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
						subnet_ptr->prefixlen,
						proxyclientaddr.lsn0_iface,
						proxyclientaddr_lsn0_idx,
						proxyclientaddr.lsn1_iface,
						proxyclientaddr_lsn1_idx);

					if ((proxyclientaddr.lsn0_iface[0] != '\0') && (lsn0_match == FALSE ))
					{
						EIPM_configure_ip(nl_socket,
							&(proxyclientaddr.ipaddr),
							subnet_ptr->prefixlen,
							proxyclientaddr_lsn0_idx,	
							proxyclientaddr.lsn0_iface,
							RTM_NEWADDR);
					}

					if ((proxyclientaddr.lsn1_iface[0] != '\0') && ( lsn1_match == FALSE ))
					{
						EIPM_configure_ip(nl_socket,
							&(proxyclientaddr.ipaddr),
							subnet_ptr->prefixlen,
							proxyclientaddr_lsn1_idx,	
							proxyclientaddr.lsn1_iface,
							RTM_NEWADDR);
					}

				}
			    }
		    }
		    }
		}

            /* Look for entry in table */
            for( ip_tbl_idx = 0, ip_tbl_ptr = &ip_tbl.ip_table[0];
                 ip_tbl_idx < ip_tbl.ip_cnt;
                 ip_tbl_idx++, ip_tbl_ptr++ )
            {
                if( IPM_IPCMPADDR(&ip_ptr->ipaddr, &ip_tbl_ptr->ipaddr) == IPM_SUCCESS )
                { 
                    break;
                }
            }

            if( ip_tbl_idx == ip_tbl.ip_cnt )
            {
                /* don't add this entry now */
                if ((ip_ptr->type == EIPM_IP_PROXY_SERVER ||
                     ip_ptr->type == EIPM_IP_PROXY_CLIENT_ADDR) &&
                     EIPM_GET_PROXY_SERVER_ENABLED() == FALSE)
                {
                     continue;
                }
                /* No entry in table */
		found_entry = FALSE;
	    }
	    else
	    {
                /* Existing entry in table */
		found_entry = TRUE;
	    }

	    if (eipm_subnet_type ==  EIPM_BFD_SUBNET)
	    {
		temp_retval = EIPM_bfd_ipcfg_check_sn(
					found_entry,
					intf_ptr,
					subnet_ptr,
					ip_ptr,
					ip_tbl_ptr,
					intfSpecDataP,
					plumbed_interface,
					nl_socket
				);
	    }
	    else if (eipm_subnet_type ==  EIPM_WCNP_SUBNET)
	    {

			if( ip_ptr->type == EIPM_IP_WCNP_ACTIVE || ip_ptr->type == EIPM_IP_ALIAS )
			{
				plumbed_interface = subnet_ptr->sub2intf_mapping[0].route_priority;
			}
			else if( ip_ptr->type == EIPM_IP_WCNP_STANDBY && subnet_ptr->sub2intf_mapping[0].route_priority == LSN0 )
			{
				plumbed_interface = LSN1;
			}
			else if( ip_ptr->type == EIPM_IP_WCNP_STANDBY && subnet_ptr->sub2intf_mapping[0].route_priority == LSN1 )
			{
				plumbed_interface = LSN0;
			}
			else if( ip_ptr->type == EIPM_IP_WCNP_FIXED && subnet_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_FIXLEFT )
			{
				plumbed_interface = LSN0;
			}
			else if( ip_ptr->type == EIPM_IP_WCNP_FIXED && subnet_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_FIXRIGHT )
			{
				plumbed_interface = LSN1;
			}
			else
			{
				LOG_ERROR(0, "Error: invalid IP type %d, ip_ptr->lsn0_iface - ip_ptr->lsn1_iface is %s-%s",
					ip_ptr->type, ip_ptr->lsn0_iface, ip_ptr->lsn1_iface);
			}
		    temp_retval = EIPM_wcnp_ipcfg_check_sn(
					found_entry,
					intf_ptr,
					subnet_ptr,
					ip_ptr,
					ip_tbl_ptr,
					intfSpecDataP,
					plumbed_interface,
					nl_socket
				    );
	    }
	    else
	    {
		temp_retval = EIPM_acm_ipcfg_check_sn(
					found_entry,
					intf_ptr,
					subnet_ptr,
					ip_ptr,
					ip_tbl_ptr,
					intfSpecDataP,
					plumbed_interface,
					nl_socket
				);
	    }

	    if (retval == IPM_SUCCESS)
	    {
		retval = temp_retval;
	    }

        } /* Look through all IPs */

    } /* Look through all subnets */

    (void)close( nl_socket );

    return retval;

} /* EIPM_check_ip_plumbing() */

int EIPM_acm_ipcfg_check_sn(
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
	int retval, temp_retval;

	/* Check IP plumbing for a subnet that uses ACM redundacny
	 * protocol.
	 */

	retval = IPM_SUCCESS;

	if (found_entry == FALSE)
	{

                /* Always plumb on LSN0 interface */
                temp_retval = EIPM_ADD_IP( nl_socket, 
                                           ip_ptr->type,
                                           &ip_ptr->ipaddr,
                                           subnet_ptr->prefixlen,
					   intfSpecDataP->lsn0_iface_indx,
                                           ip_ptr->lsn0_iface );

                EIPM_set_ip_config_time(ip_ptr);

                if( retval == IPM_SUCCESS )
                {
                    retval = temp_retval;
                }

                if( plumbed_interface == LSN0 )
                {
                    EIPM_SET_GRAT_ARP(subnet_ptr, LSN0);
                }
                else if( plumbed_interface == LSN_BOTH )
                {
                    /* Conditionally plumb on LSN1 interface */
                    temp_retval = EIPM_ADD_IP( nl_socket, 
                                               ip_ptr->type,
                                               &ip_ptr->ipaddr,
                                               subnet_ptr->prefixlen,
					       intfSpecDataP->lsn1_iface_indx,
                                               ip_ptr->lsn1_iface );

                    if( retval == IPM_SUCCESS )
                    {
                        retval = temp_retval;
                    }

                    EIPM_SET_GRAT_ARP(subnet_ptr, subnet_ptr->sub2intf_mapping[0].route_priority);
                }

            }
            else
            {
                /* Found entry in table */
                if ((ip_ptr->type == EIPM_IP_PROXY_SERVER ||
                     ip_ptr->type == EIPM_IP_PROXY_CLIENT_ADDR) &&
                     EIPM_GET_PROXY_SERVER_ENABLED() == FALSE)
                {
                    /* Need to delete the entry */
                    if( ip_tbl_ptr->lsnA_idx != -1 )
                    {
                        temp_retval = EIPM_DELETE_IP( nl_socket, 
                                                      ip_ptr->type,
                                                      &ip_tbl_ptr->ipaddr,
                                                      ip_tbl_ptr->prefix,
                                                      ip_tbl_ptr->lsnA_idx,
                                                      "" );

                        if( retval == IPM_SUCCESS )
                        {
                            retval = temp_retval;
                        }
                    }

                    if( ip_tbl_ptr->lsnB_idx != -1 )
                    {
                        temp_retval = EIPM_DELETE_IP( nl_socket, 
                                                      ip_ptr->type,
                                                      &ip_tbl_ptr->ipaddr,
                                                      ip_tbl_ptr->prefix,
                                                      ip_tbl_ptr->lsnB_idx,
                                                      "" );

                        if( retval == IPM_SUCCESS )
                        {
                            retval = temp_retval;
                        }
                    }
		    return IPM_SUCCESS;
                }

                /* Always plumb on LSN0 interface */
		if (     ( intfSpecDataP->lsn0_iface_indx != ip_tbl_ptr->lsnA_idx )
		      && ( intfSpecDataP->lsn0_iface_indx != ip_tbl_ptr->lsnB_idx ) )
                {
                    /* Adjust LSN0 plumbing */
                    if( ip_tbl_ptr->lsnA_idx != -1 )
                    {
                        temp_retval = EIPM_DELETE_IP( nl_socket, 
                                                      ip_ptr->type,
                                                      &ip_tbl_ptr->ipaddr,
                                                      ip_tbl_ptr->prefix,
                                                      ip_tbl_ptr->lsnA_idx,
                                                      "" );

                        if( retval == IPM_SUCCESS )
                        {
                            retval = temp_retval;
                        }
                    }

                    if( ip_tbl_ptr->lsnB_idx != -1 )
                    {
                        temp_retval = EIPM_DELETE_IP( nl_socket, 
                                                      ip_ptr->type,
                                                      &ip_tbl_ptr->ipaddr,
                                                      ip_tbl_ptr->prefix,
                                                      ip_tbl_ptr->lsnB_idx,
                                                      "" );

                        if( retval == IPM_SUCCESS )
                        {
                            retval = temp_retval;
                        }
                    }

                    temp_retval = EIPM_ADD_IP( nl_socket, 
                                               ip_ptr->type,
                                               &ip_ptr->ipaddr,
                                               subnet_ptr->prefixlen,
					       intfSpecDataP->lsn0_iface_indx,
                                               ip_ptr->lsn0_iface );

                    EIPM_set_ip_config_time(ip_ptr);

                    if( retval == IPM_SUCCESS )
                    {
                        retval = temp_retval;
                    }
                }
                else if( ((ip_tbl_ptr->lsnA_tentative == TRUE &&
                           ip_tbl_ptr->lsnA_idx == intfSpecDataP->lsn0_iface_indx) ||
                          (ip_tbl_ptr->lsnB_tentative == TRUE &&
                           ip_tbl_ptr->lsnB_idx == intfSpecDataP->lsn0_iface_indx)) &&
                         EIPM_check_ip_config_time(ip_ptr, EIPM_IP_CONFIG_TIMEOUT) == TRUE )
                {
                    char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];

                    LOG_OTHER( EIPM_LOG_IPCHK,
                               "EIPM_check_ip_plumbing: Tentative IP %s/%d on %d - %s\n",
                                IPM_ipaddr2p(&(ip_ptr->ipaddr), ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
                                subnet_ptr->prefixlen,
				intfSpecDataP->lsn0_iface_indx,
                                ip_ptr->lsn0_iface );

                    temp_retval = EIPM_DELETE_IP( nl_socket, 
                                                  ip_ptr->type,
                                                  &ip_ptr->ipaddr,
                                                  subnet_ptr->prefixlen,
						  intfSpecDataP->lsn0_iface_indx,
                                                  ip_ptr->lsn0_iface );

                    if( retval == IPM_SUCCESS )
                    {
                        retval = temp_retval;
                    }

                    temp_retval = EIPM_ADD_IP( nl_socket, 
                                               ip_ptr->type,
                                               &ip_ptr->ipaddr,
                                               subnet_ptr->prefixlen,
					       intfSpecDataP->lsn0_iface_indx,
                                               ip_ptr->lsn0_iface );

                    EIPM_set_ip_config_time(ip_ptr);

                    if( retval == IPM_SUCCESS )
                    {
                        retval = temp_retval;
                    }
                }

                /* Conditionally plumb on LSN1 interface */
                if( plumbed_interface == LSN0 )
                {
		    if ( intfSpecDataP->lsn1_iface_indx == ip_tbl_ptr->lsnA_idx )
                    {
                        temp_retval = EIPM_DELETE_IP( nl_socket, 
                                                      ip_ptr->type,
                                                      &ip_tbl_ptr->ipaddr,
                                                      ip_tbl_ptr->prefix,
						      intfSpecDataP->lsn1_iface_indx,
                                                      intf_ptr->lsn1_baseif );

                        if( retval == IPM_SUCCESS )
                        {
                            retval = temp_retval;
                        }

                        EIPM_SET_GRAT_ARP(subnet_ptr, LSN0);
                    }

		    if ( intfSpecDataP->lsn1_iface_indx == ip_tbl_ptr->lsnB_idx )
                    {
			/* Check. Shouldn't we be passing in 'ip_ptr->lsn1_iface'. ? */
                        temp_retval = EIPM_DELETE_IP( nl_socket, 
                                                      ip_ptr->type,
                                                      &ip_tbl_ptr->ipaddr,
                                                      ip_tbl_ptr->prefix,
						      intfSpecDataP->lsn1_iface_indx,
                                                      intf_ptr->lsn1_baseif );

                        if( retval == IPM_SUCCESS )
                        {
                            retval = temp_retval;
                        }

                        EIPM_SET_GRAT_ARP(subnet_ptr, LSN0);
                    }
                }
                else if( plumbed_interface == LSN_BOTH )
                {
		    if (    ( intfSpecDataP->lsn1_iface_indx != ip_tbl_ptr->lsnB_idx )
			 && ( intfSpecDataP->lsn1_iface_indx != ip_tbl_ptr->lsnA_idx ) )
                    {
                        /* Adjust LSN1 plumbing */
                        if( ip_tbl_ptr->lsnA_idx != -1 &&
			    ip_tbl_ptr->lsnA_idx != intfSpecDataP->lsn0_iface_indx )
                        {
                            temp_retval = EIPM_DELETE_IP( nl_socket, 
                                                          ip_ptr->type,
                                                          &ip_tbl_ptr->ipaddr,
                                                          ip_tbl_ptr->prefix,
                                                          ip_tbl_ptr->lsnA_idx,
                                                          "" );

                            if( retval == IPM_SUCCESS )
                            {
                                retval = temp_retval;
                            }
                        }

                        if( ip_tbl_ptr->lsnB_idx != -1 &&
			    ip_tbl_ptr->lsnB_idx != intfSpecDataP->lsn0_iface_indx )
                        {
                            temp_retval = EIPM_DELETE_IP( nl_socket, 
                                                          ip_ptr->type,
                                                          &ip_tbl_ptr->ipaddr,
                                                          ip_tbl_ptr->prefix,
                                                          ip_tbl_ptr->lsnB_idx,
                                                          "" );

                            if( retval == IPM_SUCCESS )
                            {
                                retval = temp_retval;
                            }
                        }

                        temp_retval = EIPM_ADD_IP( nl_socket, 
                                                   ip_ptr->type,
                                                   &ip_ptr->ipaddr,
                                                   subnet_ptr->prefixlen,
						   intfSpecDataP->lsn1_iface_indx,
                                                   ip_ptr->lsn1_iface );

                        EIPM_set_ip_config_time(ip_ptr);

                        if( retval == IPM_SUCCESS )
                        {
                            retval = temp_retval;
                        }
                    }
                    else if( ((ip_tbl_ptr->lsnA_tentative == TRUE &&
                               ip_tbl_ptr->lsnA_idx == intfSpecDataP->lsn1_iface_indx) ||
                              (ip_tbl_ptr->lsnB_tentative == TRUE &&
                               ip_tbl_ptr->lsnB_idx == intfSpecDataP->lsn1_iface_indx)) &&
                             EIPM_check_ip_config_time(ip_ptr, EIPM_IP_CONFIG_TIMEOUT) == TRUE )
                    {
                        char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
    
                        LOG_OTHER( EIPM_LOG_IPCHK,
                                   "EIPM_check_ip_plumbing: Tentative IP %s/%d on %d - %s\n",
                                    IPM_ipaddr2p(&(ip_ptr->ipaddr), ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
                                    subnet_ptr->prefixlen,
				    intfSpecDataP->lsn1_iface_indx,
                                    ip_ptr->lsn1_iface );

                        temp_retval = EIPM_DELETE_IP( nl_socket, 
                                                      ip_ptr->type,
                                                      &ip_ptr->ipaddr,
                                                      subnet_ptr->prefixlen,
						      intfSpecDataP->lsn1_iface_indx,
                                                      ip_ptr->lsn1_iface );

                        if( retval == IPM_SUCCESS )
                        {
                            retval = temp_retval;
                        }

                        temp_retval = EIPM_ADD_IP( nl_socket, 
                                                   ip_ptr->type,
                                                   &ip_ptr->ipaddr,
                                                   subnet_ptr->prefixlen,
						   intfSpecDataP->lsn1_iface_indx,
                                                   ip_ptr->lsn1_iface );

                        EIPM_set_ip_config_time(ip_ptr);
    
                        if( retval == IPM_SUCCESS )
                        {
                            retval = temp_retval;
                        }
                    }

                } /* Check plumbed interfaces */

            } /* Check if entry in table */

    return retval;
}

int EIPM_wcnp_ipcfg_check_sn(
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
	int retval, temp_retval;
	bool eipm_lsn0_populated = FALSE;
	bool eipm_lsn1_populated = FALSE;
	bool os_lsnA_deleted = FALSE;
	bool os_lsnB_deleted = FALSE;

	/* Check IP plumbing for a subnet that uses WCNP redundancy
	 * protocol.
	 */

	retval = IPM_SUCCESS;
	if ( (intfSpecDataP->lsn0_iface_indx > 0) &&
	     (ip_ptr->lsn0_iface[0] != 0) &&
		  (strlen(ip_ptr->lsn0_iface) != 0) )
	{
		eipm_lsn0_populated = TRUE;
	}

	if ( (intfSpecDataP->lsn1_iface_indx > 0) &&
	     (ip_ptr->lsn1_iface[0] != 0) &&
		  (strlen(ip_ptr->lsn1_iface) != 0) )
	{
		eipm_lsn1_populated = TRUE;
	}

	if (found_entry == FALSE)
	{
		/*found NO entries in OS table, just plumb the IP*/
		if( plumbed_interface == LSN0 ) 
		{
			retval = EIPM_ADD_IP( nl_socket, 
						   ip_ptr->type,
						   &ip_ptr->ipaddr,
						   subnet_ptr->prefixlen,
						   intfSpecDataP->lsn0_iface_indx,
						   ip_ptr->lsn0_iface );

			EIPM_set_ip_config_time(ip_ptr);
		}
		else if( plumbed_interface == LSN1 )
		{
                        retval = EIPM_ADD_IP( nl_socket, 
                                               ip_ptr->type,
                                               &ip_ptr->ipaddr,
                                               subnet_ptr->prefixlen,
					       intfSpecDataP->lsn1_iface_indx,
                                               ip_ptr->lsn1_iface );

			EIPM_set_ip_config_time(ip_ptr);
		}
		else if( plumbed_interface == LSN_BOTH )
                {
			temp_retval = EIPM_ADD_IP( nl_socket, 
						   ip_ptr->type,
						   &ip_ptr->ipaddr,
						   subnet_ptr->prefixlen,
						   intfSpecDataP->lsn0_iface_indx,
						   ip_ptr->lsn0_iface );
			if( retval == IPM_SUCCESS )
			{
				retval = temp_retval;
			}

			temp_retval = EIPM_ADD_IP( nl_socket, 
					       ip_ptr->type,
					       &ip_ptr->ipaddr,
					       subnet_ptr->prefixlen,
					       intfSpecDataP->lsn1_iface_indx,
					       ip_ptr->lsn1_iface );

			if( retval == IPM_SUCCESS )
			{
				retval = temp_retval;
			}
                }
		else
		{
			LOG_ERROR(0, "Error: invalid value for plumbed_interface %d\n", plumbed_interface);
		}

            }
            else
            {
                /* Found entry in table */
		/*
		   1. plumbed_interface - LSN0
		   - remove existing IP from eth0/eth1 and plumbed the IP only on LSN0
		   2. plumbed_interface - LSN1
		   - remove existing IP from eth0/eth1 and plumbed the IP only on LSN1
		   3. plumbed_interface - LSN_BOTH
		   - remove existing IP from both eth0/eth1 and plumbed the IP only on LSN1/LSN0
		   4. besides above, check the IP tentative status, if the IP is in that state,
		      unplumb and replumb those IP again.
		*/

		if ( plumbed_interface == LSN0 )
		{
			if ( eipm_lsn0_populated == FALSE )
			{
				LOG_ERROR(0, "Error: eipm_lsn0_populated is false and ipm is trying to add wcnp IP on lsn0");
				return IPM_FAILURE;
			}
			if ( ( intfSpecDataP->lsn0_iface_indx != ip_tbl_ptr->lsnA_idx )
			      && ( intfSpecDataP->lsn0_iface_indx != ip_tbl_ptr->lsnB_idx ) )
			{
			    /* Adjust LSN0 plumbing */
			    if( ip_tbl_ptr->lsnA_idx != -1 )
			    {
				temp_retval = EIPM_DELETE_IP( nl_socket, 
							      ip_ptr->type,
							      &ip_tbl_ptr->ipaddr,
							      ip_tbl_ptr->prefix,
							      ip_tbl_ptr->lsnA_idx,
							      "" );

				if( retval == IPM_SUCCESS )
				{
				    os_lsnA_deleted = TRUE;
				    retval = temp_retval;
				}
			    }

			    if( ip_tbl_ptr->lsnB_idx != -1 )
			    {
				temp_retval = EIPM_DELETE_IP( nl_socket, 
							      ip_ptr->type,
							      &ip_tbl_ptr->ipaddr,
							      ip_tbl_ptr->prefix,
							      ip_tbl_ptr->lsnB_idx,
							      "" );

				if( retval == IPM_SUCCESS )
				{
				    os_lsnB_deleted = TRUE;
				    retval = temp_retval;
				}
			    }

			    temp_retval = EIPM_ADD_IP( nl_socket, 
						       ip_ptr->type,
						       &ip_ptr->ipaddr,
						       subnet_ptr->prefixlen,
						       intfSpecDataP->lsn0_iface_indx,
						       ip_ptr->lsn0_iface );

			    EIPM_set_ip_config_time(ip_ptr);

			    if( retval == IPM_SUCCESS )
			    {
				retval = temp_retval;
			    }
			}
			else if( ((ip_tbl_ptr->lsnA_tentative == TRUE &&
				   ip_tbl_ptr->lsnA_idx == intfSpecDataP->lsn0_iface_indx) ||
				  (ip_tbl_ptr->lsnB_tentative == TRUE &&
				   ip_tbl_ptr->lsnB_idx == intfSpecDataP->lsn0_iface_indx)) &&
				 EIPM_check_ip_config_time(ip_ptr, EIPM_IP_CONFIG_TIMEOUT) == TRUE )
			{
			    char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];

			    LOG_OTHER( EIPM_LOG_IPCHK,
				       "EIPM_check_ip_plumbing: Tentative IP %s/%d on %d - %s\n",
					IPM_ipaddr2p(&(ip_ptr->ipaddr), ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
					subnet_ptr->prefixlen,
					intfSpecDataP->lsn0_iface_indx,
					ip_ptr->lsn0_iface );

			    temp_retval = EIPM_DELETE_IP( nl_socket, 
							  ip_ptr->type,
							  &ip_ptr->ipaddr,
							  subnet_ptr->prefixlen,
							  intfSpecDataP->lsn0_iface_indx,
							  ip_ptr->lsn0_iface );

			    if( retval == IPM_SUCCESS )
			    {
				retval = temp_retval;
			    }

			    retval = EIPM_ADD_IP( nl_socket, 
						       ip_ptr->type,
						       &ip_ptr->ipaddr,
						       subnet_ptr->prefixlen,
						       intfSpecDataP->lsn0_iface_indx,
						       ip_ptr->lsn0_iface );

			    EIPM_set_ip_config_time(ip_ptr);

			}

			//remove the additional IP on lsn1
		    if ( intfSpecDataP->lsn1_iface_indx == ip_tbl_ptr->lsnA_idx && os_lsnA_deleted == FALSE )
                    {
                        temp_retval = EIPM_DELETE_IP( nl_socket, 
                                                      ip_ptr->type,
                                                      &ip_tbl_ptr->ipaddr,
                                                      ip_tbl_ptr->prefix,
						      intfSpecDataP->lsn1_iface_indx,
                                                      intf_ptr->lsn1_baseif );

                        if( temp_retval == IPM_SUCCESS )
                        {
                            retval = temp_retval;
                        }

                        EIPM_SET_GRAT_ARP(subnet_ptr, LSN0);
                    }

		    if ( intfSpecDataP->lsn1_iface_indx == ip_tbl_ptr->lsnB_idx && os_lsnB_deleted == FALSE )
                    {
			// Check. Shouldn't we be passing in 'ip_ptr->lsn1_iface'. ? 
                        retval = EIPM_DELETE_IP( nl_socket, 
                                                      ip_ptr->type,
                                                      &ip_tbl_ptr->ipaddr,
                                                      ip_tbl_ptr->prefix,
						      intfSpecDataP->lsn1_iface_indx,
                                                      intf_ptr->lsn1_baseif );


                    }
		}

                else if( plumbed_interface == LSN1 )
                {
		    if ( eipm_lsn1_populated == FALSE )
		    {
			    LOG_ERROR( 0, "Error: eipm_lsn1_populated is false and ipm is trying to add wcnp IP on lsn1");
			    return IPM_FAILURE;
		    }
		    if ( ( intfSpecDataP->lsn1_iface_indx != ip_tbl_ptr->lsnB_idx )
			 && ( intfSpecDataP->lsn1_iface_indx != ip_tbl_ptr->lsnA_idx ) )
                    {
                        if( ip_tbl_ptr->lsnA_idx != -1 )
                        {
                            temp_retval = EIPM_DELETE_IP( nl_socket, 
                                                          ip_ptr->type,
                                                          &ip_tbl_ptr->ipaddr,
                                                          ip_tbl_ptr->prefix,
                                                          ip_tbl_ptr->lsnA_idx,
                                                          "" );

                            if( retval == IPM_SUCCESS )
                            {
				os_lsnA_deleted = TRUE;
                                retval = temp_retval;
                            }
                        }

                        if( ip_tbl_ptr->lsnB_idx != -1 )
                        {
                            temp_retval = EIPM_DELETE_IP( nl_socket, 
                                                          ip_ptr->type,
                                                          &ip_tbl_ptr->ipaddr,
                                                          ip_tbl_ptr->prefix,
                                                          ip_tbl_ptr->lsnB_idx,
                                                          "" );

                            if( retval == IPM_SUCCESS )
                            {
				os_lsnB_deleted = TRUE;
                                retval = temp_retval;
                            }
                        }

                        retval = EIPM_ADD_IP( nl_socket, 
                                                   ip_ptr->type,
                                                   &ip_ptr->ipaddr,
                                                   subnet_ptr->prefixlen,
						   intfSpecDataP->lsn1_iface_indx,
                                                   ip_ptr->lsn1_iface );

                        EIPM_set_ip_config_time(ip_ptr);

                    }
                    else if( ((ip_tbl_ptr->lsnA_tentative == TRUE &&
                               ip_tbl_ptr->lsnA_idx == intfSpecDataP->lsn1_iface_indx) ||
                              (ip_tbl_ptr->lsnB_tentative == TRUE &&
                               ip_tbl_ptr->lsnB_idx == intfSpecDataP->lsn1_iface_indx)) &&
                             EIPM_check_ip_config_time(ip_ptr, EIPM_IP_CONFIG_TIMEOUT) == TRUE )
                    {
                        char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
    
                        LOG_OTHER( EIPM_LOG_IPCHK,
                                   "EIPM_check_ip_plumbing: Tentative IP %s/%d on %d - %s\n",
                                    IPM_ipaddr2p(&(ip_ptr->ipaddr), ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
                                    subnet_ptr->prefixlen,
				    intfSpecDataP->lsn1_iface_indx,
                                    ip_ptr->lsn1_iface );

                        temp_retval = EIPM_DELETE_IP( nl_socket, 
                                                      ip_ptr->type,
                                                      &ip_ptr->ipaddr,
                                                      subnet_ptr->prefixlen,
						      intfSpecDataP->lsn1_iface_indx,
                                                      ip_ptr->lsn1_iface );

                        if( retval == IPM_SUCCESS )
                        {
                            retval = temp_retval;
                        }

                        temp_retval = EIPM_ADD_IP( nl_socket, 
                                                   ip_ptr->type,
                                                   &ip_ptr->ipaddr,
                                                   subnet_ptr->prefixlen,
						   intfSpecDataP->lsn1_iface_indx,
                                                   ip_ptr->lsn1_iface );

                        EIPM_set_ip_config_time(ip_ptr);
    
                        if( retval == IPM_SUCCESS )
                        {
                            retval = temp_retval;
                        }
                    }

			//remove the additional IP on lsn0
		    if ( intfSpecDataP->lsn0_iface_indx == ip_tbl_ptr->lsnA_idx && os_lsnA_deleted == FALSE )
                    {
                        temp_retval = EIPM_DELETE_IP( nl_socket, 
                                                      ip_ptr->type,
                                                      &ip_tbl_ptr->ipaddr,
                                                      ip_tbl_ptr->prefix,
						      intfSpecDataP->lsn0_iface_indx,
                                                      intf_ptr->lsn0_baseif );

                        if( retval == IPM_SUCCESS )
                        {
                            retval = temp_retval;
                        }

                        EIPM_SET_GRAT_ARP(subnet_ptr, LSN0);
                    }

		    if ( intfSpecDataP->lsn0_iface_indx == ip_tbl_ptr->lsnB_idx && os_lsnB_deleted == FALSE )
                    {
                        temp_retval = EIPM_DELETE_IP( nl_socket, 
                                                      ip_ptr->type,
                                                      &ip_tbl_ptr->ipaddr,
                                                      ip_tbl_ptr->prefix,
						      intfSpecDataP->lsn0_iface_indx,
                                                      intf_ptr->lsn0_baseif );

                        if( retval == IPM_SUCCESS )
                        {
                            retval = temp_retval;
                        }

                    }
                } /* Check plumbed interfaces */
		else if( plumbed_interface == LSN_BOTH)
		{
			if( eipm_lsn0_populated ==  FALSE || eipm_lsn1_populated == FALSE)
			{
				LOG_ERROR(0, "Error: lsn1 or lsn0 share memory is not populated yet");
			}
			if( ( (intfSpecDataP->lsn0_iface_indx != ip_tbl_ptr->lsnA_idx) 
				&& (intfSpecDataP->lsn0_iface_indx != ip_tbl_ptr->lsnB_idx) )
				|| ( (intfSpecDataP->lsn1_iface_indx != ip_tbl_ptr->lsnA_idx)
				&& (intfSpecDataP->lsn1_iface_indx != ip_tbl_ptr->lsnB_idx) ) )
			{
			    /* lsnA doest not match SHM data, delete the IP */
			    if( ip_tbl_ptr->lsnA_idx != -1 
				&& ip_tbl_ptr->lsnA_idx != intfSpecDataP->lsn0_iface_indx
				&& ip_tbl_ptr->lsnA_idx != intfSpecDataP->lsn1_iface_indx )
			    {
						temp_retval = EIPM_DELETE_IP( nl_socket, 
										  ip_ptr->type,
										  &ip_tbl_ptr->ipaddr,
										  ip_tbl_ptr->prefix,
										  ip_tbl_ptr->lsnA_idx,
										  "" );

						if( retval == IPM_SUCCESS )
						{
							retval = temp_retval;
						}
			    }

			    /* lsnB doest not match SHM data, delete the IP */
			    if( ip_tbl_ptr->lsnB_idx != -1 
				&& ip_tbl_ptr->lsnB_idx != intfSpecDataP->lsn0_iface_indx
				&& ip_tbl_ptr->lsnB_idx != intfSpecDataP->lsn1_iface_indx )
			    {
						temp_retval = EIPM_DELETE_IP( nl_socket, 
										  ip_ptr->type,
										  &ip_tbl_ptr->ipaddr,
										  ip_tbl_ptr->prefix,
										  ip_tbl_ptr->lsnB_idx,
										  "" );

						if( retval == IPM_SUCCESS )
						{
							retval = temp_retval;
						}
			    }

				/* IP is not plumbed on lsn0_iface_indx, do it.*/
				if( intfSpecDataP->lsn0_iface_indx != ip_tbl_ptr->lsnA_idx 
					&&  intfSpecDataP->lsn0_iface_indx != ip_tbl_ptr->lsnB_idx )
				{
						temp_retval = EIPM_ADD_IP( nl_socket, 
									   ip_ptr->type,
									   &ip_ptr->ipaddr,
									   subnet_ptr->prefixlen,
									   intfSpecDataP->lsn0_iface_indx,
									   ip_ptr->lsn0_iface );

						EIPM_set_ip_config_time(ip_ptr);

						if( retval == IPM_SUCCESS )
						{
								retval = temp_retval;
						}
				}

				/* IP is not plumbed on lsn1_iface_indx, do it.*/
				if( intfSpecDataP->lsn1_iface_indx != ip_tbl_ptr->lsnA_idx
					&&  intfSpecDataP->lsn1_iface_indx != ip_tbl_ptr->lsnB_idx )
				{
						temp_retval = EIPM_ADD_IP( nl_socket, 
									   ip_ptr->type,
									   &ip_ptr->ipaddr,
									   subnet_ptr->prefixlen,
									   intfSpecDataP->lsn1_iface_indx,
									   ip_ptr->lsn1_iface );

						EIPM_set_ip_config_time(ip_ptr);

						if( retval == IPM_SUCCESS )
						{
							retval = temp_retval;
						}
				}

			}
			//Although the IPs are in tentative status,  still replumb the IPs
			else if( ((ip_tbl_ptr->lsnA_tentative == TRUE &&
				   (ip_tbl_ptr->lsnA_idx == intfSpecDataP->lsn0_iface_indx || 
				    ip_tbl_ptr->lsnA_idx == intfSpecDataP->lsn1_iface_indx)) ||
				  (ip_tbl_ptr->lsnB_tentative == TRUE &&
				   (ip_tbl_ptr->lsnB_idx == intfSpecDataP->lsn0_iface_indx || 
				    ip_tbl_ptr->lsnB_idx == intfSpecDataP->lsn1_iface_indx ))) &&
				 EIPM_check_ip_config_time(ip_ptr, EIPM_IP_CONFIG_TIMEOUT) == TRUE )
			{
				char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
				char ipm_ipstr_buf1[IPM_IPMAXSTRSIZE];
	    
				LOG_OTHER( EIPM_LOG_IPCHK,
					   "EIPM_check_ip_plumbing: Tentative IP %s/%d on %d - %s, or %s/%d on %d - %s\n",
					    IPM_ipaddr2p(&(ip_ptr->ipaddr), ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
					    subnet_ptr->prefixlen,
					    intfSpecDataP->lsn1_iface_indx,
					    ip_ptr->lsn1_iface,
					    IPM_ipaddr2p(&(ip_ptr->ipaddr), ipm_ipstr_buf1, sizeof(ipm_ipstr_buf1)),
					    subnet_ptr->prefixlen,
					    intfSpecDataP->lsn0_iface_indx,
					    ip_ptr->lsn0_iface );

				if(ip_tbl_ptr->lsnA_idx != -1 
					&& ip_tbl_ptr->lsnA_tentative == TRUE)
				{
					temp_retval = EIPM_DELETE_IP( nl_socket, 
								      ip_ptr->type,
								      &ip_tbl_ptr->ipaddr,
								      ip_tbl_ptr->prefix,
								      ip_tbl_ptr->lsnA_idx,
								      "" );
					if( retval == IPM_SUCCESS )
					{
					    retval = temp_retval;
					}
					/* Plumb IP when lsnA_idx match SHM, otherwise do nothing */
					if( ip_tbl_ptr->lsnA_idx == intfSpecDataP->lsn0_iface_indx )
					{
							temp_retval = EIPM_ADD_IP( nl_socket, 
										   ip_ptr->type,
										   &ip_ptr->ipaddr,
										   subnet_ptr->prefixlen,
										   intfSpecDataP->lsn0_iface_indx,
										   ip_ptr->lsn0_iface );


							if( retval == IPM_SUCCESS )
							{
									retval = temp_retval;
							}
					}
					else if(ip_tbl_ptr->lsnA_idx == intfSpecDataP->lsn1_iface_indx)
					{
							temp_retval = EIPM_ADD_IP( nl_socket, 
										   ip_ptr->type,
										   &ip_ptr->ipaddr,
										   subnet_ptr->prefixlen,
										   intfSpecDataP->lsn1_iface_indx,
										   ip_ptr->lsn1_iface );


							if( retval == IPM_SUCCESS )
							{
									retval = temp_retval;
							}
					}
				}
				if(ip_tbl_ptr->lsnB_idx != -1 
					&& ip_tbl_ptr->lsnB_tentative == TRUE)
				{
					temp_retval = EIPM_DELETE_IP( nl_socket, 
								      ip_ptr->type,
								      &ip_tbl_ptr->ipaddr,
								      ip_tbl_ptr->prefix,
								      ip_tbl_ptr->lsnB_idx,
								      "" );
					if( retval == IPM_SUCCESS )
					{
					    retval = temp_retval;
					}
					/* Plumb IP when lsnB_idx match SHM, otherwise do nothing */
					if( ip_tbl_ptr->lsnB_idx == intfSpecDataP->lsn0_iface_indx )
					{
							temp_retval = EIPM_ADD_IP( nl_socket, 
										   ip_ptr->type,
										   &ip_ptr->ipaddr,
										   subnet_ptr->prefixlen,
										   intfSpecDataP->lsn0_iface_indx,
										   ip_ptr->lsn0_iface );


							if( retval == IPM_SUCCESS )
							{
									retval = temp_retval;
							}
					}
					else if(ip_tbl_ptr->lsnB_idx == intfSpecDataP->lsn1_iface_indx)
					{
							temp_retval = EIPM_ADD_IP( nl_socket, 
										   ip_ptr->type,
										   &ip_ptr->ipaddr,
										   subnet_ptr->prefixlen,
										   intfSpecDataP->lsn1_iface_indx,
										   ip_ptr->lsn1_iface );


							if( retval == IPM_SUCCESS )
							{
									retval = temp_retval;
							}
					}
				}
			}
		}
		else
		{
			LOG_ERROR(0, "Error: invalid value for plumbed_interface %d\n", plumbed_interface);
		}

            } /* Check if entry in table */

    return retval;
}


/**********************************************************************
 *
 * Name:        EIPM_read_iptable()
 *
 * Abstract:    Populate IP table for given interface via netlink socket
 *
 * Parameters:  nl_socket - netlink socket
 *              intf_ptr - interface data
 *              ip_tbl_ptr - table to populate
 *		proxyclient_ip_tbl_ptr - table to populate
 *
 * Returns:     IPM_SUCCESS - IP table was successfully populated
 *              IPM_FAILURE - some error occurred.
 *
 **********************************************************************/

int
EIPM_read_iptable( int nl_socket, int family, void *intfDataP, EIPM_INTF_TYPE intfType, IPM_IPTBL *ip_tbl_ptr, IPM_IPTBL *proxyclient_ip_tbl_ptr )
{
EIPM_INTF *intf_ptr = NULL;
EIPM_INTF_SPEC *intfSpecDataP = NULL;
struct sockaddr_nl peer;
struct msghdr msg_info;
struct iovec iov_info;
struct in_addr ipaddr;
struct {
        struct nlmsghdr         nlmsg_info;
        struct ifaddrmsg        ifaddrmsg_info;
} netlink_req;

struct ifaddrmsg *ifaddrmsg_ptr;
struct rtattr *rtattr_ptr;
struct nlmsghdr *nlmsg_ptr;

IPM_IPADDR ip;

int retval;
int nlmsg_len;
int l_nl_socket;
struct sockaddr_nl nladdr;
int ifaddrmsg_len;
int ip_cnt_idx;
int loopcnt;
int errcnt;

char *read_ptr;

char name_str[EI_INTFNAMESIZE];
char ipaddr_str[IPM_IPMAXSTRSIZE];
char localaddr_str[IPM_IPMAXSTRSIZE];
char bcastaddr_str[IPM_IPMAXSTRSIZE];
unsigned long long read_buf_size;
const int       max_read_buf_size = 65535;               
char		read_buffer[max_read_buf_size];
char            total_read_buf[IPM_IP_TBL_RD_SZ]; 
char            *total_read_buf_ptr;

    if (intf_ptr != NULL)
    {
    	intfSpecDataP = &(intf_ptr->specData);
    }
    if ( intfDataP != NULL )
    {
        EIPM_SET_INTF_PTRS( intfDataP, intfType, intf_ptr, intfSpecDataP );

        if ( NULL == intf_ptr )
        {
            return IPM_FAILURE;
        }
    }

	l_nl_socket = socket( PF_NETLINK, SOCK_RAW, NETLINK_ROUTE );

	if( l_nl_socket < 0 )
	{
		ASRT_RPT( ASUNEXP_RETURN,
			1,
			sizeof(*intf_ptr),
			intf_ptr,
			"EIPM_read_iptable: Failed to create routing socket\nretval=%d, errno=0x%x; intf_ptr dumped\n",
			l_nl_socket,
			errno );

		return( IPM_FAILURE );
	}

	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pad = 0;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;
	retval = bind( l_nl_socket, (struct sockaddr *)&nladdr, sizeof( nladdr ) );

	if( retval < 0 )
	{
		ASRT_RPT( ASUNEXP_RETURN,
			1,
			sizeof(*intf_ptr),
			intf_ptr,
			"EIPM_read_iptable: Failed to bind to routing socket\nretval=%d, errno=0x%x; intf_ptr dumped\n",
			retval, 
			errno );

		(void)close( l_nl_socket );

		return( IPM_FAILURE );
	}
    /* 
     * Send request to read table
     */
    bzero(&netlink_req, sizeof(netlink_req));

    netlink_req.nlmsg_info.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    netlink_req.nlmsg_info.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    netlink_req.nlmsg_info.nlmsg_type = RTM_GETADDR;
    netlink_req.nlmsg_info.nlmsg_pid = getpid();
    netlink_req.nlmsg_info.nlmsg_seq = IPM_ip_seq++;

    netlink_req.ifaddrmsg_info.ifa_family = family;

    bzero(&peer, sizeof(peer));
    peer.nl_family = AF_NETLINK;
    peer.nl_pad = 0;
    peer.nl_pid = 0;
    peer.nl_groups = 0;

    iov_info.iov_base = (void *) &netlink_req.nlmsg_info;
    iov_info.iov_len = netlink_req.nlmsg_info.nlmsg_len;

    bzero(&msg_info, sizeof(msg_info));
    msg_info.msg_name = (void *) &peer;
    msg_info.msg_namelen = sizeof(peer);
    msg_info.msg_iov = &iov_info;
    msg_info.msg_iovlen = 1;

    retval = sendmsg(l_nl_socket, &msg_info, 0);

    if( retval < 0 )
    {
        ASRT_RPT( ASUNEXP_RETURN,
                  2,
                  sizeof(msg_info),
                  &msg_info,
                  sizeof(netlink_req),
                  &netlink_req,
                  "EIPM_read_iptable: sendmsg() failed retval %d errno 0x%x\n", retval, errno );
	(void)close( l_nl_socket );

        return( IPM_FAILURE );
    }

	
    /*
     * Now receive the response.  We may get multiple messages
     * to retrieve the entire routing table.
     */
    bzero(read_buffer, sizeof(read_buffer));
    bzero( total_read_buf, IPM_IP_TBL_RD_SZ );

    read_ptr = read_buffer;
    nlmsg_len = 0;
    total_read_buf_ptr = total_read_buf;
    read_buf_size = 0;

    /*
     * We need to loop to get all the messages, but we cannot
     * loop forever.
     */
    for( loopcnt = 0, errcnt = 0;
         (loopcnt < IPM_IP_RD_LP_CNT) && (errcnt < 2);
         loopcnt++  )
    {
        retval = recv( l_nl_socket, read_ptr, sizeof(read_buffer) - nlmsg_len, 0);

        if( retval < 0 ) 
        {
            if( errno == EAGAIN )
            {
                /*
                 * No response.
                 *
                 * Setup timeout for 5 usec (nsec=5000)
                 * and try again.  Increment the error
                 * count so we don't repeatedly do this.
                 */
                struct timespec sel_time;

                errcnt++;
				
                sel_time.tv_sec  = 0;
                sel_time.tv_nsec = 5000;
                nanosleep(&sel_time, 0);
				
                continue;
            }
				
            ASRT_RPT( ASUNEXP_RETURN,
                      1,
                      sizeof(nlmsg_len),
                      &nlmsg_len,
                      "Error: EIPM_read_iptable - recv() failed,socket = %d, errno=%d\n",
                       l_nl_socket, errno );
			
		(void)close( l_nl_socket );
            return( IPM_FAILURE );
        }
		
        /*
         * Get a pointer to the data read.
         */
        nlmsg_ptr = (struct nlmsghdr *)read_ptr;
			
        /*
         * Have we received the last message?
         */
        if(nlmsg_ptr->nlmsg_type == NLMSG_DONE)
        {
	    if ( ( read_buf_size + ( nlmsg_len + retval ) ) >= IPM_IP_TBL_RD_SZ )
            {
                /* Received more data than allocated space for. */
                ASRT_RPT( ASUNEXPECTEDVAL, 0,
                          "ALL RCVD: Received more data (%d + %d + %llu) than allocated %d\n",
                          nlmsg_len,
                          retval,
                          read_buf_size,
                          IPM_IP_TBL_RD_SZ );
			
		(void)close( l_nl_socket );
		return IPM_FAILURE;
            }
            else
            {
                memcpy( total_read_buf_ptr, read_buffer, ( nlmsg_len + retval ) );
                read_buf_size = read_buf_size + ( nlmsg_len + retval );
		total_read_buf_ptr = total_read_buf_ptr + ( nlmsg_len + retval );
		/*
		 * When reading IP data from kernel, 
		 * if the netlink message type is NLMSG_DONE, then the retval is 20
		 * and there is no IP data in it. Therefore, don't include it in 
		 * total IP data
		 */
		nlmsg_len = read_buf_size - retval;
            }

            break;
        }
		
        /*
         * We want the next message to be added to
         * the buffer in order.
         */
        read_ptr = read_ptr + retval;
		
        /*
         * Save how many bytes have been received.
         */
       /*
         * If there are more IPs in kernel, then it will copy from kernel to
         * user space per one page per time. So if the left size in max_read_buf_size
         * is less than one page, then the rest data will be lost.
         * Therefore, before each reading, the below code is to make sure the available
         * buffer size is one page
         */
	if ( ( nlmsg_len + retval + getpagesize() ) >= max_read_buf_size )
        {

            if ( ( read_buf_size + ( nlmsg_len + retval ) ) >= IPM_IP_TBL_RD_SZ )
            {
                /* Received more data than allocated space for. */
                ASRT_RPT( ASUNEXPECTEDVAL, 0,
                          "ALL NOT RCVD: Received more data (%d + %d + %llu) than allocated %d\n",
                          nlmsg_len,
                          retval,
                          read_buf_size,
                          IPM_IP_TBL_RD_SZ );
		(void)close( l_nl_socket );
			
		return IPM_FAILURE;
            }
            else
            {
                memcpy( total_read_buf_ptr, read_buffer, ( nlmsg_len + retval ) );
                total_read_buf_ptr = total_read_buf_ptr + ( nlmsg_len + retval );
                read_buf_size = read_buf_size + ( nlmsg_len + retval );
                bzero( read_buffer, max_read_buf_size );
                nlmsg_len = 0;
                read_ptr = read_buffer;
            }
        }
        else
        {
            nlmsg_len = nlmsg_len + retval;
        }
		
    } /* end 'for loop on recv()' */
	
    if( loopcnt >= IPM_IP_RD_LP_CNT )
    {
        /*
         * We have not received the last message.
         */
        LOG_ERROR( 0,
                   "Error - EIPM_read_iptable: did not receive last message in %d attempts",
                    IPM_IP_RD_LP_CNT );
		
	(void)close( l_nl_socket );
        return( IPM_FAILURE );
    }

	(void)close( l_nl_socket );

    /*
     * Now loop through to parse and store the received data.
     */
    nlmsg_ptr = (struct nlmsghdr *)total_read_buf;

    retval = IPM_SUCCESS;

    for(; NLMSG_OK(nlmsg_ptr, nlmsg_len); nlmsg_ptr = NLMSG_NEXT(nlmsg_ptr, nlmsg_len)) 
    {
        ifaddrmsg_ptr = (struct ifaddrmsg *) NLMSG_DATA(nlmsg_ptr);

        bzero(name_str, EI_INTFNAMESIZE);
        bzero(ipaddr_str, IPM_IPMAXSTRSIZE);
        bzero(localaddr_str, IPM_IPMAXSTRSIZE);
        bzero(bcastaddr_str, IPM_IPMAXSTRSIZE);

        rtattr_ptr = (struct rtattr *) IFA_RTA(ifaddrmsg_ptr);

        ifaddrmsg_len = IFA_PAYLOAD(nlmsg_ptr);

        for(;RTA_OK(rtattr_ptr, ifaddrmsg_len); rtattr_ptr = RTA_NEXT(rtattr_ptr, ifaddrmsg_len)) 
        {
            switch(rtattr_ptr->rta_type) 
            {
            case IFA_ADDRESS:
                inet_ntop(family, RTA_DATA(rtattr_ptr), ipaddr_str, IPM_IPMAXSTRSIZE);
                break;

            case IFA_LOCAL:
                inet_ntop(family, RTA_DATA(rtattr_ptr), localaddr_str, IPM_IPMAXSTRSIZE);
                break;

            case IFA_LABEL:
                sprintf(name_str, "%s", (char *) RTA_DATA(rtattr_ptr));
                break;

            case IFA_BROADCAST:
                inet_ntop(family, RTA_DATA(rtattr_ptr), bcastaddr_str, IPM_IPMAXSTRSIZE);
                break;

            default:
                break; 
            }
        }

        LOG_DEBUG(0,
                  "EIPM_read_iptable: OS entry IP %s/%d, dev %s %d\n",
                   (ipaddr_str == NULL) ? "NULL IP" : ipaddr_str, ifaddrmsg_ptr->ifa_prefixlen,
                   (name_str == NULL) ? "NULL DEV" : name_str, ifaddrmsg_ptr->ifa_index);

	if (    ( intfSpecDataP != NULL )
             && ( intfSpecDataP->lsn0_iface_indx != ifaddrmsg_ptr->ifa_index ) 
             && ( intfSpecDataP->lsn1_iface_indx != ifaddrmsg_ptr->ifa_index ) )
        {
	    //for pivot, its interface is not lsn0/lsn1 iface index. - save it in another ip table
            if (proxyclient_ip_tbl_ptr == NULL || strlen(ipaddr_str) == 0)
            {
                continue;
            }

            IPM_ipaddr_init(&ip);

            if( IPM_p2ipaddr(ipaddr_str, &ip) != IPM_SUCCESS )
            {
                LOG_ERROR(0, "EIPM_read_iptable: Failed to translate OS entry %s\n", ipaddr_str);
                continue;
            }

	    /* Add new entry */
            proxyclient_ip_tbl_ptr->ip_table[proxyclient_ip_tbl_ptr->ip_cnt].ipaddr = ip;
            proxyclient_ip_tbl_ptr->ip_table[proxyclient_ip_tbl_ptr->ip_cnt].prefix = ifaddrmsg_ptr->ifa_prefixlen;
            proxyclient_ip_tbl_ptr->ip_table[proxyclient_ip_tbl_ptr->ip_cnt].lsnA_idx = ifaddrmsg_ptr->ifa_index;
            proxyclient_ip_tbl_ptr->ip_table[proxyclient_ip_tbl_ptr->ip_cnt].lsnA_tentative =
                    ((ifaddrmsg_ptr->ifa_flags & IFA_F_TENTATIVE) == IFA_F_TENTATIVE) ? TRUE : FALSE;
            strncpy(proxyclient_ip_tbl_ptr->ip_table[proxyclient_ip_tbl_ptr->ip_cnt].lsnA_iface, name_str, EI_INTFNAMESIZE);
            proxyclient_ip_tbl_ptr->ip_table[proxyclient_ip_tbl_ptr->ip_cnt].lsnB_idx = -1;
            proxyclient_ip_tbl_ptr->ip_table[proxyclient_ip_tbl_ptr->ip_cnt].lsnB_tentative = FALSE;
            proxyclient_ip_tbl_ptr->ip_table[proxyclient_ip_tbl_ptr->ip_cnt].lsnB_iface[0] = '\0';
            proxyclient_ip_tbl_ptr->ip_cnt++;

            /*
            * Check for additional room in the table
            */
            if( proxyclient_ip_tbl_ptr->ip_cnt >= IPM_IP_TBL_SZ)
            {
                ASRT_RPT( ASMISSING_DATA, 1,
			sizeof(*proxyclient_ip_tbl_ptr),
                        proxyclient_ip_tbl_ptr,
                        "EIPM_read_iptable: IP Table too small ip_cnt %d, nlmsg_len %d\n",
			proxyclient_ip_tbl_ptr->ip_cnt, nlmsg_len );
		break;
            }

            continue;
        }

        IPM_ipaddr_init(&ip);

        if( IPM_p2ipaddr(ipaddr_str, &ip) != IPM_SUCCESS )
        {
            LOG_ERROR(0, 
                 "EIPM_read_iptable: Failed to translate OS entry %s\n", ipaddr_str);

            continue;
        }

        /* Look for existing entry */
        for( ip_cnt_idx = 0; 
             ip_cnt_idx < ip_tbl_ptr->ip_cnt;
             ip_cnt_idx++ )
        {
            if( IPM_IPCMPADDR(&ip_tbl_ptr->ip_table[ip_cnt_idx].ipaddr, &ip) == IPM_SUCCESS )
            {
                /* Update existing entry */
                ip_tbl_ptr->ip_table[ip_cnt_idx].lsnB_idx = ifaddrmsg_ptr->ifa_index;
                ip_tbl_ptr->ip_table[ip_cnt_idx].lsnB_tentative = 
                    ((ifaddrmsg_ptr->ifa_flags & IFA_F_TENTATIVE) == IFA_F_TENTATIVE) ? TRUE : FALSE;

                strncpy(ip_tbl_ptr->ip_table[ip_cnt_idx].lsnB_iface, name_str, EI_INTFNAMESIZE);

                break;
            }
        }

        if( ip_cnt_idx != ip_tbl_ptr->ip_cnt )
        {
            continue;
        }

        /* Add new entry */
        ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].ipaddr = ip;
        ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].prefix = ifaddrmsg_ptr->ifa_prefixlen;

        ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnA_idx = ifaddrmsg_ptr->ifa_index;
        ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnA_tentative = 
            ((ifaddrmsg_ptr->ifa_flags & IFA_F_TENTATIVE) == IFA_F_TENTATIVE) ? TRUE : FALSE;
        strncpy(ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnA_iface, name_str, EI_INTFNAMESIZE);

        ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnB_idx = -1;
        ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnB_tentative = FALSE;
        ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnB_iface[0] = '\0';

        ip_tbl_ptr->ip_cnt++;

        /*
         * Check for additional room in the table
         */
        if( ip_tbl_ptr->ip_cnt >= IPM_IP_TBL_SZ)
        {
            ASRT_RPT( ASMISSING_DATA,
                      1,
                      sizeof(*ip_tbl_ptr),
                      ip_tbl_ptr,
                      "EIPM_read_iptable: IP Table too small ip_cnt %d, nlmsg_len %d\n", ip_tbl_ptr->ip_cnt, nlmsg_len );

            break;
        }
    }

    return retval;
}



/**********************************************************************
 *
 * Name:        EIPM_read_arptable()
 *
 * Abstract:    Populate ARP table for given interface via netlink socket
 *
 * Parameters:  nl_socket - netlink socket
 *              intf_ptr - interface data
 *              ip_tbl_ptr - table to populate
 *
 * Returns:     IPM_SUCCESS - IP table was successfully populated
 *              IPM_FAILURE - some error occurred.
 *
 **********************************************************************/

#define PATH_PROCNET_ARP "/proc/net/arp"

#ifndef NDA_PAYLOAD
#define NDA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ndmsg))
#endif

#ifndef NDA_RTA
#define NDA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

int
EIPM_read_arptable( int nl_socket, int family, void *intfDataP, EIPM_INTF_TYPE intfType, IPM_IPTBL *ip_tbl_ptr )
{
#if 0
    if( family == AF_INET6 )
    {
#endif
        EIPM_INTF *intf_ptr = NULL;
        EIPM_INTF_SPEC *intfSpecDataP = NULL;
        struct sockaddr_nl peer;
        struct msghdr msg_info;
        struct iovec iov_info;
        struct in_addr ipaddr;
        struct {
            struct nlmsghdr     nlmsg_info;
            struct ndmsg        ndmsg_info;
        } netlink_req;

        struct nlmsghdr *nlmsghdr_ptr;
        struct ndmsg    *ndmsg_ptr;
        struct rtattr   *rtattr_ptr;

	int l_nl_socket;
	struct sockaddr_nl nladdr;
        int retval;
        int nlmsg_len;
        int ndamsg_len;
        int ip_cnt_idx;
        int loopcnt;
        int errcnt;

        char *read_ptr;

        IPM_IPADDR ip;
        char ipaddr_str[IPM_IPMAXSTRSIZE];
	unsigned long long      read_buf_size;
        const int               max_read_buf_size = 65535;               
        char		        read_buffer[max_read_buf_size];
        char                    total_read_buf[IPM_IP_TBL_RD_SZ]; 
        char                    *total_read_buf_ptr;

	if (intf_ptr != NULL)
	{
    		intfSpecDataP = &(intf_ptr->specData);
	}

	if ( intfDataP != NULL )
        {
                EIPM_SET_INTF_PTRS( intfDataP, intfType, intf_ptr, intfSpecDataP );

                if ( NULL == intf_ptr )
                {
                        return IPM_FAILURE;
                }
        }

	if (( family != AF_INET6 ) && ( family != AF_INET ))
	{
		LOG_ERROR(0,
                     "EIPM_read_arptable: Invalid Parameter family = %d\n", family);
		return IPM_FAILURE;
	}
	l_nl_socket = socket( PF_NETLINK, SOCK_RAW, NETLINK_ROUTE );

	if( l_nl_socket < 0 )
	{
		ASRT_RPT( ASUNEXP_RETURN,
			1,
			sizeof(*intf_ptr),
			intf_ptr,
			"EIPM_read_arptable: Failed to create routing socket\nretval=%d, errno=0x%x; intf_ptr dumped\n",
			l_nl_socket,
			errno );

		return( IPM_FAILURE );
	}

	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pad = 0;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;
	retval = bind( l_nl_socket, (struct sockaddr *)&nladdr, sizeof( nladdr ) );

	if( retval < 0 )
	{
		ASRT_RPT( ASUNEXP_RETURN,
			1,
			sizeof(*intf_ptr),
			intf_ptr,
			"EIPM_read_arptable: Failed to bind to routing socket\nretval=%d, errno=0x%x; intf_ptr dumped\n",
			retval, 
			errno );

		(void)close( l_nl_socket );

		return( IPM_FAILURE );
	}

        /* 
         * Send request to read table
         */
        bzero(&netlink_req, sizeof(netlink_req));

        netlink_req.nlmsg_info.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
        netlink_req.nlmsg_info.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH;
        netlink_req.nlmsg_info.nlmsg_type = RTM_GETNEIGH;
        netlink_req.nlmsg_info.nlmsg_pid = getpid();
        netlink_req.nlmsg_info.nlmsg_seq = IPM_ip_seq++;

        netlink_req.ndmsg_info.ndm_family = family;
        netlink_req.ndmsg_info.ndm_state = NUD_PERMANENT;
        netlink_req.ndmsg_info.ndm_flags = NTF_PROXY;
        // netlink_req.ndmsg_info.ndm_ifindex = iface_idx;


        bzero(&peer, sizeof(peer));
        peer.nl_family = AF_NETLINK;
        peer.nl_pad = 0;
        peer.nl_pid = 0;
        peer.nl_groups = 0;

        iov_info.iov_base = (void *) &netlink_req.nlmsg_info;
        iov_info.iov_len = netlink_req.nlmsg_info.nlmsg_len;

        bzero(&msg_info, sizeof(msg_info));
        msg_info.msg_name = (void *) &peer;
        msg_info.msg_namelen = sizeof(peer);
        msg_info.msg_iov = &iov_info;
        msg_info.msg_iovlen = 1;

        retval = sendmsg(l_nl_socket, &msg_info, 0);

        if( retval < 0 )
        {
            ASRT_RPT( ASUNEXP_RETURN,
                      2,
                      sizeof(msg_info),
                      &msg_info,
                      sizeof(netlink_req),
                      &netlink_req,
                      "EIPM_read_arptable: sendmsg() failed retval %d errno 0x%x\n", retval, errno );

	    (void)close( l_nl_socket );
            return IPM_FAILURE;
        }

        /*
         * Now receive the response.  We may get multiple messages
         * to retrieve the entire routing table.
         */
        bzero(read_buffer, sizeof(read_buffer));
	bzero( total_read_buf, IPM_IP_TBL_RD_SZ );
        read_ptr = read_buffer;

        nlmsg_len = 0;
	total_read_buf_ptr = total_read_buf;
        read_buf_size = 0;

        /*
         * We need to loop to get all the messages, but we cannot
         * loop forever.
         */
        for( loopcnt = 0, errcnt = 0;
             (loopcnt < IPM_IP_RD_LP_CNT) && (errcnt < 2);
             loopcnt++  )
        {
            retval = recv(l_nl_socket, read_ptr, sizeof(read_buffer) - nlmsg_len, 0);

            if( retval < 0 ) 
            {
                if( errno == EAGAIN )
                {
                    /*
                     * No response.
                     *
                     * Setup timeout for 5 usec (nsec=5000)
                     * and try again.  Increment the error
                     * count so we don't repeatedly do this.
                     */
                    struct timespec sel_time;

                    errcnt++;
				
                    sel_time.tv_sec  = 0;
                    sel_time.tv_nsec = 5000;
                    nanosleep(&sel_time, 0);
				
                    continue;
                }
				
                ASRT_RPT( ASUNEXP_RETURN,
                          1,
                          sizeof(nlmsg_len),
                          &nlmsg_len,
                          "Error: EIPM_read_arptable - recv() failed, socket = %d, errno=%d\n",
                           l_nl_socket, errno );
			
		(void)close( l_nl_socket );
                return( IPM_FAILURE );
            }
		
            /*
             * Get a pointer to the data read.
             */
            nlmsghdr_ptr = (struct nlmsghdr *)read_ptr;
			
            /*
             * Have we received the last message?
             */
            if(nlmsghdr_ptr->nlmsg_type == NLMSG_DONE)
            {
		if ( ( read_buf_size + ( nlmsg_len + retval ) ) >= IPM_IP_TBL_RD_SZ )
                {
                    /* Received more data than allocated space for. */
		    LOG_ERROR( 0,
		  	       "ERROR(%s): Received more data (%d + %d + %llu) than allocated %d\n",
                               (char *)(__func__),
			       nlmsg_len,
                               retval,
                               read_buf_size,
                               IPM_IP_TBL_RD_SZ );
			
			(void)close( l_nl_socket );
		    return IPM_FAILURE;
                }
                else
                {
                    memcpy( total_read_buf_ptr, read_buffer, ( nlmsg_len + retval ) );
                    read_buf_size = read_buf_size + ( nlmsg_len + retval );
		    total_read_buf_ptr = total_read_buf_ptr + ( nlmsg_len + retval );
                }

                break;
            }
		
            /*
             * We want the next message to be added to
             * the buffer in order.
             */
            read_ptr = read_ptr + retval;
		
            /*
             * Save how many bytes have been received.
             */
	    if ( ( nlmsg_len + retval ) >= max_read_buf_size )
            {

                if ( ( read_buf_size + ( nlmsg_len + retval ) ) >= IPM_IP_TBL_RD_SZ )
                {
                    /* Received more data than allocated space for. */
		    LOG_ERROR( 0,
		   	       "ERROR(%s): Received more data (%d + %d + %llu) than allocated %d\n",
                               (char *)(__func__),
			       nlmsg_len,
                               retval,
                               read_buf_size,
                               IPM_IP_TBL_RD_SZ );
			
		(void)close( l_nl_socket );
		    return IPM_FAILURE;
                }
                else
                {
                    memcpy( total_read_buf_ptr, read_buffer, ( nlmsg_len + retval ) );
                    total_read_buf_ptr = total_read_buf_ptr + ( nlmsg_len + retval );
                    read_buf_size = read_buf_size + ( nlmsg_len + retval );
                    bzero( read_buffer, max_read_buf_size );
                    nlmsg_len = 0;
                    read_ptr = read_buffer;
                }
            }
            else
            {
                nlmsg_len = nlmsg_len + retval;
            }
		
        } /* end 'for loop on recv()' */
	
        if( loopcnt >= IPM_IP_RD_LP_CNT )
        {
            /*
             * We have not received the last message.
             */
            LOG_ERROR( 0,
                       "Error - EIPM_read_arptable: did not receive last message in %d attempts",
                        IPM_IP_RD_LP_CNT );
		
		(void)close( l_nl_socket );
            return( IPM_FAILURE );
        }

	(void)close(l_nl_socket);
        /*
         * Now loop through to parse and store the received data.
         */
	nlmsghdr_ptr = (struct nlmsghdr *)total_read_buf;

        for(; NLMSG_OK(nlmsghdr_ptr, nlmsg_len); nlmsghdr_ptr = NLMSG_NEXT(nlmsghdr_ptr, nlmsg_len)) 
        {
            ndamsg_len = NDA_PAYLOAD(nlmsghdr_ptr);

            ndmsg_ptr = (struct ndmsg *)NLMSG_DATA(nlmsghdr_ptr);

#if 0
            if( ndmsg_ptr->ndm_type != RTN_UNICAST )
            {
                continue;
            }
#endif

	    if (    ( intfSpecDataP != NULL )
                 && ( intfSpecDataP->lsn0_iface_indx != ndmsg_ptr->ndm_ifindex ) 
                 && ( intfSpecDataP->lsn1_iface_indx != ndmsg_ptr->ndm_ifindex ) )
            {
                continue;
            }

            bzero(ipaddr_str, IPM_IPMAXSTRSIZE);

            rtattr_ptr = NDA_RTA(ndmsg_ptr);

            for(;RTA_OK(rtattr_ptr, ndamsg_len); rtattr_ptr = RTA_NEXT(rtattr_ptr, ndamsg_len))
            {
                switch(rtattr_ptr->rta_type)
                {
                case NDA_DST:
                    inet_ntop(family, RTA_DATA(rtattr_ptr), ipaddr_str, IPM_IPMAXSTRSIZE);
                    break;

                case NDA_LLADDR:
                    break;

                case NDA_CACHEINFO:
                    // nda_cacheinfo
                    break;

                case NDA_PROBES:
                    break;

                default:
                    break;
                }
            }

            IPM_ipaddr_init(&ip);

            if( IPM_p2ipaddr(ipaddr_str, &ip) != IPM_SUCCESS )
            {
                LOG_ERROR(0,
                     "EIPM_read_iptable: Failed to translate OS entry %s\n", ipaddr_str);

                continue;
            }

            LOG_DEBUG(0,
                      "EIPM_read_arptable: OS entry IP %s, dev %d, state %d, flags %d\n",
                       ipaddr_str,
                       ndmsg_ptr->ndm_ifindex,
                       ndmsg_ptr->ndm_state,
                       ndmsg_ptr->ndm_flags);

            /* Look for existing entry */
            for( ip_cnt_idx = 0;
                 ip_cnt_idx < ip_tbl_ptr->ip_cnt;
                 ip_cnt_idx++ )
            {
                if( IPM_IPCMPADDR(&ip_tbl_ptr->ip_table[ip_cnt_idx].ipaddr, &ip) == IPM_SUCCESS )
                {
                    /* Update existing entry */
                    ip_tbl_ptr->ip_table[ip_cnt_idx].lsnB_idx = ndmsg_ptr->ndm_ifindex;
                    ip_tbl_ptr->ip_table[ip_cnt_idx].lsnB_tentative = 0;
		    snprintf( ip_tbl_ptr->ip_table[ip_cnt_idx].lsnB_iface, EI_INTFNAMESIZE, "%s%s",
                              ( ( ndmsg_ptr->ndm_ifindex == intfSpecDataP->lsn0_iface_indx )
                                ? intf_ptr->lsn0_baseif : intf_ptr->lsn1_baseif ),
                              ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

                    break;
                }
            }

            if( ip_cnt_idx != ip_tbl_ptr->ip_cnt )
            {
                continue;
            }

            /* Add new entry */
            ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].ipaddr = ip;
            ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].prefix = 0;;

            ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnA_idx = ndmsg_ptr->ndm_ifindex;
            ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnA_tentative = 0;
	    snprintf( ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnA_iface, EI_INTFNAMESIZE, "%s%s",
                      ( ( ndmsg_ptr->ndm_ifindex == intfSpecDataP->lsn0_iface_indx )
                        ? intf_ptr->lsn0_baseif : intf_ptr->lsn1_baseif ),
                      ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

            ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnB_idx = -1;
            ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnB_tentative = 0;
            ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnB_iface[0] = '\0';

            ip_tbl_ptr->ip_cnt++;

            /*
             * Check for additional room in the table
             */
            if( ip_tbl_ptr->ip_cnt >= IPM_IP_TBL_SZ )
            {
                ASRT_RPT( ASMISSING_DATA,
                          1,
                          sizeof(*ip_tbl_ptr),
                          ip_tbl_ptr,
                          "EIPM_read_arptable: IP Table too small ip_cnt %d, nlmsg_len %d\n", ip_tbl_ptr->ip_cnt, nlmsg_len );

                break;
            }
        }

        return IPM_SUCCESS;
#if 0
    }
    else
    {
        FILE *fp;
        IPM_IPADDR ip;
        char ipaddr_str[IPM_IPMAXSTRSIZE];
        char dev[IFNAMSIZ];
        char hwa[100];
        char mask[100];
        char line[200];
        int type, flags;
        int ip_cnt_idx, iface_idx;

        /* Open the kernel table */
        if( (fp = fopen(PATH_PROCNET_ARP, "r")) == NULL )
        {
            return IPM_FAILURE;
        }

        /* Bypass header */
        if( fgets(line, sizeof(line), fp) == (char *)NULL )
        {
            (void)fclose(fp);

            return IPM_FAILURE;
        }

        /* Read the ARP cache entries */
        while(1)
        {
            if( fgets(line, sizeof(line), fp) == (char *)NULL )
            {
                break;
            }

            if( sscanf(line, "%s 0x%x 0x%x %100s %100s %100s\n",
                       ipaddr_str, &type, &flags, hwa, mask, dev) < 4)
            {
                break;
            }

            if( strstr(dev, intf_ptr->lsn0_baseif) != 0 )
            {
                iface_idx = intf_ptr->lsn0_iface_indx;
            }
            else if( strstr(dev, intf_ptr->lsn1_baseif) != 0 )
            {
                iface_idx = intf_ptr->lsn1_iface_indx;
            }
            else
            {
                continue;
            }

            IPM_ipaddr_init(&ip);

            if( IPM_p2ipaddr(ipaddr_str, &ip) != IPM_SUCCESS )
            {
                LOG_ERROR(0,
                     "EIPM_read_iptable: Failed to translate OS entry %s\n", ipaddr_str);

                continue;
            }

            if( family == AF_INET && ip.addrtype != IPM_IPV4 ||
                family == AF_INET6 && ip.addrtype != IPM_IPV6 )
            {
                continue;
            }

            LOG_DEBUG(0,
                      "EIPM_read_arptable: OS entry IP %s, dev %s, type %d, flags %d\n",
                       ipaddr_str,
                       dev,
                       type,
                       flags);

            /* Look for existing entry */
            for( ip_cnt_idx = 0;
                 ip_cnt_idx < ip_tbl_ptr->ip_cnt;
                 ip_cnt_idx++ )
            {
                if( IPM_IPCMPADDR(&ip_tbl_ptr->ip_table[ip_cnt_idx].ipaddr, &ip) == IPM_SUCCESS )
                {
                    /* Update existing entry */
                    ip_tbl_ptr->ip_table[ip_cnt_idx].lsnB_idx = iface_idx;
                    ip_tbl_ptr->ip_table[ip_cnt_idx].lsnB_tentative = 0;
                    strncpy(ip_tbl_ptr->ip_table[ip_cnt_idx].lsnB_iface, dev, EI_INTFNAMESIZE);
                    break;
                }
            }

            if( ip_cnt_idx != ip_tbl_ptr->ip_cnt )
            {
            continue;
            }

            /* Add new entry */
            ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].ipaddr = ip;
            ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].prefix = 0;;

            ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnA_idx = iface_idx;
            ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnA_tentative = 0;
            strncpy(ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnA_iface, dev, EI_INTFNAMESIZE);

            ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnB_idx = -1;
            ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnB_tentative = 0;
            ip_tbl_ptr->ip_table[ip_tbl_ptr->ip_cnt].lsnB_iface[0] = '\0';

            ip_tbl_ptr->ip_cnt++;

            /*
             * Check for additional room in the table
             */
            if( ip_tbl_ptr->ip_cnt >= IPM_IP_TBL_SZ )
            {
                ASRT_RPT( ASMISSING_DATA,
                          1,
                          sizeof(*ip_tbl_ptr),
                          ip_tbl_ptr,
                          "EIPM_read_arptable: Table reached max entries %d\n", 
                           ip_tbl_ptr->ip_cnt );

                break;
            }
        }

        (void)fclose(fp);

        return IPM_SUCCESS;
    }
#endif
}

#ifndef NLMSG_TAIL

/* This define is here to allow building outside of the LCP environment */
#define NLMSG_TAIL(_nmsg) \
        ((struct rtattr *) (((void *) (_nmsg)) + NLMSG_ALIGN((_nmsg)->nlmsg_len)))

#endif



/**********************************************************************
 *
 * Name:        EIPM_add_attribute()
 *
 * Abstract:    Add attribute to netlink message
 *
 * Parameters:  nlmsghdr - netlink message
 *              maxlen - maximum length of message
 *              type - attribute type
 *              data - attribute data
 *              alen - attribute length
 *
 * Returns:     IPM_SUCCESS - IP was successfully configured
 *              IPM_FAILURE - some error occurred.
 *
 **********************************************************************/

int 
EIPM_add_attribute(struct nlmsghdr *n, int maxlen, int type, const void *data, int alen)
{
int len = RTA_LENGTH(alen);
struct rtattr *rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) 
    {
        ASRT_RPT( ASRTBADPARAM,
                  2,
                  sizeof(struct nlmsghdr),
                  n,
                  alen,
                  data,
                  "EIPM_add_attribute: Attribute type %d size %d exceeded message size %d\n", type, alen, maxlen); 

        return IPM_FAILURE;
    }

    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

    return IPM_SUCCESS;
}



/**********************************************************************
 *
 * Name:        EIPM_configure_ip()
 *
 * Abstract:    Configure an IP via netlink socket
 *
 * Parameters:  nl_socket - netlink socket fd
 *              ip - pointer to ip
 *              prefix - ip prefix
 *              iface_idx - interface index
 *              cmd - add/delete command
 *
 * Returns:     IPM_SUCCESS - IP was successfully configured
 *              IPM_FAILURE - some error occurred.
 *
 **********************************************************************/

int
EIPM_configure_ip( int nl_socket, 
                   IPM_IPADDR *ip,
                   int prefix,
                   int iface_idx,
                   char *iface_name,
                   int cmd ) 
{
struct {
    struct nlmsghdr         hdr;
    struct ifaddrmsg        ifa;
    char                    buf[256];
} netlink_req;

struct sockaddr_nl nladdr;
struct iovec iov_info;
struct msghdr msg_info;

char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];

int retval;

    LOG_OTHER(EIPM_LOG_IPCFG,
              "EIPM_configure_ip: %s - IP %s/%d Dev %d %s\n",
               (cmd == RTM_NEWADDR) ? "Add" : "Delete",
               IPM_ipaddr2p(ip, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
               prefix,
               iface_idx,
               iface_name);

    bzero(&netlink_req, sizeof(netlink_req));

    netlink_req.hdr.nlmsg_type = cmd;
    netlink_req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
#if defined(EIPM_ACK_NETLINK)
    netlink_req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
#else
    netlink_req.hdr.nlmsg_flags = NLM_F_REQUEST;
#endif
    netlink_req.hdr.nlmsg_pid = 0;
    netlink_req.hdr.nlmsg_seq = IPM_ip_seq++;

    netlink_req.ifa.ifa_flags = IFA_F_PERMANENT;
    netlink_req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
    netlink_req.ifa.ifa_index = iface_idx;
    netlink_req.ifa.ifa_prefixlen = prefix;

    if( ip->addrtype == IPM_IPV4 )
    {
        struct in_addr  ipv4_buf;

        netlink_req.ifa.ifa_family = AF_INET;

        IPM_ipaddr2in(ip, &ipv4_buf);

        EIPM_add_attribute(&netlink_req.hdr, 
                           sizeof(netlink_req), 
                           IFA_LOCAL, 
                           &ipv4_buf, 
                           sizeof(ipv4_buf));

        if( cmd == RTM_NEWADDR )
        {
            IPM_IPADDR      subnet_mask;
            IPM_IPADDR      subnet_bcast;

            EIPM_add_attribute(&netlink_req.hdr, 
                               sizeof(netlink_req), 
                               IFA_ADDRESS, 
                               &ipv4_buf, 
                               sizeof(ipv4_buf));

            IPM_ipaddr_init(&subnet_mask);

            retval = IPM_ipmkmask(&subnet_mask, ip->addrtype, prefix);

            if( retval != IPM_SUCCESS )
            {
                LOG_ERROR(0,
                      "EIPM_configure_ip: Failed to create mask for IP %s/%d\n",
                       IPM_ipaddr2p(ip, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
                       prefix);

                return retval;
            }

            IPM_ipaddr_init(&subnet_bcast);

            IPM_get_bcast(ip, &subnet_mask, &subnet_bcast);

            IPM_ipaddr2in(&subnet_bcast, &ipv4_buf);

            EIPM_add_attribute(&netlink_req.hdr, 
                               sizeof(netlink_req), 
                               IFA_BROADCAST, &ipv4_buf, 
                               sizeof(ipv4_buf));

	    //RH6.0 only support "label" parameters within 15 characters,
	    //that means devices like "eth0.400.1234:ABCDE" is treated as "eth0.400.1234:A"
	    //The solution is to stop adding label attribute.
	   /*
            EIPM_add_attribute(&netlink_req.hdr, 
                               sizeof(netlink_req), 
                               IFA_LABEL, 
                               iface_name, 
                               IFNAMSIZ-1);
	   */
        }
    }
    else
    {
        struct in6_addr ipv6_buf;

        netlink_req.ifa.ifa_family = AF_INET6;

        IPM_ipaddr2in(ip, &ipv6_buf);

        EIPM_add_attribute(&netlink_req.hdr, 
                           sizeof(netlink_req), 
                           IFA_LOCAL, 
                           &ipv6_buf, 
                           sizeof(ipv6_buf));

        if( cmd == RTM_NEWADDR )
        {
            EIPM_add_attribute(&netlink_req.hdr, 
                               sizeof(netlink_req), 
                               IFA_ADDRESS, 
                               &ipv6_buf, 
                               sizeof(ipv6_buf));
        }
    }

    iov_info.iov_base = (void *) &netlink_req.hdr;
    iov_info.iov_len = netlink_req.hdr.nlmsg_len;

    bzero(&msg_info, sizeof(msg_info));

    bzero(&nladdr, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pad = 0;
    nladdr.nl_pid = 0;
    nladdr.nl_groups = 0;

    msg_info.msg_name = (void *) &nladdr;
    msg_info.msg_namelen = sizeof(nladdr);
    msg_info.msg_iov = &iov_info;
    msg_info.msg_iovlen = 1;

    retval = sendmsg(nl_socket, &msg_info, 0);

    if( retval < 0 )
    {
        if( errno == EAGAIN )
        {
            /*
             * No response.
             *
             * Setup timeout for 5 msec (nsec=5000) and try again.
             */
            struct timespec sel_time;
            sel_time.tv_sec  = 0;
            sel_time.tv_nsec = 5000;
            nanosleep(&sel_time, 0);

            retval = sendmsg(nl_socket, &msg_info, 0);

            if( retval < 0 )
            {
                ASRT_RPT( ASUNEXP_RETURN,
                          2,
                          sizeof(msg_info),
                          &msg_info,
                          sizeof(netlink_req),
                          &netlink_req,
                          "EIPM_configure_ip: sendmsg() retry failed retval %d errno 0x%x\n", retval, errno );

                return IPM_FAILURE;
            }
        }
        else 
        {
            ASRT_RPT( ASUNEXP_RETURN,
                      2,
                      sizeof(msg_info),
                      &msg_info,
                      sizeof(netlink_req),
                      &netlink_req,
                      "EIPM_configure_ip: sendmsg() failed retval %d errno 0x%x\n", retval, errno );

            return IPM_FAILURE;
        }
    }

#if defined(EIPM_ACK_NETLINK)
    iov_info.iov_base = (void*)&(netlink_req.hdr);
    iov_info.iov_len = sizeof(netlink_req);

    retval = recvmsg(nl_socket, &msg_info, 0);

    if( retval < 0 )
    {
        if( errno == EAGAIN )
        {
            /*
             * No response.
             *
             * Setup timeout for 5 msec (nsec=5000) and try again.
             */
            struct timespec sel_time;
            sel_time.tv_sec  = 0;
            sel_time.tv_nsec = 5000;
            nanosleep( &sel_time, 0 );

            retval = recvmsg(nl_socket, &msg_info, 0);

            if( retval < 0 )
            {
                ASRT_RPT( ASUNEXP_RETURN,
                          2,
                          sizeof(msg_info),
                          &msg_info,
                          sizeof(netlink_req),
                          &netlink_req,
                          "EIPM_configure_ip: recvmsg() retry failed retval %d errno 0x%x\n", retval, errno );

                return IPM_FAILURE;
            }
        }
        else
        {
            ASRT_RPT( ASUNEXP_RETURN,
                      2,
                      sizeof(msg_info),
                      &msg_info,
                      sizeof(netlink_req),
                      &netlink_req,
                      "EIPM_configure_ip: recvmsg() failed retval %d errno 0x%x\n", retval, errno );

            return IPM_FAILURE;
        }
    }

    if( netlink_req.hdr.nlmsg_type == NLMSG_ERROR )
    {
        int error = -((struct nlmsgerr*)NLMSG_DATA(&netlink_req))->error;

        if( error )
        {
	    /* 
	     * The IP may not be plumbed on this interface.  So, log instead of asserting.
	     */
            if( cmd == RTM_DELADDR )
	    {
                LOG_OTHER(EIPM_LOG_IPCFG,
	              "EIPM_configure_ip: %s - IP %s/%d Dev %d %s error %d\n",
               		(cmd == RTM_NEWADDR) ? "Add" : "Delete",
               		IPM_ipaddr2p(ip, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
               		prefix,
               		iface_idx,
               		iface_name,
			error );

	    }
	    else
	    {
                ASRT_RPT( ASUNEXP_RETURN,
                      	  2,
                          sizeof(msg_info),
                          &msg_info,
                          sizeof(netlink_req),
                          &netlink_req,
                          "EIPM_configure_ip: reply failed error 0x%x\n", error );
	    }

            return IPM_FAILURE;
        }
    }
#endif

    return IPM_SUCCESS;
}



/**********************************************************************
 *
 * Name:        EIPM_configure_ip_neighbor()
 *
 * Abstract:    Configure an IP via netlink socket
 *
 * Parameters:  nl_socket - netlink socket fd
 *              ip - pointer to ip
 *              prefix - ip prefix
 *              iface_idx - interface index
 *              cmd - add/delete command
 *              flags - add/delete flags
 *
 * Returns:     IPM_SUCCESS - IP was successfully configured
 *              IPM_FAILURE - some error occurred.
 *
 **********************************************************************/
int
EIPM_configure_ip_neighbor( int nl_socket, 
                            IPM_IPADDR *ip,
                            int prefix,
                            int iface_idx,
                            char *iface_name,
                            int cmd,
                            int flags ) 
{
struct {
    struct nlmsghdr         hdr;
    struct ndmsg            ndm;
    char                    buf[256];
} netlink_req;

struct sockaddr_nl nladdr;
struct iovec iov_info;
struct msghdr msg_info;

char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];

int retval;

    LOG_OTHER(EIPM_LOG_IPCFG,
              "EIPM_configure_ip_neighbor: %s - IP %s/%d Dev %d %s\n",
               (cmd == RTM_NEWNEIGH) ? "Add" : "Delete",
               IPM_ipaddr2p(ip, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
               prefix,
               iface_idx,
               iface_name);

    bzero(&netlink_req, sizeof(netlink_req));

    netlink_req.hdr.nlmsg_type = cmd;
    netlink_req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
#if defined(EIPM_ACK_NETLINK)
    netlink_req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
#else
    netlink_req.hdr.nlmsg_flags = NLM_F_REQUEST | flags;
#endif
    netlink_req.hdr.nlmsg_pid = 0;
    netlink_req.hdr.nlmsg_seq = IPM_ip_seq++;

    netlink_req.ndm.ndm_state = NUD_PERMANENT;
    netlink_req.ndm.ndm_flags = NTF_PROXY;
    netlink_req.ndm.ndm_ifindex = iface_idx;

    if( ip->addrtype == IPM_IPV4 )
    {
        struct in_addr  ipv4_buf;

        netlink_req.ndm.ndm_family = AF_INET;

        IPM_ipaddr2in(ip, &ipv4_buf);

        EIPM_add_attribute(&netlink_req.hdr, 
                           sizeof(netlink_req), 
                           NDA_DST, 
                           &ipv4_buf, 
                           sizeof(ipv4_buf));
    }
    else
    {
        struct in6_addr ipv6_buf;

        netlink_req.ndm.ndm_family = AF_INET6;

        IPM_ipaddr2in(ip, &ipv6_buf);

        EIPM_add_attribute(&netlink_req.hdr, 
                           sizeof(netlink_req), 
                           NDA_DST, 
                           &ipv6_buf, 
                           sizeof(ipv6_buf));
    }

    iov_info.iov_base = (void *) &netlink_req.hdr;
    iov_info.iov_len = netlink_req.hdr.nlmsg_len;

    bzero(&msg_info, sizeof(msg_info));

    bzero(&nladdr, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pad = 0;
    nladdr.nl_pid = 0;
    nladdr.nl_groups = 0;

    msg_info.msg_name = (void *) &nladdr;
    msg_info.msg_namelen = sizeof(nladdr);
    msg_info.msg_iov = &iov_info;
    msg_info.msg_iovlen = 1;

    retval = sendmsg(nl_socket, &msg_info, 0);

    if( retval < 0 )
    {
        if( errno == EAGAIN )
        {
            /*
             * No response.
             *
             * Setup timeout for 5 msec (nsec=5000) and try again.
             */
            struct timespec sel_time;
            sel_time.tv_sec  = 0;
            sel_time.tv_nsec = 5000;
            nanosleep(&sel_time, 0);

            retval = sendmsg(nl_socket, &msg_info, 0);

            if( retval < 0 )
            {
                ASRT_RPT( ASUNEXP_RETURN,
                          2,
                          sizeof(msg_info),
                          &msg_info,
                          sizeof(netlink_req),
                          &netlink_req,
                          "EIPM_configure_ip_neighbor: sendmsg() retry failed retval %d errno 0x%x\n", retval, errno );

                return IPM_FAILURE;
            }
        }
        else 
        {
            ASRT_RPT( ASUNEXP_RETURN,
                      2,
                      sizeof(msg_info),
                      &msg_info,
                      sizeof(netlink_req),
                      &netlink_req,
                      "EIPM_configure_ip_neighbor: sendmsg() failed retval %d errno 0x%x\n", retval, errno );

            return IPM_FAILURE;
        }
    }

#if defined(EIPM_ACK_NETLINK)
    iov_info.iov_base = (void*)&(netlink_req.hdr);
    iov_info.iov_len = sizeof(netlink_req);

    retval = recvmsg(nl_socket, &msg_info, 0);

    if( retval < 0 )
    {
        if( errno == EAGAIN )
        {
            /*
             * No response.
             *
             * Setup timeout for 5 msec (nsec=5000) and try again.
             */
            struct timespec sel_time;
            sel_time.tv_sec  = 0;
            sel_time.tv_nsec = 5000;
            nanosleep( &sel_time, 0 );

            retval = recvmsg(nl_socket, &msg_info, 0);

            if( retval < 0 )
            {
                ASRT_RPT( ASUNEXP_RETURN,
                          2,
                          sizeof(msg_info),
                          &msg_info,
                          sizeof(netlink_req),
                          &netlink_req,
                          "EIPM_configure_ip_neighbor: recvmsg() retry failed retval %d errno 0x%x\n", retval, errno );

                return IPM_FAILURE;
            }
        }
        else
        {
            ASRT_RPT( ASUNEXP_RETURN,
                      2,
                      sizeof(msg_info),
                      &msg_info,
                      sizeof(netlink_req),
                      &netlink_req,
                      "EIPM_configure_ip_neighbor: recvmsg() failed retval %d errno 0x%x\n", retval, errno );

            return IPM_FAILURE;
        }
    }

    if( netlink_req.hdr.nlmsg_type == NLMSG_ERROR )
    {
        int error = -((struct nlmsgerr*)NLMSG_DATA(&netlink_req))->error;

        if( error )
        {
	    /* 
	     * The IP may not be plumbed on this interface.  So, log instead of asserting.
	     */
            if( cmd == RTM_DELNEIGH )
	    {
		LOG_FORCE(0,
	              "EIPM_configure_ip_neighbor: %s - IP %s/%d Dev %d %s error %d\n",
               		(cmd == RTM_NEWNEIGH) ? "Add" : "Delete",
               		IPM_ipaddr2p(ip, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
               		prefix,
               		iface_idx,
               		iface_name,
			error );

	    }
	    else
	    {
                ASRT_RPT( ASUNEXP_RETURN,
                      	  2,
                          sizeof(msg_info),
                          &msg_info,
                          sizeof(netlink_req),
                          &netlink_req,
                          "EIPM_configure_ip_neighbor: reply failed error 0x%x\n", error );
	    }

            return IPM_FAILURE;
        }
    }
#endif

    return IPM_SUCCESS;
}


/**********************************************************************
 *
 * Name:        EIPM_check_ip_tentative()
 *
 * Abstract:    Check if any IPv6 addresses are in the tentative state 
 *		for the given subnet.
 *
 * Parameters:  intf_ptr - interface data
 *		subnet_ptr - subnet data
 *
 * Returns:     IPM_SUCCESS - IP not in tentative state
 *              IPM_FAILURE - IP in tentative state
 *
 **********************************************************************/

int
EIPM_check_ip_tentative( void *intfDataP, EIPM_INTF_TYPE intfType, EIPM_SUBNET *subnet_ptr )
{
EIPM_INTF *intf_ptr;
EIPM_INTF_SPEC *intfSpecDataP;
struct sockaddr_nl nladdr;
IPM_IPTBL ip_tbl;
int nl_socket;
int retval;
char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];

    EIPM_SET_INTF_PTRS( intfDataP, intfType, intf_ptr, intfSpecDataP );

    if ( NULL == intf_ptr )
    {
        return IPM_FAILURE;
    }

    nl_socket = socket( PF_NETLINK, SOCK_RAW, NETLINK_ROUTE );

    if( nl_socket < 0 )
    {
        ASRT_RPT( ASUNEXP_RETURN,
                  1,
                  sizeof(*intf_ptr),
                  intf_ptr,
                  "EIPM_check_ip_tentative: Failed to create routing socket\nretval=%d, errno=0x%x\n",
                   nl_socket,
                   errno );

        return( IPM_FAILURE );
    }

    /*
     * Fill in the sockaddr structure for bind().
     * From the netlink man page:
     * "There are two ways to assign nl_pid to a netlink socket.
     * If the application sets nl_pid before calling bind(2),
     * then it is up to the application to make sure that nl_pid
     * is unique.  If the application sets it to 0, the kernel
     * takes care of assigning it."
     * Since both IIPM and EIPM could be binding let the kernel
     * assign it.
     */
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pad = 0;
    nladdr.nl_pid = 0;
    nladdr.nl_groups = 0;

    retval = bind( nl_socket, (struct sockaddr *)&nladdr, sizeof( nladdr ) );

    if( retval < 0 )
    {
        ASRT_RPT( ASUNEXP_RETURN,
                  1,
                  sizeof(*intf_ptr),
                  intf_ptr,
                  "EIPM_check_ip_tentative: Failed to bind to routing socket\nretval=%d, errno=0x%x\n",
                   retval, 
                   errno );

        (void)close( nl_socket );

        return( IPM_FAILURE );
    }

    memset(&ip_tbl, 0, sizeof(IPM_IPTBL));

    retval = EIPM_read_iptable( nl_socket, AF_INET6, intfDataP, intfType, &ip_tbl, NULL );

    if( retval < 0 )
    {
        ASRT_RPT( ASUNEXP_RETURN,
                  2,
                  sizeof(*intf_ptr),
                  intf_ptr,
                  sizeof(ip_tbl),
                  &ip_tbl,
                  "EIPM_check_ip_tentative: Failed to read IPv6 table: retval=%d\n",
                   retval );

        (void)close( nl_socket );

        return( retval );
    }

    retval = IPM_SUCCESS;

    EIPM_IPDATA *ip_ptr;
    EIPM_TABLE_ENTRY *ip_tbl_ptr;
    int ip_idx;
    int ip_tbl_idx;

    (void)close( nl_socket );

    /* Look through all IPs */
    for( ip_idx = 0, ip_ptr = &subnet_ptr->ips[0];
         ip_idx < subnet_ptr->ip_cnt;
         ip_idx++, ip_ptr++ )
    {
        /* Look for entry in table */
        for( ip_tbl_idx = 0, ip_tbl_ptr = &ip_tbl.ip_table[0];
             ip_tbl_idx < ip_tbl.ip_cnt;
             ip_tbl_idx++, ip_tbl_ptr++ )
        {
            if( IPM_IPCMPADDR(&ip_ptr->ipaddr, &ip_tbl_ptr->ipaddr) == IPM_SUCCESS )
            { 
		if( ip_tbl_ptr->lsnA_tentative == TRUE ||
                    ip_tbl_ptr->lsnB_tentative == TRUE )
		{
		    LOG_OTHER( 0,
		 	       "EIPM_check_ip_tentative - IP %s in tentative state\n",
		 	       IPM_ipaddr2p( (&ip_ptr->ipaddr), ipm_ipstr_buf, sizeof(ipm_ipstr_buf) )
		 	     );

		    return IPM_FAILURE;
		}
            }
        }

    } /* Look through all IPs */

    return IPM_SUCCESS;
}

