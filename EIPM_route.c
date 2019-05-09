/**********************************************************************
 *
 * File:
 *	EIPM_route.c
 *
 * Functions in this file:
 *	EIPM_read_rttable() - Read current routing table.
 *	EIPM_check_routes()  - Compare Routes in EIPM data vs. OS table
 *	EIPM_delete_routes() - Delete routes from OS table
 *	EIPM_add_routes()    - Add routes to OS table
 *	EIPM_process_route_update() - process route updates
 *	EIPM_check_pivot_routes() - Compare Routes via pivot in EIPM data vs. OS table
 *
 **********************************************************************/

	
#include "EIPM_include.h"
#include "EIPM_bfd.h"
#include "nma_route.h"

	
/**********************************************************************
 *
 * Name:	EIPM_read_rttable()
 *
 * Abstract:	Read the current routing table for this blade.
 *
 * Info:	The route table gets returned in the same order
 *		as is output by the "ip route show" command, which
 *		should be the priority the kernel is using the
 *		routes in.
 *
 * Parameters:	tbl_ptr - pointer to structure to fill with route table
 *		table_num - tabld id from which table the route will be got
 *
 * Returns:	IPM_SUCCESS - routing table was successfully read
 *		IPM_FAILURE    - some error occurred.
 *
 **********************************************************************/

int
EIPM_read_rttable(IPM_RTTBL *tbl_ptr, uint8_t table_num)
{

	struct
	{
		struct nlmsghdr header;
		struct rtmsg    route;
		char            data[1024];
	} request;
	struct sockaddr_nl nladdr;
	struct iovec	   iov;
	struct msghdr msg = {	(void*)&nladdr,
				sizeof(nladdr),
				&iov,
				1,
				NULL,
				0,
				0 };
	struct timespec sel_time;
	struct ifreq	ifr;
	unsigned long long read_buf_size;
        const int       max_read_buf_size = 65535;               
	char		read_buf[max_read_buf_size];
        char            total_read_buf[IPM_RT_TBL_RD_SZ]; 
        char            *total_read_buf_ptr;
	char		*read_ptr;
	struct in_addr  ipm_ipv4_buf;
	char            ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
	struct nlmsghdr *nlmsg_ptr;
	struct rtmsg	*rtmsg_ptr;
	struct rtattr	*rtattr_ptr;
	IPM_ROUTE_ENTRY *rt_ptr;
	int		sock;
	int		nlmsg_len;
	int		rtmsg_len;
	int		error;
	int		retval;
	int		loopcnt;
	int		errcnt;
	int		rt_cnt;
	int		nl_socket;
	int		i;

	tbl_ptr->route_cnt = 0;

	memset( tbl_ptr, 0, sizeof( *tbl_ptr ) );

	// Create OS netlink socket.
	nl_socket = IPM_open_netlink_socket();

	if (nl_socket < 0)
	{
		LOG_ERROR(NMA_OROUTE, "EIPM_read_rttable: Failed to open netlink socket.\n");
		return ( IPM_FAILURE);
	}

	for( rt_cnt = 0, i = 0; i < 2; i++ )
	{
		/*
		 * Zero out the message structure and the table we will
		 * store the route table data in.
		 */
		memset( &request, 0, sizeof(request) );

		/*
		 * Fill in the message header.
		 */
		request.header.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
		request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
		request.header.nlmsg_type  = RTM_GETROUTE;
		request.header.nlmsg_pid   = 0;
		request.header.nlmsg_seq   = IPM_rt_seq++;
	
		/*
		 * Fill in the body of the message.  This is just a read
		 * so we only need the family and which routing table.
		 */
		if( i == 0 )
		{
			request.route.rtm_family = AF_INET;
		}
		else
		{
			request.route.rtm_family = AF_INET6;
		}
		request.route.rtm_table = table_num; 
	
		/*
		 * Zero and fill in sockaddr structure.
		 */
		memset( &nladdr, 0, sizeof(nladdr) );
	
		nladdr.nl_family = AF_NETLINK;
		nladdr.nl_pid = 0;
		nladdr.nl_groups = 0;
		
	
		iov.iov_base = (void*)&(request.header);
		iov.iov_len = request.header.nlmsg_len;

		if( sendmsg( nl_socket, &msg, 0 ) == -1 )
		{
			ASRT_RPT( ASUNEXP_RETURN,
			          2,
			          sizeof( msg ),
				  &msg,
				  sizeof( request ),
				  &request,
			       	  "Error: EIPM_read_rttable - sendmsg() failed, errno=0x%x\n",
			          errno );
				  
			if( i != 0 ){
				(void)close( sock );
			}
			IPM_close_netlink_socket(&nl_socket);
			return( IPM_FAILURE );
		}
	
		/*
		 * Now receive the response.  We may get multiple messages
		 * to retrieve the entire routing table.
		 */
		bzero( read_buf, max_read_buf_size );
                bzero( total_read_buf, IPM_RT_TBL_RD_SZ );

		read_ptr = read_buf;
		nlmsg_len = 0;
		total_read_buf_ptr = total_read_buf;
                read_buf_size = 0;

		/*
		 * We need to loop to get all the messages, but we cannot
		 * loop forever.  Initial lab testing showed we can get 11 routes in
		 * 1 message - need to see what the max really is.
		 */
		for( loopcnt = 0, errcnt = 0;
		     (loopcnt < EIPM_RT_RD_LP_CNT) && (errcnt < 2);
		     loopcnt++  )
		{
			/*
			 * **** is recv() correct?
			 */
			retval = recv( nl_socket, read_ptr, sizeof(read_buf) - nlmsg_len, 0);
			if( retval < 0 ) {
				if( errno == EAGAIN )
				{
					/*
					 * No response.
					 *
					 * Setup timeout for 5 usec (nsec=5000)
					 * and try again.  Increment the error
					 * count so we don't repeatedly do this.
					 */
					errcnt++;
				
					sel_time.tv_sec  = 0;
					sel_time.tv_nsec = 5000;
					nanosleep( &sel_time, 0 );
				
					continue;
				
				}
				
				ASRT_RPT( ASUNEXP_RETURN,
				          2,
				          sizeof( nl_socket ),
					  &nl_socket,
					  sizeof( nlmsg_len ),
					  &nlmsg_len,
				       	  "Error: EIPM_read_rttable - recv() failed, errno=%d\n",
				          errno );
			
				if( i != 0 ){
					(void)close( sock );
				}
				IPM_close_netlink_socket(&nl_socket);
				return( IPM_FAILURE );
			}
		
			/*
			 * Get a pointer to the data read.
			 */
			nlmsg_ptr = (struct nlmsghdr *) read_ptr;
			
			/*
			 * Have we received the last message?
			 */
			if(nlmsg_ptr->nlmsg_type == NLMSG_DONE)
			{
				if ( ( read_buf_size + ( nlmsg_len + retval ) ) >= IPM_RT_TBL_RD_SZ )
                                {
                                        /* Received more data than allocated space for. */
				        LOG_ERROR( 0,
				                   "ERROR(%s): Received more data (%d + %d + %llu) than allocated %d\n",
                                                   (char *)(__func__),
				                   nlmsg_len,
                                                   retval,
                                                   read_buf_size,
                                                   IPM_RT_TBL_RD_SZ );
					if( i != 0 ){
						(void)close( sock );
					}
					IPM_close_netlink_socket(&nl_socket);	
				        return IPM_FAILURE;
                                }
                                else
                                {
                                        memcpy( total_read_buf_ptr, read_buf, ( nlmsg_len + retval ) );
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

                                if ( ( read_buf_size + ( nlmsg_len + retval ) ) >= IPM_RT_TBL_RD_SZ )
                                {
                                        /* Received more data than allocated space for. */
				        LOG_ERROR( 0,
				                   "ERROR(%s): Received more data (%d + %d + %llu) than allocated %d\n",
                                                   (char *)(__func__),
				                   nlmsg_len,
                                                   retval,
                                                   read_buf_size,
                                                   IPM_RT_TBL_RD_SZ );
			
					if( i != 0 ){
						(void)close( sock );
					}
					IPM_close_netlink_socket(&nl_socket);
				        return IPM_FAILURE;
                                }
                                else
                                {
                                        memcpy( total_read_buf_ptr, read_buf, ( nlmsg_len + retval ) );
                                        total_read_buf_ptr = total_read_buf_ptr + ( nlmsg_len + retval );
                                        read_buf_size = read_buf_size + ( nlmsg_len + retval );
                                        bzero( read_buf, max_read_buf_size );
                                        nlmsg_len = 0;
                                        read_ptr = read_buf;
                                }
                        }
                        else
                        {
                                nlmsg_len = nlmsg_len + retval;
                        }
		
		} /* end 'for loop on recv()' */
	
		if( loopcnt >= EIPM_RT_RD_LP_CNT )
		{
			/*
			 * We have not received the last message.
			 */
			ASRT_RPT( ASUNEXP_RETURN,
				   0,
			           "Error - EIPM_read_rttable: did not receive last message in %d attempts",
				   EIPM_RT_RD_LP_CNT );
		
			if( i != 0 ){
				(void)close( sock );
			}
			IPM_close_netlink_socket(&nl_socket);
			return( IPM_FAILURE );
		}

		/*
		 * Now loop through to parse and store the received data.
		 */
		nlmsg_ptr = (struct nlmsghdr *)total_read_buf;
		
		/*
		 * Open a raw socket so we can query the interface
		 * name using the interface index returned in the mesage.
		 */
		if( i == 0 )
		{
			sock = socket( PF_INET, SOCK_RAW, htons(ETH_P_IP) );
			if( sock < 0 )
			{
				ASRT_RPT( ASUNEXP_RETURN,
					   0,
				           "EIPM_read_rttable : socket() failed, errno=%d\n",
				           errno );
				IPM_close_netlink_socket(&nl_socket);
				return( IPM_FAILURE );
			}
		}

		/*
		 * Loop to read the data in the messages and store it in
		 * the table.
		 */
		for( rt_ptr = &tbl_ptr->route_table[rt_cnt] ;
		     (NLMSG_OK(nlmsg_ptr, nlmsg_len)) && (rt_cnt < IPM_RT_TBL_SZ);
		     nlmsg_ptr = NLMSG_NEXT(nlmsg_ptr, nlmsg_len) )
		{
			/*
			 * Get a pointer to the data portion of the msg.
			 */
			rtmsg_ptr = (struct rtmsg *) NLMSG_DATA(nlmsg_ptr);
		
			/*
			 * Ignore anything other than the specified table number.
			 */
			if( rtmsg_ptr->rtm_table != table_num)
			{
				continue;
			}

			if( request.route.rtm_family == AF_INET )
			{
				(void)IPM_p2ipaddr("0.0.0.0", &rt_ptr->dest);
				(void)IPM_p2ipaddr("0.0.0.0", &rt_ptr->gateway);
				(void)IPM_p2ipaddr("0.0.0.0", &rt_ptr->srcip);
			}
			else if( request.route.rtm_family == AF_INET6 )
			{
				(void)IPM_p2ipaddr("::", &rt_ptr->dest);
				(void)IPM_p2ipaddr("::", &rt_ptr->gateway);
				(void)IPM_p2ipaddr("::", &rt_ptr->srcip);
			}		

			/*
			 * Get a pointer to the attributes.
			 */
			rtattr_ptr = (struct rtattr *) RTM_RTA(rtmsg_ptr);
			rtmsg_len = RTM_PAYLOAD(nlmsg_ptr);
		
			for( ; 
			     RTA_OK(rtattr_ptr, rtmsg_len);
			     rtattr_ptr = RTA_NEXT(rtattr_ptr, rtmsg_len))
			{
				/*
				 * Store data based on which attribute
				 * type we are looking at.
				 */
				switch(rtattr_ptr->rta_type)
				{
				case RTA_DST:
					/*
					 * Destination for route.
					 */
					if( request.route.rtm_family == AF_INET )
					{
						ipm_ipv4_buf.s_addr = *(__u32 *)RTA_DATA(rtattr_ptr);
	
						IPM_in2ipaddr(&ipm_ipv4_buf, sizeof(ipm_ipv4_buf), &rt_ptr->dest);
					}
					else if( request.route.rtm_family == AF_INET6 )
					{
						IPM_in2ipaddr(RTA_DATA(rtattr_ptr), sizeof(struct in6_addr), &rt_ptr->dest);
					}
	
					/*
					 * Apparently the prefix is not an
					 * attribute, but is carried in the
					 * message...  Protocol and scope are
					 * also in the message (and copied here
					 * since every route has a destination).
					 */
					rt_ptr->destprefix = rtmsg_ptr->rtm_dst_len;
					rt_ptr->protocol   = rtmsg_ptr->rtm_protocol;
					rt_ptr->scope      = rtmsg_ptr->rtm_scope;
				
					break;
				
				case RTA_PREFSRC:
					/*
					 * Source IP for route.
					 */
					if( request.route.rtm_family == AF_INET )
					{
						ipm_ipv4_buf.s_addr = *(__u32 *)RTA_DATA(rtattr_ptr);
	
						IPM_in2ipaddr(&ipm_ipv4_buf, sizeof(ipm_ipv4_buf), &rt_ptr->srcip);
					}
					else if( request.route.rtm_family == AF_INET6 )
					{
						IPM_in2ipaddr(RTA_DATA(rtattr_ptr), sizeof(struct in6_addr), &rt_ptr->srcip);
					}
					break;
				
				case RTA_GATEWAY:
					/*
					 * Gateway IP for route.
					 */
					if( request.route.rtm_family == AF_INET )
					{
						ipm_ipv4_buf.s_addr = *(__u32 *)RTA_DATA(rtattr_ptr);

						IPM_in2ipaddr(&ipm_ipv4_buf, sizeof(ipm_ipv4_buf), &rt_ptr->gateway);
					}
					else if( request.route.rtm_family == AF_INET6 )
					{
						IPM_in2ipaddr(RTA_DATA(rtattr_ptr), sizeof(struct in6_addr), &rt_ptr->gateway);
					}
					break;
				
				case RTA_OIF:
					/*
					 * Interface route is associated with.
					 * Query the kernel to get the name.
					 */
					memset( &ifr, 0, sizeof(ifr) );
					ifr.ifr_addr.sa_family = PF_INET;
					ifr.ifr_ifindex = *((int *) RTA_DATA(rtattr_ptr));
					retval = ioctl( sock, SIOCGIFNAME, &ifr );
					if( retval < 0 )
					{
						ASRT_RPT( ASUNEXP_RETURN,
						          2,
						          sizeof( ifr ),
							  &ifr,
							  sizeof( sock ),
							  &sock,
						       	  "Error: EIPM_read_rttable : socket ioctl() failed, errno=%d\n",
						          errno );
			
					
						/*
						 * Since we have only used the
						 * socket descriptor in this
						 * function don't worry about
						 * checking the return from
						 * close().
						 */
						(void)close( sock );
						IPM_close_netlink_socket(&nl_socket);
						return( IPM_FAILURE );
					}
					
					/*
					 * Copy the interface name string.  Save
					 * the index while we are at it, since
					 * that is easier to compare in some
					 * cases.
					 */
					strcpy( rt_ptr->iface, ifr.ifr_name );
					rt_ptr->iface_indx = ifr.ifr_ifindex;
				
					break;

				case RTA_TABLE:
					/*
					 * For some reason the table name
					 * is also in the attribute list.  For
					 * now assume the validation above
					 * (and the fact that we only asked
					 * for the main routing table) is
					 * sufficient.
					 */
					
					break; 
				
				case RTA_PRIORITY:
					rt_ptr->priority = *(u_int32_t *)RTA_DATA(rtattr_ptr);
					break;

				case RTA_METRICS:
				case RTA_CACHEINFO:
					
					break;
				
				default:
					ASRT_RPT( ASUNEXPECTEDVAL,
					          1,
					          sizeof( *rtmsg_ptr ),
						  rtmsg_ptr,
					          "Error: EIPM_read_rttable: Got RTA_TYPE (%d) not in code\n", 
					           rtattr_ptr->rta_type );
				
					break; 
				}
			}

			/*
			 * We have parsed all the attributes in this message.
			 * Given there are at least 3 different types of routes
			 * and we have no idea what routes exist it would be
			 * difficult to validate the data.  Assume it is correct.
			 */
		
			/*
			 * Set up to fill in the next route in the table.
			 */
			++rt_ptr;
			++rt_cnt;
		}
	}       

	tbl_ptr->route_cnt = rt_cnt;

	if( rt_cnt == IPM_RT_TBL_SZ )
	{
		LOG_ERROR( 0,
		           "Error - EIPM_read_rttable: route table filled up\n" );
	}
	
	/*
	 * Close our data gathering socket.  No need to check the
	 * the return code - we haven't passed it to any non-OS
	 * functions.
	 */
	(void)close( sock );

	
#ifdef DEBUG
{
	char	prt_line[200];
	char	prt_buf[200 * EIPM_PRT_LINES];
	char	dststr[IPM_IPMAXSTRSIZE];
	char	tmpstr[IPM_IPMAXSTRSIZE];
	char	gwstr[24];
	char	ifstr[36];
	char	protstr[20];
	char	scopestr[20];
	char	srcstr[24];
	int	cnt_to_prt;
		
	/*
	 * For debugging we want to print multiple route entries
	 * per log message.
	 */
	cnt_to_prt = -1;
	
	for( rt_cnt = 0, rt_ptr = &tbl_ptr->route_table[0];
	     rt_cnt < tbl_ptr->route_cnt;
	     rt_cnt++, rt_ptr++ )
	{
		/*
		 * For debugging buffer EIPM_PRT_LINES lines of route
		 * entries before printing.
		 */
		if( rt_ptr->dest.addrtype == IPM_IPV4 ||
		    rt_ptr->dest.addrtype == IPM_IPV6 ) {
			(void)IPM_ipaddr2p(&rt_ptr->dest, dststr, sizeof(dststr));
		}
		else
		{
			sprintf( dststr, "default" );
		}
		
		if( rt_ptr->gateway.addrtype == IPM_IPV4 ||
                    rt_ptr->gateway.addrtype == IPM_IPV6 ) {
			(void)IPM_ipaddr2p(&rt_ptr->gateway, tmpstr, sizeof(tmpstr));
			sprintf( gwstr, "via %s ", tmpstr );
		}
		else
		{
			gwstr[0] = '\0';
		}
		
		if( strlen(rt_ptr->iface) != 0) {
			sprintf( ifstr, "dev %d %s ", rt_ptr->iface_indx, rt_ptr->iface );
		}
		else
		{
			ifstr[0] = '\0';
		}
		
		if( rt_ptr->protocol != 0) {
			/*
			 * Note - "ip route show" only seems to
			 * print protocol kernel.
			 */
			switch( rt_ptr->protocol )
			{
			case RTPROT_REDIRECT:
				strcpy( protstr, "protocol redirect " );
				break;
				
			case RTPROT_KERNEL:
				strcpy( protstr, "protocol kernel " );
				break;
				
			case RTPROT_BOOT:
				strcpy( protstr, "protocol boot " );
				break;
			
			case RTPROT_STATIC:
				strcpy( protstr, "protocol static " );
				break;
				
			default:
				strcpy( protstr, "protocol unknown " );
				break;
			}
		}
		else
		{
			protstr[0] = '\0';
		}
		
		/*
		 * Note - "ip route show" only seems to
		 * print scope link.
		 */
		switch( rt_ptr->scope )
		{
		case RT_SCOPE_UNIVERSE:
			strcpy( scopestr, "scope universe " );
			break;
			
		case RT_SCOPE_SITE:
			strcpy( scopestr, "scope site " );
			break;
			
		case RT_SCOPE_LINK:
			strcpy( scopestr, "scope link " );
			break;
		
		case RT_SCOPE_HOST:
			strcpy( scopestr, "scope host " );
			break;
			
		default:
			scopestr[0] = '\0';
			break;
		}
		
		if( rt_ptr->srcip.addrtype == IPM_IPV4 ||
                    rt_ptr->srcip.addrtype == IPM_IPV6 ) {
			(void)IPM_ipaddr2p(&rt_ptr->srcip, tmpstr, sizeof(tmpstr));
			sprintf( srcstr, "src %s", tmpstr );
		}
		else
		{
			srcstr[0] = '\0';
		}
		
		sprintf( prt_line,
		         "%s/%d %s %s %s %s %s\n",
		         dststr,
			 rt_ptr->destprefix,
		         gwstr,
		         ifstr,
		         protstr,
		         scopestr,
		         srcstr );
		
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
			 * We have accumulated EIPM_PRT_LINES in
			 * the buffer.  Time to log it.  Since
			 * we are inside a DEBUG ifdef print with
			 * a higher log level so we get the data.
			 */
			LOG_ERROR( 0,
			           "%s",
			           prt_buf );
			
			/*
			 * Reset print count.
			 */
			cnt_to_prt = -1;
		}
	}
	
	if( cnt_to_prt != -1 )
	{
		/*
		 * We have some data left to print.
		 */
		LOG_ERROR( 0,
		         "%s",
		         prt_buf );
	}
}
#endif
	
	IPM_close_netlink_socket(&nl_socket);
	return( IPM_SUCCESS );
	
} /* end EIPM_read_rttable() */


/* There should be subnet based route in shm if there is Ip on that subnet
 * if for some reason, subnet based route is removed from shm, we should add 
 * it back.
 */
void EIPM_check_subnet_route_in_shm(EIPM_SUBNET *subnet_ptr)
{
int route_idx;
int ip_idx;
EIPM_ROUTES *eipm_subn_route_ptr;
int subnet_route[MAX_NUM_PIVOT];
int pivot_id;
char ipbuf[ IPM_IPMAXSTRSIZE ];

	if ((subnet_ptr == NULL)
	     || (subnet_ptr->ip_cnt == 0)
	   )
	{
		return;
	}

	memset(subnet_route, 0, sizeof(subnet_route));

	/* Here if pivot_id == 0 means that ip is plumped on non-pivot interface 
	 * if pivot_id != 0 means that ip is plumped on pivot interface
	 * if one ip is plumped on that interface, one subnet based route should be added
	 */	
	for (ip_idx = 0; ip_idx < subnet_ptr->ip_cnt; ip_idx++)
	{	
		/* currently don't check proxy server and proxy client add type 
		 * In future, if subnet based route for proxy server and proxy client addr is enhanced
		 * this condition can be removed 
		 */
		if ( (subnet_ptr->ips[ip_idx].type == EIPM_IP_PROXY_SERVER)
			|| (subnet_ptr->ips[ip_idx].type == EIPM_IP_PROXY_CLIENT_ADDR)
		   )
		{
			continue;
		}
		pivot_id = subnet_ptr->ips[ip_idx].pivot_id;
		if ((pivot_id >= 0) && (pivot_id < MAX_NUM_PIVOT))
		{
			subnet_route[pivot_id] = 1;
		}
	}

	for( route_idx = 0, eipm_subn_route_ptr = &subnet_ptr->routes[0];
		route_idx < subnet_ptr->route_cnt;
		route_idx++, eipm_subn_route_ptr++ )
	{
		pivot_id = eipm_subn_route_ptr->pivot_id;
		if ( (subnet_ptr->prefixlen == eipm_subn_route_ptr->destprefix) &&
			(IPM_IPCMPADDR(&(subnet_ptr->subnet_base), &(eipm_subn_route_ptr->dest)) == IPM_SUCCESS)
			&& ((pivot_id >= 0) && (pivot_id < MAX_NUM_PIVOT))
		   ) 
		{
			subnet_route[pivot_id] = 2;
		}
	}

	/* Until now subnet_route[pivot_id] =:
	 * 0: no subnet based route is needed, do nothing
	 * 1: there is subnet based route but missed in IPM shm, we should add it back
	 * 2: there is subnet based route on interface and it still in shm, do nothing
	 */
	for (pivot_id = 0; pivot_id < MAX_NUM_PIVOT; pivot_id++)
	{
		if ((subnet_route[pivot_id] == 0) || (subnet_route[pivot_id] == 2))
		{
			continue;
		}

		if (subnet_ptr->route_cnt >= EIPM_MAX_ROUTES)
		{
			ASRT_RPT(ASBAD_DATA, 0, "no enough space is left in ipm shm on route entry\n");
			return;
		}

		/* Find first index non-subnet based route */
		/* Note, other routes be stored in the shm after the subnet based route */
		for (route_idx = 0; route_idx < subnet_ptr->route_cnt; route_idx++)
		{
			if (subnet_ptr->routes[route_idx].type != EIPM_ROUTE_SUBN)
			{
				break;
			}
		}

		/* insert subnet based route again */
		LOG_FORCE(0, "WARNING: subnet based route %s/%d is added back \n", 
				IPM_ipaddr2p(&subnet_ptr->subnet_base, ipbuf, sizeof(ipbuf)),
				subnet_ptr->prefixlen);
		eipm_subn_route_ptr = &subnet_ptr->routes[route_idx];
		memcpy(&subnet_ptr->routes[subnet_ptr->route_cnt], eipm_subn_route_ptr, sizeof(EIPM_ROUTES));

		eipm_subn_route_ptr->type = EIPM_ROUTE_SUBN;
		eipm_subn_route_ptr->dest = subnet_ptr->subnet_base;
		eipm_subn_route_ptr->destprefix = subnet_ptr->prefixlen;
		eipm_subn_route_ptr->pivot_id = pivot_id;
		IPM_ipaddr_init(&eipm_subn_route_ptr->nexthop);
		IPM_ipaddr_init(&eipm_subn_route_ptr->source_ip);
		if( subnet_ptr->subnet_base.addrtype == IPM_IPV4 )
		{
			(void)IPM_p2ipaddr("0.0.0.0", &eipm_subn_route_ptr->nexthop);
			(void)IPM_p2ipaddr("0.0.0.0", &eipm_subn_route_ptr->source_ip);
		}
		else if( subnet_ptr->subnet_base.addrtype == IPM_IPV6 )
		{
			(void)IPM_p2ipaddr("::", &eipm_subn_route_ptr->nexthop);
			(void)IPM_p2ipaddr("::", &eipm_subn_route_ptr->source_ip);
		}
		subnet_ptr->route_cnt++;
	}
	return;
}



/**********************************************************************
 *
 * Name:        EIPM_check_routes()
 *
 * Abstract:    Compare the OS route table against the IPM data.
 *		Update the OS route table if a discrepency is found.
 *
 * Parameters:  intf_ptr - pointer to interface data
 *
 * Returns:     IPM_SUCCESS - routing table was successfully changed if needed
 *              IPM_FAILURE - some error occurred.
 *
 **********************************************************************/

int
EIPM_check_routes( void *intfDataP, EIPM_INTF_TYPE intfType )
{
struct sockaddr_nl nladdr;
EIPM_INTF *intf_ptr;
EIPM_INTF_SPEC *intfSpecDataP;
int intf_idx;			/* index of EIPM_INTF pointed to by intf_ptr */
EIPM_DATA *shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
IPM_IPADDR *routing_gateway_ptr; /* gateway to use based on route priority */
EIPM_SUBNET *subnet_ptr;
EIPM_ROUTES *eipm_subn_route_ptr;
EIPM_ARP_ITEM *arpitem_ptr;
IPM_ROUTE_ENTRY *os_route_ptr;
struct in_addr ipm_ipv4_buf;
char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
char ipm_ipstr_buf1[IPM_IPMAXSTRSIZE];
IPM_RTTBL route_tbl;
IPM_RULETBL rule_tbl;
EIPM_NET routing_interface;
EIPM_NET routing_priority;
char routing_interface_str[16];
char routing_priority_str[16];
bool update_routing;
int nl_socket;
int subnet_idx;
int route_idx;
int route_table_entry_idx;
int arpitem_idx;
int retval;
int temp_retval;
char interface_status[16];
uint16_t vlanId=0;

    EIPM_SET_INTF_PTRS( intfDataP, intfType, intf_ptr, intfSpecDataP );

    if ( NULL == intf_ptr )
    {
        return IPM_FAILURE;
    }

    // Get VLAN id if it is external interface
    if ( intfType == EIPM_EXTN_INTF )
    {
	vlanId = intfSpecDataP->vlanId;
    }

    // Create OS netlink socket
    nl_socket = IPM_open_netlink_socket();

    if( nl_socket < 0 )
    {
        ASRT_RPT( ASUNEXP_RETURN,
                  1,
                  sizeof(*intf_ptr),
                  intf_ptr,
                  "EIPM_check_routes - failed to create routing socket\nretval=%d, errno=0x%x\n",
                   nl_socket, 
                   errno );

        return( IPM_FAILURE );
    }

    retval = EIPM_read_rttable(&route_tbl, RT_TABLE_MAIN);

    if( retval < 0 )
    {
        ASRT_RPT( ASUNEXP_RETURN,
                  1,
                  sizeof(*intf_ptr),
                  intf_ptr,
                  "EIPM_check_routes - failed to read route table: retval=%d\n",
                   retval );

        IPM_close_netlink_socket(&nl_socket);
        return( IPM_FAILURE );
    }

    retval = EIPM_read_rules(&rule_tbl);
    if (retval < 0)
    {
        ASRT_RPT(ASUNEXP_RETURN,
                1,
                sizeof (*intf_ptr),
                intf_ptr,
                "EIPM_check_routes - failed to read rule table: retval=%d\n",
                retval);
        IPM_close_netlink_socket(&nl_socket);
        return ( IPM_FAILURE);
    }

    ipm_chk_host_rule(rule_tbl);

    EIPM_check_route_priority( intf_ptr , vlanId);

    intf_idx = intfSpecDataP->baseIntfIdx;

    for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
         subnet_idx < intf_ptr->subnet_cnt;
         subnet_idx++, subnet_ptr++ )
    {
	if( intfType == EIPM_EXTN_INTF &&
		subnet_ptr->sub2intf_mapping[vlanId].is_intf_configured == 0)
	{
		//Skip it as this subnet is not configured on the extension interface
		continue;
	}
        arpitem_idx = 0;

	switch ( intfSpecDataP->status )
        {
        case EIPM_ONLINE:
	    routing_interface = intfSpecDataP->preferred_side;
            break;

        default:
            routing_interface = LSN_BOTH;
            break;
        }

	routing_priority = subnet_ptr->sub2intf_mapping[vlanId].route_priority;
	EIPM_status2str( intfSpecDataP->status, interface_status );

        EIPM_network2str( routing_interface, routing_interface_str );
        EIPM_network2str( routing_priority, routing_priority_str );

	LOG_OTHER( EIPM_LOG_ROUTECHK,
                   "EIPM_check_routes: Check - Subnet %d on Iface %d %s%s - %d %s%s Status %s State %d Arp State %d Idx %d -> Routing Iface %s, Priority %s\n",
                   subnet_idx,
                   intfSpecDataP->lsn0_iface_indx,
                   intf_ptr->lsn0_baseif,
                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
                   intfSpecDataP->lsn1_iface_indx,
                   intf_ptr->lsn1_baseif,
                   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
                   interface_status,
                   intfSpecDataP->state,
                   intfSpecDataP->recovery_state,
                   arpitem_idx,
                   routing_interface_str,
                   routing_priority_str );

        if( routing_priority == LSN_NONE )
        {
            IPM_close_netlink_socket(&nl_socket);
            return( IPM_SUCCESS );
        }

	/* For BFD, all OTHER routes are stored in the Left BFD Transport
	 * subnet so if we're looping through a routes[] array for a
	 * Left BFD Transport on interface A with gateway B, we could
	 * have that Left BFD Transport down so we're actually routing
	 * out of the Right BFD Transport which is on interface X with
	 * gateway Y. That means that if we're a Left BFD Transport (LSN0)
	 * and the route_priority is set to use the Right BFD Transport
	 * (LSN1) then for each OTHER route in this subnet we need to
	 * get the interface (X) and gateway (Y) values from the Right
	 * BFD Transport rather than use our own values (A and B).
	 */
	routing_gateway_ptr = &(subnet_ptr->gateway);

	if (subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT)
	{
		if (intfSpecDataP->lsn0_iface_indx > 0)
		{
			/* This is a Left BFD Transport */
            		routing_interface = LSN0;
			if (subnet_ptr->sub2intf_mapping[vlanId].route_priority == LSN1)
			{
				int		right_intf_idx;
				int		right_sn_idx;
				IPM_RETVAL	bfd_map_retval;

				/* We have a Left BFD Transport and the
				 * route priority is to use Right so get
			 	 * the gatweay address from the Right.
				 */

				bfd_map_retval = EIPM_bfd_map_left2right(intf_idx,subnet_idx,&right_intf_idx,&right_sn_idx);

				if (bfd_map_retval == IPM_SUCCESS)
				{
					routing_gateway_ptr = &(shm_ptr->intf_data[right_intf_idx].subnet[right_sn_idx].gateway);
				}
			}
		}
		else
		{
			/* This is a Right BFD Transport */
            		routing_interface = LSN1;
		}

	}
	else if ( subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD ||
		  subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR )
	{
		routing_interface = LSN_BOTH;
	}
	else if ( subnet_ptr->redundancy_mode == IPM_RED_NONE ||
	          subnet_ptr->redundancy_mode == IPM_RED_EIPM_ARPNDP )
	{
		if ( (intfSpecDataP->lsn0_iface_indx > 0) &&
		     !(intfSpecDataP->lsn1_iface_indx > 0))
		{
			routing_interface = LSN0;
		} 
		else if ( (intfSpecDataP->lsn1_iface_indx > 0) &&
		     !(intfSpecDataP->lsn0_iface_indx > 0))
		{
			routing_interface = LSN1;
		}
	}
	//For WCNP subnet, use subnet redanduncy type to determind the routing interface
	//As there is the case the ip_cnt is 0 which means NO IPs in the subnet,
	//but subnet base routing is still in OS. So we have to use the subnet
	//redanduncy type to monitor WCNP routes
	else if ( subnet_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_FIXLEFT )
	{
		routing_interface = LSN0;
	}
	else if ( subnet_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_FIXRIGHT )
	{
		routing_interface = LSN1;
	}
	else if ( subnet_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_ACTIVE ||
			subnet_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_SERVICE )
	{
		routing_interface = subnet_ptr->sub2intf_mapping[0].route_priority;
	}
	else if ( subnet_ptr->redundancy_mode == IPM_RED_EIPM_WCNP_STANDBY )
	{
		if ( subnet_ptr->sub2intf_mapping[0].route_priority == LSN0 )
		{
			routing_interface = LSN1;
		}
		else 
		{
			routing_interface = LSN0;
		}
	}


	/* check subnet based route in share memory */
	EIPM_check_subnet_route_in_shm(subnet_ptr);

	/* When policy routes are added on a feph host, kernel stops responding ARP on the interface        */
	/* with forwarding is set to 1. This leads feph host stops ARP response for the beph IPs, which     */
	/* cause packets could not reach to a feph host. This happends on WR linux, the current solution    */
	/* is to inhibit policy routing in linux panel on a feph host, while allow source routing via       */
	/* ippathmgt data panel as the packets go through kfeph/ippathmgt data panel instead of linux panel.*/
	if (EIPM_GET_PROXY_SERVER_ENABLED() == -1)
	{

	// Check the policy routing here before audit main routing table.
	EIPM_check_policy_routes(intfDataP, intfType, subnet_ptr, subnet_idx, routing_priority, rule_tbl);

	}
        update_routing = FALSE;

        for( route_idx = 0, eipm_subn_route_ptr = &subnet_ptr->routes[0];
             route_idx < subnet_ptr->route_cnt;
             route_idx++, eipm_subn_route_ptr++ )
        {
	    if (intfSpecDataP->monitor == EIPM_MONITOR_ROUTE)
	    {
		EIPM_check_pivot_routes(nl_socket,
					intf_ptr,
					subnet_ptr,
					eipm_subn_route_ptr,
					&route_tbl,
					routing_interface,
					routing_priority);
                continue;
	    }
            int lsn0_entry_idx = -1;
            int lsn1_entry_idx = -1;

            for( route_table_entry_idx = 0, os_route_ptr = &route_tbl.route_table[0];
                 route_table_entry_idx < route_tbl.route_cnt; 
                 route_table_entry_idx++, os_route_ptr++ )
            {
                if( (eipm_subn_route_ptr->destprefix == os_route_ptr->destprefix) &&
                    (((eipm_subn_route_ptr->destprefix == 0) &&
                      (IPM_IPCMPADDR(routing_gateway_ptr, &os_route_ptr->gateway) == IPM_SUCCESS)) ||
                     ((eipm_subn_route_ptr->destprefix != 0) && 
                      (IPM_IPCMPADDR(&eipm_subn_route_ptr->dest, &os_route_ptr->dest) == IPM_SUCCESS))) )
                {
		    if ( intfSpecDataP->lsn0_iface_indx == os_route_ptr->iface_indx &&
			 IPM_IPCMPADDR(&eipm_subn_route_ptr->source_ip, &os_route_ptr->srcip) == IPM_SUCCESS )
                    {
                        lsn0_entry_idx = route_table_entry_idx;
                    }
		    else if ( intfSpecDataP->lsn1_iface_indx == os_route_ptr->iface_indx &&
			      IPM_IPCMPADDR(&eipm_subn_route_ptr->source_ip, &os_route_ptr->srcip) == IPM_SUCCESS )
                    {
                        lsn1_entry_idx = route_table_entry_idx;
                    }
                    else
                    {
			//skip pivot route
                        int pivot_idx = 0;
                        bool matchFlag = FALSE;
                        for (; pivot_idx < MAX_NUM_PIVOT; pivot_idx++)
                        {
                            if (subnet_ptr->pivot_cnt[pivot_idx] > 0 &&
                                subnet_ptr->pivot_iface_indx[0][pivot_idx] == os_route_ptr->iface_indx)
                            {
                                matchFlag = TRUE;
                                break;
                            }
                        }

			/*
			 * Skip the route as its interface is a substring of IPM base interface
			 * Note:
			 *	This is a short term solution on solving issues that routes with the
			 *	destination overlap with an IPM controlled routes and they are a 
			 *	substring of IPM base interfaces.
			 *	This fix does not solve overlap routes case in general, but it is good
			 *	enough to solve the overlapping case for MGC8 specific configuration.
			 * 	Details in IMR notes of 949600.
			 */
			if(strstr(os_route_ptr->iface, intf_ptr->lsn0_baseif) != NULL
				||  strstr(os_route_ptr->iface, intf_ptr->lsn1_baseif) != NULL)
			{
				LOG_ERROR( 0, "Skip this route. Interface %s is a substring of base interface",
						os_route_ptr->iface);
				matchFlag = TRUE;
			}

                        if (matchFlag == TRUE)
                        {
                            continue;
                        }
                        LOG_ERROR( 0,
				  "Update Routes: Interface Mismatch - Dest %s/%d Src %s Type %s on %d %s; should be on %d %s%s or %d %s%s\n",
                                  IPM_ipaddr2p(&os_route_ptr->dest, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
                                  os_route_ptr->destprefix,
                                  IPM_chkipaddr2p(&os_route_ptr->srcip, ipm_ipstr_buf1, sizeof(ipm_ipstr_buf1)),
                                  (eipm_subn_route_ptr->type == EIPM_ROUTE_SUBN) ? "Subnet" : "Other ",
                                  os_route_ptr->iface_indx,
                                  os_route_ptr->iface,
				  intfSpecDataP->lsn0_iface_indx,
                                  intf_ptr->lsn0_baseif,
				  ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
				  intfSpecDataP->lsn1_iface_indx,
                                  intf_ptr->lsn1_baseif,
                                  ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
 

			/* Skip nma_route_del delete action for wcnp subnets, as the routes would be removed
			 * by EIPM_delete_routes in the end of the routine,  otherwise duplicated route delete
			 * would be triggered.
			 * The reason we minimize the scope for wcnp is that the code is here since rel17, we 
			 * do not want to add breakage for existing code.
			*/
			if ( subnet_ptr->redundancy_mode != IPM_RED_EIPM_WCNP_ACTIVE &&
			 subnet_ptr->redundancy_mode != IPM_RED_EIPM_WCNP_STANDBY    &&
			 subnet_ptr->redundancy_mode != IPM_RED_EIPM_WCNP_FIXLEFT    &&
			 subnet_ptr->redundancy_mode != IPM_RED_EIPM_WCNP_FIXRIGHT   &&
			 subnet_ptr->redundancy_mode != IPM_RED_EIPM_WCNP_SERVICE )
			{
                        (void)nma_route_del( nl_socket,
                                             os_route_ptr->iface_indx,
                                             os_route_ptr->iface,
                                            &os_route_ptr->dest,
                                             os_route_ptr->destprefix,
                                             (eipm_subn_route_ptr->type == EIPM_ROUTE_SUBN) ? NULL : &os_route_ptr->gateway );
			}

                        update_routing = TRUE;
                        route_table_entry_idx = route_tbl.route_cnt; 
                        route_idx = subnet_ptr->route_cnt;
                        break;
                    }
                }
            
            }

            if( lsn0_entry_idx == -1 &&
                lsn1_entry_idx == -1 )
            {
                LOG_ERROR( 0, 
			   "Update Routes: No Interface Match - Dest %s/%d Type %s, should be on %d %s%s or %d %s%s\n",
                           IPM_ipaddr2p(&eipm_subn_route_ptr->dest, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
                           eipm_subn_route_ptr->destprefix,
                           (eipm_subn_route_ptr->type == EIPM_ROUTE_SUBN) ? "Subnet" : "Other ",
			   intfSpecDataP->lsn0_iface_indx,
                           intf_ptr->lsn0_baseif,
			   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
                           intfSpecDataP->lsn1_iface_indx,
                           intf_ptr->lsn1_baseif,
                           ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
 

                update_routing = TRUE;
                break;
            }

            switch( eipm_subn_route_ptr->type )
            {
            case EIPM_ROUTE_SUBN:

                switch( routing_interface )
                {
                case LSN0: 
                    if( lsn0_entry_idx == -1 ||
                        lsn1_entry_idx != -1 )
                    {
                        update_routing = TRUE;
                    }
                    break;

                case LSN1: 
                    if( lsn1_entry_idx == -1 ||
                        lsn0_entry_idx != -1 )
                    {
                        update_routing = TRUE;
                    }
                    break;

                case LSN_BOTH:
                    if( lsn0_entry_idx == -1 ||
                        lsn1_entry_idx == -1  )
                    {
                        update_routing = TRUE;
                    }
                    else if( routing_priority == LSN0 &&
                             lsn0_entry_idx > lsn1_entry_idx )
                    {
                        update_routing = TRUE;
                    }
                    else if( routing_priority == LSN1 &&
                             lsn1_entry_idx > lsn0_entry_idx )
                    {
                        update_routing = TRUE;
                    }
                    break;
                }
                break;

            case EIPM_ROUTE_OTH:

                switch( routing_priority )
                {
                case LSN0: 
                    if( lsn0_entry_idx == -1 ||
                        lsn1_entry_idx != -1 )
                    {
                        update_routing = TRUE;
                    }
                    break;

                case LSN1: 
                    if( lsn1_entry_idx == -1 ||
                        lsn0_entry_idx != -1 )
                    {
                        update_routing = TRUE;
                    }
                    break;
                }
                break;
            }

            if( update_routing == TRUE )
            {
                LOG_ERROR( 0, 
			   "Update Routes: Interface Mismatch for %s%s <-> %s%s - Dest %s/%d Type %s; Routing Iface %s, Priority %s; LSN0 Table Idx %d, LSN1 Table Idx %d\n",
                           intf_ptr->lsn0_baseif,
			   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
                           intf_ptr->lsn1_baseif,
			   ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
                           IPM_ipaddr2p(&eipm_subn_route_ptr->dest, ipm_ipstr_buf, sizeof(ipm_ipstr_buf)),
                           eipm_subn_route_ptr->destprefix,
                           (eipm_subn_route_ptr->type == EIPM_ROUTE_SUBN) ? "Subnet" : "Other ",
                           routing_interface_str,
                           routing_priority_str,
                           lsn0_entry_idx,
                           lsn1_entry_idx );


                break;
            }
        }

        retval = IPM_SUCCESS;
        temp_retval = IPM_SUCCESS;

        if( update_routing == TRUE )
        {
            IPM_RTTBL delete_tbl;

            delete_tbl.route_cnt = 0;

            /* Reduce copy of OS route table to just entries that match the route data */
            for( route_idx = 0, eipm_subn_route_ptr = &subnet_ptr->routes[0];
                 route_idx < subnet_ptr->route_cnt;
                 route_idx++, eipm_subn_route_ptr++ )
            {
		if (eipm_subn_route_ptr->pivot_id > 0)
                {
                    continue;
                }

                for( route_table_entry_idx = 0, os_route_ptr = &route_tbl.route_table[0];
                     route_table_entry_idx < route_tbl.route_cnt;
                     route_table_entry_idx++, os_route_ptr++ )
                {
		    //skip pivot route
                    int pivot_idx = 0;
                    bool matchFlag = FALSE;
                    for (; pivot_idx < MAX_NUM_PIVOT; pivot_idx++)
                    {
                        if (subnet_ptr->pivot_cnt[pivot_idx] > 0 &&
                                subnet_ptr->pivot_iface_indx[0][pivot_idx] == os_route_ptr->iface_indx)
                        {
                            matchFlag = TRUE;
                        }
                    }

		    if (matchFlag)
		    {
			continue;
		    }

                    if( eipm_subn_route_ptr->destprefix == os_route_ptr->destprefix &&
                        IPM_IPCMPADDR(&eipm_subn_route_ptr->dest, &os_route_ptr->dest) ==
 IPM_SUCCESS )
                    {
			/*
			 * Skip the route as its interface is a substring of IPM base interface
			 * Note:
			 *	This is a short term solution on solving issues that routes with the
			 *	destination overlap with an IPM controlled routes and they are a 
			 *	substring of IPM base interfaces.
			 *	This fix does not solve overlap routes case in general, but it is good
			 *	enough to solve the overlapping case for MGC8 specific configuration.
			 * 	Details in IMR notes of 949600.
			 */
			if((os_route_ptr->iface_indx != intfSpecDataP->lsn0_iface_indx
				&& os_route_ptr->iface_indx != intfSpecDataP->lsn1_iface_indx)
				&&(strstr(os_route_ptr->iface, intf_ptr->lsn0_baseif) != NULL
				|| strstr(os_route_ptr->iface, intf_ptr->lsn1_baseif) != NULL))
			{
				LOG_ERROR( 0, "Skip this route. Interface %s is a substring of base interface",
						os_route_ptr->iface);
				continue;
			}
                        delete_tbl.route_table[delete_tbl.route_cnt] = *os_route_ptr;
                        delete_tbl.route_cnt++;
                    }
                }
            }

            temp_retval = EIPM_delete_routes( nl_socket, 
                                              intf_ptr, 
                                              subnet_ptr,
                                              &delete_tbl );

            if( retval == IPM_SUCCESS )
            {
                retval = temp_retval;
            }

            temp_retval = EIPM_add_routes( nl_socket, 
					   intfDataP, 
                                           intfType,
                                           subnet_idx,
                                           routing_interface,
                                           routing_priority );

            if( retval == IPM_SUCCESS )
            {
                retval = temp_retval;
            }
        }
    }


    IPM_close_netlink_socket(&nl_socket);
    return retval;
}



/**********************************************************************
 *
 * Name:        EIPM_delete_routes()
 *
 * Abstract:    Delete all routes provided in route_table_ptr
 *
 * Parameters:  nl_sock         - netlink socket fd
 *              intf_ptr        - pointer to interface data
 *              subnet_ptr      - pointer to interface data
 *              route_table_ptr - pointer to route table data
 *
 * Returns:     IPM_SUCCESS - routing table entries were deleted
 *              IPM_FAILURE - some error occurred.
 *
 **********************************************************************/

int
EIPM_delete_routes( int nl_socket, 
                    EIPM_INTF *intf_ptr, 
                    EIPM_SUBNET *subnet_ptr,
                    IPM_RTTBL *route_table_ptr )
{
IPM_ROUTE_ENTRY *route_table_entry_ptr;
int route_table_entry_idx;
int temp_retval;
int retval;

    retval = IPM_SUCCESS;
    temp_retval = IPM_SUCCESS;

    /*
     * More unsimpleness...  Originally we deleted and
     * added each route in order.  That seemed to cause
     * problems at times - sometimes the add of the
     * LSN1 route would fail, and once that happened you
     * couldn't even fix it with an "ip route" command.
     * So go through and delete all routes in reverse
     * order so we delete the subnet route last. 
     */
    for( route_table_entry_idx = route_table_ptr->route_cnt - 1, route_table_entry_ptr = &route_table_ptr->route_table[route_table_entry_idx];
         route_table_entry_idx >= 0;
         route_table_entry_idx--, route_table_entry_ptr-- )
    {
        /*
         * Delete the route.
         */
	if( route_table_entry_ptr->dest.addrtype == IPM_IPV6 )
	{
		temp_retval = nma_route_priority_del( nl_socket,
						      route_table_entry_ptr->iface_indx,
						      route_table_entry_ptr->iface,
						      &route_table_entry_ptr->dest,
						      route_table_entry_ptr->destprefix,
						      (route_table_entry_ptr->gateway.addrtype != IPM_IPBADVER) ? 
						       &route_table_entry_ptr->gateway : NULL,
						      route_table_entry_ptr->priority );
	}
	else
	{
		temp_retval = nma_route_del( nl_socket,
					     route_table_entry_ptr->iface_indx,
					     route_table_entry_ptr->iface,
					     &route_table_entry_ptr->dest,
					     route_table_entry_ptr->destprefix,
					     (route_table_entry_ptr->gateway.addrtype != IPM_IPBADVER) ? 
					      &route_table_entry_ptr->gateway : NULL );
	}
		
        /*
         * Don't overwrite a failure
         */
        if( retval == IPM_SUCCESS )
        {
            retval = temp_retval;
        }
    }

    return retval;
}



/**********************************************************************
 *
 * Name:        EIPM_add_routes()
 *
 * Abstract:    Add routes provided in the provided subnet_ptr
 *
 * Parameters:  nl_sock    - netlink socket fd
 *              intf_ptr   - pointer to base/extension interface data
 *			     Type: EIPM_INTF/EIPM_INTF_SPEC
 *		intfType - Identifies the interface as base/extension.
 *              subnet_idx - index of this subnet in interface data
 *              routing_interface - interface to add route on
 *              routing_priority - route priority when route on both
 *
 * Returns:     IPM_SUCCESS - routing table entries were deleted
 *              IPM_FAILURE - some error occurred.
 *
 **********************************************************************/
 
int
EIPM_add_routes( int nl_socket, 
		 void *intfDataP, 
                 EIPM_INTF_TYPE intfType,
                 int subnet_idx,
                 EIPM_NET routing_interface,
                 EIPM_NET routing_priority )
{
EIPM_INTF *intf_ptr;
EIPM_INTF_SPEC *intfSpecDataP;
IPM_IPADDR *routing_gateway_ptr; /* gateway to use based on route priority */
EIPM_SUBNET *subnet_ptr;
EIPM_DATA *shm_ptr = (EIPM_DATA *)EIPM_shm_ptr;
int intf_idx;
EIPM_ROUTES *route_ptr;
int route_idx;
int temp_retval;
int retval;
int primary_iface_indx;
int seconday_iface_indx;
char primary_baseif[EI_INTFNAMESIZE];
char secondary_baseif[EI_INTFNAMESIZE];
char dest_ipstr_buf[IPM_IPMAXSTRSIZE];
char gw_ipstr_buf[IPM_IPMAXSTRSIZE];
    intfSpecDataP = &(intf_ptr->specData);

    EIPM_SET_INTF_PTRS( intfDataP, intfType, intf_ptr, intfSpecDataP );

    if ( NULL == intf_ptr ) 
    {
        return IPM_FAILURE;
    }

    intf_idx = intfSpecDataP->baseIntfIdx;

    subnet_ptr = &(intf_ptr->subnet[subnet_idx]);

    retval = IPM_SUCCESS;
    temp_retval = IPM_SUCCESS;

    for( route_idx = 0, route_ptr = &subnet_ptr->routes[0];
         route_idx < subnet_ptr->route_cnt;
         route_idx++, route_ptr++ )
    {
	if (route_ptr->pivot_id > 0)
        {
            continue;
        }

       /*
        * Each subnet gets a subnet route
        * when it is created (e.g. 
        * 135.1.60.64/28 dev eth0.400)
        * and other routes may have been
        * added to this subnet.  The format
        * for the subnet routes is different.
        */
        switch( route_ptr->type )
        {
        case EIPM_ROUTE_SUBN:

            switch( routing_interface )
            {
            case LSN0:
                temp_retval = nma_route_add( nl_socket,
					     intfSpecDataP->lsn0_iface_indx,
                                             intf_ptr->lsn0_baseif,
					     intfSpecDataP->vlanId,
                                            &route_ptr->dest,
                                             route_ptr->destprefix,
                                             NULL,
                                             NULL );

                if( temp_retval != IPM_SUCCESS )
                {
                    retval = temp_retval;
                }
                break;

            case LSN1:
                temp_retval = nma_route_add( nl_socket,
					     intfSpecDataP->lsn1_iface_indx,
                                             intf_ptr->lsn1_baseif,
					     intfSpecDataP->vlanId,
                                            &route_ptr->dest,
                                             route_ptr->destprefix,
                                             NULL,
                                             NULL );

                if( temp_retval != IPM_SUCCESS )
                {
                    retval = temp_retval;
                }
                break;

            case LSN_BOTH:

                if( routing_priority == LSN1 )
                {
		    primary_iface_indx = intfSpecDataP->lsn1_iface_indx;
                    strncpy(primary_baseif, intf_ptr->lsn1_baseif, EI_INTFNAMESIZE);

		    seconday_iface_indx = intfSpecDataP->lsn0_iface_indx;
                    strncpy(secondary_baseif, intf_ptr->lsn0_baseif, EI_INTFNAMESIZE);
                }
                else /* LSN0 */
                {
		    primary_iface_indx = intfSpecDataP->lsn0_iface_indx;
                    strncpy(primary_baseif, intf_ptr->lsn0_baseif, EI_INTFNAMESIZE);

		    seconday_iface_indx = intfSpecDataP->lsn1_iface_indx;
                    strncpy(secondary_baseif, intf_ptr->lsn1_baseif, EI_INTFNAMESIZE);
                }

                temp_retval = nma_route_add( nl_socket,
                                             primary_iface_indx,
                                             primary_baseif,
					     intfSpecDataP->vlanId,
                                            &route_ptr->dest,
                                             route_ptr->destprefix,
                                             NULL,
                                             NULL );

                if( temp_retval != IPM_SUCCESS )
                {
                    retval = temp_retval;
                }

                /* 
                 * rtnetlink is the program interface for the "ip route"
                 * set of commands.  During testing we found out that
                 * ip route will not let you add the same route for
                 * each interface.  At system start here is what you
                 * see:
                 * 169.253.0.0/24 dev eth0.400  proto kernel  scope link  src 169.253.0.2
                 * 169.253.0.0/24 dev eth1.401  proto kernel  scope link  src 169.253.0.2
                 * If you delete the eth1.401 route, and then add it
                 * back in with rtnetlink you get an error that the route
                 * already exists.  You have to append it, not add it
                 * (basically the key is 169.253.0.0 and that already
                 * exists).  (Note that the "route add" command will
                 * allow you to add it).
                 */

		if(route_ptr->dest.addrtype == IPM_IPV6)
		{
			temp_retval = nma_route_append( nl_socket,
							seconday_iface_indx,
							secondary_baseif,
						       &route_ptr->dest,
							route_ptr->destprefix,
							NULL,
							NULL,
							256);
		}
		else
		{
                temp_retval = nma_route_append( nl_socket,
                                                seconday_iface_indx,
                                                secondary_baseif,
                                               &route_ptr->dest,
                                                route_ptr->destprefix,
                                                NULL,
                                                NULL,
						0);
		}
                if( retval == IPM_SUCCESS )
                {
                    retval = temp_retval;
                }
                break;

            }
            break;
				
        case EIPM_ROUTE_OTH:
            /*
             * Regular static route.
             */
	    routing_gateway_ptr = &(subnet_ptr->gateway);

            if( routing_priority == LSN1 )
            {

		if ( subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT )
		{
			int		right_intf_idx;
			int		right_sn_idx;
			IPM_RETVAL	bfd_map_retval;

			/* We have a BFD Transport and the route priority
			 * is to use Right so now check if the current one
			 * is Left and, if so, get the gatweay address from
			 * the Right.
			 */

			bfd_map_retval = EIPM_bfd_map_left2right(intf_idx,subnet_idx,&right_intf_idx,&right_sn_idx);

			if (bfd_map_retval == IPM_SUCCESS)
			{
				/* This is a Left BFD Transport subnet. */
				routing_gateway_ptr = &(shm_ptr->intf_data[right_intf_idx].subnet[right_sn_idx].gateway);
			}

		}

                temp_retval = nma_route_add( nl_socket,
					     intfSpecDataP->lsn1_iface_indx,
                                             intf_ptr->lsn1_baseif,
					     intfSpecDataP->vlanId,
                                            &route_ptr->dest,
                                             route_ptr->destprefix,
                                             routing_gateway_ptr,
                                    	     (route_ptr->source_ip.addrtype != IPM_IPBADVER) ? 
					    &route_ptr->source_ip : NULL );
            }
            else
            {
                temp_retval = nma_route_add( nl_socket,
					     intfSpecDataP->lsn0_iface_indx,
                                             intf_ptr->lsn0_baseif,
					     intfSpecDataP->vlanId,
                                            &route_ptr->dest,
                                             route_ptr->destprefix,
                                             routing_gateway_ptr,
                                    	     (route_ptr->source_ip.addrtype != IPM_IPBADVER) ? 
					    &route_ptr->source_ip : NULL );
            }

            if( temp_retval != IPM_SUCCESS )
            {
                retval = temp_retval;
            }
            break;
				
        default:
            /*
             * Invalid route.
             */
            ASRT_EXIT( ASUNEXPECTEDVAL,
                       2,
                       100,
                       subnet_ptr,
                       100,
                       &subnet_ptr->routes[0],
		       "Error: EIPM_add_routes - route type is invalid.\nsubn=%x, iface=%s%s, route type=%d\n",
                       subnet_ptr->subnet_base,
                       intf_ptr->lsn1_baseif,
		       ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ),
                       route_ptr->type );
					  
            return( IPM_FAILURE );
        }
    }

    switch( routing_interface )
    {
    case LSN0:
    case LSN1:
        EIPM_SET_GRAT_ARP(subnet_ptr, routing_interface);
        break;

    case LSN_BOTH:
        EIPM_SET_GRAT_ARP(subnet_ptr, routing_priority);
        break;
    }

    return retval;
}

/**********************************************************************
 *
 * Name:	EIPM_process_route_update
 *
 * Abstract:	Process route updates
 *
 * Parameters:	action     - add/delete
 *              ifname     - interface name ptr for route 
 *              dest_ip    - destination ptr
 *		prefixlen  - destination prefix length
 *		nexthop_ip - next hop ip ptr
 *
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 * 		IPM_PIVOT_ROUTE - this flag would notify IIPM to not monitor the route
 *
 **********************************************************************/
int EIPM_process_route_update(EIPM_ADD_DEL action, char *ifname, IPM_IPADDR *dest_ip, int prefixlen, IPM_IPADDR *nexthop_ip)
{
EIPM_DATA 	*data_ptr;
EIPM_INTF 	*intf_ptr;
EIPM_SUBNET 	*subnet_ptr;
EIPM_ROUTES 	*route_ptr;
int 		intf_idx;
int 		subnet_idx;
int 		route_idx;
int 		ret;
uint32_t	act_intf;
EIPM_NET	routing_interface;
EIPM_NET	routing_priority;
char ipm_ipstr_buf[IPM_IPMAXSTRSIZE];
EIPM_INTF_SPEC *intfSpecDataP;
char ipm_ipstr_buf1[IPM_IPMAXSTRSIZE];

int 		pivot_route = 0;

	LOG_OTHER( EIPM_LOG_ROUTECFG,
                   "EIPM_process_route_update: action %d ifname %s dest_ip %s prefixlen %d nexthop ip %s\n",
			action,
			ifname,
			(( dest_ip == NULL ) ? "null" : IPM_ipaddr2p( dest_ip, ipm_ipstr_buf, sizeof(ipm_ipstr_buf))),
			prefixlen,
			(( nexthop_ip == NULL ) ? "null" : IPM_ipaddr2p( nexthop_ip, ipm_ipstr_buf1, sizeof(ipm_ipstr_buf1))));

    if( action != EIPM_ADD &&
        action != EIPM_DEL )
    {
	/* no work to do */
	return IPM_SUCCESS;
    }

    if( ifname == NULL && 
	action == EIPM_ADD )
    {
	LOG_ERROR(0, "EIPM_process_route_update: ifname null\n" );
	return IPM_FAILURE;
    }

    if( dest_ip == NULL )
    {
	LOG_ERROR(0, "EIPM_process_route_update: dest_ip null\n" );
	return IPM_FAILURE;
    }

    if( EIPM_shm_ptr == NULL )
    {
	LOG_ERROR(0, "EIPM_process_route_update: Shared memory null\n" );
	return IPM_FAILURE;
    }

    data_ptr = (EIPM_DATA *)EIPM_shm_ptr;

    /* Look through all interfaces */
    for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
         intf_idx < data_ptr->intf_cnt;
         intf_idx++, intf_ptr++ )
    {
	intfSpecDataP = &(intf_ptr->specData);

	if( intfSpecDataP->monitor != EIPM_MONITOR_ROUTE )
	{
	    continue;		
	}

        /* Look through all subnets */
        for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
             subnet_idx < intf_ptr->subnet_cnt;
             subnet_idx++, subnet_ptr++ )
        {
		//Only feph proxy server IP is the gateway IP of access subnet
                if( (! IPM_IPADDR_ISUNSPECIFIED(dest_ip) ) &&  (! IPM_IPADDR_ISUNSPECIFIED(&subnet_ptr->gateway) ) &&
		    IPM_IPCMPADDR(dest_ip, &subnet_ptr->gateway) == IPM_SUCCESS )
		{
		    if( action == EIPM_ADD )
		    {
			if( strcmp(intf_ptr->lsn0_baseif, ifname) == 0 )
			{
			    EIPM_update_subnet_route_priority( intfSpecDataP, subnet_ptr, LSN0 );
		       	}
			else if( strcmp(intf_ptr->lsn1_baseif, ifname) == 0 )
			{
			    EIPM_update_subnet_route_priority( intfSpecDataP, subnet_ptr, LSN1 );
			}
			else
			{
			    LOG_ERROR(0, "EIPM_process_route_update: no interface match %s\n", ifname );
			    return IPM_FAILURE;
			}
		    }
		    else if( action == EIPM_DEL )
		    {
		        EIPM_update_subnet_route_priority( intfSpecDataP, subnet_ptr, LSN0 );
		    }

		    pivot_route = 1;
		    /* Schedule the configuration check to apply the above changes */
		    EIPM_CHECK_INTF_CONFIG( intfSpecDataP );
		}
	}
    }	
    if (pivot_route)
	return IPM_PIVOT_ROUTE;
    else
        return IPM_SUCCESS;
}

/**********************************************************************
*
* Name:        EIPM_check_pivot_routes()
*
* Abstract:    Compare the OS route table against the IPM data.
*               Update the OS route table if a discrepency is found.
*
* Parameters:  nl_socket - netlink socket fd
*                        intf_ptr - pointer to interface data
*                        subnet_ptr - pointer to interface data
*                        eipm_subn_route_ptr - pointer to route data
*                        route_tble - pointer to route table data
*                    routing_interface - interface to add route on
*                    routing_priority - route priority when route on both
*
*
* Returns:     IPM_SUCCESS - routing table was successfully changed if needed
*              IPM_FAILURE - some error occurred.
*
**********************************************************************/
int EIPM_check_pivot_routes(int nl_socket,
        		EIPM_INTF *intf_ptr,
        		EIPM_SUBNET *subnet_ptr,
        		EIPM_ROUTES *eipm_subn_route_ptr,
        		IPM_RTTBL * route_tbl,
        		EIPM_NET routing_interface,
        		EIPM_NET routing_priority)
{
        IPM_ROUTE_ENTRY *os_route_ptr;
        int route_table_entry_idx;
        int retval;
        int temp_retval;
	int pivot_id;
	EIPM_NET sendARP;
	char ipstr_buf[IPM_IPMAXSTRSIZE];
	char gwstr_buf[IPM_IPMAXSTRSIZE];

        retval = IPM_SUCCESS;
	sendARP = LSN_NONE;

        // for a given interface, if it is Access Subnet which uses pivot,
	//every route will have pivot_id > 0.
        if (eipm_subn_route_ptr->pivot_id == 0)
        {
                return IPM_SUCCESS;
        }

	pivot_id = eipm_subn_route_ptr->pivot_id;
	if (ipm_isVirtual() != 1)
	{
		// pivot driver
        for( route_table_entry_idx = 0, os_route_ptr = &route_tbl->route_table[0];
                route_table_entry_idx < route_tbl->route_cnt;
                route_table_entry_idx++, os_route_ptr++ )
        {
                if((subnet_ptr->pivot_iface_indx[0][pivot_id] == os_route_ptr->iface_indx) &&
                        (eipm_subn_route_ptr->destprefix == os_route_ptr->destprefix) &&
                        ( ( (eipm_subn_route_ptr->destprefix == 0) &&
                        (IPM_IPCMPADDR(&eipm_subn_route_ptr->nexthop, &os_route_ptr->gateway) == IPM_SUCCESS)
                        ) || ( (eipm_subn_route_ptr->destprefix != 0) &&
                        (IPM_IPCMPADDR(&eipm_subn_route_ptr->dest, &os_route_ptr->dest) == IPM_SUCCESS)
                        ) ) )
                {
                        //index and route info both match, does active match?
                        //get active slave in OS.
                        EIPM_NET activeSlave = EIPM_getActiveSlave(pivot_id);
                        if (activeSlave == LSN_NONE)
                        {
                                return IPM_FAILURE;
                        }

			sendARP = LSN_BOTH;

                        switch( eipm_subn_route_ptr->type )
                        {
                        case EIPM_ROUTE_SUBN:
                        {
				//Don't need to change subnet based route
                                break;
                        }
                        case EIPM_ROUTE_OTH:
                        {
                                switch( routing_priority )
                                {
                                case LSN0:
                                {
                                        if ((activeSlave != routing_priority)
					    && (ipm_check_linkup("eth0") == IPM_SUCCESS))
                                        {
                                                //switch over to LSN0
                                                EIPM_setActiveSlave(pivot_id, intf_ptr->lsn0_baseif);
                                                //update EIPM data
                                                subnet_ptr->pivot_act_base[pivot_id] = routing_priority;
						sendARP = LSN0;
                                        }
                                        break;
                                }
                                case LSN1:
                                {
                                        if ((activeSlave != routing_priority)
					     && (ipm_check_linkup("eth1") == IPM_SUCCESS))
                                        {
                                                //switch over to LSN1
                                                EIPM_setActiveSlave(pivot_id, intf_ptr->lsn1_baseif);
                                                //update EIPM data
                                                subnet_ptr->pivot_act_base[pivot_id] = routing_priority;
						sendARP = LSN1;
					}
                                        break;
                                }
                                }
                        }
                        }
                        break;
                }
        }

	//there is switchover happens, send ARP/NS
	if (sendARP == LSN0 || sendARP == LSN1)
        {
                EIPM_SUBNET *subn_ptr;
                EIPM_ROUTES *route_ptr;
                EIPM_IPDATA *ip_ptr;
                int subnet_idx;
                int route_idx;
                int ip_idx;
                IPM_IPADDR destIP;
                IPM_IPADDR srcIP;
                bool newDest = FALSE;
                bool newSrc = FALSE;

                destIP.addrtype = IPM_IPBADVER;
                srcIP.addrtype = IPM_IPBADVER;

                for( subnet_idx = 0, subn_ptr = &intf_ptr->subnet[0];
                                subnet_idx < intf_ptr->subnet_cnt;
                                subnet_idx++, subn_ptr++ )
                {
			//search for destination IP
			newDest = FALSE;	
			for( route_idx = 0, route_ptr = &subn_ptr->routes[0];
				route_idx < subn_ptr->route_cnt;
				route_idx++, route_ptr++ )
			{
				//only search static and default routes
				if ((pivot_id != route_ptr->pivot_id) ||
					(route_ptr->type == EIPM_ROUTE_SUBN))
				{
					continue;
				}
                                destIP = route_ptr->nexthop;
				newDest = TRUE;
				break; //Only one FEPH supported as next hop in each subnet
			}
			if (newDest == FALSE)
			{
				continue;
			}
			//search for source IP
                        for( ip_idx = 0, ip_ptr = &subn_ptr->ips[0];
                                        ip_idx < subn_ptr->ip_cnt;
                                        ip_idx++, ip_ptr++ )
                        {
                                if (ip_ptr->pivot_id != pivot_id)
                                {
                                        continue;
                                }

                                srcIP = ip_ptr->ipaddr;
				if ( srcIP.addrtype == IPM_IPV4 )
				{
					if (sendARP == LSN0)
					{
						int pivot_arp_socket = EIPM_create_arp_socket( LSN0,
								IPM_IPV4,
								subn_ptr->pivot_iface_indx[0][pivot_id],
								ARPOP_REQUEST);

						EIPM_sendARP(pivot_arp_socket,
								intf_ptr->lsn0_hwaddr,
								&srcIP,
								&destIP,
 								subn_ptr->pivot_iface_indx[0][pivot_id],
								ARPOP_REQUEST);
						LOG_ERROR(0, "EIPM_sendARP Send ARP Request on LSN0 for IP %s to %s\n",
								IPM_ipaddr2p(&srcIP, ipstr_buf, sizeof(ipstr_buf)),
								IPM_ipaddr2p(&destIP, gwstr_buf, sizeof(gwstr_buf)));
						if (pivot_arp_socket >= 0)
						{
							close(pivot_arp_socket);
						}
					}
					else
					{
						int pivot_arp_socket = EIPM_create_arp_socket( LSN1,
								IPM_IPV4,
								subn_ptr->pivot_iface_indx[0][pivot_id],
								ARPOP_REQUEST);

						EIPM_sendARP(pivot_arp_socket,
							intf_ptr->lsn1_hwaddr,
							&srcIP,
							&destIP,
							subn_ptr->pivot_iface_indx[0][pivot_id],
							ARPOP_REQUEST);
						LOG_ERROR(0, "EIPM_sendARP Send ARP Request on LSN1 for IP %s to %s\n",
								IPM_ipaddr2p(&srcIP, ipstr_buf, sizeof(ipstr_buf)),
								IPM_ipaddr2p(&destIP, gwstr_buf, sizeof(gwstr_buf)));
						if (pivot_arp_socket >= 0)
						{
							close(pivot_arp_socket);
						}
					}
				}
				else if (srcIP.addrtype == IPM_IPV6)
				{
					if (sendARP == LSN0)
					{
						int pivot_arp_socket = EIPM_create_arp_socket( LSN0,
								IPM_IPV6,
								subn_ptr->pivot_iface_indx[0][pivot_id],
								ND_NEIGHBOR_SOLICIT);

						EIPM_sendARP(pivot_arp_socket,
							intf_ptr->lsn0_hwaddr,
							&srcIP,
							&destIP,
							subn_ptr->pivot_iface_indx[0][pivot_id],
							ND_NEIGHBOR_SOLICIT);
						LOG_ERROR(0, "EIPM_sendARP Send NS on LSN0 for IP %s to %s\n",
								IPM_ipaddr2p(&srcIP, ipstr_buf, sizeof(ipstr_buf)),
								IPM_ipaddr2p(&destIP, gwstr_buf, sizeof(gwstr_buf)));
						if (pivot_arp_socket >= 0)
						{
							close(pivot_arp_socket);
						}
					}
					else
					{
						int pivot_arp_socket = EIPM_create_arp_socket( LSN1,
								IPM_IPV6,
								subn_ptr->pivot_iface_indx[0][pivot_id],
								ND_NEIGHBOR_SOLICIT);

						EIPM_sendARP(pivot_arp_socket,
							intf_ptr->lsn1_hwaddr,
							&srcIP,
							&destIP,
							subn_ptr->pivot_iface_indx[0][pivot_id],
							ND_NEIGHBOR_SOLICIT);
						LOG_ERROR(0, "EIPM_sendARP Send NS on LSN1 for IP %s to %s\n",
								IPM_ipaddr2p(&srcIP, ipstr_buf, sizeof(ipstr_buf)),
								IPM_ipaddr2p(&destIP, gwstr_buf, sizeof(gwstr_buf)));
						if (pivot_arp_socket >= 0)
						{
							close(pivot_arp_socket);
						}
					}
				}
			}
                }
        }
	}
	else
	{
		// Tunnel
	for( route_table_entry_idx = 0, os_route_ptr = &route_tbl->route_table[0];
		route_table_entry_idx < route_tbl->route_cnt;
		route_table_entry_idx++, os_route_ptr++ )
	{
		/*
		 * For current route pointed by eipm_subn_route_ptr, search route_tble from kernel
		 * if it is matched, then 
		 * 	if routing_priority is equal to subnet_ptr->pivot_act_base[pivot_id], then do nothing
		 *	else 	send ARP from active interface by internal floating IP 
		 * else 
		 * 	if routing_priority is equal to subnet_ptr->pivot_act_base[pivot_id], then do nothing
		 *	else 	send ARP from active interface by internal floating IP 
		 *	Add route
		 * Notes: Don't send ARP for subnet route
		 */
		if ( ((subnet_ptr->pivot_iface_indx[0][pivot_id] == os_route_ptr->iface_indx) 
			&& (eipm_subn_route_ptr->destprefix == os_route_ptr->destprefix))
		    && ( ((eipm_subn_route_ptr->destprefix == 0)
				&& (IPM_IPCMPADDR(&eipm_subn_route_ptr->nexthop, &os_route_ptr->gateway) == IPM_SUCCESS))
			|| ((eipm_subn_route_ptr->destprefix != 0) 
				&& (IPM_IPCMPADDR(&eipm_subn_route_ptr->dest, &os_route_ptr->dest) == IPM_SUCCESS))
		       )
		   )		
		{
			sendARP == LSN_BOTH;
			// Match the default route if the prefix is 0 or static route if the prefix is greater than 0
			if (EIPM_ROUTE_SUBN == eipm_subn_route_ptr->type)
			{
				// It is subnet route and break because it doesn't send ARP
				break;
			}
			else if (EIPM_ROUTE_OTH == eipm_subn_route_ptr->type)
			{
				// It is default/static route
				if (LSN0 == routing_priority)
				{
					if ( (subnet_ptr->pivot_act_base[pivot_id] != routing_priority)
						&& (ipm_check_linkup("eth0") == IPM_SUCCESS) )
					{
						subnet_ptr->pivot_act_base[pivot_id] = routing_priority;
						sendARP = LSN0;
					}

				}
				else if (LSN1 == routing_priority)
				{
					if ( (subnet_ptr->pivot_act_base[pivot_id] != routing_priority)
						&& (ipm_check_linkup("eth1") == IPM_SUCCESS) )
					{
						subnet_ptr->pivot_act_base[pivot_id] = routing_priority;
						sendARP = LSN1;
					}
				}
			}
			// break because it has found one matched route
			break;
		}

	}

	/* 
	 * Send ARP if it is needed. 
	 * It only sends ARP per based interface eth0/eth1 or eth0.800/eth1.801
	 * For IPv4 and IPv6 route, it only sends ARP because the tunnel is created
	 * on IPv4 IP and it doesn't need to sending NS
	 */ 
	if (LSN0 == sendARP || LSN1 == sendARP)
	{
		int ip_idx;
		EIPM_IPDATA *ip_ptr;
		IPM_IPADDR tmp_src_ip;
		IPM_IPADDR tmp_dst_ip;	
		for (ip_idx = 0, ip_ptr = &subnet_ptr->ips[0];
			ip_idx < subnet_ptr->ip_cnt;
			ip_idx++, ip_ptr++)
		{
			if (ip_ptr->pivot_id != pivot_id)
			{
				continue;
			}

			// Find one IP and try to send ARP
			IPM_GET_TUNNEL_ENDPOINT_IPS(pivot_id, tmp_src_ip, tmp_dst_ip);
			if ( (IPM_IPBADVER == tmp_src_ip.addrtype) 
				|| (IPM_IPBADVER == tmp_dst_ip.addrtype) )
			{
				LOG_ERROR(0, "EIPM_check_pivot_routes, Failed to find the endpoint IP by id=%d\n", pivot_id);
				continue;
			}
			if ( (IPM_IPV4 == tmp_src_ip.addrtype) 
				&& (IPM_IPV4 == tmp_dst_ip.addrtype)
			   )
			{
				char src_ip_buf[IPM_IPMAXSTRSIZE];
				char dst_ip_buf[IPM_IPMAXSTRSIZE];
				if (LSN0 == sendARP)
				{
					memset(src_ip_buf, 0, IPM_IPMAXSTRSIZE);
					memset(dst_ip_buf, 0, IPM_IPMAXSTRSIZE);
					int pivot_arp_socket = EIPM_create_arp_socket( LSN0,
						IPM_IPV4,
						intf_ptr->specData.lsn0_iface_indx,
						ARPOP_REQUEST);
					int ret = EIPM_sendARP(pivot_arp_socket,
						intf_ptr->lsn0_hwaddr,
						&tmp_src_ip,
						&tmp_dst_ip,
						intf_ptr->specData.lsn0_iface_indx,
						ARPOP_REQUEST);
					LOG_ERROR(0, "EIPM_check_pivot_routes, Send ARP on LSN0(index=%d) from %s to %s with ret=%d\n",
						intf_ptr->specData.lsn0_iface_indx,
						IPM_ipaddr2p(&tmp_src_ip, src_ip_buf, sizeof(src_ip_buf)),
						IPM_ipaddr2p(&tmp_dst_ip, dst_ip_buf, sizeof(dst_ip_buf)),
						ret);
					if (pivot_arp_socket >= 0)
					{
						close(pivot_arp_socket);
					}
				}
				else 
				{
					memset(src_ip_buf, 0, IPM_IPMAXSTRSIZE);
					memset(dst_ip_buf, 0, IPM_IPMAXSTRSIZE);
					int pivot_arp_socket = EIPM_create_arp_socket( LSN1,
						IPM_IPV4,
						intf_ptr->specData.lsn1_iface_indx,
						ARPOP_REQUEST);
					int ret = EIPM_sendARP(pivot_arp_socket,
						intf_ptr->lsn1_hwaddr,
						&tmp_src_ip,
						&tmp_dst_ip,
						intf_ptr->specData.lsn1_iface_indx,
						ARPOP_REQUEST);
					LOG_ERROR(0, "EIPM_check_pivot_routes, Send ARP on LSN1(index=%d) from %s to %s with ret=%d\n",
						intf_ptr->specData.lsn1_iface_indx,
						IPM_ipaddr2p(&tmp_src_ip, src_ip_buf, sizeof(src_ip_buf)),
						IPM_ipaddr2p(&tmp_dst_ip, dst_ip_buf, sizeof(dst_ip_buf)),
						ret);
					if (pivot_arp_socket >= 0)
					{
						close(pivot_arp_socket);
					}
				}
			}
				
		} // End loop for all IP of this subnet
	} // End if for trying to send ARP 
	} // End if of tunnel interface

        if (sendARP != LSN_NONE)
	{
		//there is match found, return.
                return retval;
        }

        if (route_table_entry_idx == route_tbl->route_cnt)
        {
		char name[EI_INTFNAMESIZE];
                sprintf(name, "pivot%d", pivot_id);

                //add new route according to EIPM data.
                switch( eipm_subn_route_ptr->type )
                {
                        case EIPM_ROUTE_SUBN:
                        {
                                retval = nma_route_append( nl_socket,
                                        subnet_ptr->pivot_iface_indx[0][pivot_id],
                                        name,
                                        &eipm_subn_route_ptr->dest,
                                        eipm_subn_route_ptr->destprefix,
                                        NULL,
                                        NULL,
                                        0);
                                break;
                        }
                        case EIPM_ROUTE_OTH:
                        {
				int metric = 0;
				if (eipm_subn_route_ptr->dest.addrtype == IPM_IPV4)
				{
					metric = pivot_id;
				}

                                retval = nma_route_append( nl_socket,
                                        subnet_ptr->pivot_iface_indx[0][pivot_id],
                                        name,
                                        &eipm_subn_route_ptr->dest,
                                        eipm_subn_route_ptr->destprefix,
                                        &eipm_subn_route_ptr->nexthop,
                                        NULL,
                                        metric);
				break;
			}
		}
        }
        return retval;
}

/*
 * Name:        EIPM_read_rules()
 *
 * Abstract:    Get all existing rules from OS.
 *
 * Parameters:  nl_socket - netlink socket fd
 *              rule_tbl_ptr - pointer to where the rules will be stored
 *
 * Returns:     IPM_SUCCESS - rule table was successfully got
 *              IPM_FAILURE - some error occurred.
 */
int EIPM_read_rules(IPM_RULETBL *rule_tbl_ptr)
{

	struct
	{
		struct nlmsghdr header;
		struct rtmsg route;
		char data[256];
	} request;

	struct msghdr msg;
	struct iovec iov;
	struct sockaddr_nl nladdr;
	int nl_socket;
	int NET_FAMILY;
	int retval, rtattr_len, i, rule_cnt;
	int nlmsg_len = 0;
	char rulebuff[sizeof (request) * EIPM_MAX_RULE_ENTRY];
	char *read_ptr;
	struct nlmsghdr * nlmsg_ptr;
	struct rtmsg * rtmsg_ptr;
	struct rtattr * rtattr_ptr;
	IPM_RULE_ENTRY *rule_ptr;
	int errcnt;
	struct timespec sel_time;
	uint32_t msg_seq;

	// Create OS netlink socket.
	nl_socket = IPM_open_netlink_socket();

	if (nl_socket < 0)
	{
		LOG_ERROR(NMA_OROUTE, "EIPM_read_rules: Failed to open netlink socket.\n");
		return ( IPM_FAILURE);
	}

	// set os socket
	memset(&nladdr, 0, sizeof (nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	// populate nlmsg header for get existing rules
	request.header.nlmsg_len = NLMSG_LENGTH(sizeof (struct rtmsg));
	request.header.nlmsg_type = RTM_GETRULE;
	request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	request.header.nlmsg_seq = msg_seq = ++IPM_rt_seq;

	request.route.rtm_family = AF_INET;

	iov.iov_base = (void *) &(request.header);
	iov.iov_len = request.header.nlmsg_len;

	// populate message struct
	msg.msg_name = (void *) &nladdr;
	msg.msg_namelen = sizeof (nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	// The rule table will cover both IPv4 and IPv6.
	for (rule_cnt = 0, i = 0; i < 2; i++)
	{
		if (i == 0)
		{
			// IPv4 first
			NET_FAMILY = AF_INET;
		}
		else
		{
			// Then IPv6
			NET_FAMILY = AF_INET6;
		}

		request.route.rtm_family = NET_FAMILY;

		if (sendmsg(nl_socket, &msg, 0) == -1)
		{
			LOG_FORCE(NMA_OROUTE, "EIPM_read_rules: Failed to send message.\n");
			rule_cnt = 0;
			IPM_close_netlink_socket(&nl_socket);
			return IPM_FAILURE;
		}

		read_ptr = rulebuff;

		// Use a while loop to receive all nlmsg from OS until NLMSG_DONE is set
		// or error count reaches the threshold.
		errcnt = 0;
		while (1)
		{
			// Fail due to too many error, return failure.
			if (errcnt > 2)
			{
				LOG_ERROR(NMA_OROUTE, "EIPM_read_rules: Too many error occur when receiving answers for read rules.\n");
				rule_cnt = 0;
				IPM_close_netlink_socket(&nl_socket);
				return IPM_FAILURE;
			}

			retval = recv(nl_socket, read_ptr, sizeof (rulebuff) - nlmsg_len, MSG_DONTWAIT);

			if (retval < 0)
			{
				if (errno == EINTR)
				{
					continue;
				}

				// For EAGAIN error, retry more times.
				if (errno == EAGAIN)
				{
					errcnt++;
					sel_time.tv_sec = 0;
					sel_time.tv_nsec = 5000;
					nanosleep(&sel_time, 0);
					continue;
				}

				LOG_FORCE(NMA_OROUTE, "EIPM_read_rules: Error found when receiving answers, error %s", strerror(errno));
				rule_cnt = 0;
				IPM_close_netlink_socket(&nl_socket);
				return IPM_FAILURE;
			}


			nlmsg_ptr = (struct nlmsghdr *) read_ptr;

			if (nlmsg_ptr->nlmsg_seq != msg_seq)
			{
				errcnt++;
				continue;
			}

			// All message have been got, break out while loop.
			if (nlmsg_ptr->nlmsg_type == NLMSG_DONE)
			{
				if (nlmsg_ptr->nlmsg_len <= sizeof (rulebuff) - nlmsg_len)
				{
					break;
				}
				else
				{
					LOG_FORCE(NMA_OROUTE, "EIPM_read_rules: Not enough buffer, received message is truncated.");
					rule_cnt = 0;
					IPM_close_netlink_socket(&nl_socket);
					return IPM_FAILURE;
				}
			}

			nlmsg_len += retval;
			if (nlmsg_len > sizeof (rulebuff))
			{
				LOG_FORCE(NMA_OROUTE, "EIPM_read_rules: Not enough buffer to receive further message.");
				rule_cnt = 0;
				IPM_close_netlink_socket(&nl_socket);
				return IPM_FAILURE;
			}

			read_ptr = read_ptr + retval;
		}

		nlmsg_ptr = (struct nlmsghdr *) rulebuff;

		// Parse every nlmsg received from OS
		for (rule_ptr = &(rule_tbl_ptr->rule_entry[rule_cnt]); NLMSG_OK(nlmsg_ptr, nlmsg_len);
			nlmsg_ptr = NLMSG_NEXT(nlmsg_ptr, nlmsg_len), rule_ptr++)
		{
			// get the pointer to the rtmsg struct in specified nlmsg
			rtmsg_ptr = (struct rtmsg *) NLMSG_DATA(nlmsg_ptr);

			// table 0 is not needed.
			if (rtmsg_ptr->rtm_table == 0)
			{
				continue;
			}

			rule_ptr->table_num = rtmsg_ptr->rtm_table;
			rule_ptr->prefix = rtmsg_ptr->rtm_src_len;
			rule_ptr->priority = 0;

			memset(&(rule_ptr->srcip), 0, sizeof (IPM_IPADDR));

			// get the pointer to attributes and the total length of attributes
			rtattr_ptr = (struct rtattr *) RTM_RTA(rtmsg_ptr);
			rtattr_len = RTM_PAYLOAD(nlmsg_ptr);

			// Parse every attributes contained in specified nlmsg header
			for (; RTA_OK(rtattr_ptr, rtattr_len); rtattr_ptr = RTA_NEXT(rtattr_ptr, rtattr_len))
			{
				// Only care the RTA_SRC as it indicates the from ip addr.
				switch (rtattr_ptr->rta_type)
				{
					case RTA_SRC:
						if (NET_FAMILY == AF_INET)
						{
							IPM_in2ipaddr(RTA_DATA(rtattr_ptr), sizeof (struct in_addr), &rule_ptr->srcip);
						}
						else if (NET_FAMILY == AF_INET6)
						{
							IPM_in2ipaddr(RTA_DATA(rtattr_ptr), sizeof (struct in6_addr), &rule_ptr->srcip);
						}
						break;

					case RTA_PRIORITY:
						rule_ptr->priority = *(int *) RTA_DATA(rtattr_ptr);
						break;

					default:
						break;
				}
			}

			// For the table main/local/default, there is no rtattr. So, the src ip addr and type will all be zero.
			// reset the addrtype here to be used by other function.
			if ((rule_ptr->srcip.addrtype == 0) &&
				((rtmsg_ptr->rtm_table == RT_TABLE_DEFAULT) ||
				(rtmsg_ptr->rtm_table == RT_TABLE_MAIN) ||
				(rtmsg_ptr->rtm_table == RT_TABLE_HOST) ||
				(rtmsg_ptr->rtm_table == RT_TABLE_LOCAL))   )
			{
				if (NET_FAMILY == AF_INET)
				{
					rule_ptr->srcip.addrtype = IPM_IPV4;
				}
				else if (NET_FAMILY == AF_INET6)
				{
					rule_ptr->srcip.addrtype = IPM_IPV6;
				}
			}

			rule_cnt++;
		}

	}

	rule_tbl_ptr->rule_cnt = rule_cnt - 1;

	IPM_close_netlink_socket(&nl_socket);
	return IPM_SUCCESS;
}

/*
 * Name:        EIPM_check_policy_routes()
 *
 * Abstract:    Audit the source based routing in the system per subnet and 
 *              correct them on any error.
 *
 * Parameters:  nl_socket       - netlink socket fd
 *              intfDataP       - interface pointer associated with the subnet
 *              intfType        - interface type associated with the subnet
 *              subnet_ptr      - subnet pointer to be checked
 *              subnet_idx      - subnet index 
 *              routing_priority- system routing priority
 *              rule_tbl        - rules existing in OS
 *
 * Returns:     IPM_SUCCESS - audit run successfully
 *              IPM_FAILURE - some error occurred.
 */
int EIPM_check_policy_routes(void *intfDataP, EIPM_INTF_TYPE intfType, EIPM_SUBNET *subnet_ptr, int subnet_idx, EIPM_NET routing_priority, IPM_RULETBL rule_tbl)
{
	int retval;
	int n, i;
	IPM_RTTBL os_route_tbl;
	EIPM_INTF *intf_ptr;
	EIPM_INTF_SPEC *intfSpecDataP;
	IPM_ROUTE_ENTRY base_route_entry[MAX_NUM_PIVOT];
	uint8_t max_valid_entry = 0;
	bool matched_rule_found = FALSE;
	IPM_IPADDR * gateway_ptr;
	IPM_RULE_ENTRY upd_rule_entry;
	bool BFD_SVC_SUBNET = FALSE;
	bool BFD_LEFT_VALID = FALSE;
	bool BFD_RIGHT_VALID = FALSE;
	int bfd_left_intf_idx, bfd_left_sn_idx, bfd_right_intf_idx, bfd_right_sn_idx;
	bool send_garp = FALSE;

	EIPM_DATA *shm_ptr = (EIPM_DATA *) EIPM_shm_ptr;

	EIPM_SET_INTF_PTRS(intfDataP, intfType, intf_ptr, intfSpecDataP);

	if (rule_tbl.rule_cnt == 0)
	{
		LOG_ERROR(NMA_OROUTE, "EIPM_check_policy_routes: No valid rule in the rule table.\n");
		return IPM_FAILURE;
	}

	//PROXY ARP does not work when SBPR is enable, so stop add policy routes
	if (EIPM_GET_PROXY_SERVER_ENABLED() == TRUE || EIPM_GET_PROXY_SERVER_ENABLED() == FALSE)
	{
		return IPM_SUCCESS;
	}

	// Source based routing is not enabled for this subnet, audit OS rule.
	if (subnet_ptr->table_num == RT_TABLE_UNSPEC)
	{
		for (n = 0; n < rule_tbl.rule_cnt; n++)
		{
			if ((IPM_IPCMPADDR(&subnet_ptr->subnet_base, &rule_tbl.rule_entry[n].srcip) == IPM_SUCCESS) &&
				(subnet_ptr->prefixlen == rule_tbl.rule_entry[n].prefix))
			{
				// We don't delete route entry in the associated table here to avoid the error
				// of deleting the route entries which are still being used by other subnet.
				ipm_rule_mgr(EIPM_DEL, &rule_tbl.rule_entry[n]);
			}
		}

		return IPM_SUCCESS;
	}

	bzero(base_route_entry, sizeof (base_route_entry));
	bzero(&upd_rule_entry, sizeof (upd_rule_entry));

	if (subnet_ptr->table_num >= RT_TABLE_DEFAULT)
	{
		LOG_ERROR(NMA_OROUTE, "EIPM_check_policy_routes: Invalid table id.\n");
		return IPM_FAILURE;
	}

	// Get the bfd service subnet attributes here. 
	if ((subnet_ptr->redundancy_mode == IPM_RED_EIPM_BFD) || (subnet_ptr->redundancy_mode == IPM_RED_BFD_RSR))
	{
		EIPM_bfd_map_svc2trans(intfSpecDataP->baseIntfIdx, subnet_idx,
			&bfd_left_intf_idx, &bfd_left_sn_idx,
			&bfd_right_intf_idx, &bfd_right_sn_idx);

		if ((bfd_left_intf_idx != -1) && (bfd_left_sn_idx != -1))
		{
			BFD_LEFT_VALID = TRUE;
		}

		if ((bfd_right_intf_idx != -1) && (bfd_right_sn_idx != -1))
		{
			BFD_RIGHT_VALID = TRUE;
		}

		BFD_SVC_SUBNET = TRUE;
	}
	// Policy based routes for the BFD Transport subnet must only use the configured interface.
    	else if (subnet_ptr->redundancy_mode == IPM_RED_BFD_TRANSPORT)
	{
		if (intf_ptr->lsn0_baseif[0] != 0)
		{
			routing_priority = LSN0;
		}
		else
		{
			routing_priority = LSN1;
		}
	}

	// First, according to the shared memory, populate the needed route entries in a array as a base,
	// which will be used to compare with the route entries got from OS.
	if (intfSpecDataP->monitor == EIPM_MONITOR_ROUTE)
	{
		for (n = 0; n < subnet_ptr->ip_cnt; n++)
		{
			if ((subnet_ptr->ips[n].type != EIPM_IP_PROXY_CLIENT) || (subnet_ptr->ips[n].pivot_id == 0))
			{
				continue;
			}

			// check if this pivot is used.
			for (i = 0; i < max_valid_entry; i++)
			{
				if (base_route_entry[i].iface_indx == subnet_ptr->pivot_iface_indx[0][subnet_ptr->ips[n].pivot_id])
				{
					break;
				}
			}

			if (i != max_valid_entry)
			{
				// Find the pivot, continue checking next valid ip
				continue;
			}

			// add default route for this pivot.
			base_route_entry[max_valid_entry].iface_indx = subnet_ptr->pivot_iface_indx[0][subnet_ptr->ips[n].pivot_id];
			memcpy(&base_route_entry[max_valid_entry].gateway, &subnet_ptr->gateway, sizeof (IPM_IPADDR));
			sprintf(base_route_entry[max_valid_entry].iface, "pivot%d", subnet_ptr->ips[n].pivot_id);
			base_route_entry[max_valid_entry].dest.addrtype = subnet_ptr->gateway.addrtype;
			//metric should be 1024 for IPV6 routes
			if(subnet_ptr->ips[n].ipaddr.addrtype == IPM_IPV6)
			{
				base_route_entry[max_valid_entry].priority = 1024;
			}
			else
			{
				base_route_entry[max_valid_entry].priority = subnet_ptr->ips[n].pivot_id;
			}
			max_valid_entry++;

			// Audit the pivot active slave interface.
			if (ipm_isVirtual() != 1)
			{
				ipm_audit_pivot_intf(intf_ptr, subnet_ptr, subnet_ptr->ips[n].pivot_id, routing_priority);
			}
		}
	}
	else
	{
		if (subnet_ptr->ip_cnt > 0)
		{
			// Only two entries for non-pivot subnet
			// - default entry
			// Only care the field destip, destprefix and default gateway.
			// Because destip and destprefix are all zero in default route entry,
			// Only populate the default gateway and dev.
			// - subnet based route entry
			// Field destip, destprefix should be subnet base, subnet prefix.
			// nexthop/gateway should be zero for subnet based route.

			max_valid_entry = 2;

			gateway_ptr = &subnet_ptr->gateway;

			if (routing_priority == LSN0)
			{
				base_route_entry[0].iface_indx = intfSpecDataP->lsn0_iface_indx;
				strcpy(base_route_entry[0].iface, intf_ptr->lsn0_baseif);
				base_route_entry[1].iface_indx = intfSpecDataP->lsn0_iface_indx;
				strcpy(base_route_entry[1].iface, intf_ptr->lsn0_baseif);

				if (BFD_SVC_SUBNET && BFD_LEFT_VALID)
				{
					base_route_entry[0].iface_indx = shm_ptr->intf_data[bfd_left_intf_idx].specData.lsn0_iface_indx;
					strcpy(base_route_entry[0].iface, shm_ptr->intf_data[bfd_left_intf_idx].lsn0_baseif);
					gateway_ptr = &(shm_ptr->intf_data[bfd_left_intf_idx].subnet[bfd_left_sn_idx].gateway);
					base_route_entry[1].iface_indx = shm_ptr->intf_data[bfd_left_intf_idx].specData.lsn0_iface_indx;
					strcpy(base_route_entry[1].iface, shm_ptr->intf_data[bfd_left_intf_idx].lsn0_baseif);
				}
				else if (BFD_SVC_SUBNET && !BFD_LEFT_VALID)
				{
					// If routing priority is lsn0 while left transport subnet is
					// not valid, this bfd service subnet can't have valid source 
					// based routing entry.
					max_valid_entry = 0;
				}
			}
			else if (routing_priority == LSN1)
			{
				base_route_entry[0].iface_indx = intfSpecDataP->lsn1_iface_indx;
				strcpy(base_route_entry[0].iface, intf_ptr->lsn1_baseif);
				base_route_entry[1].iface_indx = intfSpecDataP->lsn1_iface_indx;
				strcpy(base_route_entry[1].iface, intf_ptr->lsn1_baseif);

				if (BFD_SVC_SUBNET && BFD_RIGHT_VALID)
				{
					base_route_entry[0].iface_indx = shm_ptr->intf_data[bfd_right_intf_idx].specData.lsn1_iface_indx;
					strcpy(base_route_entry[0].iface, shm_ptr->intf_data[bfd_right_intf_idx].lsn1_baseif);
					gateway_ptr = &(shm_ptr->intf_data[bfd_right_intf_idx].subnet[bfd_right_sn_idx].gateway);
					base_route_entry[1].iface_indx = shm_ptr->intf_data[bfd_right_intf_idx].specData.lsn1_iface_indx;
					strcpy(base_route_entry[1].iface, shm_ptr->intf_data[bfd_right_intf_idx].lsn1_baseif);
				}
				else if (BFD_SVC_SUBNET && !BFD_RIGHT_VALID)
				{
					// If routing priority is lsn1 while right transport subnet is
					// not valid, this bfd service subnet can't have valid source 
					// based routing entry.
					max_valid_entry = 0;
				}
			}

			base_route_entry[0].dest.addrtype = gateway_ptr->addrtype;
			memcpy(&base_route_entry[0].gateway, gateway_ptr, sizeof (IPM_IPADDR));
			base_route_entry[1].dest = subnet_ptr->subnet_base;
			base_route_entry[1].destprefix = subnet_ptr->prefixlen;
			base_route_entry[1].gateway.addrtype = base_route_entry[1].dest.addrtype; 
		}
	}

	// Audit the rule for this subnet
	for (n = 0; n < rule_tbl.rule_cnt; n++)
	{
		if ((IPM_IPCMPADDR(&subnet_ptr->subnet_base, &rule_tbl.rule_entry[n].srcip) == IPM_SUCCESS) &&
				(subnet_ptr->prefixlen == rule_tbl.rule_entry[n].prefix))
		{
			if (subnet_ptr->table_num == rule_tbl.rule_entry[n].table_num)
			{
				// Find the correct rule.
				if ((matched_rule_found == FALSE) && (rule_tbl.rule_entry[n].priority == IPM_RULE_BASE_PRIO + subnet_ptr->table_num))
				{
					// If this is first time finding the rule, change flag.
					matched_rule_found = TRUE;
				}
				else
				{
					// Delete duplicated rule
					ipm_rule_mgr(EIPM_DEL, &rule_tbl.rule_entry[n]);
				}
			}
			else
			{
				// Find wrong rule, delete it.
				ipm_rule_mgr(EIPM_DEL, &rule_tbl.rule_entry[n]);
			}
		}
	}

	if (matched_rule_found == FALSE)
	{
		// construct rule and route entry.
		memcpy(&upd_rule_entry.srcip, &subnet_ptr->subnet_base, sizeof (IPM_IPADDR));
		upd_rule_entry.prefix = subnet_ptr->prefixlen;
		upd_rule_entry.table_num = subnet_ptr->table_num;
		upd_rule_entry.priority = IPM_RULE_BASE_PRIO + subnet_ptr->table_num;
		ipm_rule_mgr(EIPM_ADD, &upd_rule_entry);

		// After adding the rule, check if the table has existing route entry.
		// If may be left since last deleting rule. Because we only remove the 
		// rule and don't remove the route entry in the table. If there are 
		// some, delete them all first.
		EIPM_read_rttable(&os_route_tbl, subnet_ptr->table_num);
		for (n = 0; n < os_route_tbl.route_cnt; n++)
		{
			ipm_route_mgr(EIPM_DEL, &os_route_tbl.route_table[n], subnet_ptr->table_num);
		}

		// Add all entries existing in base table to OS
		for (n = 0; n < max_valid_entry; n++)
		{
			ipm_route_mgr(EIPM_ADD, &base_route_entry[n], subnet_ptr->table_num);
			send_garp = TRUE;
		}
	}
	else
	{
		// audit the route entry in the table.
		EIPM_read_rttable(&os_route_tbl, subnet_ptr->table_num);

		for (n = 0; n < os_route_tbl.route_cnt; n++)
		{
			for (i = 0; i < max_valid_entry; i++)
			{

				if ((IPM_IPCMPADDR(&os_route_tbl.route_table[n].dest, &base_route_entry[i].dest) == IPM_SUCCESS) &&
					(os_route_tbl.route_table[n].destprefix == base_route_entry[i].destprefix) &&
					(IPM_IPCMPADDR(&os_route_tbl.route_table[n].gateway, &base_route_entry[i].gateway) == IPM_SUCCESS) &&
					(os_route_tbl.route_table[n].iface_indx == base_route_entry[i].iface_indx))
				{
					// mark this entry invalid to indicate it already exists in os.
					base_route_entry[i].gateway.addrtype = 0;
					break;
				}
			}

			// we don't find this os entry in the base table. This means this is a wrong entry, delete it.
			if (i == max_valid_entry)
			{
				ipm_route_mgr(EIPM_DEL, &os_route_tbl.route_table[n], subnet_ptr->table_num);
				send_garp = TRUE;
			}
		}

		// Now, we go through the base table again. The remaining valid ones need to be added to os.
		for (n = 0; n < max_valid_entry; n++)
		{
			if (base_route_entry[n].gateway.addrtype == 0)
			{
				// If this entry has been marked as invalid at previous step,
				// This means the os has already have this entry, continue.
				continue;
			}

			// Add valid route entry in the base table to os.
			ipm_route_mgr(EIPM_ADD, &base_route_entry[n], subnet_ptr->table_num);
			send_garp = TRUE;
		}
	}

	if (send_garp == TRUE)
	{
		EIPM_SET_GRAT_ARP(subnet_ptr, routing_priority);
	}

	return IPM_SUCCESS;
}

/*
 * Name:        ipm_audit_pivot_intf()
 *
 * Abstract:    Audit the pivot active slave interface according to routing priority,
 *              and correct it on finding any discrepancy.
 *
 * Parameters:  intf_ptr        - interface pointer associated with the subnet
 *              subnet_ptr      - subnet using this pivot
 *              pivot_id        - pivot to be checked 
 *              routing_priority- system routing priority
 *
 * Returns:     IPM_SUCCESS - audit run successfully
 *              IPM_FAILURE - some error occurred.
 */
int ipm_audit_pivot_intf(EIPM_INTF *intf_ptr, EIPM_SUBNET *subnet_ptr, int pivot_id, EIPM_NET routing_priority)
{
	EIPM_NET activeSlave;
	EIPM_NET sendARP = LSN_BOTH;
	int i;
	EIPM_IPDATA *ip_ptr;
	IPM_IPADDR srcIP;
	char ipstr_buf[IPM_IPMAXSTRSIZE];
	int pivot_arp_socket = -1;

	activeSlave = EIPM_getActiveSlave(pivot_id);

	// Both pivot_act_base and activeSlave should be checked. pivot_id is a 
	// global variable while pivot_act_base is per subnet. This can avoid the 
	// error of only updating arp infor for IPv4 addr when active/slave is updated
	// during audit IPv4 subnet.
	if ((activeSlave == routing_priority) &&
		(subnet_ptr->pivot_act_base[pivot_id] == routing_priority))
	{
		return IPM_SUCCESS;
	}

	if (routing_priority == LSN0)
	{
		if ((activeSlave != routing_priority)
			&& (ipm_check_linkup("eth0") == IPM_SUCCESS))
		{
			EIPM_setActiveSlave(pivot_id, intf_ptr->lsn0_baseif);
		}
		sendARP = LSN0;
	}
	else if (routing_priority == LSN1)
	{
		if ((activeSlave != routing_priority)
			&& (ipm_check_linkup("eth1") == IPM_SUCCESS))
		{
			EIPM_setActiveSlave(pivot_id, intf_ptr->lsn1_baseif);
		}
		sendARP = LSN1;
	}

	if (sendARP == LSN_BOTH)
	{
		LOG_FORCE(0, "ipm_audit_pivot_intf: Failed to get which interface should be active for pivot%d.\n", pivot_id);
		return IPM_FAILURE;
	}

	// Update the pivot_act_base value on the subnet for the specified pivot.
	subnet_ptr->pivot_act_base[pivot_id] = routing_priority;

	// Get every IP address using this pivot and update the ARP to the destination.
	for (i = 0, ip_ptr = &subnet_ptr->ips[0]; i < subnet_ptr->ip_cnt; i++, ip_ptr++)
	{
		if (ip_ptr->pivot_id != pivot_id)
		{
			continue;
		}

		srcIP = ip_ptr->ipaddr;

		IPM_ipaddr2p(&ip_ptr->ipaddr, ipstr_buf, sizeof (ipstr_buf));

		if (srcIP.addrtype == IPM_IPV4)
		{
			if (sendARP == LSN0)
			{
				pivot_arp_socket = EIPM_create_arp_socket(LSN0,
								IPM_IPV4,
								subnet_ptr->pivot_iface_indx[0][pivot_id],
								ARPOP_REQUEST);

				EIPM_sendARP(pivot_arp_socket,
						intf_ptr->lsn0_hwaddr,
						&srcIP,
						&subnet_ptr->gateway,
						subnet_ptr->pivot_iface_indx[0][pivot_id],
						ARPOP_REQUEST);

				LOG_OTHER(0, "ipm_audit_pivot_intf: Send updated arp information for %s to use %d on pivot%d.\n", ipstr_buf, sendARP, pivot_id);
			}
			else
			{
				pivot_arp_socket = EIPM_create_arp_socket(LSN1,
								IPM_IPV4,
								subnet_ptr->pivot_iface_indx[0][pivot_id],
								ARPOP_REQUEST);

				EIPM_sendARP(pivot_arp_socket,
					intf_ptr->lsn1_hwaddr,
					&srcIP,
					&subnet_ptr->gateway,
					subnet_ptr->pivot_iface_indx[0][pivot_id],
					ARPOP_REQUEST);

				LOG_OTHER(0, "ipm_audit_pivot_intf: Send updated arp information for %s to use %d on pivot%d.\n", ipstr_buf, sendARP, pivot_id);
			}
		}
		else if (srcIP.addrtype == IPM_IPV6)
		{
			if (sendARP == LSN0)
			{
				pivot_arp_socket = EIPM_create_arp_socket(LSN0,
								IPM_IPV6,
								subnet_ptr->pivot_iface_indx[0][pivot_id],
								ND_NEIGHBOR_SOLICIT);

				EIPM_sendARP(pivot_arp_socket,
					intf_ptr->lsn0_hwaddr,
					&srcIP,
					&subnet_ptr->gateway,
					subnet_ptr->pivot_iface_indx[0][pivot_id],
					ND_NEIGHBOR_SOLICIT);

				LOG_OTHER(0, "ipm_audit_pivot_intf: Send updated arp information for %s to use %d on pivot%d.\n", ipstr_buf, sendARP, pivot_id);
			}
			else
			{
				pivot_arp_socket = EIPM_create_arp_socket(LSN1,
								IPM_IPV6,
								subnet_ptr->pivot_iface_indx[0][pivot_id],
								ND_NEIGHBOR_SOLICIT);

				EIPM_sendARP(pivot_arp_socket,
					intf_ptr->lsn1_hwaddr,
					&srcIP,
					&subnet_ptr->gateway,
					subnet_ptr->pivot_iface_indx[0][pivot_id],
					ND_NEIGHBOR_SOLICIT);

				LOG_OTHER(0, "ipm_audit_pivot_intf: Send updated arp information for %s to use %d on pivot%d.\n", ipstr_buf, sendARP, pivot_id);
			}
		}

		if (pivot_arp_socket > 0)
		{
			(void) close(pivot_arp_socket);
		}

	}

	return IPM_SUCCESS;
}

/*
 * Name:        ipm_chk_host_rule()
 *
 * Abstract:    Audit the host based routing rule. Normally, it at least has two
 *              lsn routing entries. This function also audit these two routes.
 *
 * Parameters:  rule_tbl        - current system rule entries
 */
void ipm_chk_host_rule(IPM_RULETBL rule_tbl)
{

	IPM_ROUTE_ENTRY lsn0_rt;
	IPM_ROUTE_ENTRY lsn1_rt;
	bool host_rule_v4 = FALSE;
	bool host_rule_v6 = FALSE;
	IPM_RULE_ENTRY rule_entry;
	int n;
	IPM_RTTBL rt_table;
	int lsn0_idx = -1, lsn1_idx = -1;

	//Get the needed lsn routing entries from ctx.
	ipm_get_lsn_routes(&lsn0_rt, &lsn1_rt);

	for (n = 0; n < rule_tbl.rule_cnt; n++)
	{
		if ((rule_tbl.rule_entry[n].table_num == RT_TABLE_HOST) && (rule_tbl.rule_entry[n].priority == 1))
		{
			if (rule_tbl.rule_entry[n].srcip.addrtype == IPM_IPV4)
			{
				if (host_rule_v4 == FALSE)
				{
					host_rule_v4 = TRUE;
				}
				else
				{
					ipm_rule_mgr(EIPM_DEL, &(rule_tbl.rule_entry[n]));
				}
			}
			else if (rule_tbl.rule_entry[n].srcip.addrtype == IPM_IPV6)
			{
				if (host_rule_v6 == FALSE)
				{
					host_rule_v6 = TRUE;
				}
				else
				{
					ipm_rule_mgr(EIPM_DEL, &(rule_tbl.rule_entry[n]));
				}
			}
		}
		else if ((rule_tbl.rule_entry[n].table_num == RT_TABLE_HOST) && (rule_tbl.rule_entry[n].priority != 1))
		{
			ipm_rule_mgr(EIPM_DEL, &(rule_tbl.rule_entry[n]));
		}
	}

	// IPv4 host routing rule is not found, create one.
	if (host_rule_v4 == FALSE)
	{
		memset(&rule_entry, 0, sizeof (IPM_RULE_ENTRY));
		rule_entry.srcip.addrtype = IPM_IPV4;
		rule_entry.table_num = RT_TABLE_HOST;
		rule_entry.priority = 1;
		ipm_rule_mgr(EIPM_ADD, &rule_entry);
	}

	// IPv6 host routing rule is not found, create one.
	if (host_rule_v6 == FALSE)
	{
		memset(&rule_entry, 0, sizeof (IPM_RULE_ENTRY));
		rule_entry.srcip.addrtype = IPM_IPV6;
		rule_entry.table_num = RT_TABLE_HOST;
		rule_entry.priority = 1;
		ipm_rule_mgr(EIPM_ADD, &rule_entry);
	}

	EIPM_read_rttable(&rt_table, RT_TABLE_HOST);

	// Audit lsn routing entries
	for (n = 0; n < rt_table.route_cnt; n++)
	{
		if ((IPM_IPCMPADDR(&rt_table.route_table[n].dest, &lsn0_rt.dest) == IPM_SUCCESS) &&
			rt_table.route_table[n].destprefix == lsn0_rt.destprefix &&
			(rt_table.route_table[n].iface_indx == lsn0_rt.iface_indx))
		{
			lsn0_idx = n;
		}

		if ((IPM_IPCMPADDR(&rt_table.route_table[n].dest, &lsn1_rt.dest) == IPM_SUCCESS) &&
			rt_table.route_table[n].destprefix == lsn1_rt.destprefix &&
			(rt_table.route_table[n].iface_indx == lsn1_rt.iface_indx))
		{
			lsn1_idx = n;
		}
	}

	// lsn0 route is not found, add lsn0 route entry;
	if ((lsn0_rt.iface_indx != -1) && (lsn0_idx == -1))
	{
		ipm_route_mgr(EIPM_ADD, &lsn0_rt, RT_TABLE_HOST);
	}

	// lsn1 route is not found, add lsn1 route entry;
	if ((lsn1_rt.iface_indx != -1) && (lsn1_idx == -1))
	{
		ipm_route_mgr(EIPM_ADD, &lsn1_rt, RT_TABLE_HOST);
	}
}

