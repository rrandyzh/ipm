/* File Name: 
 *		glob/src/ipm/nma_route.c
 * Description: 
 *		provide route manager related api called by nma main
 */

#include <sys/resource.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <sched.h>
#include <arpa/inet.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <pthread.h>
#include <time.h>

#include "nnn_define.h"
#include "nnn_swmnt.h"
#include "nma_route.h"
#include "nma_log.h"
#ifdef _IPM // exclude RIPM 
#include <EIPM_include.h>
#include <PIPM_include.h>
#endif

/* Sequence number to use for RTNETLINK messages */ 
time_t IPM_rt_seq;

#ifdef DEBUG_CODE
#ifndef NLMSG_TAIL

/* This define is here to allow building outside of the LCP environment */
#define NLMSG_TAIL(_nmsg) \
        ((struct rtattr *) (((void *) (_nmsg)) + NLMSG_ALIGN((_nmsg)->nlmsg_len)))

#endif
#endif

/************************************************/
/* Add attribute in netlink socket message      */
/************************************************/

static int nma_route_attr(struct nlmsghdr *n,unsigned int maxlen,int type,void *data,int alen)
{
   int len = RTA_LENGTH(alen);
   struct rtattr *rta;

   if (NLMSG_ALIGN(n->nlmsg_len) + len > maxlen) return(-1);
   rta = (struct rtattr*)(((char*)n) + NLMSG_ALIGN(n->nlmsg_len));
   rta->rta_type = type;
   rta->rta_len = len;
   memcpy(RTA_DATA(rta), data, alen);
   n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;
   return(0);
}

/*************************
 * Name:		nma_route_del
 * Description:	delete route path
 * Parameter:	netlinksocket: netlink socket fd
 *				dest:	route target, host or subnet
 *				prefixlen:	prefix length, if 32, that is host target if not network target
 * Return:		errno or -1	
**************************/

int nma_route_del(int netlinksocket, int ifindex, char *ifname, IPM_IPADDR *dest, int prefixlen, IPM_IPADDR *gateway )
{
   struct
   {
      struct nlmsghdr header;
      struct rtmsg route;
      char data[1024];
   } request;
   struct sockaddr_nl nladdr;
   struct iovec iov;
   struct msghdr msg = {(void*)&nladdr,sizeof(nladdr),&iov,1,NULL,0,0};
   int error;
   char shost[IPM_IPMAXSTRSIZE];
   struct timespec sel_time;
   char sgateway[IPM_IPMAXSTRSIZE];
   char sdevice[MAX_NLEN_DEV];
   int retval;
   int retval2;
   int max_prefix;
   unsigned int ip_len;
   unsigned rtm_family;
   int nl_socket = -1;
#ifdef DEBUG_CODE
   struct rtattr *myrta;
   int           mylen;
#endif

   if (dest == NULL)
   {
      ASRT_RPT(ASBAD_DATA, 0, "dest is null");
      return IPM_FAILURE;
   }
   switch (dest->addrtype) {
   case IPM_IPV4:
   {
      max_prefix = IPM_IPV4MAXMASKLEN;
      rtm_family = AF_INET;
      ip_len = AF_RAWIPV4SIZE;
      break;
   }
   case IPM_IPV6:
   {
      max_prefix = IPM_IPV6MAXMASKLEN;
      rtm_family = AF_INET6;
      ip_len = AF_RAWIPV6SIZE;
      break;
   }
   default:
      ASRT_RPT(ASBAD_DATA, 1, sizeof(IPM_IPADDR), dest, "Invailid dest ip address type");
      return IPM_FAILURE;
   }

   if (gateway != NULL) 
   {
       if ((gateway->addrtype != IPM_IPV4) && (gateway->addrtype != IPM_IPV6))
       {
           ASRT_RPT(ASBAD_DATA, 1, sizeof(IPM_IPADDR), gateway, "Invailid gateway address type");
           return IPM_FAILURE;
       }
   }

   memset(sgateway, 0, sizeof(sgateway));
   memset(&request,0,sizeof(request));
   request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
   request.header.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
   request.header.nlmsg_type = RTM_DELROUTE;
   request.header.nlmsg_pid = 0;
   request.header.nlmsg_seq = IPM_rt_seq++;
   request.route.rtm_family = rtm_family;
   request.route.rtm_table = RT_TABLE_MAIN; 
   request.route.rtm_scope = RT_SCOPE_NOWHERE;
   if ((prefixlen == NOPARAMETER) || (prefixlen > max_prefix))
	 request.route.rtm_dst_len = max_prefix;
   else 
	 request.route.rtm_dst_len = prefixlen;

#ifdef DEBUG_CODE
   myrta = NLMSG_TAIL(&(request.header));
   mylen = NLMSG_ALIGN(request.header.nlmsg_len);
#endif
   
   nma_route_attr(&request.header,sizeof(request),RTA_DST,dest->ipaddr,ip_len);

#ifdef _IPM // exclude RIPM 
   if( dest->addrtype == IPM_IPV6 &&
       EIPM_check_monitor_route(dest) == IPM_SUCCESS )
   {
      unsigned int metric = 1024;

      nma_route_attr(&request.header, sizeof(request), RTA_PRIORITY, &metric, sizeof(metric));
   }
#endif

   *sgateway = '\0';
   if (gateway != NULL)
   {
      nma_route_attr(&request.header,sizeof(request),RTA_GATEWAY,gateway->ipaddr,ip_len);
      IPM_ipaddr2p(gateway, sgateway,IPM_IPMAXSTRSIZE);
   }
   *sdevice = '\0';
   if (ifindex != NOPARAMETER)
   {
      nma_route_attr(&request.header,sizeof(request),RTA_OIF,&ifindex,4);
      snprintf(sdevice,MAX_NLEN_DEV," device %s", (ifname != NULL?ifname:"NULL"));
   }

   memset(&nladdr,0,sizeof(nladdr));
   nladdr.nl_family = AF_NETLINK;
   nladdr.nl_pid = 0;
   nladdr.nl_groups = 0;
   iov.iov_base = (void*)&(request.header);
   iov.iov_len = request.header.nlmsg_len;
   IPM_ipaddr2p(dest,shost,IPM_IPMAXSTRSIZE);

#ifdef DEBUG_CODE
{
   struct sockaddr_nl	*nl_ptr;
   struct iovec		*iov_ptr;
   int	 		c = 1;
   int	      		i;
	
   nl_ptr = (struct sockaddr_nl *)msg.msg_name;
	
   LOG_OTHER(NMA_OROUTE, "nma_route_del : Print assuming 'struct sockaddr_nl' for name:\n" );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : msg.msg_name= family:%d  nl_pad:%d, nl_pid=%ld, nl_groups=%ld\n", nl_ptr->nl_family, nl_ptr->nl_pad, nl_ptr->nl_pid, nl_ptr->nl_groups );
      
   LOG_OTHER(NMA_OROUTE, "nma_route_del : msg.msg_namelen=%d\n", msg.msg_namelen );
   iov_ptr = msg.msg_iov;
   LOG_OTHER(NMA_OROUTE, "nma_route_del : msg.msg_iov= iov_base=0x%x, iov_len=%d\n", iov_ptr->iov_base, iov_ptr->iov_len  );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : msg.msg_control=0x%x (magic pointer?)\n", msg.msg_control );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : msg.msg_controllen=%d\n", msg.msg_controllen );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : msg.msg_flags=%d\n", msg.msg_flags );
   
   LOG_OTHER(NMA_OROUTE, "nma_route_del : Request\n" );
   
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.header.nlmsg_len: %d\n", request.header.nlmsg_len );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.header.nlmsg_flags: 0x%x\n", request.header.nlmsg_flags );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.header.nlmsg_seq: %d\n", request.header.nlmsg_seq );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.header.nlmsg_type: %d\n", request.header.nlmsg_type );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.header.nlmsg_pid: %d\n", request.header.nlmsg_pid );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.route.rtm_family: %d\n", request.route.rtm_family );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.route.rtm_dst_len: %d\n", request.route.rtm_dst_len );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.route.rtm_src_len: %d\n", request.route.rtm_src_len );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.route.rtm_table: %d\n", request.route.rtm_table );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.route.rtm_scope: %d\n", request.route.rtm_scope );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.route.rtm_protocol: %d\n", request.route.rtm_protocol );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.route.rtm_type: %d\n", request.route.rtm_type );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.route.rtm_flags: 0x%x\n", request.route.rtm_flags );
   
   i = mylen;
   while (i < request.header.nlmsg_len)
   {
	char 		attr_buf[512];
	char 		tmp[32];
	int		b;
	unsigned char *	p;
	sprintf( attr_buf, "rtatt %d rta_len=%d rta_type=%d\n\n",
		 c, myrta->rta_len, myrta->rta_type);

	p = (unsigned char*)myrta;
	for (b = 0; b < myrta->rta_len; b++)
	{
		sprintf( tmp, "%02x", *(p+b));
		strcat( attr_buf, tmp );
		if ((b & 15) == 15) strcat( attr_buf, "\n");
	}
	strcat( attr_buf, "\n");
	LOG_OTHER(NMA_OROUTE, "%s", attr_buf );
	i += myrta->rta_len;
	p += myrta->rta_len;
	myrta = (struct rtattr *)p;
	c++;
   }
}

#endif

#ifdef _IPM // exclude RIPM 

    retval = EIPM_process_route_update(EIPM_DEL, ifname, dest, prefixlen, gateway);
    if( (retval != IPM_SUCCESS) && (retval != IPM_PIVOT_ROUTE) )
    {
	LOG_ERROR(NMA_OROUTE, "nma_route_del: EIPM_process_route_update failure ret %d", retval );
    }

    retval2 = PIPM_process_route_update(PIPM_DEL_ROUTE, ifname, 0, dest, prefixlen, gateway);
    if( retval2 != IPM_SUCCESS )
    {
	LOG_ERROR(NMA_OROUTE, "nma_route_del: PIPM_process_route_update failure ret %d", retval );
    }

    /* Don't need to del route in IIPM if it is access route.
     * From CP5.0, it access subnet will be on pivot and
     * its active slave will be updated by IOCTL
     */
    if (retval == IPM_PIVOT_ROUTE)
    {
        return 0;
    }

#endif
   nl_socket = IPM_open_netlink_socket();
   if (nl_socket < 0)
   {
      return IPM_FAILURE;
   }

   retval = sendmsg(nl_socket,&msg,0);
   if (retval < 0)
   {
      if (errno == EAGAIN)
      {
		/*
		 * No response.
		 *
		 * Setup timeout for 5 msec (nsec=5000) and try again.
		 */
		sel_time.tv_sec  = 0;
		sel_time.tv_nsec = 5000;
		nanosleep( &sel_time, 0 );
        retval = sendmsg(nl_socket,&msg,0);
        if (retval < 0)
        {
           LOG_ERROR(NMA_EDELROUTE,"nma_route_del : sendmsg failed again errno %s",strerror(errno));
           IPM_close_netlink_socket(&nl_socket);
           return IPM_FAILURE;
        }
      }
      else {
           LOG_ERROR(NMA_EDELROUTE,"nma_route_del : sendmsg failed %s",strerror(errno));
           IPM_close_netlink_socket(&nl_socket);
           return IPM_FAILURE;
      }
   }

   memset(&request, 0, sizeof(request));
   iov.iov_base = (void*)&(request.header);
   iov.iov_len = sizeof(request);
   retval = recvmsg(nl_socket,&msg,0);
   if( retval < 0 )
   {
	if( errno == EAGAIN )
	{
		/*
		 * No response.
		 *
		 * Setup timeout for 5 msec (nsec=5000) and try again.
		 */
		sel_time.tv_sec  = 0;
		sel_time.tv_nsec = 5000;
		nanosleep( &sel_time, 0 );
		retval = recvmsg(nl_socket,&msg,0);
		if( retval < 0 )
		{
		   LOG_ERROR(NMA_EDELROUTE, "nma_route_del recvmsg failed again %s", strerror(errno));
           	   IPM_close_netlink_socket(&nl_socket);
                   return IPM_FAILURE;
		}
	}
	else
	{
		LOG_ERROR(NMA_EDELROUTE, "nma_route_del recvmsg  failed %s", strerror(errno));
           	IPM_close_netlink_socket(&nl_socket);
		return IPM_FAILURE;
	}
   }

   IPM_close_netlink_socket(&nl_socket);
   LOG_ERROR(NMA_OROUTE,"nma_route_del : route del to %s/%d via %s dev %s ret = %d",shost,prefixlen,sgateway,sdevice, retval);

   switch (request.header.nlmsg_type) {
   case NLMSG_ERROR:
   {
      error = -((struct nlmsgerr*)NLMSG_DATA(&request.header))->error;
      if (error)
         LOG_ERROR(NMA_EDELROUTE,"nma_route_del : rtnetlink error %s",strerror(error));
      return(error);
   }
   case NLMSG_NOOP:
   case NLMSG_DONE:
   case NLMSG_OVERRUN:
   {
      return IPM_FAILURE;
   }
   }
   return(0);
}

/*************************
 * Name:		nma_route_priority_del
 * Description:	delete route path with priority
 * Parameter:	netlinksocket: netlink socket fd
 *				dest:	route target, host or subnet
 *				prefixlen:	prefix length, if 32, that is host target if not network target
 * Return:		errno or -1	
**************************/

int nma_route_priority_del(int netlinksocket, int ifindex, char *ifname, IPM_IPADDR *dest, int prefixlen, IPM_IPADDR *gateway, u_int32_t priority )
{
   struct
   {
      struct nlmsghdr header;
      struct rtmsg route;
      char data[1024];
   } request;
   struct sockaddr_nl nladdr;
   struct iovec iov;
   struct msghdr msg = {(void*)&nladdr,sizeof(nladdr),&iov,1,NULL,0,0};
   int error;
   char shost[IPM_IPMAXSTRSIZE];
   struct timespec sel_time;
   char sgateway[IPM_IPMAXSTRSIZE];
   char sdevice[MAX_NLEN_DEV];
   int retval;
   int retval2;
   int max_prefix;
   unsigned int ip_len;
   unsigned rtm_family;
   int nl_socket;
#ifdef DEBUG_CODE
   struct rtattr *myrta;
   int           mylen;
#endif

   if (dest == NULL)
   {
      ASRT_RPT(ASBAD_DATA, 0, "dest is null");
      return IPM_FAILURE;
   }
   switch (dest->addrtype) {
   case IPM_IPV4:
   {
      max_prefix = IPM_IPV4MAXMASKLEN;
      rtm_family = AF_INET;
      ip_len = AF_RAWIPV4SIZE;
      break;
   }
   case IPM_IPV6:
   {
      max_prefix = IPM_IPV6MAXMASKLEN;
      rtm_family = AF_INET6;
      ip_len = AF_RAWIPV6SIZE;
      break;
   }
   default:
      ASRT_RPT(ASBAD_DATA, 1, sizeof(IPM_IPADDR), dest, "Invailid dest ip address type");
      return IPM_FAILURE;
   }

   if (gateway != NULL) 
   {
       if ((gateway->addrtype != IPM_IPV4) && (gateway->addrtype != IPM_IPV6))
       {
           ASRT_RPT(ASBAD_DATA, 1, sizeof(IPM_IPADDR), gateway, "Invailid gateway address type");
           return IPM_FAILURE;
       }
   }

   memset(sgateway, 0, sizeof(sgateway));
   memset(&request,0,sizeof(request));
   request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
   request.header.nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK;
   request.header.nlmsg_type = RTM_DELROUTE;
   request.header.nlmsg_pid = 0;
   request.header.nlmsg_seq = IPM_rt_seq++;
   request.route.rtm_family = rtm_family;
   request.route.rtm_table = RT_TABLE_MAIN; 
   request.route.rtm_scope = RT_SCOPE_NOWHERE;
   if ((prefixlen == NOPARAMETER) || (prefixlen > max_prefix))
	 request.route.rtm_dst_len = max_prefix;
   else 
	 request.route.rtm_dst_len = prefixlen;

#ifdef DEBUG_CODE
   myrta = NLMSG_TAIL(&(request.header));
   mylen = NLMSG_ALIGN(request.header.nlmsg_len);
#endif
   
   nma_route_attr(&request.header,sizeof(request),RTA_DST,dest->ipaddr,ip_len);

#ifdef _IPM // exclude RIPM 
   {
      nma_route_attr(&request.header, sizeof(request), RTA_PRIORITY, &priority, sizeof(priority));
   }
#endif

   *sgateway = '\0';
   if (gateway != NULL)
   {
      nma_route_attr(&request.header,sizeof(request),RTA_GATEWAY,gateway->ipaddr,ip_len);
      IPM_ipaddr2p(gateway, sgateway,IPM_IPMAXSTRSIZE);
   }
   *sdevice = '\0';
   if (ifindex != NOPARAMETER)
   {
      nma_route_attr(&request.header,sizeof(request),RTA_OIF,&ifindex,4);
      snprintf(sdevice,MAX_NLEN_DEV," device %s", (ifname != NULL?ifname:"NULL"));
   }

   memset(&nladdr,0,sizeof(nladdr));
   nladdr.nl_family = AF_NETLINK;
   nladdr.nl_pid = 0;
   nladdr.nl_groups = 0;
   iov.iov_base = (void*)&(request.header);
   iov.iov_len = request.header.nlmsg_len;
   IPM_ipaddr2p(dest,shost,IPM_IPMAXSTRSIZE);
   LOG_ERROR(NMA_OROUTE,"nma_route_del : route del to %s/%d via %s dev %s",shost,prefixlen,sgateway,sdevice);

#ifdef DEBUG_CODE
{
   struct sockaddr_nl	*nl_ptr;
   struct iovec		*iov_ptr;
   int	 		c = 1;
   int	      		i;
	
   nl_ptr = (struct sockaddr_nl *)msg.msg_name;
	
   LOG_OTHER(NMA_OROUTE, "nma_route_del : Print assuming 'struct sockaddr_nl' for name:\n" );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : msg.msg_name= family:%d  nl_pad:%d, nl_pid=%ld, nl_groups=%ld\n", nl_ptr->nl_family, nl_ptr->nl_pad, nl_ptr->nl_pid, nl_ptr->nl_groups );
      
   LOG_OTHER(NMA_OROUTE, "nma_route_del : msg.msg_namelen=%d\n", msg.msg_namelen );
   iov_ptr = msg.msg_iov;
   LOG_OTHER(NMA_OROUTE, "nma_route_del : msg.msg_iov= iov_base=0x%x, iov_len=%d\n", iov_ptr->iov_base, iov_ptr->iov_len  );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : msg.msg_control=0x%x (magic pointer?)\n", msg.msg_control );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : msg.msg_controllen=%d\n", msg.msg_controllen );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : msg.msg_flags=%d\n", msg.msg_flags );
   
   LOG_OTHER(NMA_OROUTE, "nma_route_del : Request\n" );
   
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.header.nlmsg_len: %d\n", request.header.nlmsg_len );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.header.nlmsg_flags: 0x%x\n", request.header.nlmsg_flags );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.header.nlmsg_seq: %d\n", request.header.nlmsg_seq );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.header.nlmsg_type: %d\n", request.header.nlmsg_type );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.header.nlmsg_pid: %d\n", request.header.nlmsg_pid );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.route.rtm_family: %d\n", request.route.rtm_family );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.route.rtm_dst_len: %d\n", request.route.rtm_dst_len );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.route.rtm_src_len: %d\n", request.route.rtm_src_len );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.route.rtm_table: %d\n", request.route.rtm_table );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.route.rtm_scope: %d\n", request.route.rtm_scope );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.route.rtm_protocol: %d\n", request.route.rtm_protocol );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.route.rtm_type: %d\n", request.route.rtm_type );
   LOG_OTHER(NMA_OROUTE, "nma_route_del : request.route.rtm_flags: 0x%x\n", request.route.rtm_flags );
   
   i = mylen;
   while (i < request.header.nlmsg_len)
   {
	char 		attr_buf[512];
	char 		tmp[32];
	int		b;
	unsigned char *	p;
	sprintf( attr_buf, "rtatt %d rta_len=%d rta_type=%d\n\n",
		 c, myrta->rta_len, myrta->rta_type);

	p = (unsigned char*)myrta;
	for (b = 0; b < myrta->rta_len; b++)
	{
		sprintf( tmp, "%02x", *(p+b));
		strcat( attr_buf, tmp );
		if ((b & 15) == 15) strcat( attr_buf, "\n");
	}
	strcat( attr_buf, "\n");
	LOG_OTHER(NMA_OROUTE, "%s", attr_buf );
	i += myrta->rta_len;
	p += myrta->rta_len;
	myrta = (struct rtattr *)p;
	c++;
   }
}

#endif

#ifdef _IPM // exclude RIPM 

    retval = EIPM_process_route_update(EIPM_DEL, ifname, dest, prefixlen, gateway);
    if( (retval != IPM_SUCCESS) && (retval != IPM_PIVOT_ROUTE) )
    {
	LOG_ERROR(NMA_OROUTE, "nma_route_del: EIPM_process_route_update failure ret %d", retval );
    }

    retval2 = PIPM_process_route_update(PIPM_DEL_ROUTE, ifname, 0, dest, prefixlen, gateway);
    if( retval2 != IPM_SUCCESS )
    {
	LOG_ERROR(NMA_OROUTE, "nma_route_del: PIPM_process_route_update failure ret %d", retval );
    }

    /* Don't need to del route in IIPM if it is access route.
     * From CP5.0, it access subnet will be on pivot and
     * its active slave will be updated by IOCTL
     */
    if (retval == IPM_PIVOT_ROUTE)
    {
        return 0;
    }

#endif
   nl_socket = IPM_open_netlink_socket();
   if (nl_socket < 0)
   {
      return IPM_FAILURE;
   }

   retval = sendmsg(nl_socket,&msg,0);
   if (retval < 0)
   {
      if (errno == EAGAIN)
      {
		/*
		 * No response.
		 *
		 * Setup timeout for 5 msec (nsec=5000) and try again.
		 */
		sel_time.tv_sec  = 0;
		sel_time.tv_nsec = 5000;
		nanosleep( &sel_time, 0 );
        retval = sendmsg(nl_socket,&msg,0);
        if (retval < 0)
        {
           LOG_ERROR(NMA_EDELROUTE,"nma_route_del : sendmsg failed again errno %s",strerror(errno));
           IPM_close_netlink_socket(&nl_socket);
           return IPM_FAILURE;
        }
      }
      else {
           LOG_ERROR(NMA_EDELROUTE,"nma_route_del : sendmsg failed %s",strerror(errno));
           IPM_close_netlink_socket(&nl_socket);
           return IPM_FAILURE;
      }
   }

   memset(&request, 0, sizeof(request));
   iov.iov_base = (void*)&(request.header);
   iov.iov_len = sizeof(request);
   retval = recvmsg(nl_socket,&msg,0);
   if( retval < 0 )
   {
	if( errno == EAGAIN )
	{
		/*
		 * No response.
		 *
		 * Setup timeout for 5 msec (nsec=5000) and try again.
		 */
		sel_time.tv_sec  = 0;
		sel_time.tv_nsec = 5000;
		nanosleep( &sel_time, 0 );
		retval = recvmsg(nl_socket,&msg,0);
		if( retval < 0 )
		{
		   LOG_ERROR(NMA_EDELROUTE, "nma_route_del recvmsg failed again %s", strerror(errno));
                   IPM_close_netlink_socket(&nl_socket);
                   return IPM_FAILURE;
		}
	}
	else
	{
		LOG_ERROR(NMA_EDELROUTE, "nma_route_del recvmsg  failed %s", strerror(errno));
                IPM_close_netlink_socket(&nl_socket);
                return IPM_FAILURE;
	}
   }

   IPM_close_netlink_socket(&nl_socket);

   switch (request.header.nlmsg_type) {
   case NLMSG_ERROR:
   {
      error = -((struct nlmsgerr*)NLMSG_DATA(&request.header))->error;
      if (error)
         LOG_ERROR(NMA_EDELROUTE,"nma_route_del : rtnetlink error %s",strerror(error));
      return(error);
   }
   case NLMSG_NOOP:
   case NLMSG_DONE:
   case NLMSG_OVERRUN:
   {
      return IPM_FAILURE;
   }
   }
   return(0);
}

/*************************
 * Name:		nma_route_add
 * Description:	add route path
 * Parameter:	netlinksocket: netlink socket fd
 *				ifindex:	output interface index
 *				ifname:		output interface name
 *				dest:	route target, host or subnet
 *				prefixlen:	prefix length, if 32, that is host target if not network target
 *				gateway:	target getway
 *				source:		prefered source ip 
 * Return:		errno or -1	
**************************/

int nma_route_add(int netlinksocket, int ifindex, char *ifname, unsigned short vlanId, IPM_IPADDR *dest, int prefixlen, IPM_IPADDR *gateway,IPM_IPADDR *source)
{
   struct
   {
      struct nlmsghdr header;
      struct rtmsg route;
      char data[1024];
   } request;
   struct sockaddr_nl nladdr;
   struct iovec iov;
   struct msghdr msg = {(void*)&nladdr,sizeof(nladdr),&iov,1,NULL,0,0};
   int retval;
   int retval2;
   struct timespec sel_time;
   int error;
   char shost[IPM_IPMAXSTRSIZE];
   char sgateway[IPM_IPMAXSTRSIZE];
   char ssource[IPM_IPMAXSTRSIZE];
   char sdevice[MAX_NLEN_DEV];
   int max_prefix;
   unsigned int ip_len;
   unsigned rtm_family;
   int nl_socket = -1;
#ifdef DEBUG_CODE
   struct rtattr *myrta;
   int           mylen;
#endif

   if (dest == NULL)
   {
      ASRT_RPT(ASBAD_DATA, 0, "dest is null");
      return IPM_FAILURE;
   }

   switch (dest->addrtype) {
   case IPM_IPV4:
   {
      max_prefix = IPM_IPV4MAXMASKLEN;
      rtm_family = AF_INET;
      ip_len = AF_RAWIPV4SIZE;
      break;
   }
   case IPM_IPV6:
   {
      max_prefix = IPM_IPV6MAXMASKLEN;
      rtm_family = AF_INET6;
      ip_len = AF_RAWIPV6SIZE;
      break;
   }
   default:
      ASRT_RPT(ASBAD_DATA, 1, sizeof(IPM_IPADDR), dest, "Invailid dest ip address type");
      return IPM_FAILURE;
   }

   if (gateway != NULL)
   {
       if ((gateway->addrtype != IPM_IPV4) && (gateway->addrtype != IPM_IPV6))
       {
           ASRT_RPT(ASBAD_DATA, 1, sizeof(IPM_IPADDR), gateway, "Invailid gateway address type");
           return IPM_FAILURE;
       }
   }
   if (source != NULL)
   {
       if ((source->addrtype != IPM_IPV4) && (source->addrtype != IPM_IPV6))
       {
           ASRT_RPT(ASBAD_DATA, 1, sizeof(IPM_IPADDR), source, "Invailid source address type");
           return IPM_FAILURE;
       }
   }

   memset(&request,0,sizeof(request));
   request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
   request.header.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_APPEND|NLM_F_ACK;
   request.header.nlmsg_type = RTM_NEWROUTE;
   request.header.nlmsg_pid = 0;
   request.header.nlmsg_seq = IPM_rt_seq++;
   request.route.rtm_family = rtm_family;
   request.route.rtm_table = RT_TABLE_MAIN;
   request.route.rtm_protocol = RTPROT_BOOT;
   request.route.rtm_type = RTN_UNICAST;
   if ((prefixlen == NOPARAMETER) || (prefixlen > max_prefix))
     request.route.rtm_dst_len = max_prefix;
   else
     request.route.rtm_dst_len = prefixlen;

   /* 
    * For IPv6 monitored routes avoid creating a route with both
    * the destination and gateway having the same IP address.  This causes
    * a "no route to host" failure for other destination routes that use the 
    * same gateway.  In addition, a metric is needed to ensure the route can
    * be removed later.
    */
#ifdef _IPM // exclude RIPM 
   if( gateway == NULL && 
	prefixlen != 0 && dest->addrtype == IPM_IPV6)
   {
	unsigned int metric = 256;
	nma_route_attr(&request.header, sizeof(request), RTA_PRIORITY, &metric, sizeof(metric));
   }
   else if( gateway != NULL && 
       gateway->addrtype == IPM_IPV6 && 
       IPM_IPCMPADDR(gateway, dest) == IPM_SUCCESS &&
       EIPM_check_monitor_route(dest) == IPM_SUCCESS ) 
   {
      unsigned int metric = 1024;

      nma_route_attr(&request.header, sizeof(request), RTA_PRIORITY, &metric, sizeof(metric));
      gateway = NULL;
   }
#endif

   /*
    * The "ip route" code bases the scope on the rtm type and
    * whether or not a gateway is defined.  Since we are only
    * using rtm_type of UNICAST we can simplify the decision
    * down to whether or not there is a gateway given in this
    * routing request.  So if a gateway is given the scope is
    * UNIVERSE, otherwise it is LINK.  (We found this because
    * UNIVERSE does not work for a route without a gateway,
    * and a default route (with a gateway) did not work with
    * scope of LINK.)
    */
   if (gateway != NULL)
   {
	request.route.rtm_scope = RT_SCOPE_UNIVERSE;
   }
   else
   {
	request.route.rtm_scope = RT_SCOPE_LINK;
   }

#ifdef DEBUG_CODE
   myrta = NLMSG_TAIL(&(request.header));
   mylen = NLMSG_ALIGN(request.header.nlmsg_len);
#endif

   nma_route_attr(&request.header,sizeof(request),RTA_DST,dest->ipaddr,ip_len);
   IPM_ipaddr2p(dest, shost, IPM_IPMAXSTRSIZE);
   *sgateway = '\0';
   if (gateway != NULL)
   {
      nma_route_attr(&request.header,sizeof(request),RTA_GATEWAY,gateway->ipaddr,ip_len);
      IPM_ipaddr2p(gateway, sgateway, IPM_IPMAXSTRSIZE);
   }

   *ssource = '\0';
   if (source != NULL)
   {
      nma_route_attr(&request.header,sizeof(request),RTA_PREFSRC,source->ipaddr,ip_len);
      IPM_ipaddr2p(source, ssource, IPM_IPMAXSTRSIZE);
   }
   *sdevice = '\0';
   if (ifindex != NOPARAMETER)
   {
      nma_route_attr(&request.header,sizeof(request),RTA_OIF,&ifindex,4);
      snprintf(sdevice,MAX_NLEN_DEV," device %s", ifname);
   }
   memset(&nladdr,0,sizeof(nladdr));
   nladdr.nl_family = AF_NETLINK;
   nladdr.nl_pid = 0;
   nladdr.nl_groups = 0;
   iov.iov_base = (void*)&(request.header);
   iov.iov_len = request.header.nlmsg_len;
#ifdef DEBUG_CODE
{
   struct sockaddr_nl	*nl_ptr;
   struct iovec		*iov_ptr;
   int	 		c = 1;
   int	      		i;
	
   nl_ptr = (struct sockaddr_nl *)msg.msg_name;
	
   LOG_OTHER(NMA_OROUTE, "nma_route_add : Print assuming 'struct sockaddr_nl' for name:\n" );
   LOG_OTHER(NMA_OROUTE, "nma_route_add : msg.msg_name= family:%d  nl_pad:%d, nl_pid=%ld, nl_groups=%ld\n", nl_ptr->nl_family, nl_ptr->nl_pad, nl_ptr->nl_pid, nl_ptr->nl_groups );
      
   LOG_OTHER(NMA_OROUTE, "nma_route_add : msg.msg_namelen=%d\n", msg.msg_namelen );
   iov_ptr = msg.msg_iov;
   LOG_OTHER(NMA_OROUTE, "nma_route_add : msg.msg_iov= iov_base=0x%x, iov_len=%d\n", iov_ptr->iov_base, iov_ptr->iov_len  );
   LOG_OTHER(NMA_OROUTE, "nma_route_add : msg.msg_control=0x%x (magic pointer?)\n", msg.msg_control );
   LOG_OTHER(NMA_OROUTE, "nma_route_add : msg.msg_controllen=%d\n", msg.msg_controllen );
   LOG_OTHER(NMA_OROUTE, "nma_route_add : msg.msg_flags=%d\n", msg.msg_flags );
   
   LOG_OTHER(NMA_OROUTE, "nma_route_add : Request\n" );
   
   LOG_OTHER(NMA_OROUTE, "nma_route_add : request.header.nlmsg_len: %d\n", request.header.nlmsg_len );
   LOG_OTHER(NMA_OROUTE, "nma_route_add : request.header.nlmsg_flags: 0x%x\n", request.header.nlmsg_flags );
   LOG_OTHER(NMA_OROUTE, "nma_route_add : request.header.nlmsg_seq: %d\n", request.header.nlmsg_seq );
   LOG_OTHER(NMA_OROUTE, "nma_route_add : request.header.nlmsg_type: %d\n", request.header.nlmsg_type );
   LOG_OTHER(NMA_OROUTE, "nma_route_add : request.header.nlmsg_pid: %d\n", request.header.nlmsg_pid );
   LOG_OTHER(NMA_OROUTE, "nma_route_add : request.route.rtm_family: %d\n", request.route.rtm_family );
   LOG_OTHER(NMA_OROUTE, "nma_route_add : request.route.rtm_dst_len: %d\n", request.route.rtm_dst_len );
   LOG_OTHER(NMA_OROUTE, "nma_route_add : request.route.rtm_src_len: %d\n", request.route.rtm_src_len );
   LOG_OTHER(NMA_OROUTE, "nma_route_add : request.route.rtm_table: %d\n", request.route.rtm_table );
   LOG_OTHER(NMA_OROUTE, "nma_route_add : request.route.rtm_scope: %d\n", request.route.rtm_scope );
   LOG_OTHER(NMA_OROUTE, "nma_route_add : request.route.rtm_protocol: %d\n", request.route.rtm_protocol );
   LOG_OTHER(NMA_OROUTE, "nma_route_add : request.route.rtm_type: %d\n", request.route.rtm_type );
   LOG_OTHER(NMA_OROUTE, "nma_route_add : request.route.rtm_flags: 0x%x\n", request.route.rtm_flags );
   
   i = mylen;
   while (i < request.header.nlmsg_len)
   {
	char 		attr_buf[512];
	char 		tmp[32];
	int		b;
	unsigned char *	p;
	sprintf( attr_buf, "rtatt %d rta_len=%d rta_type=%d\n\n",
		 c, myrta->rta_len, myrta->rta_type);

	p = (unsigned char*)myrta;
	for (b = 0; b < myrta->rta_len; b++)
	{
		sprintf( tmp, "%02x", *(p+b));
		strcat( attr_buf, tmp );
		if ((b & 15) == 15) strcat( attr_buf, "\n");
	}
	strcat( attr_buf, "\n");
	LOG_OTHER(NMA_OROUTE, "%s", attr_buf );
	i += myrta->rta_len;
	p += myrta->rta_len;
	myrta = (struct rtattr *)p;
	c++;
   }
}

#endif

#ifdef _IPM // exclude RIPM 

    retval = EIPM_process_route_update(EIPM_ADD, ifname, dest, prefixlen, gateway);
    if( (retval != IPM_SUCCESS) && (retval != IPM_PIVOT_ROUTE) )
    {
	LOG_ERROR(NMA_OROUTE, "nma_route_add: EIPM_process_route_update failure ret %d", retval );
    }

    retval2 = PIPM_process_route_update(PIPM_ADD_ROUTE, ifname, vlanId, dest, prefixlen, gateway);
    if( retval2 != IPM_SUCCESS )
    {
	LOG_ERROR(NMA_OROUTE, "nma_route_add: PIPM_process_route_update failure ret %d", retval );
    }

    /* Don't need to add route in IIPM if it is access route.
     * From CP5.0, it access subnet will be on pivot and
     * its active slave will be updated by IOCTL
     */
    if (retval == IPM_PIVOT_ROUTE)
    {
        return 0;
    }
#endif
   nl_socket = IPM_open_netlink_socket();
   if (nl_socket < 0)
   {
      return IPM_FAILURE;
   }

   retval = sendmsg(nl_socket,&msg,0);
   if (retval < 0)
   {
      if (errno == EAGAIN)
      {
		/*
		 * No response.
		 *
		 * Setup timeout for 5 msec (nsec=5000) and try again.
		 */
		sel_time.tv_sec  = 0;
		sel_time.tv_nsec = 5000;
		nanosleep( &sel_time, 0 );
        retval = sendmsg(nl_socket,&msg,0);
        if (retval < 0)
        {
           LOG_ERROR(NMA_EDELROUTE,"nma_route_add : sendmsg failed again errno %s",strerror(errno));
           IPM_close_netlink_socket(&nl_socket);
           return IPM_FAILURE;
        }
      }
      else {
           LOG_ERROR(NMA_EDELROUTE,"nma_route_add : sendmsg failed %s",strerror(errno));
           IPM_close_netlink_socket(&nl_socket);
           return IPM_FAILURE;
      }
   }

   memset(&request, 0, sizeof(request));
   iov.iov_base = (void*)&(request.header);
   iov.iov_len = sizeof(request);
   retval = recvmsg(nl_socket,&msg,0);
   if( retval < 0 )
   {
	if( errno == EAGAIN )
	{
		/*
		 * No response.
		 *
		 * Setup timeout for 5 msec (nsec=5000) and try again.
		 */
		sel_time.tv_sec  = 0;
		sel_time.tv_nsec = 5000;
		nanosleep( &sel_time, 0 );
		retval = recvmsg(nl_socket,&msg,0);
		if( retval < 0 )
		{
		   LOG_ERROR(NMA_EDELROUTE, "nma_route_add recvmsg failed again %s", strerror(errno));
           	   IPM_close_netlink_socket(&nl_socket);
                   return IPM_FAILURE;
		}
	}
	else
	{
		LOG_ERROR(NMA_EDELROUTE, "nma_route_add recvmsg  failed %s", strerror(errno));
           	IPM_close_netlink_socket(&nl_socket);
                return IPM_FAILURE;
    }
   }
   IPM_close_netlink_socket(&nl_socket);
#ifdef _IPM // exclude RIPM 
    /*
     * workaround for IPv6 routing, w/o this, ping6 does not work although IPv6 routes were added.
     */
    if ((gateway != NULL) && (gateway->addrtype == IPM_IPV6))
    {
          EIPM_send_neighbor_solicitation( NULL, ifindex, ifname, NULL, gateway, NULL );
    }
#endif

   LOG_ERROR(NMA_OROUTE,"nma_route_add : add route to %s/%d via %s src %s dev %d %s ret = %d",shost,prefixlen,sgateway,ssource,ifindex,sdevice, retval);

   switch (request.header.nlmsg_type) {
   case NLMSG_ERROR:
   {
      error = -((struct nlmsgerr*)NLMSG_DATA(&request.header))->error;
      if (error)
         LOG_ERROR(NMA_EADDROUTE,"nma_route_add : rtnetlink error %s",strerror(error));
      return(error);
   }
   case NLMSG_NOOP:
   case NLMSG_DONE:
   case NLMSG_OVERRUN:
   {
      return IPM_FAILURE;
   }
   }
   return(0);
}


/*************************
 * Name:		nma_route_append
 * Description:	append route path
 * Parameter:	netlinksocket:	netlink socket fd
 *		ifindex:	output interface index
 *		ifname:		output interface name
 *		dest:		route target, host or subnet
 *		prefixlen:	prefix length, if 32, that is host
 *				target if not network target
 *		gateway:	target getway
 *		source:		prefered source ip 
 *		metric		route metric
 * Return:		errno or -1	
**************************/

int nma_route_append(int netlinksocket, int ifindex, char *ifname, IPM_IPADDR *dest, int prefixlen, IPM_IPADDR *gateway,IPM_IPADDR *source,int metric)
{
   struct
   {
      struct nlmsghdr header;
      struct rtmsg route;
      char data[1024];
   } request;
   struct sockaddr_nl nladdr;
   struct iovec iov;
   struct msghdr msg = {(void*)&nladdr,sizeof(nladdr),&iov,1,NULL,0,0};
   int retval;
   struct timespec sel_time;
   int error;
   char shost[IPM_IPMAXSTRSIZE];
   char sgateway[IPM_IPMAXSTRSIZE];
   char ssource[IPM_IPMAXSTRSIZE];
   char sdevice[MAX_NLEN_DEV];
   int max_prefix;
   unsigned int ip_len;
   unsigned rtm_family;
   int nl_socket = -1;
#ifdef DEBUG_CODE
   struct rtattr *myrta;
   int           mylen;
#endif

   if (dest == NULL)
   {
      ASRT_RPT(ASBAD_DATA, 0, "dest is null");
      return IPM_FAILURE;
   }

   switch (dest->addrtype) {
   case IPM_IPV4:
   {
      max_prefix = IPM_IPV4MAXMASKLEN;
      rtm_family = AF_INET;
      ip_len = AF_RAWIPV4SIZE;
      break;
   }
   case IPM_IPV6:
   {
      max_prefix = IPM_IPV6MAXMASKLEN;
      rtm_family = AF_INET6;
      ip_len = AF_RAWIPV6SIZE;
      break;
   }
   default:
      ASRT_RPT(ASBAD_DATA, 1, sizeof(IPM_IPADDR), dest, "Invailid dest ip address type");
      return IPM_FAILURE;
   }

   if (gateway != NULL)
   {
       if ((gateway->addrtype != IPM_IPV4) && (gateway->addrtype != IPM_IPV6))
       {
           ASRT_RPT(ASBAD_DATA, 1, sizeof(IPM_IPADDR), gateway, "Invailid gateway address type");
           return IPM_FAILURE;
       }
   }
   if (source != NULL)
   {
       if ((source->addrtype != IPM_IPV4) && (source->addrtype != IPM_IPV6))
       {
           ASRT_RPT(ASBAD_DATA, 1, sizeof(IPM_IPADDR), source, "Invailid source address type");
           return IPM_FAILURE;
       }
   }

   memset(&request,0,sizeof(request));
   request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));

   request.header.nlmsg_flags = NLM_F_REQUEST|NLM_F_CREATE|NLM_F_APPEND|NLM_F_ACK;

   request.header.nlmsg_type = RTM_NEWROUTE;
   request.header.nlmsg_pid = 0;
   request.header.nlmsg_seq = IPM_rt_seq++;
   request.route.rtm_family = rtm_family;
   request.route.rtm_table = RT_TABLE_MAIN;
   request.route.rtm_protocol = RTPROT_BOOT;
   request.route.rtm_type = RTN_UNICAST;
   if ((prefixlen == NOPARAMETER) || (prefixlen > max_prefix))
     request.route.rtm_dst_len = max_prefix;
   else
     request.route.rtm_dst_len = prefixlen;

   /*
    * The "ip route" code bases the scope on the rtm type and
    * whether or not a gateway is defined.  Since we are only
    * using rtm_type of UNICAST we can simplify the decision
    * down to whether or not there is a gateway given in this
    * routing request.  So if a gateway is given the scope is
    * UNIVERSE, otherwise it is LINK.  (We found this because
    * UNIVERSE does not work for a route without a gateway,
    * and a default route (with a gateway) did not work with
    * scope of LINK.)
    */
    if (gateway != NULL)
    {
         request.route.rtm_scope = RT_SCOPE_UNIVERSE;
    }
    else
    {
         request.route.rtm_scope = RT_SCOPE_LINK;
    }

#ifdef DEBUG_CODE
   myrta = NLMSG_TAIL(&(request.header));
   mylen = NLMSG_ALIGN(request.header.nlmsg_len);
#endif

   nma_route_attr(&request.header,sizeof(request),RTA_DST,dest->ipaddr,ip_len);
   IPM_ipaddr2p(dest, shost, IPM_IPMAXSTRSIZE);
   *sgateway = '\0';
   if (gateway != NULL)
   {
      nma_route_attr(&request.header,sizeof(request),RTA_GATEWAY,gateway->ipaddr,ip_len);
      IPM_ipaddr2p(gateway, sgateway, IPM_IPMAXSTRSIZE);
   }

   *ssource = '\0';
   if (source != NULL)
   {
      nma_route_attr(&request.header,sizeof(request),RTA_PREFSRC,source->ipaddr,ip_len);
      IPM_ipaddr2p(source, ssource, IPM_IPMAXSTRSIZE);
   }
   *sdevice = '\0';
   if (ifindex != NOPARAMETER)
   {
      nma_route_attr(&request.header,sizeof(request),RTA_OIF,&ifindex,4);
      snprintf(sdevice,MAX_NLEN_DEV," device %s", ifname);
   }
   if (metric > 0)
   {
       nma_route_attr(&request.header,sizeof(request),RTA_PRIORITY,&metric,4);
   }

   memset(&nladdr,0,sizeof(nladdr));
   nladdr.nl_family = AF_NETLINK;
   nladdr.nl_pid = 0;
   nladdr.nl_groups = 0;
   iov.iov_base = (void*)&(request.header);
   iov.iov_len = request.header.nlmsg_len;
#ifdef DEBUG_CODE
{
   struct sockaddr_nl	*nl_ptr;
   struct iovec		*iov_ptr;
   int	 		c = 1;
   int	      		i;
	
   nl_ptr = (struct sockaddr_nl *)msg.msg_name;
	
   LOG_OTHER(NMA_OROUTE, "nma_route_append : Print assuming 'struct sockaddr_nl' for name:\n" );
   LOG_OTHER(NMA_OROUTE, "nma_route_append : msg.msg_name= family:%d  nl_pad:%d, nl_pid=%ld, nl_groups=%ld\n", nl_ptr->nl_family, nl_ptr->nl_pad, nl_ptr->nl_pid, nl_ptr->nl_groups );
      
   LOG_OTHER(NMA_OROUTE, "nma_route_append : msg.msg_namelen=%d\n", msg.msg_namelen );
   iov_ptr = msg.msg_iov;
   LOG_OTHER(NMA_OROUTE, "nma_route_append : msg.msg_iov= iov_base=0x%x, iov_len=%d\n", iov_ptr->iov_base, iov_ptr->iov_len  );
   LOG_OTHER(NMA_OROUTE, "nma_route_append : msg.msg_control=0x%x (magic pointer?)\n", msg.msg_control );
   LOG_OTHER(NMA_OROUTE, "nma_route_append : msg.msg_controllen=%d\n", msg.msg_controllen );
   LOG_OTHER(NMA_OROUTE, "nma_route_append : msg.msg_flags=%d\n", msg.msg_flags );
   
   LOG_OTHER(NMA_OROUTE, "nma_route_append : Request\n" );
   
   LOG_OTHER(NMA_OROUTE, "nma_route_append : request.header.nlmsg_len: %d\n", request.header.nlmsg_len );
   LOG_OTHER(NMA_OROUTE, "nma_route_append : request.header.nlmsg_flags: 0x%x\n", request.header.nlmsg_flags );
   LOG_OTHER(NMA_OROUTE, "nma_route_append : request.header.nlmsg_seq: %d\n", request.header.nlmsg_seq );
   LOG_OTHER(NMA_OROUTE, "nma_route_append : request.header.nlmsg_type: %d\n", request.header.nlmsg_type );
   LOG_OTHER(NMA_OROUTE, "nma_route_append : request.header.nlmsg_pid: %d\n", request.header.nlmsg_pid );
   LOG_OTHER(NMA_OROUTE, "nma_route_append : request.route.rtm_family: %d\n", request.route.rtm_family );
   LOG_OTHER(NMA_OROUTE, "nma_route_append : request.route.rtm_dst_len: %d\n", request.route.rtm_dst_len );
   LOG_OTHER(NMA_OROUTE, "nma_route_append : request.route.rtm_src_len: %d\n", request.route.rtm_src_len );
   LOG_OTHER(NMA_OROUTE, "nma_route_append : request.route.rtm_table: %d\n", request.route.rtm_table );
   LOG_OTHER(NMA_OROUTE, "nma_route_append : request.route.rtm_scope: %d\n", request.route.rtm_scope );
   LOG_OTHER(NMA_OROUTE, "nma_route_append : request.route.rtm_protocol: %d\n", request.route.rtm_protocol );
   LOG_OTHER(NMA_OROUTE, "nma_route_append : request.route.rtm_type: %d\n", request.route.rtm_type );
   LOG_OTHER(NMA_OROUTE, "nma_route_append : request.route.rtm_flags: 0x%x\n", request.route.rtm_flags );
   
   i = mylen;
   while (i < request.header.nlmsg_len)
   {
	char 		attr_buf[512];
	char 		tmp[32];
	int		b;
	unsigned char *	p;
	sprintf( attr_buf, "rtatt %d rta_len=%d rta_type=%d\n\n",
		 c, myrta->rta_len, myrta->rta_type);

	p = (unsigned char*)myrta;
	for (b = 0; b < myrta->rta_len; b++)
	{
		sprintf( tmp, "%02x", *(p+b));
		strcat( attr_buf, tmp );
		if ((b & 15) == 15) strcat( attr_buf, "\n");
	}
	strcat( attr_buf, "\n");
	LOG_OTHER(NMA_OROUTE, "%s", attr_buf );
	i += myrta->rta_len;
	p += myrta->rta_len;
	myrta = (struct rtattr *)p;
	c++;
   }
}

#endif
   nl_socket = IPM_open_netlink_socket();
   if (nl_socket < 0)
   {
      return IPM_FAILURE;
   }

   retval = sendmsg(nl_socket,&msg,0);
   if (retval < 0)
   {
      if (errno == EAGAIN)
      {
		/*
		 * No response.
		 *
		 * Setup timeout for 5 msec (nsec=5000) and try again.
		 */
		sel_time.tv_sec  = 0;
		sel_time.tv_nsec = 5000;
		nanosleep( &sel_time, 0 );
        retval = sendmsg(nl_socket,&msg,0);
        if (retval < 0)
        {
           LOG_ERROR(NMA_EDELROUTE,"nma_route_append : sendmsg failed again errno %s",strerror(errno));
	   IPM_close_netlink_socket(&nl_socket);
           return IPM_FAILURE;
        }
      }
      else {
           LOG_ERROR(NMA_EDELROUTE,"nma_route_append : sendmsg failed %s",strerror(errno));
	   IPM_close_netlink_socket(&nl_socket);
           return IPM_FAILURE;
      }
   }

   memset(&request, 0, sizeof(request));
   iov.iov_base = (void*)&(request.header);
   iov.iov_len = sizeof(request);
   retval = recvmsg(nl_socket,&msg,0);
   if( retval < 0 )
   {
	if( errno == EAGAIN )
	{
		/*
		 * No response.
		 *
		 * Setup timeout for 5 msec (nsec=5000) and try again.
		 */
		sel_time.tv_sec  = 0;
		sel_time.tv_nsec = 5000;
		nanosleep( &sel_time, 0 );
		retval = recvmsg(nl_socket,&msg,0);
		if( retval < 0 )
		{
		   LOG_ERROR(NMA_EDELROUTE, "nma_route_append recvmsg failed again %s", strerror(errno));
	   	   IPM_close_netlink_socket(&nl_socket);
           	   return IPM_FAILURE;
		}
	}
	else
	{
		LOG_ERROR(NMA_EDELROUTE, "nma_route_append recvmsg  failed %s", strerror(errno));
	   	IPM_close_netlink_socket(&nl_socket);
           	return IPM_FAILURE;
    }
   }

   IPM_close_netlink_socket(&nl_socket);
   LOG_ERROR(NMA_OROUTE,"nma_route_append : add route to %s/%d via %s src %s dev %d %s ret=%d",shost,prefixlen,sgateway,ssource,ifindex,sdevice, retval);

   switch (request.header.nlmsg_type) {
   case NLMSG_ERROR:
   {
      error = -((struct nlmsgerr*)NLMSG_DATA(&request.header))->error;
      if (error)
         LOG_ERROR(NMA_EADDROUTE,"nma_route_append : rtnetlink error %s",strerror(error));
      return(error);
   }
   case NLMSG_NOOP:
   case NLMSG_DONE:
   case NLMSG_OVERRUN:
   {
      return IPM_FAILURE;
   }
   }
   return(0);
}


/*************************
 * Name:                nma_route_chk
 * Description: check route path
 * Parameter:   netlinksocket: 	netlink socket fd
 *              ifindex:        output interface index
 *              ifname:         output interface name
 *              dest:   	route target, host or subnet
 *              prefixlen:      prefix length, if 32, that is host target if not network target
 *              gateway:        target getway
 *              source:         prefered source ip
 *
 * Return:	1: route path does exist;
 *		0: 0: route path does not exist;
 *		-1: error 
**************************/

int nma_route_chk(int netlinksocket, int ifindex, char *ifname, IPM_IPADDR *dest, int prefixlen, IPM_IPADDR *gateway, IPM_IPADDR *source)
{
	struct
	{
		struct nlmsghdr header;
		struct rtmsg route;
		char data[1024];
	} request;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {(void*)&nladdr,sizeof(nladdr),&iov,1,NULL,0,0};
	struct timespec sel_time;
	char NETWORK[IPM_IPMAXSTRSIZE];
	char NETMASK[IPM_IPMAXSTRSIZE];
	char GATEWAY[IPM_IPMAXSTRSIZE];
	char SOURCE[IPM_IPMAXSTRSIZE];
	int max_prefix;
	unsigned int ip_len;
	unsigned rtm_family;
	int retval;
	int error;
	if (dest == NULL)
	{
		ASRT_RPT(ASBAD_DATA, 0, "dest is null");
		return IPM_FAILURE;
	}

	switch (dest->addrtype) {
	case IPM_IPV4:
	{
		max_prefix = IPM_IPV4MAXMASKLEN;
		rtm_family = AF_INET;
		ip_len = AF_RAWIPV4SIZE;
		break;
	}
	case IPM_IPV6:
	{
		max_prefix = IPM_IPV6MAXMASKLEN;
		rtm_family = AF_INET6;
		ip_len = AF_RAWIPV6SIZE;
		break;
	}
	default:
	{
		ASRT_RPT(ASBAD_DATA, 1, sizeof(IPM_IPADDR), dest, "Invailid dest ip address type");
		return IPM_FAILURE;
	}
	}

	if (gateway != NULL)
	{
		if ((gateway->addrtype != IPM_IPV4) && (gateway->addrtype != IPM_IPV6))
		{
			ASRT_RPT(ASBAD_DATA, 1, sizeof(IPM_IPADDR), gateway, "Invailid gateway address type");
			return IPM_FAILURE;
		}
	}
	if (source != NULL)
	{
		if ((source->addrtype != IPM_IPV4) && (source->addrtype != IPM_IPV6))
		{
			ASRT_RPT(ASBAD_DATA, 1, sizeof(IPM_IPADDR), source, "Invailid source address type");
			return IPM_FAILURE;
		}
	}

	bzero(&request,sizeof(request));
	request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	request.header.nlmsg_flags = NLM_F_REQUEST|NLM_F_EXCL|NLM_F_ACK;
	request.header.nlmsg_type = RTM_NEWROUTE;
	request.route.rtm_family = rtm_family;
	request.route.rtm_table = RT_TABLE_MAIN;
	request.route.rtm_protocol = RTPROT_BOOT;
	request.route.rtm_scope = RT_SCOPE_UNIVERSE;
	request.route.rtm_type = RTN_UNICAST;
	request.route.rtm_dst_len = prefixlen;

	nma_route_attr(&request.header,sizeof(request),RTA_DST,dest->ipaddr,ip_len);
	IPM_ipaddr2p(dest, NETWORK, IPM_IPMAXSTRSIZE);
	if (gateway != NULL) 
	{
		nma_route_attr(&request.header,sizeof(request),RTA_GATEWAY,gateway->ipaddr,ip_len);
		IPM_ipaddr2p(gateway,GATEWAY,IPM_IPMAXSTRSIZE);
	}
	if (source != NULL) 
	{
		nma_route_attr(&request.header,sizeof(request),RTA_PREFSRC,source->ipaddr,ip_len);
		IPM_ipaddr2p(source,SOURCE,IPM_IPMAXSTRSIZE);
	}

	if (ifindex != NOPARAMETER) 
	{
		nma_route_attr(&request.header,sizeof(request),RTA_OIF,&ifindex,4);
	}

	bzero(&nladdr,sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;
	iov.iov_base = (void*)&(request);
	iov.iov_len = request.header.nlmsg_len;
	LOG_OTHER(NMA_OROUTE,"nma_route_chk: dest %s netmask %s gateway %s src %s dev %s",NETWORK,NETMASK,GATEWAY,SOURCE, ifname);
	retval = sendmsg(netlinksocket, &msg,0);
	if (retval < 0)
	{
		if (errno == EAGAIN)
		{
			/*
			 * No response.
			 *
			 * Setup timeout for 5 msec (nsec=5000) and try again.
			 */
			sel_time.tv_sec  = 0;
			sel_time.tv_nsec = 5000;
			nanosleep( &sel_time, 0 );
			retval = sendmsg(netlinksocket,&msg,0);
			if (retval < 0)
			{
				LOG_ERROR(NMA_OROUTE, "nma_route_chk: sendmsg failed again errno %s",strerror(errno));
				return (errno);
			}
		}
		else {
			LOG_ERROR(NMA_OROUTE, "nma_route_chk: sendmsg failed %s",strerror(errno));
			return(errno);
		}
	}
	iov.iov_base = (void*)&(request.header);
	iov.iov_len = sizeof(request);
	retval = recvmsg(netlinksocket, &msg,0);
	if( retval < 0 )
	{
		if( errno == EAGAIN )
		{
			/*
			 * No response.
			 *
			 * Setup timeout for 5 msec (nsec=5000) and try again.
			 */
			sel_time.tv_sec  = 0;
			sel_time.tv_nsec = 5000;
			nanosleep( &sel_time, 0 );
			retval = recvmsg(netlinksocket,&msg,0);
			if( retval < 0 )
			{
				LOG_ERROR(NMA_OROUTE, "nma_route_chk: recvmsg failed again %s", strerror(errno));
			}
		}
		else
		{
			LOG_ERROR(NMA_OROUTE, "nma_route_chk: recvmsg  failed %s", strerror(errno));
		}
	}

	if (request.header.nlmsg_type == NLMSG_ERROR)
	{
		error = -((struct nlmsgerr*)NLMSG_DATA(&request.header))->error;
		if (error == EEXIST)
		{
			return (1);
		}
		else if (error == 0)
		{
			return (0);
		}
		else 
		{
			LOG_ERROR(NMA_OROUTE, "nma_route_chk: failed %d (%s)", error, strerror(error));
			return (-1);
		}

	}
	LOG_ERROR(NMA_OROUTE, "nma_route_chk: rtnetlink msg unknown");
	return(-1);
}


IPM_RETVAL IPM_getlinklocalv6addr(int netlinksocket, int lsn0, IPM_IPADDR *linklocal0, int lsn1, IPM_IPADDR *linklocal1)
{
	static int ipm_linklocalip_ready = 0;
	int rtn;
	int lsn0_is_ready = 0;
	int lsn1_is_ready = 0;

	/* SENDMSG Variable */
	struct {
		struct nlmsghdr         nlmsg_info;
		struct ifaddrmsg        ifaddrmsg_info;
		char                    buffer[2048];
	} netlink_req;

	struct sockaddr_nl local;
	struct sockaddr_nl peer;
	struct msghdr msg_info;
	struct iovec iov_info;


	/* RECVMSG Variable */
	struct sockaddr_nl nladdr;
	struct iovec iov;

	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char buf[16384];
	struct ifaddrmsg *ifaddrmsg_ptr;
	struct rtattr *rtattr_ptr;
	int ifaddrmsg_len;


 	iov.iov_base = buf;

	if (ipm_linklocalip_ready == 1)
	{
		return IPM_SUCCESS;
	}

	bzero(&local, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pad = 0;
	local.nl_pid = getpid();
	local.nl_groups = 0;
	rtn = bind(netlinksocket, (struct sockaddr*) &local, sizeof(local));
	if (rtn < 0) {
		ASRT_RPT(ASUNEXP_RETURN, 
					1, 
					sizeof(local), 
					&local, 
					"bind() failed retval = %d, errno = %d", rtn, errno);
		return IPM_FAILURE;
        }

	bzero(&peer, sizeof(peer));
	peer.nl_family = AF_NETLINK;
	peer.nl_pad = 0;
	peer.nl_pid = 0;
	peer.nl_groups = 0;

	bzero(&msg_info, sizeof(msg_info));
	msg_info.msg_name = (void *) &peer;
	msg_info.msg_namelen = sizeof(peer);

	bzero(&netlink_req, sizeof(netlink_req));
	netlink_req.nlmsg_info.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	netlink_req.nlmsg_info.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH;
	netlink_req.nlmsg_info.nlmsg_type = RTM_GETADDR;
	netlink_req.nlmsg_info.nlmsg_pid = 0; //getpid();
	netlink_req.ifaddrmsg_info.ifa_family = AF_INET6;

	iov_info.iov_base = (void *) &netlink_req.nlmsg_info;
	iov_info.iov_len = netlink_req.nlmsg_info.nlmsg_len;
	msg_info.msg_iov = &iov_info;
	msg_info.msg_iovlen = 1;

	rtn = sendmsg(netlinksocket, &msg_info, 0);
	if(rtn < 0) {
		ASRT_RPT(ASUNEXP_RETURN,
					2,
					sizeof(msg_info),
					&msg_info,
					sizeof(netlink_req),
					&netlink_req,
					"sendmsg() failed retval %d errno 0x%x\n", rtn, errno );
		return IPM_FAILURE;
	}

	while(1) {
		int status;
		struct nlmsghdr *h;

		iov.iov_len = sizeof(buf);
		status = recvmsg(netlinksocket, &msg, 0);

		if (status < 0) {
			if (errno == EINTR)
			{
				continue;
			}
			else
			{
				ASRT_RPT( ASUNEXP_RETURN,
						1,
						sizeof(netlinksocket),
						&netlinksocket,
						"recvmsg() failed retval %d errno 0x%x/%s\n", status, errno, strerror(errno) );
				return IPM_FAILURE;
			}
		}

		if (status == 0) {
			return IPM_FAILURE;
		}
		h = (struct nlmsghdr*)buf;
		while (NLMSG_OK(h, status)) {
			if (h->nlmsg_type == NLMSG_DONE)
				return IPM_FAILURE;
			if (h->nlmsg_type == NLMSG_ERROR) {
				return IPM_FAILURE;
			}
			ifaddrmsg_ptr = (struct ifaddrmsg *) NLMSG_DATA(h);
			rtattr_ptr = (struct rtattr *) IFA_RTA(ifaddrmsg_ptr);
			ifaddrmsg_len = IFA_PAYLOAD(h);

			for(;RTA_OK(rtattr_ptr, ifaddrmsg_len); rtattr_ptr = RTA_NEXT(rtattr_ptr, ifaddrmsg_len))
			{
				if ((rtattr_ptr->rta_type == IFA_ADDRESS)
					&& (ifaddrmsg_ptr->ifa_scope == RT_SCOPE_LINK)
					)
				{
					if (ifaddrmsg_ptr->ifa_index == lsn0)
					{
						IPM_ipaddr_init(linklocal0);
						memcpy(linklocal0->ipaddr, ((struct in6_addr *)RTA_DATA(rtattr_ptr))->s6_addr, AF_RAWIPV6SIZE);
						linklocal0->addrtype = IPM_IPV6;
						lsn0_is_ready = 1;
					}
					if (ifaddrmsg_ptr->ifa_index == lsn1)
					{
						IPM_ipaddr_init(linklocal1);
						memcpy(linklocal1->ipaddr, ((struct in6_addr *)RTA_DATA(rtattr_ptr))->s6_addr, AF_RAWIPV6SIZE);
						linklocal1->addrtype = IPM_IPV6;
						lsn1_is_ready = 1;
					}
				}
				if ((lsn0_is_ready == 1) && (lsn1_is_ready == 1))
				{
					ipm_linklocalip_ready = 1;
					return IPM_SUCCESS;
				}
			}

			h = NLMSG_NEXT(h, status);
		}
		if (msg.msg_flags & MSG_TRUNC) {
			continue;
		}
	}
}

/* There are a lot of place to open netlink socet in IPM code, so here combine them into one function */
int IPM_open_netlink_socket(void)
{
	struct sockaddr_nl nladdr;
	int retval;
	int nl_socket;

	nl_socket = socket( PF_NETLINK, SOCK_RAW, NETLINK_ROUTE );

	if( nl_socket < 0 )
	{
		ASRT_RPT( ASOSFNFAIL,
					0,
					"IPM_open_netlink_socket - failed to create netlink socket\nnl_socke =%d, errno=0x%x:%s\n",
					nl_socket,
					errno, strerror(errno) );

		return( IPM_FAILURE );
	}

	retval = fcntl(nl_socket, F_GETFL, 0);
	if (retval < 0)
	{
		ASRT_RPT(ASOSFNFAIL, 0, "fcntl(GET) for netlink failed; errno=%d/%s",
				errno, strerror(errno));
		(void)close( nl_socket );
		return IPM_FAILURE;
	}

	retval |= O_NONBLOCK;
	retval = fcntl(nl_socket, F_SETFL, retval);
	if (retval < 0)
	{
		ASRT_RPT(ASOSFNFAIL, 0, "fcntl(SET,%d) for netlink failed; errno=%d/%s",
				retval, errno, strerror(errno));
		(void)close( nl_socket );
		return IPM_FAILURE;
	}

	// Bind socket
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pad = 0;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	retval = bind(nl_socket, (struct sockaddr *) &nladdr, sizeof ( nladdr));

	if (retval < 0)
	{
		ASRT_RPT(ASOSFNFAIL, 0, "bind for netlink failed; errno=%d/%s",
				errno, strerror(errno));
		(void)close( nl_socket );
		return ( IPM_FAILURE);
	}

	return nl_socket;
}
void IPM_close_netlink_socket(int *nl_socket)
{
	if (*nl_socket >=0)
	{
		(void)close(*nl_socket);
	}
	*nl_socket = -1;	
}

/*
 * Name:        ipm_route_mgr()
 *
 * Abstract:    Common function to add or del routing entry
 *
 * Parameters:  action     - add or delete operation
 *              route_ptr  - route entry to be operated
 *              table_num   - route table id for the operation 
 *
 * Returns:     IPM_SUCCESS - operation is done successfully
 *              IPM_FAILURE - some error occurred.
 */
int ipm_route_mgr(EIPM_ADD_DEL action, IPM_ROUTE_ENTRY *route_ptr, uint8_t table_num)
{

	struct
	{
		struct nlmsghdr header;
		struct rtmsg route;
		char data[1024];
	} request;

	struct sockaddr_nl nladdr;
	int nl_socket;
	struct iovec iov;
	struct msghdr msg = {(void*) &nladdr, sizeof (nladdr), &iov, 1, NULL, 0, 0};
	int retval;
	struct timespec sel_time;
	int errnum = 0;
	char sdest[IPM_IPMAXSTRSIZE];
	char sgateway[IPM_IPMAXSTRSIZE];
	char ssource[IPM_IPMAXSTRSIZE];
	char sdevice[MAX_NLEN_DEV];
	char saction[20] = {0};
	int max_prefix;
	unsigned int ip_len;
	unsigned rtm_family;
	int msg_seq;
	IPM_IPADDRTYPE dst_ip_ver = IPM_IPBADVER;
	IPM_IPADDRTYPE gw_ip_ver = IPM_IPBADVER;

	if ((action != EIPM_ADD) && (action != EIPM_DEL))
	{
		LOG_ERROR(NMA_OROUTE, "ipm_route_mgr: Invalid route operation, %d\n", action);
		return IPM_FAILURE;
	}

	if (route_ptr == NULL)
	{
		LOG_ERROR(NMA_OROUTE, "ipm_route_mgr: Invalid route pointer\n");
		return IPM_FAILURE;
	}

	// Try to get dest IP version if it is valid
	if (route_ptr->dest.addrtype == IPM_IPV4)
	{
		dst_ip_ver = IPM_IPV4;
	}
	else if (route_ptr->dest.addrtype == IPM_IPV6)
	{
		dst_ip_ver = IPM_IPV6;
	}

	// Try to get dest IP version if it is valid
	if (route_ptr->gateway.addrtype == IPM_IPV4)
	{
		gw_ip_ver = IPM_IPV4;
	}
	else if (route_ptr->gateway.addrtype == IPM_IPV6)
	{
		gw_ip_ver = IPM_IPV6;
	}

	// For dest and gateway, at least one IP version should be valid
	if ((dst_ip_ver == IPM_IPBADVER) && (gw_ip_ver == IPM_IPBADVER))
	{
		LOG_ERROR(NMA_OROUTE, "ipm_route_mgr: Invalid IP version for destination and gateway.\n");
		return IPM_FAILURE;
	}

	// If both dest and gateway IP version are valid, they should be same.
	if ((dst_ip_ver != IPM_IPBADVER) && (gw_ip_ver != IPM_IPBADVER) && (dst_ip_ver != gw_ip_ver))
	{
		LOG_ERROR(NMA_OROUTE, "ipm_route_mgr: IP version for destination and gateway are not same.\n");
		return IPM_FAILURE;
	}

	// Create socket.
	nl_socket = IPM_open_netlink_socket();

	if (nl_socket < 0)
	{
		LOG_ERROR(NMA_OROUTE, "ipm_route_mgr: Failed to open netlink socket.\n");
		return ( IPM_FAILURE);
	}

	// Populate net attributes according to IP version.
	if ((dst_ip_ver == IPM_IPV4) || (gw_ip_ver == IPM_IPV4))
	{
		max_prefix = IPM_IPV4MAXMASKLEN;
		rtm_family = AF_INET;
		ip_len = AF_RAWIPV4SIZE;
	}
	else if ((dst_ip_ver == IPM_IPV6) || (gw_ip_ver == IPM_IPV6))
	{
		max_prefix = IPM_IPV6MAXMASKLEN;
		rtm_family = AF_INET6;
		ip_len = AF_RAWIPV6SIZE;
	}

	memset(&request, 0, sizeof (request));
	request.header.nlmsg_len = NLMSG_LENGTH(sizeof (struct rtmsg));
	request.header.nlmsg_pid = 0;
	request.header.nlmsg_seq = msg_seq = ++IPM_rt_seq;
	request.route.rtm_family = rtm_family;
	request.route.rtm_table = table_num;

	if (action == EIPM_ADD)
	{
		request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK;
		request.header.nlmsg_type = RTM_NEWROUTE;
		request.route.rtm_protocol = RTPROT_BOOT;
		request.route.rtm_type = RTN_UNICAST;
		strcpy(saction, "add route");
	}
	else
	{
		request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
		request.header.nlmsg_type = RTM_DELROUTE;
		strcpy(saction, "del route");
	}

	// Populate rtattr
	*sdest = '\0';
	if (!IPM_IPADDR_ISUNSPECIFIED(&(route_ptr->dest)))
	{
		nma_route_attr(&request.header, sizeof (request), RTA_DST, route_ptr->dest.ipaddr, ip_len);
		request.route.rtm_dst_len = route_ptr->destprefix;
		IPM_ipaddr2p(&route_ptr->dest, sdest, IPM_IPMAXSTRSIZE);
	}

	*sgateway = '\0';
	if (!IPM_IPADDR_ISUNSPECIFIED(&(route_ptr->gateway)))
	{
		nma_route_attr(&request.header, sizeof (request), RTA_GATEWAY, route_ptr->gateway.ipaddr, ip_len);
		IPM_ipaddr2p(&route_ptr->gateway, sgateway, IPM_IPMAXSTRSIZE);
		request.route.rtm_scope = RT_SCOPE_UNIVERSE;
	}
	else
	{
		request.route.rtm_scope = RT_SCOPE_LINK;
	}

	if (action == EIPM_DEL)
	{
		request.route.rtm_scope = RT_SCOPE_NOWHERE;
	}

	*ssource = '\0';
	if (!IPM_IPADDR_ISUNSPECIFIED(&(route_ptr->srcip)))
	{
		nma_route_attr(&request.header, sizeof (request), RTA_PREFSRC, route_ptr->srcip.ipaddr, ip_len);
		IPM_ipaddr2p(&route_ptr->srcip, ssource, IPM_IPMAXSTRSIZE);
	}

	*sdevice = '\0';
	if (route_ptr->iface_indx != NOPARAMETER)
	{
		nma_route_attr(&request.header, sizeof (request), RTA_OIF, &(route_ptr->iface_indx), 4);
		snprintf(sdevice, MAX_NLEN_DEV, "%s", route_ptr->iface);
	}

	if (route_ptr->priority != 0)
	{
		nma_route_attr(&request.header, sizeof (request), RTA_PRIORITY, &(route_ptr->priority), 4);
	}

	memset(&nladdr, 0, sizeof (nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;
	iov.iov_base = (void*) &(request.header);
	iov.iov_len = request.header.nlmsg_len;

	if (sendmsg(nl_socket, &msg, 0) == -1)
	{
		LOG_FORCE(NMA_OROUTE, "ipm_route_mgr: Failed to send netlink message.\n");
		IPM_close_netlink_socket(&nl_socket);
		return IPM_FAILURE;
	}

	memset(&request, 0, sizeof (request));
	iov.iov_base = (void*) &(request.header);
	iov.iov_len = sizeof (request);

	// receive the answers.
	while (1)
	{
		if (errnum > 2)
		{
			LOG_ERROR(NMA_OROUTE, "ipm_route_mgr: Too many error occur when receiving answers.\n");
			IPM_close_netlink_socket(&nl_socket);
			return IPM_FAILURE;
		}

		retval = recvmsg(nl_socket, &msg, 0);

		if (retval < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}

			// For EAGAIN error, retry more times.
			if (errno == EAGAIN)
			{
				errnum++;
				sel_time.tv_sec = 0;
				sel_time.tv_nsec = 5000;
				nanosleep(&sel_time, 0);
				continue;
			}

			LOG_FORCE(NMA_OROUTE, "ipm_route_mgr: Error found when receiving answers for %s, error %s", saction, strerror(errno));
			IPM_close_netlink_socket(&nl_socket);
			return IPM_FAILURE;
		}

		if (request.header.nlmsg_seq != msg_seq)
		{
			errnum++;
			continue;
		}

		// Only one nlmsg is expected for the answer.
		break;
	}

	IPM_close_netlink_socket(&nl_socket);

#ifdef _IPM // exclude RIPM 
	/*
	 * workaround for IPv6 routing, w/o this, ping6 does not work although IPv6 routes were added.
	 */
	if (action == EIPM_ADD)
	{
		if ((!IPM_IPADDR_ISUNSPECIFIED(&(route_ptr->gateway))) && (route_ptr->gateway.addrtype == IPM_IPV6))
		{
			EIPM_send_neighbor_solicitation(NULL, route_ptr->iface_indx, route_ptr->iface, NULL, &(route_ptr->gateway), NULL);
		}
	}
#endif

	// Modify contents of the key parameters for logging.
	if (*sdest == '\0') strcpy(sdest, "0");
	if (*sgateway == '\0') strcpy(sgateway, "0");
	if (*ssource == '\0') strcpy(ssource, "0");
	errnum = IPM_SUCCESS;
	if (request.header.nlmsg_type == NLMSG_ERROR)
	{
		errnum = -((struct nlmsgerr*) NLMSG_DATA(&request.header))->error;
		if (errnum)
		{
			LOG_ERROR(NMA_OROUTE, "ipm_route_mgr: Error found in received message for %s destination %s/%d, gw %s, device %s, error %s", saction, sdest, route_ptr->destprefix, sgateway, sdevice, strerror(errnum));
			if(errnum == EEXIST)
			{
				return(EEXIST);
			}
			errnum = IPM_FAILURE;
		}
	}

	LOG_OTHER(NMA_OROUTE, "ipm_route_mgr: %s destination %s/%d, gateway %s, prefer src %s, device %s, priority %d. return value %d",
		saction, sdest, route_ptr->destprefix, sgateway, ssource, sdevice, route_ptr->priority, errnum);

	return errnum;
}

/*
 * Name:        ipm_rule_mgr()
 *
 * Abstract:    Common function to add or del rule entry
 *
 * Parameters:  action     - add or delete operation
 *              rule_ptr   - rule entry to be operated
 *
 * Returns:     IPM_SUCCESS - operation is done successfully
 *              IPM_FAILURE - some error occurred.
 */
IPM_RETVAL ipm_rule_mgr(EIPM_ADD_DEL action, IPM_RULE_ENTRY *rule_ptr)
{

	struct
	{
		struct nlmsghdr header;
		struct rtmsg route;
		char data[1024];
	} request;

	struct sockaddr_nl nladdr;
	int nl_socket;
	struct iovec iov;
	struct msghdr msg = {(void*) &nladdr, sizeof (nladdr), &iov, 1, NULL, 0, 0};
	char ssrcip[IPM_IPMAXSTRSIZE];
	char saction[20] = {0};
	struct timespec sel_time;
	int retval;
	int max_prefix;
	unsigned int ip_len;
	unsigned rtm_family;
	int errnum = 0;
	uint32_t msg_seq;

	if ((action != EIPM_ADD) && (action != EIPM_DEL))
	{
		LOG_ERROR(NMA_OROUTE, "ipm_rule_mgr: Invalid rule operation, %d\n", action);
		return IPM_FAILURE;
	}

	if (rule_ptr == NULL)
	{
		LOG_ERROR(NMA_OROUTE, "ipm_rule_mgr: Invalid rule pointer.\n");
		return IPM_FAILURE;
	}

	if (rule_ptr->srcip.addrtype == 0)
	{
		LOG_ERROR(NMA_OROUTE, "ipm_rule_mgr: Source IP for the rule is not specified.\n");
		return IPM_FAILURE;
	}

	if ((action == EIPM_ADD) &&
		((rule_ptr->table_num == RT_TABLE_UNSPEC) || (rule_ptr->table_num >= RT_TABLE_DEFAULT)))
	{
		LOG_ERROR(NMA_OROUTE, "ipm_rule_mgr: Invalid table id for adding rule.\n");
		return IPM_FAILURE;
	}

	if (rule_ptr->srcip.addrtype == IPM_IPV4)
	{
		max_prefix = IPM_IPV4MAXMASKLEN;
		rtm_family = AF_INET;
		ip_len = AF_RAWIPV4SIZE;
	}
	else if (rule_ptr->srcip.addrtype == IPM_IPV6)
	{
		max_prefix = IPM_IPV6MAXMASKLEN;
		rtm_family = AF_INET6;
		ip_len = AF_RAWIPV6SIZE;
	}
	else
	{
		LOG_ERROR(NMA_OROUTE, "ipm_rule_mgr: Source IP version is not valid.\n");
		return IPM_FAILURE;
	}

	// Create OS netlink socket.
	nl_socket = IPM_open_netlink_socket();

	if (nl_socket < 0)
	{
		LOG_ERROR(NMA_OROUTE, "ipm_rule_mgr: Failed to open netlink socket.\n");
		return ( IPM_FAILURE);
	}

	// Populate nlmsg header and rtmsg
	memset(&request, 0, sizeof (request));
	request.header.nlmsg_len = NLMSG_LENGTH(sizeof (struct rtmsg));
	request.header.nlmsg_pid = 0;
	request.header.nlmsg_seq = msg_seq = ++IPM_rt_seq;

	if (action == EIPM_ADD)
	{
		request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
		request.header.nlmsg_type = RTM_NEWRULE;
		strcpy(saction, "add rule");
	}
	else
	{
		request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
		request.header.nlmsg_type = RTM_DELRULE;
		strcpy(saction, "del rule");
	}

	// Populate rtmsg struct
	request.route.rtm_table = rule_ptr->table_num;
	request.route.rtm_family = rtm_family;
	request.route.rtm_scope = RT_SCOPE_NOWHERE;
	request.route.rtm_type = RTN_UNICAST;

	if (rule_ptr->prefix > max_prefix)
		request.route.rtm_src_len = max_prefix;
	else
		request.route.rtm_src_len = rule_ptr->prefix;

	// Attach the rtattr of source
	nma_route_attr(&request.header, sizeof (request), RTA_SRC, rule_ptr->srcip.ipaddr, ip_len);
	IPM_ipaddr2p(&(rule_ptr->srcip), ssrcip, IPM_IPMAXSTRSIZE);

	nma_route_attr(&request.header, sizeof (request), RTA_PRIORITY, &(rule_ptr->priority), 4);

	memset(&nladdr, 0, sizeof (nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;
	iov.iov_base = (void*) &(request.header);
	iov.iov_len = request.header.nlmsg_len;

	if (sendmsg(nl_socket, &msg, 0) == -1)
	{
		LOG_FORCE(NMA_OROUTE, "ipm_rule_mgr: Failed to send message.\n");
		IPM_close_netlink_socket(&nl_socket);
		return IPM_FAILURE;
	}

	memset(&request, 0, sizeof (request));
	iov.iov_base = (void*) &(request.header);
	iov.iov_len = sizeof (request);

	// receive the answers.
	while (1)
	{
		if (errnum > 2)
		{
			LOG_ERROR(NMA_OROUTE, "ipm_rule_mgr: Too many error occur when receiving answers for %s.\n", saction);
			IPM_close_netlink_socket(&nl_socket);
			return IPM_FAILURE;
		}

		retval = recvmsg(nl_socket, &msg, 0);

		if (retval < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}

			// For EAGAIN error, retry more times.
			if (errno == EAGAIN)
			{
				errnum++;
				sel_time.tv_sec = 0;
				sel_time.tv_nsec = 5000;
				nanosleep(&sel_time, 0);
				continue;
			}

			LOG_FORCE(NMA_OROUTE, "ipm_rule_mgr: Error found when receiving answers for %s, error %s", saction, strerror(errno));
			IPM_close_netlink_socket(&nl_socket);
			return IPM_FAILURE;
		}

		if (request.header.nlmsg_seq != msg_seq)
		{
			errnum++;
			continue;
		}

		// Only one nlmsg is expected for the answer.
		break;
	}

	IPM_close_netlink_socket(&nl_socket);

	errnum = IPM_SUCCESS;
	if (request.header.nlmsg_type == NLMSG_ERROR)
	{
		errnum = -((struct nlmsgerr*) NLMSG_DATA(&request.header))->error;
		if (errnum)
		{
			LOG_ERROR(NMA_OROUTE, "ipm_rule_mgr: Error found in received message for %s, error %s", saction, strerror(errnum));
			errnum = IPM_FAILURE;
		}
	}

	if (*ssrcip == '\0') strcpy(ssrcip, "0");
	LOG_OTHER(NMA_OROUTE, "ipm_rule_mgr: %s from %s/%d lookup table %d, return value %d",
		saction, ssrcip, rule_ptr->prefix, rule_ptr->table_num, errnum);

	return errnum;
}

/*
 * Name:        ipm_route_add()
 *
 * Abstract:    Common function to add route entry. It is used to replace the original
 *              nma_route_add. Also, it has a new parameter, table_num, to specify the
 *              table in which the route will be added.
 *
 * Returns:     IPM_SUCCESS - operation is done successfully
 *              IPM_FAILURE - some error occurred.
 */
int ipm_route_add(int ifindex, char *ifname, unsigned short vlanId, IPM_IPADDR *dest, int prefixlen, IPM_IPADDR *gateway, IPM_IPADDR *source, uint8_t table_num)
{
	int retval, retval2;
	IPM_ROUTE_ENTRY rt_entry;

	// Populate route entry according to the parameters, which will be used by
	// ipm_route_mgr.
	memset(&rt_entry, 0, sizeof (IPM_ROUTE_ENTRY));

	rt_entry.iface_indx = ifindex;

	if (ifname != NULL)
	{
		strcpy(rt_entry.iface, ifname);
	}

	if (dest != NULL)
	{
		memcpy(&rt_entry.dest, dest, sizeof (IPM_IPADDR));
	}

	rt_entry.destprefix = prefixlen;

	if (gateway != NULL)
	{
		memcpy(&rt_entry.gateway, gateway, sizeof (IPM_IPADDR));
	}

	if (source != NULL)
	{
		memcpy(&rt_entry.srcip, source, sizeof (IPM_IPADDR));
	}

#ifdef _IPM // exclude RIPM 
	/* 
	 * For IPv6 monitored routes avoid creating a route with both
	 * the destination and gateway having the same IP address.  This causes
	 * a "no route to host" failure for other destination routes that use the 
	 * same gateway.  In addition, a metric is needed to ensure the route can
	 * be removed later.
	 */
	if (gateway != NULL &&
		gateway->addrtype == IPM_IPV6 &&
		IPM_IPCMPADDR(gateway, dest) == IPM_SUCCESS &&
		EIPM_check_monitor_route(dest) == IPM_SUCCESS)
	{
		rt_entry.priority = 1024;
		IPM_ipaddr_init(&rt_entry.gateway);
	}

	retval = EIPM_process_route_update(EIPM_ADD, ifname, dest, prefixlen, gateway);
	if ((retval != IPM_SUCCESS) && (retval != IPM_PIVOT_ROUTE))
	{
		LOG_ERROR(NMA_OROUTE, "nma_route_add: EIPM_process_route_update failure ret %d", retval);
	}

	retval2 = PIPM_process_route_update(PIPM_ADD_ROUTE, ifname, vlanId, dest, prefixlen, gateway);
	if (retval2 != IPM_SUCCESS)
	{
		LOG_ERROR(NMA_OROUTE, "nma_route_add: PIPM_process_route_update failure ret %d", retval);
	}

	/* Don't need to add route in IIPM if it is access route.
	 * From CP5.0, it access subnet will be on pivot and
	 * its active slave will be updated by IOCTL
	 */
	if (retval == IPM_PIVOT_ROUTE)
	{
		return 0;
	}
#endif

	retval = ipm_route_mgr(EIPM_ADD, &rt_entry, table_num);

	return retval;
}

/*
 * Name:        ipm_route_del()
 *
 * Abstract:    Common function to del route entry. It is used to replace the original
 *              nma_route_del. Also, it has a new parameter, table_num, to specify the
 *              table from which the route will be deleted.
 *
 * Returns:     IPM_SUCCESS - operation is done successfully
 *              IPM_FAILURE - some error occurred.
 */
int ipm_route_del(int ifindex, char *ifname, IPM_IPADDR *dest, int prefixlen, IPM_IPADDR *gateway, uint8_t table_num)
{

	int retval, retval2;
	IPM_ROUTE_ENTRY rt_entry;

	// Populate route entry according to the parameters, which will be used by
	// ipm_route_mgr.
	memset(&rt_entry, 0, sizeof (IPM_ROUTE_ENTRY));

	rt_entry.iface_indx = ifindex;

	if (ifname != NULL)
	{
		strcpy(rt_entry.iface, ifname);
	}

	if (dest != NULL)
	{
		memcpy(&rt_entry.dest, dest, sizeof (IPM_IPADDR));
	}

	rt_entry.destprefix = prefixlen;

	if (gateway != NULL)
	{
		memcpy(&rt_entry.gateway, gateway, sizeof (IPM_IPADDR));
	}

#ifdef _IPM // exclude RIPM 
	if (dest->addrtype == IPM_IPV6 &&
		EIPM_check_monitor_route(dest) == IPM_SUCCESS)
	{
		rt_entry.priority = 1024;
	}

	retval = EIPM_process_route_update(EIPM_DEL, ifname, dest, prefixlen, gateway);
	if ((retval != IPM_SUCCESS) && (retval != IPM_PIVOT_ROUTE))
	{
		LOG_ERROR(NMA_OROUTE, "nma_route_del: EIPM_process_route_update failure ret %d", retval);
	}

	retval2 = PIPM_process_route_update(PIPM_DEL_ROUTE, ifname, 0, dest, prefixlen, gateway);
	if (retval2 != IPM_SUCCESS)
	{
		LOG_ERROR(NMA_OROUTE, "nma_route_del: PIPM_process_route_update failure ret %d", retval);
	}

	/* Don't need to del route in IIPM if it is access route.
	 * From CP5.0, it access subnet will be on pivot and
	 * its active slave will be updated by IOCTL
	 */
	if (retval == IPM_PIVOT_ROUTE)
	{
		return 0;
	}
#endif

	retval = ipm_route_mgr(EIPM_DEL, &rt_entry, table_num);

	return retval;
}

