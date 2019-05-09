/*
 *  File:        ipm_util.c
 *
 *  Contents:    This file contains primitives used by the ipm process.
 *
 *  Functions:   
 *               ipm_get_aliasip_shm () - Gets a pointer to the ailias ip share memory
 *               ipm_get_intf() - get interface parameter related with nma_interface_t
 *		 ipm_get_pif - get paired interface from shm
 *               ip_ss2str() - convert sockaddr_storage to string
 *		 ip_sscmp() - compare sockaddr_stoage
 *               ipm_getVLANStr - converts a valid VLAN Id to a string.
 *               ipm_check_linkup - check link carrier status for a certain interface
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

#include "nma_log.h"
#include "ipm_util.h"
#include "ipm_init.h"
#include "nma_ctx.h"
#include "EIPM_include.h"
#include "EIPM_bfd.h"
#include "nma_route.h"

extern char ipmHostName[NAME_MAX];

extern nma_ctx_t * tab_ctx;
/* Pointer to IPM's shared alias ip structure */
ipm_shm_t * ipm_shm_ptr = (ipm_shm_t *)0;

/* Buffer to hold supplementary diagnostic message for Log/Alarm/Assert */
static char dump_buffer[UMAX_LOG_SIZE];

/* ipm alarm table */
typedef struct ipm_alarm_t {
        FSALARM_SEVERITY_TYPE level;
        char altResource[FSALARM_RESOURCE_BUFFSZ];
        char userText[FSALARM_UTEXT_BUFFSZ];
        unsigned int lineNumber;
        char fileName[128];
        int  delay_cnt;
} ipm_alarm_t;

static ipm_alarm_t * p_ipm_alarm[MAX_IPM_ALARMS];
static int ipm_alarm_cnt;

extern int ipm_alarm_delay;

ipm_shm_t * ipm_get_shm(int * isNew)
{
	/* Pointer to a particular process's shared memory region */
	char * shm_ptr;

	/* The application process's shared memory id */
	int shmid;

	/* The application process's shared memory key */
	int shm_key;

	*isNew = FALSE;

	/*
	 * First check to see if there's already a pointer setup to
	 * the application image shared memory.
	 */
	if( ipm_shm_ptr != 0)
	{
		return( ipm_shm_ptr );
	}

	shm_key = IPM_SHM_KEY;
	if ( (shmid = shmget ( shm_key, sizeof(ipm_shm_t), IPM_SHM_MODE) ) < 0 )
	{
		if (errno == EEXIST)
		{
			/*
			 * It exists already
			 */
			if ( (shmid = shmget ( shm_key, sizeof(ipm_shm_t), IPM_SHM_EXISTS) ) < 0 )
			{
				ASRT_RPT(ASOSFNFAIL, 0, "Bad return from shmget (), errno = %d\n", errno);
				return ( (ipm_shm_t *)0 );
			}
		}
		else
		{
			ASRT_RPT(ASOSFNFAIL, 0, "Bad errno from shmget (), errno = %d\n", errno);
			return ( (ipm_shm_t *)0 );
		}
	}
	else
	{
		/*
		 * Just created new image shared memory.
		 */
		*isNew = TRUE;
	}

	/*
	 * Attach the shared memory to our process.
	 */
	if ( (shm_ptr = (char *) shmat (shmid, NULL, 0)) == (void *) -1)
	{
		ASRT_RPT(ASOSFNFAIL, 0,"Bad return from shmat (), errno = %d\n",  errno);
		return ( (ipm_shm_t *)0 );
	}
	else
	{
		/*
		 * Save a pointer to the shared memory.
		 */
		ipm_shm_ptr = (ipm_shm_t *)shm_ptr;
		if( *isNew == TRUE)
		{
			memset(ipm_shm_ptr, 0, sizeof(ipm_shm_t));
		}
		return ( ipm_shm_ptr );
	}
}

int ipm_get_ifindex(int inetsocket, char *name)
{
    struct ifreq  ifr;

    if (name == NULL)
    {
        ASRT_RPT(ASRTBADPARAM, 0, "input paremater name (%s) is invalid\n", name);
        return -1;
    }

    memset((void *)&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, name, IFNAMSIZ-1);

    if (ioctl(inetsocket, SIOCGIFINDEX, &ifr) < 0)
    {
        ASRT_RPT(ASOSFNFAIL, 0, "ioctl SIOCGIFINDEX errno %d, name %s\n", errno, name);
        return(-1);
    }
    return (ifr.ifr_ifindex);
}

/* populate nma_interface_t according to its name */
int ipm_get_intf(int inetsocket, nma_interface_t *nma_intf)
{
	struct ifreq  ifr;
	struct vlan_ioctl_args vlan;
	int i;
	char *p;

	if ((nma_intf == NULL) || (nma_intf->name[0] == '\0'))
	{
		ASRT_RPT(ASRTBADPARAM, 0, "invalid parameter\n" );
		return -1;
	}

	strncpy(ifr.ifr_name,nma_intf->name, IFNAMSIZ-1);
	ifr.ifr_name[IFNAMSIZ-1] = 0;
	/* Get Interface Index */
	if (ioctl(inetsocket, SIOCGIFINDEX, &ifr) < 0)
	{
		ASRT_RPT(ASOSFNFAIL, 0, "ioctl SIOCGIFINDEX name %s, errno %d\n", nma_intf->name, errno);
		return(-1);
	}
	nma_intf->ifindex = ifr.ifr_ifindex;
	/* Get Interface MAC address */
	if (ioctl(inetsocket, SIOCGIFHWADDR, &ifr) < 0)
	{
		ASRT_RPT(ASOSFNFAIL, 0, "ioctl SIOCGIFHWADDR name %s, errno %d\n", nma_intf->name, errno);
		return(-1);
	}
	memcpy(&(nma_intf->ether),(ifr.ifr_hwaddr.sa_data),ETH_ALEN);

	// vlan id is optional
	p= strchr(nma_intf->name, '.');
	if(p == NULL)
	{
		nma_intf->vid = -1;
		return 0;
	}

	//get vlan id
	vlan.cmd = GET_VLAN_VID_CMD;
	//remove ':', which is not recognized vlan command
	p= strchr(nma_intf->name, ':');
	if(p == NULL)
	{
		strncpy(vlan.device1, nma_intf->name, 23);
		vlan.device1[23] = 0;
	}
	else
	{
		strncpy(vlan.device1, nma_intf->name, (p - nma_intf->name));
		//make sure null terminated
		vlan.device1[p - nma_intf->name] = '\0';
	}
	/* Get VLAN ID */
	if(ioctl(inetsocket, SIOCGIFVLAN, (char*)&vlan) < 0)
	{
		ASRT_RPT(ASOSFNFAIL, 0, "ioctl SIOCGIFVLAN name %s, errno %d\n", nma_intf->name, errno);
		nma_intf->vid = -1;
		return -1;
	}
	else
	{
		nma_intf->vid = vlan.u.VID;
	}

    return 0;
}

/* 
 * Name: ipm_close_socket
 * Descritpion: close socket and assert
 *
 */

void ipm_close_socket(int *sockfd)
{
	if (*sockfd >= 0)
	{
		if (close(*sockfd) < 0)
        	{
                        char err_buff[UMAX_LOG_SIZE];
                        snprintf(err_buff, UMAX_LOG_SIZE, 
                                 "ipm_close_socket: close failed with errno = %d", errno);
                        LOG_ERROR(NMA_OCONTEXT, "%s\n", err_buff);
		}
		*sockfd = -1;
	}
	return;
}

/*
 * Function name:
 *		ipm_get_pif
 * Description:
 *		Get Paried Interface Index from share memory
 * Parameter:
 * 		l_ifindex: Left Interface Index
 * 		r_ifindex: Right Interface Index
 *		pift: Paried interface array in share memory contain all interfaces: for example: eth0.800/eth1.801, eth0.400/eth1.401 etc
 *		pift_nb: The number of paried interfaces 
 * Return:
 *		index of LSN0/LSN1 in paried interface array
*/
int ipm_get_pif(int l_ifindex, int r_ifindex, ipm_paired_if_t *pift, int pift_nb)
{
    int pifind;
        
    if (pift == NULL)
    {
        ASRT_RPT(ASRTBADPARAM, 0, "invalid parameter\n");
        return -1;
    }
    /* before return pif index, update all inteface index firstly because some operations for example:
     * ifup/ifdown will change interface index 
     */
    (void)ipm_upd_ifindex();
 
    for (pifind = 0; pifind < pift_nb; pifind++)
    {
        if ((l_ifindex == pift[pifind].if_t[0].ifindex) && (r_ifindex == pift[pifind].if_t[1].ifindex))
        {
            return pifind;
        }
    }

    return -1;
}

int ip_ss2str(struct sockaddr_storage *ss, char *buf, int cnt)
{
    const char *p = NULL;

    memset(buf, 0, cnt);
    switch (ss->ss_family) {
    case AF_INET:
    {
        p = inet_ntop(AF_INET, &(((struct sockaddr_in *)ss)->sin_addr), buf, cnt);
        if (p == NULL)
        {
            ASRT_RPT(ASOSFNFAIL, 0, "inet_ntop v4 failed errno = %d\n", errno);
            return -1;
        }
        break;
    }
    case AF_INET6:
    {
        p = inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)ss)->sin6_addr), buf, cnt);
        if (p == NULL)
        {
            ASRT_RPT(ASOSFNFAIL, 0, "inet_ntop v6 failed errno = %d\n", errno);
            return -1;
        }
        break;
    }
    default:
    {
        ASRT_RPT(ASRTBADPARAM, 0, "invalid parameter\n"); 
        return -1;
    }
    }
    return 0;
}

int ip_sscmp(struct sockaddr_storage *src, struct sockaddr_storage *dest)
{
    if ((src == NULL) || (dest == NULL))
    {
        ASRT_RPT(ASRTBADPARAM, 0, "invalid parameter\n");
        return -1;
    }
    if (src->ss_family != dest->ss_family)
    {
        return -1;
    }
    switch (src->ss_family) {
    case AF_INET:
    {
        if (((struct sockaddr_in *)src)->sin_addr.s_addr == ((struct sockaddr_in *)dest)->sin_addr.s_addr)
        {
            return 0;
        }
        else
        {
            return -1;
        }
        break;
    }
    case AF_INET6:
    {
        if (memcmp(((struct sockaddr_in6 *)src)->sin6_addr.s6_addr, ((struct sockaddr_in6 *)dest)->sin6_addr.s6_addr, sizeof(((struct sockaddr_in6 *)dest)->sin6_addr.s6_addr) == 0))
        {
            return 0;
        }
        else
        {
            return -1;
        }
        break;
    }
    default:
    {
        ASRT_RPT(ASRTBADPARAM, 0, "invalid parameter\n");
        return -1;
    }
    }
}

void print_hex(unsigned char *p, int len)
{
    int i;
    for (i=0; i<len; i++) {
        printf("%02X", p[i]);
        if (i != len-1)
            printf(":");
    }
    printf("\n");
}

//ipm update base interface index
int ipm_upd_ifindex(void)
{
  int i, j;
  int ret = 0;

  //base interfaces
  for(i=0; i < ipm_shm_ptr->ipm_pif_nb; i++)
  {
	for(j=0; j<MAX_NB_DEV; j++)
	{
	   if (ipm_shm_ptr->ipm_pif[i].if_t[j].name[0] == '\0')
           {
               continue;
           }
	   ipm_shm_ptr->ipm_pif[i].if_t[j].ifindex =
			ipm_get_ifindex(inetsocket,
			ipm_shm_ptr->ipm_pif[i].if_t[j].name);
           if (ipm_shm_ptr->ipm_pif[i].if_t[j].ifindex < 0)
           {
               ret = -1;
           }		
	}
  }

  return ret;

} //end: ipm_chk_ifindex

void ipm_add_shm_rt(IPM_IPADDR dest, char *ifname)
{
	char *iface_ptr;
	char *save_ptr;

	if(ipm_shm_ptr->route_info_nb < 0)
	{
		ASRT_RPT(ASBAD_DATA, 0, "route_info_nb = %d\n", ipm_shm_ptr->route_info_nb);
		return;
	}
	if (ipm_shm_ptr->route_info_nb >= MAX_REMOTE_ALIAS)
	{
		ASRT_RPT(ASBAD_DATA, 0, "ipm share memory route info is full\n");
		return;
	}
	
	iface_ptr = strtok_r(ifname, ":", &save_ptr);
	if( iface_ptr != NULL )
	{
		memcpy(ipm_shm_ptr->route_info[ipm_shm_ptr->route_info_nb].ifname, iface_ptr, 
			sizeof(ipm_shm_ptr->route_info[ipm_shm_ptr->route_info_nb].ifname));
	}
	else
	{
		memcpy(ipm_shm_ptr->route_info[ipm_shm_ptr->route_info_nb].ifname, ifname, 
			sizeof(ipm_shm_ptr->route_info[ipm_shm_ptr->route_info_nb].ifname));
	}
	memcpy(&(ipm_shm_ptr->route_info[ipm_shm_ptr->route_info_nb].dest), &(dest), IPM_IPADDRSIZE);


	ipm_shm_ptr->route_info_nb++;

	return;

} //end: ipm_add_shm_rt

void ipm_removeall_shm_rt(int netlinksocket)
{
	int index;
	int ret;
	int prefix;

	for  (index = 0; index < ipm_shm_ptr->route_info_nb; index++)
	{
		if (ipm_shm_ptr->route_info[index].dest.addrtype == IPM_IPV6)
		{
			prefix = IPM_IPV6MAXMASKLEN;
		}
		else if (ipm_shm_ptr->route_info[index].dest.addrtype == IPM_IPV4)
		{
			prefix = IPM_IPV4MAXMASKLEN;
		}
		else
		{
			continue;
		}
		ret = ipm_route_del(NOPARAMETER, "", &(ipm_shm_ptr->route_info[index].dest), prefix, NULL, RT_TABLE_HOST);
	}

	memset(ipm_shm_ptr->route_info, 0, sizeof(ipm_shm_ptr->route_info));

	ipm_shm_ptr->route_info_nb = 0;

	return;

} //end: ipm_removeall_shm_rt

void ipm_delete_shm_rt(int netlinksocket, IPM_IPADDR dest, int prefix)
{
	int index;
	int location = -1;

	if(ipm_shm_ptr->route_info_nb < 0)
	{
		ASRT_RPT(ASBAD_DATA, 0, "route_info_nb = %d\n", ipm_shm_ptr->route_info_nb);
		return;
	}

	if(ipm_shm_ptr->route_info_nb == 0) 
	{
		return;
	}

	for (index = 0; index < ipm_shm_ptr->route_info_nb; index++)
	{
		if (IPM_IPCMPADDR(&(ipm_shm_ptr->route_info[index].dest), &dest) == IPM_SUCCESS)
		{
			location = index;
			break;
		}
	}

	if (location == -1)
	{
		return;
	}

	for (index = location + 1; index < ipm_shm_ptr->route_info_nb; index++)
	{
		memcpy( (void *)&(ipm_shm_ptr->route_info[index - 1]),
			(void *)&(ipm_shm_ptr->route_info[index]),
			sizeof(ipm_route_info_t));
	}
	
	memset(&(ipm_shm_ptr->route_info[ipm_shm_ptr->route_info_nb - 1]),
		0,
		sizeof(ipm_route_info_t));

	ipm_shm_ptr->route_info_nb--;

	return;

} //end: ipm_delete_shm_rt

/* dump ctx content by ipm_cli comamnd */
void ipm_dump_ctx(nma_ctx_t *ctx)
{
	char buff[UMAX_LOG_SIZE];
	station_t *station;
	int index;
	nma_ipalias_dst_t *alias;
	char *ptr = dump_buffer;
	int ret_len = 0, total = 0;
        unsigned int *ip_alias;
        unsigned short *ip_remote;
        unsigned char *bitmap_alias;
        unsigned char *bitmap_remote;
        IPM_IPADDR *ipv6_link;
        IPM_IPADDR *ip_alias_more;
        unsigned char *bitmap_alias_more;

	memset(dump_buffer, 0, sizeof(dump_buffer));
	/* dump ctx->a part */
	snprintf(dump_buffer, UMAX_LOG_SIZE, "IPM DUMPING CTX BEGIN...\n");
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);

	memset(dump_buffer, 0, sizeof(dump_buffer));
	snprintf(dump_buffer, UMAX_LOG_SIZE, "\tctx->a.inuse = %d\n\tctx->a.globalstate=%d\n\tctx->a.lsn=%d\n\tctx->a.credit_degraded=%d\n\tctx->a.isolated=%d\n\tctx->a.master=%d\n\tctx->a.nb_station_list=%d\n\tctx->a.nb_alias=%d\n\tctx->a.nb_alias_ipv6=%d\n\tctx->a.flaglog=%d\n\tctx->a.ticks=%d\n\tctx->a.more=%d\n\tctx->a.gnmindex=%d\n\tctx->a.qos=%d\n\tctx->a.shelfid=%d\n\tctx->a.gnmsession=%d\n\tctx->a.creditinframe=%d",
					ctx->a.inuse,
					ctx->a.globalstate,
					ctx->a.lsn,
					ctx->a.credit_degraded,
					ctx->a.isolated,
					ctx->a.master,
					ctx->a.nb_station_list,
					ctx->a.nb_alias,
					ctx->a.nb_alias_ipv6,
					ctx->a.flaglog,
					ctx->a.ticks,
					ctx->a.more,
					ctx->a.gnmindex,
					ctx->a.qos,
					ctx->a.shelfid,
					ctx->a.gnmsession,
					ctx->a.creditinframe);
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);

	for  (index = 0; index < MAX_NB_DEV; index++)
	{
		char linkip[IPM_IPMAXSTRSIZE];
		memset(dump_buffer, 0, sizeof(dump_buffer));
		snprintf(dump_buffer, UMAX_LOG_SIZE, "ctx->a.my[%d]: name=%s, ip=0X%x, mask=0X%0x, ipv6link = %s, ether=%s, ifindex=%d, vid=%d", 
					index, ctx->a.my[index].name, ctx->a.my[index].ip, ctx->a.my[index].mask, 
					IPM_chkipaddr2p(&(ctx->a.my[index].link_ip), linkip, IPM_IPMAXSTRSIZE), 
					ether_ntoa((struct ether_addr*)&(ctx->a.my[index].ether)), ctx->a.my[index].ifindex, ctx->a.my[index].vid);
		LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);
	}

	for (station = ctx->a.STATIONHEAD;station != NULL;station = station->next)
	{
		ret_len = 0;
		total = 0;
		ptr = dump_buffer;

		memset(dump_buffer, 0, sizeof(dump_buffer));
		memset(buff, 0, sizeof(buff));
		ret_len = snprintf(ptr, UMAX_LOG_SIZE, "station: empty=%d", station->empty);
		total = total + ret_len;
		ptr = ptr + ret_len;

		memset(buff, 0, sizeof(buff));
		IPM_FORMAT_STR(station->ip_addr, MAX_NB_DEV, buff, UMAX_LOG_SIZE);
		ret_len = snprintf(ptr, UMAX_LOG_SIZE - total, ", ip_addr=%s", buff);
		total = total + ret_len;	
		ptr = ptr + ret_len;

		for (index = 0; index < MAX_NB_DEV; index++)
		{
			char network[IPM_IPMAXSTRSIZE];

			memset(buff,0, sizeof(buff));
			ret_len = snprintf(ptr, UMAX_LOG_SIZE - total, ", link_ip%d=%s", index, IPM_chkipaddr2p(&(station->link_ip[index]), network, IPM_IPMAXSTRSIZE));
			total = total + ret_len;
			ptr = ptr + ret_len;
		}

		memset(buff, 0, sizeof(buff));
		IPM_FORMAT_STR(station->ln_credit, MAX_NB_DEV, buff, UMAX_LOG_SIZE);
		ret_len = snprintf(ptr, UMAX_LOG_SIZE - total, ", ln_credit=%s", buff);
		total = total + ret_len;	
		ptr = ptr + ret_len;

		memset(buff, 0, sizeof(buff));
		IPM_FORMAT_STR(station->ln_credit_receive, MAX_NB_DEV, buff, UMAX_LOG_SIZE);
		ret_len = snprintf(ptr, UMAX_LOG_SIZE - total, ", ln_credit_receive=%s", buff);
		total = total + ret_len;	
		ptr = ptr + ret_len;

		ret_len = snprintf(ptr, UMAX_LOG_SIZE - total, ", ln_credit_ddegfull=%d, ln_status=%d, ln_status_start=%d, ln_qos=%d, seq_remote=%d, seq_alias=%d, nb_sub=%d, total_remote=%d, full_remote=%d, degraded_timer=%d, qos_active=%d, freeze=%d, last_degraded=%d, current_delay_degfull=%d, last_delay_degfull=%d, ln_access=%d, shelf_id=%d", station->ln_credit_degfull, station->ln_status, station->ln_status_start, station->ln_qos, station->seq_remote, station->seq_alias, station->nb_sub, station->total_remote, station->full_remote, station->degraded_timer, station->qos_active, station->freeze, station->last_degraded, station->current_delay_degfull, station->last_delay_degfull, station->ln_access, station->shelf_id);
		total = total + ret_len;	
		ptr = ptr + ret_len;

		memset(buff, 0, sizeof(buff));
		IPM_FORMAT_STR(station->frame_number, MAX_NB_DEV, buff, UMAX_LOG_SIZE);
		ret_len = snprintf(ptr, UMAX_LOG_SIZE - total, ", frame_number=%s", buff);
		total = total + ret_len;	
		ptr = ptr + ret_len;

		memset(buff, 0, sizeof(buff));
		IPM_FORMAT_STR(station->ln_remote, ctx->a.nb_station_list, buff, UMAX_LOG_SIZE);
		ret_len = snprintf(ptr, UMAX_LOG_SIZE - total, ", ln_remote=%s", buff);
		total = total + ret_len;	
		ptr = ptr + ret_len;
		
		LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);
	}
	memset(dump_buffer, 0, sizeof(dump_buffer));
	/* dump ctx->b part */
	snprintf(dump_buffer, UMAX_LOG_SIZE, "ctx->ctx->b.supervision_new.ip_local=0X%x/0X%x, ctx->ctx->b.supervision_new.ether_local=%s/%s", ctx->b.supervision_new.ip_local[0], ctx->b.supervision_new.ip_local[1], ether_ntoa((struct ether_addr*)&(ctx->b.supervision_new.ether_local[0])), ether_ntoa((struct ether_addr*)&(ctx->b.supervision_new.ether_local[1].address)));
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);

	memset(dump_buffer, 0, sizeof(dump_buffer));
	snprintf(dump_buffer, UMAX_LOG_SIZE, "ctx->ctx->b.supervision_new.checksum=%d, ctx->ctx->b.supervision_new.version=%d, ctx->ctx->b.supervision_new.frame_number=%d, ctx->ctx->b.supervision_new.nb_alias=%d, ctx->ctx->b.supervision_new.nb_remote=%d, ctx->ctx->b.supervision_new.shelfid=%d, ctx->ctx->b.supervision_new.seq_alias=%d, ctx->ctx->b.supervision_new.seq_remote=%d",
		ctx->b.supervision_new.checksum, ctx->b.supervision_new.version, ctx->b.supervision_new.frame_number, ctx->b.supervision_new.nb_alias, ctx->b.supervision_new.nb_remote, ctx->b.supervision_new.shelfid, ctx->b.supervision_new.seq_alias, ctx->b.supervision_new.seq_remote);
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);
		
	GETTABLE(&(ctx->b.supervision_new),ip_remote,bitmap_remote,ip_alias,bitmap_alias,ipv6_link,ip_alias_more,bitmap_alias_more);

	memset(dump_buffer, 0, sizeof(dump_buffer));
	memset(buff, 0, sizeof(buff));
	IPM_FORMAT_STR(ip_alias, ctx->b.supervision_new.nb_alias, buff, UMAX_LOG_SIZE);
	snprintf(dump_buffer, UMAX_LOG_SIZE, "ctx->ctx->b.supervision_new.ip_alias=%s", buff);
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);
		
	memset(dump_buffer, 0, sizeof(dump_buffer));
	memset(buff, 0, sizeof(buff));
	IPM_FORMAT_STR(bitmap_alias, ctx->b.supervision_new.nb_alias, buff, UMAX_LOG_SIZE);
	snprintf(dump_buffer, UMAX_LOG_SIZE, "ctx->ctx->b.supervision_new.bitmap_alias=%s", buff);
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);

	memset(dump_buffer, 0, sizeof(dump_buffer));
	memset(buff, 0, sizeof(buff));
	IPM_FORMAT_STR(ip_remote, ctx->b.supervision_new.nb_remote, buff, UMAX_LOG_SIZE);
	snprintf(dump_buffer, UMAX_LOG_SIZE, "ctx->ctx->b.supervision_new.ip_remote=%s", buff);
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);

	memset(dump_buffer, 0, sizeof(dump_buffer));
	memset(buff, 0, sizeof(buff));
	IPM_FORMAT_STR(bitmap_remote, ctx->b.supervision_new.nb_remote, buff, UMAX_LOG_SIZE);
	snprintf(dump_buffer, UMAX_LOG_SIZE, "ctx->ctx->b.supervision_new.bitmap_remote=%s", buff);
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);

	memset(dump_buffer, 0, sizeof(dump_buffer));
	memset(buff, 0, sizeof(buff));
	IPM_FORMAT_STR(ctx->b.group_multicast.address, ETHER_ADDR_SIZE, buff, UMAX_LOG_SIZE);
	snprintf(dump_buffer, UMAX_LOG_SIZE, "ctx->b.grup_multicast=%s, ctx->b.proid=%d, ctx->b.credit=%d, ctx->b.psupervision=%d, ctx->b.min_credit_degfull=%d, ctx->b.max_credit_degfull=%d, ctx->b.cli_socket_name=%s", buff, ctx->b.proid, ctx->b.credit, ctx->b.psupervision, ctx->b.min_credit_degfull, ctx->b.max_credit_degfull, ctx->b.cli_socket_name);
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);

	memset(dump_buffer, 0, sizeof(dump_buffer));
	memset(buff, 0, sizeof(buff));
	IPM_FORMAT_STR(ctx->b.station_list, ctx->a.nb_station_list, buff, UMAX_LOG_SIZE);
	snprintf(dump_buffer, UMAX_LOG_SIZE, "ctx->b.station_list=%s", buff);
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);

		
	memset(dump_buffer, 0, sizeof(dump_buffer));
	memset(buff, 0, sizeof(buff));
	IPM_FORMAT_STR(ctx->b.station_access, ctx->a.nb_station_list, buff, UMAX_LOG_SIZE);
	snprintf(dump_buffer, UMAX_LOG_SIZE, "ctx->b.station_access=%s", buff);
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);

	memset(dump_buffer, 0, sizeof(dump_buffer));
	memset(buff, 0, sizeof(buff));
	IPM_FORMAT_STR(ctx->b.station_shelfid, ctx->a.nb_station_list, buff, UMAX_LOG_SIZE);
	snprintf(dump_buffer, UMAX_LOG_SIZE, "ctx->b.station_shelfid=%s", buff);
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);

	memset(dump_buffer, 0, sizeof(dump_buffer));
	memset(buff, 0, sizeof(buff));
	IPM_FORMAT_STR(ctx->b.station_changed, ctx->a.nb_station_list, buff, UMAX_LOG_SIZE);
	snprintf(dump_buffer, UMAX_LOG_SIZE, "ctx->b.station_changed=%s", buff);
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);

	memset(dump_buffer, 0, sizeof(dump_buffer));
	memset(buff, 0, sizeof(buff));
	IPM_FORMAT_STR(ctx->b.shelf_access, MAX_NB_SHELF, buff, UMAX_LOG_SIZE);
	snprintf(dump_buffer, UMAX_LOG_SIZE, "ctx->b.shelf_access=%s", buff);
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);

	for (index = 0; index < MAX_NB_SHELF; index++)
	{
		memset(dump_buffer, 0, sizeof(dump_buffer));
		memset(buff, 0, sizeof(buff));
		IPM_FORMAT_STR(ctx->b.lsn_access[index], MAX_NB_SHELF, buff, UMAX_LOG_SIZE);
		snprintf(dump_buffer, UMAX_LOG_SIZE, "ctx->b.lsn_access[%d]=%s", index, buff);
		LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);
	}

	for (index = 0; index < ctx->a.nb_alias; index++)
	{
		char network[IPM_IPMAXSTRSIZE];
		char netmask[IPM_IPMAXSTRSIZE];

		memset(dump_buffer, 0, sizeof(dump_buffer));
		snprintf(dump_buffer, UMAX_LOG_SIZE, "ctx->b.local_ipalias[%d]: name=%s, ip=%s, mask=%s, links=%d", 
				index, ctx->b.local_ipalias[index].name, 
				IPM_chkipaddr2p(&(ctx->b.local_ipalias[index].ip), network, IPM_IPMAXSTRSIZE), 
				IPM_chkipaddr2p(&(ctx->b.local_ipalias[index].mask), netmask, IPM_IPMAXSTRSIZE), 
				ctx->b.local_ipalias[index].links);
		LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);
	}
	
	for (alias = ctx->b.aliaspool.head;alias != NULL;alias = alias->next)
	{
		char network[IPM_IPMAXSTRSIZE];

		memset(dump_buffer, 0, sizeof(dump_buffer));
		memset(buff, 0, sizeof(buff));
		snprintf(dump_buffer, UMAX_LOG_SIZE, 
				"ctx->b.aliaspool: station=0X%x, delete=%d, inuse=%d, links=%d, failed_link=%d, alias_ip=%s, device_index=%d", 
			alias->station->ip_addr[0], alias->delete_flag, alias->inuse, alias->links, alias->failed_link, 
			IPM_chkipaddr2p(&(alias->alias_ip), network, IPM_IPMAXSTRSIZE), 
			alias->device_index);
		LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);
	}

	memset(dump_buffer, 0, sizeof(dump_buffer));
	snprintf(dump_buffer, UMAX_LOG_SIZE, "iipm_enable=%d, eipm_enable=%d", iipm_enable, eipm_enable);
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);

	memset(dump_buffer, 0, sizeof(dump_buffer));
	snprintf(dump_buffer, UMAX_LOG_SIZE, "IPM DUMPING CTX END");
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);

} //end: ipm_dump_ctx

/* dump shm content ipm_cli command */
void ipm_dump_shm()
{
	int index;
	int pindex;
	char buff[UMAX_LOG_SIZE];
	
	if (ipm_shm_ptr == NULL)
	{
		LOG_FORCE(NMA_OCONTEXT, "%s\n", "ipm_dump_shm: ipm_shm_ptr is NULL");
		return;
	}
	memset(dump_buffer, 0, sizeof(dump_buffer));
	snprintf(dump_buffer, UMAX_LOG_SIZE, "IPM DUMPING SHM BEGIN ......");
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);

	LOG_FORCE(0, "Simplex Mode: %s\n", (IS_SIMPLEX_MODE?"On":"Off"));

	for (index = 0; index < ipm_shm_ptr->ipm_pif_nb; index++)
	{
		for (pindex = 0; pindex < MAX_NB_DEV; pindex++)
		{
			char linkip[IPM_IPMAXSTRSIZE];
			memset(dump_buffer, 0, sizeof(dump_buffer));
			snprintf(dump_buffer, UMAX_LOG_SIZE, "ipm_shm_ptr->ipm_pif[%d].if_t[%d]: name=%s, ip=%d, mask=%d, ether=%s, ifindex=%d, vid=%d", 
					index, pindex, ipm_shm_ptr->ipm_pif[index].if_t[pindex].name, ipm_shm_ptr->ipm_pif[index].if_t[pindex].ip, 
					ipm_shm_ptr->ipm_pif[index].if_t[pindex].mask, 
					ether_ntoa((struct ether_addr*)&(ipm_shm_ptr->ipm_pif[index].if_t[pindex].ether)), 
					ipm_shm_ptr->ipm_pif[index].if_t[pindex].ifindex, ipm_shm_ptr->ipm_pif[index].if_t[pindex].vid);
			LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);
		}	
	}

	for (index = 0; index< MAX_NB_DEV; index++)
	{
		memset(dump_buffer, 0, sizeof(dump_buffer));
		snprintf(dump_buffer, UMAX_LOG_SIZE, "ipm_shm_ptr->lsn_ip[%d]: name=%s, ip=%s, prefix=%d,  subnet_type=%d, expedite_noification=%d",
			index ,ipm_shm_ptr->lsn_ip[index].alias_if, ipm_shm_ptr->lsn_ip[index].ip, ipm_shm_ptr->lsn_ip[index].prefix, ipm_shm_ptr->lsn_ip[index].subnet_type, ipm_shm_ptr->lsn_ip[index].expedite_notification);
		LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);
	}
	

	for (index = 0; index < ipm_shm_ptr->alias_ip_nb; index++)
	{
		char aliasip[IPM_IPMAXSTRSIZE];
		char mask[IPM_IPMAXSTRSIZE];

		memset(dump_buffer, 0, sizeof(dump_buffer));
		snprintf(dump_buffer, UMAX_LOG_SIZE, "ipm_shm_ptr->alias_ip[%d]: name=%s/%s, ip=%s, mask=%s, links=%d, subnet_type=%d, pif_index=%d",
			index, ipm_shm_ptr->alias_ip[index].name[0], ipm_shm_ptr->alias_ip[index].name[1], 
			IPM_chkipaddr2p(&(ipm_shm_ptr->alias_ip[index].ip), aliasip, IPM_IPMAXSTRSIZE), 
			IPM_chkipaddr2p(&(ipm_shm_ptr->alias_ip[index].mask), mask, IPM_IPMAXSTRSIZE), 
			ipm_shm_ptr->alias_ip[index].links, ipm_shm_ptr->alias_ip[index].subnet_type, ipm_shm_ptr->alias_ip[index].pif_index);
		LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);
	}

	for (index = 0; index < ipm_shm_ptr->route_info_nb; index++)
	{
		char route[IPM_IPMAXSTRSIZE];

		memset(dump_buffer, 0, sizeof(dump_buffer));
		snprintf(dump_buffer, UMAX_LOG_SIZE, "ipm_shm_ptr->route_info[%d]: ip=%s intf=%s", index, IPM_chkipaddr2p(&(ipm_shm_ptr->route_info[index].dest), route, IPM_IPMAXSTRSIZE), ipm_shm_ptr->route_info[index].ifname);
		LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);
	}

	memset(dump_buffer, 0, sizeof(dump_buffer));
	snprintf(dump_buffer, UMAX_LOG_SIZE, "IPM DUMPING SHM END");
	LOG_FORCE(NMA_OCONTEXT, "%s\n", dump_buffer);
} //end: ipm_dump_shm


void ipm_interface_change(unsigned char old_status,
			unsigned char new_status)
{
	static char rsc_fmt[]="Machine=%s%cResource_type=Link%cLinkId=LSN%d";
	FSALARM_SEVERITY_TYPE a_sev[2];
	char resource_str[2][FSALARM_RESOURCE_BUFFSZ];
	char user_text[FSALARM_UTEXT_BUFFSZ];
	int i;
	unsigned char cur_status;

	(void)gethostname(ipmHostName, sizeof(ipmHostName));

#ifndef _VHE
	/* File interface change timestamp to be used by WCNP redundancy schema */
	gettimeofday(&(tab_ctx[0].a.degrade_time), 0);
	tab_ctx[0].a.iipm_timer = EIPM_wcnp_set_timer(tab_ctx[0].a.degrade_time);
#endif


	cur_status = new_status;
	if ((IS_SIMPLEX_MODE) && ((cur_status == LINK_0) || (cur_status == LINK_1)))
	{
		cur_status = LINK_ALL;
	}

	switch (cur_status) {
	case LINK_ALL:
		//audit IPv6 internal IP, which is proxy_client_address IP
		EIPM_CHECK_INTF_CONFIG_PROXYCLIENTADDR();

		if(old_status == LINK_NONE)
		{
			//send two clear alarms
			for(i=0; i<2; i++)
			{
				a_sev[i] = FSAS_cleared;

				sprintf(resource_str[i], rsc_fmt,
					ipmHostName, 
					FSALARM_RESOURCE_FIELD_DELIMITER,
					FSALARM_RESOURCE_FIELD_DELIMITER,
					i);
			}
		}
		else if((old_status == LINK_0) || (old_status == LINK_1))
		{
			a_sev[0] = FSAS_cleared;

			sprintf(resource_str[0], rsc_fmt,
				ipmHostName,
				FSALARM_RESOURCE_FIELD_DELIMITER,
				FSALARM_RESOURCE_FIELD_DELIMITER,
				(old_status == LINK_0) ? 1 : 0);

			//one alarm only
			resource_str[1][0] = '\0';
		}
		else //LINK_ALL
		{
			//should never happen
			return; 
		}
		break;
	case LINK_NONE:
		if(old_status == LINK_ALL)
		{
			//send two critical alarms
			for(i=0; i<2; i++)
			{
				a_sev[i] = FSAS_critical;

				sprintf(resource_str[i], rsc_fmt,
					ipmHostName,
					FSALARM_RESOURCE_FIELD_DELIMITER,
					FSALARM_RESOURCE_FIELD_DELIMITER,
					i);
			}
		}
		else if( (old_status == LINK_0) || (old_status == LINK_1) )
		{
			a_sev[0] = FSAS_critical;

			sprintf(resource_str[0], rsc_fmt,
				ipmHostName,
				FSALARM_RESOURCE_FIELD_DELIMITER,
				FSALARM_RESOURCE_FIELD_DELIMITER,
				(old_status == LINK_0) ? 0 : 1);

			//one alarm only
			resource_str[1][0] = '\0';
		}
		else //LINK_NONE
		{
			//should never happen
			return; 
		}
		break;
	case LINK_0:
	case LINK_1:
		if(old_status == LINK_NONE)
		{
			a_sev[0] = FSAS_cleared;

			sprintf(resource_str[0], rsc_fmt,
				ipmHostName,
				FSALARM_RESOURCE_FIELD_DELIMITER,
				FSALARM_RESOURCE_FIELD_DELIMITER,
				(cur_status == LINK_0) ? 0 : 1);

			a_sev[1] = FSAS_major;

			sprintf(resource_str[1], rsc_fmt,
				ipmHostName,
				FSALARM_RESOURCE_FIELD_DELIMITER,
				FSALARM_RESOURCE_FIELD_DELIMITER,
				(cur_status == LINK_1) ? 0 : 1);

		}
		else if(old_status == LINK_ALL)
		{
			a_sev[0] = FSAS_major;

			sprintf(resource_str[0], rsc_fmt,
				ipmHostName,
				FSALARM_RESOURCE_FIELD_DELIMITER,
				FSALARM_RESOURCE_FIELD_DELIMITER,
				(cur_status == LINK_0) ? 1 : 0);

			//one alarm
			resource_str[1][0] = '\0';
		}
		else if((cur_status & old_status) == LINK_NONE)
		{
			a_sev[0] = FSAS_cleared;

			sprintf(resource_str[0], rsc_fmt,
				ipmHostName,
				FSALARM_RESOURCE_FIELD_DELIMITER,
				FSALARM_RESOURCE_FIELD_DELIMITER,
				(old_status == LINK_0) ? 1 : 0);

			a_sev[1] = FSAS_major;

			sprintf(resource_str[1], rsc_fmt,
				ipmHostName,
				FSALARM_RESOURCE_FIELD_DELIMITER,
				FSALARM_RESOURCE_FIELD_DELIMITER,
				(cur_status == LINK_0) ? 1 : 0);
				
		}
		else
		{
			//should never happen
			return; 
		}
		break;
		default:
			return;
	} //end switch

	switch(cur_status)
	{
	case LINK_ALL:
		snprintf(user_text, FSALARM_UTEXT_BUFFSZ,
			"IIPM STATUS: ONLINE");
			break;
	case LINK_0:
	case LINK_1:
		snprintf(user_text, FSALARM_UTEXT_BUFFSZ,
			"IIPM STATUS: DEGRADED - LSN%d",
			(cur_status == LINK_0) ? 1 : 0);
			break;
	case LINK_NONE:
		snprintf(user_text, FSALARM_UTEXT_BUFFSZ,
			"IIPM STATUS: OFFLINE");
			break;
	default:
		snprintf(user_text, FSALARM_UTEXT_BUFFSZ,
			"IIPM STATUS: OFFLINE - %d", cur_status);
			break;
	}

	//put alarms into table
	for(i =0 ; i <2; i++)
	{
		if(resource_str[i][0] != '\0')
		{
			ipm_alarm_t *p_a_alarm;

			p_a_alarm = (ipm_alarm_t *)malloc(sizeof(*p_a_alarm));

			if(p_a_alarm != NULL)
			{
				memset((void *)p_a_alarm, 0, sizeof(*p_a_alarm));

				//add to alarm table
				p_a_alarm->level = a_sev[i];

				strncpy(p_a_alarm->altResource,
					resource_str[i], FSALARM_RESOURCE_BUFFSZ-1);
				p_a_alarm->altResource[FSALARM_RESOURCE_BUFFSZ-1] = 0;

				strncpy(p_a_alarm->userText, user_text, FSALARM_UTEXT_BUFFSZ-1);
				p_a_alarm->userText[FSALARM_UTEXT_BUFFSZ-1] = 0;

				p_a_alarm->delay_cnt = ipm_alarm_delay;

				p_ipm_alarm[ipm_alarm_cnt] = p_a_alarm;
 
				ipm_alarm_cnt++;
			}
			else if( iipm_enable == TRUE )
			{
				/* memory allocation failed, send alarm now */
				SEND_ALARM(FSAC_ethernet,
					a_sev[i],
					FSAP_linkDown,
					FSAR_link,
					resource_str[i],
					NULL,
					user_text, 
					FSADK_UNUSED, 
					FSARK_UNUSED);
			}
		} //end resource_str check
	} //end for loop

	return; 

} 


//ipm_send_alarm()
//send alarm out from a pre-saved table
void ipm_send_alarm()
{
	int i = 0;

	while( i< ipm_alarm_cnt )
	{
		p_ipm_alarm[i]->delay_cnt--;

		if(p_ipm_alarm[i]->delay_cnt <= 0)
		{
			if( iipm_enable == TRUE )
			{
				SEND_ALARM(FSAC_ethernet,
					   p_ipm_alarm[i]->level,
					   FSAP_linkDown,
					   FSAR_link,
					   p_ipm_alarm[i]->altResource,
					   NULL,
					   p_ipm_alarm[i]->userText, 
					   FSADK_UNUSED, 
					   FSARK_UNUSED);
			}

			//free memory
			free(p_ipm_alarm[i]);
			p_ipm_alarm[i] = NULL;
			ipm_alarm_cnt--;

			//swap
			if( (ipm_alarm_cnt > 0) && (i != ipm_alarm_cnt) )
			{
				p_ipm_alarm[i] = p_ipm_alarm[ipm_alarm_cnt];
				p_ipm_alarm[ipm_alarm_cnt] = NULL;
			}
		}
		else
		{
			//step to next element
			i++;
		}

	} //end while loop

	return;

} //end ipm_send_alarm

void ipm_send_iipm_status(nma_ctx_t *ctx)
{
#ifndef _VHE
ipm_status_t ipm_status;
EIPM_STATUS iipm_interface_status;
SMCarMulti_msg multi_msg;

    multi_msg.hdr.tag = SMCarMultiMembersNotify;
    multi_msg.hdr.length = sizeof(multi_msg.msg.SMCarMultiMemNotify);
    strcpy(multi_msg.msg.SMCarMultiMemNotify.car_name, SM_CAR_INTCONN);
    multi_msg.msg.SMCarMultiMemNotify.members[0] = 0;
    multi_msg.msg.SMCarMultiMemNotify.members[1] = 1;
    multi_msg.msg.SMCarMultiMemNotify.member_end = 2;


    memset((void *)&ipm_status, 0, sizeof(ipm_status));

    strcpy(ipm_status.type, "Internal");

    strncpy(ipm_status.lsn0_baseif, ctx->a.my[0].name, MAX_NLEN_DEV-1);
    ipm_status.lsn0_baseif[MAX_NLEN_DEV-1];
    strncpy(ipm_status.lsn1_baseif, ctx->a.my[1].name, MAX_NLEN_DEV-1);
    ipm_status.lsn1_baseif[MAX_NLEN_DEV-1];

    if( iipm_enable == FALSE )
    {
        iipm_interface_status = EIPM_INHIBITED;
        multi_msg.msg.SMCarMultiMemNotify.event[0] = SM_CAR_NORM;
        multi_msg.msg.SMCarMultiMemNotify.event[1] = SM_CAR_NORM;
    }
    else
    {
        switch( ctx->a.iipm_interface_status )
        {
        case LINK_ALL:
            iipm_interface_status = EIPM_ONLINE;
            multi_msg.msg.SMCarMultiMemNotify.event[0] = SM_CAR_NORM;
            multi_msg.msg.SMCarMultiMemNotify.event[1] = SM_CAR_NORM;
            break;
	
        case LINK_0:
        case LINK_1:
            if (IS_SIMPLEX_MODE)
            {
                iipm_interface_status = EIPM_ONLINE;
                multi_msg.msg.SMCarMultiMemNotify.event[0] = SM_CAR_NORM;
                multi_msg.msg.SMCarMultiMemNotify.event[1] = SM_CAR_NORM;
            }
            else
            {
                iipm_interface_status = EIPM_DEGRADED;
            }
            break;

        case LINK_NONE:
        default:
            iipm_interface_status = EIPM_OFFLINE;
            multi_msg.msg.SMCarMultiMemNotify.event[0] = SM_CAR_OFFNORM;
            multi_msg.msg.SMCarMultiMemNotify.event[1] = SM_CAR_OFFNORM;
            break;
        }
    }

    EIPM_status2str(iipm_interface_status, ipm_status.status);

    if( iipm_interface_status == EIPM_DEGRADED )
    {
        if( ctx->a.iipm_interface_status == LINK_0 )
        {
            strcat(ipm_status.status, " LSN1");
            multi_msg.msg.SMCarMultiMemNotify.event[1] = SM_CAR_OFFNORM;
            multi_msg.msg.SMCarMultiMemNotify.event[0] = SM_CAR_NORM;
        }
        else
        {
            strcat(ipm_status.status, " LSN0");
            multi_msg.msg.SMCarMultiMemNotify.event[0] = SM_CAR_OFFNORM;
            multi_msg.msg.SMCarMultiMemNotify.event[1] = SM_CAR_NORM;
        }
    }

    ipm_send_status(&multi_msg, sizeof(multi_msg));
    return;

/*need to revisit the broadcast of the IPM specific message*/

    ipm_send_status(&ipm_status, sizeof(ipm_status));

#endif
    return;
}

void ipm_send_status( void *data_ptr, int data_size )
{
struct in_addr          mcast_intf;
struct sockaddr_in	dest_addr;
int			sockfd;
int			ret;
unsigned char		mcast_loop;

static int		set_lo_multicast = 0;

    if( set_lo_multicast == 0 )
    {
        struct ifreq ifs;

        memset((void *)&ifs, 0, sizeof(ifs));

        sockfd = socket(PF_INET, SOCK_DGRAM, 0);

        if( sockfd < 0 )
        {
            LOG_ERROR(NMA_OCONTEXT, 
                      "IPM MCAST: Failed to Open Raw Socket ret %d, errno %d - %s\n",
                       sockfd, errno, strerror(errno));

            return;
        }
        
        strncpy(ifs.ifr_name, "lo", IFNAMSIZ);

        ret = ioctl(sockfd, SIOCGIFFLAGS, (char *)&ifs);

        if( ret < 0 )
        {
            LOG_ERROR(NMA_OCONTEXT, 
                      "IPM MCAST: Failed to Get Intf Flags ret %d, errno %d - %s\n",
                       ret, errno, strerror(errno));

            close(sockfd);

            return;
        }

        ifs.ifr_flags |= IFF_MULTICAST;

        ret = ioctl(sockfd, SIOCSIFFLAGS, (char *)&ifs);

        if( ret < 0 )
        {
            LOG_ERROR(NMA_OCONTEXT, 
                      "IPM MCAST: Failed to Set Intf Flags ret %d, errno %d - %s\n",
                       ret, errno, strerror(errno));

            close(sockfd);

            return;
        }

        close(sockfd);

        set_lo_multicast = 1;
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if(sockfd < 0)
    {
        LOG_ERROR(NMA_OCONTEXT, 
                  "IPM MCAST: Failed to Open DGRAM Socket ret %d, errno %d - %s\n",
                   sockfd, errno, strerror(errno));

        return;
    }

    mcast_loop = 1;

    ret = setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_LOOP, 
                     &mcast_loop, sizeof(mcast_loop));

    if( ret < 0 )
    {
        LOG_ERROR(NMA_OCONTEXT, 
                  "IPM MCAST: Failed to Set IP_MULTICAST_LOOP ret %d, errno %d - %s\n",
                   ret, errno, strerror(errno));

        (void)close(sockfd);

        return;
    }

    memset((void *)&mcast_intf, 0, sizeof(mcast_intf));

    mcast_intf.s_addr = inet_addr("127.0.0.1");

    ret = setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF,
                     (char *)&mcast_intf, sizeof(mcast_intf));

    if( ret < 0 )
    {
        LOG_ERROR(NMA_OCONTEXT, 
                  "IPM MCAST: Failed to Set IP_MULTICAST_IF ret %d, errno %d - %s\n",
                   ret, errno, strerror(errno));

        (void)close(sockfd);

        return;
    }

    memset((void *)&dest_addr, 0, sizeof(dest_addr));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(20012); // REM_UDP_RESET_PORT + 1
    dest_addr.sin_addr.s_addr = inet_addr("224.1.1.2");

    ret = sendto(sockfd, data_ptr, data_size, 0,
                 (const struct sockaddr *)&dest_addr, sizeof(dest_addr));

    if( ret < 0 )
    {
        LOG_ERROR(NMA_OCONTEXT, 
                  "IPM MCAST: Failed to Send Status: ret %d, errno %d - %s\n",
                   ret, errno, strerror(errno));
    }

    (void)close(sockfd);

    return;
}
/**********************************************************************
 *
 * Name:	ipm_get_intf_to_nexthop()
 *
 * Abstract:	get the interface to use to reach the next hop
 *
 * Parameters:	iface0_base_ptr   	  - interface 0
 *              iface1_base_ptr		  - interface 1	
 *              nexthop_ip_ptr	  	  - next hop ip
 *              act_intf	   	  - pointer to location to store the active interface
 *
 * Returns:	IPM_FAILURE 
 *              IPM_SUCCESS 		  - active interface populated
 *
 **********************************************************************/
int ipm_get_intf_to_nexthop( char *iface0_base_ptr, char *iface1_base_ptr, IPM_IPADDR *nexthop_ip_ptr, unsigned char *act_intf )
{
	int index;
	int location = -1;

	if( act_intf == NULL)
	{
		LOG_ERROR(NMA_OCONTEXT, "ipm_get_intf_to_nexthop: NULL active interface pointer\n" );
		return IPM_FAILURE;
	}

	if (ipm_shm_ptr == NULL)
	{
		LOG_ERROR(NMA_OCONTEXT, "ipm_get_intf_to_nexthop: ipm_shm_ptr is NULL");
		return IPM_FAILURE;
	}

	if( ipm_shm_ptr->route_info_nb < 0 )
	{
		LOG_ERROR(NMA_OCONTEXT, "ipm_get_intf_to_nexthop: route_info_nb failure %d\n", ipm_shm_ptr->route_info_nb );
		return IPM_FAILURE;
	}

	*act_intf = LINK_0;

	for (index = 0; index < ipm_shm_ptr->route_info_nb; index++)
	{
		if (IPM_IPCMPADDR(&(ipm_shm_ptr->route_info[index].dest), nexthop_ip_ptr) == IPM_SUCCESS)
		{
			if( strcmp(iface1_base_ptr, ipm_shm_ptr->route_info[index].ifname) == 0 )
			{
				*act_intf = LINK_1;
				return IPM_SUCCESS;
			}
			else if( strcmp(iface0_base_ptr, ipm_shm_ptr->route_info[index].ifname) == 0 )
			{
				*act_intf = LINK_0;
				return IPM_SUCCESS;
			}
			else
			{
				LOG_FORCE(NMA_OCONTEXT, "ipm_get_intf_to_nexthop interface match failure lsn0 %s lsn1 %s route intf %s", 
					  iface0_base_ptr, iface1_base_ptr, ipm_shm_ptr->route_info[index].ifname );
				return IPM_FAILURE;
			}
		}
	}

	return IPM_SUCCESS;
}


void
ipm_get_hostname(char shelf, unsigned int ip, char *host )
{
    if( 0 )
    {
#if BYTE_ORDER == LITTLE_ENDIAN
        union ip_value {
            struct {
                unsigned char d;
                unsigned char c;
                unsigned char b;
                unsigned char a;
            } octets;

            unsigned int val;
        };
#else
        union ip_value {
            struct {
                unsigned char a;
                unsigned char b;
                unsigned char c;
                unsigned char d;
            } octets;

            unsigned int val;
        };
#endif

        union ip_value ip_buf;

        ip_buf.val = ip;

        sprintf(host, "s%02dc%02dh%01d",
                shelf,
                ((ip_buf.octets.d >> 4) & 0xf),
                (ip_buf.octets.d & 0xf));
    }
    else
    {
        strncpy(host, inet_ntoa(*(struct in_addr*)(&ip)), IPM_MAX_HOST_SIZE-1);
	host[IPM_MAX_HOST_SIZE-1] = 0;
    }

    return;
}

char *
ipm_get_named_status(unsigned char status)
{
    switch(status)
    {
    case LINK_ALL:
        return "ONLINE";

    case LINK_0:
        if (IS_SIMPLEX_MODE)
        {
            return "ONLINE";
        }
        else
        {
            return "LSN1 DEGRADED";
        }

    case LINK_1:
        if (IS_SIMPLEX_MODE)
        {
            return "ONLINE";
        }
        else
        {
            return "LSN0 DEGRADED";
        }

    case LINK_NONE:
        return "OFFLINE";

    default:
        return "UNKNOWN";
    }
}

unsigned short ipm_log_remote = FALSE;

unsigned short ipm_check_log_level = LOG_MEDIUM;
unsigned short ipm_action_log_level = LOG_MEDIUM;

unsigned short ipm_get_log_level(int error_type)
{
    switch( error_type )
    {
    case NMA_EBADCHECKSUM:
    case NMA_OROUTE:
    case NMA_SEMSGSOCKET:
    case EIPM_LOG_IPCFG:
    case EIPM_LOG_ROUTECFG:
    case EIPM_LOG_ARP:
        return ipm_action_log_level;

    case EIPM_LOG_IPCHK:
    case EIPM_LOG_ROUTECHK:
        return ipm_check_log_level;

    default:
        return LOG_NONE;
    }
}



int
ipm_get_active_side( nma_ctx_t *ctx, IPM_IPADDR *ip )
{
struct in_addr addr;
int index; 

    if( ip->addrtype != IPM_IPV4 )
    {
        return LINK_NONE;
    }

    if( IPM_ipaddr2in(ip, &addr) == IPM_FAILURE )
    {
        return LINK_NONE;
    }

    if( addr.s_addr == ctx->a.my[0].ip )
    {
        return LINK_0;
    }
    else if( addr.s_addr == ctx->a.my[1].ip )
    {
        return LINK_1;
    }

    for( index = 0; index < ctx->a.nb_alias; index++ )
    {
        if( IPM_IPCMPADDR(&(ctx->b.local_ipalias[index].ip), ip) == IPM_SUCCESS )
        {
            if( ctx->a.iipm_interface_status == LINK_ALL )
            {
                return ctx->a.iipm_preferred_side;
            }
            else
            {
                return ctx->a.iipm_interface_status;
            }
        }
    }

    return LINK_NONE;
}

IPM_RETVAL 
ipm_grat_arp_ip( nma_ctx_t *ctx, char *entry, char *resp )
{
char 		*ip_ptr;
char 		*iface_ptr;
char  		iface[MAX_NLEN_DEV];
EIPM_DATA       *data_ptr;
EIPM_INTF       *intf_ptr;
IPM_IPADDR      ip;
IPM_RETVAL      ipm_retval;
int             intf_idx;
int 		active_side;


    /* Check and format entry "[interface,]ip" into ip and optional interface */
    ip_ptr = strchr(entry, ',');

    if( ip_ptr == NULL )
    {
        iface_ptr = NULL;

        ip_ptr = entry;
    }
    else
    {
        strncpy(iface, entry, ip_ptr - entry );
        iface[ip_ptr - entry] = '\0';

        iface_ptr = &iface[0];

        ip_ptr++;
    }

    IPM_ipaddr_init(&ip);

    ipm_retval = IPM_p2ipaddr(ip_ptr, &ip);

    if( ipm_retval != IPM_SUCCESS )
    {
        char buffer[IPM_IPMAXSTRSIZE + MAX_NLEN_DEV + 1];

        strncpy(buffer, entry, IPM_IPMAXSTRSIZE + MAX_NLEN_DEV);

        snprintf(resp, REPLY_TEXT,
                 "IPM GARP IP: Failed %d to translate entry %s\n",
                  ipm_retval, 
                  buffer);

        LOG_ERROR(0, resp);

        return IPM_FAILURE;
    }


    /* Handle Managed External IPs first since IIPM stores external IPs */
    if( EIPM_shm_ptr == NULL )
    {
        snprintf(resp, REPLY_TEXT,
                 "IPM GARP IP: Shared memory null\n");

        LOG_ERROR(0, resp);

        return IPM_FAILURE;
    }

    data_ptr = (EIPM_DATA *)EIPM_shm_ptr;

    for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
         intf_idx < data_ptr->intf_cnt;
         intf_idx++, intf_ptr++ )
    {
        EIPM_SUBNET     *subnet_ptr;
        int             subnet_idx;

        for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
             subnet_idx < intf_ptr->subnet_cnt;
             subnet_idx++, subnet_ptr++ )
        {
            IPM_IPADDR      subnet_mask;
            IPM_IPADDR      subnet_base;

            if( IPM_IPCMPADDRTYPE(&subnet_ptr->subnet_base, &ip) != IPM_SUCCESS )
            {
                continue;
            }

            IPM_ipaddr_init(&subnet_mask);

            ipm_retval = IPM_ipmkmask(&subnet_mask, 
                                      subnet_ptr->subnet_base.addrtype, 
                                      subnet_ptr->prefixlen);

            if( ipm_retval != IPM_SUCCESS )
            {
                snprintf(resp, REPLY_TEXT,
                         "IPM GARP IP: Failed %d to create Mask\n",
                          ipm_retval);

                LOG_ERROR(0, resp);

                continue;
            }

            IPM_ipaddr_init(&subnet_base);

            IPM_get_subnet(&ip, &subnet_mask, &subnet_base);

            if( IPM_IPCMPADDR(&subnet_ptr->subnet_base, &subnet_base) == IPM_SUCCESS )
            {
                EIPM_SUBNET subnet_data = *subnet_ptr;

                subnet_data.ip_cnt = 1;

                subnet_data.ips[0].ipaddr = ip;

		ipm_retval = EIPM_grat_arp( intf_ptr, EIPM_BASE_INTF, subnet_data.sub2intf_mapping[0].route_priority, &subnet_data );

                LOG_DEBUG( 0,
                           "IPM GARP IP: %s on %s (%d), ret %d\n",
                            ip_ptr,
                            (subnet_data.sub2intf_mapping[0].route_priority == LSN1) ? intf_ptr->lsn1_baseif : intf_ptr->lsn0_baseif,
                            (subnet_data.sub2intf_mapping[0].route_priority == LSN1) ? intf_ptr->specData.lsn1_iface_indx : intf_ptr->specData.lsn0_iface_indx,
                            ipm_retval );

                return ipm_retval;
            }
        }
    }


    /* Handle Managed Internal IPs */
    active_side = ipm_get_active_side(ctx, &ip);

    if( active_side != LINK_NONE )
    {
        EIPM_INTF   intf_data;
        EIPM_SUBNET subnet_data;

        memset(&intf_data, 0, sizeof(intf_data));

	intf_data.specData.lsn0_iface_indx = ctx->a.my[0].ifindex;
        strncpy(intf_data.lsn0_baseif, ctx->a.my[0].name, EI_INTFNAMESIZE-1);
	intf_data.lsn0_baseif[EI_INTFNAMESIZE-1] = 0;
        strtok(intf_data.lsn0_baseif,":");
        memcpy(intf_data.lsn0_hwaddr, ctx->a.my[0].ether.address, ETH_ALEN);

	intf_data.specData.lsn0_garpsock = -1;
        intf_data.specData.lsn0_v6garpsock = -1;

	intf_data.specData.lsn1_iface_indx = ctx->a.my[1].ifindex;
        strncpy(intf_data.lsn1_baseif, ctx->a.my[1].name, EI_INTFNAMESIZE-1);
	intf_data.lsn1_baseif[EI_INTFNAMESIZE-1] = 0;
        strtok(intf_data.lsn1_baseif,":");
        memcpy(intf_data.lsn1_hwaddr, ctx->a.my[1].ether.address, ETH_ALEN);

	intf_data.specData.lsn1_garpsock = -1;
        intf_data.specData.lsn1_v6garpsock = -1;

        memset(&subnet_data, 0, sizeof(subnet_data));

        subnet_data.ip_cnt = 1;
        subnet_data.ips[0].ipaddr = ip;

        switch( active_side )
        {
        case LINK_1:
            subnet_data.sub2intf_mapping[0].route_priority = LSN1;
            break;

        default:
            subnet_data.sub2intf_mapping[0].route_priority = LSN0;
            break;
        }

	ipm_retval = EIPM_grat_arp( &intf_data, EIPM_BASE_INTF, subnet_data.sub2intf_mapping[0].route_priority, &subnet_data );

        LOG_DEBUG( 0,
                   "IPM GARP IP: %s on %s (%d), ret %d\n",
                    ip_ptr,
                    (subnet_data.sub2intf_mapping[0].route_priority == LSN1) ? intf_data.lsn1_baseif : intf_data.lsn0_baseif,
                    (subnet_data.sub2intf_mapping[0].route_priority == LSN1) ? intf_data.specData.lsn1_iface_indx : intf_data.specData.lsn0_iface_indx,
                    ipm_retval );

	if( intf_data.specData.lsn0_garpsock >= 0 )
        {
                (void)close( intf_data.specData.lsn0_garpsock );
        }

        if( intf_data.specData.lsn0_v6garpsock >= 0 )
        {
                (void)close( intf_data.specData.lsn0_v6garpsock );
        }

        if( intf_data.specData.lsn1_garpsock >= 0 )
        {
                (void)close( intf_data.specData.lsn1_garpsock );
        }

        if( intf_data.specData.lsn1_v6garpsock >= 0 )
        {
                (void)close( intf_data.specData.lsn1_v6garpsock );
        }

        return ipm_retval;
    }


    /* Handle Unmanaged IP */

    EIPM_INTF   u_intf_data;
    EIPM_SUBNET u_subnet_data;
    IPM_RETVAL ipm_retval_1, ipm_retval_2;

    ipm_retval = IPM_SUCCESS;
    ipm_retval_1 = IPM_SUCCESS;
    ipm_retval_2 = IPM_SUCCESS;

    // populate subnet_data
    memset(&u_subnet_data, 0, sizeof(u_subnet_data));

    u_subnet_data.ip_cnt = 1;
    u_subnet_data.ips[0].ipaddr = ip;

    // populate INTF data
    memset(&u_intf_data, 0, sizeof(u_intf_data));
    u_intf_data.specData.lsn0_garpsock = -1;
    u_intf_data.specData.lsn0_v6garpsock = -1;
    u_intf_data.specData.lsn0_iface_indx = -1;
    u_intf_data.specData.lsn1_garpsock = -1;
    u_intf_data.specData.lsn1_v6garpsock = -1;
    u_intf_data.specData.lsn1_iface_indx = -1;

    if ( ipm_lookup_intf (&u_intf_data, &u_subnet_data ) == IPM_FAILURE )
    {
         LOG_ERROR( 0, "ipm_lookup_intf() failed - IP %s\n",
                        ip_ptr );

         return IPM_FAILURE;
    }

    if ( u_intf_data.specData.lsn0_iface_indx != -1 )
    {
	ipm_retval_1 = EIPM_grat_arp( &u_intf_data, EIPM_BASE_INTF, LSN0, &u_subnet_data );
    }

    if ( u_intf_data.specData.lsn1_iface_indx != -1 )
    {
	ipm_retval_2 = EIPM_grat_arp( &u_intf_data, EIPM_BASE_INTF, LSN1, &u_subnet_data );
    }

    if ( ipm_retval_1 != IPM_SUCCESS || ipm_retval_2 != IPM_SUCCESS )
        ipm_retval = IPM_FAILURE;

    LOG_DEBUG( 0,
              "IPM GARP IP: %s, ret %d\n",
              ip_ptr,
              ipm_retval );

    if( u_intf_data.specData.lsn0_garpsock >= 0 )
    {
        (void)close( u_intf_data.specData.lsn0_garpsock );
    }

    if( u_intf_data.specData.lsn0_v6garpsock >= 0 )
    {
        (void)close( u_intf_data.specData.lsn0_v6garpsock );
    }

    if( u_intf_data.specData.lsn1_garpsock >= 0 )
    {
        (void)close( u_intf_data.specData.lsn1_garpsock );
    }

    if( u_intf_data.specData.lsn1_v6garpsock >= 0 )
    {
        (void)close( u_intf_data.specData.lsn1_v6garpsock );
    }

    return ipm_retval;


}

int
ipm_get_externalCount( char *iface, char *rsp_stats )
{
EIPM_DATA       *data_ptr;
EIPM_INTF       *intf_ptr;
int             intf_idx;
int             len;
char            *iface_base_ptr;
char            iface_base[MAX_NLEN_DEV];
EIPM_INTF_SPEC  *intfSpecDataP;
BOOL            bAggrStats;
int             extnIntfIdx;
char            lsn0_intfName[MAX_NLEN_DEV];
char            lsn1_intfName[MAX_NLEN_DEV];
char		*lsn0_baseif;
char		*lsn1_baseif;
unsigned long long lsn0_corrupt_packet_count;
unsigned long long lsn1_corrupt_packet_count;
unsigned long long lsn0_sequence_error_count;
unsigned long long lsn1_sequence_error_count;

    if( EIPM_shm_ptr == NULL )
    {
        return -1;
    }

    strncpy(iface_base, iface, MAX_NLEN_DEV);

    iface_base_ptr = strtok(iface_base, ":");

    if( iface_base_ptr == NULL )
    {
        iface_base_ptr = iface_base;
    }

    len = strlen(rsp_stats);

    data_ptr = (EIPM_DATA *)EIPM_shm_ptr;

    /* Update the external counts with the BFD internal
     * counts and clear those internal counts.
     */
    (void)EIPM_bfd_get_stats();

    bAggrStats = (    ( 0 == strcmp( iface_base_ptr, "all" ) )
                   || ( 0 == strcmp( iface_base_ptr, "external" ) ) ) ? TRUE : FALSE;

    for ( ( intf_idx = 0, intf_ptr = &(data_ptr->intf_data[0]) );
          ( intf_idx < data_ptr->intf_cnt );
          ( intf_idx++, intf_ptr++ ) )
    {

        if (    ( intf_ptr->specData.monitor != EIPM_MONITOR_SNDPKT ) 
	     && (intf_ptr->specData.monitor != EIPM_MONITOR_BFD ) )
        {
            continue;
        }

        lsn0_corrupt_packet_count = 0;
        lsn0_sequence_error_count = 0;
        lsn1_corrupt_packet_count = 0;
        lsn1_sequence_error_count = 0;

	if (intf_ptr->lsn0_baseif[0] == 0)
	{
		lsn0_baseif = "empty";
	}
	else
	{
		lsn0_baseif = intf_ptr->lsn0_baseif;
	}

	if (intf_ptr->lsn1_baseif[0] == 0)
	{
		lsn1_baseif = "empty";
	}
	else
	{
		lsn1_baseif = intf_ptr->lsn1_baseif;

		/*
		 * If this is a BFD left transport interface, include only the 
		 * left interface name and not the right interface name.
		 * The BFD right transport will be included separately on its 
		 * own interface.
		 */
	     	if ((intf_ptr->specData.monitor == EIPM_MONITOR_BFD) &&
		     (intf_ptr->lsn0_baseif[0] != 0))
		{
			lsn1_baseif = "empty";	
		}
	}

        if ( TRUE == bAggrStats )
        {

            /* 
             *  Add the relevant counts for the base interface and 
             *  corresponding extension interfaces.
             */

	    /* NOTE: Get the values from intf_ptr->specData */
            lsn0_corrupt_packet_count = intf_ptr->specData.lsn0_corrupt_packet_count;
            lsn0_sequence_error_count = intf_ptr->specData.lsn0_sequence_error_count;
            lsn1_corrupt_packet_count = intf_ptr->specData.lsn1_corrupt_packet_count;
            lsn1_sequence_error_count = intf_ptr->specData.lsn1_sequence_error_count;

            if ( intf_ptr->extnIntfIdx != -1 )
            {

                for ( ( extnIntfIdx = 0, intfSpecDataP = &(data_ptr->extnIntfData[0]) );
                      ( extnIntfIdx < data_ptr->extnIntfCount );
                      ( extnIntfIdx++, intfSpecDataP++ ) )
                {
                    
                    if (    ( intfSpecDataP->baseIntfIdx != intf_idx ) 
                         || ( intfSpecDataP->monitor != EIPM_MONITOR_SNDPKT ) )
                    {
                        continue;
                    }

                    lsn0_corrupt_packet_count += intfSpecDataP->lsn0_corrupt_packet_count;
                    lsn0_sequence_error_count += intfSpecDataP->lsn0_sequence_error_count;
                    lsn1_corrupt_packet_count += intfSpecDataP->lsn1_corrupt_packet_count;
                    lsn1_sequence_error_count += intfSpecDataP->lsn1_sequence_error_count;

                }

            }

            len += snprintf( ( rsp_stats + len ), ( REPLY_TEXT - len ),
                             "%s crc:%llu seq:%llu %s crc:%llu seq:%llu\n",
                             lsn0_baseif,
                             lsn0_corrupt_packet_count,
                             lsn0_sequence_error_count,
                             lsn1_baseif,
                             lsn1_corrupt_packet_count,
                             lsn1_sequence_error_count );

        } /* end 'collect aggregate counts' */
        else
        {

            if (    ( 0 == strcmp( iface_base_ptr, lsn0_baseif ) ) 
                 || ( 0 == strcmp( iface_base_ptr, lsn1_baseif ) ) )
            {

	        /* NOTE: Get the values from intf_ptr->specData */
                lsn0_corrupt_packet_count = intf_ptr->specData.lsn0_corrupt_packet_count;
                lsn0_sequence_error_count = intf_ptr->specData.lsn0_sequence_error_count;
                lsn1_corrupt_packet_count = intf_ptr->specData.lsn1_corrupt_packet_count;
                lsn1_sequence_error_count = intf_ptr->specData.lsn1_sequence_error_count;

                len += snprintf( ( rsp_stats + len ), ( REPLY_TEXT - len ),
                                 "%s crc:%llu seq:%llu %s crc:%llu seq:%llu\n",
				lsn0_baseif,
				lsn0_corrupt_packet_count,
				lsn0_sequence_error_count,
				lsn1_baseif,
				lsn1_corrupt_packet_count,
				lsn1_sequence_error_count );
                break;
            }
            else
            {

                if ( intf_ptr->extnIntfIdx != -1 )
                {

                    for ( ( extnIntfIdx = 0, intfSpecDataP = &(data_ptr->extnIntfData[0]) );
                          ( extnIntfIdx < data_ptr->extnIntfCount );
                          ( extnIntfIdx++, intfSpecDataP++ ) )
                    {
                    
                        if ( intfSpecDataP->baseIntfIdx != intf_idx )
                        {
                            continue;
                        }

			/* NOTE: Get the values from *intfSpecDataP
			 * rather than intf_ptr->specData
			 */
			lsn0_corrupt_packet_count = intfSpecDataP->lsn0_corrupt_packet_count;
			lsn0_sequence_error_count = intfSpecDataP->lsn0_sequence_error_count;
			lsn1_corrupt_packet_count = intfSpecDataP->lsn1_corrupt_packet_count;
			lsn1_sequence_error_count = intfSpecDataP->lsn1_sequence_error_count;

                        snprintf( lsn0_intfName, sizeof( lsn0_intfName ),
                                  "%s%s", 
                                  lsn0_baseif,
                                  ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
                        snprintf( lsn1_intfName, sizeof( lsn1_intfName ),
                                  "%s%s", 
                                  lsn1_baseif,
                                  ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );

                        if (    ( 0 == strcmp( iface_base_ptr, lsn0_intfName ) ) 
                             || ( 0 == strcmp( iface_base_ptr, lsn1_intfName ) ) )
                        {
                            len += snprintf( ( rsp_stats + len ), ( REPLY_TEXT - len ),
                                             "%s crc:%llu seq:%llu %s crc:%llu seq:%llu\n",
                                             lsn0_intfName,
					     lsn0_corrupt_packet_count,
					     lsn0_sequence_error_count,
                                             lsn1_intfName,
					     lsn1_corrupt_packet_count,
					     lsn1_sequence_error_count );

                            intf_idx = data_ptr->intf_cnt;
                            break;
                        }

                    } /* end 'extension intfs loop' */

                }

            } /* end 'search in extension interfaces for specific match' */

        } /* end 'collect specific interface counts' */

    } /* end 'base interfaces loop' */

    return 0;
}


int
ipm_get_internalCount(  nma_ctx_t *ctx, char *iface, char *rsp_stats )
{
int             len;
int             index;
int             error;
int             total_seq;
char            *iface_base_ptr;
char            iface_base[MAX_NLEN_DEV];
char            *lsn0_base_ptr;
char            lsn0_base[MAX_NLEN_DEV];
char            *lsn1_base_ptr;
char            lsn1_base[MAX_NLEN_DEV];
char            iface_name[MAX_NLEN_DEV];
station_t       *station;


   len = strlen(rsp_stats);

    strncpy(lsn0_base, ctx->a.my[0].name, MAX_NLEN_DEV);

    lsn0_base_ptr = strtok(lsn0_base, ":");

    if( lsn0_base_ptr == NULL )
    {
        lsn0_base_ptr = lsn0_base;
    }

    strncpy(lsn1_base, ctx->a.my[1].name, MAX_NLEN_DEV);

    lsn1_base_ptr = strtok(lsn1_base, ":");

    if( lsn1_base_ptr == NULL )
    {
        lsn1_base_ptr = lsn1_base;
    }

    strncpy(iface_base, iface, MAX_NLEN_DEV);

    iface_base_ptr = strtok(iface_base, ":");

    if( iface_base_ptr == NULL )
    {
        iface_base_ptr = iface_base;
    }

    if( strcmp(iface,"all") == 0 ||
        strcmp(iface,"internal") == 0 ||
        strcmp(lsn0_base_ptr, iface_base_ptr) == 0 ||
        strcmp(lsn1_base_ptr, iface_base_ptr) == 0 )
    {

        for  (index = 0; index < MAX_NB_DEV; index++)
        {
		if (ctx->a.my[index].name[0] == '\0')
		{
			continue;
		}
               total_seq = 0;
               strncpy( iface_name, ctx->a.my[index].name, MAX_NLEN_DEV-1);
	       iface_name[MAX_NLEN_DEV-1] = 0;
               for (station = ctx->a.STATIONHEAD;station != NULL;station = station->next)

               {
                   total_seq += station->frame_number_error_count[index];
               }

               len += snprintf( rsp_stats + len, REPLY_TEXT- len ,
                            "%s crc:%d seq:%d ",
                             strtok(iface_name,  ":"),
                             ctx->a.my[index].checksum_error_count,
                             total_seq);

        }
        len += snprintf( rsp_stats + len, REPLY_TEXT- len, "\n");
    }



     return 0;

}

int
ipm_clr_externalCount( char *iface, char *count )
{
EIPM_DATA       *data_ptr;
EIPM_INTF       *intf_ptr;
int             intf_idx;
char            *iface_base_ptr;
char            iface_base[MAX_NLEN_DEV];
EIPM_INTF_SPEC  *intfSpecDataP;
int             extnIntfIdx;
BOOL            bClrAllStats;
BOOL            bClrCRCStat;
BOOL            bClrSEQStat;
BOOL            bClrLSN0Stats = FALSE;
BOOL            bClrLSN1Stats = FALSE;
char            lsn0_intfName[MAX_NLEN_DEV];
char            lsn1_intfName[MAX_NLEN_DEV];


    if( EIPM_shm_ptr == NULL )
    {
        return -1;
    }

    strncpy(iface_base, iface, MAX_NLEN_DEV);

    iface_base_ptr = strtok(iface_base, ":");

    if( iface_base_ptr == NULL )
    {
        iface_base_ptr = iface_base;
    }

    // Loop through shared segment
    data_ptr = (EIPM_DATA *)EIPM_shm_ptr;

    /* Update the external counts with the BFD internal
     * counts and clear those internal counts.
     */
    (void)EIPM_bfd_get_stats();

    if (    ( 0 == strcmp( iface_base_ptr, "all" ) )
         || ( 0 == strcmp( iface_base_ptr, "external" ) ) )
    {
        bClrAllStats = TRUE;
    }
    else
    {
        bClrAllStats = FALSE;

        if ( 0 == strcmp( iface_base_ptr, "lsn0" ) )
        {
            bClrLSN0Stats = TRUE;
        }
        else if ( 0 == strcmp( iface_base_ptr, "lsn1" ) )
        {
            bClrLSN1Stats = TRUE;
        }
        
    }    
    
    if ( 0 == strcmp( count, "all" ) )
    {
        bClrCRCStat = TRUE;
        bClrSEQStat = TRUE;
    }
    else
    {
        bClrCRCStat = ( 0 == strcmp( count, "crc" ) ) ? TRUE : FALSE;
        bClrSEQStat = ( 0 == strcmp( count, "seq" ) ) ? TRUE : FALSE;
    }

    
    for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
         intf_idx < data_ptr->intf_cnt;
         intf_idx++, intf_ptr++ )
    {

        if (    ( TRUE == bClrAllStats ) 
             || ( TRUE == bClrLSN1Stats ) 
             || ( TRUE == bClrLSN0Stats ) )
        {

            if ( TRUE == bClrCRCStat )
            {
                if ( TRUE == bClrLSN0Stats )
                {
                    intf_ptr->specData.lsn0_corrupt_packet_count = 0;
                }
                else if ( TRUE == bClrLSN1Stats )
                {
                    intf_ptr->specData.lsn1_corrupt_packet_count = 0;
                }
                else
                {
                    intf_ptr->specData.lsn0_corrupt_packet_count = 0;
                    intf_ptr->specData.lsn1_corrupt_packet_count = 0;
                }
            }

            if ( TRUE == bClrSEQStat )
            {
                if ( TRUE == bClrLSN0Stats )
                {
                    intf_ptr->specData.lsn0_sequence_error_count = 0;
                }
                else if ( TRUE == bClrLSN1Stats )
                {
                    intf_ptr->specData.lsn1_sequence_error_count = 0;
                }
                else
                {
                    intf_ptr->specData.lsn0_sequence_error_count = 0;
                    intf_ptr->specData.lsn1_sequence_error_count = 0;
                }
            }

            /* Clear the counts for the extension interfaces also. */
            if ( intf_ptr->extnIntfIdx != -1 )
            {

                for ( ( extnIntfIdx = 0, intfSpecDataP = &(data_ptr->extnIntfData[0]) );
                      ( extnIntfIdx < data_ptr->extnIntfCount);
                      ( extnIntfIdx++, intfSpecDataP++ ) )
                {

                    if ( intfSpecDataP->baseIntfIdx != intf_idx )
                    {
                        continue;
                    }

                    if ( TRUE == bClrCRCStat )
                    {
                        if ( TRUE == bClrLSN0Stats )
                        {
                            intfSpecDataP->lsn0_corrupt_packet_count = 0;
                        }
                        else if ( TRUE == bClrLSN1Stats )
                        {
                            intfSpecDataP->lsn1_corrupt_packet_count = 0;
                        }
                        else
                        {
                            intfSpecDataP->lsn0_corrupt_packet_count = 0;
                            intfSpecDataP->lsn1_corrupt_packet_count = 0;
                        }
                    }

                    if ( TRUE == bClrSEQStat )
                    {
                        if ( TRUE == bClrLSN0Stats )
                        {
                            intfSpecDataP->lsn0_sequence_error_count = 0;
                        }
                        else if ( TRUE == bClrLSN1Stats )
                        {
                            intfSpecDataP->lsn1_sequence_error_count = 0;
                        }
                        else
                        {
                            intfSpecDataP->lsn0_sequence_error_count = 0;
                            intfSpecDataP->lsn1_sequence_error_count = 0;
                        }
                    }

                } /* end 'extension interfaces loop' */

            } /* end 'valid extension intf idx' */            

        } /* end 'clear all/lsn0/lsn1/external stats' */
        else
        {

            /* Find specific interface to clear counts for. */
            if ( 0 == strcmp( iface_base_ptr, intf_ptr->lsn0_baseif ) )
            {
                if ( TRUE == bClrCRCStat )
                {                
                    intf_ptr->specData.lsn0_corrupt_packet_count = 0;                
                }

                if ( TRUE == bClrSEQStat )
                {                
                    intf_ptr->specData.lsn0_sequence_error_count = 0;                
                }
                break;
            }
            else if ( 0 == strcmp( iface_base_ptr, intf_ptr->lsn1_baseif ) )
            {
                if ( TRUE == bClrCRCStat )
                {                
                    intf_ptr->specData.lsn1_corrupt_packet_count = 0;                
                }

                if ( TRUE == bClrSEQStat )
                {                
                    intf_ptr->specData.lsn1_sequence_error_count = 0;                
                }
                break;
            }
            else
            {
                /* Search in the extension interfaces. */
                if ( intf_ptr->extnIntfIdx != -1 )
                {

                    for ( ( extnIntfIdx = 0, intfSpecDataP = &(data_ptr->extnIntfData[0]) );
                          ( extnIntfIdx < data_ptr->extnIntfCount );
                          ( extnIntfIdx++, intfSpecDataP++ ) )
                    {
                    
                        if ( intfSpecDataP->baseIntfIdx != intf_idx )
                        {
                            continue;
                        }

                        snprintf( lsn0_intfName, sizeof( lsn0_intfName ),
                                  "%s%s", 
                                  intf_ptr->lsn0_baseif,
                                  ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
                        snprintf( lsn1_intfName, sizeof( lsn1_intfName ),
                                  "%s%s", 
                                  intf_ptr->lsn1_baseif,
                                  ipm_getVLANStr( intfSpecDataP->vlanId, TRUE ) );
                        
                        if ( 0 == strcmp( iface_base_ptr, lsn0_intfName ) )
                        {
                            if ( TRUE == bClrCRCStat )
                            {                
                                intfSpecDataP->lsn0_corrupt_packet_count = 0;                
                            }

                            if ( TRUE == bClrSEQStat )
                            {                
                                intfSpecDataP->lsn0_sequence_error_count = 0;                
                            }

                            intf_idx = data_ptr->intf_cnt;
                            break;
                        }
                        else if ( 0 == strcmp( iface_base_ptr, lsn1_intfName ) )
                        {
                            if ( TRUE == bClrCRCStat )
                            {                
                                intfSpecDataP->lsn1_corrupt_packet_count = 0;                
                            }

                            if ( TRUE == bClrSEQStat )
                            {                
                                intfSpecDataP->lsn1_sequence_error_count = 0;                
                            }

                            intf_idx = data_ptr->intf_cnt;
                            break;
                        }

                    } /* end 'extension intfs loop' */

                } /* end 'valid extension intf idx' */

            } /* end 'search extension interfaces' */

        } /* end 'clear count for specific intf' */

    } /* end 'base interfaces loop' */

    return 0;
}

int
ipm_clr_internalCount( nma_ctx_t *ctx, char *iface, char *count )
{
int             index;
char            *iface_base_ptr;
char            iface_base[MAX_NLEN_DEV];
char            *lsn0_base_ptr;
char            lsn0_base[MAX_NLEN_DEV];
char            *lsn1_base_ptr;
char            lsn1_base[MAX_NLEN_DEV];
char            iface_name[MAX_NLEN_DEV];
station_t       *station;


    strncpy(lsn0_base, ctx->a.my[0].name, MAX_NLEN_DEV);

    lsn0_base_ptr = strtok(lsn0_base, ":");

    if( lsn0_base_ptr == NULL )
    {
        lsn0_base_ptr = lsn0_base;
    }

    strncpy(lsn1_base, ctx->a.my[1].name, MAX_NLEN_DEV);

    lsn1_base_ptr = strtok(lsn1_base, ":");

    if( lsn1_base_ptr == NULL )
    {
        lsn1_base_ptr = lsn1_base;
    }

    strncpy(iface_base, iface, MAX_NLEN_DEV);

    iface_base_ptr = strtok(iface_base, ":");

    if( iface_base_ptr == NULL )
    {
        iface_base_ptr = iface_base;
    }

    if( strcmp(iface, "all") == 0 ||
        strcmp(iface, "lsn0") == 0 ||
        strcmp(iface, "internal") == 0 ||
        strcmp(lsn0_base_ptr, iface_base_ptr) == 0 )
    {
        if( strcmp(count,"all") == 0 ||
            strcmp(count, "crc") == 0 )
        {
            ctx->a.my[0].checksum_error_count = 0;
        }

        if( strcmp(count,"all") == 0 ||
            strcmp(count, "seq") == 0 )
        {
            for(station = ctx->a.STATIONHEAD;station != NULL;station = station->next)
            {
                station->frame_number_error_count[0] = 0;
            }
        }
    }

    if( strcmp(iface, "all") == 0 ||
        strcmp(iface, "lsn1") == 0 ||
        strcmp(iface, "internal") == 0 ||
        strcmp(lsn1_base_ptr, iface_base_ptr) == 0 )
    {
        if( strcmp(count,"all") == 0 ||
            strcmp(count, "crc") == 0 )
        {
            ctx->a.my[1].checksum_error_count = 0;
        }

        if( strcmp(count,"all") == 0 ||
            strcmp(count, "seq") == 0 )
        {
            for(station = ctx->a.STATIONHEAD;station != NULL;station = station->next)
            {
                station->frame_number_error_count[1] = 0;
            }
        }
    }

    return 0;
}


int
ipm_set_externalCount( char *iface, char *count, int value )
{
EIPM_DATA       *data_ptr;
EIPM_INTF       *intf_ptr;
int             intf_idx;
char            *iface_base_ptr;
char            iface_base[MAX_NLEN_DEV];


    if( EIPM_shm_ptr == NULL )
    {
        return -1;
    }

    strncpy(iface_base, iface, MAX_NLEN_DEV);

    iface_base_ptr = strtok(iface_base, ":");

    if( iface_base_ptr == NULL )
    {
        iface_base_ptr = iface_base;
    }

    // Loop through shared segment
    data_ptr = (EIPM_DATA *)EIPM_shm_ptr;

    for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
         intf_idx < data_ptr->intf_cnt;
         intf_idx++, intf_ptr++ )
    {
	if (intf_ptr->specData.monitor == EIPM_MONITOR_BFD )
	{
	    /* Update the external counts with the BFD internal
	     * counts and clear those internal counts.
	     */
   	    (void)EIPM_bfd_get_stats_intf(intf_ptr);
	}

	if ((strcmp(iface,"all") == 0 ||
            strcmp(iface,"lsn0") == 0 ||
            strcmp(iface,"external") == 0 ||
            strcmp(iface_base_ptr, intf_ptr->lsn0_baseif) == 0 )) 
        {
            if( strcmp(count,"all") == 0 ||
                strcmp(count, "crc") == 0 )
            {
	       intf_ptr->specData.lsn0_corrupt_packet_count += value;
            }

            if( strcmp(count,"all") == 0 ||
                strcmp(count, "seq") == 0 )
            {
	       intf_ptr->specData.lsn0_sequence_error_count += value;
            }
        }

	if(( strcmp(iface,"all") == 0 ||
            strcmp(iface,"lsn1") == 0 ||
            strcmp(iface,"external") == 0 ||
            strcmp(iface_base_ptr, intf_ptr->lsn1_baseif) == 0 )) 
        {
            if( strcmp(count,"all") == 0 ||
                strcmp(count, "crc") == 0 )
            {
	       intf_ptr->specData.lsn1_corrupt_packet_count += value;
            }

            if( strcmp(count,"all") == 0 ||
                strcmp(count, "seq") == 0 )
            {
	       intf_ptr->specData.lsn1_sequence_error_count += value;
            }
        }
    }

    return 0;
}

int
ipm_set_internalCount( nma_ctx_t *ctx, char *iface, char *count, int value )
{
int             index;
char            *iface_base_ptr;
char            iface_base[MAX_NLEN_DEV];
char            *lsn0_base_ptr;
char            lsn0_base[MAX_NLEN_DEV];
char            *lsn1_base_ptr;
char            lsn1_base[MAX_NLEN_DEV];
char            iface_name[MAX_NLEN_DEV];
station_t       *station;



    strncpy(lsn0_base, ctx->a.my[0].name, MAX_NLEN_DEV);

    lsn0_base_ptr = strtok(lsn0_base, ":");

    if( lsn0_base_ptr == NULL )
    {
        lsn0_base_ptr = lsn0_base;
    }

    strncpy(lsn1_base, ctx->a.my[1].name, MAX_NLEN_DEV);

    lsn1_base_ptr = strtok(lsn1_base, ":");

    if( lsn1_base_ptr == NULL )
    {
        lsn1_base_ptr = lsn1_base;
    }

    strncpy(iface_base, iface, MAX_NLEN_DEV);

    iface_base_ptr = strtok(iface_base, ":");

    if( iface_base_ptr == NULL )
    {
        iface_base_ptr = iface_base;
    }

    if( strcmp(iface, "all") == 0 ||
        strcmp(iface, "lsn0") == 0 ||
        strcmp(iface, "internal") == 0 ||
        strcmp(lsn0_base_ptr, iface_base_ptr) == 0 )
    {
        if( strcmp(count,"all") == 0 ||
            strcmp(count, "crc") == 0 )
        {
            ctx->a.my[0].checksum_error_count += value;
        }

        if( strcmp(count,"all") == 0 ||
            strcmp(count, "seq") == 0 )
        {
            for(station = ctx->a.STATIONHEAD;station != NULL;station = station->next)
            {
                station->frame_number_error_count[0] += value;
            }
        }
    }

    if( strcmp(iface, "all") == 0 ||
        strcmp(iface, "lsn1") == 0 ||
        strcmp(iface, "internal") == 0 ||
        strcmp(lsn1_base_ptr, iface_base_ptr) == 0 )
    {
        if( strcmp(count,"all") == 0 ||
            strcmp(count, "crc") == 0 )
        {
            ctx->a.my[1].checksum_error_count += value;
        }

        if( strcmp(count,"all") == 0 ||
            strcmp(count, "seq") == 0 )
        {
            for(station = ctx->a.STATIONHEAD;station != NULL;station = station->next)
            {
                station->frame_number_error_count[1] += value;
            }
        }
    }

    return 0;
}


int 
ipm_get_side( nma_ctx_t *ctx, char *iface, char *active_iface )
{
EIPM_DATA       *data_ptr;
EIPM_INTF       *intf_ptr;
int             intf_idx;
int             ret;
char            *iface_base_ptr;
char            iface_base[MAX_NLEN_DEV];
char            *lsn0_base_ptr;
char            lsn0_base[MAX_NLEN_DEV];
char            *lsn1_base_ptr;
char            lsn1_base[MAX_NLEN_DEV];

    strncpy(lsn0_base, ctx->a.my[0].name, MAX_NLEN_DEV);

    lsn0_base_ptr = strtok(lsn0_base, ":");

    if( lsn0_base_ptr == NULL )
    {
        lsn0_base_ptr = lsn0_base;
    }

    strncpy(lsn1_base, ctx->a.my[1].name, MAX_NLEN_DEV);

    lsn1_base_ptr = strtok(lsn1_base, ":");

    if( lsn1_base_ptr == NULL )
    {
        lsn1_base_ptr = lsn1_base;
    }

    strncpy(iface_base, iface, MAX_NLEN_DEV);

    iface_base_ptr = strtok(iface_base, ":");

    if( iface_base_ptr == NULL )
    {
        iface_base_ptr = iface_base;
    }

    strcpy(active_iface, " ");
    ret = -1;

    if( strcmp(iface, "all") == 0 ||
        strcmp(iface, "internal") == 0 ||
        strcmp(iface_base_ptr, lsn0_base_ptr) == 0 ||
        strcmp(iface_base_ptr, lsn1_base_ptr) == 0 )
    {
        switch( ctx->a.iipm_interface_status )
        {
        case LINK_ALL:
            if( ctx->a.iipm_preferred_side == LINK_1 )
            {
                strcat(active_iface, lsn1_base_ptr);
                strcat(active_iface, " ");
                ret = 0;
            }
            else
            {
                strcat(active_iface, lsn0_base_ptr);
                strcat(active_iface, " ");
                ret = 0;
            }
            break;

        case LINK_1:
            strcat(active_iface, lsn1_base_ptr);
            strcat(active_iface, " ");
            ret = 0;
            break;

        default:
            strcat(active_iface, lsn0_base_ptr);
            strcat(active_iface, " ");
            ret = 0;
            break;
        }

        if( strcmp(iface, "all") != 0 )
        {
            return ret;
        }
    }

    if( EIPM_shm_ptr == NULL )
    {
        if( ret != 0 )
        {
            strcpy(active_iface, "Unknown - No Interface Match");
        }

        return ret;
    }

    data_ptr = (EIPM_DATA *)EIPM_shm_ptr;

    for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
         intf_idx < data_ptr->intf_cnt;
         intf_idx++, intf_ptr++ )
    {
	if ( (intf_ptr->specData.monitor != EIPM_MONITOR_SNDPKT) &&
	     (intf_ptr->specData.monitor != EIPM_MONITOR_BFD) )
        {
            continue;
        }

        if( strcmp(iface, "all") == 0 ||
            strcmp(iface, "external") == 0 ||
            strcmp(iface_base_ptr, intf_ptr->lsn0_baseif) == 0 ||
            strcmp(iface_base_ptr, intf_ptr->lsn1_baseif) == 0 )
        {
            EIPM_SUBNET     *subnet_ptr;
            int             subnet_idx;

            for( subnet_idx = 0, subnet_ptr = &intf_ptr->subnet[0];
                 subnet_idx < intf_ptr->subnet_cnt;
                 subnet_idx++, subnet_ptr++ )
            {
                switch( subnet_ptr->sub2intf_mapping[0].route_priority )
                {
                case LSN1:
                    strcat(active_iface, intf_ptr->lsn1_baseif);
                    strcat(active_iface, " ");
                    ret = 0;
                    subnet_idx = intf_ptr->subnet_cnt;
                    break;

                default:
                    strcat(active_iface, intf_ptr->lsn0_baseif);
                    strcat(active_iface, " ");
                    ret = 0;
                    subnet_idx = intf_ptr->subnet_cnt;
                    break;
                }
            }
        }
    }

    if( ret != 0 )
    {
        strcpy(active_iface, "Unknown - No Interface Match");
    }

    return ret;
}

int 
ipm_set_side( nma_ctx_t* ctx, char *iface )
{
EIPM_DATA       *data_ptr;
EIPM_INTF       *intf_ptr;
int             intf_idx;
int             retval;
char            *iface_base_ptr;
char            iface_base[MAX_NLEN_DEV];
char            *lsn0_base_ptr;
char            lsn0_base[MAX_NLEN_DEV];
char            *lsn1_base_ptr;
char            lsn1_base[MAX_NLEN_DEV];

    // Temp Change for LM4.0.1
    return IPM_SUCCESS;

    strncpy(lsn0_base, ctx->a.my[0].name, MAX_NLEN_DEV);

    lsn0_base_ptr = strtok(lsn0_base, ":");

    if( lsn0_base_ptr == NULL )
    {
        lsn0_base_ptr = lsn0_base;
    }

    strncpy(lsn1_base, ctx->a.my[1].name, MAX_NLEN_DEV);

    lsn1_base_ptr = strtok(lsn1_base, ":");

    if( lsn1_base_ptr == NULL )
    {
        lsn1_base_ptr = lsn1_base;
    }

    strncpy(iface_base, iface, MAX_NLEN_DEV);

    iface_base_ptr = strtok(iface_base, ":");

    if( iface_base_ptr == NULL )
    {
        iface_base_ptr = iface_base;
    }

    retval = IPM_INVALIDPARAMETER;

    /* Handle Managed Internal IP */
    if( strcmp(iface_base_ptr, "lsn0") == 0 ||
        strcmp(iface_base_ptr, lsn0_base_ptr) == 0 )
    {
        retval = IPM_SUCCESS;

        if( ctx->a.iipm_preferred_side != LINK_0 )
        {
            ctx->a.iipm_preferred_side = LINK_0;

            ctx->a.iipm_preferred_side_update = 3;
        }

    }
    else if( strcmp(iface_base_ptr, "lsn1") == 0 ||
             strcmp(iface_base_ptr, lsn1_base_ptr) == 0 )
    {
        if( ctx->a.iipm_preferred_side == LINK_1 )
        {
            retval = IPM_SUCCESS;
        }
        else
        {
            if( ctx->a.iipm_interface_status == LINK_ALL )
            {
                ctx->a.iipm_preferred_side = LINK_1;

                ctx->a.iipm_preferred_side_update = 3;

                retval = IPM_SUCCESS;
            }
            else
            {
                retval = IPM_FAILURE;
            }
        }
    }

    if( retval == IPM_FAILURE )
    {
        return retval;
    }

    /* Handle Managed External IP */
    data_ptr = (EIPM_DATA *)EIPM_shm_ptr;

    for( intf_idx = 0, intf_ptr = &data_ptr->intf_data[0];
         intf_idx < data_ptr->intf_cnt;
         intf_idx++, intf_ptr++ )
    {
        if( strcmp(iface_base_ptr, "lsn0") == 0 ||
            strcmp(iface_base_ptr, intf_ptr->lsn0_baseif) == 0 )
        {
            retval = IPM_SUCCESS;

	    if ( intf_ptr->specData.preferred_side != LSN0 )
            {
                intf_ptr->specData.preferred_side = LSN0;

                intf_ptr->specData.preferred_side_update = TRUE;
            }
        }
        else if( strcmp(iface_base_ptr, "lsn1") == 0 ||
                 strcmp(iface_base_ptr, intf_ptr->lsn1_baseif) == 0 )
        {
	    if ( intf_ptr->specData.preferred_side == LSN1 )
            {
                retval = IPM_SUCCESS;
            }
            else
            {
		if ( intf_ptr->specData.status == EIPM_ONLINE )
                {
		    intf_ptr->specData.preferred_side = LSN1;

                    intf_ptr->specData.preferred_side_update = TRUE;

                    retval = IPM_SUCCESS;
                }
                else if( strcmp(iface_base_ptr, intf_ptr->lsn1_baseif) == 0 )
                {
                    retval = IPM_FAILURE;
                }
            }
        }
    }

    return retval;
}


int ipm_handle_alias(nma_ctx_t* ctx, station_t* station, int add, int side )
{
nma_ipalias_dst_t* alias;
int prefix;
int ifindex;
int filter;
int error;
int retval;
char ip_str[IPM_IPMAXSTRSIZE];
char ifname[MAX_NLEN_DEV];

    error = 0;
    /* Do nothing in simplex mode */
    if (IS_SIMPLEX_MODE)
    {
        return IPM_SUCCESS;
    }

    //check & update ifindex
    ipm_upd_ifindex();

    filter = (station != NULL);
    alias = ctx->b.aliaspool.head;

    while( alias != NULL )
    {
        IPM_ipaddr2p(&(alias->alias_ip), ip_str, IPM_IPMAXSTRSIZE);

        switch( alias->alias_ip.addrtype )
        {
        case IPM_IPV4:
            prefix = IPM_IPV4MAXMASKLEN;
            break;

        case IPM_IPV6:
            prefix = IPM_IPV6MAXMASKLEN;
            break;

        default:
            ASRT_RPT(ASBAD_DATA, 1, 
                     sizeof(IPM_IPADDR), &(alias->alias_ip), 
                     "Invalid addresss type");

            alias = alias->next;

            continue;
        }

        if( !filter || 
            (alias->station == station) )
        {
            station = alias->station;

            if( add == TRUE )
            {
                // use pif_t to get if index, if pif_t is null 
                //check netmask with local ip alias to find a match
                // and get pif_t information, if no match found, no
                // host routing change need based on LCP arch 
                if( alias->pif_t == NULL )
                {
                    alias->pif_t = find_matching_subnet(alias->alias_ip, 
                                                        ctx->b.local_ipalias,
                                                        ctx->a.nb_alias);
                }

                if( side == LINK_1 )
                {
                    if (alias->links == LINK_ALL)
                    {
                        if( alias->pif_t != NULL ) 
                        {
                            memcpy(&(alias->gateway_ip), &(alias->alias_ip), IPM_IPADDRSIZE);

                            alias->device_index = 1;

                            ifindex = alias->pif_t->if_t[alias->device_index].ifindex;

                            strncpy(ifname, alias->pif_t->if_t[alias->device_index].name, MAX_NLEN_DEV);

                            retval = nma_route_add(netlinksocket, 
                                                   ifindex, ifname, 0,
                                                   &(alias->alias_ip), prefix, 
                                                   &(alias->gateway_ip),NULL);
                            if( retval == 0 )
                            {
                                ipm_add_shm_rt(alias->alias_ip, ifname);

                                alias->inuse = TRUE;

                                LOG_OTHER(NMA_OALIAS,
                                          "ipm_handle_alias: add host route %s -> %s", ip_str, ifname);
                            }
                            else if( retval == EEXIST )
                            {
                                LOG_OTHER(NMA_OALIAS,
                                          "ipm_handle_alias: had host route %s -> %s", ip_str, ifname);
                            }
                            else
                            {
                                error = -1;
                            }
                        }
                    }
#if 0
                    // Don't think host route for LSN IPs are needed,
                    // but leave code here for now in case we do.
                    else if (alias->links == LINK_0)
                    {
                        if( alias->pif_t != NULL )
                        {
                            if( alias->alias_ip.addrtype == IPM_IPV4 )
                            {
                                alias->gateway_ip.addrtype = IPM_IPV4;
                                memcpy(alias->gateway_ip.ipaddr, &(station->ip_addr[1]), AF_RAWIPV4SIZE);

                                alias->source_ip.addrtype = IPM_IPV4;
                                memcpy(alias->source_ip.ipaddr, &(ctx->a.my[0].ip), AF_RAWIPV4SIZE);
                            }
                            else // IPM_IPV6 use link ip as "VIA" for IPv6 currently 
                            {
                                memcpy(&(alias->gateway_ip), &(station->link_ip[1]), IPM_IPADDRSIZE);

                                memcpy(&(alias->source_ip), &(ctx->a.my[0].link_ip), IPM_IPADDRSIZE);
                            }

                            alias->device_index = 1;

                            ifindex = ctx->a.my[alias->device_index].ifindex;

                            strncpy(ifname, ctx->a.my[alias->device_index].name, MAX_NLEN_DEV);

                            retval = nma_route_add(netlinksocket, 
                                                   ifindex, ifname, 
                                                   &(alias->alias_ip), prefix, 
                                                   &(alias->gateway_ip),NULL);

                            if( retval == 0 )
                            {
                                ipm_add_shm_rt(alias->alias_ip, ifname);

                                alias->inuse = TRUE;

                                LOG_OTHER(NMA_OALIAS,
                                          "ipm_handle_alias: add lsn ip route %s",ip_str);
                            }
                            else if( retval == EEXIST )
                            {
                                LOG_OTHER(NMA_OALIAS,
                                          "ipm_handle_alias: had lsn ip route %s",ip_str);
                            }
                            else
                            {
                                error = -1;
                            }
                        } 
                    }
#endif
                }
                else if( side == LINK_0 )
                {
                    if (alias->links == LINK_ALL)
                    {
                        if(alias->pif_t != NULL) 
                        {
                            memcpy(&(alias->gateway_ip), &(alias->alias_ip), IPM_IPADDRSIZE);

                            alias->device_index = 0;  

                            ifindex = alias->pif_t->if_t[alias->device_index].ifindex;

                            strncpy(ifname, alias->pif_t->if_t[alias->device_index].name, MAX_NLEN_DEV);

                            retval = nma_route_add(netlinksocket, 
                                                   ifindex, ifname, 0,
                                                   &(alias->alias_ip), prefix, 
                                                   &(alias->gateway_ip),NULL);
                            if( retval == 0 )
                            {
                                ipm_add_shm_rt(alias->alias_ip, ifname);

                                alias->inuse = TRUE;

                                LOG_OTHER(NMA_OALIAS,
                                          "ipm_handle_alias: add host route %s -> %s", ip_str, ifname);
                            }
                            else if( retval == EEXIST )
                            {
                                LOG_OTHER(NMA_OALIAS,
                                          "ipm_handle_alias: had host route %s -> %s", ip_str, ifname);
                            }
                            else
                            {
                                error = -1;
                            }
                        }
                    }
#if 0
                    // Don't think host route for LSN IPs are needed,
                    // but leave code here for now in case we do.
                    else if (alias->links == LINK_1)
                    {
                        if( alias->pif_t != NULL )
                        {
                            if( alias->alias_ip.addrtype == IPM_IPV4 )
                            {
                                alias->gateway_ip.addrtype = IPM_IPV4;
                                memcpy(alias->gateway_ip.ipaddr, &(station->ip_addr[0]), AF_RAWIPV4SIZE);

                                alias->source_ip.addrtype = IPM_IPV4;
                                memcpy(alias->source_ip.ipaddr, &(ctx->a.my[1].ip), AF_RAWIPV4SIZE);
                            }
                            else // IPM_IPV6
                            {
                                memcpy(&(alias->gateway_ip), &(station->link_ip[0]), IPM_IPADDRSIZE);

                                memcpy(&(alias->source_ip), &(ctx->a.my[1].link_ip), IPM_IPADDRSIZE);
                            }

                            alias->device_index = 0;

                            ifindex = ctx->a.my[alias->device_index].ifindex;

                            strncpy(ifname, ctx->a.my[alias->device_index].name, MAX_NLEN_DEV);

                            retval = nma_route_add(netlinksocket, 
                                                   ifindex, ifname, 
                                                   &(alias->alias_ip), prefix, 
                                                   &(alias->gateway_ip),NULL);

                            if( retval == 0 )
                            {
                                ipm_add_shm_rt(alias->alias_ip, ifname);

                                alias->inuse = TRUE;

                                LOG_OTHER(NMA_OALIAS,
                                          "ipm_handle_alias: add lsn ip route %s",ip_str);
                            }
                            else if( retval == EEXIST )
                            {
                                LOG_OTHER(NMA_OALIAS,
                                          "ipm_handle_alias: had lsn ip route %s",ip_str);
                            }
                            else
                            {
                                error = -1;
                            }
                        } 
                    }
#endif
                }
            }
            else
            {
                if( alias->links == LINK_ALL &&
                    alias->inuse == TRUE )
                {
                    if( alias->alias_ip.addrtype == IPM_IPV6 )
                    {
                        ifindex = ctx->a.my[alias->device_index].ifindex;
                    }
                    else
                    {
                        ifindex = NOPARAMETER;
                    }

                    if( nma_route_del(netlinksocket, 
                                      ifindex, 
                                      "", 
                                      &(alias->alias_ip), 
                                      prefix,  
                                      NULL) < 0)
                    {
                        error = -1;
                    }
                    else
                    {
                        ipm_delete_shm_rt(netlinksocket, alias->alias_ip, prefix);

                        alias->inuse = FALSE;

                        LOG_OTHER(NMA_OALIAS,
                                  "ipm_handle_alias: delete route %s",ip_str);
                    }
                }
            }
        }

        alias = alias->next;
    }

    return error;
}

int
ipm_lookup_intf( EIPM_INTF *intf_ptr, EIPM_SUBNET *subnet_ptr )
{
struct sockaddr_nl nladdr;
IPM_IPTBL ip_tbl;
EIPM_NET side;
struct ifreq ifr;
int nl_socket;
int retval;
int sock;
char ip_buf[IPM_IPMAXSTRSIZE];

    nl_socket = socket( PF_NETLINK, SOCK_RAW, NETLINK_ROUTE );

    if( nl_socket < 0 )
    {
        ASRT_RPT( ASUNEXP_RETURN, 0,
                  "ipm_lookup_intf(): Failed to create socket when attempting to look up ip = %s, errno = 0x%x\n",
                   IPM_ipaddr2p( &(subnet_ptr->ips[0].ipaddr), ip_buf, sizeof(ip_buf) ),
                   errno );

        return IPM_FAILURE;
    }

   // Fill in the sockaddr structure for bind()
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pad = 0;
    nladdr.nl_pid = 0;
    nladdr.nl_groups = 0;

    retval = bind( nl_socket, (struct sockaddr *)&nladdr, sizeof( nladdr ) );

    if( retval < 0 )
    {
        ASRT_RPT( ASUNEXP_RETURN, 0,
                  "ipm_lookup_intf(): Failed to bind to socket when attempting to look up ip = %s, errno = 0x%x\n",
                   IPM_ipaddr2p( &(subnet_ptr->ips[0].ipaddr), ip_buf, sizeof(ip_buf) ),
                   errno );

        (void)close( nl_socket );

        return IPM_FAILURE;
    }

    ip_tbl.ip_cnt = 0;
    retval = EIPM_read_iptable( nl_socket,
                                (subnet_ptr->ips[0].ipaddr.addrtype == IPM_IPV6) ? AF_INET6 : AF_INET,
                                NULL,
				EIPM_INVALID_INTF,
                                &ip_tbl,
				NULL );

    if( retval < 0 )
    {
        ASRT_RPT( ASUNEXP_RETURN,
                  1,
                  sizeof(ip_tbl),
                  &ip_tbl,
                  "ipm_lookup_intf(): Failed to read IP table: retval=%d\n",
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
            if( IPM_IPCMPADDR( &ip_ptr->ipaddr, &ip_tbl_ptr->ipaddr) == IPM_SUCCESS )
            {
                sock = socket(PF_INET, SOCK_RAW, htons(ETH_P_IP));
                if( sock < 0 )
                {
                     ASRT_RPT( ASUNEXP_RETURN,
                     1,
                     sizeof(*intf_ptr),
                     intf_ptr,
                     "ipm_lookup_intf(): Failed to create socket\nretval=%d, errno=0x%x\n",
                     sock,
                     errno );
                     return IPM_FAILURE;
                }

                if (ip_tbl_ptr->lsnA_idx != -1 )
                {
		    intf_ptr->specData.lsn0_iface_indx = ip_tbl_ptr->lsnA_idx;
                    strncpy(intf_ptr->lsn0_baseif , ip_tbl_ptr->lsnA_iface, EI_INTFNAMESIZE-1);
		    intf_ptr->lsn0_baseif[EI_INTFNAMESIZE-1] = 0;
                    subnet_ptr->sub2intf_mapping[0].route_priority = LSN0;

                    // Get MAC address
                    memset( &ifr, 0, sizeof(ifr) );
                    ifr.ifr_addr.sa_family = PF_INET;
                    strncpy( ifr.ifr_name, intf_ptr->lsn0_baseif , IFNAMSIZ-1);
		    ifr.ifr_name[IFNAMSIZ-1] = 0;
		    ifr.ifr_ifindex = intf_ptr->specData.lsn0_iface_indx;

                    retval = ioctl( sock, SIOCGIFHWADDR, &ifr );
                    if( retval < 0 )
                    {
                          LOG_ERROR( 0,
                                     "Error: get MAC failed - ioctl(SIOCGIFHWADDR) failed for interface=%s, retval %d, errno %d\n",
                                     intf_ptr->lsn0_baseif,
                                     retval, 
                                     errno );

                          (void)close( sock );
                          return IPM_FAILURE;
                    }

                    memcpy(intf_ptr->lsn0_hwaddr,
                                    ifr.ifr_ifru.ifru_hwaddr.sa_data,
                                    ETH_ALEN);
                }

                if (ip_tbl_ptr->lsnB_idx  != -1 )
                {
		    intf_ptr->specData.lsn1_iface_indx = ip_tbl_ptr->lsnB_idx;
                    strncpy( intf_ptr->lsn1_baseif , ip_tbl_ptr->lsnB_iface, EI_INTFNAMESIZE-1);
		    intf_ptr->lsn1_baseif[EI_INTFNAMESIZE-1] = 0;
                    subnet_ptr->sub2intf_mapping[0].route_priority = LSN1;

                    // Get MAC address
                    memset( &ifr, 0, sizeof(ifr) );
                    ifr.ifr_addr.sa_family = PF_INET;
                    strncpy(ifr.ifr_name, intf_ptr->lsn1_baseif, IFNAMSIZ-1);
		    ifr.ifr_name[IFNAMSIZ-1] = 0;
		    ifr.ifr_ifindex = intf_ptr->specData.lsn1_iface_indx;

                    retval = ioctl( sock, SIOCGIFHWADDR, &ifr );
                    if( retval < 0 )
                    {
                          LOG_ERROR( 0,
                                     "Error: get MAC failed - ioctl(SIOCGIFHWADDR) failed for interface=%s, retval %d, errno %d\n",
                                     intf_ptr->lsn1_baseif,
                                     retval, 
                                     errno );

                          (void)close( sock );
                          return IPM_FAILURE;
                    }

                    memcpy( intf_ptr->lsn1_hwaddr,
                                    ifr.ifr_ifru.ifru_hwaddr.sa_data,
                                    ETH_ALEN );
                }

                (void)close( sock );
                return IPM_SUCCESS;
            }
        }

        LOG_ERROR( 0,
                   "Error: Look through all IPs but didn't find the IP = %s\n",
                   IPM_ipaddr2p( &(subnet_ptr->ips[0].ipaddr), ip_buf, sizeof(ip_buf) ));

        return IPM_FAILURE;

    } /* Look through all IPs */

    return IPM_SUCCESS;

}

/*
 *  Function: ipm_getVLANStr.
 *  Input   : vlanId - VLAN Id to be converted to string.
 *          : bIncludeDot - Includes the '.' preceding the VLAN Id in the string.
 *  Output  : Returns the VLAN Id (if valid) as a string. Else returns an empty string.
 *  Desc.   : Converts a valid VLAN Id to a string.
 */
char *ipm_getVLANStr( unsigned short vlanId, unsigned short bIncludeDot )
{
        static char vlanIdStr[7];

        if ( 0 == vlanId )
        {
                return (char *)"";
        }

        snprintf( vlanIdStr, sizeof( vlanIdStr ), "%s%u", 
                  ( ( TRUE == bIncludeDot ) ? "." : "" ),
                  vlanId );

        return vlanIdStr;
} /* end ipm_getVLANStr() */

int ipm_getIntfVlanAlias( char *intfStr, char *intfName, char *aliasStr, unsigned short *vlanIdP )
{

        char            localIntfStr[MAX_NLEN_DEV];
        char            *aliasSepP;     /* Points to the ':' character preceding the alias. */
        char            *vlanSepP;      /* Points to the '.' character preceding the VLAN. */

        strncpy( localIntfStr, intfStr, ( MAX_NLEN_DEV - 1 ) );

        if ( aliasStr != NULL )
        {
                aliasSepP = strchr( localIntfStr, ':' );

                if ( aliasSepP != NULL )
                {
                        strcpy( aliasStr, ( aliasSepP + 1 ) );
                        *aliasSepP = '\0';
                }
                else
                {
                        aliasStr[0] = '\0';
                }
        }
        else
        {
                strtok( localIntfStr, ":" );
        }

        vlanSepP = strchr( localIntfStr, '.' );

        if ( vlanSepP != NULL )
        {
                errno = 0;
                *vlanIdP = (unsigned short)strtoul( ( vlanSepP + 1 ), (char **)NULL, 10 );

                if ( errno != 0 )
                {
                        *vlanIdP = 0;
                        LOG_ERROR( 0, "ERROR(%s): Failed to determine VLAN for %s (%s). errno: %d.\n",
                                   (char *)(__func__), intfStr, ( vlanSepP + 1 ), errno );

                        return IPM_FAILURE;
                }

                *vlanSepP = '\0';
        }
        else
        {
                *vlanIdP = 0;
        }

        strcpy( intfName, localIntfStr );

        return IPM_SUCCESS;

} /* end ipm_getIntfVlanAlias() */

/*************************
 * Name:        ipm_checkStackedVLAN
 * Description: check if an interface is stacked vlan,
 *		and get base interface and stacked interface.
 * Parameter:
 *              iface_base - pointer to a base interface buffer
 *		iface_base_ptr - pointer to base interface pointer
 *		stacked_iface - pointer to a stacked interface buffer
 *		stacked_iface_ptr - pointer to stacked interface pointer
 *		iface_name - pointer to an interface name
 * Return:
 *              void
 **************************/
void ipm_checkStackedVLAN(char* iface_base,
        		char** iface_base_ptr,
        		char* stacked_iface,
        		char** stacked_iface_ptr,
        		char* iface_name)
{
        char *dot, *remain;
	char lsn0_intfStr[MAX_NLEN_DEV];
	char lsn1_intfStr[MAX_NLEN_DEV];

	ipm_get_internal_intfs( lsn0_intfStr, lsn1_intfStr );
	strncpy(stacked_iface, iface_name, MAX_NLEN_DEV);

	if ((strstr(iface_name, lsn0_intfStr) != NULL) && (iface_name[strlen(lsn0_intfStr)] == '.'))
	{
		strncpy(iface_base, stacked_iface, strlen(lsn0_intfStr));
		*iface_base_ptr = iface_base;
		*stacked_iface_ptr = strtok_r(stacked_iface, ":", &remain);
		if (*stacked_iface_ptr == NULL)
		{
			*stacked_iface_ptr = stacked_iface;
		}
		return;
	}
	else if ((strstr(iface_name, lsn1_intfStr) != NULL) && (iface_name[strlen(lsn1_intfStr)] == '.'))
	{
		strncpy(iface_base, stacked_iface, strlen(lsn1_intfStr));
		*iface_base_ptr = iface_base;
		*stacked_iface_ptr = strtok_r(stacked_iface, ":", &remain);
		if (*stacked_iface_ptr == NULL)
		{
			*stacked_iface_ptr = stacked_iface;
		}
		return;
	}

        //normal interface
        *iface_base_ptr = strtok(stacked_iface, ":");

        if( *iface_base_ptr == NULL )
        {
                *iface_base_ptr = stacked_iface;
        }

        *stacked_iface_ptr = *iface_base_ptr;
        return;
}

/*************************
 * Name:        ipm_open_netlink
 * Description: open a netlink socket
 * Parameter:
 *              void
 * Return:
 *              socket id for success
 *              -1 for error
 **************************/
int ipm_open_netlink()
{
        int nl_socket;
        struct sockaddr_nl nladdr;
        int retval;

        nl_socket = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

        if( nl_socket < 0 )
        {
                ASRT_RPT( ASOSFNFAIL,
                        0,
                        "ipm_get_netlink: Failed to create routing socket\nretval=%d, errno=0x%x\n",
                        nl_socket,
                        errno );
                return -1;
        }

        nladdr.nl_family = AF_NETLINK;
        nladdr.nl_pad = 0;
        nladdr.nl_pid = 0;
        nladdr.nl_groups = 0;

        retval = bind(nl_socket, (struct sockaddr *)&nladdr, sizeof(nladdr));

        if( retval < 0 )
        {
                ASRT_RPT( ASOSFNFAIL,
                        0,
                        "ipm_get_netlink: Failed to bind to routing socket\nretval=%d, errno=0x%x\n",
                        retval,
                        errno );
		close(nl_socket);
                return -1;
        }

        return nl_socket;
}

/*************************
 * Name:        ipm_close_netlink
 * Description: close a socket
 * Parameter:
 *              skfd: socket id
 * Return:
 *              void
 **************************/
void ipm_close_netlink(int skfd)
{
        if (skfd >= 0)
        {
                if (close(skfd) < 0)
                {
                        ASRT_RPT(ASOSFNFAIL, 0, 
				"ipm_close_netlink: close(%d) for netlink failed; errno=%d/%s",
                                skfd, errno, strerror(errno));
                        return;
                }
        }
}

/*************************
 * Name:        ipm_vlan_add
 * Description: add vlan on an interface
 * Parameter:
 *              iface:  interface name which will add/del vlan on
 *              vlan:   vlan id which should be >0 && <MAX_NUM_PIVOT
 * Return:
 *              IPM_SUCCESS for success;
 *              IPM_FAILURE for error
 **************************/

int ipm_vlan_add(char *iface, unsigned int vlan)
{
        int fd;
        struct vlan_ioctl_args if_request;
        struct ifreq ifr;

        char config_file[] = "/proc/net/vlan/config";

        if (vlan <= 0 || vlan >= MAX_NUM_PIVOT)
        {
                ASRT_RPT( ASRTBADPARAM, 0, "vlan %d out of range!\n", vlan);
                return IPM_FAILURE;
        }

        if (strlen(iface) > 15)
        {
                ASRT_RPT( ASRTBADPARAM, 0, "iface %s is too long!\n", iface);
                return IPM_FAILURE;
        }

        //is /proc/net/vlan/config is avaliable?
        if ((fd = open(config_file, O_RDONLY)) < 0)
        {
                ASRT_RPT(ASOSFNFAIL, 0,
                        "Failed to open file /proc/net/vlan/config; errno=%d/%s",
                        errno, strerror(errno));
                return IPM_FAILURE;
        }
        else
        {
                close(fd);
        }

        memset(&if_request, 0, sizeof(struct vlan_ioctl_args));
        memset(&ifr, 0, sizeof(struct ifreq));

        strcpy(if_request.device1, iface);
        if_request.u.VID = vlan;
        if_request.cmd = ADD_VLAN_CMD;

        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
                ASRT_RPT(ASOSFNFAIL, 0,
                        "Failed to open socket; errno=%d/%s",
                        errno, strerror(errno));
                return IPM_FAILURE;
        }

        //check if the base interface is there
        strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
        if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
        {
                ASRT_RPT(ASOSFNFAIL, 0,
                        "Unknown interface %s; errno=%d/%s",
                        iface, errno, strerror(errno));
                close(fd);
                return IPM_FAILURE;
        }

        //check if the new interface is already there
        memset(&ifr, 0, sizeof(struct ifreq));
        sprintf(ifr.ifr_name, "%s.%d", iface, vlan);
        if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0)
        {
                //is it up?
                if (!(ifr.ifr_flags & IFF_UP))
                {
                        //make it up
                        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
                        if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
                        {
                                ASRT_RPT(ASOSFNFAIL, 0,
                                        "ioctl -  SIOCSIFFLAGS for IFF_UP | IFF_RUNNING failed; errno=%d/%s",
                                        errno, strerror(errno));
                                close(fd);
                                return IPM_FAILURE;
                        }
                }
                close(fd);
                return IPM_SUCCESS;
        }

        //add vlan
        if (ioctl(fd, SIOCSIFVLAN, &if_request) < 0)
        {
                ASRT_RPT(ASOSFNFAIL, 0,
                        "ioctl() failed to add vlan - iface %s vlan %d; errno=%d/%s",
                        iface, vlan, errno, strerror(errno));
                close(fd);
                return IPM_FAILURE;
        }

        //check if the new interface is there
        if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
        {
                ASRT_RPT(ASOSFNFAIL, 0,
                        "Unknown interface %s; errno=%d/%s",
                        iface, errno, strerror(errno));
                close(fd);
                return IPM_FAILURE;
        }

        //make it up
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
        {
                ASRT_RPT(ASOSFNFAIL, 0,
                        "ioctl -  SIOCSIFFLAGS for IFF_UP | IFF_RUNNING failed; errno=%d/%s",
                        errno, strerror(errno));
                close(fd);
                return IPM_FAILURE;
        }

        close(fd);

        return IPM_SUCCESS;
}

/*************************
 * Name:        ipm_vlan_del
 * Description: delete vlan on an interface
 * Parameter:
 *              iface:  interface name which will delete vlan on
 * Return:
 *              IPM_SUCCESS for success;
 *              -1 for error
 **************************/

int ipm_vlan_del(char *iface)
{
        int fd;
        struct vlan_ioctl_args if_request;
        struct ifreq ifr;

        char config_file[] = "/proc/net/vlan/config";

        /*
        if (vlan <= 0 || vlan >= MAX_NUM_PIVOT)
        {
                ASRT_RPT( ASRTBADPARAM, 0, "vlan out of range!\n");
                return IPM_FAILURE;
        }
        */

        if (strlen(iface) > 15)
        {
                ASRT_RPT( ASRTBADPARAM, 0, "iface %s is too long!\n",
                        iface);
                return IPM_FAILURE;
        }

        //is /proc/net/vlan/config is avaliable?
        if ((fd = open(config_file, O_RDONLY)) < 0)
        {
                ASRT_RPT(ASOSFNFAIL, 0,
                        "Failed to open file /proc/net/vlan/config; errno=%d/%s",
                        errno, strerror(errno));
                return IPM_FAILURE;
        }
        else
        {
                close(fd);
        }

        memset(&if_request, 0, sizeof(struct vlan_ioctl_args));
        memset(&ifr, 0, sizeof(struct ifreq));

        strcpy(if_request.device1, iface);
        if_request.cmd = DEL_VLAN_CMD;

        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
                ASRT_RPT(ASOSFNFAIL, 0,
                        "Failed to open socket; errno=%d/%s",
                        errno, strerror(errno));
                return IPM_FAILURE;
        }

        //check if the interface is there.
        strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
        if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
        {
                ASRT_RPT(ASOSFNFAIL, 0,
                        "Unknown interface %s; errno=%d/%s",
                        iface, errno, strerror(errno));
		close(fd);
                return IPM_FAILURE;
        }

        //make it down
        ifr.ifr_flags &= ~IFF_UP;
        if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
        {
                ASRT_RPT(ASOSFNFAIL, 0,
                        "ioctl -  SIOCSIFFLAGS for ~IFF_UP failed; errno=%d/%s",
                        errno, strerror(errno));
                close(fd);
                return IPM_FAILURE;
        }

        //remove vlan
        if (ioctl(fd, SIOCSIFVLAN, &if_request) < 0)
        {
                ASRT_RPT(ASOSFNFAIL, 0,
                        "ioctl() failed to del vlan - iface %s\n errno=%d/%s",
                        iface, errno, strerror(errno));
                close(fd);
                return IPM_FAILURE;
        }

        close(fd);

        return IPM_SUCCESS;
}

/*************************
 * Name:        ipm_check_linkup
 * Description: check the link carrier status for certain interface
 * Parameter:
 *              intf:  interface name which will be checked
 * Return:
 *              IPM_SUCCESS for success;
 *              IPM_FAILURE for error
 **************************/

int ipm_check_linkup(char *intf)
{
	char link_stats_dir[] = "/sys/class/net";
	char conf_file[100];
	FILE *fd;
	char line[100];
	int status;

	if (strstr(intf, "eth0") != NULL)
	{
		snprintf(conf_file, sizeof(conf_file), "%s/%s/carrier", link_stats_dir, "eth0");
	}
	else if (strstr(intf, "eth1") != NULL)
	{
		snprintf(conf_file, sizeof(conf_file), "%s/%s/carrier", link_stats_dir, "eth1");
	}
	else
	{
		return IPM_FAILURE;
	}

	fd = fopen(conf_file, "r");
	if (fd == NULL) return IPM_FAILURE;

	if( fgets(line, sizeof(line), fd) == (char *)NULL )
	{
		fclose(fd);
		return IPM_FAILURE;
	}
	if( sscanf(line, "%d\n", &status) < 1)
	{
		fclose(fd);
		return IPM_FAILURE;
	}
	fclose(fd);
	if (status == 1)
		return IPM_SUCCESS;
	else
		return IPM_FAILURE;

}

/*
 *  Function: ipm_get_internal_intfs.
 *  Input   : None.
 *  Output  : lsn0_intfStr - String to set the LSN0 internal interface name.
 *          : lsn1_intfStr - String to set the LSN1 internal interface name.
 *  Desc.   : Scans IIPM's data to find and return the internal interface names.
 */
void ipm_get_internal_intfs( char *lsn0_intfStr, char *lsn1_intfStr )
{

	int i;
	char * search = ":";

        lsn0_intfStr[0] = '\0';
        lsn1_intfStr[0] = '\0';

	strncpy( lsn0_intfStr, tab_ctx[0].a.my[0].name, (sizeof(tab_ctx[0].a.my[0].name) - 1) );
	strncpy( lsn1_intfStr, tab_ctx[0].a.my[1].name, (sizeof(tab_ctx[0].a.my[1].name) - 1) );

	/* remove the vlan id. E.G: make eth0.800:0 to eth0.800*/
	strtok(lsn0_intfStr, search);
	strtok(lsn1_intfStr, search);


} /* end 'ipm_get_internal_intfs' */

void ipm_get_lsn_routes(IPM_ROUTE_ENTRY *lsn0_rt, IPM_ROUTE_ENTRY *lsn1_rt)
{
	IPM_IPADDR ipmask;
	unsigned int base_int;

	memset(lsn0_rt, 0, sizeof (IPM_ROUTE_ENTRY));
	memset(lsn1_rt, 0, sizeof (IPM_ROUTE_ENTRY));

	lsn0_rt->iface_indx = -1;
	lsn1_rt->iface_indx = -1;

	if (tab_ctx[0].a.my[0].name[0] != '\0')
	{
		// Populating lsn0 routing entry
		lsn0_rt->iface_indx = tab_ctx[0].a.my[0].ifindex;

		IPM_in2ipaddr(&tab_ctx[0].a.my[0].mask, sizeof (struct in_addr), &ipmask);
		lsn0_rt->destprefix = IPM_ipgetmasklen(&ipmask);

		base_int = tab_ctx[0].a.my[0].ip & tab_ctx[0].a.my[0].mask;
		IPM_in2ipaddr(&base_int, sizeof (struct in_addr), &(lsn0_rt->dest));
	}

	if (tab_ctx[0].a.my[1].name[0] != '\0')
	{
		// Populating lsn1 routing entry
		lsn1_rt->iface_indx = tab_ctx[0].a.my[1].ifindex;

		IPM_in2ipaddr(&tab_ctx[0].a.my[1].mask, sizeof (struct in_addr), &ipmask);
		lsn1_rt->destprefix = IPM_ipgetmasklen(&ipmask);

		base_int = tab_ctx[0].a.my[1].ip & tab_ctx[0].a.my[1].mask;
		IPM_in2ipaddr(&base_int, sizeof (struct in_addr), &(lsn1_rt->dest));
	}
}

int ipm_get_iipm_status(struct timeval *degrade_timer, int *iipm_timer)
{
	memcpy(degrade_timer, &(tab_ctx[0].a.degrade_time), sizeof(struct timeval));
	*iipm_timer = tab_ctx[0].a.iipm_timer;
	return tab_ctx[0].a.iipm_interface_status;
}

/*
 * In Virtual env, it will use tunnel to replace pivot
 */
int ipm_isVirtual()
{
        static int isVirtual = -1;
        char cmd[256];
        int ret = -1;

        if (isVirtual == -1)
        {
                snprintf(cmd, sizeof(cmd), "/opt/LSS/sbin/is_virtual  2>&1");
                ret = system(cmd);
                if (WIFEXITED(ret))
                {
                        isVirtual = WEXITSTATUS(ret);
			if (isVirtual != 0 &&
			    isVirtual != 1)
			{
	                        LOG_FORCE(0, "ipm_isVirtual: Failed exit status cmd=%s WEXITSTATUS=%d ret=%d\n",
                                cmd, isVirtual, ret);								
	                        isVirtual = 0;
			}
                }
                else
                {
                        LOG_ERROR(0, "ipm_isVirtual: Failed to call system(%s),errorno=%d (%s)\n",
                                cmd, errno, strerror(errno));
                        isVirtual = 0;
                }
        }
        return isVirtual;
}

