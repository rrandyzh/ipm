/*
**  File Name:
**  	glob/src/ipm/nma_main.c                                
**  Description:
**	this file include NMA core logical code.
**  Note:
**	The code is based on Tomix NMA 5.0 SP1 01/29/08
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
#include <sys/select.h>
#include <unistd.h>
#include <libgen.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <sched.h>
#include <arpa/inet.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>

#include "nma_ctx.h"
#include "nma_log.h"
#include "nnn_socket.h"

#include "ipm_init.h"
#include "ipm_util.h"
#include "ipm_spv.h"
#include "ipm_msg.h"
#include "nma_route.h"
#include "ipm_retval.h"
#include "EIPM_include.h"
#include "PIPM_include.h"
#include "EIPM_bfd.h"
#include "BSPtrace.h"


#define SHELF_MASK (0x0f)

char
trt[][30]={ \
"SUPINDIC",               "SESDATAINDIC",      "SESOPENINDIC", \
"SESOPENCONFIRM",         "SESCONGENDINDIC",   "SESABORTINDIC", \
"SPVTIMER",               "SETALIAS",          "UNSETALIAS", \
"SETLSN",                 "SETLOG",            "GETSTAACCESS", \
"GETLSNACCESS",           "GETCTXSTATIONHEAD", "SETGLOBALLSN", \
"RESETSTAT",              "GETSTAT",           "SETGLOBALLOG", \
"CONNECT",                "DISCONNECT",        "SUBSTASTATUS", \
"SUBSTAACCESS",           "UNSUBSTASTATUS",    "UNSUBSTAACCESS", \
"SUBLSNACCESS",           "UNSUBLSNACCESS",    "SUBPLATFORMSTAACCESS", \
"UNSUBPLATFORMSTAACCESS", "GETCONFIG",         "SUBPLATFORMLSNACCESS", \
"UNSUBPLATFORMLSNACCESS", "MANAGEALIAS",       "UNMANAGEALIAS", \
"IPM_ADD_BASEIF",         "IPM_DEL_BASEIF",    "IPM_ADD_LSN_ALIAS", \
"IPM_DEL_LSN_ALIAS",      "IPM_ADD_INT_ALIAS", "IPM_DEL_INT_ALIAS", \
"IPM_ADD_EXT_ALIAS",      "IPM_DEL_EXT_ALIAS", "IPM_ADD_ARP", \
"IPM_DEL_ARP",            "IPM_ADD_ROUTE",     "IPM_DEL_ROUTE", \
"IPM_ADD_PROXY",          "IPM_DEL_PROXY",     "IPM_ADD_PATH", \
"IPM_DEL_PATH", \
"NOTHING" \
};


//need more check
unsigned int overrun = 0;
unsigned int hangup[MAX_NB_SLOT] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
unsigned int hangupmax = 0;
unsigned int hangupmax_frames = 0;
unsigned int hangupmax_routes = 0;
struct timespec hangupmax_date = {0,0};
struct timespec overrun_date = {0,0};
char hangupmax_trt[32] = "";

//need remove
#if 0
int macrefspv;
extern int _mac_fd;
#endif


nma_ctx_t* tab_ctx;
int inetsocket;
int netlinksocket;
int packetsocket;
int routecache;

/********************************************************
*  LCP related functions				*
********************************************************/
#define nma_subplatformtimers_update(ctx)

#define nma_subplatform_notify(ctx, stat)

#define nma_substation_notify(ctx, stat ,current)

int ipm_is_ready = 0;

int ipm_ctx(nma_ctx_t * ctx);

static int keepRunning = 1;

static void handleTerm(int sig)
{
	keepRunning = 0;
	LOG_FORCE(0, "IPM terminating: received TERM signal.");
}

static void install_IPMSignalHandlers(void)
{
	if (signal(SIGTERM, handleTerm) == SIG_ERR)
	{
		NMA_PANIC(NULL, NMA_PFATALERROR,
			"IPM: failed to install the TERM signal handler");
	}

	return;
}

#define	IPM_MAX_DGRAM_QLEN	100

static int ipm_get_max_dgram_qlen()
{
	FILE		*fp;
	const char	*path = "/proc/sys/net/unix/max_dgram_qlen";
	char		ibuf[64];

	fp = fopen( path, "r" );
	if ( fp == NULL ) 
	{
		LOG_ERROR(NMA_ESTARTSUB,"Error: Cannot open: %s\n", path);
		return(-1);
	}
	if ( fgets( ibuf, 64, fp ) == NULL ) 
	{
		LOG_ERROR(NMA_ESTARTSUB,"Error: Cannot read row from: %s\n", path);
		fclose(fp);
		return(-2);
	}
	int limit = atoi( ibuf );
	fclose(fp);
	return(limit);
}

static int ipm_set_max_dgram_qlen( int limit )
{
	FILE		*fp;
	const char	*path = "/proc/sys/net/unix/max_dgram_qlen";
	char		ibuf[64];

	sprintf( ibuf, "%d\n", limit );
	fp = fopen( path, "w" );
	if ( fp == NULL ) 
	{
		LOG_ERROR(NMA_ESTARTSUB,"Error: Cannot write to: %s\n", path);
		return(-1);
	}
	if ( fputs( ibuf, fp ) <= 0 ) 
	{
		LOG_ERROR(NMA_ESTARTSUB,"Error: Cannot update row in path: %s\n", path);
		fclose(fp);
		return(-2);
	}
	fclose(fp);
	return(limit);
}

static int ipm_update_max_dgram_qlen( int desired_max )
{
	//
	// Obtain the current Linux maximum unix qlen size.
	//
	int limit = ipm_get_max_dgram_qlen();

	//
	// If the current policy limit is less than our desired
	// size, then we'll boost the limit to our desired size.
	//
	if ( limit <  desired_max ) 
	{
		ipm_set_max_dgram_qlen( desired_max );
	}
	return 0;
}


#if defined(_MIPS)

/* Max open file descriptors allowed for IPM process. */
#define IPM_MAX_OPEN_FILE_DESC          65535

/* 
 *  Function: ipm_setOpenFDLimit.
 *  Input   : None.
 *  Output  : None.
 *  Desc.   : Sets max open file descriptors limit for IPM process.
 */
void ipm_setOpenFDLimit()
{

        int             retVal;
	struct rlimit   rLimit;

        retVal = getrlimit( RLIMIT_NOFILE, &rLimit );

        if ( 0 == retVal )
        {
                if ( IPM_MAX_OPEN_FILE_DESC == rLimit.rlim_cur )
                {
                        /* Limit already set. */
                        return;
                }

                rLimit.rlim_cur = rLimit.rlim_max = IPM_MAX_OPEN_FILE_DESC;

                retVal = setrlimit( RLIMIT_NOFILE, &rLimit );

                if ( 0 == retVal )
                {
                        /* Read back the value set for confirmation. */
                        retVal = getrlimit( RLIMIT_NOFILE, &rLimit );

                        if ( 0 == retVal )
                        {
                                if ( rLimit.rlim_cur < IPM_MAX_OPEN_FILE_DESC )
                                {
                                        LOG_ERROR( 0, "ERROR-%s: Failed to set open file descriptor limit to %d (%d)\n",
                                                   (char *)(__func__),
                                                   IPM_MAX_OPEN_FILE_DESC,
                                                   rLimit.rlim_cur );
                                }
                        }
                        else
                        {
                                LOG_ERROR( 0, "ERROR-%s: Failed to read open file descriptor limit for confirmation. errno: %d (%s)\n",
                                           (char *)(__func__),
                                           errno,
                                           strerror( errno ) );
	                }
                }
	        else
                {
                        LOG_ERROR( 0, "ERROR-%s: Failed to set open file descriptor limit. errno: %d (%s)\n",
                                   (char *)(__func__),
                                   errno,
                                   strerror( errno ) );
	        }
        }
        else
        {
                LOG_ERROR( 0, "ERROR-%s: Failed to read open file descriptor limit. errno: %d (%s)\n",
                           (char *)(__func__),
                           errno,
                           strerror( errno ) );
	}

        return;

} /* end 'ipm_setOpenFDLimit' */

#endif /* #if defined(_MIPS) */

/********************************************************
*  Init RT Thread Attributes				*
********************************************************/

void nma_attr_init(nma_ctx_t* ctx,pthread_attr_t* attr,int priority)
{
   int status;
   struct sched_param sched;

   status =  pthread_attr_init(attr);
   if ( status != 0 )
   {
      NMA_PANIC(&(ctx->a.my[0].ip),NMA_PFATALERROR,"nma_attr_init : pthread_attr_init error %d",status);
   }
   status = pthread_attr_setinheritsched(attr,PTHREAD_EXPLICIT_SCHED);
   if ( status != 0 )
   {
      NMA_PANIC(&(ctx->a.my[0].ip),NMA_PFATALERROR,"nma_attr_init : pthread_attr_setinheritsched error %d",status);
   }
   status = pthread_attr_setscope(attr,PTHREAD_SCOPE_SYSTEM);
   if ( status != 0 )
   {
      NMA_PANIC(&(ctx->a.my[0].ip),NMA_PFATALERROR,"nma_attr_init : pthread_attr_setscope error %d",status);
   }
   status = pthread_attr_setschedpolicy(attr,SCHED_FIFO);
   if ( status != 0 )
   {
      NMA_PANIC(&(ctx->a.my[0].ip),NMA_PFATALERROR,"nma_attr_init : pthread_attr_setschedpolicy error %d",status);
   }
   sched.sched_priority = priority;
   status = pthread_attr_setschedparam(attr,&sched);
   if ( status != 0 )
   {
      NMA_PANIC(&(ctx->a.my[0].ip),NMA_PFATALERROR,"nma_attr_init : pthread_attr_setschedparam error %d",status);
   }
}

/************************/
/* Frame checksum       */
/************************/

int csum(void* buffer,int size)
{
   int sum = 0;
   unsigned short *ptr = buffer;

   while (size > 1)
   {
      sum += ~*ptr++;
      size -= 2;
   }
   if (size > 0)
   {
      sum += ~*(unsigned char*)ptr;
   }
   return(~sum);
}

/*************************/
/* Find station context  */
/*************************/

station_t* nma_find_station(nma_ctx_t* ctx,unsigned int ip)
{
   station_t* station;

   for (station = ctx->a.STATIONHEAD;station != NULL;station = station->next)
   {
      if (ip == station->ip_addr[0]) break;
   }
   return(station);
}

/***************************/
/* Get new station context */
/***************************/

station_t *nma_new_station(nma_ctx_t* ctx)
{
   station_t *station;
   
   if ((station = (station_t*)malloc((size_t)sizeof(station_t))) == NULL)
   {
      LOG_ERROR(NMA_EMALLOC,"nma_new_station : malloc error");
   }
   else
   {
      memset(station,0,sizeof(station_t));
   }
   return (station);
}

/***************************/
/* Add station context     */
/****************************/

void nma_add_station(nma_ctx_t* ctx,station_t* station)
{   
   station->next = NULL;
   if (ctx->a.STATIONHEAD == NULL)
   {
      ctx->a.STATIONHEAD = station;
   }
   else
   {
      (ctx->a.STATIONTAIL)->next = station;
   }
   ctx->a.STATIONTAIL = station;
   return;
}

/*************************/
/* Find and Add ip list  */
/*************************/

int nma_find_add_list(nma_ctx_t* ctx,unsigned int ip)
{
   int index = 0;

   while ((index != ctx->a.nb_station_list) && (ctx->b.station_list[index] != ip)) index++;
   if (ctx->a.nb_station_list == index)
   {
      if (index == MAX_NB_STA) return(-1);
      ctx->b.station_list[index] = ip;
      (ctx->a.nb_station_list)++;
   }
   return(index);
}

/*********************************/
/* Compute global station access */
/* compute global station access */
/* send message to GNM if change */
/* compute global lsn and shelf   */
/* access                        */
/* send message to GNM if change */
/*********************************/

void nma_compute_access(nma_ctx_t* ctx)
{
	int i;
	int j;
	int k;
	unsigned int ip;
	unsigned char shelf;
	unsigned char access;
	unsigned char s_access;
	unsigned char l_access[MAX_NB_SHELF][MAX_NB_SHELF];
	unsigned char r_access;
	unsigned char o_access;
	station_t* station;
	station_t* current;
	int changed;
	unsigned char status;
	int platformmodified = FALSE;
   
	memset(l_access,0,sizeof(l_access));
	o_access = ctx->b.shelf_access[ctx->b.station_shelfid[0]];
	for (i = 0;i < ctx->a.nb_station_list;i++)
	{
		s_access = 0;
		current = NULL;
		shelf = ctx->b.station_shelfid[i];
		ip = ctx->b.station_list[i];
		access = ctx->b.station_access[i];
		ctx->b.station_changed[i] = FALSE;
		for (station = ctx->a.STATIONHEAD;station != NULL;station = station->next)
		{ 
			status = station->ln_remote[i] & LINK_MASK;
			s_access |= status;
			l_access[station->shelf_id][shelf] |= status;
			if ((station->ip_addr[0]) == ip) current = station;
		}
		if (current && (changed = s_access ^ access))
		{
			if ((s_access != LINK_NONE) && 
				(current != ctx->a.STATIONHEAD) &&
				(ctx->a.nb_station_list > 2))
			{
				for (k = 0;k < MAX_NB_DEV;k++)
				{
					if ((access & (1 << k) & changed) && (current->ln_credit[(k+1) % MAX_NB_DEV] <= 2)) 
					s_access |= (1 << k);
				}
			}
			if (s_access != access)
			{
				ctx->b.station_changed[i] = TRUE;

				if (current->ip_addr[0] == ctx->a.my[0].ip) 
				{
				char host[IPM_MAX_HOST_SIZE];

					ipm_get_hostname(ctx->a.shelfid, ctx->a.my[0].ip, host);

					LOG_ERROR(NMA_OSTATUS,"IIPM Connectivity %s : %s -> %s (Interface Change)",
						host,
						ipm_get_named_status(current->ln_access),
						ipm_get_named_status(s_access));

					if ((IS_SIMPLEX_MODE) && ((s_access == LINK_0) || (s_access == LINK_1)))
					{
						s_access = LINK_ALL;
					}

					ipm_interface_change(ctx->a.iipm_interface_status,
							     s_access);

					ctx->a.iipm_interface_status = s_access;

					if( ctx->a.iipm_interface_status != LINK_ALL )
					{
						ctx->a.iipm_preferred_side = LINK_0;
					}

					ipm_send_iipm_status(ctx);
                                }
				else
				{
				char host[IPM_MAX_HOST_SIZE];
				char target[IPM_MAX_HOST_SIZE];

					ipm_get_hostname(ctx->a.shelfid, ctx->a.my[0].ip, host);

					ipm_get_hostname(shelf, current->ip_addr[0], target);

					LOG_ERROR(NMA_OSTATUS,"IIPM Connectivity %s -> %s : %s -> %s (Access Change)",
						host,
						target,
						ipm_get_named_status(current->ln_access),
						ipm_get_named_status(s_access));
				}

				ctx->b.station_access[i] = s_access;
				current->ln_access = s_access;

				nma_substation_notify(ctx,TYPESTAACCESS,current);
			}
		}
	}
	nma_subplatform_notify(ctx,TYPEPLATFORMSTAACCESS);
	for (i = 0;i < MAX_NB_SHELF;i++)
	{
		r_access = 0;
		for (j = 0;j < MAX_NB_SHELF;j++)
		{
			if (l_access[i][j] != ctx->b.lsn_access[i][j])
			{
				ctx->b.lsn_access[i][j] = l_access[i][j];
				platformmodified = TRUE;
			}
			r_access |= (l_access[i][j] | l_access[j][i]);
		}
		ctx->b.shelf_access[i] = r_access;
	}
	if (ctx->b.shelf_access[ctx->b.station_shelfid[0]] != o_access)
	{
		nma_subplatform_notify(ctx,TYPELSNACCESS);
	}
	if (platformmodified)
	{
		nma_subplatform_notify(ctx,TYPEPLATFORMLSNACCESS);
	}
	return;
}

/******************************************/
/* Lost of links :		          */
/* add/del host routes			  */
/* notify messages to subscribers         */
/******************************************/

void nma_link_down(nma_ctx_t* ctx,station_t* station,int link)
{
	char host[IPM_MAX_HOST_SIZE];
	char target[IPM_MAX_HOST_SIZE];
	int oldstatus;

	oldstatus = station->ln_status;
	station->ln_status -= link;
	ipm_get_hostname(ctx->a.shelfid, ctx->a.my[0].ip, host);

	ipm_get_hostname(station->shelf_id, station->ip_addr[0], target);

	LOG_ERROR(NMA_OSTATUS,"IIPM Connectivity %s -> %s : %s -> %s (Link Down)",
		host,
		target,
		ipm_get_named_status(oldstatus),
		ipm_get_named_status(station->ln_status));
	station->ln_qos = (station->ln_status | (station->ln_qos & ~LINK_MASK));
	nma_substation_notify(ctx,TYPESTASTATUS,station);

}

/*************************************************/
/* Recover of links :                            */
/* start timer for waiting degraded/full if none */
/* reset timer if full                           */
/* update link status and notify messages to     */
/* subscribers if necessary                      */
/*************************************************/

void nma_link_up(nma_ctx_t* ctx,station_t* station,int link)
{
	char host[IPM_MAX_HOST_SIZE];
	char saddr[IPM_MAX_HOST_SIZE];
	int oldstatus;

	oldstatus = station->ln_status;
	if (station->ln_status == LINK_NONE)
	{
		if (station->ln_status_start == LINK_NONE)
		{
			station->ln_status_start += link;
			station->degraded_timer = 3;
			return;
		}
		else 
		{
			station->degraded_timer = 0;
		}
	}
	station->ln_status_start = LINK_NONE;
	station->ln_status = LINK_ALL;

	ipm_get_hostname(ctx->a.shelfid, ctx->a.my[0].ip, host);

	ipm_get_hostname(station->shelf_id, station->ip_addr[0], saddr);

	LOG_ERROR(NMA_OSTATUS,"IIPM Connectivity %s -> %s : %s -> %s (Link Up)",
		host,
		saddr,
		ipm_get_named_status(oldstatus),
		ipm_get_named_status(station->ln_status));

	if (!station->freeze)
	{
		station->ln_qos = station->ln_status;
		if (ctx->a.qos)
		{
			LOG_DEBUG(NMA_OSTATUS,"nma_link_up : station %s QOS set to %d",saddr,station->ln_qos);
		}
	}
	nma_substation_notify(ctx,TYPESTASTATUS,station);

}      

/******************************************/
/* End of start timer  :                  */
/* set station to DEGRADED                */
/* notify messages to subscribers         */
/* activate aliases                       */
/******************************************/

void nma_link_degraded(nma_ctx_t* ctx,station_t* station,int* flush,int* routecounter)
{
	char host[IPM_MAX_HOST_SIZE];
	char saddr[IPM_MAX_HOST_SIZE];
	int index;
	station_t* mystation;

	mystation = ctx->a.STATIONHEAD; 
	station->ln_status = station->ln_status_start;
	station->ln_qos = station->ln_status;
	station->ln_status_start = LINK_NONE;  

	ipm_get_hostname(ctx->a.shelfid, ctx->a.my[0].ip, host);

	ipm_get_hostname(station->shelf_id, station->ip_addr[0], saddr);

	LOG_ERROR(NMA_OSTATUS,"IIPM Connectivity %s -> %s : %s -> %s (Link Degraded)",
		host,
		saddr,
		ipm_get_named_status(LINK_NONE),
		ipm_get_named_status(station->ln_status));

	if ((index = nma_find_add_list(ctx,station->ip_addr[0])) == -1)
	{
		LOG_ERROR(NMA_EBADSTATION,"nma_link_degraded : station %s add in list impossible", saddr);
		return;
	}
	mystation->ln_remote[index] = station->ln_status;
	ctx->b.station_shelfid[index] = station->shelf_id;
	if (ctx->a.qos)
	{
		station->current_delay_degfull = 0;
		station->last_degraded = station->ln_status;
		station->qos_active = TRUE;
		LOG_DEBUG(NMA_OSTATUS,"nma_link_degraded : station %s QOS set to %d",saddr,station->ln_qos);
	}
	(void)nma_activate_alias(ctx,station,flush,routecounter);
	nma_substation_notify(ctx,TYPESTASTATUS,station);
}

/******************************************/
/* Check start timers  :                  */
/* decrement timers if necessary          */
/* if go through 0 , set DEGRADED         */
/******************************************/

void nma_check_degraded(nma_ctx_t* ctx,int* flush,int* compute,int* routecounter)
{
	station_t* station;
   
	if (ctx->a.STATIONHEAD == NULL)
	{
		return;
	}

	for (station = ctx->a.STATIONHEAD->next;station != NULL;station = station->next)
	{
		if ((station->degraded_timer) && (--(station->degraded_timer) == 0))
		{
			nma_link_degraded(ctx,station,flush,routecounter);
			*compute = TRUE;
		}
	}
}

/******************************************/
/* Periodic management :                  */
/* send supervision messages              */
/* credit control and link down detection */
/******************************************/

void nma_send_spv(nma_ctx_t* ctx,int credit,int* flush,int* compute,int* routecounter)
{
	station_t *station;
	station_t *mystation;
	int i,j;
	int size;
	int failed;
	int retcode;
	unsigned int* ip_alias;
	unsigned short* ip_remote;
	unsigned char* bitmap_alias;
	unsigned char* bitmap_remote;
	IPM_IPADDR *ipv6_link;
	IPM_IPADDR *ip_alias_more;
	unsigned char *bitmap_alias_more;
	int alias_num = 0;
	int alias_num_more = 0;
	int nb_station = 0;
	int index;
	int links;
#if 0
	union nos_sigval value;
#endif
	struct msgframe* msg;
	int update = FALSE;
	int add;
	char sstation[20];
  
	mystation = ctx->a.STATIONHEAD; 
	if (mystation == NULL)
	{
		return;
	}

	for (station = mystation->next;station != NULL;station = station->next)
	{
		if (credit)
		{
			for (i = 0;i < MAX_NB_DEV;i++)
			{
				if (station->ln_credit_receive[i]) station->ln_credit_receive[i]--;
				if (station->ln_credit[i]) station->ln_credit[i]--;
			}
			if ((station->ln_status == LINK_ALL) &&
				(((station->ln_credit[0] == 0) && (station->ln_credit[1] <= 1)) ||
				((station->ln_credit[1] == 0) && (station->ln_credit[0] <= 1))))
			{
				station->ln_credit[0] = 0;
				station->ln_credit[1] = 0;
			}
			if ((station->ln_credit[0] >=  ctx->b.credit-1) && 
			    (station->ln_credit[1] <= (ctx->b.credit-1)-ctx->a.credit_degraded))
			{
				station->ln_credit[1] = 0;
			}
			if ((station->ln_credit[1] >=  ctx->b.credit-1) && 
			    (station->ln_credit[0] <= (ctx->b.credit-1)-ctx->a.credit_degraded))
			{
				station->ln_credit[0] = 0;
			}
			if ((station->ln_status & LINK_0) && (station->ln_credit[0] == 0))
			{
				station->ln_credit_receive[0] = 0;
			}
			if ((station->ln_status & LINK_1) && (station->ln_credit[1] == 0))
			{
				station->ln_credit_receive[1] = 0;
			}
		}
		for (i = 0;i < MAX_NB_DEV;i++)
		{
			if (station->ln_credit_receive[i] > 0)
			{
				nb_station++;
				break;
			}
		}
	}
	ctx->b.supervision_new.frame_number++;
	if( iipm_debug == 2 )
	{
		ctx->b.supervision_new.frame_number - 1;
	}
	ctx->b.supervision_new.nb_alias = (ctx->a.nb_alias - ctx->a.nb_alias_ipv6 > MAX_NB_ALIAS_IPV4? MAX_NB_ALIAS_IPV4:ctx->a.nb_alias - ctx->a.nb_alias_ipv6);
	ctx->b.supervision_new.nb_alias_more = (ctx->a.nb_alias - ctx->a.nb_alias_ipv6 > MAX_NB_ALIAS_IPV4? ctx->a.nb_alias - MAX_NB_ALIAS_IPV4:ctx->a.nb_alias_ipv6);
	ctx->b.supervision_new.nb_remote = nb_station;
	GETTABLE(&(ctx->b.supervision_new),ip_remote,bitmap_remote,ip_alias,bitmap_alias,ipv6_link,ip_alias_more,bitmap_alias_more);
	i = 0;
	alias_num = 0;
	alias_num_more = 0;
	while (i < ctx->a.nb_alias)
	{
		if ((ctx->b.local_ipalias[i].ip.addrtype == IPM_IPV4) && (alias_num < ctx->b.supervision_new.nb_alias))
		{
			//ip_alias[i] = ctx->b.local_ipalias[i].ip;
			memcpy(&(ip_alias[alias_num]), ctx->b.local_ipalias[i].ip.ipaddr, AF_RAWIPV4SIZE);
			bitmap_alias[alias_num] = ctx->b.local_ipalias[i].links;
			alias_num++;
		}
		else if (((ctx->b.local_ipalias[i].ip.addrtype == IPM_IPV6) 
				|| ( (ctx->b.local_ipalias[i].ip.addrtype == IPM_IPV4) && (alias_num >= ctx->b.supervision_new.nb_alias)))
				&& (alias_num_more < ctx->b.supervision_new.nb_alias_more))
		{
			memcpy(&(ip_alias_more[alias_num_more]), &(ctx->b.local_ipalias[i].ip), IPM_IPADDRSIZE);
			bitmap_alias_more[alias_num_more] = ctx->b.local_ipalias[i].links;	
			alias_num_more++;
		}
		i++;
	}

	if (ipv6_link != NULL)
	{
		for (i = 0; i < MAX_NB_DEV; i++)
		{
			memcpy(&(ipv6_link[i]), &(ctx->a.my[i].link_ip), IPM_IPADDRSIZE);
		}
	}

	for (i = 0,station = mystation->next;station != NULL;station = station->next)
	{
		failed = LINK_NONE;
		links = 0;
		for (j = 0;j < MAX_NB_DEV;j++)
		{ 
			if (station->ln_credit_receive[j] > 0)
			{
				links |= (1<<(j+4));
			}
			if ((station->ln_credit[j] == 0) && (station->ln_status & (1<<j)))
			{
				failed += (1<<j);
			} 
		}
		if (failed)
		{
			char saddr[20];
			nma_link_down(ctx,station,failed);
			if ((index = nma_find_add_list(ctx,station->ip_addr[0])) == -1)
			{
				strncpy(saddr,inet_ntoa(*(struct in_addr*)(&(station->ip_addr[0]))), 19);
				saddr[19] = 0;
				LOG_ERROR(NMA_EBADSTATION,"nma_send_spv : station %s find in list impossible", saddr);
				return;
			}
			mystation->ln_remote[index] = station->ln_status;
			if (station->ln_status == LINK_NONE)
			{
				station->seq_remote = 0;
				station->seq_alias = 0;
				memset(station->ln_remote,0,ctx->a.nb_station_list);
				if (ctx->a.qos)
				{
					station->ln_credit_degfull = 0;
					station->qos_active = FALSE;
					station->freeze = FALSE;
					station->ln_qos &= LINK_MASK;
					strncpy(sstation,inet_ntoa(*(struct in_addr*)(&(station->ip_addr[0]))), 19);
					sstation[19] = 0;
					LOG_DEBUG(NMA_OSTATUS,"nma_send_spv : station %s QOS set to %d",sstation,station->ln_qos);
				}
			}
			else
			{
				if (ctx->a.qos)
				{
					if (station->qos_active)
					{
						if (station->last_degraded != (station->ln_qos & LINK_MASK))
						{
							station->ln_credit_degfull = 0;
							station->current_delay_degfull = 0;
							station->freeze = FALSE;
							station->ln_qos &= LINK_MASK;       
							strncpy(sstation,inet_ntoa(*(struct in_addr*)(&(station->ip_addr[0]))), 19);
							sstation[19] = 0;
							LOG_DEBUG(NMA_OSTATUS,"nma_send_spv : station %s QOS set to %d",sstation,station->ln_qos);
						}
						else
						{
							station->last_delay_degfull = station->current_delay_degfull;
							station->current_delay_degfull = 0;
							if (station->last_delay_degfull > ctx->b.max_credit_degfull )
							{
								add = ctx->b.max_credit_degfull;
							}
							else
							{
								if (station->last_delay_degfull <= ctx->b.min_credit_degfull)
								{
									station->last_delay_degfull = ctx->b.min_credit_degfull;
									add = (station->last_delay_degfull << minshiftdegfull) + 1;
								}
								else
								{
									add = station->last_delay_degfull + (station->last_delay_degfull >> addshiftdegfull) +
									((station->last_delay_degfull >> (addshiftdegfull - 1)) & 1) + 1;
								}
							}
							station->ln_credit_degfull += add;
							if (!station->freeze)
							{
								if (station->ln_credit_degfull > (station->last_delay_degfull << minshiftdegfull))
								{
									station->freeze = TRUE;
									station->ln_qos |= QOS_UNSTABLE;
								}
								strncpy(sstation,inet_ntoa(*(struct in_addr*)(&(station->ip_addr[0]))), 19);
								sstation[19] = 0;
								LOG_DEBUG(NMA_OSTATUS,"nma_send_spv : station %s QOS set to %d",sstation,station->ln_qos);
							}
							if (station->ln_credit_degfull > (station->last_delay_degfull << maxshiftdegfull))
								station->ln_credit_degfull = (station->last_delay_degfull << maxshiftdegfull);
						}
					}
					else
					{
						station->current_delay_degfull = 0;
						strncpy(sstation,inet_ntoa(*(struct in_addr*)(&(station->ip_addr[0]))), 19);
						sstation[19] = 0;
						LOG_DEBUG(NMA_OSTATUS,"nma_send_spv : station %s QOS set to %d",sstation,station->ln_qos);
					}
					station->qos_active = TRUE;
					station->last_degraded = station->ln_status;
				}
			}
			*compute = TRUE;
			update = TRUE;
		}
		else
		{
			if (credit)
			{
				station->current_delay_degfull++;
				if (station->ln_credit_degfull)
				{
					station->ln_credit_degfull--;
					if (station->freeze && (station->ln_credit_degfull == station->last_delay_degfull))
					{
						station->freeze = FALSE;
						station->ln_qos &= LINK_MASK;
						if (station->ln_qos != station->ln_status)
						{ 
							station->ln_qos = station->ln_status;
							update = TRUE;
						}
						strncpy(sstation,inet_ntoa(*(struct in_addr*)(&(station->ip_addr[0]))), 19);
						sstation[19] = 0;
						LOG_DEBUG(NMA_OSTATUS,"nma_send_spv : station %s QOS set to %d",sstation,station->ln_qos);
					}
					if (!station->ln_credit_degfull)
					{
						if (station->ln_qos == LINK_ALL) 
							station->qos_active = FALSE;
						else
							station->current_delay_degfull = 0;
					}
				}
			}
		}
		if (links)
		{
			ip_remote[i] = htons(ntohl(station->ip_addr[0]));
			bitmap_remote[i] = links | (station->ln_status);
			if (ctx->a.creditinframe)
			{
				bitmap_remote[i] |= ((((station->ln_credit[1] > CREDIT_MAX_FRAME)? CREDIT_MAX_FRAME:station->ln_credit[1]) << CREDIT1_SHIFT) | (((station->ln_credit[0] > CREDIT_MAX_FRAME)? CREDIT_MAX_FRAME:station->ln_credit[0]) << CREDIT0_SHIFT));
			}
			else
			{
				if (ctx->a.iipm_preferred_side == LINK_1)
				{
					bitmap_remote[i] |= 0x80;
				}
			}
			i++;
		}
	}
	if ((ctx->b.supervision_new.frame_number == 1) ||
		(ctx->b.supervision_new.nb_alias != ctx->b.supervision_old.nb_alias) ||
		(ctx->b.supervision_new.nb_alias_more != ctx->b.supervision_old.nb_alias_more) ||
		(memcmp(ip_alias,IP_ALIAS(&(ctx->b.supervision_old)),(ctx->b.supervision_new.nb_alias)*sizeof(int)) != 0) ||
		(memcmp(bitmap_alias,BITMAP_ALIAS(&(ctx->b.supervision_old)),ctx->b.supervision_new.nb_alias) != 0) ||
		((ip_alias_more != NULL) && (memcmp(ip_alias_more,IP_ALIAS_MORE(&(ctx->b.supervision_old)),(ctx->b.supervision_new.nb_alias_more)*IPM_IPADDRSIZE) != 0)) ||
		((bitmap_alias_more != NULL) && (memcmp(bitmap_alias_more,BITMAP_ALIAS_MORE(&(ctx->b.supervision_old)),ctx->b.supervision_new.nb_alias_more) != 0)))
	{
		(ctx->b.supervision_new.seq_alias)++;
		update = TRUE;
	}
	if ((ctx->b.supervision_new.frame_number == 1) ||
		(ctx->b.supervision_new.nb_remote != ctx->b.supervision_old.nb_remote) ||
		(memcmp(ip_remote,IP_REMOTE(&(ctx->b.supervision_old)),ctx->b.supervision_new.nb_remote*sizeof(short)) != 0) ||
		(memcmp(bitmap_remote,BITMAP_REMOTE(&(ctx->b.supervision_old)),ctx->b.supervision_new.nb_remote) != 0))
	{
		(ctx->b.supervision_new.seq_remote)++;
	}
	ctx->b.supervision_old = ctx->b.supervision_new;
	if (ctx->b.supervision_new.nb_alias_more == 0)
	{
		size = bitmap_remote+ctx->b.supervision_new.nb_remote-(unsigned char*)&ctx->b.supervision_new;
	}
	else
	{
		size = bitmap_alias_more+ctx->b.supervision_new.nb_alias_more - (unsigned char*)&ctx->b.supervision_new;
	}
	ctx->b.supervision_new.checksum = csum(&(ctx->b.supervision_new.version),SPVCHECKSIZE);
	if( iipm_debug == 1 )
	{
		ctx->b.supervision_new.shelfid += 0xae;
	}
#if 0 
	if ((retcode = nmacs_send(macrefspv,(char*)&(ctx->b.group_multicast),lsn & ctx->a.lsn,(unsigned char*)&(ctx->b.supervision_new),size)) != 0)
#endif
	if ((retcode = ipm_spv_send(ctx,lsn & ctx->a.lsn,(unsigned char*)&(ctx->b.supervision_new),size)) != 0)
	{
		LOG_ERROR(NMA_ENMACS,"nma_send_spv : ipm__send retcode %d",retcode);
	}
#ifdef _XMA
   if (nb_slave >= 1)
   {
      for (j = 0;j <= nb_slave;j++)
      {
         if (tab_ctx[j].a.inuse &&
             (ctx != &(tab_ctx[j])) &&
             (lsn & ctx->a.lsn & tab_ctx[j].a.lsn))
         {
            msg = malloc(sizeof(struct msgframe));
            msg->type = SUPMSG;
            memcpy(&(msg->supervision),&(ctx->b.supervision_new),size);
            msg->size = size;
            msg->links = lsn & tab_ctx[j].a.lsn;
            value.sigval_ptr = msg;
            if (nos_qsend(tab_ctx[j].b.qidspv,1,&value) == -1)
            {
               LOG_ERROR(NMA_EMSGSIMU,"nma_send_spv : nos_qsend errno %d",errno);
               free(msg);
            }
         }
      }
   }
#endif
	if (update)
	{
		(void)nma_activate_alias(ctx,NULL,flush,routecounter);
	}
	return;
}

/***************************************/
/* Supervision messages reception  :   */
/* station context handling            */
/* credit update and link up detection */
/***************************************/

void nma_rec_spv(nma_ctx_t* ctx,supervision_t* supervision,int link,int size,int local,int* flush,int* compute,int* routecounter) 
{
	station_t *station;
	station_t *mystation;
	int i,j;
	int found;
	char saddr[20];
	unsigned int* ip_alias;
	unsigned short* ip_remote;
	unsigned char* bitmap_alias;
	unsigned char* bitmap_remote;
	IPM_IPADDR *ipv6_link;
	IPM_IPADDR *ip_alias_more;
	unsigned char *bitmap_alias_more;
	int link_size; 
	int side;
	int old_status;
	int index;
	unsigned int network;
	struct msgframe* msg;
#if 0
	union nos_sigval value;
#endif
	int delta;
	unsigned short ip_local;

	mystation = ctx->a.STATIONHEAD;
	if ((ctx->a.master) && (!local))
	{
#ifdef _XMA
		if (nb_slave >= 1)
		{
			for (j = 0;j <= nb_slave;j++)
			{
				if (tab_ctx[j].a.inuse &&
					(ctx != &(tab_ctx[j])) &&
					(lsn & tab_ctx[j].a.lsn & (1 << link)))
				{
					msg = malloc(sizeof(struct msgframe));
					msg->type = SUPMSG;
					memcpy(&(msg->supervision),supervision,size);
					msg->size = size;
					msg->links = (1 << link);
					value.sigval_ptr = msg;
					if (nos_qsend(tab_ctx[j].b.qidspv,1,&value) == -1)
					{
						LOG_ERROR(NMA_EMSGSIMU,"nma_rec_spv : nos_qsend errno %d",errno);
						free(msg);
					}
				}
			}
		}
#endif
	}
	if(!(lsn & ctx->a.lsn & (1 << link)))
   	{
		return;
	}
  	if (size < SPVHEADERSIZE) 
	{
		LOG_ERROR(NMA_EBADCHECKSUM,"nma_rec_spv : bad frame size");
		return;
	}
	if (((supervision->ip_local[0]) & ctx->a.my[0].mask) != (ctx->a.my[0].ip & ctx->a.my[0].mask))
	{ 
		LOG_ERROR(NMA_EBADCHECKSUM,"nma_rec_spv : bad network supervision->ip_local: H'%x,  ctx->a.my[0].mask: H'%x, ctx->a.my[0].ip: H'%x",
			supervision->ip_local[0],
			ctx->a.my[0].mask,
			ctx->a.my[0].ip);
		return;
	}
	link_size = (supervision->nb_alias_more == 0?0:MAX_NB_DEV);
	if ((supervision->nb_alias*(sizeof(int)+1) + supervision->nb_remote*(sizeof(short)+1) + supervision->nb_alias_more*(sizeof(IPM_IPADDR)+1) + link_size*sizeof(IPM_IPADDR) + SPVHEADERSIZE) != size)
	{
		LOG_ERROR(NMA_EBADCHECKSUM,"nma_rec_spv : bad frame size");
		return;
	}  
	GETTABLE(supervision,ip_remote,bitmap_remote,ip_alias,bitmap_alias,ipv6_link,ip_alias_more,bitmap_alias_more);
	network = ntohl(ctx->a.my[0].ip & ctx->a.my[0].mask);
	if ((station = nma_find_station(ctx,supervision->ip_local[0])) == NULL)
	{
		strncpy(saddr,inet_ntoa(*(struct in_addr*)(&(supervision->ip_local[0]))), 19);
		saddr[19] = 0;
		LOG_OTHER(NMA_OCONTEXT,"nma_rec_spv : new station ip %s",saddr);
		if ((station = nma_new_station(ctx)) == NULL)
		{
			LOG_ERROR(NMA_EBADSTATION,"nma_rec_spv : station %s context creation impossible", saddr);
			return;
		}
		for (i = 0;i < MAX_NB_DEV;i++) 
		{
			station->ip_addr[i] = supervision->ip_local[i];
			if (ipv6_link != NULL)
			{
				memcpy(&(station->link_ip[i]), &(ipv6_link[i]), IPM_IPADDRSIZE);
			}
		}
		station->shelf_id = supervision->shelfid;
		nma_add_station(ctx,station);
	}
	else if (station->empty)
	{
		for (i = 0;i < MAX_NB_DEV;i++)
		{
			station->ip_addr[i] = supervision->ip_local[i];
			if (ipv6_link != NULL)
			{
				memcpy(&(station->link_ip[i]), &(ipv6_link[i]), IPM_IPADDRSIZE);
			}
		}
		station->shelf_id = supervision->shelfid;
		station->empty = FALSE;
	}
	/* when station is created, maybe link local ip address 
	 * is not ready for this station. so when it is ready, 
	 * Update it in this staion
	 */
	else if ((station->link_ip[0].addrtype != IPM_IPV6) || (station->link_ip[1].addrtype != IPM_IPV6))
	{
		if (ipv6_link != NULL)
		{
			for (i = 0;i < MAX_NB_DEV;i++)
			{
				memcpy(&(station->link_ip[i]), &(ipv6_link[i]), IPM_IPADDRSIZE);
			}
		}
	}

	delta = supervision->frame_number - station->frame_number[link];
	/*   if ((station->ln_status & (1 << link)) && (delta != 1)) */
	if (delta != 1)
	{
		strncpy(saddr,inet_ntoa(*(struct in_addr*)(&(station->ip_addr[0]))), 19);
		saddr[19] = 0;
		LOG_OTHER(NMA_EBADFRAMENUMBER,"nma_rec_spv : station %s link %d waiting %d received %d",saddr,link,(station->frame_number[link])+1,supervision->frame_number); 

		if( station->frame_number[link] > 0 &&
		    supervision->frame_number != 1 )
		{
			station->frame_number_error_count[link]++;
		}
	}
	station->frame_number[link] = supervision->frame_number;
	station->ln_credit_receive[link] = ctx->b.credit;
	old_status = station->ln_status;
	found = FALSE;
	side = LINK_0;
	ip_local = htons(ntohl(ctx->a.my[0].ip));
	for (i = 0;i < supervision->nb_remote;i++)
	{
		if (ip_local == ip_remote[i])
		{
			found = (bitmap_remote[i] & (1<<(link+4)));
			if(bitmap_remote[i] & 0x80)
			{
				side = LINK_1;
			}
			break;
		}
	}
	if (found)
	{
		station->ln_credit[link] = ctx->b.credit;
		if (((station->ln_status_start == LINK_NONE) && (station->ln_status & (1<<link)) == 0) ||
			((station->ln_status == LINK_NONE) && (station->ln_status_start & (1<< link)) == 0))
		{
			nma_link_up(ctx,station,1<<link);
		}
	}
	if (old_status != station->ln_status)
	{
		if ((index = nma_find_add_list(ctx,station->ip_addr[0])) == -1)
		{
			char saddr[20];
			strncpy(saddr,inet_ntoa(*(struct in_addr*)(&(station->ip_addr[0]))), 19);
			saddr[19] = 0;
			LOG_ERROR(NMA_EBADSTATION,"nma_rec_spv : station %s add in list impossible", saddr);
			return;
		}
		mystation->ln_remote[index] = station->ln_status;
		ctx->b.station_shelfid[index] = station->shelf_id;
		*compute = TRUE;
	}
	else if (station->side != side)
	{
		if( station->side != 0 )
		{
			char saddr[20];
			strncpy(saddr,inet_ntoa(*(struct in_addr*)(&(station->ip_addr[0]))), 19);
			saddr[19] = 0;

			LOG_ERROR(0,"nma_rec_spv : station %s supv->side 0x%x, station->side  0x%x", saddr, side, station->side);
			station->updated_side = IIPM_SIDE_UPDATE_COUNT;
		}

		station->side = side;
	}
	if (supervision->seq_remote > station->seq_remote)
	{
		memset(station->ln_remote,0,ctx->a.nb_station_list);
		for (i = 0,j = 0;i < supervision->nb_remote;i++)
		{
			
			if ((index = nma_find_add_list(ctx,htonl(network | ntohs(ip_remote[i])))) == -1)
			{
				char saddr[20];
				unsigned int temp_ip;
				temp_ip = htonl(network | ntohs(ip_remote[i]));
				strncpy(saddr,inet_ntoa(*(struct in_addr*)(&(temp_ip))),19);
				saddr[19] = 0;
				LOG_ERROR(NMA_EBADSTATION,"nma_rec_spv : station%s add in list impossible", saddr);
				return;
			}
			if (ctx->b.station_shelfid[index] == 0xff)
			{
				ctx->b.station_shelfid[index] = (ip_remote[i] & SHELF_MASK);
			}
			station->ln_remote[index] = bitmap_remote[i];
			if ((bitmap_remote[i] & LINK_ALL) == LINK_ALL) j++;
		}
		station->seq_remote = supervision->seq_remote;
		station->total_remote = supervision->nb_remote;
		station->full_remote = j;
		*compute = TRUE;
	}
	if (supervision->seq_alias > station->seq_alias) 
	{
		(void)nma_update_alias(ctx,station,supervision,flush,routecounter);
	}
	if ((supervision->seq_alias > station->seq_alias) ||
		(old_status != station->ln_status))
	{
		station->seq_alias = supervision->seq_alias;
		(void)nma_activate_alias(ctx,station,flush,routecounter);
	}
	return;
}

/*****************************/
/* Init interfaces :         */
/* get ip  interface address */
/* get network mask          */
/* get interface index       */
/* get mac interface address */
/* set multicast spv address */
/*****************************/
/* changes may need for LCP depends on how to eth0.920, eth1.921 */
int nma_init_interfaces(nma_ctx_t* ctx)
{
   struct ifreq  ifr;
   struct vlan_ioctl_args vlan;
   int i;
   char *p;

   for (i = 0;i < MAX_NB_DEV;i++) 
   {
      memset((void *)&ifr, 0, sizeof(ifr));
      strncpy(ifr.ifr_name, ctx->a.my[i].name, IFNAMSIZ-1);

      if (ioctl(inetsocket, SIOCGIFNETMASK, &ifr) < 0) 
      {
         LOG_ERROR(NMA_EIOCTL,"nma_init_interfaces : ioctl SIOCGIFNETMASK errno %d",errno);
         return(-1);
      }
      ctx->a.my[i].mask = ((*(struct sockaddr_in *)&(ifr.ifr_netmask)).sin_addr.s_addr);
      if (ioctl(inetsocket, SIOCGIFINDEX, &ifr) < 0) 
      {
         LOG_ERROR(NMA_EIOCTL,"nma_init_interfaces : ioctl SIOCGIFINDEX errno %d",errno);
         return(-1);
      }
      ctx->a.my[i].ifindex = ifr.ifr_ifindex;
      if (ioctl(inetsocket, SIOCGIFHWADDR, &ifr) < 0) 
      {
         LOG_ERROR(NMA_EIOCTL,"nma_init_interfaces : ioctl SIOCGIFHWADDR errno %d",errno);
         return(-1);
      }
      memcpy(&(ctx->a.my[i].ether),(ifr.ifr_hwaddr.sa_data),ETH_ALEN);
      if (ctx->a.master)
      {
         if (ioctl(inetsocket, SIOCGIFADDR, &ifr) < 0) 
         {
            LOG_ERROR(NMA_EIOCTL,"nma_init_interfaces : ioctl SIOCGIFADDR errno %d",errno);
            return(-1);
         }
         ctx->a.my[i].ip = ((*(struct sockaddr_in *)&(ifr.ifr_addr)).sin_addr.s_addr);
         ifr.ifr_hwaddr.sa_family = AF_UNSPEC;
         memcpy(ifr.ifr_hwaddr.sa_data,&(ctx->b.group_multicast),ETH_ALEN);
         if (ioctl(inetsocket,SIOCADDMULTI,&ifr) < 0) 
         {
            LOG_ERROR(NMA_EIOCTL,"nma_init_interfaces : ioctl SIOCADDMULTI errno %d",errno);
            return(-1);
         }
      }

      //get vlan id
      vlan.cmd = GET_VLAN_VID_CMD;

      //remove ':', which is not recognized vlan command
      p= strchr(ctx->a.my[i].name, ':');
      if(p == NULL)
      {
        strncpy(vlan.device1, ctx->a.my[i].name, 23);
        vlan.device1[23] = 0;
      }
      else
      {
        strncpy(vlan.device1, ctx->a.my[i].name, (p-ctx->a.my[i].name));
	//make sure null terminated
        vlan.device1[p-ctx->a.my[i].name] = '\0';
      }

      if(ioctl(inetsocket, SIOCGIFVLAN, (char*)&vlan) < 0)
      {
         LOG_ERROR(NMA_EIOCTL,"nma_init_interfaces : ioctl SIOCGIFVLAN errno %d",errno);
	 ctx->a.my[i].vid = -1; //invalid 
      }
      else
      {
	 ctx->a.my[i].vid = vlan.u.VID; 
      }
   }
   return(0);
}

int	IPMtimeout = 0;
void
ipm_spv_timer_handler(int sig, siginfo_t *si, void*v)
{
	IPMtimeout = 1;
}


#define IIPM_STATUS_REPORT_INTERVAL 30 * 1000/50; // every 30 secs on 50 mS interval timer


#define IPM_INTERVAL_TIMER	5 	// msec 

/********************************************************
*  Main loop						*
********************************************************/

int nma_main(nma_ctx_t* ctx)
{
	int i;
	int error;
	struct timeval time1,time2;
	int time;
	int ixtrt;
	int flush;
	int compute;
	int reccounter;
	int routecounter;

	//LCP related
	int rc;
	int retval;
	int initFinished = FALSE;
	int isNew = FALSE;
	ipm_shm_t * pShm = NULL;
	int nready;
	int maxFd = 0;
	int clientfd; //replace acceptsocket
	fd_set rset;
	fd_set eset;
	//100ms by default
	int lsn_ip_count = 0;
	int chkIfindex = FALSE;

	reccounter = 0;
	routecounter = 0;
	flush = FALSE;
	compute = FALSE;
	timer_t			tag;
	struct sigevent		sig;
	struct itimerspec	timer_spec;
	struct sigaction	act;
	sigset_t		bss;
	sigset_t		oss;
	int ipmerrno;
	static unsigned int send_iipm_status = IIPM_STATUS_REPORT_INTERVAL;
	static unsigned int pselect_error_count = 0;
	unsigned int		ticks=0;
	IPM_RULETBL 		rule_tbl;

	LOG_DEBUG(NMA_OINIT,"NMA begin of initialisation");

	install_IPMSignalHandlers();


	// Update the Unix datagram maximum queue length prior to opening CLI socket
	ipm_update_max_dgram_qlen(IPM_MAX_DGRAM_QLEN);

	// Open CLI socket 
	// check NMA IPC directory first */
	if(access(NMA_IPC_DIR, F_OK|R_OK|W_OK) != 0 )
	{
		NMA_PANIC(NULL, NMA_PFATALERROR, 
					"NMA IPC directory: %s does not exist or has wrong permission, errno= %d, %s",
					NMA_IPC_DIR,
					errno,
					strerror(errno));
	}
	else
	{
		sprintf(ctx->b.cli_socket_name,"%s/%s",NMA_IPC_DIR, NMA_SRV_NAME);
		//remove old one
		(void)unlink(ctx->b.cli_socket_name);

		ctx->b.cli_socket = ipm_init_cliSrv_socket(ctx->b.cli_socket_name);
		if (ctx->b.cli_socket < 0)
		{
			NMA_PANIC(NULL, NMA_PFATALERROR, "nma_main : ipm_init_cliSrv_socket for cli socket error");
		}
	}

	//attach shared memory
	pShm = ipm_get_shm(&isNew);
	if(pShm == NULL)
	{
		NMA_PANIC(NULL, NMA_PFATALERROR, "nma_main : create shared memory failed");
	}
	else 
	{
		//read information in shared memory
		if(isNew == FALSE)
		{
			IPM_BASE_HOOK(ctx);

			ipm_removeall_shm_rt(netlinksocket);

			//get lsn ip from shared memory
			for(i=0; i<MAX_NB_DEV; i++)
			{
				if(pShm->lsn_ip[i].alias_if[0] != '\0')
				{
					lsn_ip_count++;
				}
			}

			if(((lsn_ip_count == MAX_NB_DEV) && (IS_DUPLEX_MODE)) ||
				((lsn_ip_count == 1) && (IS_SIMPLEX_MODE)))
			{
				rc = ipm_init_interfaces(ctx, pShm->lsn_ip);
				if(rc == IPM_SUCCESS)
				{
					ipm_is_ready = 1;
				}
			}
			else 
			{
				NMA_PANIC(NULL, NMA_PFATALERROR, "only one LSN ip in share memory, share memory maybe corrupted");
			}


			//get alias information 
			if( (ctx->a.master) && (ipm_is_ready == 1) )
			{
				ctx->a.nb_alias = 0;
#if 0
				if (nma_get_alias(ctx,&(ctx->a.nb_alias),ctx->b.local_ipalias) < 0)
#endif
				if (ipm_get_alias(ctx, ctx->b.local_ipalias, pShm) != 0)
				{
					NMA_PANIC(NULL, NMA_PFATALERROR, "nma_main : ipm_get_alias error");
				}
			}
		} //end if isNew == FALSE
	} //end pShm check
 
	/* SPV TIMER SETUP BEGIN */
	rc = pthread_sigmask(SIG_SETMASK, NULL, &bss);
	if (rc != 0)
	{
		NMA_PANIC(NULL, NMA_PFATALERROR, "nma_main : pthread_sigmask error %d", errno);
	}

	sigemptyset(&bss);
	sigaddset(&bss, IPM_SIGSPVTIMER);

	memset(&act, 0, sizeof(act));
	memset(&sig, 0, sizeof(sig));
	act.sa_sigaction = ipm_spv_timer_handler;
	act.sa_flags = SA_SIGINFO | SA_RESTART;

	rc = sigaction(IPM_SIGSPVTIMER, &act, NULL);
	if (rc != 0)
	{
		NMA_PANIC(NULL, NMA_PFATALERROR, "nma_main : sigaction error %d", errno);
	}

	sig.sigev_notify = SIGEV_SIGNAL | SIGEV_THREAD_ID;
	sig._sigev_un._tid = gettid();
	sig.sigev_signo = IPM_SIGSPVTIMER;

	rc = timer_create(CLOCK_MONOTONIC, &sig, &tag);
	if (rc != 0)
	{
		NMA_PANIC(NULL, NMA_PFATALERROR, "nma_main : timer_create error %d", errno);
	}

	timer_spec.it_value.tv_sec = 0;
	timer_spec.it_value.tv_nsec = IPM_INTERVAL_TIMER * 1000 * 1000;
	timer_spec.it_interval = timer_spec.it_value;

	rc = timer_settime(tag, 0, &timer_spec, NULL);
	if (rc != 0)
	{
		NMA_PANIC(NULL, NMA_PFATALERROR, "nma_main : timer_settime error %d", errno);
	}

	while(1)
	{
		/* check if  interface names are received  or not */
		if( (!initFinished) && 
			(ipm_is_ready == 1) )
		{
			//init ctx information, like allocate
			//memory for remote alias,  create station etc
			ipm_ctx(ctx);

			initFinished = TRUE;

			if (iipm_enable)
			{
				for(i=0; i<MAX_NB_DEV; i++)
				{
					ctx->b.spv_socket[i] = crt_spv_socket(ctx, i); 
				}

				if (!ctx->a.isolated)
				{ 
					nma_send_spv(ctx,TRUE,&flush,&compute,&routecounter);
				}
			}
  
			//ipm_init_output(ctx);
   
			ctx->a.inuse = TRUE;

			retval = EIPM_read_rules(&rule_tbl);
			if (retval < 0)
			{
				ASRT_RPT(ASUNEXP_RETURN,
					0, "Failed to read rule table: retval=%d\n",
					 retval);
			}
			else
			{
				ipm_chk_host_rule(rule_tbl);
			}

			LOG_OTHER(NMA_OINIT,"NMA end of initialisation,Tspv = %d,credit = %d,degraded = %d,qos = %d,min = %d,max = %d,shelfid = %d,session = %d",
						ctx->b.psupervision,ctx->b.credit,ctx->a.credit_degraded,ctx->a.qos,ctx->b.min_credit_degfull,ctx->b.max_credit_degfull,ctx->a.shelfid,ctx->a.gnmsession);

		} //check init finished or not
	   
		FD_ZERO(&rset);
		FD_ZERO(&eset);
		maxFd = 0;

		if(ctx->b.cli_socket < 0)
		{
			ctx->b.cli_socket = ipm_init_cliSrv_socket(ctx->b.cli_socket_name);
		}

		if(ctx->b.cli_socket > 0)
		{
			FD_SET(ctx->b.cli_socket, &rset);
			FD_SET(ctx->b.cli_socket, &eset);
			maxFd = ctx->b.cli_socket;
		}

		if((iipm_enable) && (initFinished))
		{
			for(i=0; i<MAX_NB_DEV; i++)
			{
				if(ctx->b.spv_socket[i] < 0)
				{
					ctx->b.spv_socket[i] = crt_spv_socket(ctx, i);
					if(ctx->b.spv_socket[i] > 0)
					{
						chkIfindex = TRUE;
					}
				}

				if(ctx->b.spv_socket[i] > 0)
				{
					FD_SET(ctx->b.spv_socket[i], &rset);
					FD_SET(ctx->b.spv_socket[i], &eset);
				}
	   
				if( maxFd < ctx->b.spv_socket[i] )
				{
					maxFd = ctx->b.spv_socket[i];
				}
			} // end for loop

			if(chkIfindex == TRUE)
			{
				if(ipm_upd_ifindex() == 0)
				{
					chkIfindex = FALSE;
					LOG_OTHER(NMA_OSTATUS,"nma_main : base interface index update complete");
				}
			}
		} //end if iipm_enable
		else
		{
			for(i=0; i<MAX_NB_DEV; i++)
			{
				if(ctx->b.spv_socket[i] > 0)
				{
					ipm_close_socket(&(ctx->b.spv_socket[i]));
					ctx->b.spv_socket[i] = -1;
				}

			}
		}

		/* Unblock the signal in case its been raised; the
		** signal handler will be called immediately.
		*/
		rc = pthread_sigmask(SIG_UNBLOCK, &bss, NULL);
		if (rc != 0)
		{
			NMA_PANIC(NULL, NMA_PFATALERROR, "nma_main : pthread_sigmask error %d", errno);
		}
		/* Block the signal again to avoid race condition in
		** pselect
		*/
		rc = pthread_sigmask(SIG_BLOCK, &bss, &oss);
		if (rc != 0)
		{
			NMA_PANIC(NULL, NMA_PFATALERROR, "nma_main : pthread_sigmask error %d", errno);
		}
		if (IPMtimeout)
		{
			if((iipm_enable) && (initFinished))
			{
				struct timeval timeout = { 0, 0 };
				fd_set spv_rset;
				int spv_max_socketFd = 0;

				/*
				 * We've received a signal outside of pselect.  Unload any supervision frames 
				 * from the socket before processing the timeout.
				 */

				/*
				 * Only look at the supversion sockets.
				 */
				FD_ZERO(&spv_rset);

				spv_max_socketFd=0;
				for(i=0; i<MAX_NB_DEV; i++)
				{
					if(ctx->b.spv_socket[i] > 0)
					{
						FD_SET(ctx->b.spv_socket[i], &spv_rset);
					}

					if( spv_max_socketFd < ctx->b.spv_socket[i] )
					{
						spv_max_socketFd = ctx->b.spv_socket[i];
					}
				} 

				nready = pselect(spv_max_socketFd+1, &spv_rset, NULL, NULL, &timeout, NULL);

				if(nready > 0)
				{
					for(i=0; i<MAX_NB_DEV; i++)
					{
						if (ctx->b.spv_socket[i] > 0)
						{
							if (FD_ISSET(ctx->b.spv_socket[i], &spv_rset))
							{
								onRcv_spv_msg(&(ctx->b.spv_socket[i]),
												i,
												ctx->a.my[i].vid,
												&reccounter,
												&(ctx->a.my[i].checksum_error_count),
												ctx->b.proid);
								nready--;
								if(nready <= 0)
								{
									break;
								}
							} // end read set
						}
					}
				} //end for loop for spv_socket
			}
			goto nma_timeout;
		}

		/* add BFD sockets */
		(void)EIPM_bfd_fsm_add_sockets(&rset, &maxFd);

#ifndef _VHE
		/* add WCNP mcast sockets */
		(void)EIPM_wcnp_add_mcast_socket(&rset, &maxFd);
#endif

#if defined(_X86) && !defined(_VHE)
		/* add PIPM ARP/NDP sockets */
		(void)PIPM_add_arp_ndp_socket(&rset, &maxFd);
#endif		

		nready = pselect(maxFd+1, &rset, NULL, &eset, NULL, &oss);
		ipmerrno = errno;

		if(keepRunning == 0)
		{
			//exit the program
			LOG_FORCE(0, "nma_main : IPM exit.");
			exit(0);
		}

		if(nready < 0)
		{
			if(ipmerrno != EINTR)
			{
				//report error
				pselect_error_count++;

				LOG_FORCE(0,
					"nma_main: pselect error %d %s, count %d, cli %d, spv0 %d, spv1 %d, maxFd %d", 
					ipmerrno, strerror(ipmerrno), 
					pselect_error_count,
					ctx->b.cli_socket,
					ctx->b.spv_socket[0],
					ctx->b.spv_socket[1],
					maxFd);

				if(pselect_error_count > 2)
				{
					keepRunning = 0;
					LOG_FORCE(0, "IPM terminating: excessive pselect errors.");
				}

			}
			else
			{
				goto nma_timeout;
			}

			continue;
		}
		else if(nready == 0) //timeout
		{
nma_timeout:
			IPMtimeout = 0;

			ticks++;
			pselect_error_count = 0;
			gettimeofday(&time1,NULL);

			if( (iipm_enable) &&
			    (ipm_is_ready == 1) &&
			    (ticks % (ctx->b.psupervision / (IPM_INTERVAL_TIMER * 2)) == 0))
			{
				ixtrt = 6;
				ctx->a.ticks++;

				//process all nam spv msg
				process_spv_msg(ctx, &flush, &compute, &routecounter);

				nma_check_degraded(ctx,&flush,&compute,&routecounter);

				if ((ctx->a.ticks) % 2 == 0)
				{
					nma_send_spv(ctx,TRUE,&flush,&compute,&routecounter);
				}
				else
				{
					ipm_send_alarm();
					nma_subplatformtimers_update(ctx);
					nma_subplatform_notify(ctx,TYPEPLATFORMSTATS);
				}

				if ((routecounter < maxroutes) && (ctx->a.more))
				{
					(void)nma_activate_alias(ctx,NULL,&flush,&routecounter);
				}

				if (compute)
				{
					nma_compute_access(ctx);
				}

				if (ctx->a.master && flush)
				{
					LOG_OTHER(NMA_OROUTE,"nma_main : start flush");
					ipm_route_flush();
					//write(routecache,"0\n",2);
					LOG_OTHER(NMA_OROUTE,"nma_main : end flush");
				}

				//reset value for next timeout		
				reccounter = 0;
				routecounter = 0;
				flush = FALSE;
				compute = FALSE;

				if( send_iipm_status == 0 )
				{
					ipm_send_iipm_status(ctx);

					send_iipm_status = IIPM_STATUS_REPORT_INTERVAL;
				}
				else
				{
					send_iipm_status--;
				}

				if( ctx->a.iipm_preferred_side_update > 0 &&
				    ctx->a.iipm_interface_status == LINK_ALL )
				{
					if( ctx->a.iipm_preferred_side == LINK_1 )
					{
						retval = ipm_handle_alias(ctx, NULL, TRUE, LINK_1);
					}
					else
					{
						ctx->a.iipm_preferred_side = LINK_0;

						retval = ipm_handle_alias(ctx, NULL, FALSE, LINK_1);
					}

					if( retval == 0 )
					{
						ctx->a.iipm_preferred_side_update = 0;

						LOG_FORCE( 0,
							   "IPM - Updated Preferred Side to %s for %s - %s\n",
							    (ctx->a.iipm_preferred_side == LINK_1) ? "LSN1" : "LSN0",
							    ctx->a.my[0].name,
							    ctx->a.my[1].name );

					}
					else
					{
						ctx->a.iipm_preferred_side_update--;

						if( ctx->a.iipm_preferred_side_update == 0 )
						{
							unsigned char requested_side = ctx->a.iipm_preferred_side;

							ctx->a.iipm_preferred_side = LINK_0;

							(void)ipm_handle_alias(ctx, NULL, FALSE, LINK_1);

							LOG_FORCE( 0,
								   "IPM - Failed to Update Preferred Side to %s for %s - %s, reverted back to LSN0\n",
								    (requested_side == LINK_1) ? "LSN1" : "LSN0",
								    ctx->a.my[0].name,
								    ctx->a.my[1].name );

						}
					}
				}
				else
				{
					station_t *station;

					for( station = ctx->a.STATIONHEAD;station != NULL;station = station->next )
					{
						if( station->updated_side > 0 &&
						    station->ln_status == LINK_ALL &&
						  --station->updated_side == 0 )
						{
							char saddr[20];
							memset((void *)&saddr, 0, 20);
							strncpy(saddr,inet_ntoa(*(struct in_addr*)(&(station->ip_addr[0]))), 19);

							if( station->side == LINK_1 )
							{
								retval = ipm_handle_alias(ctx, station, TRUE, LINK_1);
							}
							else
							{
								retval = ipm_handle_alias(ctx, station, FALSE, LINK_1);
							}

							LOG_ERROR(0,
								"nma_main : side select change for %s station->side 0x%x, ret %d", 
								 saddr, station->side, retval);
						}
					}
				}
			} //end iipm enable

			if( eipm_enable &&
			    (ticks % (EIPM_INTERVAL_TIMER / IPM_INTERVAL_TIMER) == 0))
			{
				//process EIPM timeout code
				retval = EIPM_timeout();
				if( retval != IPM_SUCCESS )
				{
					LOG_ERROR(NMA_ESTARTSUB,"Error: nma_main - EIPM_timeout() failed, retval=%d\n", retval );
					exit( -1 );
				}
			}

			if( pipm_enable &&
			    (ticks % (PIPM_INTERVAL_TIMER / IPM_INTERVAL_TIMER) == 0))
			{
				//process PIPM timeout code
				retval = PIPM_timeout();
				if( retval != IPM_SUCCESS )
				{
					LOG_ERROR(NMA_ESTARTSUB,"Error: nma_main - PIPM_timeout() failed, retval=%d\n", retval );
					exit( -1 );
				}
			}
			//reset timeout value

			//check timeout value delay too make necessary
			//adjustment and warning if it shiftted two much
			gettimeofday(&time2,NULL);
			
			time = (time2.tv_sec-time1.tv_sec)*1000000 + time2.tv_usec-time1.tv_usec;
			if(time < 0) continue;

			if ((unsigned int)time >= hangupmax)
			{
				hangupmax = time;
				hangupmax_frames = reccounter;
				hangupmax_routes = routecounter;
				strncpy(hangupmax_trt,trt[ixtrt], 31);
				hangupmax_trt[31] = 0;
				clock_gettime(CLOCK_REALTIME,&hangupmax_date);
			}

			i = (time >> SHIFT_SLOT);
			if (i >= MAX_NB_SLOT) i = MAX_NB_SLOT-1;
			hangup[i]++;

			//warning if spent too much time 75% percent of our interval
			if (time > (IPM_INTERVAL_TIMER * 1000) * 0.75)
			{
				LOG_ERROR(NMA_ETIMEOVERRUN,"nma_main : code running over time limit %d microseconds", time);
			}

		}
		else if(nready > 0)
		{
			/* process BFD message */
			(void)EIPM_bfd_fsm_recv(&rset);
#ifndef _VHE
			/* Process WCNP alert message */
			(void)EIPM_wcnp_mcast_msg_handler(&rset);
#endif

#if defined(_X86) && !defined(_VHE)
			/* Process PIPM ARP/NDP sockets */
			(void)PIPM_process_arpndp_socket(&rset);
#endif		

			pselect_error_count = 0;
			// only process cli msg and spv msg, eipm msg will be processed at timeout
			if(ctx->b.cli_socket > 0)
			{
				if (FD_ISSET(ctx->b.cli_socket, &rset))
				{
					onRcv_cli_msg(ctx, &reccounter, &flush, &compute, &routecounter);
					nready--;
					if(nready <= 0)
					{
						continue;
					}
				} // end read set

				if (FD_ISSET(ctx->b.cli_socket, &eset))
				{
					ipm_close_socket(&(ctx->b.cli_socket));
					ctx->b.cli_socket = -1;
					nready--;
					if(nready <= 0)
					{
						continue;
					}
				}
			} //end if cli_socket

			for(i=0; i<MAX_NB_DEV; i++)
			{
				if (ctx->b.spv_socket[i] > 0)
				{
					if (FD_ISSET(ctx->b.spv_socket[i], &rset))
					{
						onRcv_spv_msg(&(ctx->b.spv_socket[i]),
										i,
										ctx->a.my[i].vid,
										&reccounter,
										&(ctx->a.my[i].checksum_error_count),
										ctx->b.proid);
						nready--;
						if(nready <= 0)
						{
							break;
						}
					} // end read set

					if (FD_ISSET(ctx->b.spv_socket[i], &eset))
					{
						ipm_close_socket(&(ctx->b.spv_socket[i]));
						ctx->b.spv_socket[i] = -1;
						nready--;
						if(nready <= 0)
						{
							break;
						}
					}
				}
			} //end for loop for spv_socket

		} //end if(nready)

	} // end LCP while 1

	return 0;
  
} //end nma_main function

/********************************************************
*  Slave NMA init					*
********************************************************/

void nma_init_slave(int i,unsigned int ip0,unsigned int ip1)
{
#ifdef _XMA
   int error;
   pthread_t thread;
   pthread_attr_t attr;

   tab_ctx[i].a.master = FALSE;
   tab_ctx[i].a.my[0].ip = ip0;
   tab_ctx[i].a.my[1].ip = ip1;
   tab_ctx[i].b.local_ipalias[0].name[0] = '\0';
   tab_ctx[i].b.local_ipalias[0].ip = tab_ctx[i].a.my[0].ip;
   tab_ctx[i].b.local_ipalias[0].mask = tab_ctx[i].a.my[0].mask;
   tab_ctx[i].b.local_ipalias[0].links = 1;
   tab_ctx[i].b.local_ipalias[1].name[0] = '\0';
   tab_ctx[i].b.local_ipalias[1].ip = tab_ctx[i].a.my[1].ip;
   tab_ctx[i].b.local_ipalias[1].mask = tab_ctx[i].a.my[1].mask;
   tab_ctx[i].b.local_ipalias[1].links = 2;
   tab_ctx[i].a.nb_alias = 2;
   nma_attr_init(&(tab_ctx[i]),&attr,90);
   if ((error = pthread_create(&thread,&attr,(void*(*)())nma_main,(void*)&(tab_ctx[i]))) != 0)
   {
     NMA_PANIC(&tab_ctx[i].a.my[0].ip,NMA_PFATALERROR,"nma_init_slave : pthread_create error %d",error);
   }
#endif
}

/********************************************************
*  Master NMA init					*
********************************************************/

void nma_init_master(void)
{
   int error;
   pthread_t thread;
   pthread_attr_t attr;

   nma_attr_init(&tab_ctx[0],&attr,90);
   if ((error = pthread_create(&thread,&attr,(void*(*)())nma_main,(void*)&tab_ctx[0])) != 0)
   {
     NMA_PANIC(&tab_ctx[0].a.my[0].ip,NMA_PFATALERROR,"nma_init_master : pthread_create error %d",error);
   }
}


/********************************************************
*  Main							*
********************************************************/

int main( int argc, char *argv[] )
{
	int i;
	int retval;
	struct timespec delay;

	// if provided, use command line arguments
	for( i = 1; i < argc; i++ )
	{
		if( strstr(argv[i], "ipm.cfg") != NULL &&
		    strlen(argv[i]) < sizeof(ipmCfgFname) )
		{
			strcpy(ipmCfgFname, argv[i]);
		}

		if( isdigit(*argv[i]) &&
		    atoi(argv[i]) >= 0 )
		{
			nma_ctx.a.shelfid = atoi(argv[i]);
		}
	}  

	//put ipm into background 
	retval = daemon(0, 0);
	if(retval != 0)
	{
		NMA_PANIC(NULL, NMA_PFATALERROR,
			"main: put ipm into daemon %d, pid:%d ",
			retval, getpid());
	}
	else
	{
		LOG_OTHER(NMA_SOINIT,
			"main: put ipm into daemon pid:%d ",
			getpid());

	}

	retval = gethostname(ipmHostName, sizeof(ipmHostName));
	if(retval != 0)
	{
		NMA_PANIC(NULL, NMA_PFATALERROR, "main: IPM gethostname failed, %d", retval);
	}

	BSPSYMTABINIT();

	/* Setup Signal Handler */
	IPM_setup_signal_handler();

	/* init configure parameter */
	ipm_cfg_init();

	/* Setup IPM directories */
	ipm_check_dirs();

	/* create a pid file */
	if(access(ipmPidDir, F_OK|R_OK|W_OK) != 0 )
	{
		NMA_PANIC(NULL, NMA_PFATALERROR,
			"main: IPM pid directory: %s does not exist or has wrong permission, errno= %d, %s",
			ipmPidDir,
			errno,
			strerror(errno));
	}
	else
	{
		char ipmPidFile[PATH_MAX];
		FILE * fp;
   		sprintf(ipmPidFile,"%s/%s.pid", ipmPidDir, basename(argv[0]));

		if((fp = fopen(ipmPidFile, "w")) == NULL)
		{
			NMA_PANIC(NULL, NMA_PFATALERROR, "main: fopen error, ipmPidFile: %s, errno= %d, %s", 
							ipmPidFile, errno, strerror(errno));
		}

		(void)fprintf(fp, "%d", getpid());
		retval = fclose(fp);
		if (retval < 0)
		{
			ASRT_RPT(ASUNEXP_RETURN, 0, "fclos failed errno %d", errno);
		}
		fp = NULL;
	}

	if ((inetsocket= socket(PF_INET,SOCK_DGRAM,0)) < 0)
	{
		NMA_PANIC(NULL,NMA_PFATALERROR,"main : open socket inetsocket errno %d",errno);
	}
	if ((netlinksocket = socket(PF_NETLINK,SOCK_RAW,NETLINK_ROUTE)) < 0)
	{
		NMA_PANIC(NULL,NMA_PFATALERROR,"main : open socket netlinksocket errno %d",errno);
	}
	retval = fcntl(netlinksocket, F_GETFL, 0);
	if (retval < 0)
	{
		NMA_PANIC(NULL, NMA_PFATALERROR, "main: fcntl(netlinksocket, F_GETFL, 0) failed,  errno %d", errno);
	}
	retval |= O_NONBLOCK;
	retval = fcntl(netlinksocket, F_SETFL, retval);
	if (retval < 0)
	{
		NMA_PANIC(NULL, NMA_PFATALERROR, "main: fcntl(netlinksocket, F_SETFL, retval) failed,  errno %d", errno);
	}

#ifdef _XMA
	if ((packetsocket = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ARP))) < 0)
	{
		NMA_PANIC(NULL,NMA_PFATALERROR,"main : open socket errno %d",errno);
	}
	if ((routecache = open("/proc/sys/net/ipv4/route/flush",O_RDWR)) < 0)
	{
		NMA_PANIC(NULL,NMA_PFATALERROR,"main : open route cache errno %d",errno);
	}
#endif
	if ((tab_ctx = malloc(sizeof(nma_ctx_t)*(nb_slave+1))) == NULL)
	{
		NMA_PANIC(NULL,NMA_PFATALERROR,"main : context table malloc error");
	}
	for (i = 0;i <= nb_slave;i++) tab_ctx[i] = nma_ctx;
	//sleep(5);

#if defined(_MIPS)

        /* Set open file descriptors limit for IPM. */
        ipm_setOpenFDLimit();

#endif /* #if defined(_MIPS) */

	// 
	// Call EIPM init function.  This HAS to be called even
	// if EIPM is not enabled since messages are processed
	// if EIPM is not enabled.
	retval = EIPM_init( );
	if( retval != IPM_SUCCESS )
	{
		NMA_PANIC(NULL,NMA_PFATALERROR,"main : EIPM_init() failed");
	}

	if (eipm_enable)
	{
		//
		// Call function to prepare for monitoring any existing 
		// interfaces if this is a process restart.
		retval = EIPM_startup( );
		if( retval != IPM_SUCCESS )
		{
			NMA_PANIC(NULL,NMA_PFATALERROR,"main : EIPM_startup() failed");
		}
	}
	
	// 
	// Call PIPM init function.  This HAS to be called even
	// if PIPM is not enabled since messages are processed
	// if PIPM is not enabled.
	retval = PIPM_init( );
	if( retval != IPM_SUCCESS )
	{
		NMA_PANIC(NULL,NMA_PFATALERROR,"main : PIPM_init() failed");
	}

	if (pipm_enable)
	{
		//
		// Call function to prepare for monitoring any existing 
		// interfaces if this is a process restart.
		retval = PIPM_startup( );
		if( retval != IPM_SUCCESS )
		{
			NMA_PANIC(NULL,NMA_PFATALERROR,"main : PIPM_startup() failed");
		}
	}

	nma_init_master();
#ifdef _XMA
	delay.tv_sec = 0;
	delay.tv_nsec = 15000000;
	for (i = 1;i <= nb_slave;i++)
	{
		nanosleep(&delay,NULL);
		nma_init_slave(i,htonl(ntohl(tab_ctx[0].a.my[0].ip & tab_ctx[0].a.my[0].mask) | (i+baseaddr)),htonl(ntohl(tab_ctx[0].a.my[1].ip & tab_ctx[0].a.my[1].mask) | (i+baseaddr)));
	}
#endif
	while (1)
	{
		sleep(100);
	}
	return(0);
}  // end main function

//may need to move ipm_init.c

int ipm_ctx(nma_ctx_t * ctx)
{
	int i;
	char name[64];
	int ret;
	station_t *station;

	if (!ctx->a.isolated)
	{
		for (i = 0;i < MAX_NB_DEV;i++)
		{
			ctx->b.supervision_new.ip_local[i] = ctx->a.my[i].ip;
			ctx->b.supervision_new.ether_local[i] = ctx->a.my[i].ether;
		}
		(void)IPM_getlinklocalv6addr(netlinksocket, ctx->a.my[0].ifindex, &(ctx->a.my[0].link_ip),ctx->a.my[1].ifindex, &(ctx->a.my[1].link_ip));
		ctx->b.supervision_new.frame_number = 0;
		ctx->b.supervision_new.shelfid = ctx->a.shelfid;
		ctx->b.supervision_new.version = 1;

		//allocate memory and init link list ctx->b.aliaspool
		if (nma_init_alias(ctx) < 0)
		{
			NMA_PANIC(&(ctx->a.my[0].ip),NMA_PFATALERROR,"nma_main : nma_init_alias error");
		}
	} //end if (!ctx->a.isolated)

	memset(ctx->b.station_list,0,sizeof(ctx->b.station_list));
	memset(ctx->b.station_access,0,sizeof(ctx->b.station_access));
	memset(ctx->b.station_shelfid,-1,sizeof(ctx->b.station_shelfid));
	memset(ctx->b.lsn_access,0,sizeof(ctx->b.lsn_access));
	memset(ctx->b.shelf_access,0,sizeof(ctx->b.shelf_access));

	ret = nma_find_add_list(ctx,ctx->a.my[0].ip);
	if (ret == -1)
	{
		NMA_PANIC(&(ctx->a.my[0].ip),NMA_PFATALERROR,"nma_main : nma_find_add_list failed");
	}
	ctx->b.station_shelfid[0] = ctx->a.shelfid;
	if ((station = nma_new_station(ctx)) == NULL)
	{
		NMA_PANIC(&(ctx->a.my[0].ip),NMA_PFATALERROR,"nma_main : station context creation impossible");
	}
	for (i = 0;i < MAX_NB_DEV;i++)
	{
		station->ip_addr[i] = ctx->a.my[i].ip;
		memcpy(&(station->link_ip[i]), &(ctx->a.my[i].link_ip), IPM_IPADDRSIZE);
	}
	station->shelf_id = ctx->a.shelfid;
	nma_add_station(ctx,station);
   	return 0;

} //end ipm_ctx
