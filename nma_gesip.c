/* File Name:
**  	glob/src/ipm/nma_gesip.c
** Description:
**	this file includes route management, ipm_cli command process etc.
**
** NOTE:
**	The file is based on Tomix NMA code
*/

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#include <net/if.h>
#include <asm/types.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>

#ifdef _XMA
#include "ncs.h"
#include "nmac.h"
#include "nnn_init.h"
#include "nos.h"
#endif
#include "nma_ctx.h"
#include "nma_pool.h"
#include "nma_log.h"
#include "nnn_socket.h"
#include "nma_route.h"

//LCP include start
#include "ipm_util.h"
#include "ipm_retval.h"

//stub for now
#define nmacs_send_pt(a,b,c,d,e)        0

extern int netlinksocket;
extern int ipm_is_ready;
extern ipm_shm_t * ipm_shm_ptr;

/******************************************/
/******************************************/
/*  REMOTE ALIASES HANDLING		  */
/******************************************/
/******************************************/

/*************************/
/* Alias pool allocation */
/*************************/

//allocate memory and create alias link list
int nma_allocate_alias(nma_ctx_t* ctx) 
POOL_ALLOCATE(nma_ipalias_dst_t,ctx->b.aliaspool)
   
/***************************/
/* Get new alias from pool */
/***************************/

//return a free element from pool
nma_ipalias_dst_t* nma_new_alias(nma_ctx_t* ctx) 
POOL_NEWELEMENT(nma_ipalias_dst_t,ctx->b.aliaspool)
   
/***************************/
/* Dispose alias to pool   */
/***************************/

//add the alias to the end of the pool
void nma_dispose_alias(nma_ctx_t* ctx,nma_ipalias_dst_t* alias) 
POOL_DISPOSEELEMENT(ctx->b.aliaspool,alias)
   
/***************************/
/* add new alias to  pool  */
/***************************/

//add alias to the head of the pool
void nma_add_alias(nma_ctx_t* ctx,nma_ipalias_dst_t* alias)
POOL_ADDELEMENT(ctx->b.aliaspool,alias)
   
/***************************/
/* delete alias from  pool */
/***************************/

void nma_del_alias(nma_ctx_t* ctx,nma_ipalias_dst_t* previous,nma_ipalias_dst_t* alias) 
POOL_REMELEMENT(nma_ipalias_dst_t,ctx->b.aliaspool,previous,alias)

/*************************/
/* Alias handling init : */
/* ioctl socket init     */
/* packet socket init    */
/* alias pool allocation */
/*************************/

int nma_init_alias(nma_ctx_t* ctx)
{
   ctx->b.aliaspool.size = MAX_REMOTE_ALIAS;
   if (nma_allocate_alias(ctx) < 0)
   {
      LOG_ERROR(NMA_EALIAS,"nma_init_alias : nma_allocate_alias error");
      return(-1);
   }      
   return(0);
}


/*****************************/
/* Find alias adress in pool */
/*****************************/

nma_ipalias_dst_t* nma_find_alias(nma_ctx_t* ctx,IPM_IPADDR ip, station_t* station)
{
   nma_ipalias_dst_t *alias;

   for (alias = ctx->b.aliaspool.head;alias != NULL;alias = alias->next)
   {
      if (IPM_IPCMPADDR(&(alias->alias_ip), &ip) == IPM_SUCCESS && station == alias->station) break;
   }
   return(alias);
}

/************************************/
/* Update alias table :  	    */
/* update alias table for a station */
/************************************/

int nma_update_alias(nma_ctx_t* ctx,station_t* station,supervision_t* supervision,int* flush,int* routecounter)
{
	int i;
	nma_ipalias_dst_t* previous;
	nma_ipalias_dst_t* alias;
	unsigned int* ip_alias;
	unsigned char* bitmap_alias;
	char sip[IPM_IPMAXSTRSIZE];
	char sstation[20];
	int error = 0;
	IPM_IPADDR * ip_alias_more;
	unsigned char * bitmap_alias_more;
	int prefix = 0;
	char links;
	int ifindex = NOPARAMETER;  //-1

	/* Do nothing in simplex mode */
	if (IS_SIMPLEX_MODE)
	{
		return IPM_SUCCESS;
	}

	ip_alias = IP_ALIAS(supervision);
	bitmap_alias = BITMAP_ALIAS(supervision);
	ip_alias_more = IP_ALIAS_MORE(supervision);
	bitmap_alias_more = BITMAP_ALIAS_MORE(supervision);

	strncpy(sstation, inet_ntoa(*(struct in_addr*)(&(station->ip_addr[0]))), 19);
	sstation[19] = 0;
	for (i = 0;i < supervision->nb_alias + supervision->nb_alias_more;i++)
	{
		IPM_IPADDR ipaddr;

		IPM_ipaddr_init(&ipaddr);
		if (i < supervision->nb_alias) 
		{
			ipaddr.addrtype = IPM_IPV4;
			memcpy(ipaddr.ipaddr, &(ip_alias[i]), AF_RAWIPV4SIZE);	
			prefix = IPM_IPV4MAXMASKLEN;
			links = bitmap_alias[i];
		}
		else
		{
			memcpy(&ipaddr, &(ip_alias_more[i - supervision->nb_alias]), IPM_IPADDRSIZE);
			links = bitmap_alias_more[i - supervision->nb_alias];
			if (ipaddr.addrtype == IPM_IPV4)
			{
				prefix = IPM_IPV4MAXMASKLEN;
			}
			else if (ipaddr.addrtype == IPM_IPV6)
			{
				prefix = IPM_IPV6MAXMASKLEN;
			}
			else
			{
				ASRT_RPT(ASBAD_DATA, 1, IPM_IPADDRSIZE, &ipaddr, "Invalid IP address type");
				continue;
			}
		}
		IPM_ipaddr2p(&ipaddr, sip, IPM_IPMAXSTRSIZE);

		if ((alias = nma_find_alias(ctx,ipaddr,station)) != 0)
		{
			alias->delete_flag = FALSE;
			{
				if (alias->inuse)
				{
					ifindex = NOPARAMETER;
					if (alias->alias_ip.addrtype == IPM_IPV6)
					{
						ifindex = ctx->a.my[alias->device_index].ifindex;
					}
					LOG_ERROR(NMA_EDUPLICATEALIAS,"nma_update_alias : duplicate alias %s",sip);
					(*routecounter)++;
					if (ipm_route_del(ifindex, "", &ipaddr, prefix, NULL, RT_TABLE_HOST) != 0)
					{
						error = -1;
					}
					else 
					{
						ipm_delete_shm_rt(netlinksocket, ipaddr, prefix);
					}
				}
				alias->station = station;
				alias->delete_flag = FALSE;
				alias->inuse = FALSE;
				alias->links = links;
			}
		}
		else
		{
			if ((alias = nma_new_alias(ctx)) == NULL)
			{
				LOG_ERROR(NMA_ENOMOREALIAS,"nma_update_alias : no more free alias");
				error = -1;
			}
			else
			{
				alias->station = station;
				alias->delete_flag = FALSE;
				alias->inuse = FALSE;
				alias->links = links;
				memcpy(&(alias->alias_ip), &ipaddr, IPM_IPADDRSIZE);

				//lcp add interface pointer
				alias->pif_t = find_matching_subnet(alias->alias_ip, 
												ctx->b.local_ipalias,
												ctx->a.nb_alias);
				nma_add_alias(ctx,alias);
				LOG_OTHER(NMA_OALIAS,"nma_update_alias : station %s create ip alias %s links %d",sstation,sip,alias->links);
			}
		}
	}

	previous = NULL;
	alias = ctx->b.aliaspool.head;
	while (alias != NULL)
	{
		IPM_ipaddr2p(&(alias->alias_ip), sip, IPM_IPMAXSTRSIZE);
		if (alias->alias_ip.addrtype == IPM_IPV4)
		{
			prefix = IPM_IPV4MAXMASKLEN;
		}
		else if (alias->alias_ip.addrtype == IPM_IPV6)
		{
			prefix = IPM_IPV6MAXMASKLEN;
		}
		else 
		{
			ASRT_RPT(ASBAD_DATA, 1, sizeof(IPM_IPADDR), &(alias->alias_ip), "Invalid addresss type");
			alias = alias->next;
			continue;
		}

		if (alias->delete_flag && (alias->station == station))
		{
			if (alias->inuse)
			{
				ifindex = NOPARAMETER;
				if (alias->alias_ip.addrtype == IPM_IPV6)
				{
					ifindex = ctx->a.my[alias->device_index].ifindex;
				}
				LOG_OTHER(NMA_OALIAS,"nma_update_alias : delete route %s",sip);
				(*routecounter)++;
				if (ipm_route_del(ifindex, "", &(alias->alias_ip), prefix, NULL, RT_TABLE_HOST) != 0) error = -1;
				else ipm_delete_shm_rt(netlinksocket, alias->alias_ip, prefix);
			}
			LOG_OTHER(NMA_OALIAS,"nma_update_alias : station %s delete ip alias %s",sstation,sip);
			nma_del_alias(ctx,previous,alias);
			if (previous == NULL)
				alias = ctx->b.aliaspool.head;
			else
				alias = previous->next;
		}
		else
		{
			alias->delete_flag = TRUE;
			previous = alias;
			alias = alias->next;
		}
	}
	return(error); 
}

/************************************/
/* Aliases activate :  	    	    */
/* activate aliases for a station   */
/************************************/

int nma_activate_alias(nma_ctx_t* ctx,station_t* station,int* flush,int* routecounter)
{
	nma_ipalias_dst_t* alias;
	int error = 0;
	int filter;
	int status;
	char sip[IPM_IPMAXSTRSIZE];
	char ifname[MAX_NLEN_DEV];
	int prefix;
	IPM_IPADDR *ipaddr_ptr;
	int retval = 0;

	/* In Simplex Mode, do nothing */
	if (IS_SIMPLEX_MODE)
	{
		return IPM_SUCCESS;
	}
	//LCP
	int ifindex = NOPARAMETER;  //-1

	//check & update ifindex
	ipm_upd_ifindex();

	filter = (station != NULL);
	alias = ctx->b.aliaspool.head;
	while (alias != NULL)
	{
		IPM_ipaddr2p(&(alias->alias_ip), sip, IPM_IPMAXSTRSIZE);
		if (alias->alias_ip.addrtype == IPM_IPV4)
		{
			prefix = IPM_IPV4MAXMASKLEN;
		}
		else if (alias->alias_ip.addrtype == IPM_IPV6)
		{
			prefix = IPM_IPV6MAXMASKLEN;
		}
		else 
		{
			ASRT_RPT(ASBAD_DATA, 1, sizeof(IPM_IPADDR), &(alias->alias_ip), "Invalid addresss type");
			alias = alias->next;
			continue;
		}

		if (!filter || (alias->station == station))
		{
			station = alias->station;
			status = station->ln_qos & LINK_MASK;

			if (alias->inuse)
			{
				if ((status == LINK_NONE) || (status & alias->failed_link))
				{
					ifindex = NOPARAMETER;
					if (alias->alias_ip.addrtype == IPM_IPV6)
					{
						ifindex = ctx->a.my[alias->device_index].ifindex;
					}
					if (ipm_route_del(ifindex, "", &(alias->alias_ip), prefix, NULL, RT_TABLE_HOST) < 0)
					{
						error = -1;
					}
					else
					{
						ipm_delete_shm_rt(netlinksocket, alias->alias_ip, prefix);
						LOG_OTHER(NMA_OALIAS,"nma_activate_alias: delete route %s",sip);
						alias->inuse = FALSE;

						(*routecounter)++;
						if ((*routecounter) >= maxroutes)
						{
							ctx->a.more = TRUE;
							return(error);
						}
					}
				}

				if ((status == LINK_1) && ((alias->links) & LINK_0))
				{
					alias->failed_link = LINK_0;
				}
				else if ((status == LINK_0) && ((alias->links) & LINK_1))
				{
					alias->failed_link = LINK_1;
				}
			}
			if (!alias->inuse)
			{
				// use pif_t to get if index, if pif_t is null 
				//check netmask with local ip alias to find a match
				// and get pif_t information, if no match found, no
				// host routing change need based on LCP arch 
				if(alias->pif_t == NULL)
				{
					alias->pif_t = find_matching_subnet(alias->alias_ip, 
														ctx->b.local_ipalias,
														ctx->a.nb_alias);
				}

				if ((status == LINK_1) && ((alias->links) & LINK_0))
				{
					alias->failed_link = LINK_0;
					if (alias->links == LINK_ALL)
					{
						if (alias->pif_t != NULL) 
						{
							memcpy(&(alias->gateway_ip), &(alias->alias_ip), IPM_IPADDRSIZE);
							alias->device_index = 1;
							//alias->source_ip = NOPARAMETER;

							ifindex = alias->pif_t->if_t[alias->device_index].ifindex;
							strncpy(ifname, alias->pif_t->if_t[alias->device_index].name, MAX_NLEN_DEV);
							retval = ipm_route_add(ifindex, ifname, 0,  &(alias->alias_ip), prefix, &(alias->gateway_ip),NULL, RT_TABLE_HOST);
							if(retval != 0)
							{
								error = -1;
								/*below block should NOT be hit before R26*/
								if(retval == EEXIST) 
								{
									if(ipm_route_del(0, "", &(alias->alias_ip), prefix, NULL, RT_TABLE_HOST) == 0) 
									{
										if(ipm_route_add(ifindex, ifname, 0,  &(alias->alias_ip), prefix, &(alias->gateway_ip),NULL, RT_TABLE_HOST)  == 0)	
										{
											//route add succeed, overwrite error
											error = 0;
											LOG_ERROR(NMA_OROUTE, "nma_activate_alias: add host route %s",sip);
											ipm_add_shm_rt(alias->alias_ip, ifname);
											alias->inuse = TRUE;
											*flush = TRUE;
											(*routecounter)++;
											if ((*routecounter) >= maxroutes)
											{
												ctx->a.more = TRUE;
												return(error);
											}
										}
									}
								}
							}
							else
							{
								LOG_OTHER(NMA_OALIAS,"nma_activate_alias: add host route %s",sip);
								ipm_add_shm_rt(alias->alias_ip, ifname);
								alias->inuse = TRUE;
								*flush = TRUE;

								(*routecounter)++;
								if ((*routecounter) >= maxroutes)
								{
									ctx->a.more = TRUE;
									return(error);
								}
							}
						}
					}
					else
					{
						if (alias->pif_t != NULL)
						{
							if (alias->alias_ip.addrtype == IPM_IPV4)
							{
								alias->gateway_ip.addrtype = IPM_IPV4;
								memcpy(alias->gateway_ip.ipaddr, &(station->ip_addr[1]), AF_RAWIPV4SIZE);
								alias->source_ip.addrtype = IPM_IPV4;
								memcpy(alias->source_ip.ipaddr, &(ctx->a.my[0].ip), AF_RAWIPV4SIZE);
							}
							else if (alias->alias_ip.addrtype == IPM_IPV6) /*use link ip as "VIA" for IPv6 currently */
							{
								memcpy(&(alias->gateway_ip), &(station->link_ip[1]), IPM_IPADDRSIZE);
								memcpy(&(alias->source_ip), &(ctx->a.my[0].link_ip), IPM_IPADDRSIZE);
							}

							//alias->device_index = NOPARAMETER;
							alias->device_index = 1;
#if 0
							if( ( alias->pif_t->if_t[0].vid == ctx->a.my[0].vid) &&
									( alias->pif_t->if_t[1].vid == ctx->a.my[1].vid) )
#endif
							{
								//ifindex = NOPARAMETER;
								//if (nma_route_add(netlinksocket, ifindex, NULL, &(alias->alias_ip), prefix, &(alias->gateway_ip),&(alias->source_ip)) != 0)
								ifindex = ctx->a.my[alias->device_index].ifindex;
								strncpy(ifname, ctx->a.my[alias->device_index].name, MAX_NLEN_DEV);
								retval = ipm_route_add(ifindex, ifname, 0, &(alias->alias_ip), prefix, &(alias->gateway_ip),NULL, RT_TABLE_HOST);
								if(retval != 0)
								{
									error = -1;
									/*below block should NOT be hit before R26*/
									if(retval == EEXIST) 
									{
										if(ipm_route_del(0, "", &(alias->alias_ip), prefix, NULL, RT_TABLE_HOST) == 0) 
										{
											if (ipm_route_add(ifindex, ifname, 0,  &(alias->alias_ip), prefix, &(alias->gateway_ip),NULL, RT_TABLE_HOST) == 0)	
											{
												//route add succeed, overwrite error
												error = 0;
												LOG_ERROR(NMA_OROUTE, "nma_activate_alias: add host route %s",sip);
												ipm_add_shm_rt(alias->alias_ip, ifname);
												alias->inuse = TRUE;
												*flush = TRUE;
												(*routecounter)++;
												if ((*routecounter) >= maxroutes)
												{
													ctx->a.more = TRUE;
													 return(error);
												}
											}
										}
									}
								}
								else
								{
									ipm_add_shm_rt(alias->alias_ip, ifname);
									LOG_OTHER(NMA_OALIAS,"nma_activate_alias: add lsn ip route %s",sip);
									alias->inuse = TRUE;
									*flush = TRUE;

									(*routecounter)++;
									if ((*routecounter) >= maxroutes)
									{
										ctx->a.more = TRUE;
										return(error);
									}
								}
							}
						} 
					}
				}
 				else if ((status == LINK_0) && ((alias->links) & LINK_1))
				{
					alias->failed_link = LINK_1;
					if (alias->links == LINK_ALL)
					{
						if(alias->pif_t != NULL) 
						{
							memcpy(&(alias->gateway_ip), &(alias->alias_ip), IPM_IPADDRSIZE);
							alias->device_index = 0;  
							//alias->source_ip = NOPARAMETER;

							ifindex = alias->pif_t->if_t[alias->device_index].ifindex;
							strncpy(ifname, alias->pif_t->if_t[alias->device_index].name, MAX_NLEN_DEV);
							retval = ipm_route_add(ifindex, ifname, 0, &(alias->alias_ip), prefix, &(alias->gateway_ip),NULL, RT_TABLE_HOST);
							if(retval != 0)
							{
								error = -1;
								/*below block should NOT be hit before R26*/
								if(retval == EEXIST) 
								{
									if(ipm_route_del(0, "", &(alias->alias_ip), prefix, NULL, RT_TABLE_HOST) == 0) 
									{
										if (ipm_route_add(ifindex, ifname, 0,  &(alias->alias_ip), prefix, &(alias->gateway_ip),NULL, RT_TABLE_HOST) == 0)	
										{
											//route add succeed, overwrite error
											error = 0;
											LOG_ERROR(NMA_OROUTE, "nma_activate_alias: add host route %s",sip);
											ipm_add_shm_rt(alias->alias_ip, ifname);
											alias->inuse = TRUE;
											*flush = TRUE;
											(*routecounter)++;
											if ((*routecounter) >= maxroutes)
											{
												ctx->a.more = TRUE;
												 return(error);
											}
										}
									}
								}
							}
							else
							{
								LOG_OTHER(NMA_OALIAS,"nma_activate_alias: add route for %s",sip);
								ipm_add_shm_rt(alias->alias_ip, ifname);
								alias->inuse = TRUE;
								*flush = TRUE;

								(*routecounter)++;
								if ((*routecounter) >= maxroutes)
								{
									ctx->a.more = TRUE;
									return(error);
								}
							}
						}
					}
					else
					{
						if (alias->pif_t != NULL)
						{
							if (alias->alias_ip.addrtype == IPM_IPV4)
							{
								alias->gateway_ip.addrtype = IPM_IPV4;
								memcpy(alias->gateway_ip.ipaddr, &(station->ip_addr[0]), AF_RAWIPV4SIZE);
								alias->source_ip.addrtype = IPM_IPV4;
								memcpy(alias->source_ip.ipaddr, &(ctx->a.my[1].ip), AF_RAWIPV4SIZE);
							}
							else if (alias->alias_ip.addrtype == IPM_IPV6)
							{
								memcpy(&(alias->gateway_ip), &(station->link_ip[0]), IPM_IPADDRSIZE);
								memcpy(&(alias->source_ip), &(ctx->a.my[1].link_ip), IPM_IPADDRSIZE);
							}

							//alias->device_index = NOPARAMETER;
							alias->device_index = 0;
#if 0
							if( ( alias->pif_t->if_t[0].vid == ctx->a.my[0].vid) &&
									( alias->pif_t->if_t[1].vid == ctx->a.my[1].vid) )
#endif
							{
								//ifindex = NOPARAMETER;
								//if (nma_route_add(netlinksocket, ifindex, NULL, &(alias->alias_ip), prefix, &(alias->gateway_ip),&(alias->source_ip)) != 0)
								ifindex = ctx->a.my[alias->device_index].ifindex;
								strncpy(ifname, ctx->a.my[alias->device_index].name, MAX_NLEN_DEV);
								retval = ipm_route_add(ifindex, ifname, 0, &(alias->alias_ip), prefix, &(alias->gateway_ip),NULL, RT_TABLE_HOST);
								if(retval != 0)
								{
									error = -1;
									/*below block should NOT be hit before R26*/
									if(retval == EEXIST) 
									{
										if(ipm_route_del(0, "", &(alias->alias_ip), prefix, NULL, RT_TABLE_HOST) == 0) 
										{
											if (ipm_route_add(ifindex, ifname, 0,  &(alias->alias_ip), prefix, &(alias->gateway_ip),NULL, RT_TABLE_HOST) == 0)	
											{
												//route add succeed, overwrite error
												error = 0;
												LOG_ERROR(NMA_OROUTE, "nma_activate_alias: add host route %s",sip);
												ipm_add_shm_rt(alias->alias_ip, ifname);
												alias->inuse = TRUE;
												*flush = TRUE;
												(*routecounter)++;
												if ((*routecounter) >= maxroutes)
												{
													ctx->a.more = TRUE;
													 return(error);
												}
											}
										}
									}
								}
								else
								{
									ipm_add_shm_rt(alias->alias_ip, ifname);
									LOG_OTHER(NMA_OALIAS,"nma_activate_alias: add lsn ip route %s",sip);
									alias->inuse = TRUE;
									*flush = TRUE;

									(*routecounter)++;
									if ((*routecounter) >= maxroutes)
									{
										ctx->a.more = TRUE;
										return(error);
									}
								}
							}
						} 
					}
				}
			}
		}
		alias = alias->next;
	}
	if( !filter )
	{
		ctx->a.more = FALSE;
	}
	return(error);
}

/******************************************/
/******************************************/
/*  LOCAL ALIASES HANDLING		  */
/******************************************/
/******************************************/

/****************************/
/* Get ip alias addresses : */
/* ioctl SIOCGIFCONF        */
/* ioctl SIOCGIFADDR        */
/* ioctl SIOCGIFNETMASK     */
/****************************/

//get all interface information from ioctl when NMA started, will not be used
// in LCP, LCP will get all alias from shared memory, ipm_get_alias() 
int nma_get_alias(nma_ctx_t* ctx,int* nb_alias,nma_ipalias_local_t* aliaslist)
{
#ifdef _XMA
	struct ifreq* ifr;
	struct ifconf ifc;
	int i,j,k;
	int n;
	int links;
	nma_ipalias_local_t tempolist[(*nb_alias)*2];
	int max;
	char* p;

	max = *nb_alias;
	ifc.ifc_req = ctx->b.ifrbuf;
	ifc.ifc_len = sizeof(ctx->b.ifrbuf);
	if (ioctl(inetsocket,SIOCGIFCONF,(char*)&ifc) < 0)
	{
		LOG_ERROR(NMA_EIOCTL,"nma_get_alias : ioctl SIOCGIFCONF errno %d",errno);
		return(-1);
	}
	n = ifc.ifc_len/sizeof(struct ifreq);
	for (i = 0,k = 0,ifr = ifc.ifc_req;i < n;i++,ifr++)
	{
		if (ifr->ifr_addr.sa_family != AF_INET) continue;
		links = LINK_NONE;
		for (j = 0;j < MAX_NB_DEV;j++)
		{
			if (strncmp(ifr->ifr_name,ctx->a.my[j].name,strlen(ctx->a.my[j].name)) == 0)
			{
				links = (1<<j);
				break;
			}
		}
		if (links == LINK_NONE) continue;
		if ((p = strchr(ifr->ifr_name,'.')) != NULL)
		{
			continue;
		}      
		else 
	if ((p = strchr(ifr->ifr_name,':')) != NULL)
      {
         if (*(p+1) == '-')
	 {
	    continue;
	 }
	 else
	 {
            if (k >= 2*max)
            {
               LOG_ERROR(NMA_EALIAS,"nma_get_alias : too much local ip alias ...");
               return(-1);
            }
	    strncpy(tempolist[k].name,p+1, MAX_NLEN_DEV-1);
	    tempolist[k].name[MAX_NLEN_DEV-1] = 0;
	 }
      }
      else
      {
         if (k >= 2*max)
         {
            LOG_ERROR(NMA_EALIAS,"nma_get_alias : too much local ip alias ...");
            return(-1);
         }
	 tempolist[k].name[0] = '\0';
      }
      tempolist[k].links = links;
      if (ioctl(inetsocket,SIOCGIFADDR,(char*)ifr) < 0)
      {
         LOG_ERROR(NMA_EIOCTL,"nma_get_alias : ioctl SIOCGIFADDR errno %d",errno);
         return(-1);
      }
      tempolist[k].ip = ((struct sockaddr_in*)(&(ifr->ifr_addr)))->sin_addr.s_addr;
      if (ioctl(inetsocket,SIOCGIFNETMASK,(char*)ifr) < 0)
      {
         LOG_ERROR(NMA_EIOCTL,"nma_get_alias : ioctl SIOCGIFNETMASK errno %d",errno);
         return(-1);
      }
      tempolist[k++].mask = ((struct sockaddr_in*)(&(ifr->ifr_netmask)))->sin_addr.s_addr;
   }
   for (i = 0,*nb_alias = 0;i < k;i++)
   {
      if (tempolist[i].links != LINK_NONE)
      {
         for (j = i+1;j < k;j++)
         {
            if ((tempolist[i].ip == tempolist[j].ip) &&
                (tempolist[i].mask == tempolist[j].mask) &&
                (strcmp(tempolist[i].name,tempolist[j].name) == 0))
            {
               tempolist[i].links += tempolist[j].links;
               tempolist[j].links = LINK_NONE;
            }
         }
         if ((*nb_alias) >= max)
         {
            LOG_ERROR(NMA_EALIAS,"nma_get_alias : too much local ip alias ...");
            return(-1);
         }
         aliaslist[(*nb_alias)++] = tempolist[i];
      }
   }
#endif
   return(0);
}

/************************************/
/* Configure local alias :  	    */
/* configure alias		    */
/************************************/

//for testing, non master only
int nma_config_alias(nma_ctx_t* ctx,unsigned int ip,unsigned int mask,int links,char* name)
{ 
   int i;
   char NETWORK[20];
   char NETMASK[20];
   struct ifreq ifr;

   strncpy(NETWORK,inet_ntoa(*(struct in_addr*)(&ip)), 19);
   NETWORK[19] = 0;
   strncpy(NETMASK,inet_ntoa(*(struct in_addr*)(&mask)), 19);
   NETMASK[19] = 0;
   ((struct sockaddr_in*)(&(ifr.ifr_dstaddr)))->sin_family = AF_INET;
   for (i = 0;i < MAX_NB_DEV;i++)
   {
      if (links & (1 << i))
      {
         sprintf(ifr.ifr_name,"%s:%s",ctx->a.my[i].name,name);
         ((struct sockaddr_in*)(&(ifr.ifr_dstaddr)))->sin_addr.s_addr = ip;
         if (ioctl(inetsocket,SIOCSIFADDR,(char*)&ifr) < 0)
         {
            LOG_ERROR(NMA_EIOCTL,"nma_config_alias : ioctl SIOCSIFADDR %s %s %s , errno %d",ifr.ifr_name,NETWORK,NETMASK,errno);
            return(IPM_SETIFADDR);
         }
         ((struct sockaddr_in*)(&(ifr.ifr_netmask)))->sin_addr.s_addr = mask;
         if (ioctl(inetsocket,SIOCSIFNETMASK,(char*)&ifr) < 0)
         {
            LOG_ERROR(NMA_EIOCTL,"nma_config_alias : ioctl SIOCSIFNETMASK %s %s %s , errno %d",ifr.ifr_name,NETWORK,NETMASK,errno);
            return(IPM_SETIFNETMASK);
         }
         ((struct sockaddr_in*)(&(ifr.ifr_broadaddr)))->sin_addr.s_addr = ip | (~mask);
         if (ioctl(inetsocket,SIOCSIFBRDADDR,(char*)&ifr) < 0)
         {
            LOG_ERROR(NMA_EIOCTL,"nma_config_alias : ioctl SIOCSIFBRDADDR %s %s %s , errno %d",ifr.ifr_name,NETWORK,NETMASK,errno);
            return(IPM_SETIFBRDADDR);
         }
      }
   }
   return(0);
}

/************************************/
/* Create local alias :  	    */
/* create alias			    */
/* add in local list		    */
/* send gratuitous ARP		    */
/************************************/

//LCP will not use this function, since LCP will plumb the ip from ip utility
//tool, not from NMA/ipm, the LCP equivalent function is: ipm_add_one_alias
 
int nma_create_alias(nma_ctx_t* ctx,unsigned int ip,unsigned int mask,int links,char* name,int max,int* nb_alias,nma_ipalias_local_t* aliaslist)
{ 
#ifdef _XMA
   struct ifreq ifr;
   int i;
   char NETWORK[20];
   char NETMASK[20];
   struct ether_arp arp;
   char dst[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

   if (name[0] == '\0')
   {
      LOG_ERROR(NMA_EALIAS,"nma_create_alias : primary addresses forbidden");
      return(IPM_PRIMARYFORBIDDEN);
   }
   if (*nb_alias >= max) 
   {
      LOG_ERROR(NMA_EALIAS,"nma_create_alias : too much local ip alias ...");
      return(IPM_TOOMUCHALIAS);
   }
   if (links == LINK_NONE)
   {
      LOG_ERROR(NMA_EALIAS,"nma_create_alias : no configured links for alias ...");
      return(IPM_BADLSNNUMBER);
   }

   strncpy(NETWORK,inet_ntoa(*(struct in_addr*)(&ip)), 19);
   NETWORK[19] = 0;
   strncpy(NETMASK,inet_ntoa(*(struct in_addr*)(&mask)), 19);
   NETMASK[19] = 0;
   for (i = 0;i < *nb_alias;i++)
   { 
      if (((strcmp(aliaslist[i].name,name) == 0) && (aliaslist[i].links & links)) || (aliaslist[i].ip == ip))
      {
         LOG_ERROR(NMA_EALIAS,"nma_create_alias : name %s , ip %s already exists",name,NETWORK);
         return(IPM_ALIASALREADYKNOWN);
      }
   }
   ((struct sockaddr_in*)(&(ifr.ifr_dstaddr)))->sin_family = AF_INET;
   for (i = 0;i < MAX_NB_DEV;i++)
   {
      if (links & (1 << i))
      {
         sprintf(ifr.ifr_name,"%s:%s",ctx->a.my[i].name,name);
         ((struct sockaddr_in*)(&(ifr.ifr_dstaddr)))->sin_addr.s_addr = ip;
         if (ioctl(inetsocket,SIOCSIFADDR,(char*)&ifr) < 0)
         {
            LOG_ERROR(NMA_EIOCTL,"nma_create_alias : ioctl SIOCSIFADDR %s %s %s , errno %s",ifr.ifr_name,NETWORK,NETMASK,strerror(errno));
            return(IPM_SETIFADDR);
         }
         ((struct sockaddr_in*)(&(ifr.ifr_netmask)))->sin_addr.s_addr = mask;
         if (ioctl(inetsocket,SIOCSIFNETMASK,(char*)&ifr) < 0)
         {
            LOG_ERROR(NMA_EIOCTL,"nma_create_alias : ioctl SIOCSIFNETMASK %s %s %s , errno %s",ifr.ifr_name,NETWORK,NETMASK,strerror(errno));
            return(IPM_SETIFNETMASK);
         }
         ((struct sockaddr_in*)(&(ifr.ifr_broadaddr)))->sin_addr.s_addr = ip | (~mask);
         if (ioctl(inetsocket,SIOCSIFBRDADDR,(char*)&ifr) < 0)
         {
            LOG_ERROR(NMA_EIOCTL,"nma_create_alias : ioctl SIOCSIFBRDADDR %s %s %s , errno %s",ifr.ifr_name,NETWORK,NETMASK,strerror(errno));
            return(IPM_SETIFBRDADDR);
         }
      }
   }
   strncpy(aliaslist[*nb_alias].name, name, MAX_NLEN_DEV-1);
   aliaslist[*nb_alias].name[MAX_NLEN_DEV-1] = 0;
   aliaslist[*nb_alias].ip = ip;
   aliaslist[*nb_alias].mask = mask;
   aliaslist[*nb_alias].links = links;
   LOG_OTHER(NMA_OALIAS,"nma_create_alias : name %s , ip %s , mask %s , links %d",
   aliaslist[*nb_alias].name,
   NETWORK,
   NETMASK,
   aliaslist[*nb_alias].links);
   (*nb_alias)++;
   for (i = 0;i < MAX_NB_DEV;i++)
   {
      if (links & (1 << i))
      {
	 memset(&arp,0,sizeof(arp));
	 arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
	 arp.ea_hdr.ar_pro = htons(ETH_P_IP);
	 arp.ea_hdr.ar_hln = ETH_ALEN;
	 arp.ea_hdr.ar_pln = 4;
	 arp.ea_hdr.ar_op = htons(ARPOP_REQUEST);
         memcpy(arp.arp_sha,&(ctx->a.my[i].ether),ETH_ALEN);
	 memcpy(arp.arp_spa, &ip,4);
	 memset(arp.arp_tha,0xFF,ETH_ALEN);
	 memcpy(arp.arp_tpa,&ip,4);
         if (nmacs_send_pt(ETH_P_ARP,dst,links & (1 << i),(char*)&arp,sizeof(arp)) < 0)
         {
            LOG_ERROR(NMA_ESEND,"nma_create_alias : nmacs errno %s",strerror(errno));
            /* return(SENDGRATUITOUSARP); */
         }
      }
   }
#endif
   return(0);
}

/***************************************/
/* New local ip alias management  :    */
/***************************************/

//from NMA cli, not used for LCP, lcp get command from ipm_cli
int nma_set_alias(nma_ctx_t* ctx,unsigned int ip,unsigned int mask,int links,char* name,int immediate)
{
   int error;
   int flush = FALSE;
   int compute = FALSE;
   int routecounter = 0;

   if ((error = nma_create_alias(ctx,ip,mask,links,name,MAX_NB_ALIAS,&(ctx->a.nb_alias),ctx->b.local_ipalias)) != 0)
   {
      return(error);
   }
   if (immediate) nma_send_spv(ctx,FALSE,&flush,&compute,&routecounter);
   if (ctx->a.master && immediate)
   {
      write(routecache,"0\n",2);
   }
   return(0);
}

/************************************/
/* Delete local alias :  	    */
/* delete alias			    */
/* del in local list		    */
/************************************/

//not used by LCP, LCP receive the command from ipm_cli, and LCP ipm does
// not need bring down the interface. the code call ipm_cli will bring the 
// interface down after receive the ack from ipm  
int nma_delete_alias(nma_ctx_t* ctx,unsigned int ip,int* nb_alias,nma_ipalias_local_t* aliaslist)
{ 
#ifdef _XMA
   struct ifreq ifr;
   int i,j,index;
   char NETWORK[20];
   char NETMASK[20];

   memeset((void *)NETWORK, 0 , 20);
   memeset((void *)NETMASK, 0 , 20);
   for (index = 0;index < *nb_alias;index++) 
      if (aliaslist[index].ip == ip) break;
   if (index >= *nb_alias)
   {
      strncpy(NETWORK,inet_ntoa(*(struct in_addr*)&ip), 19);
      LOG_ERROR(NMA_EALIAS,"nma_delete_alias : local ip alias %s unknown",NETWORK);
      return(IPM_ALIASUNKNOWN);
   }
   if (aliaslist[index].name[0] == '\0')
   {
      LOG_ERROR(NMA_EALIAS,"nma_set_alias : primary addresses forbidden");
      return(IPM_PRIMARYFORBIDDEN);
   }
   strncpy(NETWORK,inet_ntoa(*(struct in_addr*)&(aliaslist[index].ip)), 19);
   strncpy(NETMASK,inet_ntoa(*(struct in_addr*)&(aliaslist[index].mask)), 19);
   LOG_OTHER(NMA_OALIAS,"nma_delete_alias : name %s , ip %s , mask %s , links %d",
   aliaslist[index].name,
   NETWORK,
   NETMASK,
   aliaslist[index].links);
   for (i = 0;i < MAX_NB_DEV;i++)
   {
      if (aliaslist[index].links & (1 << i))
      {
         sprintf(ifr.ifr_name,"%s:%s",ctx->a.my[i].name,aliaslist[index].name);
         if (ioctl(inetsocket,SIOCGIFFLAGS,(char*)&ifr) == -1)
         {
            strncpy(NETWORK,inet_ntoa(*(struct in_addr*)(&ip)), 19);
            LOG_ERROR(NMA_EIOCTL,"nma_delete_alias : ioctl SIOCGIFFLAGS %s %s , errno %d",ifr.ifr_name,NETWORK,errno);
            return(IPM_GETIFFLAGS);
         }
         ifr.ifr_flags &= ~IFF_UP;
         if (ioctl(inetsocket,SIOCSIFFLAGS,(char*)&ifr) < 0)
         {
            strncpy(NETWORK,inet_ntoa(*(struct in_addr*)(&ip)), 19);
            LOG_ERROR(NMA_EIOCTL,"nma_delete_alias : ioctl SIOCSIFFLAGS %s %s , errno %d",ifr.ifr_name,NETWORK,errno);
            return(IPM_SETIFFLAGS);
         }
      }
   }
   for (i = 0,j = 0;i < *nb_alias;i++)
   {
      if (i == index) continue;
      aliaslist[j++]=aliaslist[i];
   }
   *nb_alias = j;
#endif
   return(0);
}

/***************************************/
/* local ip alias delete management  : */
/***************************************/
//NMA cli, not used by LCP
int nma_unset_alias(nma_ctx_t* ctx,unsigned int ip,int immediate)
{
   int error;
   int flush = FALSE;
   int compute = FALSE;
   int routecounter = 0;
   
   if ((error = nma_delete_alias(ctx,ip,&(ctx->a.nb_alias),ctx->b.local_ipalias)) != 0)
   {
      return(error);
   }
   if (immediate)
   { 
      nma_send_spv(ctx,FALSE,&flush,&compute,&routecounter);
   }
   if (ctx->a.master && immediate)
   {
      write(routecache,"0\n",2);
   }
   return(0);
}

/************************************/
/* Secure local alias :  	    */
/* add in local list		    */
/* send gratuitous ARP		    */
/************************************/

int nma_secure_alias(nma_ctx_t* ctx,IPM_IPADDR ip,IPM_IPADDR mask,int links,char* name,ipm_paired_if_t *pif, int max,int* nb_alias,nma_ipalias_local_t* aliaslist)
{ 
   int i;
   char NETWORK[IPM_IPMAXSTRSIZE];
   char NETMASK[IPM_IPMAXSTRSIZE];
#ifdef _XMA
   struct ether_arp arp;
   char dst[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

   if (name[0] == '\0')
   {
      LOG_ERROR(NMA_EALIAS,"nma_secure_alias : primary addresses forbidden");
      return(IPM_PRIMARYFORBIDDEN);
   }
#endif
   if (*nb_alias >= max) 
   {
      LOG_ERROR(NMA_EALIAS,"nma_secure_alias : too much local ip alias ...");
      return(IPM_TOOMUCHALIAS);
   }
   if (links == LINK_NONE)
   {
      LOG_ERROR(NMA_EALIAS,"nma_secure_alias : no configured links for alias ...");
      return(IPM_BADLSNNUMBER);
   }

   if((ip.addrtype != IPM_IPV4) && (ip.addrtype != IPM_IPV6))
   {
      LOG_ERROR(NMA_EALIAS,"nma_secure_alias : invalid ip address");
      return(IPM_ALIASUNKNOWN);
   }

   IPM_ipaddr2p(&ip, NETWORK, IPM_IPMAXSTRSIZE);
   IPM_ipaddr2p(&mask, NETMASK, IPM_IPMAXSTRSIZE);
   for (i = 0;i < *nb_alias;i++)
   {
#ifdef _XMA
      if (((strcmp(aliaslist[i].name,name) == 0) && (aliaslist[i].links & links)) || (aliaslist[i].ip == ip))
      {
         LOG_ERROR(NMA_EALIAS,"nma_secure_alias : name %s , ip %s already exists",name,NETWORK);
         return(IPM_ALIASALREADYKNOWN);
      }
#endif

      if ( IPM_IPCMPADDR(&(aliaslist[i].ip), &ip) == IPM_SUCCESS)
      {
      	if (aliaslist[i].links == LINK_ALL)
	{
          return(IPM_ALIASALREADYKNOWN);
	}
	
      	if ((aliaslist[i].links |= links) != LINK_ALL)
	{
           return(IPM_ALIASALREADYKNOWN);
	}
	
	return 0;
      }
   }
   strncpy(aliaslist[*nb_alias].name, name, MAX_NLEN_DEV-1);
   aliaslist[*nb_alias].name[MAX_NLEN_DEV-1] = 0;
   memcpy(&(aliaslist[*nb_alias].ip), &ip, IPM_IPADDRSIZE);
   memcpy(&(aliaslist[*nb_alias].mask), &mask, IPM_IPADDRSIZE);
   aliaslist[*nb_alias].links = links;
   aliaslist[*nb_alias].pif_t = pif;
   LOG_OTHER(NMA_OALIAS,"nma_secure_alias : name %s , ip %s , mask %s , links %d",
   aliaslist[*nb_alias].name,
   NETWORK,
   NETMASK,
   aliaslist[*nb_alias].links);
   (*nb_alias)++;
   if (ip.addrtype == IPM_IPV6) ctx->a.nb_alias_ipv6++;
#ifdef _XMA
   for (i = 0;i < MAX_NB_DEV;i++)
   {
      if (links & (1 << i))
      {
	 memset(&arp,0,sizeof(arp));
	 arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
	 arp.ea_hdr.ar_pro = htons(ETH_P_IP);
	 arp.ea_hdr.ar_hln = ETH_ALEN;
	 arp.ea_hdr.ar_pln = 4;
	 arp.ea_hdr.ar_op = htons(ARPOP_REQUEST);
         memcpy(arp.arp_sha,&(ctx->a.my[i].ether),ETH_ALEN);
	 memcpy(arp.arp_spa, &ip,4);
	 memset(arp.arp_tha,0xFF,ETH_ALEN);
	 memcpy(arp.arp_tpa,&ip,4);
         if (nmacs_send_pt(ETH_P_ARP,dst,links & (1 << i),(char*)&arp,sizeof(arp)) < 0)
         {
            LOG_ERROR(NMA_ESEND,"nma_secure_alias : nmacs errno %d",errno);
            /* return(SENDGRATUITOUSARP); */
         }
      }
   }
#endif
   return(0);
}

/***************************************/
/* local ip alias management  :        */
/***************************************/

int nma_manage_alias(nma_ctx_t* ctx,IPM_IPADDR ip,IPM_IPADDR mask,int links,char* name,ipm_paired_if_t *pif, int immediate)
{
   int error;
   int flush = FALSE;
   int compute = FALSE;
   int routecounter = 0;

   if ((error = nma_secure_alias(ctx,ip,mask,links,name,pif, MAX_NB_ALIAS,&(ctx->a.nb_alias),ctx->b.local_ipalias)) != 0)
   {
      return(error);
   }
   if (immediate) nma_send_spv(ctx,FALSE,&flush,&compute,&routecounter);
   return(0);
}


/************************************/
/* Unsecure local alias :  	    */
/* del in local list		    */
/************************************/

int nma_unsecure_alias(nma_ctx_t* ctx,IPM_IPADDR ip,int* nb_alias,nma_ipalias_local_t* aliaslist)
{ 
   int i,j,index;
   char NETWORK[IPM_IPMAXSTRSIZE];
   char NETMASK[IPM_IPMAXSTRSIZE];

   for (index = 0;index < *nb_alias;index++) 
   {
      if (IPM_IPCMPADDR(&(aliaslist[index].ip), &ip) == IPM_SUCCESS) 
      {
         break;
      }
   }
   if (index >= *nb_alias)
   {
      IPM_ipaddr2p(&ip, NETWORK, IPM_IPMAXSTRSIZE);
      LOG_ERROR(NMA_EALIAS,"nma_unsecure_alias : local ip alias %s unknown",NETWORK);
      return(IPM_SUCCESS);
   }
   if (aliaslist[index].name[0] == '\0')
   {
      LOG_ERROR(NMA_EALIAS,"nma_unsecure_alias : primary addresses forbidden");
      return(IPM_PRIMARYFORBIDDEN);
   }
   IPM_ipaddr2p(&(aliaslist[index].ip), NETWORK, IPM_IPMAXSTRSIZE);
   IPM_ipaddr2p(&(aliaslist[index].mask), NETMASK, IPM_IPMAXSTRSIZE);
   LOG_OTHER(NMA_OALIAS,"nma_unsecure_alias : name %s , ip %s , mask %s , links %d",
   aliaslist[index].name,
   NETWORK,
   NETMASK,
   aliaslist[index].links);
   for (i = 0,j = 0;i < *nb_alias;i++)
   {
      if (i == index) continue;
      aliaslist[j++]=aliaslist[i];
   }
   *nb_alias = j;
   if (ip.addrtype == IPM_IPV6) ctx->a.nb_alias_ipv6--;
   return(0);
}

/***************************************/
/* local ip alias unmanagement  :      */
/***************************************/

int nma_unmanage_alias(nma_ctx_t* ctx,IPM_IPADDR ip,int immediate)
{
   int error;
   int flush = FALSE;
   int compute = FALSE;
   int routecounter = 0;
   
   if ((error = nma_unsecure_alias(ctx,ip,&(ctx->a.nb_alias),ctx->b.local_ipalias)) != 0)
   {
      return(error);
   }
   if (immediate)
   { 
      nma_send_spv(ctx,FALSE,&flush,&compute,&routecounter);
   }
   return(0);
}

//get alias information from shared memory at init time
int ipm_get_alias(nma_ctx_t* ctx,
		nma_ipalias_local_t* aliaslist,
		ipm_shm_t * ipm_shm_ptr)
{
   int i;
   int rc;
   int l_ifindex, r_ifindex, pif_index;
   IPM_IPADDR mask;
   IPM_IPADDR network;

   //get paired interface
   l_ifindex = ctx->a.my[0].ifindex;
   r_ifindex = ctx->a.my[1].ifindex;
   pif_index = ipm_get_pif(l_ifindex, r_ifindex, ipm_shm_ptr->ipm_pif, ipm_shm_ptr->ipm_pif_nb);

   if (pif_index < 0)
   {
	    LOG_ERROR(NMA_SEMSGSOCKET, "%s: did not find paired interface for lsn ip %s %s\n",
		__FUNCTION__,
		ipm_shm_ptr->lsn_ip[0].alias_if,
		ipm_shm_ptr->lsn_ip[1].alias_if);

	    return -1;
   }

   for (i = 0; i < MAX_NB_DEV; i++)
   {
	if (ipm_shm_ptr->lsn_ip[i].alias_if[0] == '\0')
	{
		continue;
	}

	rc = IPM_p2ipaddr(ipm_shm_ptr->lsn_ip[i].ip, &network);
	if (rc != IPM_SUCCESS)
	{
            continue;
	}
        rc = IPM_ipmkmask(&mask, network.addrtype, ipm_shm_ptr->lsn_ip[i].prefix); 
        if (rc != IPM_SUCCESS)
        {
            continue;
        }

	//need one more field for interface index
    	rc = nma_manage_alias(ctx,
		network,
		mask,
		1<<i,
		ipm_shm_ptr->lsn_ip[i].alias_if,
		&(ipm_shm_ptr->ipm_pif[pif_index]),
		0);
	if (rc != 0)
	{
		return rc;
	}
   }

   for(i=0; i < ipm_shm_ptr->alias_ip_nb; i++)
   {

      rc = nma_manage_alias(ctx, 
		ipm_shm_ptr->alias_ip[i].ip,
		ipm_shm_ptr->alias_ip[i].mask,
		ipm_shm_ptr->alias_ip[i].links,
                ipm_shm_ptr->alias_ip[i].name[0],
		&(ipm_shm_ptr->ipm_pif[ipm_shm_ptr->alias_ip[i].pif_index]),
		0);
      if (rc != 0)
      {
          return rc;
      }
    }

    return(0);

} //end ipm_get_alias

/* 
  1. Add base interface to shm
  2. Populate nma_interface_t
*/
int ipm_add_baseif(nma_ctx_t* ctx, struct cmd_base_iface *cbi)
{
    char ifname[MAX_NLEN_DEV];
    int ifind, pifind;
    int error;

    if ((cbi->base_if[0][0] == '\0') && (cbi->base_if[1][0] == '\0'))
    {
          LOG_ERROR(NMA_SEMSGSOCKET, "ipm_add_baseif: Both interfaces are empty - discarded \n");
          return IPM_INVALIDPARAMETER;
    }

    if (strcmp(cbi->base_if[0], cbi->base_if[1]) == 0)
    {
        LOG_ERROR(NMA_SEMSGSOCKET, "ipm_add_baseif: left interface is same with right interface - discarded");
        return IPM_INVALIDPARAMETER; 
    }

    if (ipm_shm_ptr->ipm_pif_nb == MAX_PAIRED_IF)
    {
        LOG_ERROR(NMA_SEMSGSOCKET, "ipm_add_baseif: shm base interface buffer full\n");
        return (IPM_TOOMUCHBIF);
    }

    for (pifind = 0; pifind < ipm_shm_ptr->ipm_pif_nb; pifind++)
    {
        if ( ((strlen(cbi->base_if[0]) > 0) && (strcmp(ipm_shm_ptr->ipm_pif[pifind].if_t[0].name, cbi->base_if[0]) == 0)) || 
            ((strlen(cbi->base_if[1]) > 0) && (strcmp(ipm_shm_ptr->ipm_pif[pifind].if_t[1].name, cbi->base_if[1]) == 0)) )
        {
            LOG_OTHER(NMA_SEMSGSOCKET, "ipm_add_baseif: duplicated interface - %s/%s, discarded \n", cbi->base_if[0], cbi->base_if[1]);
            return (IPM_DUPLICATED);
        }
    }

    // New interface defined, populated to shm
    for (ifind = 0; ifind < MAX_NB_DEV; ifind++)
    {
        if (cbi->base_if[ifind][0] == '\0')
        {
                continue;
        }
         strncpy(ipm_shm_ptr->ipm_pif[ipm_shm_ptr->ipm_pif_nb].if_t[ifind].name, cbi->base_if[ifind], MAX_NLEN_DEV-1);
         ipm_shm_ptr->ipm_pif[ipm_shm_ptr->ipm_pif_nb].if_t[ifind].name[MAX_NLEN_DEV-1] = 0;
         error = ipm_get_intf(inetsocket, &(ipm_shm_ptr->ipm_pif[pifind].if_t[ifind]));
        if (error < 0) 
        {
             memset(&(ipm_shm_ptr->ipm_pif[ipm_shm_ptr->ipm_pif_nb]), 0, sizeof(nma_interface_t) * MAX_NB_DEV);
             return IPM_SYSTEMERR;
        }
    }   
    ipm_shm_ptr->ipm_pif_nb++;

    return IPM_SUCCESS;
}

/* 
1. Check if there duplicated lsn ip
2. Populter shm lsn_ip_t 
3. Update ctx_nma.my interface
4. Add local alias ip table
*/
int ipm_add_lsn_alias(nma_ctx_t* ctx, struct cmd_alias_ip *lsn_alias)
{
	int error;
	int index, pindex;
	int l_ifindex, r_ifindex, pif_index; 
	IPM_IPADDR netmask;
	IPM_IPADDR network;
	IPM_RETVAL retval;

	/* Check if LSN0 IP is same or not with LSN1 IP*/
	if (memcmp(lsn_alias->alias_t[0].ip, lsn_alias->alias_t[1].ip, IPM_IPMAXSTRSIZE) == 0)
	{
		LOG_ERROR(NMA_SEMSGSOCKET, "ERROR: ipm_add_lsn_alias: LSN0 IP is same with LSN1 IP");
		return IPM_INVALIDPARAMETER;
	}

	/* Check if it is simplex
	 * if right interface is null then means it is simplex mod e now
	 */
        if ((lsn_alias->alias_t[0].alias_if[0] != '\0') && (lsn_alias->alias_t[1].alias_if[0] != '\0'))
        {
            IS_SIMPLEX_CONFIGURED = 0;
            LOG_FORCE(0, "IPM now is running in DUPLEX mode.");
        }
        else if ((lsn_alias->alias_t[0].alias_if[0] == '\0') && (lsn_alias->alias_t[1].alias_if[0] == '\0'))
        {
               LOG_FORCE(0, "No available interfaces\n");
               return IPM_INVALIDPARAMETER;
        }
        else
        {
            IS_SIMPLEX_CONFIGURED = 1;
            LOG_FORCE(0, "IPM now is running in SIMPLEX mode.");
        }

	/* 1. Check if there duplicated lsn ip */
	for (index = 0; index < MAX_NB_DEV; index++)
	{
		if (lsn_alias->alias_t[index].alias_if[0] == '\0')
		{
			continue;
		}
		if (memcmp(ipm_shm_ptr->lsn_ip[index].ip, lsn_alias->alias_t[index].ip, IPM_IPMAXSTRSIZE) == 0)
		{
			LOG_ERROR(NMA_SEMSGSOCKET, "ipm_add_lsn_alias: duplicated ip \n");
			return IPM_DUPLICATED;
		}
	}

	/* 2. Populate shm lsn_ip_t */
	for (index = 0; index < MAX_NB_DEV; index++)
	{
		memcpy(&(ipm_shm_ptr->lsn_ip[index]), &(lsn_alias->alias_t[index]), sizeof(struct alias_ip_t));
	}

	/* 3. Update ctx_nma.my */
	error = ipm_init_interfaces(ctx, lsn_alias->alias_t) ;
	if (error != IPM_SUCCESS)
	{
		LOG_ERROR(NMA_SEMSGSOCKET, "ipm_add_lsn_alias: failed to update ctx.my \n");
		memset(ipm_shm_ptr->lsn_ip, 0, sizeof(ipm_shm_ptr->lsn_ip));
		return IPM_SYSTEMERR;
	}

	// For simplex case, the ctx->a.my may hold the old data if it's not handled due to empty interface. 
	// So, clear the ifindex data for empty interface
	if (lsn_alias->alias_t[0].alias_if[0] == '\0')
	{
		ctx->a.my[0].ifindex = 0;
	}

	if (lsn_alias->alias_t[1].alias_if[0] == '\0')
	{
		ctx->a.my[1].ifindex = 0;
	}

	/*  4. Add local alias ip table */
	l_ifindex = ctx->a.my[0].ifindex;
	r_ifindex = ctx->a.my[1].ifindex;
	pif_index = ipm_get_pif(l_ifindex, r_ifindex, ipm_shm_ptr->ipm_pif, ipm_shm_ptr->ipm_pif_nb);
	if (pif_index < 0) 
	{
			LOG_ERROR(NMA_SEMSGSOCKET, "ip_add_lsn_alias: did not find paired interface %s/%s\n", lsn_alias->alias_t[0].alias_if, lsn_alias->alias_t[1].alias_if);
			memset(ipm_shm_ptr->lsn_ip, 0, sizeof(ipm_shm_ptr->lsn_ip));
			return IPM_INVALIDPARAMETER;
	}
	for (index = 0; index < MAX_NB_DEV; index++)
	{
		if (lsn_alias->alias_t[index].alias_if[0] == '\0')
		{
			continue;
		}
		retval = IPM_p2ipaddr(lsn_alias->alias_t[index].ip, &network);
		if (retval != IPM_SUCCESS)
		{
			memset(ipm_shm_ptr->lsn_ip, 0, sizeof(ipm_shm_ptr->lsn_ip));
			return IPM_INVALIDPARAMETER;	
		}
		retval = IPM_ipmkmask(&netmask, network.addrtype, lsn_alias->alias_t[index].prefix);
		if (retval != IPM_SUCCESS)
		{
			memset(ipm_shm_ptr->lsn_ip, 0, sizeof(ipm_shm_ptr->lsn_ip));
			return IPM_INVALIDPARAMETER;	
		}

		error = nma_manage_alias(ctx, network, netmask,
					1 << index, 
					lsn_alias->alias_t[index].alias_if, 
					&(ipm_shm_ptr->ipm_pif[pif_index]), 0);
		if (error != IPM_SUCCESS)
		{
			LOG_ERROR(NMA_SEMSGSOCKET, "ipm_add_lsn_alias: failed to local alias ip table\n");
			memset(ipm_shm_ptr->lsn_ip, 0, sizeof(ipm_shm_ptr->lsn_ip));
			return IPM_SYSTEMERR;
		}
	}
	ipm_is_ready = 1;
	return 0;
}

/*
  1. Determine the native interface of the lsn interfaces (e.g., eth0/eth1)
  2. Determine if the inteface passed in is located on either lsn interface, if not return not supported
*/
int ipm_check_intf(nma_ctx_t* ctx, struct cmd_alias_ip *alias_ip)
{
	char iface[MAX_NLEN_DEV];
	char i,j;

	for  (i = 0; i < MAX_NB_DEV; i++)
	{
		strncpy( iface, ctx->a.my[i].name, ( MAX_NLEN_DEV - 1 ) );

		strtok( iface, "." );
		strtok( iface, ":" );

		for  (j = 0; j < MAX_NB_DEV; j++)
		{
			if (strlen(alias_ip->alias_t[j].alias_if) != 0) 
			{
				if (strstr( alias_ip->alias_t[j].alias_if, iface) != NULL)
				{
					return IPM_SUCCESS;
				}
			}
		}
	}

	return IPM_NOTSUPPORT;
}

/*
  1. Find  if alias ip is in shm
  2. Add this alias to shm
  3. Add local alias ip table
*/
int ipm_add_alias(nma_ctx_t* ctx, struct cmd_alias_ip *alias_ip, int subnet_type)
{
	int index;
	int error;
	int pif_index;
	ipm_paired_if_t *pif_ptr;
	int l_ifindex, r_ifindex;
	nma_interface_t nif;
	IPM_IPADDR lip;
	IPM_IPADDR netmask;
	IPM_RETVAL retval;

	/* In Simplex Mode, there is no need to add any ip to shm 
	 * because we can't switch route for all IPs. So just keep LSN IP in shm
	 */
	if (IS_SIMPLEX_MODE)
	{
		return IPM_SUCCESS;
	}
	if ((strlen(alias_ip->alias_t[0].alias_if) == 0) ||
	    (strlen(alias_ip->alias_t[1].alias_if) == 0))
	{
		return IPM_SUCCESS;
	}

	if ((memcmp(alias_ip->alias_t[0].ip, alias_ip->alias_t[1].ip, IPM_IPMAXSTRSIZE) != 0) || 
		(alias_ip->alias_t[0].prefix != alias_ip->alias_t[1].prefix))
	{
		LOG_ERROR(NMA_SEMSGSOCKET, "ip_add_alias: alias ip on two interfaces are different which should be same");
		return IPM_INVALIDPARAMETER;
	}

	if (ipm_check_intf(ctx, alias_ip) == IPM_NOTSUPPORT)
	{
		return IPM_SUCCESS;
	}

	if (ipm_shm_ptr->alias_ip_nb == MAX_NB_ALIAS)
	{
		LOG_ERROR(NMA_SEMSGSOCKET, "ip_add_alias: buffer full\n");
		return IPM_TOOMUCHALIAS;
	}

	retval = IPM_p2ipaddr(alias_ip->alias_t[0].ip, &lip);
	if (retval != IPM_SUCCESS)
	{
		LOG_ERROR(0, "ip_add_alias: invalid IP address");
		return IPM_INVALIDPARAMETER;
	}
	retval = IPM_ipmkmask(&netmask, lip.addrtype, alias_ip->alias_t[0].prefix);
	if (retval != IPM_SUCCESS)
	{
		LOG_ERROR(0, "ip_add_alias: invalid prefix");
		return IPM_INVALIDPARAMETER;
	}
	/* Get Link local IP when IPv6 arrive, hope now is ready */
	if (lip.addrtype == IPM_IPV6)
	{
		(void)IPM_getlinklocalv6addr(netlinksocket, ctx->a.my[0].ifindex, &(ctx->a.my[0].link_ip), ctx->a.my[1].ifindex, &(ctx->a.my[1].link_ip));
	}

	/* 1. Find if alias ip is in shm */
	for (index = 0; index < ipm_shm_ptr->alias_ip_nb; index++)
	{
		if (IPM_IPCMPADDR(&(ipm_shm_ptr->alias_ip[index].ip), &lip) == IPM_SUCCESS)
		{
			break;
		} 
	}
	if (index < ipm_shm_ptr->alias_ip_nb)
	{
		LOG_OTHER(NMA_SEMSGSOCKET, "ip_add_alias: duplicated ip added\n");
		return IPM_DUPLICATED;
	}

	/* 2. Add this alais to shm */    
	memset(&nif, 0, sizeof(nma_interface_t));
	memcpy(nif.name, alias_ip->alias_t[0].alias_if, MAX_NLEN_DEV);
	error = ipm_get_intf(inetsocket, &nif);	
	if (error != IPM_SUCCESS)
	{
		LOG_ERROR(NMA_SEMSGSOCKET, "ip_add_alias: failed to get left intf\n");
		return IPM_SYSTEMERR;
	}
	l_ifindex = nif.ifindex;
	memset(&nif, 0, sizeof(nma_interface_t));
	memcpy(nif.name, alias_ip->alias_t[1].alias_if, MAX_NLEN_DEV);
	error = ipm_get_intf(inetsocket, &nif);
	if (error != IPM_SUCCESS)
	{
		LOG_ERROR(NMA_SEMSGSOCKET, "ip_add_alias: failed to get right intf\n");
		return IPM_SYSTEMERR;
	}
	r_ifindex = nif.ifindex;
	pif_index = ipm_get_pif(l_ifindex, r_ifindex, ipm_shm_ptr->ipm_pif, ipm_shm_ptr->ipm_pif_nb);
	if (pif_index < 0) 
	{
		struct cmd_base_iface base_iface;
		memset(&base_iface, 0, sizeof(base_iface));

		base_iface.subnet_type = subnet_type;
		strncpy(base_iface.base_if[0], alias_ip->alias_t[0].alias_if, MAX_NLEN_DEV);
		strncpy(base_iface.base_if[1], alias_ip->alias_t[1].alias_if, MAX_NLEN_DEV);

		error = ipm_add_baseif(ctx, &base_iface);

		if( error != IPM_SUCCESS )
		{
			LOG_ERROR(NMA_SEMSGSOCKET, "ip_add_alias: failed to add paired interface %s/%s\n", alias_ip->alias_t[0].alias_if, alias_ip->alias_t[1].alias_if);
			return IPM_INVALIDPARAMETER;
		}

		pif_index = ipm_get_pif(l_ifindex, r_ifindex, ipm_shm_ptr->ipm_pif, ipm_shm_ptr->ipm_pif_nb);
		if (pif_index < 0)
		{
			LOG_ERROR(NMA_SEMSGSOCKET, "ip_add_alias: did not find paired interface %s/%s \n", alias_ip->alias_t[0].alias_if, alias_ip->alias_t[1].alias_if);
			return IPM_INVALIDPARAMETER;
		}
	}
	ipm_shm_ptr->alias_ip[ipm_shm_ptr->alias_ip_nb].pif_index = pif_index;
	memcpy(&(ipm_shm_ptr->alias_ip[ipm_shm_ptr->alias_ip_nb].ip), &lip, IPM_IPADDRSIZE);
	for (index = 0; index < MAX_NB_DEV; index++)
	{
		memcpy(ipm_shm_ptr->alias_ip[ipm_shm_ptr->alias_ip_nb].name[index], alias_ip->alias_t[index].alias_if, MAX_NLEN_DEV);
	}
	if (subnet_type == IPM_INTERNAL_IP)
	{
		ipm_shm_ptr->alias_ip[ipm_shm_ptr->alias_ip_nb].links = LINK_ALL;
	}
	else 
	{
		ipm_shm_ptr->alias_ip[ipm_shm_ptr->alias_ip_nb].links = LINK_0;
	}
	memcpy(&(ipm_shm_ptr->alias_ip[ipm_shm_ptr->alias_ip_nb].mask), &netmask, IPM_IPADDRSIZE);
	ipm_shm_ptr->alias_ip[ipm_shm_ptr->alias_ip_nb].subnet_type = subnet_type;

	/* 3. Add to local ip alais table */
	error = nma_manage_alias(ctx, ipm_shm_ptr->alias_ip[ipm_shm_ptr->alias_ip_nb].ip
                                ,ipm_shm_ptr->alias_ip[ipm_shm_ptr->alias_ip_nb].mask, 
                                ipm_shm_ptr->alias_ip[ipm_shm_ptr->alias_ip_nb].links
                                ,ipm_shm_ptr->alias_ip[ipm_shm_ptr->alias_ip_nb].name[0] 
			        ,&(ipm_shm_ptr->ipm_pif[ipm_shm_ptr->alias_ip[ipm_shm_ptr->alias_ip_nb].pif_index]), 0);
	if (error != IPM_SUCCESS)
	{
		memset(&(ipm_shm_ptr->alias_ip[ipm_shm_ptr->alias_ip_nb]), 0, sizeof(ipm_alias_ip_t));
		LOG_ERROR(NMA_SEMSGSOCKET, "ip_add_alias: failed to add local alias ip table\n");
		return error;
	}
	ipm_shm_ptr->alias_ip_nb++;   

	return IPM_SUCCESS;
}

/*
  1. Find alias ip from shm
  2. Delete it from shm
  3. Delete from local ip 
*/
int ipm_del_alias(nma_ctx_t* ctx, struct cmd_alias_ip *alias_ip)
{
	int index, location = -1;
	int error;
	IPM_IPADDR lip;
	IPM_RETVAL retval;

	/* In Simplex Mode, there is no need to add any ip to shm 
	 * because we can't switch route for all IPs. So just keep LSN IP in shm
	 */
	if (IS_SIMPLEX_MODE)
	{
		return IPM_SUCCESS;
	}

	if ((strlen(alias_ip->alias_t[0].alias_if) == 0) ||
	    (strlen(alias_ip->alias_t[1].alias_if) == 0))
	{
		return IPM_SUCCESS;
	}

	if ((memcmp(alias_ip->alias_t[0].ip, alias_ip->alias_t[1].ip, IPM_IPMAXSTRSIZE) !=  0) || 
		(alias_ip->alias_t[0].prefix != alias_ip->alias_t[1].prefix))
	{
		LOG_ERROR(NMA_SEMSGSOCKET, "ip_del_alias: ip on two interface are different\n");
		return IPM_INVALIDPARAMETER;
	}

	if (ipm_shm_ptr->alias_ip_nb == 0)
	{
		LOG_ERROR(NMA_SEMSGSOCKET, "ERROR: ip_del_alias: there is no alias IP in share memory\n");
		return IPM_SYSTEMERR;
	}

	retval = IPM_p2ipaddr(alias_ip->alias_t[0].ip, &lip);
	if (retval != IPM_SUCCESS)
	{
		LOG_ERROR(0, "ip_del_alias: invalid IP address");
		return IPM_INVALIDPARAMETER;
	}

	/* 1. Find if alias ip is in shm */
	for (index = 0; index < ipm_shm_ptr->alias_ip_nb; index++)
	{
		if (IPM_IPCMPADDR(&(ipm_shm_ptr->alias_ip[index].ip), &lip) == IPM_SUCCESS)
		{
			location = index;            
			break;
		} 
	}

	if (location == -1)
	{
		LOG_ERROR(NMA_SEMSGSOCKET, "ip_del_alias: no alias ip in shm\n");
		return IPM_SUCCESS;
	}

	/* 2. Del this alias from shm */
	for (index = location + 1; index < ipm_shm_ptr->alias_ip_nb; index++)
	{
		memcpy(&(ipm_shm_ptr->alias_ip[index - 1]), &(ipm_shm_ptr->alias_ip[index]), sizeof(ipm_alias_ip_t));
	}
	ipm_shm_ptr->alias_ip_nb--;
	memset(&(ipm_shm_ptr->alias_ip[ipm_shm_ptr->alias_ip_nb]), 0, sizeof(ipm_alias_ip_t));

	/* 3. remvoe it from local alias ip table */
	error = nma_unmanage_alias(ctx, lip, 0);
	return error;
}

/* This function is used to get paired output interface pointer for remote alias ip in the host based route 
 * alias_ip:  remote alias IP
 * p_local_t: pointer of local alias IP table
 */
ipm_paired_if_t * find_matching_subnet(IPM_IPADDR alias_ip,  
			nma_ipalias_local_t * p_local_t,
			int count)
{
	int i, j, len;
	int match = 1;

	if (alias_ip.addrtype == IPM_IPV4)
	{
		len = 1;
	}
	else if (alias_ip.addrtype == IPM_IPV6)
	{
		len = 4;
	}
	else
	{
		ASRT_RPT(ASRTBADPARAM, 1, sizeof(IPM_IPADDR), &alias_ip, "Invalid address type");
		return NULL;
	}

	for(i=0; i<count; i++)
	{
		match = 1;
		if (alias_ip.addrtype != p_local_t[i].ip.addrtype)
		{
			continue;
		}
		for (j = 0; j < len; j++)
		{
			if((alias_ip.ipaddr[j] & p_local_t[i].mask.ipaddr[j]) != (p_local_t[i].ip.ipaddr[j] & p_local_t[i].mask.ipaddr[j]))
			{
				match = 0;
				break;
			}
		}
		if (match == 1)
		{
			return p_local_t[i].pif_t;
		}
	}
	
	return NULL;
} //end ipm_paired_if_t
