/* File name:
 *		glob/src/ipm/ipm_spv.c
 * Description:
 *		This file is used to spv msg operations
 */

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>

#include "ipm_spv.h"
#include "ipm_init.h"
#include "nma_log.h"
#include "ipm_msg.h"

extern int inetsocket;

typedef struct spv_msg_t {
   unsigned char data[ ETH_FRAME_LEN+4 ];
   int    len;
   int    lsn;
   int    local;
   int    vid;
   struct spv_msg_t * next;
} spv_msg_t;

static spv_msg_t * pSpvHead = NULL;
static spv_msg_t * pSpvTail = NULL;

#define CHKCONVERT16(_object) ((((_object) << 8) & 0xFF00) | (((_object) >> 8) & 0x00FF))

#define CONVERT16(_object) (_object) = CHKCONVERT16(_object)

#define CHKCONVERT32(_object) ((((_object) >> 24) & 0x000000FF) | (((_object) << 8) & 0x00FF0000) | (((_object) >> 8) & 0x0000FF00) | (((_object) << 24) & 0xFF000000))

#define CONVERT32(_object) (_object) = CHKCONVERT32(_object)

int ccsum(void* buffer,int size)
{
   int sum = 0;
   unsigned short *ptr = buffer;

   while (size > 1)
   {
      sum += ~(CHKCONVERT16(*ptr));
	ptr++;
      size -= 2;
   }
   if (size > 0)
   {
      sum += ~*(unsigned char*)ptr;
   }
   return(~sum);
}

/* Supervision message is in sent/received in Little Endian Format convert if necessary */
void ipm_convert_spv_msg( supervision_t * spv_msg )
{
	int i;

#if BYTE_ORDER == BIG_ENDIAN

	CONVERT32( spv_msg->version );
	CONVERT32( spv_msg->frame_number );
	CONVERT16( spv_msg->nb_alias );	
	CONVERT16( spv_msg->nb_remote );	
	CONVERT32( spv_msg->seq_alias );
	CONVERT32( spv_msg->seq_remote );

	spv_msg->checksum = ccsum(&spv_msg->version,SPVCHECKSIZE);

	CONVERT32( spv_msg->checksum );

#endif
	return;
}

//need add code to get vlan id
int crt_spv_socket(nma_ctx_t * ctx, int lsn)
{
	int rc;
	int s; 	//socket for spv message
	int flag = -1;
	int b_size;  //socket buffer size
	nma_interface_t * nma_if; 
	struct sockaddr_ll socket_address;
	struct ifreq  ifr;

	if(ctx == NULL)
	{
		ASRT_RPT(ASRTBADPARAM, 0, "ctx is null\n");
		return -1;
	}

	if(lsn > (MAX_NB_DEV -1) )
	{
		ASRT_RPT(ASRTBADPARAM, 0, "lsn(%d) is invalid\n", lsn);
		return -2;
	}

	// For simplex case, the interface could be empty, just return.
	if (ctx->a.my[lsn].name[0] == '\0')
	{
		return -1;
	}
 
	nma_if = &(ctx->a.my[lsn]);

	//fucntion to create raw socket 
	s = socket(AF_PACKET, SOCK_RAW, htons(ctx->b.proid));

	if (s == 0)
	{
		s = socket(AF_PACKET, SOCK_RAW, htons(ctx->b.proid));
	}

	if (s == -1)
	{
		//check error number log and return
		ASRT_RPT(ASOSFNFAIL, 0, "create socket failed, errno=%d\n", errno);
		return -3;
	}

	//ok if setsocktop failed.
	rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
	if(rc < 0)
	{
		//log only  
		ASRT_RPT(ASOSFNFAIL, 0, "setsockopt SO_REUSEADDR failed, rc=%d, errno=%d\n", rc, errno);
	}

	flag = fcntl(s, F_GETFL, 0);

	if (flag >= 0) {
		flag |= O_NONBLOCK;
		flag = fcntl(s, F_SETFL, flag);
		if (flag < 0)
		{
			ipm_close_socket(&s);
			ASRT_RPT(ASOSFNFAIL, 0, "fcntl set O_NONBLOCK failed flag=%d, errno=%d\n", flag, errno);
			return -1;
		}
	}
	else
	{
		ipm_close_socket(&s);
		ASRT_RPT(ASOSFNFAIL, 0, "fcntl get flag failed flag=%d, errno=%d\n", flag, errno);
		return -1;
	}

	//set a big socket buffer size, it is ok the function fail
	b_size = IPM_SO_SNDBUFSZE;
	rc = setsockopt(s, SOL_SOCKET, SO_RCVBUF,  &b_size, sizeof(b_size));
	if(rc != 0)
	{
		//log only
		ASRT_RPT(ASOSFNFAIL, 0, "setsockopt SO_RCVBUF failed, rc=%d, errno=%d\n", rc, errno);
	}

	memset(&socket_address, 0, sizeof(socket_address));

	/*prepare sockaddr_ll*/
	socket_address.sll_family   = PF_PACKET;
	socket_address.sll_protocol = htons(ctx->b.proid);
	socket_address.sll_ifindex  = ipm_get_ifindex(inetsocket, nma_if->name);
	if (socket_address.sll_ifindex < 0)
	{
		ASRT_RPT(ASOSFNFAIL, 0, "failed to get ifindex\n");
		ipm_close_socket(&s);
		return  -4;
	}
	else
	{
		//update ifindex in ctx
		if(nma_if->ifindex != socket_address.sll_ifindex)
		{
			memset((void *)&ifr, 0, sizeof(ifr));
			strncpy(ifr.ifr_name, nma_if->name, IFNAMSIZ-1);
        		(*(struct sockaddr_in *)&(ifr.ifr_netmask)).sin_addr.s_addr = nma_if->mask;
			ifr.ifr_ifindex = socket_address.sll_ifindex;
			memcpy(ifr.ifr_hwaddr.sa_data, &(nma_if->ether), ETH_ALEN);
			(*(struct sockaddr_in *)&(ifr.ifr_addr)).sin_addr.s_addr = nma_if->ip; 
			//add multicasting address
			ifr.ifr_hwaddr.sa_family = AF_UNSPEC;
			memcpy(ifr.ifr_hwaddr.sa_data,&(ctx->b.group_multicast),ETH_ALEN);

			if (ioctl(inetsocket,SIOCADDMULTI,&ifr) < 0)
			{
				ASRT_RPT(ASOSFNFAIL, 0, "ioctl SIOCADDMULTI errno %d", errno);
				ipm_close_socket(&s);
				return -5;
			}
			nma_if->ifindex = socket_address.sll_ifindex;
		}
	}

	socket_address.sll_hatype   = ARPHRD_ETHER;
	socket_address.sll_pkttype  = PACKET_OTHERHOST;
	socket_address.sll_halen    = ETH_ALEN;

	memcpy((void *)&socket_address.sll_addr[0],
	(void *)&(ctx->b.group_multicast),
	sizeof(ctx->b.group_multicast));

	socket_address.sll_addr[6]  = 0x00; //not used
	socket_address.sll_addr[7]  = 0x00; //not used

	rc = bind(s, (struct sockaddr*)&socket_address, sizeof(socket_address));
	if (rc != 0) {
		ASRT_RPT(ASOSFNFAIL, 0, "bind failed, rc=%d, errno=%d", rc, errno);
		ipm_close_socket(&s);
		return(-6);
	}

	return s;
} //end crt_spv_socekt function

int ipm_spv_send(nma_ctx_t * ctx, int link, unsigned char * buf, int bufSize)
{
	int rc;
	int i;
	unsigned char buffer[ETH_FRAME_LEN+4];
	struct ethhdr * eh;
	static int msg_cnt_snd = 0;
	static int msg_loop_snd = 0;
 
	if ((bufSize < 1) || (bufSize > 1500))
	{
		ASRT_RPT(ASRTBADPARAM, 0, "msg size(%d) is wrong\n", bufSize);
		return(-1);
	}

	if( (link & LINK_ALL) == 0)
	{
		return(0);
	}

	eh = (struct ethhdr *)buffer;

	//fill dst mac address
	memcpy(eh->h_dest, (void*)&(ctx->b.group_multicast), ETH_ALEN);
  
	for (i = 0; i < MAX_NB_DEV; i++)
	{
		if (ctx->a.my[i].name[0] == '\0')
		{
			continue;
		}
		if (link & (1 << i) )
		{  
			if(ctx->b.spv_socket[i] < 0) 
			{
				continue;
			}

			//fill source mac address
			memcpy(eh->h_source , (void*)&(ctx->a.my[i].ether), ETH_ALEN );
			eh->h_proto = htons(ctx->b.proid);
			memcpy((void*)(&buffer[ETH_HLEN]), buf, bufSize);

			/* Convert if necessary */
			ipm_convert_spv_msg( (supervision_t*)(&(buffer[ETH_HLEN])) );

			//send the message out
			rc = send(ctx->b.spv_socket[i], buffer, bufSize+ETH_HLEN, 0);
			if(rc < 0)
			{
				if( (errno != EINTR) && (errno != ENETDOWN) ) 
				{
					ASRT_RPT(ASOSFNFAIL, 0, "send failed, rc=%d, errno=%d", rc, errno);
					ipm_close_socket(&(ctx->b.spv_socket[i]));
					ctx->b.spv_socket[i] = -1;
					return rc;
				}
			}
			else {
				if (debug_enable == 1)
				{
					msg_cnt_snd++;
					if (msg_cnt_snd % debug_msg_cnt == 0) 
					{
						msg_cnt_snd = 0;
						msg_loop_snd++;
						if (msg_loop_snd > 50000) msg_loop_snd = 0;
						printf("#################################\n");
						printf("ipm_spv_send(%d), lsn = %d, fd = %d, total msg cnt = %d\n", rc, 1 << i, ctx->b.spv_socket[i], msg_loop_snd * debug_msg_cnt);
						print_hex(buffer, bufSize+ETH_HLEN);
						printf("#################################\n");
					}
				}
			}
		} //end if link & (1 << i) 

	} //end for loop

	return 0;

} //end ipm_send

//add spv message to the link list for later processing
int onRcv_spv_msg(int * s, int lsn, int vid, int * reccounter, unsigned int * errcounter, int proid)
{
	struct ethhdr * eh;
	spv_msg_t *pTemp = NULL;
	int ret = 0;
	static int msg_cnt_rcv = 0;
	static int msg_loop_rcv = 0;


	while(1) 
	{
		pTemp = (spv_msg_t *) malloc(sizeof(*pTemp));
		if(pTemp == NULL)
		{
			return -1;
		}

		pTemp->len = recv(*s, pTemp->data, sizeof(pTemp->data), MSG_DONTWAIT);
		if (pTemp->len <= 0)
		{ 
			free(pTemp);

			if( (errno != EINTR) &&
				(errno != EWOULDBLOCK) &&
				(errno != ENETDOWN) ) 
			{
				ASRT_RPT(ASOSFNFAIL, 0, "recv failed, errno=%d", errno);
				ipm_close_socket(s);
				*s = -1;
				ret = -1;
			}
			if (errno == ENETDOWN)
			{
				struct ifreq  ifr;

				LOG_ERROR(0, "RECV - netdown - ifname %s, link %d socket %d", nma_ctx.a.my[lsn].name, lsn, *s);
				/* in this case, don't need to close socket, but this interface left multicast group.
				 * So must add multicast group again
				 */
				memset(&ifr, 0, sizeof(struct ifreq));
				strncpy(ifr.ifr_name, nma_ctx.a.my[lsn].name, IFNAMSIZ);
				if (ioctl(inetsocket, SIOCGIFINDEX, &ifr) == -1) {
					ASRT_RPT(ASOSFNFAIL, 0, "ioctl SIOCGIFHWADDR(name = %s) errno %d", nma_ctx.a.my[lsn].name, errno);
				}
				if (ioctl(inetsocket, SIOCGIFHWADDR, &ifr) == -1) {
					ASRT_RPT(ASOSFNFAIL, 0, "ioctl SIOCGIFHWADDR(name = %s) errno %d", nma_ctx.a.my[lsn].name, errno);
				}

				ifr.ifr_hwaddr.sa_family = AF_UNSPEC;
				memcpy(ifr.ifr_hwaddr.sa_data,&(nma_ctx.b.group_multicast),ETH_ALEN);
				if (ioctl(inetsocket,SIOCADDMULTI,&ifr) < 0)
				{
					ASRT_RPT(ASOSFNFAIL, 0, "ioctl SIOCADDMULTI(name = %s) errno %d", nma_ctx.a.my[lsn].name, errno);
				}
			}


			//break while loop
			break;
		}
		else {
			if (debug_enable) {
				msg_cnt_rcv++;
				if (msg_cnt_rcv  % debug_msg_cnt == 0)
				{
					msg_cnt_rcv = 0;
					msg_loop_rcv++;
					if (msg_loop_rcv > 50000) msg_loop_rcv = 0;
					printf("********************************\n");
					printf("onRcv_spv_msg(%d), lsn = %d, fd = %d, total msg cnt = %d\n", pTemp->len, lsn, *s, msg_loop_rcv * debug_msg_cnt);
					print_hex(pTemp->data, pTemp->len);
					printf("*******************************\n");
				}
			}
		}

		eh = (struct ethhdr *)pTemp->data;
		if (eh->h_proto != htons(proid))
		{
			LOG_OTHER(NMA_OSOCKET,
				"%s, proid does not match, eh->h_proto=H'%x, proid=H'%x", 
				__FUNCTION__,
				eh->h_proto,
				htons(proid));
			free(pTemp);
			continue;
		}

#if BYTE_ORDER == LITTLE_ENDIAN

		if (csum(&(((supervision_t*)(&(pTemp->data[ETH_HLEN])))->version),SPVCHECKSIZE) != ((supervision_t*)(&(pTemp->data[ETH_HLEN])))->checksum)
		{
			LOG_ERROR(NMA_EBADCHECKSUM,"nma_rec_spv : bad frame received csum=%X, checksum=%X, size=%d", 
				  csum(&(((supervision_t*)(&(pTemp->data[ETH_HLEN])))->version),SPVCHECKSIZE),
				  ((supervision_t*)(&(pTemp->data[ETH_HLEN])))->checksum, SPVCHECKSIZE );
			(*errcounter)++;
			free(pTemp);
			continue;
		}
#else
		if (ccsum(&(((supervision_t*)(&(pTemp->data[ETH_HLEN])))->version),SPVCHECKSIZE) != (CHKCONVERT32(((supervision_t*)(&(pTemp->data[ETH_HLEN])))->checksum)))
		{
			LOG_ERROR(NMA_EBADCHECKSUM,"nma_rec_spv : bad frame received csum=%X, checksum=%X, size=%d", 
				  ccsum(&(((supervision_t*)(&(pTemp->data[ETH_HLEN])))->version),SPVCHECKSIZE),
				  ((supervision_t*)(&(pTemp->data[ETH_HLEN])))->checksum, SPVCHECKSIZE );
			(*errcounter)++;
			free(pTemp);
			continue;
		}
#endif
		/* Convert if necessary */
		ipm_convert_spv_msg( (supervision_t*)(&(pTemp->data[ETH_HLEN])) );

		//correct packets
		(*reccounter)++;

		pTemp->lsn = lsn; 
		pTemp->local = FALSE; 
		pTemp->vid = vid; 
		pTemp->next = NULL;

		if(pSpvHead == NULL)
		{
			pSpvHead = pTemp;
		}
		else
		{
			pSpvTail->next = pTemp;
		}
		//upate tail
		pSpvTail = pTemp;

	} // end while (1) loop

	//report error
	if( (*reccounter) > MAX_NB_STA * 2 * 10)
	{
		LOG_ERROR(NMA_OSOCKET,
			"%s, too many spv messages %d", 
			__FUNCTION__,
			*reccounter);
	}

	return ret;

} //end onRcv_spv_msg

int process_spv_msg(nma_ctx_t * ctx,
		    int * flush,
		    int * compute,
		    int * routecounter)
{
	spv_msg_t *pTemp;

	while( pSpvHead != NULL)
	{
		pTemp = pSpvHead;

		//process spv msg in link list, remove mac header
		nma_rec_spv(ctx,
			(supervision_t*)(&(pTemp->data[ETH_HLEN])),
			pTemp->lsn,
			pTemp->len - ETH_HLEN,
			pTemp->local,
			flush,
			compute,
			routecounter);

		pSpvHead = pTemp->next;
		free(pTemp);
	}

	//set tail to NULL too
	pSpvTail = NULL;

	return 0;

} //end process_spv_msg
