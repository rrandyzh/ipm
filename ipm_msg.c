/* File:
 *	glob/src/ipm/ipm_msg.c
 * Description:	
 *	process  ipm cli msg  
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/time.h>
#include <fcntl.h>

#include "nma_log.h"
#include "nma_ctx.h"
#include "nnn_socket.h"
#include "nnn_internal.h"
#include "ipm_init.h"
#include "ipm_msg.h"
#include "ipm_util.h"
#include "EIPM_include.h"
#include "ipm_retval.h"
#include "PIPM_include.h"
#include "BFD_api.h"
#include "ARPNDP_api.h"

extern char trt[][30];


/*******************************************************/
/* unix domain server socket creation, used for	   */
/* nma_main()                           	   */
/* - UNIX socket creation                          */
/* - UNIX socket bind                              */
/* returns  -1 if error else socket fd             */
/*******************************************************/
int ipm_init_cliSrv_socket(char* name)
{
	int rc;
	int s;
	int flag = 1;
	struct sockaddr_un servername;

	//change to UDP based for LCP
	s = socket(AF_UNIX,SOCK_DGRAM,0);  

	if ( s == 0)
   	{
		s = socket(AF_UNIX,SOCK_DGRAM,0);  
	}

	if ( s < 0)
   	{
		LOG_ERROR(NMA_ESOCKET,"%s: socket errno %d",__FUNCTION__, errno);
		return(-1);
	}

	// OK if setsockopt fail 
	rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
	if (rc < 0)
	{
		LOG_ERROR(NMA_ESOCKET,
			"%s: setsockopt SO_REUSEADDR failed, rc=%d, errno=%d",
			__FUNCTION__,
			rc,
			errno );
	}

	/* get current socket F_GETFL option */
	flag = fcntl(s, F_GETFL, 0);
	if (flag < 0) 
	{
		LOG_ERROR(NMA_ESOCKET,
			"%s: fcntl get socket option F_GETFL failed, flag=%d, errno=%d",
			__FUNCTION__,
			flag,
 			errno );
		ipm_close_socket(&s);
		return -1;
	}
	else
	{
		/* make socket non-blocking */
		flag |= O_NONBLOCK;
		rc = fcntl(s, F_SETFL, flag);
		if (rc < 0)
		{
			LOG_ERROR(NMA_ESOCKET,
				"%s: fcntl cli_server set socket non-blocking failed, rc=%d, errno=%d",
				__FUNCTION__,
				rc,
				errno );
			ipm_close_socket(&s);
			return -1;
		}
	}

	(void)unlink(name);
	servername.sun_family = AF_UNIX;
	strncpy(servername.sun_path, name, 107);
	servername.sun_path[107] = 0;

	if (bind(s,(struct sockaddr*)&servername,sizeof(servername)) == -1)
	{
		LOG_ERROR(NMA_EBIND,"%s: bind errno %d",__FUNCTION__, errno);
		ipm_close_socket(&s);
		return(-2);
	}

	return(s);
} //end ipm_init_cliSrv_socket

//process cli cmd message
int onRcv_cli_msg(nma_ctx_t * ctx,
		   int * reccounter,
		   int * flush,
		   int * compute,
		   int * routecounter)
{
	int size;
	struct nma_msgsocket_t  msg;
	struct sockaddr_un  cliAddr;
	socklen_t cliAddrLen;

	while (1)
	{
		cliAddrLen = sizeof(cliAddr);
		memset(&cliAddr, 0, sizeof(cliAddr));
		memset((void *)&msg, 0, sizeof(msg));

		size = recvfrom(ctx->b.cli_socket,
				&msg,
				sizeof(struct nma_msgsocket_t),
				MSG_DONTWAIT,
				(struct sockaddr *)&cliAddr,
				&cliAddrLen );

		msg.h.s = ctx->b.cli_socket;
		if (size < 0 )
		{
			if( (errno != EINTR) && (errno != EWOULDBLOCK) ) 
			{
				LOG_ERROR(NMA_ESOCKET,
					"nma cli_server recvfrom() errno=%d, ret_len=%d",
					errno,
					size);
				ipm_close_socket(&(ctx->b.cli_socket));
			}
			break;
		}
		else if (size == 0)
		{
			break;
		}
		else
		{
			ipm_proc_cli_msg(&msg,
					ctx,
					reccounter,
					flush,
					compute,
					routecounter,
					&cliAddr);
		} //end recv size check

	} // end while loop
	return (0);

} //end function onRcv_cli_msg

/* fill err text in response msg to ipm_cli */
void ipm_fill_errtext(int err_no, char *buf, int buf_len)
{
	memset(buf, 0, buf_len);
	switch (err_no) {
	case IPM_SUCCESS:
	{
		snprintf(buf, buf_len, "Success");	
		break;
	}
	case IPM_DUPLICATED:
	{
		snprintf(buf, buf_len, "Duplicated -%d", IPM_DUPLICATED);	
		break;
	}
	case IPM_TOOMUCHBIF:
	{
		snprintf(buf, buf_len, "Too Much Interface Defined(Max = %d) - %d", MAX_PAIRED_IF, IPM_TOOMUCHBIF);
		break;
	}	
	case IPM_INVALIDPARAMETER:
	{
		snprintf(buf, buf_len, "Invalid Parameter - %d", IPM_INVALIDPARAMETER);
		break;
	}
	case IPM_SYSTEMERR:
	{
		snprintf(buf, buf_len, "System Error - %d", IPM_SYSTEMERR);
		break;
	}
	case IPM_INVALIDMSGLEN:
	{
		snprintf(buf, buf_len, "Invalid Msg Length - %d", IPM_INVALIDMSGLEN);
		break;
	}
	case IPM_NOTSUPPORT:
	{
		snprintf(buf, buf_len, "Not Supported Currently - %d", IPM_NOTSUPPORT);
		break;
	}
	/* following is nma error code */
	case IPM_TOOMUCHALIAS:
	{
		snprintf(buf, buf_len, "Too Much Alias IP defined(Max = %d) - %d", MAX_NB_ALIAS, IPM_TOOMUCHALIAS);
		break;
	}
	case IPM_ALIASUNKNOWN:
	{
		snprintf(buf, buf_len, "Alias Unknow - %d", IPM_ALIASUNKNOWN);
		break;
	}
	case IPM_PRIMARYFORBIDDEN:
	{
		snprintf(buf, buf_len, "Primary Forbindden - %d", IPM_PRIMARYFORBIDDEN);
		break;
	}
	case IPM_ALIASALREADYKNOWN:
	{
		snprintf(buf, buf_len, "Alias Aready Known - %d", IPM_ALIASALREADYKNOWN);
		break;
	}
	case IPM_BADLSNNUMBER:
	{
		snprintf(buf, buf_len, "Bad LSN Number - %d", IPM_BADLSNNUMBER);	
		break;
	}
	default:
	{
		snprintf(buf, buf_len, "Other or Unknow error - %d", err_no);
	}
	}
	return;
}

char *ipm_cmd2ptr(int msg_type)
{
	switch (msg_type) {
	case IPM_ADD_BASEIF:
		return "IPM_ADD_BASEIF";
	case IPM_DEL_BASEIF:
		return "IPM_DEL_BASEIF";
	case IPM_ADD_LSN_ALIAS:
		return "IPM_ADD_LSN_ALIAS";
	case IPM_DEL_LSN_ALIAS:
		return "IPM_DEL_LSN_ALIAS";
	case IPM_ADD_INT_ALIAS:
		return "IPM_ADD_INT_ALIAS";
	case IPM_DEL_INT_ALIAS:
		return "IPM_DEL_INT_ALIAS";
	case IPM_ADD_EXT_ALIAS:
		return "IPM_ADD_EXT_ALIAS";
	case IPM_DEL_EXT_ALIAS:
		return "IPM_DEL_EXT_ALIAS";
	case IPM_ADD_ARP:
		return "IPM_ADD_ARP";
	case IPM_DEL_ARP:
		return "IPM_DEL_ARP";
	case IPM_GARP_REQUEST:
		return "IPM_GARP_REQUEST";
	case IPM_ADD_ROUTE:
		return "IPM_ADD_ROUTE";
	case IPM_DEL_ROUTE:
		return "IPM_DEL_ROUTE";
	case IPM_ADD_PROXY_SERVER:
		return "IPM_ADD_PROXY_SERVER";
	case IPM_DEL_PROXY_SERVER:
		return "IPM_DEL_PROXY_SERVER";
	case IPM_ADD_PROXY_CLIENT:
		return "IPM_ADD_PROXY_CLIENT";
	case IPM_DEL_PROXY_CLIENT:
		return "IPM_DEL_PROXY_CLIENT";
	case IPM_ADD_PROXY_CLIENT_ADDR:
		return "IPM_ADD_PROXY_CLIENT_ADDR";
	case IPM_DEL_PROXY_CLIENT_ADDR:
		return "IPM_DEL_PROXY_CLIENT_ADDR";
	case IPM_ADD_PATH:
		return "IPM_ADD_PATH";
	case IPM_DEL_PATH:
		return "IPM_DEL_PATH";
	case IPM_GET_STATS:
		return "IPM_GET_STATS";
	case IPM_SET_STATS:
		return "IPM_SET_STATS";
	case IPM_CLR_STATS:
		return "IPM_CLR_STATS";
	case IPM_GET_SIDE:
		return "IPM_GET_SIDE";
	case IPM_SET_SIDE:
		return "IPM_SET_SIDE";
	case IPM_INH_IPM:
		return "IPM_INH_IPM";
	case IPM_ALW_IPM:
		return "IPM_ALW_IPM";
	case IPM_INH_IIPM:
		return "IPM_INH_IIPM";
	case IPM_ALW_IIPM:
		return "IPM_ALW_IIPM";
	case IPM_INH_EIPM:
		return "IPM_INH_EIPM";
	case IPM_ALW_EIPM:
		return "IPM_ALW_EIPM";
	case IPM_INH_PIPM:
		return "IPM_INH_PIPM";
	case IPM_ALW_PIPM:
		return "IPM_ALW_PIPM";
	case IPM_INH_PIPM_L2_PATH:
		return "IPM_INH_PIPM_L2_PATH";
	case IPM_ALW_PIPM_L2_PATH:
		return "IPM_ALW_PIPM_L2_PATH";
	case IPM_INH_PROXY_SERVER:
		return "IPM_INH_PROXY_SERVER";
	case IPM_ALW_PROXY_SERVER:
		return "IPM_ALW_PROXY_SERVER";
	case IPM_INH_CFGCHK:
		return "IPM_INH_CFGCHK";
	case IPM_ALW_CFGCHK:
		return "IPM_ALW_CFGCHK";
	case IPM_CLEAR_EVENTS:
		return "IPM_CLEAR_EVENTS";
	case IPM_REPORT_EVENTS:
		return "IPM_REPORT_EVENTS";
	case IPM_DUMP_DATA:
		return "IPM_DUMP_DATA";
	case IPM_DUMP_STATS:
		return "IPM_DUMP_STATS";
	case IPM_DUMP_CTX:
		return "IPM_DUMP_CTX";
	case IPM_DUMP_SHM:
		return "IPM_DUMP_SHM";
	case IPM_DUMP_ALARM:
		return "IPM_DUMP_ALARM";
	case IPM_DUMP_STATUS:
		return "IPM_DUMP_STATUS";
	case IPM_ALW_SYSLOG:
		return "IPM_ALW_SYSLOG";
	case IPM_INH_SYSLOG:
		return "IPM_INH_SYSLOG";
	case IPM_INH_REMOTE_LOG:
		return "IPM_INH_REMOTE_LOG";
	case IPM_ALW_REMOTE_LOG:
		return "IPM_ALW_REMOTE_LOG";
	case IPM_INH_CHECK_LOG:
		return "IPM_INH_CHECK_LOG";
	case IPM_ALW_CHECK_LOG:
		return "IPM_ALW_CHECK_LOG";
	case IPM_INH_ACTION_LOG:
		return "IPM_INH_ACTION_LOG";
	case IPM_ALW_ACTION_LOG:
		return "IPM_ALW_ACTION_LOG";
	case IPM_SET_IIPM_DEBUG:
		return "IPM_SET_IIPM_DEBUG";
	case IPM_CLR_IIPM_DEBUG:
		return "IPM_CLR_IIPM_DEBUG";
	case IPM_SET_EIPM_DEBUG:
		return "IPM_SET_EIPM_DEBUG";
	case IPM_CLR_EIPM_DEBUG:
		return "IPM_CLR_EIPM_DEBUG";
	case IPM_DUMP_SESSION:
		return "IPM_DUMP_SESSION";
	case IPM_SET_SESSION:
		return "IPM_SET_SESSION";
	case IPM_SET_SUBNET:
		return "IPM_SET_SUBNET";
	case IPM_ADD_INT_SUBNET:
		return "IPM_ADD_INT_SUBNET";
	case IPM_DEL_INT_SUBNET:
		return "IPM_DEL_INT_SUBNET";
	case IPM_ADD_EXT_SUBNET:
		return "IPM_ADD_EXT_SUBNET";
	case IPM_DEL_EXT_SUBNET:
		return "IPM_DEL_EXT_SUBNET";
	case IPM_ADD_WCNP_FIX:
		return "IPM_ADD_WCNP_FIX";
	case IPM_DEL_WCNP_FIX:
		return "IPM_DEL_WCNP_FIX";
	case IPM_ADD_WCNP_ACTIVE:
		return "IPM_ADD_WCNP_ACTIVE";
	case IPM_DEL_WCNP_ACTIVE:
		return "IPM_DEL_WCNP_ACTIVE";
	case IPM_ADD_WCNP_STANDBY:
		return "IPM_ADD_WCNP_STANDBY";
	case IPM_DEL_WCNP_STANDBY:
		return "IPM_DEL_WCNP_STANDBY";
	case IPM_SET_SOAK_TIMER:
		return "IPM_SET_SOAK_TIMER";
	case IPM_ADD_TUNNEL:
		return "IPM_ADD_TUNNEL";
	case IPM_DEL_TUNNEL:
		return "IPM_DEL_TUNNEL";
	default:
		return "UnknowCMD";
	}
}

void ipm_msg_prtlog(int type, void *data, int size)
{
	char logbuf[UMAX_LOG_SIZE];
	char *ptr = logbuf;
	int total = 0, cnt  = 0;

	memset(logbuf, 0, sizeof(logbuf));

	switch (type) { 
	case IPM_ADD_BASEIF:
	case IPM_DEL_BASEIF:
	{
		struct cmd_base_iface *cmd;
		cmd = (struct cmd_base_iface *)data;
		if (size != sizeof(struct cmd_base_iface)) goto len_error;
		snprintf(logbuf, UMAX_LOG_SIZE, "CMD: %s red_mode %d subnet_type %d left %s right %s;\n", 
					ipm_cmd2ptr(type),
					cmd->redundancy_mode,
					cmd->subnet_type,
					cmd->base_if[0],
					cmd->base_if[1]
					);
		break;
	}
	case IPM_ADD_LSN_ALIAS:
	case IPM_DEL_LSN_ALIAS:
	case IPM_ADD_INT_ALIAS:
	case IPM_DEL_INT_ALIAS:
	case IPM_ADD_EXT_ALIAS:
	case IPM_DEL_EXT_ALIAS:
	case IPM_ADD_WCNP_FIX:
	case IPM_DEL_WCNP_FIX:
	case IPM_ADD_WCNP_ACTIVE:
	case IPM_DEL_WCNP_ACTIVE:
	case IPM_ADD_WCNP_STANDBY:
	case IPM_DEL_WCNP_STANDBY:
	{
		struct cmd_alias_ip * cmd;
		cmd = (struct cmd_alias_ip *)data;
		if (size != sizeof(struct cmd_alias_ip)) goto len_error;
		snprintf(logbuf, UMAX_LOG_SIZE, "CMD: %s left %s:%s/%d right %s:%s/%d subnet_type %d gateway %s;\n",
					ipm_cmd2ptr(type),
					cmd->alias_t[0].alias_if,
					cmd->alias_t[0].ip,
					cmd->alias_t[0].prefix,
					cmd->alias_t[1].alias_if,
					cmd->alias_t[1].ip,
					cmd->alias_t[1].prefix,
					cmd->alias_t[0].subnet_type,
					cmd->gateway
					);
		break;
					
	}
	case IPM_ADD_ARP:
	case IPM_DEL_ARP:
	{
		struct cmd_arp_list *cmd;
		cmd = (struct cmd_arp_list *)data;
		if (size != sizeof(struct cmd_arp_list)) goto len_error;
		snprintf(logbuf, UMAX_LOG_SIZE, "CMD: %s ip %s/%d left %s right %s prio %d;\n",
					ipm_cmd2ptr(type),
					cmd->ip,
					cmd->prefix,
					cmd->iface[0],
					cmd->iface[1],
					cmd->priority
					);
		break;
	}
	case IPM_GARP_REQUEST:
	{
		struct cmd_garp_request *cmd;
		cmd = (struct cmd_garp_request *)data;
		if (size != sizeof(struct cmd_garp_request)) goto len_error;
		snprintf(logbuf, UMAX_LOG_SIZE, "CMD: %s ip %s subnet_type %d address_type %d;\n",
					ipm_cmd2ptr(type),
					cmd->ip,
					cmd->subnet_type,
					cmd->address_type
					);
		break;
	}
	case IPM_ADD_ROUTE:
	case IPM_DEL_ROUTE:
	{
		struct cmd_route_upd *cmd;
		cmd = (struct cmd_route_upd *)data;
		if (size != sizeof(struct cmd_route_upd)) goto len_error;
		snprintf(logbuf, UMAX_LOG_SIZE, "CMD: %s dest %s/%d nexthop %s src %s left %s right %s pivot %d vlanId %d;\n",
					ipm_cmd2ptr(type),
					cmd->dest,
					cmd->prefix,
					cmd->nexthop,
					cmd->source_ip,
					cmd->iface[0],
					cmd->iface[1],
					cmd->pivot_id,
					cmd->vlanId
					);
		break;
	}
	case IPM_ADD_PROXY_SERVER:
	case IPM_DEL_PROXY_SERVER:
	case IPM_ADD_PROXY_CLIENT:
	case IPM_DEL_PROXY_CLIENT:
	case IPM_ADD_PROXY_CLIENT_ADDR:
	case IPM_DEL_PROXY_CLIENT_ADDR:
	{
		struct cmd_proxy_server *cmd;
		cmd = (struct cmd_proxy_server *)data;
		if (size != sizeof(struct cmd_proxy_server)) goto len_error;
		snprintf(logbuf, UMAX_LOG_SIZE, "CMD: %s ip %s/%d  fe_left %s fe_right %s be_left %s be_right %s intFltIP %s pivot %d vlanId %d;\n",
					ipm_cmd2ptr(type),
					cmd->ip,
					cmd->prefix,
					cmd->fe_iface[0],
					cmd->fe_iface[1],
					cmd->be_iface[0],
					cmd->be_iface[1],
					cmd->intFloatIp,
					cmd->pivot_id,
					cmd->vlanId
					);
		break;
	}
	case IPM_ADD_PATH:
	case IPM_DEL_PATH:
	{
		struct cmd_proxy_path *cmd;
		cmd = (struct cmd_proxy_path *)data;
		if (size != sizeof(struct cmd_proxy_path)) goto len_error;
		snprintf(logbuf, UMAX_LOG_SIZE, "CMD: %s ip %s/%d left %s right %s;\n",
					ipm_cmd2ptr(type),
					cmd->ip,
					cmd->prefix,
					cmd->iface[0],
					cmd->iface[1]
					);
		break;
	}
	case IPM_GET_STATS:
	case IPM_SET_STATS:
	case IPM_CLR_STATS:
	{
		struct cmd_stats_request *cmd;
		cmd = (struct cmd_stats_request *)data;
		if (size != sizeof(struct cmd_stats_request)) goto len_error;
		snprintf(logbuf, UMAX_LOG_SIZE, "CMD: %s iface %s count %s value %d;\n",
					ipm_cmd2ptr(type),
					cmd->iface,
					cmd->count,
					cmd->value
					);
		break;
	}
	case IPM_GET_SIDE:
	case IPM_SET_SIDE:
	{
		struct cmd_side_selection *cmd;
		cmd = (struct cmd_side_selection *)data;
		if (size != sizeof(struct cmd_side_selection)) goto len_error;
		snprintf(logbuf, UMAX_LOG_SIZE, "CMD: %s iface %s;\n ",
					ipm_cmd2ptr(type),
					cmd->iface
					);
		break;
	}
	case IPM_INH_IPM:
	case IPM_ALW_IPM:
	case IPM_INH_IIPM:
	case IPM_ALW_IIPM:
	case IPM_INH_EIPM:
	case IPM_ALW_EIPM:
	case IPM_INH_PIPM:
	case IPM_ALW_PIPM:
	case IPM_INH_PIPM_L2_PATH:
	case IPM_ALW_PIPM_L2_PATH:
	case IPM_INH_PROXY_SERVER:
	case IPM_ALW_PROXY_SERVER:
	case IPM_INH_CFGCHK:
	case IPM_ALW_CFGCHK:
	case IPM_CLEAR_EVENTS:
	case IPM_REPORT_EVENTS:
	case IPM_DUMP_DATA:
	case IPM_DUMP_STATS:
	case IPM_DUMP_CTX:
	case IPM_DUMP_SHM:
	case IPM_DUMP_ALARM:
	case IPM_DUMP_STATUS:
	case IPM_ALW_SYSLOG:
	case IPM_INH_SYSLOG:
	case IPM_INH_REMOTE_LOG:
	case IPM_ALW_REMOTE_LOG:
	case IPM_INH_CHECK_LOG:
	case IPM_ALW_CHECK_LOG:
	case IPM_INH_ACTION_LOG:
	case IPM_ALW_ACTION_LOG:
	case IPM_SET_IIPM_DEBUG:
	case IPM_CLR_IIPM_DEBUG:
	case IPM_SET_EIPM_DEBUG:
	case IPM_CLR_EIPM_DEBUG:
	case IPM_DUMP_SESSION:
	case IPM_SET_SESSION:
	{
		struct cmd_ipm_admin *cmd;
		cmd = (struct cmd_ipm_admin *)data;
		if (size != sizeof(struct cmd_ipm_admin)) goto len_error;
		snprintf(logbuf, UMAX_LOG_SIZE, "CMD: %s ip %s/%d gateway %s data %d state %d;\n ",
					ipm_cmd2ptr(type),
					cmd->ip,
					cmd->prefix,
					cmd->gateway,
					cmd->data,
					cmd->state
					);
		break;
	}
	case IPM_SET_SOAK_TIMER:
	{
		struct cmd_ipm_admin *cmd;
		cmd = (struct cmd_ipm_admin *) data;
		if (size != sizeof (struct cmd_ipm_admin)) goto len_error;
		snprintf(logbuf, UMAX_LOG_SIZE, "CMD: %s soak time is set to %d at system level;\n ",
			ipm_cmd2ptr(type),
			cmd->data
			);
		break;
	}
	case IPM_SET_SUBNET:
	case IPM_ADD_INT_SUBNET:
	case IPM_DEL_INT_SUBNET:
	case IPM_ADD_EXT_SUBNET:
	case IPM_DEL_EXT_SUBNET:
	{
		struct cmd_subnet_upd *cmd;
		cmd = (struct cmd_subnet_upd *)data;
		if (size != sizeof(struct cmd_subnet_upd)) goto len_error;
		snprintf(logbuf, UMAX_LOG_SIZE, "CMD: %s subnet %s/%d gateway %s red_mode %d table %d left %s right %s dm %d dmti %d rmri %d;\n ",
					ipm_cmd2ptr(type),
					cmd->subnet_base,
					cmd->prefix,
					cmd->gateway,
					cmd->redundancy_mode,
					cmd->table_num,
					cmd->dev_t[0].dev_if,
					cmd->dev_t[1].dev_if,
					cmd->detection_multiplier,
					cmd->desired_min_tx_interval,
					cmd->required_min_rx_interval
					);
		break;
	}
	case IPM_ADD_TUNNEL:
	case IPM_DEL_TUNNEL:
	{
		struct cmd_tunnel_upd *cmd;
		cmd = (struct cmd_tunnel_upd *)data;
		if (size != sizeof(struct cmd_tunnel_upd)) goto len_error;
		snprintf(logbuf, UMAX_LOG_SIZE, "CMD: %s name %s, local endpoint %s, remote endpoint %s, key %d, id %d, ttl %d\n",
			ipm_cmd2ptr(type),
			cmd->name, cmd->lepip, cmd->repip,
			cmd->key, cmd->id, cmd->ttl);
		break;
	}
	default:
		snprintf(logbuf, UMAX_LOG_SIZE, "CMD: Unknow command");
	}
	LOG_OTHER(NMA_SEMSGSOCKET, logbuf);
	return;

len_error:
	LOG_OTHER(NMA_SEMSGSOCKET, "CMD: %s Error: invalid len\n",
		ipm_cmd2ptr(type)
		);
	return;
}

int ipm_proc_cli_msg(   struct nma_msgsocket_t * msg,
			nma_ctx_t * ctx,
			int * reccounter,
			int * flush,
			int * compute,
			int * routecounter,
			struct sockaddr_un * cliAddr)
{
	int ixtrt = 0;
	int i;
	station_t *station;
	struct msgframe *msgframe;
	char reply_text[REPLY_TEXT];
	char reply_text1[REPLY_TEXT];
	int index, rsperr = 0;
	int rsperr1 = 0;

	reply_text[0] = '\0';
	reply_text1[0] = '\0';

	switch(msg->h.type) {
	case  IPM_ADD_BASEIF:
	{
		IPM_BASE_HOOK(ctx);

		rsperr = IPM_SUCCESS;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_base_iface), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_base_iface))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			//process this command 
			msg->h.error = ipm_add_baseif(ctx,&(msg->cmd_base_iface));

			rsperr = EIPM_base_update( &msg->cmd_base_iface,
						   EIPM_ADD,
						   reply_text );

			// don't overwrite iipm failure
			if (msg->h.error != IPM_SUCCESS )
			{
				rsperr = msg->h.error;
			}
		}
		if( strlen(reply_text) > 0 )
		{
			strncpy(msg->rsp_base_iface.text, reply_text, REPLY_TEXT);
		}
		else
		{
			ipm_fill_errtext(msg->h.error, msg->rsp_base_iface.text, REPLY_TEXT);
		}

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_base_iface);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_ADD_BASEIF", errno);
		}
		break;
	}
	case IPM_DEL_BASEIF:
	{
		rsperr = IPM_SUCCESS;

		ipm_msg_prtlog(msg->h.type, &(msg->cmd_base_iface), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_base_iface))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			//process this command 
			rsperr = EIPM_base_update( &msg->cmd_base_iface,
						   EIPM_DEL,
						   reply_text );
		}
		if( strlen(reply_text) > 0 )
		{
			strncpy(msg->rsp_base_iface.text, reply_text, REPLY_TEXT);
		}
		else
		{
			ipm_fill_errtext(msg->h.error, msg->rsp_base_iface.text, REPLY_TEXT);
		}

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_base_iface);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_ADD_BASEIF", errno);
		}
		break;
	}
	case IPM_ADD_LSN_ALIAS:
	{
		//update shm ipm_pif_t
		rsperr = IPM_SUCCESS;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_alias_ip), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_alias_ip))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if (rsperr == IPM_SUCCESS)
			{
				//process this command 
				rsperr = ipm_add_lsn_alias(ctx,&(msg->cmd_alias_ip));
			}
		}
		ipm_fill_errtext(rsperr, msg->rsp_alias_ip.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_alias_ip);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_ADD_LSN_ALIAS", errno);
		}
		break;
	}
	case IPM_DEL_LSN_ALIAS:
	{
		//update shm ipm_pif_t
		//process this command 
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_alias_ip), msg->h.size);
		ipm_fill_errtext(msg->h.error, msg->rsp_alias_ip.text, REPLY_TEXT);

		msg->h.error = IPM_NOTSUPPORT;
		msg->h.size = sizeof(msg->rsp_alias_ip);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_DEL_LSN_ALIAS", errno);
		}
		break;
	}
	case IPM_ADD_INT_ALIAS:
	{
		rsperr = IPM_SUCCESS;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_alias_ip), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_alias_ip))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if (rsperr == IPM_SUCCESS)
			{
				//process this command
				msg->h.error = ipm_add_alias(ctx,&(msg->cmd_alias_ip), IPM_INTERNAL_IP);


                        	rsperr = PIPM_cmd_path_update( (void *)&msg->cmd_alias_ip,
                                                            	msg->h.type,
                                                            	reply_text );

                                // don't overwrite iipm failure
                                if (msg->h.error != IPM_SUCCESS )
                                {
                                        rsperr = msg->h.error;
                                }
			}
		}
		if( strlen(reply_text) > 0 )
		{
			strncpy(msg->rsp_alias_ip.text, reply_text, REPLY_TEXT);
		}
		else
		{
			ipm_fill_errtext(msg->h.error, msg->rsp_alias_ip.text, REPLY_TEXT);
		}

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_alias_ip);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_ADD_INT_ALIAS", errno);
		}
		break;
	}
	case IPM_DEL_INT_ALIAS:
	{
		rsperr = IPM_SUCCESS;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_alias_ip), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_alias_ip))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if (rsperr == IPM_SUCCESS)
			{
				//process this command
				msg->h.error = ipm_del_alias(ctx,&(msg->cmd_alias_ip));


                        	rsperr = PIPM_cmd_path_update( (void *)&msg->cmd_alias_ip,
                                                            	msg->h.type,
                                                            	reply_text );

                                // don't overwrite iipm failure
                                if (msg->h.error != IPM_SUCCESS )
                                {
                                        rsperr = msg->h.error;
                                }
			}
		}
		if( strlen(reply_text) > 0 )
		{
			strncpy(msg->rsp_alias_ip.text, reply_text, REPLY_TEXT);
		}
		else
		{
			ipm_fill_errtext(msg->h.error, msg->rsp_alias_ip.text, REPLY_TEXT);
		}

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_alias_ip);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_DEL_INT_ALIAS", errno);
		}
		break;
	}
	case IPM_ADD_EXT_ALIAS:
	{
		rsperr = IPM_SUCCESS;
		rsperr1 = IPM_SUCCESS;

		ipm_msg_prtlog(msg->h.type, &(msg->cmd_alias_ip), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_alias_ip))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			//process this command
			if (rsperr == IPM_SUCCESS)
			{
				msg->h.error = ipm_add_alias(ctx,&(msg->cmd_alias_ip), IPM_EXTERNAL_IP);
				rsperr1 = EIPM_intf_update(&msg->cmd_alias_ip,
							  EIPM_ADD,
							  reply_text1);

                        	rsperr = PIPM_cmd_path_update( (void *)&msg->cmd_alias_ip,
                                                            	msg->h.type,
                                                            	reply_text );
                                // don't overwrite iipm failure
                                if (msg->h.error != IPM_SUCCESS )
                                {
                                        rsperr = msg->h.error;
                                }
				else if (rsperr1 != IPM_SUCCESS )
				{
                                        rsperr = rsperr1;
					strncpy(reply_text, reply_text1, REPLY_TEXT);
				}
			}
		}
		if( strlen(reply_text) > 0 )
		{
			strncpy(msg->rsp_alias_ip.text, reply_text, REPLY_TEXT);
		}
		else
		{
			ipm_fill_errtext(msg->h.error, msg->rsp_alias_ip.text, REPLY_TEXT);
		}

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_alias_ip);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_ADD_EXT_ALIAS", errno);
		}
		break;
	}
	case IPM_DEL_EXT_ALIAS:
	{
		rsperr = IPM_SUCCESS;
		rsperr1 = IPM_SUCCESS;

		ipm_msg_prtlog(msg->h.type, &(msg->cmd_alias_ip), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_alias_ip))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if (rsperr == IPM_SUCCESS)
			{
				// process this command
				msg->h.error = ipm_del_alias(ctx,&(msg->cmd_alias_ip));
		    		rsperr1 = EIPM_intf_update(&msg->cmd_alias_ip,
							  EIPM_DEL,
							  reply_text1);

                        	rsperr = PIPM_cmd_path_update( (void *)&msg->cmd_alias_ip,
                                                            	msg->h.type,
                                                            	reply_text );

				// don't overwrite iipm failure
				if (msg->h.error != IPM_SUCCESS )
				{
					rsperr = msg->h.error;
				}
				else if (rsperr1 != IPM_SUCCESS )
				{
                                        rsperr = rsperr1;
					strncpy(reply_text, reply_text1, REPLY_TEXT);
				}
			}
		}
		if( strlen(reply_text) > 0 )
		{
			strncpy(msg->rsp_alias_ip.text, reply_text, REPLY_TEXT);
		}
		else
		{
			ipm_fill_errtext(msg->h.error, msg->rsp_alias_ip.text, REPLY_TEXT);
		}

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_alias_ip);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_DEL_EXT_ALIAS", errno);
		}
		break;
	}
	case IPM_ADD_WCNP_FIX:
	case IPM_DEL_WCNP_FIX:
	case IPM_ADD_WCNP_ACTIVE:
	case IPM_DEL_WCNP_ACTIVE:
	case IPM_ADD_WCNP_STANDBY:
	case IPM_DEL_WCNP_STANDBY:
	{
		rsperr = IPM_SUCCESS;
		rsperr1 = IPM_SUCCESS;

		ipm_msg_prtlog(msg->h.type, &(msg->cmd_alias_ip), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_alias_ip))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			//process this command
			if (rsperr == IPM_SUCCESS)
			{
				rsperr = EIPM_wcnp_update(&msg->cmd_alias_ip,
							  msg->h.type,
							  reply_text1);

                                if (msg->h.error != IPM_SUCCESS )
                                {
                                        rsperr = msg->h.error;
                                }
			}
		}
		if( strlen(reply_text) > 0 )
		{
			strncpy(msg->rsp_alias_ip.text, reply_text, REPLY_TEXT);
		}
		else
		{
			ipm_fill_errtext(msg->h.error, msg->rsp_alias_ip.text, REPLY_TEXT);
		}

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_alias_ip);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: msg type %d: send errno %d", __FUNCTION__, msg->h.type, errno);
		}
		break;

	}
	case IPM_ADD_ARP:
	{
		ixtrt = 41;
		rsperr = IPM_SUCCESS;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_arp_list), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_arp_list))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			rsperr = EIPM_arp_update( &msg->cmd_arp_list,
			                          EIPM_ADD,
			                          msg->rsp_arp_list.text );
		}
		msg->h.error = rsperr;
	        msg->h.size = sizeof(msg->rsp_arp_list);

	        if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
	        {
	            LOG_ERROR(NMA_ESEND,"nma_main: %s: send errno %d", trt[ixtrt], errno);
	        }
	        break;
	}
	case IPM_DEL_ARP:
	{
		ixtrt = 42;
		rsperr = IPM_SUCCESS;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_arp_list), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_arp_list))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			rsperr = EIPM_arp_update( &msg->cmd_arp_list,
		                                  EIPM_DEL,
			                          msg->rsp_arp_list.text );
		}
		msg->h.error = rsperr;
	        msg->h.size = sizeof(msg->rsp_arp_list);

	        if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
	        {
	            LOG_ERROR(NMA_ESEND,"nma_main: %s: send errno %d", trt[ixtrt], errno);
	        }

	        break;
	}
	case IPM_GARP_REQUEST:
	{
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_garp_request), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_garp_request))
		{
			rsperr = IPM_INVALIDMSGLEN;
			msg->h.error = rsperr;
			ipm_fill_errtext(msg->h.error, msg->rsp_garp_request.text, REPLY_TEXT);
		}
		else
		{
			rsperr = IPM_SUCCESS;
			if( strlen(msg->cmd_garp_request.ip) > 0 )
			{
				rsperr = ipm_grat_arp_ip(ctx,
                                                         msg->cmd_garp_request.ip,
			                                 msg->rsp_garp_request.text);
			}

			if( msg->cmd_garp_request.subnet_type == IPM_SUBNET_EXTERNAL ||
			    msg->cmd_garp_request.subnet_type == IPM_SUBNET_BOTH )
			{
				// handle fixed, float, all 
				rsperr = EIPM_grat_arp_all();
				msg->h.error = rsperr;
				ipm_fill_errtext(msg->h.error, msg->rsp_garp_request.text, REPLY_TEXT);
			}
		}
		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_garp_request);

		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_ALW_EIPM", errno);
		}
		break;
	}
	case IPM_ADD_ROUTE:
	{
		int		    ret;
		char 		    text[REPLY_TEXT];

		text[0] = '\0';
		ixtrt = 43;
		rsperr = IPM_SUCCESS;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_route_upd), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_route_upd))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			ret = EIPM_route_update( &msg->cmd_route_upd,
			                            EIPM_ADD,
			                            text );

			rsperr = PIPM_cmd_route_update( &msg->cmd_route_upd,
			                            	msg->h.type,
			                            	msg->rsp_route_upd.text );

			// save first failure
			if (ret != IPM_SUCCESS )
			{
				rsperr = ret;
				memcpy( msg->rsp_route_upd.text, text, sizeof(msg->rsp_route_upd.text) );
			}
		}
		msg->h.error = rsperr;
	        msg->h.size = sizeof(msg->rsp_route_upd);

	        if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
	        {
	            LOG_ERROR(NMA_ESEND,"nma_main: %s: send errno %d", trt[ixtrt], errno);
	        }
		
	        break;
	}
	case IPM_DEL_ROUTE:
	{
		int		    ret;
		char 		    text[REPLY_TEXT];

		text[0] = '\0';
		ixtrt = 44;
		rsperr = IPM_SUCCESS;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_route_upd), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_route_upd))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			ret = EIPM_route_update( &msg->cmd_route_upd,
		                                    EIPM_DEL,
			                            text );

			rsperr = PIPM_cmd_route_update( &msg->cmd_route_upd,
			                            	msg->h.type,
			                            	msg->rsp_route_upd.text );

			// save first failure
			if (ret != IPM_SUCCESS )
			{
				rsperr = ret;
				memcpy( msg->rsp_route_upd.text, text, sizeof(msg->rsp_route_upd.text) );
			}
		}
		msg->h.error = rsperr;
	        msg->h.size = sizeof(msg->rsp_route_upd);

	        if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
	        {
	            LOG_ERROR(NMA_ESEND,"nma_main: %s: send errno %d", trt[ixtrt], errno);
	        }
		
	        break;
	}
        case IPM_ADD_PROXY_SERVER:
        case IPM_DEL_PROXY_SERVER:
        case IPM_ADD_PROXY_CLIENT:
        case IPM_DEL_PROXY_CLIENT:
        {
                rsperr = IPM_SUCCESS;
                rsperr1 = IPM_SUCCESS;

		ipm_msg_prtlog(msg->h.type, &(msg->cmd_proxy_server), msg->h.size);
                if (msg->h.size != sizeof(struct cmd_proxy_server))
                {
                        rsperr = IPM_INVALIDMSGLEN;
                }
                else
                {
			struct cmd_alias_ip cmd_alias_ip;
			memset((void *)&cmd_alias_ip, 0, sizeof(cmd_alias_ip));

			cmd_alias_ip.alias_t[0].subnet_type = IPM_SUBNET_EXTERNAL;
			cmd_alias_ip.alias_t[1].subnet_type = IPM_SUBNET_EXTERNAL;

			cmd_alias_ip.alias_t[0].prefix = msg->cmd_proxy_server.prefix;
			cmd_alias_ip.alias_t[1].prefix = msg->cmd_proxy_server.prefix;

			strncpy(cmd_alias_ip.alias_t[0].ip, msg->cmd_proxy_server.ip, IPM_IPMAXSTRSIZE-1);
			cmd_alias_ip.alias_t[0].ip[IPM_IPMAXSTRSIZE-1] = 0;
			strncpy(cmd_alias_ip.alias_t[1].ip, msg->cmd_proxy_server.ip, IPM_IPMAXSTRSIZE-1);
			cmd_alias_ip.alias_t[1].ip[IPM_IPMAXSTRSIZE-1] = 0;

                        if( msg->h.type == IPM_ADD_PROXY_SERVER ||
                            msg->h.type == IPM_DEL_PROXY_SERVER )
                        {
			    strncpy(cmd_alias_ip.alias_t[0].alias_if, msg->cmd_proxy_server.be_iface[0], MAX_NLEN_DEV-1);
			    cmd_alias_ip.alias_t[0].alias_if[MAX_NLEN_DEV-1] = 0;
			    strncpy(cmd_alias_ip.alias_t[1].alias_if, msg->cmd_proxy_server.be_iface[1], MAX_NLEN_DEV-1);
			    cmd_alias_ip.alias_t[1].alias_if[MAX_NLEN_DEV-1] = 0;
                        }
                        else
                        {
			    strncpy(cmd_alias_ip.alias_t[0].alias_if, msg->cmd_proxy_server.fe_iface[0], MAX_NLEN_DEV-1);
			    cmd_alias_ip.alias_t[0].alias_if[MAX_NLEN_DEV-1] = 0;
			    strncpy(cmd_alias_ip.alias_t[1].alias_if, msg->cmd_proxy_server.fe_iface[1], MAX_NLEN_DEV-1);
			    cmd_alias_ip.alias_t[1].alias_if[MAX_NLEN_DEV-1] = 0;

			    if (msg->h.type == IPM_ADD_PROXY_CLIENT ||
					msg->h.type == IPM_DEL_PROXY_CLIENT)
			    {
				//Make sure the alias_if is only base interface without inner vlan.
				char *dot, *colon;
				char pivotStr[8];

				sprintf(pivotStr, "%d", msg->cmd_proxy_server.pivot_id);

				if ((dot = strrchr(cmd_alias_ip.alias_t[0].alias_if, '.')) != NULL)
				{
					strtok(cmd_alias_ip.alias_t[0].alias_if, ":");

					if (strcmp(dot + 1, pivotStr) == 0)
					{
						*dot = '\0';
					}

					if ((colon = strchr(msg->cmd_proxy_server.fe_iface[0], ':')) != NULL)
					{
						strcat(dot, colon);
					}
				}

				if ((dot = strrchr(cmd_alias_ip.alias_t[1].alias_if, '.')) != NULL)
				{
					strtok(cmd_alias_ip.alias_t[1].alias_if, ":");

					if (strcmp(dot + 1, pivotStr) == 0)
					{
						*dot = '\0';
					}

					if ((colon = strchr(msg->cmd_proxy_server.fe_iface[1], ':')) != NULL)
					{
						strcat(dot, colon);
					}
				}
			    }
                        }

			if( msg->h.type == IPM_ADD_PROXY_SERVER )
			{
				if ( EIPM_GET_PROXY_SERVER_ENABLED() == TRUE )
				{
				// ip setup on both interfaces like an internal
				msg->h.error = ipm_add_alias(ctx, &cmd_alias_ip, IPM_INTERNAL_IP);
				}
			}
			else if( msg->h.type == IPM_ADD_PROXY_CLIENT )
			{
				msg->h.error = ipm_add_alias(ctx, &cmd_alias_ip, IPM_INTERNAL_IP);
			}
			else
			{
				msg->h.error = ipm_del_alias(ctx, &cmd_alias_ip);
			}

                        rsperr1 = EIPM_proxy_server_update( &msg->cmd_proxy_server,
                                                           msg->h.type,
                                                           reply_text1 );

                        if( msg->h.type == IPM_ADD_PROXY_SERVER ||
                            msg->h.type == IPM_DEL_PROXY_SERVER )
			{
	                        rsperr = PIPM_cmd_path_update( (void *)&msg->cmd_proxy_server,
	                                                               	msg->h.type,
	                                                            	reply_text );
	                }

                        // don't overwrite iipm failure
                        if (msg->h.error != IPM_SUCCESS )
                        {
                                rsperr = msg->h.error;
                        }
			else if (rsperr1 != IPM_SUCCESS )
			{
                                rsperr = rsperr1;
				strncpy(reply_text, reply_text1, REPLY_TEXT);
			}
                }


		if( strlen(reply_text) > 0 )
		{
			strncpy(msg->rsp_alias_ip.text, reply_text, REPLY_TEXT);
		}
		else
		{
			ipm_fill_errtext(msg->h.error, msg->rsp_proxy_server.text, REPLY_TEXT);
		}

                msg->h.error = rsperr;
                msg->h.size = sizeof(msg->rsp_proxy_server);
                if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
                {
                    LOG_ERROR(NMA_ESEND,"nma_main: msg type %d, send errno %d", msg->h.type, errno);
                }

                break;
        }
        case IPM_ADD_PROXY_CLIENT_ADDR:
        case IPM_DEL_PROXY_CLIENT_ADDR:
        {
                rsperr = IPM_SUCCESS;
		rsperr1 = IPM_SUCCESS;

		ipm_msg_prtlog(msg->h.type, &(msg->cmd_proxy_server), msg->h.size);
                if (msg->h.size != sizeof(struct cmd_proxy_server))
                {
                        rsperr = IPM_INVALIDMSGLEN;
                }
                else
                {
                        rsperr1 = EIPM_proxy_server_update( &msg->cmd_proxy_server,
                                                           msg->h.type,
                                                           reply_text1 );

                        rsperr = PIPM_cmd_path_update( (void *)&msg->cmd_proxy_server,
                                                            	msg->h.type,
                                                            	reply_text );

                        // don't overwrite a failure
			if (rsperr1 != IPM_SUCCESS )
			{
                                rsperr = rsperr1;
				strncpy(reply_text, reply_text1, REPLY_TEXT);
			}
                }


		if( strlen(reply_text) > 0 )
		{
			strncpy(msg->rsp_proxy_server.text, reply_text, REPLY_TEXT);
		}
		else
		{
			ipm_fill_errtext(msg->h.error, msg->rsp_proxy_server.text, REPLY_TEXT);
		}

                msg->h.error = rsperr;
                msg->h.size = sizeof(msg->rsp_proxy_server);
                if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
                {
                    LOG_ERROR(NMA_ESEND,"nma_main: msg type %d, send errno %d", msg->h.type, errno);
                }

                break;
        }
        case IPM_ADD_PATH:
        case IPM_DEL_PATH:
        {
                rsperr = IPM_SUCCESS;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_proxy_path), msg->h.size);
                if (msg->h.size != sizeof(struct cmd_proxy_path))
                {
                        rsperr = IPM_INVALIDMSGLEN;
                }
                else
                {
                        rsperr = PIPM_cmd_path_update( (void *)&msg->cmd_proxy_path,
                                                  msg->h.type,
                                                  msg->rsp_proxy_path.text );
                }


                msg->h.error = rsperr;
                msg->h.size = sizeof(msg->rsp_proxy_path);

                if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
                {
                    LOG_ERROR(NMA_ESEND,"nma_main: msg type %d, send errno %d", msg->h.type, errno);
                }

                break;
        }

        case IPM_GET_STATS:
        {

                char stats[REPLY_TEXT];
                stats[0] = '\0';
                char stats2[REPLY_TEXT];
                stats2[0] = '\0';

                rsperr = IPM_SUCCESS;

		ipm_msg_prtlog(msg->h.type, &(msg->cmd_stats_request), msg->h.size);
                if (msg->h.size != sizeof(struct cmd_stats_request))
                {
                        rsperr = IPM_INVALIDMSGLEN;
                        ipm_fill_errtext(msg->h.error, msg->rsp_ipm.text, REPLY_TEXT);
                }
                else
                {
                        //  get internal count;
                        msg->h.error = ipm_get_internalCount( ctx, msg->cmd_stats_request.iface, stats);

                        //  get external count;
                        rsperr = ipm_get_externalCount( msg->cmd_stats_request.iface, stats2);

                        // don't overwrite interna failure
                        if (msg->h.error != IPM_SUCCESS )
                        {
                             rsperr = msg->h.error;
                        }

                        snprintf(msg->rsp_ipm.text, REPLY_TEXT,
                                               "%s%s\n", stats, stats2);

                        if ( strlen( msg->rsp_ipm.text ) < 10 )
                        {
                            strcpy(msg->rsp_ipm.text, "Unknown - No Interface Match");
                            rsperr = IPM_INVALIDPARAMETER;
                        }
                }

                msg->h.error = rsperr;
                msg->h.size = sizeof(msg->rsp_ipm);

                if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
                {
                        LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_GET_STATS", errno);
                }
                break;
        }
        case IPM_SET_STATS:
        {
                rsperr = IPM_SUCCESS;

		ipm_msg_prtlog(msg->h.type, &(msg->cmd_stats_request), msg->h.size);
                if (msg->h.size != sizeof(struct cmd_stats_request))
                {
                        rsperr = IPM_INVALIDMSGLEN;
                }
                else
                {
                        // set internal count;
			msg->h.error = ipm_set_internalCount( ctx, 
							      msg->cmd_stats_request.iface, 
							      msg->cmd_stats_request.count, 
							      msg->cmd_stats_request.value );

                        //  set external count;
                        rsperr = ipm_set_externalCount( msg->cmd_stats_request.iface, 
							msg->cmd_stats_request.count, 
							msg->cmd_stats_request.value );

                        // don't overwrite interna failure
                        if (msg->h.error != IPM_SUCCESS )
                        {
                             rsperr = msg->h.error;
                        }
                }

                ipm_fill_errtext(msg->h.error, msg->rsp_ipm.text, REPLY_TEXT);

                msg->h.error = rsperr;
                msg->h.size = sizeof(msg->rsp_ipm);
                if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
                {
                        LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_SET_STATS", errno);
                }
                break;
        }
        case IPM_CLR_STATS:
        {
                rsperr = IPM_SUCCESS;

		ipm_msg_prtlog(msg->h.type, &(msg->cmd_stats_request), msg->h.size);
                if (msg->h.size != sizeof(struct cmd_stats_request))
                {
                        rsperr = IPM_INVALIDMSGLEN;
                }
                else
                {
                        // clear internal count;
			msg->h.error = ipm_clr_internalCount( ctx, msg->cmd_stats_request.iface, msg->cmd_stats_request.count );

                        // clear external count;
                        rsperr = ipm_clr_externalCount( msg->cmd_stats_request.iface, msg->cmd_stats_request.count );

                        // don't overwrite interna failure
                        if (msg->h.error != IPM_SUCCESS )
                        {
                             rsperr = msg->h.error;
                        }
                }

                ipm_fill_errtext(msg->h.error, msg->rsp_ipm.text, REPLY_TEXT);

                msg->h.error = rsperr;
                msg->h.size = sizeof(msg->rsp_ipm);
                if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
                {
                        LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_SET_STATS", errno);
                }
                break;
        }
	case IPM_GET_SIDE:
	{
		msg->h.error = IPM_SUCCESS;

		ipm_msg_prtlog(msg->h.type, &(msg->cmd_side_selection), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_side_selection))
		{
			msg->h.error = IPM_INVALIDMSGLEN;
			ipm_fill_errtext(msg->h.error, msg->rsp_ipm.text, REPLY_TEXT);
		}
		else
		{
			char iface[REPLY_TEXT];

			rsperr = ipm_get_side(ctx, msg->cmd_side_selection.iface, iface);

			if( rsperr < 0 )
			{
				msg->h.error = rsperr;
			}

			snprintf(msg->rsp_ipm.text, REPLY_TEXT,
				"active side:%s", iface);
		}

		msg->h.size = sizeof(msg->rsp_ipm);

		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_INH_IIPM", errno);
		}
		break;
	}
	case IPM_SET_SIDE:
	{
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_side_selection), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_side_selection))
		{
			msg->h.error = IPM_INVALIDMSGLEN;
		}
		else
		{
			msg->h.error = ipm_set_side(ctx, msg->cmd_side_selection.iface);
		}

		ipm_fill_errtext(msg->h.error, msg->rsp_ipm.text, REPLY_TEXT);

		msg->h.size = sizeof(msg->rsp_ipm);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_INH_IIPM", errno);
		}
		break;
	}
	case IPM_INH_IPM:
	{
		rsperr = IPM_SUCCESS;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if( eipm_enable != FALSE )
			{
				eipm_enable = FALSE;

				rsperr = EIPM_shutdown();
			}

			if( pipm_enable != FALSE )
			{
				pipm_enable = FALSE;

				rsperr = PIPM_shutdown();
			}

			iipm_enable = FALSE;
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_INH_IIPM", errno);
		}
		break;
	}
	case IPM_ALW_IPM:
	{
		rsperr = IPM_SUCCESS;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
                int  ret;
                char cmd[256];

			if( eipm_enable != TRUE )
			{
				eipm_enable = TRUE;
	
				rsperr = EIPM_startup();
			}

#ifndef _VHE
			sprintf(cmd, "/opt/LSS/sbin/brdinfo | grep 440BX");

			ret = system(cmd);

			if( ret != 0 )
#endif
			{
				iipm_enable = TRUE;
			}
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_INH_IIPM", errno);
		}
		break;
	}
	case IPM_INH_IIPM:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			iipm_enable=FALSE;
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_INH_IIPM", errno);
		}
		break;
	}
	case IPM_ALW_IIPM:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
		int  ret;
		char cmd[256];

			sprintf(cmd, "/opt/LSS/sbin/brdinfo | grep 440BX");

			ret = system(cmd);

			if( ret != 0 )
			{
				iipm_enable=TRUE;
			}
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_ALW_IIPM", errno);
		}
		break;
	}
	case IPM_INH_EIPM:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if( eipm_enable != FALSE )
			{
				eipm_enable = FALSE;

				rsperr = EIPM_shutdown();
			}
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_INH_EIPM", errno);
		}
		break;
	}
	case IPM_ALW_EIPM:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if( eipm_enable != TRUE )
			{
				eipm_enable = TRUE;

				rsperr = EIPM_startup();
			}
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_ALW_EIPM", errno);
		}
		break;
	}
	case IPM_INH_PIPM:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if( pipm_enable != FALSE )
			{
				pipm_enable = FALSE;

				rsperr = PIPM_shutdown();
			}
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_INH_PIPM", errno);
		}
		break;
	}
	case IPM_ALW_PIPM:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if( pipm_enable != TRUE )
			{
				pipm_enable = TRUE;

				rsperr = PIPM_startup();
			}
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_ALW_PIPM", errno);
		}
		break;
	}
	case IPM_INH_PIPM_L2_PATH:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
#if defined(_X86) && !defined(_VHE)
			if( pipm_l2_path_enable != FALSE )
			{
				// paths will be refreshed at next timeout interval
				pipm_l2_path_enable = FALSE;

				rsperr = PIPM_send_l2_pathmsg( PIPM_INH_L2_PATH );
			}
#endif
		}

		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);
		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);

		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_INH_PIPM", errno);
		}
		break;
	}
	case IPM_ALW_PIPM_L2_PATH:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
#if defined(_X86) && !defined(_VHE)
			if( pipm_l2_path_enable != TRUE )
			{
				// paths will be refreshed at next timeout interval
				pipm_l2_path_enable = TRUE;
				
				rsperr = PIPM_send_l2_pathmsg( PIPM_ALW_L2_PATH );
			}
#endif
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_ALW_PIPM", errno);
		}
		break;
	}
	case IPM_INH_PROXY_SERVER:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if( EIPM_GET_PROXY_SERVER_ENABLED() != FALSE )
			{
				//PROXY ARP does not work when SBPR is enable, disable SBPR
				EIPM_disable_all_policy_routes();
				EIPM_SET_PROXY_SERVER_ENABLED( FALSE );

				/*kick off the audit immediately*/
				EIPM_audit_all_syctl();

				/* Audit the 'syctl' values for the internal interfaces. */
                                EIPM_audit_sysctl_for_internalIntfs();
			}
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_INH_PROXY_SERVER", errno);
		}
		break;
	}
	case IPM_ALW_PROXY_SERVER:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if( EIPM_GET_PROXY_SERVER_ENABLED() != TRUE )
			{
				//PROXY ARP does not work when SBPR is enable, disable SBPR
				EIPM_disable_all_policy_routes();
				EIPM_SET_PROXY_SERVER_ENABLED( TRUE );

				/*kick off the audit immediately*/
				EIPM_audit_all_syctl();

				/* Audit the 'syctl' values for the internal interfaces. */
                                EIPM_audit_sysctl_for_internalIntfs();

				PIPM_resetAllPathUpdateCounters();
			}
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_ALW_PROXY_SERVER", errno);
		}
		break;
        }
        case IPM_INH_CFGCHK:
        {
                rsperr = IPM_FAILURE;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
                if (msg->h.size != sizeof(struct cmd_ipm_admin))
                {
                        rsperr = IPM_INVALIDMSGLEN;
                }
                else if (msg->cmd_ipm_admin.data < 0 ||
                         msg->cmd_ipm_admin.data > EIPM_MAX_EXT_SUB)
		{
                       	rsperr = IPM_INVALIDPARAMETER;
		}
		else
		{
			EIPM_DATA *data_ptr = (EIPM_DATA *)EIPM_shm_ptr;
			EIPM_INTF *intf_ptr = &data_ptr->intf_data[0];
			int index;

			for( index = 0; index < data_ptr->intf_cnt; index++, intf_ptr++ )
       		        {
				if( msg->cmd_ipm_admin.data == EIPM_MAX_EXT_SUB ||
				    msg->cmd_ipm_admin.data == index )
				{
					LOG_ERROR(NMA_SOSTATUS,
						  "Disable Config Check for Interface %d: %s - %s", 
						   index, intf_ptr->lsn0_baseif, intf_ptr->lsn1_baseif);

					EIPM_SET_INTF_CHECK_DISABLE( &(intf_ptr->specData), TRUE );
				}
			}

			rsperr = IPM_SUCCESS;
                }

                ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

                msg->h.error = rsperr;
                msg->h.size = sizeof(msg->rsp_ipm_admin);
                if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
                {
                        LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_INH_CFGCHK", errno);
                }
                break;
        }
        case IPM_ALW_CFGCHK:
        {
                rsperr = IPM_FAILURE;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
                if (msg->h.size != sizeof(struct cmd_ipm_admin))
                {
                        rsperr = IPM_INVALIDMSGLEN;
                }
                else if (msg->cmd_ipm_admin.data < 0 ||
                         msg->cmd_ipm_admin.data > EIPM_MAX_EXT_SUB)
		{
                       	rsperr = IPM_INVALIDPARAMETER;
		}
		else
		{
			EIPM_DATA *data_ptr = (EIPM_DATA *)EIPM_shm_ptr;
			EIPM_INTF *intf_ptr = &data_ptr->intf_data[0];
			int index;

			for( index = 0; index < data_ptr->intf_cnt; index++, intf_ptr++ )
       		        {
				if( msg->cmd_ipm_admin.data == EIPM_MAX_EXT_SUB ||
				    msg->cmd_ipm_admin.data == index )
				{
					LOG_ERROR(NMA_SOSTATUS,
						  "Enable Config Check for Interface %d: %s - %s",

						   index, intf_ptr->lsn0_baseif, intf_ptr->lsn1_baseif);

					EIPM_SET_INTF_CHECK_DISABLE( &(intf_ptr->specData), FALSE );

					EIPM_CHECK_INTF_CONFIG( &(intf_ptr->specData) );
				}
			}

			rsperr = IPM_SUCCESS;
                }

                ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

                msg->h.error = rsperr;
                msg->h.size = sizeof(msg->rsp_ipm_admin);
                if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
                {
                        LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_ALW_CFGCHK", errno);
                }
                break;
        }

        case IPM_CLEAR_EVENTS:
        {
                rsperr = IPM_FAILURE;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
                if (msg->h.size != sizeof(struct cmd_ipm_admin))
                {
                        rsperr = IPM_INVALIDMSGLEN;
                }
		else
		{
			IPM_CLEAR_ALL_ALARMS();
			rsperr = IPM_SUCCESS;
                }

                ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

                msg->h.error = rsperr;
                msg->h.size = sizeof(msg->rsp_ipm_admin);
                if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
                {
                        LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_CLEAR_EVENTS", errno);
                }
                break;
        }

        case IPM_REPORT_EVENTS:
        {
                rsperr = IPM_FAILURE;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
                if (msg->h.size != sizeof(struct cmd_ipm_admin))
                {
                        rsperr = IPM_INVALIDMSGLEN;
                }
		else
		{
			EIPM_report_status();

			/*
			 * report or clear alarms based on the current
			 * status.
			 */
			if (ctx->a.iipm_interface_status == LINK_ALL) 
			{
				ipm_interface_change( LINK_NONE, ctx->a.iipm_interface_status);
			}
			else
			{
				ipm_interface_change( LINK_ALL, ctx->a.iipm_interface_status);
			}

			EIPM_report_alarms();
			rsperr = IPM_SUCCESS;
                }

                ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

                msg->h.error = rsperr;
                msg->h.size = sizeof(msg->rsp_ipm_admin);
                if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
                {
                        LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_REPORT_EVENTS", errno);
                }
                break;
        }
	case IPM_DUMP_DATA:
	{
		rsperr = IPM_FAILURE;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			BFD_log_data();
			ARPNDP_log_data();
			rsperr = IPM_SUCCESS;
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_DUMP_DATA", errno);
		}
		break;
	}
	case IPM_DUMP_STATS:
	{
		rsperr = IPM_FAILURE;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			BFD_log_stats();
			ARPNDP_log_stats();
			rsperr = IPM_SUCCESS;
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_DUMP_STATS", errno);
		}
		break;
	}
	case IPM_DUMP_CTX:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			ipm_dump_ctx(ctx);
#ifndef _VHE
			EIPM_wcnp_dump();
#endif
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_DUMP_CTX", errno);
		}
		break;
	}
	case IPM_DUMP_SHM:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			ipm_dump_shm();
			(void)EIPM_dumpshm();
			(void)PIPM_dumpshm();
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main: %s: send errno %d", "IPM_DUMP_SHM", errno);
		}
		break;
	}
	case IPM_DUMP_ALARM:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			(void)EIPM_dumpalarm();
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main: %s: send errno %d", "IPM_DUMP_ALARM", errno);
		}
		break;
	}
	case IPM_DUMP_STATUS:
	{
		EIPM_STATUS iipm_interface_status = EIPM_STAT_NULL;
		EIPM_STATUS eipm_interface_status = EIPM_STAT_NULL;
		char iipm_status[16];
		char iipm_info[8];
		char eipm_status[EIPM_LOG_SIZE];


		iipm_info[0] = '\0';

		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		/* Determine IIPM Status */
		if( iipm_enable == FALSE )
		{
			iipm_interface_status = EIPM_INHIBITED;
			msg->h.error = 0;
		}
		else
		{
			switch( ctx->a.iipm_interface_status )
			{
			case LINK_ALL:
				iipm_interface_status = EIPM_ONLINE;
				msg->h.error = 0;
				break;
	
			case LINK_0:
			case LINK_1:
				iipm_interface_status = EIPM_DEGRADED;
				msg->h.error = ~ctx->a.iipm_interface_status;

				if( ctx->a.iipm_interface_status == LINK_0 )
				{
					strcpy(iipm_info, "LSN1");
				}
				else
				{
					strcpy(iipm_info, "LSN0");
				}
				break;

			default:
				ASRT_RPT(ASBAD_DATA, 0, "Illegal IIPM Status %d", ctx->a.iipm_interface_status);
				sprintf(iipm_info, "%d ??", ctx->a.iipm_interface_status);

				/* Fall Through */

			case LINK_NONE:
				iipm_interface_status = EIPM_OFFLINE;
				msg->h.error = ~ctx->a.iipm_interface_status;
				break;
			}
		}

		EIPM_status2str(iipm_interface_status, iipm_status);

		/* Determine EIPM Status */
		eipm_interface_status = EIPM_getstatus( eipm_status, sizeof( eipm_status ) );

		switch( eipm_interface_status )
		{
		case EIPM_ONLINE:
		case EIPM_SOAKING:
		case EIPM_INHIBITED:
		case EIPM_STAT_NULL:
			break;

		default:
			ASRT_RPT(ASBAD_DATA, 0, "Illegal EIPM Status %d", eipm_interface_status);
			/* Fall Through */

		case EIPM_DEGRADED:
		case EIPM_OFFLINE:
			if( msg->h.error == 0 )
			{
				msg->h.error = (int)eipm_interface_status;
				msg->h.error += 10; /* make sure it's non-zero */
			}
			break;
		}

		snprintf(msg->rsp_ipm.text, REPLY_TEXT, 
			"IIPM STATUS: %s %s\nEIPM STATUS: %s", 
			iipm_status, 
			iipm_info, 
			eipm_status);


		msg->h.size = sizeof(msg->rsp_ipm);

		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main: %s: send errno %d", "IPM_DUMP_STATUS", errno);
		}

		switch( iipm_interface_status )
		{
		case EIPM_ONLINE:
		case EIPM_INHIBITED:
			break;

		default:
			ipm_dump_shm();
			ipm_dump_ctx(ctx);
			break;
		}

		switch( eipm_interface_status )
		{
		case EIPM_ONLINE:
		case EIPM_INHIBITED:
			break;

		default:
			(void)EIPM_dumpshm();
			(void)PIPM_dumpshm();
			break;
		}
		break;
	}
	case IPM_ALW_SYSLOG:
	{
		ipm_syslog_start();
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		msg->h.error = 0;
		msg->h.size = sizeof(msg->rsp_ipm_admin);

		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main: %s: send errno %d", "IPM_ALW_SYSLOG", errno);
		}
		break;
	}
	case IPM_INH_SYSLOG:
	{
		ipm_syslog_close();
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		msg->h.error = 0;
		msg->h.size = sizeof(msg->rsp_ipm_admin);

		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main: %s: send errno %d", "IPM_INH_SYSLOG", errno);
		}
		break;
	}
	case IPM_INH_REMOTE_LOG:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if( ipm_log_remote != FALSE )
			{
				ipm_log_remote = FALSE;
			}
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_INH_REMOTE_LOG", errno);
		}
		break;
	}
	case IPM_ALW_REMOTE_LOG:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if( ipm_log_remote != TRUE )
			{
				ipm_log_remote = TRUE;
			}
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_ALW_REMOTE_LOG", errno);
		}
		break;
	}
	case IPM_INH_CHECK_LOG:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if( ipm_check_log_level != LOG_MEDIUM )
			{
				ipm_check_log_level = LOG_MEDIUM;
			}
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_INH_CHECK_LOG", errno);
		}
		break;
	}
	case IPM_ALW_CHECK_LOG:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if( ipm_check_log_level != LOG_HIGH )
			{
				ipm_check_log_level = LOG_HIGH;
			}
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_ALW_CHECK_LOG", errno);
		}
		break;
	}
	case IPM_INH_ACTION_LOG:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if( ipm_action_log_level != LOG_MEDIUM )
			{
				ipm_action_log_level = LOG_MEDIUM;
			}
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_INH_ACTION_LOG", errno);
		}
		break;
	}
	case IPM_ALW_ACTION_LOG:
	{
		rsperr = 0;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if( ipm_action_log_level != LOG_HIGH )
			{
				ipm_action_log_level = LOG_HIGH;
			}
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_ALW_ACTION_LOG", errno);
		}
		break;
	}
	case IPM_SET_IIPM_DEBUG:
	case IPM_CLR_IIPM_DEBUG:
	{
		rsperr = IPM_SUCCESS;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if( msg->h.type == IPM_SET_IIPM_DEBUG )
			{
				iipm_debug = msg->cmd_ipm_admin.data;
			}
			else
			{
				iipm_debug = 0;
			}
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_IIPM_DEBUG", errno);
		}
		break;
	}
	case IPM_SET_EIPM_DEBUG:
	case IPM_CLR_EIPM_DEBUG:
	{
		rsperr = IPM_SUCCESS;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			if( msg->h.type == IPM_SET_EIPM_DEBUG )
			{
				eipm_debug = msg->cmd_ipm_admin.data;
			}
			else
			{
				eipm_debug = 0;
			}
		}
		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_EIPM_DEBUG", errno);
		}
		break;
	}
	case IPM_DUMP_SESSION:
	{
		rsperr = IPM_SUCCESS;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			(void) EIPM_dump_session(
				&msg->cmd_ipm_admin,
				reply_text
			);
		}

		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_DUMP_SESSION", errno);
		}
		break;
	}

	case IPM_SET_SOAK_TIMER:
	{
		rsperr = IPM_SUCCESS;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof (struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			int soak_timer = msg->cmd_ipm_admin.data;
			if ((soak_timer > MAX_SOAK_TIME) || (soak_timer < MIN_SOAK_TIME))
			{
				// Invalid value, set soak timer to default value.
				soak_timer = DFT_SOAK_TIME;
			}
			EIPM_DATA *data_ptr = (EIPM_DATA *) EIPM_shm_ptr;
			data_ptr->soak_timer = soak_timer;
			rsperr = IPM_SUCCESS;
		}

		ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);

		msg->h.error = rsperr;
		msg->h.size = sizeof (msg->rsp_ipm_admin);
		if (sendto(msg->h.s, msg, sizeof (struct nma_msgsocketheader_t) +msg->h.size, MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *) cliAddr, sizeof (*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND, "%s: %s: send errno %d", __FUNCTION__, "IPM_SET_SOAK_TIMER", errno);
		}
		break;
	}

	case IPM_SET_SESSION:
	{
		rsperr = IPM_SUCCESS;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_ipm_admin), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_ipm_admin))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			rsperr = EIPM_set_session(
					&msg->cmd_ipm_admin,
					reply_text
				);
		}
		if( strlen(reply_text) > 0 )
		{
			strncpy(msg->rsp_ipm_admin.text, reply_text, REPLY_TEXT);
		}
		else
		{
			ipm_fill_errtext(msg->h.error, msg->rsp_ipm_admin.text, REPLY_TEXT);
		}

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_ipm_admin);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_SET_SESSION", errno);
		}
		break;
	}

	case IPM_SET_SUBNET:
	{
		rsperr = IPM_SUCCESS;
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_subnet_upd), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_subnet_upd))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			struct cmd_subnet_upd *subnet_upd_ptr = &msg->cmd_subnet_upd;
			
			msg->h.error = rsperr;
			/* put EIPM API to call the BFD api */
			msg->h.error = EIPM_set_subnet(
				 &msg->cmd_subnet_upd,
				 reply_text);

			/*255 means NO update for table_num */
			if(subnet_upd_ptr->table_num == 255)
			{
				rsperr = msg->h.error;
			}
			else
			{
				/* put PIPM API to update sbpr value */
				rsperr = PIPM_set_subnet(
					(void *)&msg->cmd_subnet_upd,
					reply_text1);

				if (msg->h.error != IPM_SUCCESS )
				{
					rsperr = msg->h.error;
				}
				else if (rsperr != IPM_SUCCESS )
				{
					strncpy(reply_text, reply_text1, REPLY_TEXT);
				}
			}

		}

		if( strlen(reply_text) > 0 )
		{
			strncpy(msg->rsp_subnet_upd.text, reply_text, REPLY_TEXT);
		}
		else
		{
			ipm_fill_errtext(msg->h.error, msg->rsp_subnet_upd.text, REPLY_TEXT);
		}

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_subnet_upd);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, "IPM_SET_SUBNET", errno);
		}
		break;
	}

	case IPM_ADD_TUNNEL:
	case IPM_DEL_TUNNEL:
	{
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_tunnel_upd), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_tunnel_upd))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{		
			rsperr = EIPM_cmd_tunnel_update(
					&msg->cmd_tunnel_upd, 
					msg->h.type, reply_text);

			msg->h.error = rsperr;
			msg->h.size = sizeof(msg->rsp_tunnel_upd);
			if( strlen(reply_text) > 0 )
			{
				strncpy(msg->rsp_tunnel_upd.text, reply_text, REPLY_TEXT);
			}
			else
			{
				ipm_fill_errtext(msg->h.error, msg->rsp_tunnel_upd.text, REPLY_TEXT);
			}

			if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
			{
				LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, msg->h.type, errno);
			}

			break;		

		}
	}

	case IPM_ADD_INT_SUBNET:
	case IPM_DEL_INT_SUBNET:
	case IPM_ADD_EXT_SUBNET:
	case IPM_DEL_EXT_SUBNET:
	{
		int del_flag = 0;
		rsperr = IPM_SUCCESS;

		if ((msg->h.type == IPM_DEL_INT_SUBNET) || ( msg->h.type == IPM_DEL_EXT_SUBNET))
		{
			del_flag = 1;
		}
		ipm_msg_prtlog(msg->h.type, &(msg->cmd_subnet_upd), msg->h.size);
		if (msg->h.size != sizeof(struct cmd_subnet_upd))
		{
			rsperr = IPM_INVALIDMSGLEN;
		}
		else
		{
			struct cmd_subnet_upd *subnet_upd_ptr = &msg->cmd_subnet_upd;

			msg->h.error = rsperr;
			msg->h.error = EIPM_subnet_update(
					&msg->cmd_subnet_upd,
					( del_flag ? EIPM_DEL : EIPM_ADD ),
					reply_text, CLI_REQUEST
				);
			rsperr = PIPM_cmd_subnet_update(
				(void *)&msg->cmd_subnet_upd,
				msg->h.type,
				reply_text1, CLI_REQUEST
			);

			if (msg->h.error != IPM_SUCCESS )
			{
				rsperr = msg->h.error;
			}
			else if (rsperr != IPM_SUCCESS )
			{
				strncpy(reply_text, reply_text1, REPLY_TEXT);
			}
		}

		if( strlen(reply_text) > 0 )
		{
			strncpy(msg->rsp_subnet_upd.text, reply_text, REPLY_TEXT);
		}
		else
		{
			ipm_fill_errtext(msg->h.error, msg->rsp_subnet_upd.text, REPLY_TEXT);
		}

		msg->h.error = rsperr;
		msg->h.size = sizeof(msg->rsp_subnet_upd);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, (struct sockaddr *)cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"%s: %s: send errno %d", __FUNCTION__, ( del_flag ? "IPM_DEL_EXT_SUBNET" : "IPM_ADD_EXT_SUBNET"), errno);
		}

		break;
	}


#ifdef _XMA
/* The following cmd are not used by ipm now */
	case SUPMSG:
	{
		ixtrt = 6;
		msgframe = (struct msgframe*)msg;
		for (i = 0;i < MAX_NB_DEV;i++)
		{
			if (msgframe->links & (1 << i))
			{
				reccounter++;
				//function need to be changed
				nma_rec_spv(ctx,&(msgframe->supervision),i,msgframe->size,TRUE,&flush,&compute,&routecounter);
			}
	    	}
		break;
	}
	case SETALIAS :
	{
		ixtrt = 7;
		msg->h.error = nma_set_alias(ctx,msg->cmdsetalias.ip,msg->cmdsetalias.mask,msg->cmdsetalias.links,msg->cmdsetalias.name,msg->cmdsetalias.flush); 
		msg->h.size = sizeof(msg->rspsetalias);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main : send errno %d",errno);
		}
		break;
	}
	case UNSETALIAS :
	{
		ixtrt = 8;
		msg->h.error = nma_unset_alias(ctx,msg->cmdunsetalias.ip,msg->cmdunsetalias.flush);
		msg->h.size = sizeof(msg->rspunsetalias);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main : send errno %d",errno);
		}
		break;
	}
	case SETLSN :
	{
		ixtrt = 9;
		ctx->a.lsn = msg->cmdsetlsn.lsn;
		LOG_OTHER(NMA_OAPI,"nma_main : station lsn set to %d",ctx->a.lsn);
		msg->h.error = 0;
		msg->h.size = sizeof(msg->rspsetlsn);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT,  cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main : send errno %d",errno);
		}
		break;
	}
	case SETLOG:
	{
		ixtrt = 10;
		ctx->a.flaglog = msg->cmdsetlog.filter;
		LOG_FORCE(NMA_OAPI,"nma_main : log filter set to 0x%x",ctx->a.flaglog);
		msg->h.error = 0; 
		msg->h.size = sizeof(msg->rspsetlog);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main : send errno %d",errno);
		}
		break;
	}
	case GETPLATFORMSTAACCESS:
	{
		ixtrt = 11;
		for (i = 0;i < ctx->a.nb_station_list;i++)
		{
			msg->rspgetplatformstaaccess.station[i] = ctx->b.station_list[i];
			msg->rspgetplatformstaaccess.access[i] = ctx->b.station_access[i];
			msg->rspgetplatformstaaccess.shelf[i] = ctx->b.station_shelfid[i];
		}
		msg->rspgetplatformstaaccess.nb_sta = ctx->a.nb_station_list;
		msg->h.error = 0; 
		msg->h.size = sizeof(msg->rspgetplatformstaaccess);                
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT,  cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main : send errno %d",errno);
		}
		break;
	}
	case GETLSNACCESS:
	{
		ixtrt = 12;
		msg->rspgetlsnaccess.shelf = ctx->b.station_shelfid[0];
		msg->rspgetlsnaccess.access = ctx->b.shelf_access[ctx->b.station_shelfid[0]];
		msg->h.error = 0; 
		msg->h.size = sizeof(msg->rspgetlsnaccess);                
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT,  cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main : send errno %d",errno);
		}
		break;
	}
	case GETCTXSTATION:
	{
		ixtrt = 13;
		for (station = ctx->a.STATIONHEAD;station != NULL;station = station->next)
		{
			if (msg->cmdgetctxsta.ip == station->ip_addr[0])
			{
				msg->rspgetctxsta.ip = msg->cmdgetctxsta.ip;
				msg->rspgetctxsta.ctx = *station;
				msg->rspgetctxsta.nb_sta = ctx->a.nb_station_list;               
				memcpy(msg->rspgetctxsta.station,ctx->b.station_list,sizeof(ctx->b.station_list));
				break;
			}
		}
		if (station == NULL)
		{
			msg->h.error = UNKNOWNSTATION;
		} 
		else
		{
			msg->h.error = 0; 
		} 
		msg->h.size = sizeof(msg->rspgetctxsta);                
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT,  cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main : send errno %d",errno);
		}
		break;
	}
	case SETGLOBALLSN :
	{
		ixtrt = 14;
		lsn = msg->cmdsetgloballsn.lsn;
		LOG_OTHER(NMA_OAPI,"nma_main : platform lsn set to %d",lsn);
		msg->h.error = 0;
		msg->h.size = sizeof(msg->rspsetgloballsn);                
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT,  cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main : send errno %d",errno);
		}
		break;
	}	  
	case RESETSTAT :
	{
		ixtrt = 15;
		overrun = 0;
		hangupmax = 0;
		hangupmax_frames = 0;
		hangupmax_routes = 0;
		hangupmax_date.tv_sec = 0;
		hangupmax_date.tv_nsec = 0;
		overrun_date.tv_sec = 0;
		overrun_date.tv_nsec = 0;
		hangupmax_trt[0] = '\0';
		memset(hangup,0,sizeof(hangup));
		msg->h.error = 0;
		msg->h.size = sizeof(msg->rspresetstat);                
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT,  cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main : send errno %d",errno);
		}
		break;
	}
	case GETSTAT:
	{
		ixtrt = 16;
		msg->rspgetstat.n = MAX_NB_SLOT;
		msg->rspgetstat.slot = 1 << SHIFT_SLOT;
		msg->rspgetstat.overrun = overrun;
		msg->rspgetstat.overrun_date = overrun_date;
		msg->rspgetstat.hangupmax = hangupmax;
		msg->rspgetstat.hangupmax_frames = hangupmax_frames;
		msg->rspgetstat.hangupmax_routes = hangupmax_routes;
		msg->rspgetstat.hangupmax_date = hangupmax_date;
		strncpy(msg->rspgetstat.hangupmax_trt, hangupmax_trt, 31);
		msg->rspgetstat.hangupmax_trt[31] = 0;
		memcpy(msg->rspgetstat.hangup,hangup,sizeof(hangup));
		msg->h.error = 0; 
		msg->h.size = sizeof(msg->rspgetstat);                
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT,  cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main : send errno %d",errno);
		}
		break;
	}
	case SETGLOBALLOG:
	{
		ixtrt = 17;
		flaglog = msg->cmdsetgloballog.filter;
		LOG_FORCE(NMA_OAPI,"nma_main : global log filter set to 0x%x",flaglog);
		msg->h.error = 0; 
		msg->h.size = sizeof(msg->rspsetgloballog);                
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main : send errno %d",errno);
		}
		free(msg);
		break;
	}	
	case SUBSTASTATUS:
	{
		ixtrt = 20;
		index = nma_indexconnection(ctx,msg->h.s);
		if (index >= 0)
		{
			(void)nma_startstation_subscription(ctx,TYPESTASTATUS,index,msg->substastatus.ip,msg->h.invokeid);
		}
		break;	 
	}
	case SUBSTAACCESS:
	{
		ixtrt = 21;
		index = nma_indexconnection(ctx,msg->h.s);
		if (index >= 0)
		{
			(void)nma_startstation_subscription(ctx,TYPESTAACCESS,index,msg->substaaccess.ip,msg->h.invokeid);
		}
		break;	
	}		  		  	
	case UNSUBSTASTATUS:
	{
		ixtrt = 22;
		index = nma_indexconnection(ctx,msg->h.s);
		if (index >= 0)
		{
			(void)nma_stopstation_subscription(ctx,index,msg->h.invokeid);
		}
		break;	 
	}
	case UNSUBSTAACCESS:
	{
		ixtrt = 23;
		index = nma_indexconnection(ctx,msg->h.s);
		if (index >= 0)
		{
			(void)nma_stopstation_subscription(ctx,index,msg->h.invokeid);
		}
		break; 
	}
	case SUBLSNACCESS:
	{
		ixtrt = 24;
		index = nma_indexconnection(ctx,msg->h.s);
		if (index >= 0)
		{
			(void)nma_startplatform_subscription(ctx,TYPELSNACCESS,index,msg->h.invokeid,0);
		}
		break;	
	}
	case UNSUBLSNACCESS:
	{
		ixtrt = 25;
		index = nma_indexconnection(ctx,msg->h.s);
		if (index >= 0)
		{
			(void)nma_stopplatform_subscription(ctx,index,msg->h.invokeid);
		}
		break;	
	}
	case SUBPLATFORMSTAACCESS:
	{
		ixtrt = 26;
		index = nma_indexconnection(ctx,msg->h.s);
		if (index >= 0)
		{
			(void)nma_startplatform_subscription(ctx,TYPEPLATFORMSTAACCESS,index,msg->h.invokeid,0);
		}
		break;	
	}
	case UNSUBPLATFORMSTAACCESS:
	{
		ixtrt = 27;
		index = nma_indexconnection(ctx,msg->h.s);
		if (index >= 0)
		{
			(void)nma_stopplatform_subscription(ctx,index,msg->h.invokeid);
		}
		break;
	}
	case GETCONFIG:
	{
		ixtrt = 28;
		msg->rspgetconfig.credit = ctx->b.credit;
		msg->rspgetconfig.credit_degraded = ctx->a.credit_degraded;
		msg->rspgetconfig.psupervision = ctx->b.psupervision;
		msg->rspgetconfig.slave = nb_slave;
		msg->rspgetconfig.slave_base = baseaddr;
		msg->rspgetconfig.log = flaglog;
		msg->rspgetconfig.lsn = lsn;
		msg->rspgetconfig.hang_threshold = hangthreshold;
		msg->rspgetconfig.maxroutes = maxroutes;
		msg->rspgetconfig.qos = ctx->a.qos;
		msg->rspgetconfig.add_shift_degfull = addshiftdegfull;
		msg->rspgetconfig.min_shift_degfull = minshiftdegfull;
		msg->rspgetconfig.max_shift_degfull = maxshiftdegfull;
		msg->rspgetconfig.min_period_degfull = minperioddegfull;
		msg->rspgetconfig.max_period_degfull = maxperioddegfull;
		msg->rspgetconfig.shelfid = ctx->a.shelfid;
		msg->rspgetconfig.gnmsession = ctx->a.gnmsession;
		msg->h.error = 0; 
		msg->h.size = sizeof(msg->rspgetconfig);                
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT, cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main : send errno %d",errno);
		}
		break;		  		  		  		  
	}
	case SUBPLATFORMLSNACCESS:
	{
		ixtrt = 29;
		index = nma_indexconnection(ctx,msg->h.s);
		if (index >= 0)
		{
			(void)nma_startplatform_subscription(ctx,TYPEPLATFORMLSNACCESS,index,msg->h.invokeid,0);
		}
		break;	
	}
	case UNSUBPLATFORMLSNACCESS:
	{
		ixtrt = 30;
		index = nma_indexconnection(ctx,msg->h.s);
		if (index >= 0)
		{
			(void)nma_stopplatform_subscription(ctx,index,msg->h.invokeid);
		}
		break;	
	}
	case MANAGEALIAS :
	{
		ixtrt = 31;
		msg->h.error = nma_manage_alias(ctx,msg->cmdmanagealias.ip,msg->cmdmanagealias.mask,msg->cmdmanagealias.links,msg->cmdmanagealias.name,msg->cmdmanagealias.immediate); 
		msg->h.size = sizeof(msg->rspmanagealias);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT,  cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main : send errno %d",errno);
		}
		break;
	}
	case UNMANAGEALIAS :
	{
		ixtrt = 32;
		msg->h.error = nma_unmanage_alias(ctx,msg->cmdunmanagealias.ip,msg->cmdunmanagealias.immediate);
		msg->h.size = sizeof(msg->rspunmanagealias);
		if (sendto(msg->h.s,msg,sizeof(struct nma_msgsocketheader_t)+msg->h.size,MSG_NOSIGNAL | MSG_DONTWAIT,  cliAddr, sizeof(*cliAddr)) < 0)
		{
			LOG_ERROR(NMA_ESEND,"nma_main : send errno %d",errno);
		}
		break;
	}
#endif
	default :
	{
		LOG_ERROR(NMA_SEMSGSOCKET, "Unknow Command %d, discard it", msg->h.type);
		break;
	}

   } // end switch(msg->h.type)

   return(0);

} //end function ipm_proc_cli_msg
