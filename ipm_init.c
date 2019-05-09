
/* File: 
 *	glob/src/ipm/ipm_init.c
 *
 * Description: 
 *	initialize configuration parameter by set default value or read it from config file
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "nnn_internal.h"
#include "nnn_define.h"
#include "ipm_init.h"
#include "nma_log.h"
#include "nma_route.h"
#include "nnn_socket.h"
#include "ipm_util.h"
#include "ipm_retval.h"
#include "EIPM_include.h"
#include "PIPM_include.h"
#include "ipm_msg.h"


/* Global Variables for configure parameter */
#if defined (_VHE) && !defined(_NFF)
char ipmCfgFname[PATH_MAX] = "/etc/opt/vcp/ipm/ipm.cfg";
char ipmPidDir[PATH_MAX] = "/var/opt/vcp/run";
#elif _NFF
char ipmCfgFname[PATH_MAX] = "/etc/opt/nff/ipm/ipm.cfg";
char ipmPidDir[PATH_MAX] = "/var/opt/nff/run";
#else
char ipmCfgFname[PATH_MAX] = "/etc/opt/LSS/ipm.cfg";
char ipmPidDir[PATH_MAX] = "/var/opt/run";
#endif
char ipmHostName[NAME_MAX];

nma_ctx_t nma_ctx;

int nb_slave = 0;
int baseaddr = 0;

unsigned char lsn = LINK_ALL;

int hangthreshold = HANGTHRESHOLD;
int maxroutes = MAX_NB_ROUTES;
int addshiftdegfull = ADD_SHIFT_DEGFULL;
int minshiftdegfull = MIN_SHIFT_DEGFULL;
int maxshiftdegfull = MAX_SHIFT_DEGFULL;
int minperioddegfull = MIN_PERIOD_DEGFULL;
int maxperioddegfull = MAX_PERIOD_DEGFULL;
unsigned int flaglog = MANDATORYLOGS;

int iipm_enable = FALSE;
int eipm_enable = FALSE;
int iipm_debug = 0;
int eipm_debug = 0;
int pipm_enable = FALSE;
int pipm_path_refresh_time = PIPM_PATH_REFRESH_TIME;
int pipm_l2_path_enable = FALSE;
int eipm_proid = EIPM_ETH_PROTO;
int eipm_arp_delay_degraded = EIPM_ARP_DELAY_DEGRADED;
int eipm_arp_sent_degraded = EIPM_ARP_SENT_DEGRADED;
int eipm_garp_cnt = EIPM_GARP_CNT_DEFAULT;
int eipm_garp_delay = EIPM_GARP_DELAY_DEFAULT;
int eipm_delete_interface_with_no_subnet = TRUE;
int debug_enable = FALSE;
int debug_msg_cnt = 1;
int syslog_enable = 0;
int logger_ready = FALSE;
int nma_thread_priority = NMA_THREAD_PRIORITY;

int ipm_alarm_delay = NNN_CREDIT * 2;

/* Set configuration value */
int ipm_cfg_setvalue(char *tagName, char *tagValue)
{
	if (strcasecmp(tagName, "NMA_PROID") == 0)
	{
		nma_ctx.b.proid = atoi(tagValue);
		if (nma_ctx.b.proid == 0) 
		{
			nma_ctx.b.proid = NNN_PROTOID;
		}
	}
	else if (strcasecmp(tagName, "NMA_CREDIT") == 0)
	{
		nma_ctx.b.credit = atoi(tagValue);
		if (nma_ctx.b.credit <= 0)
		{
			nma_ctx.b.credit = NNN_CREDIT;
		}
	}
	else if (strcasecmp(tagName, "NMA_PSUPERVISION") == 0)
	{
		nma_ctx.b.psupervision = atoi(tagValue);
		if (nma_ctx.b.psupervision <= 0)
		{
			nma_ctx.b.psupervision = NNN_PSUPERVISION;
		}
	}
	else if (strcasecmp(tagName, "NMA_CREDIT_DEGRADED") == 0)
	{
		nma_ctx.a.credit_degraded = atoi(tagValue);
		if (nma_ctx.a.credit_degraded <= 0)
		{
			nma_ctx.a.credit_degraded = 3;
		}
	}
	else if (strcasecmp(tagName, "NMA_ISOLATED") == 0)
	{
		nma_ctx.a.isolated = atoi(tagValue);
	}
	else if (strcasecmp(tagName, "NMA_QOS") == 0)
	{
		nma_ctx.a.qos = atoi(tagValue);
	}
	else if (strcasecmp(tagName, "NMA_SLAVE") == 0)
	{
		nb_slave = atoi(tagValue); 
		if (nb_slave > MAX_NB_STA-1) nb_slave = MAX_NB_STA-1;
	}
	else if (strcasecmp(tagName, "NMA_SLAVE_BASE") == 0)
	{
		baseaddr = strtol(tagValue,(char **)NULL,0);
	}
	else if (strcasecmp(tagName, "NMA_LOG") == 0)
	{
		flaglog = strtol(tagValue,(char **)NULL,0);
		if (flaglog <= 0)
		{
			flaglog = MANDATORYLOGS;
		}
	}
	else if (strcasecmp(tagName, "NMA_LSN") == 0)
	{
		lsn = atoi(tagValue);
		if (lsn <= 0)
		{
			lsn = LINK_ALL;
		}
	}
	else if (strcasecmp(tagName, "NMA_HANG_THRESHOLD") == 0)
	{
		hangthreshold = atoi(tagValue);
		if (hangthreshold < 0)
		{
			hangthreshold = HANGTHRESHOLD;
		}
	}
	else if (strcasecmp(tagName, "NMA_MAXROUTES") == 0)
	{
		maxroutes = atoi(tagValue);
		if (maxroutes <= 0)
		{
			maxroutes = MAX_NB_ROUTES;
		}
	}
	else if (strcasecmp(tagName, "NMA_ADD_SHIFT_DEGFULL") == 0)
	{
		addshiftdegfull = atoi(tagValue);
		if (addshiftdegfull <= 0)
		{
			addshiftdegfull = ADD_SHIFT_DEGFULL;
		}
	}
	else if (strcasecmp(tagName, "NMA_MIN_SHIFT_DEGFULL") == 0)
	{
		minshiftdegfull = atoi(tagValue);
		if (minshiftdegfull <= 0)
		{
			minshiftdegfull = MIN_SHIFT_DEGFULL;
		}
	}
	else if (strcasecmp(tagName, "NMA_MAX_SHIFT_DEGFULL") == 0)
	{
		maxshiftdegfull = atoi(tagValue);
		if (maxshiftdegfull <= 0)
		{
			maxshiftdegfull = MAX_SHIFT_DEGFULL;
		}
	}
	else if (strcasecmp(tagName, "NMA_MIN_PERIOD_DEGFULL") == 0)
	{
		minperioddegfull = atoi(tagValue);
		if (minperioddegfull <= 0)
		{
			minperioddegfull = MIN_PERIOD_DEGFULL;
		}
	}
	else if (strcasecmp(tagName, "NMA_MAX_PERIOD_DEGFULL") == 0)
	{
		maxperioddegfull = atoi(tagValue);
		if (maxperioddegfull <= 0)
		{
			maxperioddegfull = MAX_PERIOD_DEGFULL;
		}
	}
	else if (strcasecmp(tagName, "IPM_PID_DIR") == 0)
	{
		strncpy(ipmPidDir, tagValue, sizeof(ipmPidDir));
	}
	else if (strcasecmp(tagName, "NMA_THREAD_PRIORITY") == 0)
	{
		nma_thread_priority = atoi(tagValue);
		if (nma_thread_priority <= 0)
		{
			nma_thread_priority = NMA_THREAD_PRIORITY;
		}
	}
	else if (strcasecmp(tagName, "IIPM_ENABLE") == 0)
	{
		iipm_enable = atoi(tagValue);
	}
	else if (strcasecmp(tagName, "PIPM_ENABLE") == 0)
	{
		pipm_enable = atoi(tagValue);
	}
	else if (strcasecmp(tagName, "PIPM_PATH_REFRESH_TIME") == 0)
        {
                pipm_path_refresh_time = atoi(tagValue);
        }
	else if (strcasecmp(tagName, "EIPM_ENABLE") == 0)
	{
		eipm_enable = atoi(tagValue);
	}
	else if (strcasecmp(tagName, "EIPM_PROID") == 0)
	{
		eipm_proid = atoi(tagValue);
	}
	else if (strcasecmp(tagName, "EIPM_ARP_DELAY_DEGRADED") == 0)
	{
		eipm_arp_delay_degraded = atoi(tagValue);
	}
	else if (strcasecmp(tagName, "EIPM_ARP_SENT_DEGRADED") == 0)
	{
		eipm_arp_sent_degraded = atoi(tagValue);
	}
	else if (strcasecmp(tagName, "EIPM_GARP_CNT") == 0)
	{
		eipm_garp_cnt = atoi(tagValue);
	}
	else if (strcasecmp(tagName, "EIPM_GARP_DELAY") == 0)
	{
		eipm_garp_delay = atoi(tagValue);
	}
	else if (strcasecmp(tagName, "EIPM_DELETE_INTERFACE_WITH_NO_SUBNET") == 0)
	{
		eipm_delete_interface_with_no_subnet = atoi(tagValue);
	}
	else if (strcasecmp(tagName, "DEBUG_ENABLE") == 0)
	{
		debug_enable = atoi(tagValue);
	}
	else if (strcasecmp(tagName, "DEBUG_MSG") == 0)
	{
		debug_msg_cnt = atoi(tagValue);
	}
	else if (strcasecmp(tagName, "SYSLOG_ENABLE") == 0)
	{
		syslog_enable = atoi(tagValue);
	}
	else if (strcasecmp(tagName, "LOG_LOCAL") == 0)
	{
		syslog_enable = atoi(tagValue);
	}
	else if (strcasecmp(tagName, "LOG_REMOTE") == 0)
	{
		ipm_log_remote = atoi(tagValue);
	}
	else if (strcasecmp(tagName, "LOG_ACTION") == 0)
	{
		ipm_action_log_level = atoi(tagValue);
                if (ipm_action_log_level)
                {
                        ipm_action_log_level = LOG_HIGH;
                }
                else
                {
                        ipm_action_log_level = LOG_MEDIUM;
                }
	}
	else if (strcasecmp(tagName, "LOG_CHECKING") == 0)
	{
		ipm_check_log_level = atoi(tagValue);
                if (ipm_check_log_level)
                {
                        ipm_check_log_level = LOG_HIGH;
                }
                else
                {
                        ipm_check_log_level = LOG_MEDIUM;
                }
	}
	else if (strcasecmp(tagName, "SHELF_ID") == 0)
	{
		nma_ctx.a.shelfid = atoi(tagValue);
	}
	else if (strcasecmp(tagName, "EIPM_PROXY_PATH_TIMER") == 0)
        {
                nma_ctx.b.proxy_path_timer = atoi(tagValue);
                if (nma_ctx.b.proxy_path_timer <= 0)
                {
                        nma_ctx.b.proxy_path_timer = EIPM_PROXY_PATH_TIMER;
                }

        }

	return 0;
}

/* Read configuration parameter of IPM from file */
int ipm_cfg_read(char* fname)
{
	FILE *  fp;
	char    line[IPM_LINE_LEN];
	char    tagName[IPM_LINE_LEN];
	char    tagValue[IPM_LINE_LEN];
	char    seps[] = " =,\t\n";
	char *  token;
	char *  saveptr;
	int     lineLen;
	int     rc;
	struct stat fs;

	if(access(fname, F_OK|R_OK) < 0 )
	{
		ASRT_RPT(ASUNEXP_RETURN, 0, "not exist or no read permission: %s errno = %d\n", fname, errno);
		return -1;
	}
	if (stat(fname, &fs) < 0)
	{
		ASRT_RPT(ASUNEXP_RETURN, 0, "stat failed: %s errno = %d\n", fname, errno);
		return -1;
	}
	if (!(S_ISREG(fs.st_mode)))
	{
		ASRT_RPT(ASUNEXP_RETURN, 0, "not regular file: %s errno = %d\n", fname, errno);
		return -1;
	}
	if((fp = fopen(fname, "r")) == NULL)
	{
		ASRT_RPT(ASUNEXP_RETURN, 0, "Open file failed: %s errno = %d\n", fname, errno);
		return -1;  /* open file failed */
	}

	fgets(line, IPM_LINE_LEN, fp);
	while(!feof(fp))
	{
		tagName[0] = '\0';
		tagValue[0] = '\0';

		if(line[0] != '#' && line[0] != '\n' && line[0] != '[')
		{
			token = strtok_r(line, seps, &saveptr);
			if(token != NULL)
			{
				strncpy(tagName, token, IPM_LINE_LEN-1);
				tagName[IPM_LINE_LEN-1] = 0;
				/* Get next token: */
				token = strtok_r(NULL, seps, &saveptr);
				strncpy(tagValue, token, IPM_LINE_LEN-1);
				tagValue[IPM_LINE_LEN-1] = 0;
			}

			if(tagName[0] != '\0' && tagValue[0] != '\0')
			{
				if((rc = ipm_cfg_setvalue(tagName, tagValue)) < 0)
				{
					ASRT_RPT(ASBAD_DATA, 0, "ipm_cfg_setvalue(%s,%s) failed, %d", tagName, tagValue, rc);
					rc = fclose(fp);
					if (rc < 0)
					{
						ASRT_RPT(ASUNEXP_RETURN, 0, "fclose failed errno=%d\n", errno);
					}
					return -2; /* wrong configuration */
				}
			}
		} /* end if(line[0] != '#'...) */

		fgets(line, IPM_LINE_LEN, fp);

	} /* end while loop reading file */

	rc = fclose(fp);
	if (rc < 0)
	{
		ASRT_RPT(ASUNEXP_RETURN, 0, "fclose failed errno=%d\n", errno);
	}
	return 0;
}


// read config file to overwrite default changes.
int ipm_cfg_init()
{
	unsigned char m_cast[] = NNN_GMULTICAST;
	char * envPtr;

	memset(&nma_ctx, 0, sizeof(nma_ctx_t));
	//set default value for nma_ctx
	nma_ctx.a.inuse = FALSE;
	nma_ctx.a.globalstate = NNN_INIT;
	nma_ctx.a.STATIONHEAD = NULL;
	nma_ctx.a.STATIONTAIL = NULL;
	nma_ctx.a.lsn = LINK_ALL;
	nma_ctx.a.credit_degraded = 3;
	nma_ctx.a.isolated = FALSE;
	nma_ctx.a.master = TRUE;
	nma_ctx.a.nb_station_list = 0;
	nma_ctx.a.nb_alias = 0;
	nma_ctx.a.flaglog = ALLLOGS;
	nma_ctx.a.ticks = 0;
	nma_ctx.a.more = FALSE;
	nma_ctx.a.gnmindex = -1;
	nma_ctx.a.qos = QOS;
	nma_ctx.a.shelfid = SHELFID0;
	nma_ctx.a.gnmsession = FALSE;
	nma_ctx.a.creditinframe = FALSE;
	nma_ctx.a.iipm_interface_status = LINK_NONE; //when ipm start, it should be 0 not 3
	nma_ctx.a.iipm_preferred_side = LINK_0;
	nma_ctx.a.iipm_preferred_side_update = 0;

	//set default value. based on default value from nnn_init.c
	nma_ctx.b.proid = NNN_PROTOID;

	nma_ctx.b.credit = NNN_CREDIT; 

	nma_ctx.b.psupervision = NNN_PSUPERVISION; //default 128ms 

	nma_ctx.b.proxy_path_timer = EIPM_PROXY_PATH_TIMER; //default 300s

	memcpy(&(nma_ctx.b.group_multicast),
		m_cast,
		sizeof(nma_ctx.b.group_multicast));

	nma_ctx.b.credit = NNN_CREDIT; 
	nma_ctx.a.credit_degraded = 3;
	nma_ctx.a.isolated = FALSE;
	nb_slave = 0;
	baseaddr = 0;
	lsn = LINK_ALL;
	//micro seconds
	hangthreshold = 20000;
  
	/* Sequence number to use for RTNETLINK messages */ 
	IPM_rt_seq = time( NULL );

	addshiftdegfull = ADD_SHIFT_DEGFULL;
	minshiftdegfull = MIN_SHIFT_DEGFULL;
	maxshiftdegfull = MAX_SHIFT_DEGFULL;
	minperioddegfull = MIN_PERIOD_DEGFULL;
	maxperioddegfull = MAX_PERIOD_DEGFULL;

	envPtr = getenv("IPM_CFG_FILE");
	if(envPtr != NULL)
	{
		if( strlen(envPtr) < sizeof(ipmCfgFname) )
		{
			strcpy(ipmCfgFname, envPtr);
		}
	}

	/* read conf parameter from file */
	ipm_cfg_read(ipmCfgFname);

#ifndef _VHE
	/* leave IPM inhibited in ATE */
	{
	int  ret;
	char cmd[256];

		sprintf(cmd, "/opt/LSS/sbin/brdinfo | grep 440BX");

		ret = system(cmd);

		if( ret == 0 )
		{
			iipm_enable = FALSE;
		}
	}
#endif

	/* take any action based on conf parameter */
	if( syslog_enable == 1 )
	{
		ipm_syslog_start();
	}

	//calculate after get all data
	nma_ctx.b.min_credit_degfull = minperioddegfull/nma_ctx.b.psupervision;
	nma_ctx.b.max_credit_degfull = maxperioddegfull/nma_ctx.b.psupervision;

	//calculate alarm delay, which equals to degrad interval plus delta(2)
	ipm_alarm_delay = (nma_ctx.b.credit-nma_ctx.a.credit_degraded+1)+2;
	
	return 0;

}

void ipm_init_output(nma_ctx_t * ctx)
{
	FILE * file;

	if (ctx->a.master)
	{
		// init result output
		if ((file = fopen(NMAFILE,"w+")) == NULL)
		{
			NMA_PANIC(&(ctx->a.my[0].ip),NMA_PFATALERROR,"nma_main : fopen errno %d",errno);
			return;
		}
		if (fprintf(file,"%s %s\n", ctx->a.my[0].name,ctx->a.my[1].name) == 0) 
		{
			NMA_PANIC(&(ctx->a.my[0].ip),NMA_PFATALERROR,"nma_main : fprintf errno %d",errno);
		}
		if (fprintf(file,"%d %d %d %d %s 0x%x %d %d %d\n",ctx->b.credit,
								ctx->a.credit_degraded,
								ctx->b.psupervision,
								nb_slave,
								strchr(strchr(inet_ntoa(*(struct in_addr*)(&baseaddr)),'.')+1,'.')+1,
								flaglog,
								lsn,
								hangthreshold,
								maxroutes) == 0) 
		{
			NMA_PANIC(&(ctx->a.my[0].ip),NMA_PFATALERROR,"nma_main : fprintf errno %d",errno);
		}
		if (fprintf(file,"%d %d %d %d %d %d %d\n",ctx->a.qos,
								addshiftdegfull,
								minshiftdegfull,
								minperioddegfull,
								maxperioddegfull,
								ctx->a.shelfid,
								ctx->a.gnmsession) == 0)
		{
			NMA_PANIC(&(ctx->a.my[0].ip),NMA_PFATALERROR,"nma_main : fprintf errno %d",errno);
		}
		if (fprintf(file, "%d %d %d %d %d\n", iipm_enable, eipm_enable, pipm_enable, debug_enable, debug_msg_cnt) == 0)
		{
			NMA_PANIC(&(ctx->a.my[0].ip),NMA_PFATALERROR,"nma_main : fprintf errno %d",errno);
		}
		fclose(file);
	} // end if(ctx->master)
}

/*
    struct alias_ip_t lsn_alias[MAX_NB_DEV]
 */
int ipm_init_interfaces(nma_ctx_t *ctx, struct alias_ip_t *lsn_alias)
{
	nma_interface_t nif;
	int index, error;
	struct ifreq  ifr;
	IPM_IPADDR addr;
	IPM_RETVAL retval;

	for (index = 0; index < MAX_NB_DEV; index++)
	{
		if (lsn_alias[index].alias_if[0] == '\0')
		{
			continue;
		}
		memset(&nif, 0, sizeof(nma_interface_t));
		strncpy(nif.name, lsn_alias[index].alias_if, sizeof(nif.name));
		error = ipm_get_intf(inetsocket, &nif);
		if (error != IPM_SUCCESS)
		{
			return error;
		}
		nif.mask = CONVERT2NETMASK(lsn_alias[index].prefix);
		retval = IPM_p2ipaddr(lsn_alias[index].ip, &addr);
		if (retval != IPM_SUCCESS)
		{
			LOG_ERROR(0, "ipm_init_interfaces: wrong input ip (%s)", lsn_alias[index].ip);
			return (IPM_INVALIDPARAMETER);	
		}
		if (addr.addrtype != IPM_IPV4) /* LSN IP should be IPv4 */
		{
			LOG_ERROR(0, "ipm_init_interfaces: Invalid address type %d", addr.addrtype);
			return (IPM_INVALIDPARAMETER);
		}
		memcpy(&(nif.ip), addr.ipaddr, AF_RAWIPV4SIZE);
		memcpy(&(ctx->a.my[index]), &nif, sizeof(nma_interface_t));
		strncpy(ifr.ifr_name, ctx->a.my[index].name, IFNAMSIZ-1);
		ifr.ifr_name[IFNAMSIZ-1] = 0;
		(*(struct sockaddr_in *)&(ifr.ifr_netmask)).sin_addr.s_addr = ctx->a.my[index].mask;
		ifr.ifr_ifindex = ctx->a.my[index].ifindex;
		memcpy(ifr.ifr_hwaddr.sa_data, &(ctx->a.my[index].ether), ETH_ALEN);
		(*(struct sockaddr_in *)&(ifr.ifr_addr)).sin_addr.s_addr = ctx->a.my[index].ip;
		ifr.ifr_hwaddr.sa_family = AF_UNSPEC;
		memcpy(ifr.ifr_hwaddr.sa_data,&(ctx->b.group_multicast),ETH_ALEN);
		if (ioctl(inetsocket,SIOCADDMULTI,&ifr) < 0)
		{
			LOG_ERROR(NMA_EIOCTL,"ipm_init_interfaces: ioctl SIOCADDMULTI errno %d",errno);
			return(IPM_SYSTEMERR);
		}
	}
	return IPM_SUCCESS;
}

/* Set shelf value */
void ipm_set_shelf(nma_ctx_t *ctx, int shelf)
{
	ctx->a.shelfid = shelf;
}

void ipm_setup_dir(const char * dir)
{

	int ret;
	int exitval;

	char tmp[256];
	char *p;
	snprintf(tmp, sizeof(tmp), dir);
	if(access(dir, F_OK|R_OK|W_OK) != 0 )
	{

		//Make sure all directory components in the path exist
		for(p = tmp + 1; *p != '\0'; p++)
		{
			if(*p == '/')
			{
				*p = '\0';
				if(access(tmp, F_OK|R_OK|W_OK) != 0)
				{
					mkdir(tmp, 0755);
				}
				*p = '/';
			}

		}
		if((mkdir(dir, 0755) != 0) && (errno != EEXIST))
		{
			LOG_FORCE(0, "Failed to created %s \n", dir);
		}

	}

	return;

}
/* Setup directories that IPM needs. */
void ipm_check_dirs(void)
{
	ipm_setup_dir(ipmPidDir);
	ipm_setup_dir(NMA_IPC_DIR);

	return;
}
