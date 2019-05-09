
/**********************************************************************
 *
 * File:
 *	EIPM_stubs.c
 *
 * This file is only used for stubbing out LCP specific functions
 * to allow building EIPM on a standalone processor running CentOS or
 * RedHat.  It is under ECMS so it doesn't get lost, but should
 * not be built as part of the IPM process in LCP.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <ctype.h>
#include <netdb.h>
#include <asm/param.h>
#include <bits/time.h>
#include <errno.h> 
#include <dirent.h>
#include <linux/sockios.h>
#include <linux/un.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include "include/ipm_msg.h"
#include "include/EIPM_include.h"
#include "include/EIPM_stubs.h"


unsigned short Min_log_level = LOG_HIGH;


/*
 * Array for maintaining list of active socket descriptors.
 */
typedef struct {
	bool	valid;		/* Is entry valid? */
	int	desc;		/* Descriptor */
	int	index;		/* Index back to interface data entry */
} IPM_SOCKET_DESC;

/* For now assume 2 sockets for each external subnet,
 * plus 2 for internal use.
 */
#define	IPM_MAX_DESCR	(2 * EIPM_MAX_EXT_SUB) + 2
#define MAIN_SOCKET	0

#define MAX( _a, _b )     ((_a) > (_b)) ? (_a) : (_b)

/*
 * Define global data.
 */
IPM_SOCKET_DESC	IPM_skt_desc[ IPM_MAX_DESCR ];


struct timespec cur_time, prev_time;

#define ALIAS_DEBUG	\
	PRTLOG1( LOG_LOW, \
	         LOG_TRACE, \
	         (char *)__FILE__, \
	         __LINE__, \
	         LOG_NOALLOC, \
       	 	"IPM_main() - Received INTF message\ntype=%d, size=%d\nip[0]=0x%x\nprefix[0]=%d\nsubnet_type[0]=%d\nalias_if[0]=%s\nip[1]=0x%x\nprefix[1]=%d\nsubnet_type[1]=%d\nalias_if[1]=%s\n", \
	         msg->h.type, \
	         msg->h.size, \
		 ((struct sockaddr_in *)&(msg->cmd_alias_ip.alias_t[0].ip))->sin_addr.s_addr, \
		msg->cmd_alias_ip.alias_t[0].prefix, \
		msg->cmd_alias_ip.alias_t[0].subnet_type, \
		msg->cmd_alias_ip.alias_t[0].alias_if, \
		((struct sockaddr_in *)&(msg->cmd_alias_ip.alias_t[1].ip))->sin_addr.s_addr, \
		msg->cmd_alias_ip.alias_t[1].prefix, \
		msg->cmd_alias_ip.alias_t[1].subnet_type, \
		msg->cmd_alias_ip.alias_t[1].alias_if )

#define ARP_DEBUG	\
	PRTLOG1( LOG_LOW, \
	         LOG_TRACE, \
	         (char *)__FILE__, \
	         __LINE__, \
	         LOG_NOALLOC, \
       	 	"IPM_main() - Received ARP message\ntype=%d, size=%d\nip=0x%x\nprefix=%d\npriority=%d\n", \
	         msg->h.type, \
	         msg->h.size, \
		 ((struct sockaddr_in *)&(msg->cmd_arp_list.ip))->sin_addr.s_addr, \
		msg->cmd_arp_list.prefix, \
		msg->cmd_arp_list.priority )


#if defined(EIPM_STANDALONE)

int eipm_enable = TRUE;

int main( int argc, char** argv ) {
		

	struct sockaddr_un s_unix;
	struct sockaddr_un from;
	struct timespec sel_time;
	sigset_t sig_mask;
	struct nma_msgsocket_t *msg;
	struct nma_msgsocket_t rsp;
	fd_set read_fds;
	char buffer[ MAX_RCV_SIZE ];
	char name[ 128 ];
	int sock;
	int fromlen;
	int n;
	int i;
	int retval;
	int ret2;
	int desc;
	int maxfd;
	int flag;
	
	/*
	 * Set level of logs that are considered debugging.
	 */
#if ( DEBUG )
	logSetDbgLevel( LOG_MEDIUM );
#else
	logSetDbgLevel( LOG_MEDIUM );
#endif
#if ( DEBUG2 )
	logSetDbgLevel( LOG_LOWEST );
#endif
	
	/*
	 * Initialize globals.
	 */
	
	/* Initialize list of socket descriptors */
	for( i = 0; i < IPM_MAX_DESCR; ++i )
	{
		IPM_skt_desc[i].valid = FALSE;
		IPM_skt_desc[i].desc  = 0;
		IPM_skt_desc[i].index = -1;
	}

	/*
	 * For now assuming no arguments.
	 */
	if( argc != 1 )
	{
		/* Invalid options */
		fprintf(stderr,
		        "Usage: %s\n", argv[0] );
		PRTLOG1( LOG_HIGH, LOG_TRACE, (char *)__FILE__, __LINE__, LOG_NOALLOC,
		       	 "Usage: %s\n", argv[0] );
		exit( -1 );
	}
		

	/* Open IP socket for receiving messages */
	sock = socket( AF_UNIX, SOCK_DGRAM, 0 );
	if( sock < 0 ){
		PRTLOG1( LOG_HIGH, LOG_TRACE, (char *)__FILE__, __LINE__, LOG_NOALLOC,
		       	 "Cannot open receive socket, retval=%d, errno=%d\n", sock, errno );
		exit( -1 );
        }
	
   // OK if setsockopt fail 
   flag = 1;
   retval = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
   if (retval < 0)
   {
	PRTLOG1( LOG_HIGH,
	         LOG_TRACE,
	         (char *)__FILE__,
	         __LINE__,
	         LOG_NOALLOC,
	       	 "IPM_main : cli_server setsockopt SO_REUSEADDR failed, rc=%d, errno=%d\n",
	          retval, errno );

   }

   /* get current socket F_GETFL option */
   flag = fcntl(sock, F_GETFL, 0);
   if (flag < 0) {

	PRTLOG1( LOG_HIGH,
	         LOG_TRACE,
	         (char *)__FILE__,
	         __LINE__,
	         LOG_NOALLOC,
	       	 "IPM_main : fcntl cli_server get socket option failed, flag=%d, errno=%d\n",
	          flag, errno );
   }
   else
   {
   	/* make socket non-blocking */
	flag |= O_NONBLOCK;
	retval = fcntl(sock, F_SETFL, flag);
 	if (retval < 0)
	{

	PRTLOG1( LOG_HIGH,
	         LOG_TRACE,
	         (char *)__FILE__,
	         __LINE__,
	         LOG_NOALLOC,
	       	 "IPM_main : fcntl cli_server set socket non-blocking failed, rc=%d, errno=%d\n",
	          retval, errno );
	}
   }

   sprintf( name,"%s/%s", NMA_IPC_DIR, NMA_SRV_NAME);	

   (void)unlink(name);
   s_unix.sun_family = AF_UNIX;
   strcpy(s_unix.sun_path,name);

   if (bind(sock,(struct sockaddr*)&s_unix,sizeof(s_unix)) == -1)
   {

	PRTLOG1( LOG_HIGH,
	         LOG_TRACE,
	         (char *)__FILE__,
	         __LINE__,
	         LOG_NOALLOC,
	       	 "IPM_main : bind failed using path %s, errno=%d\n",
	          name,
		 errno );
      close(sock);
      exit( -1 );
   }
	
#ifdef NOTUSED
	/* Open IP socket for receiving messages */
	sock = socket( AF_INET, SOCK_DGRAM, 0 );
	if( sock < 0 ){
		PRTLOG1( LOG_HIGH, LOG_TRACE, (char *)__FILE__, __LINE__, LOG_NOALLOC,
		       	 "Cannot open receive socket, retval=%d, errno=%d\n", sock, errno );
		exit( -1 );
        }
	
	bzero( &sin, sizeof( sin ) );
	sin.sin_family      = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port        = htons( EIPM_TEST_PORT );

	if( (retval = bind( sock, (struct sockaddr *)&sin, sizeof( sin ))) < 0 )
	{
		PRTLOG1( LOG_HIGH, LOG_TRACE, (char *)__FILE__, __LINE__, LOG_NOALLOC,
		       	 "Cannot bind receive socket, retval=%d, errno=%d\n", retval, errno );
		exit( -1 );
	}
#endif	

	/*
	 * Save socket descriptor in descriptor list (this
	 * socket always gets the first entry).
	 */
	IPM_skt_desc[MAIN_SOCKET].desc = sock;
	IPM_skt_desc[MAIN_SOCKET].valid = TRUE;
	IPM_skt_desc[MAIN_SOCKET].index = -1;

	/*
	 * Call init functions for IIPM.
	 */
	
	/*
	 * Call init functions for EIPM.
	 *
	 * Initialization.
	 */
	retval = EIPM_init( );
	if( retval != IPM_SUCCESS )
	{
		PRTLOG1( LOG_HIGH, LOG_TRACE, (char *)__FILE__, __LINE__, LOG_NOALLOC,
	       	 	"Error: EIPM_init() failed, retval=%d\n", retval, errno );
		exit( -1 );
	}
	
	/*
	 * Call function to start monitoring any existing 
	 * interfaces if this is a process restart.
	 */
	retval = EIPM_startup( );
	if( retval != IPM_SUCCESS )
	{
		PRTLOG1( LOG_HIGH, LOG_TRACE, (char *)__FILE__, __LINE__, LOG_NOALLOC,
	       	 	"Error: EIPM_startup() failed, retval=%d\n", retval, errno );
		exit( -1 );
	}
	
	
	/*
	 * Wait for a message or timeout.  We may eventually want
	 * to wait for signals, so use pselect().
	 */
	(void) clock_gettime( CLOCK_REALTIME, &prev_time );
	
	while( 1 )
	{
		/*
		 * Init structures for pselect().
		 */
		FD_ZERO( &read_fds );
		
		/*
		 * Add socket descriptors to list pselect() will use.
		 */
		maxfd = 0;
		for( desc = 0; desc < IPM_MAX_DESCR; ++desc )
		{
			if( IPM_skt_desc[desc].valid == TRUE )
			{
				/*
				 * Found a valid one - add to list.
				 */
				FD_SET( IPM_skt_desc[desc].desc, &read_fds );
				
				/*
				 * Save max FD number.
				 */
				maxfd = MAX( maxfd, IPM_skt_desc[desc].desc );
			}
		}
		
		PRTLOG1( LOG_LOWEST, LOG_TRACE, (char *)__FILE__, __LINE__, LOG_NOALLOC,
	       	 	"IPM_main() - read_fds =0x%x\n", read_fds );

		/*
		 * Setup timeout (should be 50 msec (nsec=50000000)
		 */
		sel_time.tv_sec  = 0;
/* 		sel_time.tv_nsec = 500000000; */
		sel_time.tv_nsec = 50000000;
		
	/* 	sig_mask = 0; */
		

		retval = pselect( maxfd + 1, &read_fds, (fd_set *)NULL,
				  (fd_set *)NULL, &sel_time, 
				  (const sigset_t *)NULL );
				  
		PRTLOG1( LOG_LOWEST, LOG_TRACE, (char *)__FILE__, __LINE__, LOG_NOALLOC,
	       	 	"IPM_main() - return from select, read_fds =0x%x\n", read_fds );
		
		if( retval < 0 )
		{
			/*
			 * AAAAHHHHHHHHHHHH!!!!!
			 */
			PRTLOG1( LOG_HIGH,
			         LOG_TRACE,
			         (char *)__FILE__,
			         __LINE__,
			         LOG_NOALLOC,
		       	 	"Error: IPM_main() - pselect() failed, retval=%d\n", ret2, errno );
			exit( 1 );
		}
		else if ( retval == 0 )
		{
		
			(void) clock_gettime( CLOCK_REALTIME, &cur_time );
/***			
			printf( "Time since last timeout = %d sec, %d nsec (%d msec)\n",
				cur_time.tv_sec - prev_time.tv_sec,
				cur_time.tv_nsec - prev_time.tv_nsec,
				(cur_time.tv_nsec - prev_time.tv_nsec)/1000000 );
				
			prev_time = cur_time;
****/				
			/*
			 * This is a timeout.
			 */
			ret2 = EIPM_timeout();
			if( ret2 != IPM_SUCCESS )
			{
				PRTLOG1( LOG_HIGH, LOG_TRACE, (char *)__FILE__, __LINE__, LOG_NOALLOC,
			       	 	"Error: EIPM_timeout() failed, retval=%d\n", ret2 );
				exit( -1 );
			}
		}
		else
		{
			/* 
			 * Received a message.  Find which FDs
			 * have activity.
			 */
			PRTLOG1( LOG_LOWEST, LOG_TRACE, (char *)__FILE__, __LINE__, LOG_NOALLOC,
		       	 	"IPM Main received message, retval=%d\n", retval );
		
			for( desc = 0; desc < IPM_MAX_DESCR; ++desc )
			{
				if( IPM_skt_desc[desc].valid != TRUE )
				{
					continue;
				}
				
		
				/*
				 * Found a valid one - see if it
				 * has had activity.
				 */
				if( FD_ISSET( IPM_skt_desc[desc].desc, &read_fds ) )
				{
					PRTLOG1( LOG_LOW,
					         LOG_TRACE,
					         (char *)__FILE__,
					         __LINE__,
					         LOG_NOALLOC,
				       	 	"IPM Main received message for desc=%d, index=%d\n",
				                desc, IPM_skt_desc[desc].index );
					/*
					 * Msg received on this
					 * socket.  Figure out
					 * who to give it to.
					 */
					if( desc == MAIN_SOCKET )
					{
						/*
						 * Process here.
						 */
						fromlen = sizeof(struct sockaddr_un);
						from.sun_family = AF_UNIX;
						
						n = recvfrom( sock, buffer, MAX_RCV_SIZE,
						              0, (struct sockaddr *)&from,
						              &fromlen);
/* printf( "recvfrom - errno=%d\n", errno); */
						if ( n < 0)
						{
							PRTLOG1( LOG_HIGH,
							         LOG_TRACE,
							         (char *)__FILE__,
							         __LINE__,
							         LOG_NOALLOC,
						       	 	"Error: IPM_main() - recvfrom() failed, retval=%d\n", n, errno );
							exit(1);
						}	
						
						msg = (struct nma_msgsocket_t *)&buffer;
						bzero( &rsp, sizeof( rsp ) );
						/*
						 * Switch on message type.
						 */
						switch( msg->h.type )
						{
							
						case IPM_ADD_EXT_ALIAS:

							ALIAS_DEBUG;
							msg->h.error = EIPM_intf_update( &msg->cmd_alias_ip,
							                                 EIPM_ADD,
							                                 rsp.rsp_alias_ip.text );
							break;
							
						case IPM_DEL_EXT_ALIAS:
							ALIAS_DEBUG;
							msg->h.error = EIPM_intf_update( &msg->cmd_alias_ip,
							                                 EIPM_DEL,
							                                 rsp.rsp_alias_ip.text );
							break;
							
						case IPM_ADD_ARP:
							ARP_DEBUG;
							msg->h.error = EIPM_arp_update( &msg->cmd_arp_list,
							                                EIPM_ADD,
							                                rsp.rsp_arp_list.text );
							break;
							
						case IPM_DEL_ARP:
							ARP_DEBUG;
							msg->h.error = EIPM_arp_update( &msg->cmd_arp_list,
						                                        EIPM_DEL,
							                                rsp.rsp_arp_list.text );
							break;
						
						case IPM_ADD_ROUTE:
							msg->h.error = EIPM_route_update( &msg->cmd_route_upd,
							                                  EIPM_ADD,
							                                  rsp.rsp_route_upd.text );
							break;
							
						case IPM_DEL_ROUTE:
							msg->h.error = EIPM_route_update( &msg->cmd_route_upd,
							                                  EIPM_DEL,
							                                  rsp.rsp_route_upd.text );
							break;
						
							
						case IPM_DUMP_SHM:
							msg->h.error = EIPM_dumpshm( );
							break;
						
						default:
							write( 1, "Main - got a message: ", 22 );
							write( 1, buffer, n );
							break;
						}
						
						/*
						 * Send reply to message.
						 * Copy header to response
						 * first
						 */
						rsp.h = msg->h;
						if (sendto(sock,
						           (void *)&rsp,
						           sizeof(struct nma_msgsocketheader_t)+msg->h.size,
						           MSG_NOSIGNAL | MSG_DONTWAIT,
						           (struct sockaddr *)&from,
						           sizeof(from))
						     < 0 )
						{
							PRTLOG1( LOG_HIGH,
							         LOG_TRACE,
							         (char *)__FILE__,
							         __LINE__,
							         LOG_NOALLOC,
						       	 	"Error: IPM_main() - sendto() failed, errorno=%d\n",
							         errno );
						}
					}
#ifdef USINGSELECT
					else
					{
						/*
*****						 * Assume EIPM socket
						 * for now.
						 */
						EIPM_rcv_msg( desc );
					}
#endif					
					/*
					 * Clear the FD - it has been
					 * processed.
					 */
					FD_CLR( IPM_skt_desc[desc].desc, &read_fds );
	
				} /* end 'if FD_ISSET()' */
				
			} /* end 'for desc...' */
		
		} /* if on retval from select() */
	
	} /* end 'while( 1 )' */
}

#endif /* EIPM_STANDALONE */



/*************************************************************
 * logMessage() sends a log message to stdout
 *
 * Inputs: logging level (use #define value)
 *         message class (identifies application class)
 *         source file (use __FILE__)
 *         line number (use __LINE__)
 *         formatted string (like printf)
 * Return: TRUE :   message printed
 *	   FALSE :  failed
 *************************************************************/
int logMessage(unsigned short level, uint64_t message_class,  
               char* file_name, int line_number, 
	       int allocation_flag, char* format, ...)
{
	va_list arglist;
	char	buffer[ 1000 ];
	int	msglen;

	if( level < Min_log_level )
	{
		/*
		 * Don't print messages below min level.
		 */
		return;
	}
	
	if(format != NULL) /* make sure not cause printf problem */
	{
		fprintf( stdout, "\nFile=%s, Line=%d\n", file_name, line_number );
		va_start( arglist, format );
		msglen = vsnprintf( buffer, (size_t)1000, format, arglist );
		va_end(arglist);
	        if( msglen < 0 )
		{
			fprintf( stdout, "vsnprintf() failed\n" );
			return;
		}
		fprintf( stdout, "%s\n", buffer );
	}

	fflush( stdout );

	return;

} /*** end logMessage ***/


void logSetDbgLevel( unsigned short level )
{
	Min_log_level = level;
	return;
}



int send_alarm( unsigned short servcFlag,
            FSALARM_ALARM_TYPE a_type,
            FSALARM_CLASS_TYPE class,
            FSALARM_SEVERITY_TYPE sev,
            FSALARM_PROBLEM_TYPE prob,
            FSALARM_RESOURCE_TYPE rtype,
            char * resource,
            char * far_res,
            char * usertxt,
            FSALARM_DESC_TYPE desc,
            FSALARM_RCVRY_TYPE rcvry,
			char * file,
            int line,
            char *sUser,
            char *sProvider,
            char *saDetector,
            unsigned int delayed_time )
{
	
	char aclass[10];
	char asev[10];
	char aprob[30];
	char artype[20];

	memset(aclass, 0, sizeof(aclass));
	memset(asev, 0, sizeof(asev));
	memset(aprob, 0, sizeof(aprob));
	memset(artype, 0, sizeof(artype));
	
	if( class == FSAC_ethernet )
	{
		strncpy( aclass, "Ethernet" , sizeof(aclass)-1);
		
	}
	else
	{
		strncpy( aclass, "CLASS_UNK" , sizeof(aclass)-1);
	}
	
	switch( sev )
	{
	case FSAS_cleared:
		strncpy( asev, "CLEARED", sizeof(asev)-1);
		break;
	case FSAS_minor:
		strncpy( asev, "MINOR", sizeof(asev)-1);
		break;
	case FSAS_major:
		strncpy( asev, "MAJOR", sizeof(asev)-1);
		break;
	case FSAS_critical:
		strncpy( asev, "CRITICAL", sizeof(asev)-1);
		break;
	default:
		strncpy( asev, "UNKNOWN", sizeof(asev)-1);
		break;
	}
	
	switch (prob)
	{
	case FSAP_ethernetError:
		strncpy( aprob, "EthernetError", sizeof(aprob)-1);
		break;
	case FSAP_externalConnectivity:
		strncpy( aprob, "ExternalConnectivity", sizeof(aprob)-1);
		break;
	case FSAP_linkDown:
		strncpy( aprob, "LinkDown", sizeof(aprob)-1);
		break;
	case FSAP_stateChange:
		strcpy(aprob, "StateChange");
		break;
	default:
		strncpy( aprob, "PROB_UNK", sizeof(aprob)-1);
		break;
	}
	
	if( rtype == FSAR_link )
	{
		strncpy( artype, "link", sizeof(artype)-1);
		
	}
	else
	{
		strncpy( artype, "RESTYPE_UNK", sizeof(artype)-1);
	}
	
	LOG_FORCE(0, "\n\nAlarm Received\nClass:\t\t\t%s\nSeverity:\t\t%s\nProblem Type:\t\t%s\nResource Type:\t\t%s\nResource:\t\t%s\nFar-end Resource:\t%s\nUser Text:\t\t%s\nFile:\t\t\t%s\nLine:\t\t\t%d\n",
		aclass, asev, aprob, artype, resource, far_res, usertxt,
		file, line );
}


ASRT_TPE ASmissing_data = {
	(char *) "MISSING_DATA",
	(char *) "Data is missing from a database or data structure."
};

ASRT_TPE ASbad_data = {
        (char *) "BAD_DATA",
        (char *) "Bad data encountered."
};

ASRT_TPE ASunexpectedval = {
	(char *) "UNEXPECTED_VALUE",
	(char *) "An unexpected value was found (invalid or out of range\nor fell into switch default and so on)."
};

ASRT_TPE ASunexp_return = {
	(char *) "UNEXPECTED_RETURN",
	(char *) "Unexpected return code from a function."
};

ASRT_TPE ASrtbadparam = {
        (char *) "BADPARAM",
        (char *) "A bad parameter was passed."
};

ASRT_TPE ASOSfnFail = {
        (char *) "Call_to_OS_function_failed",
        (char *) "Call to OS function failed"
};

ASRT_TPE ASlogicerr = {
        (char *) "LOGIC_ERROR",
        (char *) "Code is logically incorrect.\nThis could be due to an internal interface problem, a data problem\nor something else."
};



void
ASrept(ASRT_LEVEL level, unsigned int dcnt, ASRT_TPE *type_ptr, char *file, int line, ...)
{
va_list			ap;			// Optional param. info.
char			*auname;		// Audit name.
char			str[2048-160];		// String buffer.
ASSERT_DMP		dumps[2];
char			*string_ptr;		// User string.

	// Decode the optional parameters.
        va_start(ap, line);

	// Get everything other than the optional dumps and string.
	switch(level)
	{
	default:

		// Unknown level. Report this via a report-only
		// assert (which will not cause infinite recursion
		// because the level will be known) then fall through
		// and treat the original assert as a report-only.

		ASRT_RPT(ASUNEXPECTEDVAL, 0,
			"Unknown assert level value=%d.\n", level);

		// Fall through.

	case AS_REPT:

		auname = (char *) NULL;
		break;

	case AS_ESCALATE:

		auname = va_arg(ap, char *);
		break;

	case AS_RESTART_TASK:

		auname = va_arg(ap, char *);
		break;

	case AS_RESTART_PROCESS:

		auname = (char *) NULL;
		break;

	} // End switch(assert level).

	switch(dcnt)
	{
	case 0:

		break;

	case 1:

		dumps[0].length = va_arg(ap, int);
		dumps[0].ptr = va_arg(ap, char *);
		break;

	case 2:

		dumps[0].length = va_arg(ap, int);
		dumps[0].ptr = va_arg(ap, char *);

		dumps[1].length = va_arg(ap, int);
		dumps[1].ptr = va_arg(ap, char *);
		break;

	default:

		// The arguments are invalid. They can't be sorted
		// out so just flag the error.

		fprintf( stdout, "\nFile=%s, Line=%d\n", file, line );
		fprintf( stdout, "Assert dump count parameter=%d is invalid. All dumps and strings are lost.\n",
			dcnt);

		return;

	} // End switch(dump count).

	// Check for an optional string (unless the dump count was invalid).
	// There will always be at least a (NULL) format string.

	if(dcnt < 3)
	{
	char *fmt;

		fmt = va_arg(ap, char *);

		if(fmt != NULL)
		{
			vsnprintf(str, sizeof(str), fmt, ap);
			string_ptr = str;
		}
	}

        va_end(ap);

	switch(level)
	{
	default:

		// If the level is not known we should have already
		// asserted. However, this switch may not have been updated.

		// Fall through to treat as report-only.

	case AS_REPT:


		LOG_FORCE(0, "File %s, Line %d: %s", file, line, string_ptr );
		break;

	case AS_RESTART_TASK:
	case AS_RESTART_PROCESS:
		// No support for task restart. Treat all cases
		// like a process restart.
	case AS_ESCALATE:

		LOG_FORCE(0, "File %s, Line %d: %s", file, line, string_ptr );
		exit( 1 );
		
		break;
		
	} // End switch(assert level).

	// Some day when bored put in the data dumps
	
	return;
}

/* Linux glibc does not provide a system call definition for this system call.  */
pid_t gettid(void)
{
	return syscall(SYS_gettid);
}
