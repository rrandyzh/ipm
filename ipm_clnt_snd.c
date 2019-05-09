#include <types.h>
#include <stdio.h>

#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include <sys/fcntl.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include "nnn_socket.h"
#include "ipm_msg.h"
#include "ipm_clnt_snd.h"
#include "nma_log.h"
#include "ipm_retval.h"
#if defined(_LIBRARY_IPM_CLI)
#include "ipmcomm.h"
#endif

int
ipm_socket_open( int *socketfd, char *filename )
{
struct sockaddr_un clientaddr;
int ret;
int flag = 1;

    if( *socketfd > 0 )
    {
        return IPM_CLI_RET_SUCCESS;
    }

    *socketfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if( *socketfd < 0 )
    {
        CLI_LOG("ipm_socket_open(): socket() failed, errno=%d, %s\n",
                errno,
                strerror(errno));

        return IPM_CLI_RET_SOCKET_OPEN_FAILURE;
    }

    ret = setsockopt(*socketfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    if( ret < 0 )
    {
        CLI_LOG("ipm_socket_open(): setsockopt() SO_REUSEADDR failed, ret=%d, errno=%d, %s\n",
                ret,
                errno,
		strerror(errno));

        ipm_socket_close(socketfd, filename);

        return IPM_CLI_RET_SOCKET_OPTION_FAILURE;
    }

    ret = fcntl(*socketfd, F_GETFL, 0);
    if( ret < 0 )
    {
	CLI_LOG("ipm_socket_open(): fcntl() get option F_GETFL failed, ret=%d, errno=%d, %s\n",
                ret,
                errno,
		strerror(errno));

        ipm_socket_close(socketfd, filename);

        return IPM_CLI_RET_SOCKET_CONTROL_FAILURE;
    }

    ret |= O_NONBLOCK;
    ret = fcntl(*socketfd, F_SETFL, ret);
    if( ret < 0 )
    { 
	CLI_LOG("ipm_socket_open(): fcntl() set non-blocking option F_SETFL failed, ret=%d, errno=%d, %s\n",
                ret,
                errno,
		strerror(errno));

        ipm_socket_close(socketfd, filename);

        return IPM_CLI_RET_SOCKET_CONTROL_FAILURE;
    }

    memset(&clientaddr, 0, sizeof(clientaddr));
    clientaddr.sun_family = AF_UNIX;
    strncpy(clientaddr.sun_path, filename, 107);
    clientaddr.sun_path[107] = 0;

    ret = bind(*socketfd, (struct sockaddr *)&clientaddr, sizeof(clientaddr));
    if( ret < 0 )
    { 
	CLI_LOG("ipm_socket_open(): bind() failed, ret=%d, errno=%d, %s\n",
                ret,
                errno,
		strerror(errno));

        ipm_socket_close(socketfd, filename);

        return IPM_CLI_RET_SOCKET_BIND_FAILURE;
    }

    return IPM_CLI_RET_SUCCESS;
}

void
ipm_socket_close( int *socketfd, char *filename )
{
    if( *socketfd > 0 )
    {
        close(*socketfd);
	unlink(filename);
        *socketfd = -1;
    }

    return;
}

int
ipm_socket_send( int *socketfd, struct nma_msgsocket_t *msg )
{
struct sockaddr_un serveraddr;
int ret;

    char serverfilename[128]; 
    sprintf(serverfilename, "%s/%s", NMA_IPC_DIR, NMA_SRV_NAME);

    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sun_family = AF_UNIX;
    strncpy(serveraddr.sun_path, serverfilename, 107);
    serveraddr.sun_path[107] = 0;

    ret = sendto(*socketfd, 
                 msg, sizeof(struct nma_msgsocket_t), 
                 0,
                 (struct sockaddr *)&serveraddr, sizeof(serveraddr));

    if( ret < 0 )
    {
        CLI_LOG("ipm_socket_send(): sendto() failed, ret=%d, errno=%d, %s\n",
                ret, 
                errno, 
                strerror(errno));

        return IPM_CLI_RET_SOCKET_SEND_FAILURE;
    }

    return IPM_CLI_RET_SUCCESS;
}

int
ipm_socket_ack( int *socketfd, 
                struct nma_msgsocket_t *msg, 
                struct nma_msgsocket_t *reply, 
                int timeout )
{
struct pollfd readfd;
int ret;

	readfd.fd = *socketfd;
	readfd.events = POLLIN;
	readfd.revents = 0;

	while(1)
	{
		ret = poll(&readfd, 1, timeout * 1000);
		if( ret < 0 && errno == EINTR )
		{
		    continue;
		}
		break;
	}
	if( ret < 0 )
	{
		CLI_LOG("ipm_socket_ack(): poll() failed, ret=%d, errno=%d, %s\n",
			ret,
			errno,
		strerror(errno));

		return IPM_CLI_RET_SOCKET_SELECT_FAILURE;
	}
	else if( ret == 0 ) /* time out */
	{
		CLI_LOG1("ipm_socket_ack(): %d seconds elapsed waiting for reply and request type (%d)\n", timeout, msg->h.type);

		return IPM_CLI_RET_SOCKET_TIMEOUT;
	}

	if (readfd.revents & ((POLLERR | POLLHUP | POLLNVAL)))
	{
		CLI_LOG("ipm_socket_ack(): poll() error , revent=%d\n", readfd.revents);

       	 return IPM_CLI_RET_SOCKET_SELECT_FAILURE;
	}

	if (readfd.revents & POLLIN)
	{	
		memset((void *)reply, 0, sizeof(*reply));

		ret = recvfrom(*socketfd, reply, sizeof(*reply), 0, NULL, NULL);
		if( ret <= 0 )
		{
			CLI_LOG("ipm_socket_ack(): recvfrom() failed, ret=%d, errno=%d, %s\n",
				ret,
				errno,
			strerror(errno));

			return IPM_CLI_RET_SOCKET_RCV_FAILURE;
		}

		if( msg->h.type != reply->h.type )
		{
			CLI_LOG("ipm_socket_ack(): Received the wrong reply type, expected: %d, received: %d\n",
			msg->h.type, 
			reply->h.type);

			return IPM_CLI_RET_ACK_BAD_TYPE;
		}

		switch( reply->h.type ) {
		case IPM_DUMP_STATUS:
		case IPM_GET_SIDE:
		case IPM_GET_STATS:
			if( strlen(reply->rsp_ipm.text) > 0 )
			{
				CLI_LOG("%s\n", reply->rsp_ipm.text);
			}
			break;

		default:
			break;
		}

		switch( reply->h.error ) {
		case IPM_SUCCESS:
		case IPM_DUPLICATED:
			return IPM_CLI_RET_SUCCESS;

		default:
			switch( reply->h.type ) {
			case IPM_DUMP_STATUS:
				/* Status dumped out above */
				return IPM_CLI_RET_ACK_ERROR;

			default:
				CLI_LOG("Cmd %d Error %d\n",
					reply->h.type, 
					reply->h.error);
				return IPM_CLI_RET_ACK_ERROR;
			}
			break;
		}
	}
	CLI_LOG("ipm_socket_ack(): poll() error , revent=%d\n", readfd.revents);
	return IPM_CLI_RET_ACK_ERROR;
}

static char templatefilename[] = "/tmp/ipm_cli_client_XXXXXX";
static pthread_key_t clisocketkey;
static pthread_once_t clisocketonce = PTHREAD_ONCE_INIT;

void clisocket_key_create() {
	pthread_key_create( &clisocketkey, NULL );
}

static CLI_SOCKET_DATA *ipm_get_cli_socket()
{
	CLI_SOCKET_DATA *clisocket = NULL;

/* TSD here only is supported by IPM_CLI lib instead of ipm_cli command line 
 * so don't need to create key again and again when calling ipm_cli tool again and again
 */
#if defined(_LIBRARY_IPM_CLI)
	int ret;

	ret = pthread_once( &clisocketonce, clisocket_key_create);
	if (ret != 0)
	{
		CLI_LOG("ipm_get_cli_socket(): pthread_once() failed with error %d, %s \n", ret, strerror(ret));
		return;
	}

	clisocket = (CLI_SOCKET_DATA *)pthread_getspecific(clisocketkey);
	if (clisocket != NULL)
	{
		return clisocket;
	}
#endif

	clisocket = (CLI_SOCKET_DATA*) calloc(1, sizeof(CLI_SOCKET_DATA) );
	if (clisocket == NULL)
	{
		CLI_LOG("ipm_get_cli_socket(): calloc() failed with error %d/%s \n", errno, strerror(errno));
		return NULL;
	}

	clisocket->socketfd = -1;
	
#if defined(_LIBRARY_IPM_CLI)
	if (pthread_setspecific(clisocketkey, clisocket) != 0) {
		free(clisocket);
		CLI_LOG("ipm_get_cli_socket(): pthread_setspecific() failed with error %d/%s \n", errno, strerror(errno));
		return NULL;
	}
#endif
	return clisocket;
}

int
ipm_send_msg( struct nma_msgsocket_t *msg )
{
struct nma_msgsocket_t reply;
int ret;
int clientfd;
CLI_SOCKET_DATA *clisocket;

	clisocket = ipm_get_cli_socket();
	if (clisocket == NULL)
	{
		return IPM_CLI_RET_SOCKET_TSD_FAILURE;
	}

    if (clisocket->socketfd == -1)
    {
	strcpy(clisocket->clientfilename, templatefilename);
	clientfd = mkstemp(clisocket->clientfilename);
	if( clientfd < 0 )
	{
	    CLI_LOG("ipm_send_msg(): mkstemp() failed, errno=%d, %s\n",
		     errno,
		     strerror(errno));

	    return IPM_CLI_RET_FILE_CREATE_FAILURE;
	}

	close(clientfd);
	unlink(clisocket->clientfilename);

	ret = ipm_socket_open(&(clisocket->socketfd), clisocket->clientfilename);
	if( ret < 0 )
	{
	    return ret;
	}
    }

    ret = ipm_socket_send(&(clisocket->socketfd), msg);
    if( ret < 0 )
    {
        ipm_socket_close(&(clisocket->socketfd), clisocket->clientfilename);
        return ret;
    }

    ret = ipm_socket_ack(&(clisocket->socketfd), msg, &reply, 5);

#if !defined(_LIBRARY_IPM_CLI)
    ipm_socket_close(&(clisocket->socketfd), clisocket->clientfilename);
#endif

    return ret;
}

#if defined(_LIBRARY_IPM_CLI)
void
ipm_comm_shutdown(void)
{
CLI_SOCKET_DATA *clisocket;

	clisocket = ipm_get_cli_socket();
	if (clisocket == NULL)
	{
		return;
	}
  ipm_socket_close(&(clisocket->socketfd), clisocket->clientfilename);
}

#endif

int
ipm_send_client_msg( struct nma_msgsocket_t *msg )
{
int ret;
int index;

    for( index = 1; index < 4; index++ )
    {
        ret = ipm_send_msg(msg);

        switch( ret )
        { 
        case IPM_CLI_RET_SUCCESS:
            if (index == 1) 
            {
                return ret;
            }
            /* fall through when index != 1 and break the loop
             * shutdown socket to avoid another response back in case
             */
        case IPM_CLI_RET_ACK_ERROR:
            index = 4;
            break;
        }

        if( index < 3 )
        {
            sleep(index);
        }
    }

    if ( ret == IPM_CLI_RET_SOCKET_TIMEOUT) 
    {
	CLI_LOG("ipm_socket_ack(): Timed out waiting for reply, check if IPM is running\n");
    }

#if defined(_LIBRARY_IPM_CLI)
    if (index > 1)
    {
        ipm_comm_shutdown();
    }
#endif
    return ret;
}

