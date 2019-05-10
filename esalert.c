/**********************************************************************
 *
 * File:
 *      esalert.c
 *
 * Abstract:
 *  wcnp alert msg simulator. 
 *  Using this simulator, we can send es alert msg to EIPM w/o depending on ESRM located in malban
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "rm/EIPM_alertmon.h"

#define WCNP_MCAST_PORT 2335
#define WCNP_MCAST_IP_ADDRESS "230.0.1.1"
#define CMD_LEFT_STR "left"
#define CMD_RIGHT_STR "right"
#define CMD_CLEAR_STR "clear"


typedef enum {
	CMD_LEFT,
	CMD_RIGHT,
	CMD_CLEAR,
	CMD_UNKNOW
} CMD_TYPE;

CMD_TYPE cmd_control = CMD_CLEAR;
int left_cnt = 0;
int right_cnt = 0;
int clear_cnt = 0;
int unknow_cnt = 0;
extern int is_sender;
extern int is_recver;

pthread_mutex_t control_mutex = PTHREAD_MUTEX_INITIALIZER;

void *AlertRecvThread()
{
	fd_set readset;
	int maxfd = -1;
	int retval;
	struct timeval timeout;

	while (1) {
		FD_ZERO(&readset);
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;

		FD_SET(mcast_data.mcast_side[EIPM_ALERT_LEFT].mcast_socket, &readset);
		if (maxfd < mcast_data.mcast_side[EIPM_ALERT_LEFT].mcast_socket)
		{
			maxfd = mcast_data.mcast_side[EIPM_ALERT_LEFT].mcast_socket;
		}
		FD_SET(mcast_data.mcast_side[EIPM_ALERT_RIGHT].mcast_socket, &readset);
		if (maxfd < mcast_data.mcast_side[EIPM_ALERT_RIGHT].mcast_socket)
		{
			maxfd = mcast_data.mcast_side[EIPM_ALERT_RIGHT].mcast_socket;
		}
		retval = select(maxfd+1, &readset, NULL, NULL, &timeout);

		if (retval < 0)
		{
			/* something wrong */
			continue;
		}
		else if (retval == 0)
		{
			/* timeout , do nothing */
			continue;
		}
		else
		{
			/* mcast msg is coming */
			retval = EIPM_wcnp_mcast_recv(&readset);
			if (retval <= 0)
			{
				continue;
			}
			printf("Active Side: %d, Left Timestamp: %d, Right Timestamp: %d\n",
				mcast_data.active_side,
				mcast_data.mcast_side[EIPM_ALERT_LEFT].last_time.tv_sec,
				mcast_data.mcast_side[EIPM_ALERT_RIGHT].last_time.tv_sec);	
		}
	}
}

void *AlertSendThread()
{
CMD_TYPE current_cmd;
char alert_str[500];
EIPM_SWITCHSIDE switch_side;


	while (1)
	{
		memset(alert_str, 0, sizeof(alert_str));
		pthread_mutex_lock(&control_mutex);
		current_cmd = cmd_control;
		pthread_mutex_unlock(&control_mutex);
		switch (current_cmd) {
		case CMD_LEFT:
			left_cnt++;
			switch_side = EIPM_ALERT_LEFT;
			//pthread_mutex_lock(&control_mutex);
			//cmd_control = CMD_CLEAR;
			//pthread_mutex_unlock(&control_mutex);
			break;
		case CMD_RIGHT:
			right_cnt++;
			switch_side = EIPM_ALERT_RIGHT;
			//pthread_mutex_lock(&control_mutex);
			//cmd_control = CMD_CLEAR;
			//pthread_mutex_unlock(&control_mutex);
			break;
		case CMD_CLEAR:
			clear_cnt++;
			switch_side = EIPM_ALERT_MAX;
			break;
		case CMD_UNKNOW:
		default:
			unknow_cnt++;
			switch_side = EIPM_ALERT_MAX;
			break;
		}
		EIPM_setSwitchSide(switch_side);
		EIPM_buildESAlert(alert_str, sizeof(alert_str));
		EIPM_wcnp_mcast_send(alert_str, strlen(alert_str));

		sleep(1);
	}
}

int main(int argc, char** argv)
{
	pthread_t send_thread;
	pthread_t recv_thread;
	in_addr_t left;
	in_addr_t right;
	char *cmd_ptr;
	char cmd[1024];

	if (argc < 4)
	{
		printf("ERROR: Invalid Argument\n");
		printf("USAGE: argv[0] send|recv leftip rightip\n");
		return 255;
	}
	if (strcmp(argv[1], "send") == 0)
	{
		is_sender = 1;
	}
	else if (strcmp(argv[1], "recv") == 0)
	{
		is_recver = 1;
	}
	else
	{
		printf("ERROR: Invalid Argument\n");
		printf("USAGE: argv[0] send|recv leftip rightip\n");
		return 255;
	}
	left = inet_addr(argv[2]);
	right = inet_addr(argv[3]);

	EIPM_wcnp_InitMcast(left, NULL, right, NULL);
	if (mcast_data.is_mcast_inited == 0)
	{
		return 255;
	}

	if (is_sender)
	{
		pthread_create(&send_thread, NULL, AlertSendThread, NULL);
	}
	else if (is_recver)
	{
		pthread_create(&recv_thread, NULL, AlertRecvThread, NULL);
	}
	while (1)
	{
		if (is_sender)
		{
			printf("Active Side> ");
			cmd_ptr = fgets(cmd, sizeof(cmd), stdin);
			pthread_mutex_lock(&control_mutex);
			if (strstr(cmd_ptr, CMD_LEFT_STR) != NULL)
			{
				cmd_control = CMD_LEFT;
			}
			else if (strstr(cmd_ptr, CMD_RIGHT_STR) != NULL)
			{
				cmd_control = CMD_RIGHT;
			}
			else if (strstr(cmd_ptr, CMD_CLEAR_STR) != NULL)
			{
				cmd_control = CMD_CLEAR;
			}
			pthread_mutex_unlock(&control_mutex);
		}
		else if (is_recver)
		{
			sleep(1);
		}
	}
}
