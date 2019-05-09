/*************************************************************************
 *
 * File:     ARPNDP_history.c
 *
 * Abstract: implementation file of ARP/NDP history module
 *           this module handles ARP/NDP history
 *           ARP/NDP history is implemented as a circular buffer
 *
 * Data:     none
 *
 * Functions:
 *     ARPNDP_history_init       - function to initialize ARP/NDP history
 *                                 module
 *
 *     ARPNDP_history_print_data - module-internal function to print ARP/NDP
 *                                 history data
 *
 *     ARPNDP_history_add        - function to add a new ARP/NDP history
 *     ARPNDP_history_log        - function to log ARP/NDP history of a
 *                                 ARP/NDP session
 *
 ************************************************************************/

#include "ARPNDP_int_hdr.h"


/*
 * Name:        ARPNDP_history_init
 *
 * Abstract:    function to initialize ARP/NDP history module
 *
 * Parameters:  none
 *
 * Returns:     none
 */
void ARPNDP_history_init()
{
    memset (arpndp_data->hist, 0, sizeof(arpndp_data->hist));
    memset (arpndp_data->hist_cur_idx, 0, sizeof(arpndp_data->hist_cur_idx));
}


/*
 * Name:        ARPNDP_history_print_data
 *
 * Abstract:    module-internal function to print ARP/NDP history data
 *
 * Parameters:
 *     history_type     - ARP/NDP history type
 *     history_data     - ARP/NDP history data
 *
 * Returns:
 *     history_data_str - ARP/NDP history data as string
 */
static const char *ARPNDP_history_print_data (
    ARPNDP_HISTORY_TYPE history_type, uint32_t history_data)
{
    static IPM_IPADDR local_ip;

    static char buffer[ 100];

    switch (history_type)
    {
    case ARPNDP_HISTORY_ADMIN_STATE:
        return ARPNDP_ADMIN_STATE_to_str (history_data);
    case ARPNDP_HISTORY_SESS_STATE:
        return ARPNDP_SESS_STATE_to_str (history_data);

    case ARPNDP_HISTORY_LOCAL_IP_IPV4:
        /* special treatment for local IPv4 */

        memset (&local_ip, 0, sizeof(local_ip));
        local_ip.addrtype = IPM_IPV4;
        local_ip.ipaddr[0] = history_data;

        IPM_ipaddr2p (&local_ip, &buffer[0], sizeof(buffer));
        return buffer;

    case ARPNDP_HISTORY_DETECT_TIME_MULT:
        sprintf (buffer, "%u", history_data);
        return buffer;
    case ARPNDP_HISTORY_MIN_TX:
        sprintf (buffer, "%u", history_data);
        return buffer;
    case ARPNDP_HISTORY_MIN_RX:
        sprintf (buffer, "%u", history_data);
        return buffer;

    case ARPNDP_HISTORY_TRANSMISSION_TIMER:
        sprintf (buffer, "%u", history_data);
        return buffer;
    case ARPNDP_HISTORY_FAULT_DETECT_TIMER:
        sprintf (buffer, "%u", history_data);
        return buffer;

    case ARPNDP_HISTORY_RECV_COUNT:
        sprintf (buffer, "%u", history_data);
        return buffer;
    case ARPNDP_HISTORY_SEND_COUNT:
        sprintf (buffer, "%u", history_data);
        return buffer;

    case ARPNDP_HISTORY_LOCAL_IP_IPV6_1:
    case ARPNDP_HISTORY_LOCAL_IP_IPV6_2:
    case ARPNDP_HISTORY_LOCAL_IP_IPV6_3:
    case ARPNDP_HISTORY_LOCAL_IP_IPV6_4:
        return "ERROR";

    default:
        return "UNKNOWN";
    }
}


/*
 * Name:        ARPNDP_history_add
 *
 * Abstract:    function to add a new ARP/NDP history
 *
 * Parameters:
 *     sess_idx     - ARP/NDP session index
 *     history_type - ARP/NDP history type
 *     history_data - ARP/NDP hstory data
 *
 * Returns:     none
 */
void ARPNDP_history_add (int sess_idx, ARPNDP_HISTORY_TYPE history_type,
    uint32_t history_data)
{
    int cur_idx;

    /* circular buffer */

    /* current index to store data */
    cur_idx = arpndp_data->hist_cur_idx[sess_idx];

    if ((cur_idx < 0) || (cur_idx >= ARPNDP_HISTORY_MAX))
    {
        ARPNDP_INTERNAL_ERROR ("invalid cur_idx %d, 0 to %d expected\n",
            cur_idx, ARPNDP_HISTORY_MAX - 1);
        arpndp_data->stats.inv_history_cur_idx++;

        /* re-initialize data */
        memset (arpndp_data->hist[sess_idx], 0, sizeof(arpndp_data->hist[0]));
        cur_idx = 0;
    }

    arpndp_data->hist[sess_idx][cur_idx].history_type = history_type;
    arpndp_data->hist[sess_idx][cur_idx].history_data = history_data;

    /* next index */
    cur_idx++;
    if (cur_idx == ARPNDP_HISTORY_MAX)
    {
        cur_idx = 0;
    }
    arpndp_data->hist_cur_idx[sess_idx] = cur_idx;
}


/*
 * Name:        ARPNDP_history_log
 *
 * Abstract:    function to log ARP/NDP history for an ARP/NDP session
 *
 * Parameters:
 *     sess_idx  - ARP/NDP session index
 *
 * Returns:     none
 */
void ARPNDP_history_log (int sess_idx)
{
    int cur_idx;
    int end_idx;

    char buffer[ARPNDP_ERR_LOG_BUF_SIZE];
    char *ptr = &buffer[0];
    int size = sizeof(buffer);

    static IPM_IPADDR local_ip;
    char local_ip_str[IPM_IPMAXSTRSIZE];

    int count = 0;

    /* circular buffer */

    cur_idx = arpndp_data->hist_cur_idx[sess_idx];
    end_idx = cur_idx;

    if ((cur_idx < 0) || (cur_idx >= ARPNDP_HISTORY_MAX))
    {
        ARPNDP_INTERNAL_ERROR ("invalid cur_idx %d, 0 to %d expected\n",
            cur_idx, ARPNDP_HISTORY_MAX - 1);
        arpndp_data->stats.inv_history_cur_idx++;

        /* re-initialize data */
        memset (arpndp_data->hist[sess_idx], 0, sizeof(arpndp_data->hist[0]));
        arpndp_data->hist_cur_idx[sess_idx] = 0;

        /* log nothing */
        return;
    }

    ARPNDP_PRINTF (ptr, size, "ARP/NDP history at index %d report 1:\n",
        sess_idx);

    for(;;)
    {
        if ((count != 0) && ((count % (ARPNDP_HISTORY_MAX / 4)) == 0))
        {
            ARPNDP_LOG_FORCED (buffer);

            ptr = &buffer[0];
            size = sizeof(buffer);
            ARPNDP_PRINTF (ptr, size,
		"ARP/NDP history at index %d report %u\n",
                sess_idx, (count / (ARPNDP_HISTORY_MAX / 4)) + 1);
        }

        /* previous index to retrieve data */
        cur_idx--;
        if (cur_idx < 0)
        {
            cur_idx = ARPNDP_HISTORY_MAX - 1;
        }

        if (cur_idx == end_idx)
        {
            /* make a full circle */
            /* stop */
            break;
        }

        if (arpndp_data->hist[sess_idx][cur_idx].history_type ==
            ARPNDP_HISTORY_NOT_USED)
        {
            /* no more data */
            /* stop */
            break;
        }

        /*
         * special treatment for local IPv6;
         * 4 ARP/NDP history entries are used for 1 local IPv6;
         * process order: ARPNDP_HISTORY_LOCAL_IP_IPV6_4, *_3, *_2, *_1
         */
        if (arpndp_data->hist[sess_idx][cur_idx].history_type ==
            ARPNDP_HISTORY_LOCAL_IP_IPV6_1)
        {
            local_ip.ipaddr[0] =
                arpndp_data->hist[sess_idx][cur_idx].history_data;

            IPM_ipaddr2p (&local_ip, &local_ip_str[0], sizeof(local_ip_str));

            ARPNDP_PRINTF (ptr, size, "    %-36s %s\n",
                ARPNDP_HISTORY_TYPE_to_str (ARPNDP_HISTORY_LOCAL_IP_IPV6_1),
                    local_ip_str);

            continue;
        }
        else if (arpndp_data->hist[sess_idx][cur_idx].history_type ==
            ARPNDP_HISTORY_LOCAL_IP_IPV6_2)
        {
            local_ip.ipaddr[1] =
                arpndp_data->hist[sess_idx][cur_idx].history_data;
            continue;
        }
        else if (arpndp_data->hist[sess_idx][cur_idx].history_type ==
            ARPNDP_HISTORY_LOCAL_IP_IPV6_3)
        {
            local_ip.ipaddr[2] =
                arpndp_data->hist[sess_idx][cur_idx].history_data;
            continue;
        }
        else if (arpndp_data->hist[sess_idx][cur_idx].history_type ==
            ARPNDP_HISTORY_LOCAL_IP_IPV6_4)
        {
            memset (&local_ip, 0, sizeof(local_ip));
            local_ip.addrtype = IPM_IPV6;

            local_ip.ipaddr[3] =
                arpndp_data->hist[sess_idx][cur_idx].history_data;
            continue;
        }

        ARPNDP_PRINTF (ptr, size, "    %-36s %s\n",
            ARPNDP_HISTORY_TYPE_to_str (
                arpndp_data->hist[sess_idx][cur_idx].history_type),
            ARPNDP_history_print_data (
                arpndp_data->hist[sess_idx][cur_idx].history_type,
                arpndp_data->hist[sess_idx][cur_idx].history_data));
    }

    ARPNDP_LOG_FORCED (buffer);
}
