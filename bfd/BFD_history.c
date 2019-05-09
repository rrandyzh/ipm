/*************************************************************************
 *
 * File:     BFD_history.c
 *
 * Abstract: implementation file of BFD history module
 *           this module handles BFD history
 *           BFD history is implemented as a circular buffer
 *
 * Data:     none
 *
 * Functions:
 *     BFD_history_init       - function to initialize BFD history module
 *
 *     BFD_history_print_data - module-internal function to print BFD history
 *                              data
 *
 *     BFD_history_add        - function to add a new BFD history
 *     BFD_history_log        - function to log BFD history of a
 *                              BFD session
 *
 ************************************************************************/

#include "BFD_int_hdr.h"


/*
 * Name:        BFD_history_init
 *
 * Abstract:    function to initialize BFD history module
 *
 * Parameters:  none
 *
 * Returns:     none
 */
void BFD_history_init()
{
    memset (bfd_data->hist, 0, sizeof(bfd_data->hist));
    memset (bfd_data->hist_cur_idx, 0, sizeof(bfd_data->hist_cur_idx));
}


/*
 * Name:        BFD_history_print_data
 *
 * Abstract:    module-internal function to print BFD history data
 *
 * Parameters:
 *     history_type     - BFD history type
 *     history_data     - BFD history data
 *
 * Returns:
 *     history_data_str - BFD history data as string
 */
static const char *BFD_history_print_data (BFD_HISTORY_TYPE history_type,
    uint32_t history_data)
{
    static char buffer[ 100];

    switch (history_type)
    {
    case BFD_HISTORY_REMOTE_SESS_STATE:
        return BFD_SESS_STATE_to_str (history_data);
    case BFD_HISTORY_REMOTE_DIAGNOSTIC:
        return BFD_DIAGNOSTIC_to_str (history_data);
    case BFD_HISTORY_REMOTE_DISCRIMINATOR:
        sprintf (buffer, "%u", history_data);
        return buffer;

    case BFD_HISTORY_REMOTE_DETECT_TIME_MULT:
        sprintf (buffer, "%u", history_data);
        return buffer;
    case BFD_HISTORY_REMOTE_MIN_TX:
        sprintf (buffer, "%u", history_data);
        return buffer;
    case BFD_HISTORY_REMOTE_MIN_RX:
        sprintf (buffer, "%u", history_data);
        return buffer;

    case BFD_HISTORY_LOCAL_ADMIN_STATE:
        return BFD_ADMIN_STATE_to_str (history_data);
    case BFD_HISTORY_LOCAL_SESS_STATE:
        return BFD_SESS_STATE_to_str (history_data);
    case BFD_HISTORY_LOCAL_DIAGNOSTIC:
        return BFD_DIAGNOSTIC_to_str (history_data);

    case BFD_HISTORY_LOCAL_DETECT_TIME_MULT:
        sprintf (buffer, "%u", history_data);
        return buffer;
    case BFD_HISTORY_LOCAL_CFG_MIN_TX:
        sprintf (buffer, "%u", history_data);
        return buffer;
    case BFD_HISTORY_LOCAL_USED_MIN_TX:
        sprintf (buffer, "%u", history_data);
        return buffer;
    case BFD_HISTORY_LOCAL_MIN_RX:
        sprintf (buffer, "%u", history_data);
        return buffer;

#ifdef BFD_LISTEN_TIMER_ENABLED

    case BFD_HISTORY_LISTEN_TIMER:
        sprintf (buffer, "%u", history_data);
        return buffer;

#endif /* #ifdef BFD_LISTEN_TIMER_ENABLED */

    case BFD_HISTORY_TRANSMISSION_TIMER:
        sprintf (buffer, "%u", history_data);
        return buffer;
    case BFD_HISTORY_FAULT_DETECT_TIMER:
        sprintf (buffer, "%u", history_data);
        return buffer;

    case BFD_HISTORY_RECV_COUNT:
        sprintf (buffer, "%u", history_data);
        return buffer;
    case BFD_HISTORY_SEND_COUNT:
        sprintf (buffer, "%u", history_data);
        return buffer;
    default:
        return "UNKNOWN";
    }
}


/*
 * Name:        BFD_history_add
 *
 * Abstract:    function to add a new BFD history
 *
 * Parameters:
 *     sess_idx     - BFD session index
 *     history_type - BFD history type
 *     history_data - BFD hstory data
 *
 * Returns:     none
 */
void BFD_history_add (int sess_idx, BFD_HISTORY_TYPE history_type,
    uint32_t history_data)
{
    int cur_idx;

    if (BFD_LOG_ENABLED)
    {
        BFD_LOG (
            "BFD_history_add: "
            "sess_idx %d, "
            "history_type %s, "
            "history_data %s\n",
            sess_idx,
            BFD_HISTORY_TYPE_to_str (history_type),
            BFD_history_print_data (history_type, history_data));
    }

    /* circular buffer */

    /* current index to store data */
    cur_idx = bfd_data->hist_cur_idx[sess_idx];

    if ((cur_idx < 0) || (cur_idx >= BFD_HISTORY_MAX))
    {
        BFD_INTERNAL_ERROR ("invalid cur_idx %d, 0 to %d expected\n",
            cur_idx, BFD_HISTORY_MAX - 1);
        bfd_data->stats.inv_history_cur_idx++;

        /* re-initialize data */
        memset (bfd_data->hist[sess_idx], 0, sizeof(bfd_data->hist[0]));
        cur_idx = 0;
    }

    bfd_data->hist[sess_idx][cur_idx].history_type = history_type;
    bfd_data->hist[sess_idx][cur_idx].history_data = history_data;

    /* next index */
    cur_idx++;
    if (cur_idx == BFD_HISTORY_MAX)
    {
        cur_idx = 0;
    }
    bfd_data->hist_cur_idx[sess_idx] = cur_idx;
}


/*
 * Name:        BFD_history_log
 *
 * Abstract:    function to log BFD history for a BFD session
 *
 * Parameters:
 *     sess_idx  - BFD session index
 *
 * Returns:     none
 */
void BFD_history_log (int sess_idx)
{
    int cur_idx;
    int end_idx;

    char buffer[BFD_ERR_LOG_BUF_SIZE];
    char *ptr = &buffer[0];
    int size = sizeof(buffer);

    int count = 0;

    /* circular buffer */

    cur_idx = bfd_data->hist_cur_idx[sess_idx];
    end_idx = cur_idx;

    if ((cur_idx < 0) || (cur_idx >= BFD_HISTORY_MAX))
    {
        BFD_INTERNAL_ERROR ("invalid cur_idx %d, 0 to %d expected\n",
            cur_idx, BFD_HISTORY_MAX - 1);
        bfd_data->stats.inv_history_cur_idx++;

        /* re-initialize data */
        memset (bfd_data->hist[sess_idx], 0, sizeof(bfd_data->hist[0]));
        bfd_data->hist_cur_idx[sess_idx] = 0;

        /* log nothing */
        return;
    }

    BFD_PRINTF (ptr, size, "BFD history at index %d report 1\n",
        sess_idx);

    for(;;)
    {
        if ((count != 0) && ((count % (BFD_HISTORY_MAX / 4)) == 0))
        {
            BFD_LOG_FORCED (buffer);

            ptr = &buffer[0];
            size = sizeof(buffer);
            BFD_PRINTF (ptr, size, "BFD history at index %d report %u\n",
                sess_idx, (count / (BFD_HISTORY_MAX / 4)) + 1);
        }

        /* previous index to retrieve data */
        cur_idx--;
        if (cur_idx < 0)
        {
            cur_idx = BFD_HISTORY_MAX - 1;
        }

        if (cur_idx == end_idx)
        {
            /* make a full circle */
            /* stop */
            break;
        }

        if (bfd_data->hist[sess_idx][cur_idx].history_type ==
            BFD_HISTORY_NOT_USED)
        {
            /* no more data */
            /* stop */
            break;
        }

        BFD_PRINTF (ptr, size, "    %-36s %s\n",
            BFD_HISTORY_TYPE_to_str (
                bfd_data->hist[sess_idx][cur_idx].history_type),
            BFD_history_print_data (
                bfd_data->hist[sess_idx][cur_idx].history_type,
                bfd_data->hist[sess_idx][cur_idx].history_data));
    }

    BFD_LOG_FORCED (buffer);
}
