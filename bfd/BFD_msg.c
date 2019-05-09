/*************************************************************************
 *
 * File:     BFD_msg.c
 *
 * Abstract: implementation file of BFD message module
 *           this module encodes/decodes BFD message
 *
 * Data:     none
 *
 * Functions:
 *     BFD_msg_encode - function to encode a BFD message
 *     BFD_msg_decode - function to decode/process a BFD message
 *
 *     BFD_msg_log    - function to log a BFD message
 *
 ************************************************************************/

#include "BFD_int_hdr.h"


/*
 * Name:        BFD_msg_encode
 *
 * Abstract:    function to encode a BFD message
 *
 * Parameters:
 *     sess_idx   - BFD session index
 *     final_flag - whether to set final flag (final message)
 *
 * Retunrs:     none
 */
void BFD_msg_encode (int sess_idx, BOOL final_flag)
{
    /* message buffer is is BFD session data */
    BFD_MSG *msg_buf = &bfd_data->sess[sess_idx].send_msg;

    /* BFD version is always 1 */
    msg_buf->version = BFD_PROTO_VERSION;

    msg_buf->diagnostic = bfd_data->sess[sess_idx].local.diagnostic;

    msg_buf->sess_state = bfd_data->sess[sess_idx].local.sess_state;

    if (final_flag == TRUE)
    {
        /* final message */
        /* poll flag must be clear */
        msg_buf->poll_flag = FALSE;
    }
    else
    {
        /* non-final message */
        msg_buf->poll_flag = bfd_data->sess[sess_idx].local_poll_seq;
    }

    msg_buf->final_flag = final_flag;

    /* control plane independent flag is always TRUE */
    msg_buf->ctl_plane_indpd_flag = TRUE;

    /* authentication flag is always FALSE */
    msg_buf->auth_present_flag = FALSE;

    /* demand flag is always FALSE */
    msg_buf->demand_flag = FALSE;

    /* multi-point flag is always FALSE */
    msg_buf->multi_point_flag = FALSE;

    msg_buf->detect_time_mult =
        bfd_data->sess[sess_idx].local.detect_time_mult;

    /* BFD message length is always 24 */
    msg_buf->length = BFD_MSG_LENGTH;

    /* convert host byte-order to network byte-order if field size > 1 */

    msg_buf->my_discr = htonl (bfd_data->sess[sess_idx].local.discriminator);
    msg_buf->your_discr = htonl
        (bfd_data->sess[sess_idx].remote.discriminator);

    /* required min echo Tx interval is always 0 */
    msg_buf->min_echo_rx = 0;

    if (bfd_data->sess[sess_idx].local_poll_seq == TRUE)
    {
        /* in local poll sequence */
        /* use transition local session data */
        msg_buf->min_tx = htonl
            (bfd_data->sess[sess_idx].local.trans.min_tx * BFD_USEC_IN_MSEC);
        msg_buf->min_rx = htonl
            (bfd_data->sess[sess_idx].local.trans.min_rx * BFD_USEC_IN_MSEC);
    }
    else
    {
        /* not in local poll sequence */
        /* use official local session data */
        msg_buf->min_tx = htonl
            (bfd_data->sess[sess_idx].local.ofc.min_tx * BFD_USEC_IN_MSEC);
        msg_buf->min_rx = htonl
            (bfd_data->sess[sess_idx].local.ofc.min_rx * BFD_USEC_IN_MSEC);
    }

    bfd_data->sess_stats[sess_idx].good_encode++;
}


/*
 * Name:        BFD_msg_decode
 *
 * Abstract:    function to decode/process a BFD message;
 *              this function must not modify the recieved BFD message
 *
 * Parameters:
 *     sess_idx                 - BFD session index
 *
 * Retunrs:
 *     ret_val                  - success or failure
 *
 *     start_transmission_timer - whether to start transmission timer
 *     start_fault_detect_timer - whether to start fault detection timer
 */
BFD_RETVAL BFD_msg_decode (int sess_idx, BOOL *start_transmission_timer,
    BOOL *start_fault_detect_timer)
{
    /* received message is is BFD session data */
    BFD_MSG *recv_msg = &bfd_data->sess[sess_idx].recv_msg;

    uint32_t new_your_discr;
    uint32_t new_my_discr;
    uint32_t new_min_tx;
    uint32_t new_min_rx;

    /* sanity checks */

    if (recv_msg->version != BFD_PROTO_VERSION)
    {
        /* BFD version is not 1 */
        BFD_REMOTE_ERROR ("invalid remote BFD version %u, %u expected\n",
            recv_msg->version, BFD_PROTO_VERSION);
        bfd_data->sess_stats[sess_idx].inv_remote_version++;
        return BFD_REMOTE_FAIL;
    }

    if (recv_msg->diagnostic > BFD_DIAG_REVERSE_CONCAT_PATH_DOWN)
    {
        /* BFD diagnostic code is out of range */
        BFD_REMOTE_ERROR ("invalid remote BFD diagnostic %u, "
            "%d to %d expected\n", recv_msg->diagnostic, BFD_DIAG_NONE,
            BFD_DIAG_REVERSE_CONCAT_PATH_DOWN);
        bfd_data->sess_stats[sess_idx].inv_remote_diagnostic++;
        return BFD_REMOTE_FAIL;
    }

    if (recv_msg->sess_state > BFD_SESS_STATE_UP)
    {
        /* session state is out of range */
        BFD_REMOTE_ERROR ("invalid remote session state %u, "
            "%d to %d expected\n", recv_msg->sess_state,
            BFD_SESS_STATE_ADMIN_DOWN, BFD_SESS_STATE_UP);
        bfd_data->sess_stats[sess_idx].inv_remote_sess_state++;
        return BFD_REMOTE_FAIL;
    }

    if ((recv_msg->poll_flag == TRUE) && (recv_msg->final_flag == TRUE))
    {
        /* both poll_flag and final_flag are TRUE */
        BFD_REMOTE_ERROR ("remote both poll and final flags are set\n");
        bfd_data->sess_stats[sess_idx].remote_both_poll_and_final++;
        return BFD_REMOTE_FAIL;
    }
    /* Do not care about ctl_plane_indpd flag */
    if (recv_msg->auth_present_flag == TRUE)
    {
        /* authentication present flag is TRUE */
        BFD_REMOTE_ERROR ("remote authentication present flag is set\n");
        bfd_data->sess_stats[sess_idx].inv_remote_auth_present_flag++;
        return BFD_REMOTE_FAIL;
    }
    if (recv_msg->demand_flag == TRUE)
    {
        /* demand flag is TRUE */
        BFD_REMOTE_ERROR ("remote demand flag is set\n");
        bfd_data->sess_stats[sess_idx].inv_remote_demand_flag++;
        return BFD_REMOTE_FAIL;
    }
    if (recv_msg->multi_point_flag == TRUE)
    {
        /* multi-point flag is TRUE */
        BFD_REMOTE_ERROR ("remote multi-point flag is set\n");
        bfd_data->sess_stats[sess_idx].inv_remote_multi_point_flag++;
        return BFD_REMOTE_FAIL;
    }

    if (recv_msg->detect_time_mult == 0)
    {
        /* detection time multiplier is 0 */
        BFD_REMOTE_ERROR ("remote detection time multiplier is 0, "
            "non-zero expected\n");
        bfd_data->sess_stats[sess_idx].inv_remote_detect_time_mult++;
        return BFD_REMOTE_FAIL;
    }

    if (recv_msg->length != BFD_MSG_LENGTH)
    {
        /* BFD message length is not 24 */
        BFD_REMOTE_ERROR ("invalid remote BFD message length %u, "
            "%u expected\n", recv_msg->length, BFD_MSG_LENGTH);
        bfd_data->sess_stats[sess_idx].inv_remote_length++;
        return BFD_REMOTE_FAIL;
    }

    if (recv_msg->my_discr == 0)
    {
        /* my discriminator is 0 */
        BFD_REMOTE_ERROR ("remote 'my discriminator' is 0, "
            "non-zero expected\n");
        bfd_data->sess_stats[sess_idx].inv_remote_my_discr++;
        return BFD_REMOTE_FAIL;
    }

    if (recv_msg->your_discr == 0)
    {
        if ((recv_msg->sess_state != BFD_SESS_STATE_ADMIN_DOWN) &&
            (recv_msg->sess_state != BFD_SESS_STATE_DOWN))
        {
            /*
             * your discriminator is 0
             * when remote session state is not ADMIN DOWN nor DOWN
             */
            BFD_REMOTE_ERROR ("remote 'your discriminator' is 0 when in "
                "remote session state %u, non-zero expected\n",
                recv_msg->sess_state);
            bfd_data->sess_stats[sess_idx].inv_remote_your_discr++;
            return BFD_REMOTE_FAIL;
        }
    }
    else
    {
#ifdef BFD_LISTEN_TIMER_ENABLED
        if (bfd_data->sess[sess_idx].listen_timer == 0)
        {
#endif /* #ifdef BFD_LISTEN_TIMER_ENABLED */
            new_your_discr = ntohl (recv_msg->your_discr);
            if (new_your_discr != bfd_data->sess[sess_idx].local.discriminator)
            {
                /*
                 * your discriminator does not match with local discriminator
                 * this BFD session
                 */

                BFD_REMOTE_ERROR ("invalid remote 'your discriminator' %u, "
                    "%u expected\n", new_your_discr,
                    bfd_data->sess[sess_idx].local.discriminator);
                bfd_data->sess_stats[sess_idx].inv_remote_your_discr++;
                return BFD_REMOTE_FAIL;
            }
#ifdef BFD_LISTEN_TIMER_ENABLED
        }
#endif /* #ifdef BFD_LISTEN_TIMER_ENABLED */
    }

    if (recv_msg->min_echo_rx != 0)
    {
        /* required min echo Rx interval is not 0 */
        BFD_REMOTE_ERROR ("invalid remote required min Rx interval %u, "
            "0 expected\n", recv_msg->min_echo_rx);
        bfd_data->sess_stats[sess_idx].inv_remote_min_echo_rx++;
        return BFD_REMOTE_FAIL;
    }

    /* save information in received message to BFD session data */
    /* also decide whether to start BFD timers */

    if (recv_msg->diagnostic != bfd_data->sess[sess_idx].remote.diagnostic)
    {
        /* remote diagnostic changes */
        BFD_history_add (sess_idx, BFD_HISTORY_REMOTE_DIAGNOSTIC,
            (uint32_t) recv_msg->diagnostic);

        bfd_data->sess[sess_idx].remote.diagnostic = recv_msg->diagnostic;
    }

    if (recv_msg->sess_state != bfd_data->sess[sess_idx].remote.sess_state)
    {
        /* remote session state changes */
        BFD_history_add (sess_idx, BFD_HISTORY_REMOTE_SESS_STATE,
            (uint32_t) recv_msg->sess_state);

        bfd_data->sess[sess_idx].remote.sess_state = recv_msg->sess_state;
    }

    if (recv_msg->detect_time_mult !=
        bfd_data->sess[sess_idx].remote.detect_time_mult)
    {
        /* remote detection time multiplier changes */

        BFD_history_add (sess_idx, BFD_HISTORY_REMOTE_DETECT_TIME_MULT,
            (uint32_t) recv_msg->detect_time_mult);

        *start_fault_detect_timer = TRUE;

        bfd_data->sess[sess_idx].remote.detect_time_mult =
            recv_msg->detect_time_mult;

        /* fix fault_detect_timer_fire_num if needed */
        if (bfd_data->sess[sess_idx].fault_detect_timer_fire_num >=
            bfd_data->sess[sess_idx].remote.detect_time_mult)
        {
            bfd_data->sess[sess_idx].fault_detect_timer_fire_num =
                bfd_data->sess[sess_idx].remote.detect_time_mult - 1;
        }
    }

    /* convert network byte-order to host byte-order if field size > 1 */

    new_my_discr = ntohl (recv_msg->my_discr);
    if (new_my_discr != bfd_data->sess[sess_idx].remote.discriminator)
    {
        /* remote my discriminator changes */

        BFD_history_add (sess_idx, BFD_HISTORY_REMOTE_DISCRIMINATOR,
            (uint32_t) new_my_discr);

        bfd_data->sess[sess_idx].remote.discriminator = new_my_discr;
    }
    
    new_min_tx = ntohl (recv_msg->min_tx) / BFD_USEC_IN_MSEC;
    if (new_min_tx != bfd_data->sess[sess_idx].remote.min_tx)
    {
        /* remote desired Tx interval changes */

        BFD_history_add (sess_idx, BFD_HISTORY_REMOTE_MIN_TX,
            (uint32_t) new_min_tx);

        *start_fault_detect_timer = TRUE;

        bfd_data->sess[sess_idx].remote.min_tx = new_min_tx;
    }

    new_min_rx = ntohl (recv_msg->min_rx) / BFD_USEC_IN_MSEC;
    if (new_min_rx != bfd_data->sess[sess_idx].remote.min_rx)
    {
        /* remote required min Rx interval changes */

        BFD_history_add (sess_idx, BFD_HISTORY_REMOTE_MIN_RX,
            (uint32_t) new_min_rx);

        *start_transmission_timer = TRUE;

        bfd_data->sess[sess_idx].remote.min_rx = new_min_rx;
    }

    bfd_data->sess_stats[sess_idx].good_decode++;
    return BFD_SUCCESS;
}



/*
 * Name:        BFD_msg_log
 *
 * Abstract:    function to log a BFD message
 *
 * Parameters:
 *     sess_idx - BFD session index
 *
 * Retunrs:     none
 */
void BFD_msg_log (int sess_idx)
{
    char buffer[BFD_ERR_LOG_BUF_SIZE];
    char *ptr = &buffer[0];
    int size = sizeof(buffer);

    BFD_MSG *msg = &bfd_data->sess[sess_idx].recv_msg;

    BFD_PRINTF (ptr, size,
        "Invalid received message at index %d:\n"

        "    version                              %u\n"
        "    diagnostic                           %u - %s\n"
        "\n"
        "    sess_state                           %u - %s\n"
        "\n"
        "    poll_flag                            %u\n"
        "    final_flag                           %u\n"
        "    ctl_plane_indpd_flag                 %u\n"
        "    auth_present_flag                    %u\n"
        "    demand_flag                          %u\n"
        "    multi_point_flag                     %u\n"
        "\n"
        "    detect_time_mult                     %u\n"
        "    length                               %u\n"
        "\n"
        "    my_discr                             %u\n"
        "    your_discr                           %u\n"
        "\n"
        "    min_tx                               %u\n"
        "    min_rx                               %u\n"
        "    min_echo_rx                          %u\n",

        sess_idx,

        msg->version,
        msg->diagnostic, BFD_DIAGNOSTIC_to_str (msg->diagnostic),

        msg->sess_state, BFD_SESS_STATE_to_str (msg->sess_state),

        msg->poll_flag,
        msg->final_flag,
        msg->ctl_plane_indpd_flag,
        msg->auth_present_flag,
        msg->demand_flag,
        msg->multi_point_flag,

        msg->detect_time_mult,
        msg->length,

        ntohl (msg->my_discr),
        ntohl (msg->your_discr),

        ntohl (msg->min_tx) / BFD_USEC_IN_MSEC,
        ntohl (msg->min_rx) / BFD_USEC_IN_MSEC,
        ntohl (msg->min_echo_rx) / BFD_USEC_IN_MSEC);

    BFD_LOG_FORCED (buffer);
}

