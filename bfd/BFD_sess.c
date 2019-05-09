/*************************************************************************
 *
 * File:     BFD_sess.c
 *
 * Abstract: implementation file of BFD session module
 *           this module handles BFD session
 *
 * Data:     none
 *
 * Functions:
 *     BFD_sess_create          - function to create a new BFD session
 *                                without creating socket and binding
 *     BFD_sess_change_cfg      - function to change BFD session parameters
 *                                after BFD session has been created
 *     BFD_sess_destroy         - function to destroy an existing BFD session
 *
 *     BFD_sess_get_sess_state  - function to get session state a BFD session
 *     BFD_sess_set_admin_state - function to set administrative state of a
 *                                BFD session
 *
 *     BFD_sess_get_stats       - function to get statistics/counts of a BFD
 *                                session
 *     BFD_sess_clear_stats     - function to clear statistics/counts of
 *                                a BFD session
 *
 *     BFD_sess_timer           - function to call every 5 milli-seconds to
 *                                implement BFD timers
 *     BFD_sess_recv            - function to process a received BFD message
 *
 *     BFD_sess_check_sock      - function to check this socket in this BFD
 *                                session with sockets in all other BFD
 *                                sessions
 *     BFD_sess_ext_audit       - function to externally audit BFD session
 *     BFD_sess_int_audit       - function to internally audit BFD session
 *
 ************************************************************************/

#include "BFD_int_hdr.h"


/*
 * Name:        BFD_sess_create
 *
 * Abstract:    function to create a new BFD session
 *
 * Parameters:
 *     local_ip         - local IP of this BFD session
 *     remote_ip        - remote IP
 *
 *     detect_time_mult - detection time multiplier
 *     min_tx           - desired min Tx interval
 *     min_rx           - required min Tx interval
 *
 * Returns:
 *     ret_val          - success or failure
 *
 * Notes: Local and remote IPs can be IPv4 or IPv6
 */
BFD_RETVAL BFD_sess_create (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    uint8_t detect_time_mult, uint32_t min_tx, uint32_t min_rx)
{
    BFD_RETVAL ret_val;
    int sess_idx = BFD_INV_SESS_IDX;
    int fixed_sess_idx;

    /* allocate a new BFD session data */
    ret_val = BFD_sess_data_alloc (local_ip, remote_ip, &sess_idx);
    if (ret_val != BFD_SUCCESS)
    {
        return ret_val;
    }

    /* save LCP data in BFD session */

    bfd_data->sess[sess_idx].local_ip = *local_ip;
    bfd_data->sess[sess_idx].remote_ip = *remote_ip;

    bfd_data->sess[sess_idx].local.detect_time_mult = detect_time_mult;
    bfd_data->sess[sess_idx].local.cfg_min_tx = min_tx;
    bfd_data->sess[sess_idx].local.ofc.min_rx = min_rx;

    /* record BFD history */

    BFD_history_add (sess_idx, BFD_HISTORY_LOCAL_DETECT_TIME_MULT,
        (uint32_t) detect_time_mult);

    BFD_history_add (sess_idx, BFD_HISTORY_LOCAL_CFG_MIN_TX,
        (uint32_t) min_tx);
    BFD_history_add (sess_idx, BFD_HISTORY_LOCAL_USED_MIN_TX,
        (uint32_t) BFD_SLOW_TRANSMISSION_TIMER);

    BFD_history_add (sess_idx, BFD_HISTORY_LOCAL_MIN_RX,
        (uint32_t) min_rx);

    /* populate default values in BFD session */

#ifdef BFD_STAND_ALONE
    /* BFD stand-alone/simulator has passive role */
    bfd_data->sess[sess_idx].active_passive = BFD_ROLE_PASSIVE;
#else /* #ifdef BFD_STAND_ALONE */
    /* official BFD stack has active role */
    bfd_data->sess[sess_idx].active_passive = BFD_ROLE_ACTIVE;
#endif /* #ifdef BFD_STAND_ALONE */

    bfd_data->sess[sess_idx].admin_state = BFD_ADMIN_STATE_UP;
    bfd_data->sess[sess_idx].local_poll_seq = FALSE;
    bfd_data->sess[sess_idx].has_recv_msg = FALSE;

    bfd_data->sess[sess_idx].local.diagnostic = BFD_DIAG_NONE;
    bfd_data->sess[sess_idx].local.sess_state = BFD_SESS_STATE_DOWN;
    bfd_data->sess[sess_idx].local.discriminator =
        BFD_LOCAL_DISCRIMINATOR_BASE + sess_idx;

    bfd_data->sess[sess_idx].local.ofc.min_tx = BFD_SLOW_TRANSMISSION_TIMER;

    bfd_data->sess[sess_idx].local.trans.min_tx = 0;
    bfd_data->sess[sess_idx].local.trans.min_rx = 0;

    bfd_data->sess[sess_idx].remote.diagnostic = BFD_DIAG_NONE;
    bfd_data->sess[sess_idx].remote.sess_state = BFD_SESS_STATE_DOWN;
    bfd_data->sess[sess_idx].remote.detect_time_mult = 0;
    bfd_data->sess[sess_idx].remote.discriminator = 0;

    bfd_data->sess[sess_idx].remote.min_tx = 0;

    /* need non-zero to send BFD message with transmission timer */
    bfd_data->sess[sess_idx].remote.min_rx = 1;


#ifdef BFD_LISTEN_TIMER_ENABLED

    /*
     * get/find another fixed-IP BFD session with the same remote IP and
     * its local session state is UP
     */
    ret_val = BFD_sess_data_get_fixed (remote_ip, sess_idx, &fixed_sess_idx);
    if (ret_val != BFD_SUCCESS)
    {
        /* no fixed-IP BFD session */

        /* start listening timer using default values */
        BFD_timer_start_listen_timer (sess_idx, BFD_INV_SESS_IDX);
    }
    else
    {
        /* has fixed-IP BFD session */

        /* start listening timer using data from fixed-IP BFD session */
        BFD_timer_start_listen_timer (sess_idx, fixed_sess_idx);
    }

    /*
     * do not send out BFD message until listening timer fires;
     * do not start transmission timer
     */
    BFD_timer_stop_transmission_timer (sess_idx);

#else /* #ifdef BFD_LISTEN_TIMER_ENABLED */

     /* start transmission timer to send BFD message immediately */
     BFD_timer_start_transmission_timer (sess_idx);

#endif /* #ifdef BFD_LISTEN_TIMER_ENABLED */


    /*
     * fault detection timer is not started 
     * until local session state is INIT or UP
     */
    BFD_timer_stop_fault_detect_timer (sess_idx);


    /* create sockets and bind later */
    bfd_data->sess[sess_idx].send_sock = -1;
    bfd_data->sess[sess_idx].recv_sock = -1;

    bfd_data->sess[sess_idx].recv_count = 0;
    bfd_data->sess[sess_idx].send_count = 0;

    return BFD_SUCCESS;
}


/*
 * Name:        BFD_sess_change_cfg
 *
 * Abstract:    function to change BFD session parameters after BFD session
 *              has been created
 *
 * Parameters:
 *     sess_idx         - BFD session index
 *
 *     detect_time_mult - new detection time multiplier
 *     min_tx           - new desired min Tx interval
 *     min_rx           - new required min Tx interval
 *
 * Returns:
 *     ret_val          - success or failure
 */
BFD_RETVAL BFD_sess_change_cfg (int sess_idx, uint8_t detect_time_mult,
    uint32_t min_tx, uint32_t min_rx)
{
    if (detect_time_mult != bfd_data->sess[sess_idx].local.detect_time_mult)
    {
        /* local detection time multiplier changes */

        BFD_history_add (sess_idx, BFD_HISTORY_LOCAL_DETECT_TIME_MULT,
            (uint32_t) detect_time_mult);

        /* takes affect immediately */
        bfd_data->sess[sess_idx].local.detect_time_mult = detect_time_mult;
    }

    if (min_tx != bfd_data->sess[sess_idx].local.cfg_min_tx)
    {
        /* local desired min Tx changes */

        BFD_history_add (sess_idx, BFD_HISTORY_LOCAL_CFG_MIN_TX,
            (uint32_t) min_tx);

        bfd_data->sess[sess_idx].local.cfg_min_tx = min_tx;
    }

    if ((bfd_data->sess[sess_idx].local_poll_seq == TRUE) &&
        (min_tx == bfd_data->sess[sess_idx].local.ofc.min_tx) &&
        (min_rx == bfd_data->sess[sess_idx].local.ofc.min_rx))
    {
        /*
         * previous poll sequence has not finished;
         * it is probablly gets stuck due to router not sending final;
         *
         * new min_tx and min_rx values are the same as before poll sequence;
         * user wants to back out current poll sequence;
         */

        bfd_data->sess[sess_idx].local_poll_seq = FALSE;
        bfd_data->sess[sess_idx].local.trans.min_tx = 0;
        bfd_data->sess[sess_idx].local.trans.min_rx = 0;
    }

    if (bfd_data->sess[sess_idx].local.sess_state == BFD_SESS_STATE_UP)
    {
        /* session state is UP */

        if ((min_tx != bfd_data->sess[sess_idx].local.ofc.min_tx) ||
            (min_rx != bfd_data->sess[sess_idx].local.ofc.min_rx))
        {
            /*
             * desired min Tx interval or required min Rx interval or both
             * changes
             */

            if (bfd_data->sess[sess_idx].local_poll_seq == TRUE)
            {
                BFD_LOCAL_ERROR ("session configuration data change fails; "
                    "previous local poll sequence is still in progress\n");
                bfd_data->stats.local_poll_seq_in_progress++;
                return BFD_LOCAL_FAIL;
            }

            /* do a real local poll sequence */
            bfd_data->sess[sess_idx].local_poll_seq = TRUE;
            bfd_data->sess[sess_idx].local.trans.min_tx = min_tx;
            bfd_data->sess[sess_idx].local.trans.min_rx = min_rx;

            /* add BFD history later when receiving final */
        }
    }
    else
    {
        /* session state is (ADMIN DOWN, DOWN, or INIT) */

        if (bfd_data->sess[sess_idx].local.ofc.min_tx !=
            BFD_SLOW_TRANSMISSION_TIMER)
        {
            BFD_SESS_ERROR (sess_idx, "invalid local.ofc.min_tx %u; "
                "slow transmission timer expected\n",
                bfd_data->sess[sess_idx].local.ofc.min_tx);
            bfd_data->stats.inv_local_ofc_min_tx++;
        }

        /*
         * no change to bfd_data->sess[sess_idx].local.ofc.min_tx;
         * it is always slow timer in non-UP session state
         */

        if (min_rx != bfd_data->sess[sess_idx].local.ofc.min_rx)
        {
            /* required min Rx interval changes */

            BFD_history_add (sess_idx, BFD_HISTORY_LOCAL_MIN_RX,
                (uint32_t) min_rx);

            bfd_data->sess[sess_idx].local.ofc.min_rx = min_rx;
        }
    }

    return BFD_SUCCESS;
}


/*
 * Name:        BFD_sess_destroy
 *
 * Abstract:    function to destroy an existing BFD session
 *
 * Parameters:
 *     sess_idx - BFD sesion index
 *
 * Returns:     none
 */
void BFD_sess_destroy (int sess_idx)
{
    /* close receive and send sockets */
    BFD_trans_close_sockets (sess_idx);

    /* free BFD session data */
    BFD_sess_data_free (sess_idx);
}


/*
 * Name:        BFD_sess_get_sess_state
 *
 * Abstract:    function to get session state of BFD session
 *
 * Parameters:
 *     sess_idx - BFD sesion index
 *
 * Returns:     none
 */
void BFD_sess_get_sess_state (int sess_idx, BFD_SESS_STATE *sess_state)
{
    /* return session state */
    *sess_state = bfd_data->sess[sess_idx].local.sess_state;
}


/*
 * Name:        BFD_sess_set_admin_state
 *
 * Abstract:    function to set administrative state of BFD session
 *
 * Parameters:
 *     sess_idx        - BFD sesion index
 *     new_admin_state - new administrative state
 *
 * Returns:
 *     ret_val         - success or failure
 */
BFD_RETVAL BFD_sess_set_admin_state (int sess_idx,
    BFD_ADMIN_STATE new_admin_state)
{
    BFD_RETVAL ret_val;

    if (new_admin_state == bfd_data->sess[sess_idx].admin_state)
    {
        /* no change in admin state */
        return BFD_SUCCESS;
    }

    BFD_history_add (sess_idx, BFD_HISTORY_LOCAL_ADMIN_STATE,
        (uint32_t) new_admin_state);

    /* run finite state machine with new admin state */
    ret_val = BFD_fsm_run (sess_idx, (BFD_EVENT) new_admin_state);
    if (ret_val != BFD_SUCCESS)
    {
        return ret_val;
    }

    /* save new admin state */
    bfd_data->sess[sess_idx].admin_state = new_admin_state;

    return BFD_SUCCESS;
}


/*
 * Name:        BFD_sess_get_stats
 *
 * Abstract:    function to get statistics/counts of BFD session
 *
 * Parameters:
 *     sess_idx - BFD sesion index
 *
 * Returns:
 *     missed_hb - missed heartbeat
 *     corrupt_pkt - corrupt packets
 */
void BFD_sess_get_stats (int sess_idx, uint32_t *missed_hb, uint32_t *corrupt_pkt)
{
    /* return missed heartbeat */
    *missed_hb = bfd_data->sess[sess_idx].missed_hb;
    *corrupt_pkt = bfd_data->sess[sess_idx].corrupt_pkt;
}


/*     
 * Name:        BFD_sess_clear_stats
 *
 * Abstract:    function to clear statistics/counts of BFD session
 *
 * Parameters:
 *     sess_idx - BFD sesion index
 * 
 * Returns:     none
 */
void BFD_sess_clear_stats (int sess_idx)
{
    /* clear missed heartbeat */
    bfd_data->sess[sess_idx].missed_hb = 0;
    bfd_data->sess[sess_idx].corrupt_pkt = 0;
}


/*
 * Name:        BFD_sess_timer
 *
 * Abstract:    function to call every 5 milli-seconds to implement BFD
 *              timers
 *
 * Parameters:
 *     sess_idx - BFD sesion index
 *
 * Returns:     none
 */
void BFD_sess_timer (int sess_idx)
{
    BFD_RETVAL ret_val;

    /* create receiving socket and bind if having not done so */
    if (bfd_data->sess[sess_idx].recv_sock == -1)
    {
        ret_val = BFD_trans_create_recv_sock (sess_idx);
        if (ret_val != BFD_SUCCESS)
        {
            /* fail to create receiving socket and bind; try again later */
            return;
        }
    }

    /* create sending socket and bind if having not done so */
    if (bfd_data->sess[sess_idx].send_sock == -1)
    {
        ret_val = BFD_trans_create_send_sock (sess_idx);
        if (ret_val != BFD_SUCCESS)
        {
            /* fail to create sending socket and bind; try again later */
            return;
        }   
    }


#ifdef BFD_LISTEN_TIMER_ENABLED

    if (bfd_data->sess[sess_idx].listen_timer != 0)
    {
        /* listening timer is running */

        bfd_data->sess[sess_idx].listen_timer_countdown -=
            BFD_TIMER_INTERVAL;
        if (bfd_data->sess[sess_idx].listen_timer_countdown <= 0)
        {
            /* listening timer fires */
            BFD_timer_fire_listen_timer (sess_idx);
        }
    }

#endif /* #ifdef BFD_LISTEN_TIMER_ENABLED */

    if (bfd_data->sess[sess_idx].transmission_timer != 0)
    {
        /* transmission timer is running */

        bfd_data->sess[sess_idx].transmission_timer_countdown -=
            BFD_TIMER_INTERVAL;
        if (bfd_data->sess[sess_idx].transmission_timer_countdown <= 0)
        {
            /* transmision timer fires */
            BFD_timer_fire_transmission_timer (sess_idx);
        }
    }

    if (bfd_data->sess[sess_idx].fault_detect_timer != 0)
    {
        /* fault detection timer is running */

        bfd_data->sess[sess_idx].fault_detect_timer_countdown -=
            BFD_TIMER_INTERVAL;
        if (bfd_data->sess[sess_idx].fault_detect_timer_countdown <= 0)
        {
            /* fault detection timer fires */
            BFD_timer_fire_fault_detect_timer (sess_idx);
        }
    }
}


/*
 * Name:        BFD_sess_recv
 *
 * Abstract:    function to process a received BFD message
 *
 * Parameters:
 *     sess_idx - BFD sesion index
 *
 * Returns:
 *     ret_val  - success or failure
 */
BFD_RETVAL BFD_sess_recv (int sess_idx)
{
    BFD_RETVAL ret_val;

    BOOL start_transmission_timer = FALSE;
    BOOL start_fault_detect_timer = FALSE;

    BFD_MSG *recv_msg;

    if (bfd_data->sess[sess_idx].local.sess_state ==
        BFD_SESS_STATE_ADMIN_DOWN)
    {
        /* ignore all incoming messages while in ADMIN DOWN state */
        return BFD_SUCCESS;
    }

    if (bfd_data->sess[sess_idx].local.diagnostic ==
        BFD_DIAG_CTL_DETECT_TIME_EXPIRED)
    {
        /* local diagnostic changes */

        BFD_history_add (sess_idx, BFD_HISTORY_LOCAL_DIAGNOSTIC,
            (uint32_t) BFD_DIAG_NONE);

        bfd_data->sess[sess_idx].local.diagnostic =
            BFD_DIAG_NONE;
    }

    /* decode and process incoming message */
    ret_val = BFD_msg_decode (sess_idx, &start_transmission_timer,
        &start_fault_detect_timer);
    if (ret_val != BFD_SUCCESS)
    {
	if (ret_val == BFD_REMOTE_FAIL)
	{
		/* invalid data in received message */
        	bfd_data->sess[sess_idx].corrupt_pkt++;
	}

        /* incoming message is discarded */

        return ret_val;
    }

    recv_msg = (BFD_MSG *) &bfd_data->sess[sess_idx].recv_msg[0];

#ifdef BFD_LISTEN_TIMER_ENABLED

    if (bfd_data->sess[sess_idx].listen_timer != 0)
    {
        /* listening timer is running */

        /* stop listening timer */
        BFD_timer_stop_listen_timer (sess_idx);

        if (bfd_data->sess[sess_idx].remote.sess_state == BFD_SESS_STATE_UP)
        {
            /* remote session state is UP */

            /* set local session state to UP */
            BFD_history_add (sess_idx, BFD_HISTORY_LOCAL_SESS_STATE,
                (uint32_t) BFD_SESS_STATE_UP);
            bfd_data->sess[sess_idx].local.sess_state = BFD_SESS_STATE_UP;

            /* start fault detection timer */
            BFD_timer_start_fault_detect_timer (sess_idx);

            /* use fast transmission timer */
            bfd_data->sess[sess_idx].local.ofc.min_tx =
                bfd_data->sess[sess_idx].local.cfg_min_tx;
        }
        else
        {
            /* local session state stays as DOWN */
            /* no fault detection timer
            /* use slow transmission timer */
        }

        /* start transmission timer to send message periodically */
        BFD_timer_start_transmission_timer (sess_idx);

        if (bfd_data->sess[sess_idx].remote.min_rx != 0)
        {
            /* remote wants to receive message */

            /* send out a message immediately */
            if (recv_msg->poll_flag == TRUE)
            {
                BFD_msg_encode (sess_idx, /*final_flag*/ TRUE);
            }
            else
            {
                BFD_msg_encode (sess_idx, /*final_flag*/ FALSE);
            }

            ret_val = BFD_trans_send (sess_idx);
            if (ret_val != BFD_SUCCESS)
            {
                return ret_val;
            }
        }

        return BFD_SUCCESS;
    }

#endif /* #ifdef BFD_LISTEN_TIMER_ENABLED */

    /* incoming message is good */
    bfd_data->sess[sess_idx].has_recv_msg = TRUE;

    if (recv_msg->final_flag == TRUE)
    {
        /* receive final message */

        if (bfd_data->sess[sess_idx].local_poll_seq == TRUE)
        {
            /* in local poll sequence */

            /* finish local poll sequence */
            bfd_data->sess[sess_idx].local_poll_seq = FALSE;

            if (bfd_data->sess[sess_idx].local.trans.min_tx !=
                bfd_data->sess[sess_idx].local.ofc.min_tx)
            {
                /* local desired min Tx interval changes */

                BFD_history_add (sess_idx, BFD_HISTORY_LOCAL_USED_MIN_TX,
                    bfd_data->sess[sess_idx].local.trans.min_tx);

                bfd_data->sess[sess_idx].local.ofc.min_tx =
                    bfd_data->sess[sess_idx].local.trans.min_tx;

                start_transmission_timer = TRUE;
            }

            if (bfd_data->sess[sess_idx].local.trans.min_rx !=
                bfd_data->sess[sess_idx].local.ofc.min_rx)
            {
                /* local required min Rx interval changes */

                BFD_history_add (sess_idx, BFD_HISTORY_LOCAL_MIN_RX,
                    bfd_data->sess[sess_idx].local.trans.min_rx);

                bfd_data->sess[sess_idx].local.ofc.min_rx =
                    bfd_data->sess[sess_idx].local.trans.min_rx;

                start_fault_detect_timer = TRUE;
            }

            bfd_data->sess[sess_idx].local.trans.min_tx = 0;
            bfd_data->sess[sess_idx].local.trans.min_rx = 0;
        }
    }

    if (bfd_data->sess[sess_idx].transmission_timer != 0)
    {
        /* transmission timer is running */

        if (start_transmission_timer == TRUE)
        {
            /*
             * The following BFD session data has changed:
             *     local.ofc.min_tx
             *     remote.min_rx
             *
             * (re)calculate and (re)start transmission timer
             */
            BFD_timer_start_transmission_timer (sess_idx);
        }
    }

    if (bfd_data->sess[sess_idx].fault_detect_timer != 0)
    {
        /* fault detection timer is running */

        if (start_fault_detect_timer == TRUE)
        {
            /*
             * The following BFD session data has changed:
             *     local.ofc.min_rx
             *     remote.min_tx
             *
             * (re)calculate and (re)start fault detection timer
             */
            BFD_timer_start_fault_detect_timer (sess_idx);
        }
    }

    /* run finite state machine with remote session state */
    ret_val = BFD_fsm_run (sess_idx, recv_msg->sess_state);
    if (ret_val != BFD_SUCCESS)
    {
        return ret_val;
    }

    if (recv_msg->poll_flag == TRUE)
    {
        /* in remote poll sequence */

        if (bfd_data->sess[sess_idx].remote.min_rx != 0)
        {
            /* remote wants to receive message */

            /*
             * always send final message immediately
             * no check of bfd_data->sess[sess_idx].remote.min_rx
             */

            BFD_msg_encode (sess_idx, /*final_flag*/ TRUE);

            ret_val = BFD_trans_send (sess_idx);
            if (ret_val != BFD_SUCCESS)
            {
                return ret_val;
            }
        }
    }

    return BFD_SUCCESS;
}


/* 
 * Name:        BFD_sess_check_sock
 * 
 * Abstract:    function to check this socket in this BFD session with
 *              sockets in all other BFD sessions
 * 
 * Parameters:
 *     sess_idx - BFD sesion index
 *     sock     - socket to check
 * 
 * Returns:
  *     ret_val - success or failure
*/
BFD_RETVAL BFD_sess_check_sock (int sess_idx, int sock)
{
    BFD_RETVAL ret_val = BFD_SUCCESS;
    int other_sess_idx;

    /* get first BFD session */
    other_sess_idx = BFD_sess_data_get_first();

    /* loop until no more BFD session */
    while (other_sess_idx != BFD_INV_SESS_IDX)
    {
        if (sess_idx != sess_idx)
        {
            if (sock == bfd_data->sess[other_sess_idx].recv_sock)
            {
                BFD_INTERNAL_ERROR ("two or more sockets with the same "
                    "file descriptor, close and re-create the sockets\n");
                (void) close (bfd_data->sess[other_sess_idx].recv_sock);
                BFD_trans_create_recv_sock (other_sess_idx);
                ret_val = BFD_INTERNAL_FAIL;
            }
            if (sock == bfd_data->sess[sess_idx].send_sock)
            {
                BFD_INTERNAL_ERROR ("two or more sockets with the same "
                    "file descriptor, close and re-create the sockets\n");
                (void) close (bfd_data->sess[other_sess_idx].send_sock);
                BFD_trans_create_send_sock (other_sess_idx);
                ret_val = BFD_INTERNAL_FAIL;
            }
        }

        /* get next BFD session */
        other_sess_idx = BFD_sess_data_get_next (other_sess_idx);
    }

    return ret_val;
}


/*
 * Name:        BFD_sess_ext_audit
 *
 * Abstract:    function to externally audit BFD session
 * 
 * Parameters:
 *     sess_idx - BFD sesion index 
 * 
 * Returns:     none
 */    
void BFD_sess_ext_audit (int sess_idx) 
{      
    uint32_t audit_min_rx;

    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];

    /* get local required min Rx */
    if (bfd_data->sess[sess_idx].local.sess_state ==
        BFD_SESS_STATE_UP)
    {
        /* session state is UP */

        if (bfd_data->sess[sess_idx].local_poll_seq == FALSE)
        {
            /* not in local poll sequence */

            audit_min_rx = bfd_data->sess[sess_idx].local.ofc.min_rx;
        }
        else
        {
            /* in local poll sequence */

            audit_min_rx = bfd_data->sess[sess_idx].local.trans.min_rx;
        }
    }
    else
    {
        /* session state is (ADMIN DOWN, DOWN, or INIT) */

        audit_min_rx = bfd_data->sess[sess_idx].local.ofc.min_rx;
    }

    if (BFD_LOG_ENABLED)
    {
        IPM_ipaddr2p (&bfd_data->sess[sess_idx].local_ip,
            &local_ip_str[0], sizeof(local_ip_str));
        IPM_ipaddr2p (&bfd_data->sess[sess_idx].remote_ip,
            &remote_ip_str[0], sizeof(remote_ip_str));

        BFD_LOG (
            "BFD_fsm_report_state_change: "
            "local_ip %s, "
            "remote_ip %s, "
            "detect_time_mult %u\n"
            "min_tx %u\n"
            "min_rx %u\n",
            &local_ip_str[0],
            &remote_ip_str[0],
            bfd_data->sess[sess_idx].local.detect_time_mult,
            bfd_data->sess[sess_idx].local.cfg_min_tx,
            audit_min_rx);
    }

    if ((* bfd_audit_cb_func)(
        &bfd_data->sess[sess_idx].local_ip,
        &bfd_data->sess[sess_idx].remote_ip,
        bfd_data->sess[sess_idx].local.detect_time_mult,
        bfd_data->sess[sess_idx].local.cfg_min_tx,
        audit_min_rx) !=
        BFD_SUCCESS)
    {
        /* LCP does not have this BFD session */

        BFD_AUDIT_ERROR (sess_idx, "BFD session exists at BFD, but not "
            "at LCP, destroy it\n");
        bfd_data->stats.ext_audit++;

        /* automatically destroy BFD session */
        BFD_destroy_sess (&bfd_data->sess[sess_idx].local_ip,
            &bfd_data->sess[sess_idx].remote_ip);
    }
    else
    {
        /* ths BFD session was created recently */

        /* there might be a BFD_change_cfg() */

        /* mark this BFD session as audited */
        bfd_data->sess[sess_idx].audited = TRUE;
    }
}


/*
 * Name:        BFD_sess_int_audit
 *
 * Abstract:    function to internally audit BFD session
 *
 * Parameters:
 *     sess_idx - BFD sesion index
 *
 * Returns:     none
 */
void BFD_sess_int_audit (int sess_idx)
{
    BFD_RETVAL ret_val;
    uint32_t key_add;
    uint32_t key_xor;
    int other_sess_idx;

    struct msghdr *recv_msg_hdr;
    unsigned long recv_msg_hdr_checksum;

    struct sockaddr_in *remote_sock_addr_ipv4;
    struct sockaddr_in6 *remote_sock_addr_ipv6;

    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];

    char other_local_ip_str[IPM_IPMAXSTRSIZE];
    char other_remote_ip_str[IPM_IPMAXSTRSIZE];




    key_add = BFD_sess_data_calc_keys (&bfd_data->sess[sess_idx].local_ip,
        &bfd_data->sess[sess_idx].remote_ip, &key_xor);
    if ((key_add != bfd_data->sess[sess_idx].key_add) ||
        (key_xor != bfd_data->sess[sess_idx].key_xor))
    {
        IPM_ipaddr2p (&bfd_data->sess[sess_idx].local_ip,
            &local_ip_str[0], sizeof(local_ip_str));
        IPM_ipaddr2p (&bfd_data->sess[sess_idx].remote_ip,
            &remote_ip_str[0], sizeof(remote_ip_str));

        BFD_AUDIT_ERROR (sess_idx, "invalid key_add 0x%08x, key_xor 0x%08x, "
            "local_ip %s, or remote_ip %s, destroy this BFD session\n",
            key_add, key_xor, &local_ip_str[0], &remote_ip_str[0]);
        BFD_sess_destroy (sess_idx);
        bfd_data->stats.int_audit_major++;
        return;
    }

    ret_val = BFD_sess_data_chk_keys (sess_idx, key_add, key_xor,
        &other_sess_idx);
    if (ret_val != BFD_SUCCESS)
    {
        IPM_ipaddr2p (&bfd_data->sess[sess_idx].local_ip,
            &local_ip_str[0], sizeof(local_ip_str));
        IPM_ipaddr2p (&bfd_data->sess[sess_idx].remote_ip,
            &remote_ip_str[0], sizeof(remote_ip_str));

        IPM_ipaddr2p (&bfd_data->sess[other_sess_idx].local_ip,
            &other_local_ip_str[0], sizeof(other_local_ip_str));
        IPM_ipaddr2p (&bfd_data->sess[other_sess_idx].remote_ip,
            &other_remote_ip_str[0], sizeof(other_remote_ip_str));

        BFD_AUDIT_ERROR (sess_idx, "this BFD session with local IP %s and "
            "remote IP %s has the same key_add 0x%08x and key_xor 0x%08x "
            " as another BFD session with local IP %s and remote IP %s, "
            "destroy both BFD sessions\n",
            &local_ip_str[0], &remote_ip_str[0],
            key_add, key_xor,
            &other_local_ip_str[0], &other_remote_ip_str[0]);
        BFD_sess_destroy (sess_idx);
        BFD_sess_destroy (other_sess_idx);
        bfd_data->stats.int_audit_major++;
        return;
    }

    if ((bfd_data->sess[sess_idx].local_ip.addrtype != IPM_IPV4) &&
        (bfd_data->sess[sess_idx].local_ip.addrtype != IPM_IPV6))
    {       
        BFD_AUDIT_ERROR (sess_idx, "invalid local_ip address type %d; "
            "%d or %d expected; destroy this BFD session\n",
            bfd_data->sess[sess_idx].local_ip.addrtype,
            IPM_IPV4, IPM_IPV6);
        BFD_sess_destroy (sess_idx);
        bfd_data->stats.int_audit_major++;
        return;
    }

    if ((bfd_data->sess[sess_idx].remote_ip.addrtype != IPM_IPV4) &&
        (bfd_data->sess[sess_idx].remote_ip.addrtype != IPM_IPV6))
    {       
        BFD_AUDIT_ERROR (sess_idx, "invalid remote_ip address type %d; "
            "%d or %d expected; destroy this BFD session\n",
            bfd_data->sess[sess_idx].remote_ip.addrtype,
            IPM_IPV4, IPM_IPV6);
        BFD_sess_destroy (sess_idx);
        bfd_data->stats.int_audit_major++;
        return;
    }

    if (bfd_data->sess[sess_idx].local_ip.addrtype !=
        bfd_data->sess[sess_idx].remote_ip.addrtype)
    {
        BFD_AUDIT_ERROR (sess_idx, "local_ip address type %d != "
            "remote_ip address type %d; they must be the same; "
            "destroy this BFD session\n",
            bfd_data->sess[sess_idx].local_ip.addrtype,
            bfd_data->sess[sess_idx].remote_ip.addrtype);
        BFD_sess_destroy (sess_idx);
        bfd_data->stats.int_audit_major++;
        return;
    }




    if ((bfd_data->sess[sess_idx].local.cfg_min_tx < BFD_MIN_TX_MIN) ||
        (bfd_data->sess[sess_idx].local.cfg_min_tx > BFD_MIN_TX_MAX))
    {
        BFD_AUDIT_ERROR (sess_idx, "invalid 'local.cfg_min_tx' %u, "
            "set to %u\n", bfd_data->sess[sess_idx].local.cfg_min_tx,
            BFD_MIN_TX_DEF);
        bfd_data->sess[sess_idx].local.cfg_min_tx = BFD_MIN_TX_DEF;
        bfd_data->stats.int_audit_minor++;
    }       
    else if ((bfd_data->sess[sess_idx].local.cfg_min_tx % BFD_MIN_TX_UNIT)
        != 0)
    {
        BFD_AUDIT_ERROR (sess_idx, "invalid 'local.cfg_min_tx' %u, "
            "set to %u\n", bfd_data->sess[sess_idx].local.cfg_min_tx,
            ( bfd_data->sess[sess_idx].local.cfg_min_tx / BFD_MIN_TX_UNIT) *
            BFD_MIN_TX_UNIT);
        bfd_data->sess[sess_idx].local.cfg_min_tx =
            ( bfd_data->sess[sess_idx].local.cfg_min_tx / BFD_MIN_TX_UNIT) *
            BFD_MIN_TX_UNIT;
        bfd_data->stats.int_audit_minor++;
    }

    if (bfd_data->sess[sess_idx].active_passive != BFD_ROLE_ACTIVE)
    {
        BFD_AUDIT_ERROR (sess_idx, "invalid 'active_passive' %u, "
            "set to %u\n", bfd_data->sess[sess_idx].active_passive,
            BFD_ROLE_ACTIVE);
        bfd_data->sess[sess_idx].active_passive = BFD_ROLE_ACTIVE;
        bfd_data->stats.int_audit_minor++;
    }

    if ((bfd_data->sess[sess_idx].admin_state != BFD_ADMIN_STATE_DOWN) &&
        (bfd_data->sess[sess_idx].admin_state != BFD_ADMIN_STATE_UP))
    {   
        BFD_ADMIN_STATE admin_state;
        if (bfd_data->sess[sess_idx].local.sess_state ==
            BFD_SESS_STATE_ADMIN_DOWN)
        {
            admin_state = BFD_ADMIN_STATE_DOWN;
        }
        else
        {
            admin_state = BFD_ADMIN_STATE_UP;
        }

        BFD_AUDIT_ERROR (sess_idx, "invalid 'admin_state' %u, "
            "set to %u\n", bfd_data->sess[sess_idx].admin_state,
            admin_state);
        bfd_data->sess[sess_idx].admin_state = admin_state;
        bfd_data->stats.int_audit_minor++;
    }

    if ((bfd_data->sess[sess_idx].local_poll_seq != FALSE) &&
        (bfd_data->sess[sess_idx].local_poll_seq != TRUE))
    {   
        BFD_AUDIT_ERROR (sess_idx, "invalid 'local_poll_seq' %u, "
            "set to %u\n", bfd_data->sess[sess_idx].local_poll_seq, FALSE);
        bfd_data->sess[sess_idx].local_poll_seq = FALSE;
        bfd_data->stats.int_audit_minor++;
    }   

    if ((bfd_data->sess[sess_idx].has_recv_msg != FALSE) &&
        (bfd_data->sess[sess_idx].has_recv_msg != TRUE))
    {
        BFD_AUDIT_ERROR (sess_idx, "invalid 'has_recv_msg' %u, "
            "set to %u\n", bfd_data->sess[sess_idx].has_recv_msg, TRUE);
        bfd_data->sess[sess_idx].has_recv_msg = TRUE;
        bfd_data->stats.int_audit_minor++;
    }   




    if (((int) bfd_data->sess[sess_idx].local.diagnostic < BFD_DIAG_NONE) ||
        (bfd_data->sess[sess_idx].local.diagnostic > 
            BFD_DIAG_REVERSE_CONCAT_PATH_DOWN))
    {       
        BFD_AUDIT_ERROR (sess_idx, "invalid 'local.diagnostic' %u, "
            "clear it\n", bfd_data->sess[sess_idx].local.diagnostic);
        bfd_data->sess[sess_idx].local.diagnostic = BFD_DIAG_NONE;
        bfd_data->stats.int_audit_minor++;
    }   
        
    if (((int) bfd_data->sess[sess_idx].local.sess_state <
            BFD_SESS_STATE_ADMIN_DOWN) ||
        (bfd_data->sess[sess_idx].local.sess_state > BFD_SESS_STATE_UP))
    {   
        BFD_AUDIT_ERROR (sess_idx, "invalid 'local.sess_state' %u, "
            "set to %u\n", bfd_data->sess[sess_idx].local.sess_state,
            BFD_SESS_STATE_DOWN);
        bfd_data->sess[sess_idx].local.sess_state = BFD_SESS_STATE_DOWN;
        bfd_data->stats.int_audit_minor++;
    }   
        
    if ((bfd_data->sess[sess_idx].local.detect_time_mult <
            BFD_DETECT_TIME_MULT_MIN) ||
        (bfd_data->sess[sess_idx].local.detect_time_mult >
            BFD_DETECT_TIME_MULT_MAX))
    {       
        BFD_AUDIT_ERROR (sess_idx, "invalid 'local.mult_time_mult' %u, "
            "set to %u\n", bfd_data->sess[sess_idx].local.detect_time_mult,
            BFD_DETECT_TIME_MULT_DEF);
        bfd_data->sess[sess_idx].local.detect_time_mult =
            BFD_DETECT_TIME_MULT_DEF;
        bfd_data->stats.int_audit_minor++;
    }   
        
    /* no audit on 'local.discriminator' */
 
    if (bfd_data->sess[sess_idx].local_poll_seq == FALSE)
    {
        if ((bfd_data->sess[sess_idx].local.ofc.min_tx <
                BFD_MIN_TX_MIN) ||
            (bfd_data->sess[sess_idx].local.ofc.min_tx > BFD_MIN_TX_MAX))
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'local.ofc.min_tx' %u, "
                "set to %u\n", bfd_data->sess[sess_idx].local.ofc.min_tx,
                BFD_MIN_TX_DEF);
            bfd_data->sess[sess_idx].local.ofc.min_tx = BFD_MIN_TX_DEF;
            bfd_data->stats.int_audit_minor++;
        }   
        else if ((bfd_data->sess[sess_idx].local.ofc.min_tx % BFD_MIN_TX_UNIT)
            != 0)
        {
            BFD_AUDIT_ERROR (sess_idx, "invalid 'local.ofc.min_tx' %u, "
                "set to %u\n", bfd_data->sess[sess_idx].local.ofc.min_tx,
                ( bfd_data->sess[sess_idx].local.ofc.min_tx / BFD_MIN_TX_UNIT)
                * BFD_MIN_TX_UNIT);
            bfd_data->sess[sess_idx].local.ofc.min_tx =
                ( bfd_data->sess[sess_idx].local.ofc.min_tx / BFD_MIN_TX_UNIT)
                * BFD_MIN_TX_UNIT;
            bfd_data->stats.int_audit_minor++;
        }

        if ((bfd_data->sess[sess_idx].local.ofc.min_rx <
                BFD_MIN_RX_MIN) ||
            (bfd_data->sess[sess_idx].local.ofc.min_rx > BFD_MIN_RX_MAX))
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'local.ofc.min_rx' %u, "
                "set to %u\n", bfd_data->sess[sess_idx].local.ofc.min_rx,
                BFD_MIN_RX_DEF);
            bfd_data->sess[sess_idx].local.ofc.min_rx = BFD_MIN_RX_DEF;
            bfd_data->stats.int_audit_minor++;
        }
        else if ((bfd_data->sess[sess_idx].local.ofc.min_rx % BFD_MIN_RX_UNIT)
            != 0)
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'local.ofc.min_rx' %u, "
                "set to %u\n", bfd_data->sess[sess_idx].local.ofc.min_rx,
                ( bfd_data->sess[sess_idx].local.ofc.min_rx / BFD_MIN_RX_UNIT)
                * BFD_MIN_RX_UNIT);
            bfd_data->sess[sess_idx].local.ofc.min_rx =
                ( bfd_data->sess[sess_idx].local.ofc.min_rx / BFD_MIN_RX_UNIT)
                * BFD_MIN_RX_UNIT;
            bfd_data->stats.int_audit_minor++;
        }       

        if (bfd_data->sess[sess_idx].local.trans.min_tx != 0)
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'local.trans.min_tx' %u, "
                "clear it\n", bfd_data->sess[sess_idx].local.trans.min_tx);
            bfd_data->sess[sess_idx].local.trans.min_tx = 0;
            bfd_data->stats.int_audit_minor++;
        }   
        
        if (bfd_data->sess[sess_idx].local.trans.min_rx != 0)
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'local.trans.min_rx' %u, "
                "clear it\n", bfd_data->sess[sess_idx].local.trans.min_rx);
            bfd_data->sess[sess_idx].local.trans.min_rx = 0;
            bfd_data->stats.int_audit_minor++;
        }
    }   
    else
    {
        if ((bfd_data->sess[sess_idx].local.ofc.min_tx <
                BFD_MIN_TX_MIN) ||
            (bfd_data->sess[sess_idx].local.ofc.min_tx > BFD_MIN_TX_MAX))
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'local.ofc.min_tx' %u, "
                "set to %u\n", bfd_data->sess[sess_idx].local.ofc.min_tx,
                BFD_MIN_TX_DEF);
            bfd_data->sess[sess_idx].local.ofc.min_tx = BFD_MIN_TX_DEF;
            bfd_data->stats.int_audit_minor++;
        }   
        else if ((bfd_data->sess[sess_idx].local.ofc.min_tx % BFD_MIN_TX_UNIT)
            != 0)
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'local.ofc.min_tx' %u, "
                "set to %u\n", bfd_data->sess[sess_idx].local.ofc.min_tx,
                ( bfd_data->sess[sess_idx].local.ofc.min_tx / BFD_MIN_TX_UNIT)
                * BFD_MIN_TX_UNIT);
            bfd_data->sess[sess_idx].local.ofc.min_tx =
                ( bfd_data->sess[sess_idx].local.ofc.min_tx / BFD_MIN_TX_UNIT)
                * BFD_MIN_TX_UNIT;
            bfd_data->stats.int_audit_minor++;
        }   

        if (bfd_data->sess[sess_idx].local.sess_state != BFD_SESS_STATE_UP)
        {
            if (bfd_data->sess[sess_idx].local.ofc.min_tx !=
                BFD_SLOW_TRANSMISSION_TIMER)
            {   
                BFD_AUDIT_ERROR (sess_idx, "invalid 'local.ofc.min_tx' "  
                    "%u, set to slow transmission timer\n",
                    bfd_data->sess[sess_idx].local.ofc.min_tx);  
                bfd_data->sess[sess_idx].local.ofc.min_tx =  
                    BFD_SLOW_TRANSMISSION_TIMER;
                bfd_data->stats.int_audit_minor++;
            }   
        }   

        if ((bfd_data->sess[sess_idx].local.ofc.min_rx <
                BFD_MIN_RX_MIN) ||
            (bfd_data->sess[sess_idx].local.ofc.min_rx > BFD_MIN_RX_MAX))
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'local.ofc.min_rx' %u, "
                "set to %u\n", bfd_data->sess[sess_idx].local.ofc.min_rx,
                BFD_MIN_RX_DEF);
            bfd_data->sess[sess_idx].local.ofc.min_rx = BFD_MIN_RX_DEF;
            bfd_data->stats.int_audit_minor++;
        }   
        else if ((bfd_data->sess[sess_idx].local.ofc.min_rx % BFD_MIN_RX_UNIT)
            != 0)
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'local.ofc.min_rx' %u, "
                "set to %u\n", bfd_data->sess[sess_idx].local.ofc.min_rx,
                ( bfd_data->sess[sess_idx].local.ofc.min_rx / BFD_MIN_RX_UNIT)
                * BFD_MIN_RX_UNIT);
            bfd_data->sess[sess_idx].local.ofc.min_rx = 
                ( bfd_data->sess[sess_idx].local.ofc.min_rx / BFD_MIN_RX_UNIT)
                * BFD_MIN_RX_UNIT;
            bfd_data->stats.int_audit_minor++;
        }

        if ((bfd_data->sess[sess_idx].local.trans.min_tx <
                BFD_MIN_TX_MIN) ||
            (bfd_data->sess[sess_idx].local.trans.min_tx > BFD_MIN_TX_MAX))
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'local.trans.min_tx' %u, "
                "set to %u\n", bfd_data->sess[sess_idx].local.trans.min_tx,
                BFD_MIN_TX_DEF);
            bfd_data->sess[sess_idx].local.trans.min_tx = BFD_MIN_TX_DEF;
            bfd_data->stats.int_audit_minor++;
        }   
        else if ((bfd_data->sess[sess_idx].local.trans.min_tx %
            BFD_MIN_TX_UNIT) != 0)
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'local.trans.min_tx' %u, "
                "set to %u\n", bfd_data->sess[sess_idx].local.trans.min_tx,
                bfd_data->sess[sess_idx].local.trans.min_tx / BFD_MIN_TX_UNIT *
                BFD_MIN_TX_UNIT);
            bfd_data->sess[sess_idx].local.trans.min_tx =
                ( bfd_data->sess[sess_idx].local.trans.min_tx /
                BFD_MIN_TX_UNIT) * BFD_MIN_TX_UNIT;
            bfd_data->stats.int_audit_minor++;
        }   
            
        if ((bfd_data->sess[sess_idx].local.trans.min_rx <
                BFD_MIN_RX_MIN) ||
            (bfd_data->sess[sess_idx].local.trans.min_rx > BFD_MIN_RX_MAX))
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'local.trans.min_rx' %u, "
                "set to %u\n", bfd_data->sess[sess_idx].local.trans.min_rx,
                BFD_MIN_RX_DEF);
            bfd_data->sess[sess_idx].local.trans.min_rx = BFD_MIN_RX_DEF;
            bfd_data->stats.int_audit_minor++;
        }   
        else if ((bfd_data->sess[sess_idx].local.trans.min_rx %
            BFD_MIN_RX_UNIT) != 0)
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'local.trans.min_rx' %u, "
                "set to %u\n", bfd_data->sess[sess_idx].local.trans.min_rx,
                ( bfd_data->sess[sess_idx].local.trans.min_rx /
                BFD_MIN_RX_UNIT) * BFD_MIN_RX_UNIT);
            bfd_data->sess[sess_idx].local.trans.min_rx = 
                ( bfd_data->sess[sess_idx].local.trans.min_rx /
                BFD_MIN_RX_UNIT) * BFD_MIN_RX_UNIT;
            bfd_data->stats.int_audit_minor++;
        }
    }




    if (((int) bfd_data->sess[sess_idx].remote.diagnostic < BFD_DIAG_NONE) ||
        (bfd_data->sess[sess_idx].remote.diagnostic >
            BFD_DIAG_REVERSE_CONCAT_PATH_DOWN))
    {
        BFD_AUDIT_ERROR (sess_idx, "invalid 'remote.diagnostic' %u, "
            "clear it\n", bfd_data->sess[sess_idx].remote.diagnostic);
        bfd_data->sess[sess_idx].remote.diagnostic = BFD_DIAG_NONE;
        bfd_data->stats.int_audit_minor++;
    }

    if (((int) bfd_data->sess[sess_idx].remote.sess_state <
            BFD_SESS_STATE_ADMIN_DOWN) ||
        (bfd_data->sess[sess_idx].remote.sess_state > BFD_SESS_STATE_UP))
    {
        BFD_AUDIT_ERROR (sess_idx, "invalid 'remote.sess_state' %u, "
            "set to %u\n", bfd_data->sess[sess_idx].remote.sess_state,
            BFD_SESS_STATE_DOWN);
        bfd_data->sess[sess_idx].remote.sess_state = BFD_SESS_STATE_DOWN;
        bfd_data->stats.int_audit_minor++;
    }

    /* no audit on 'remote.detect_time_mult' */

    /* no audit on 'remote.discriminator' */

    if( bfd_data->sess[sess_idx].remote.discriminator != 0)
    {
        /* has received one remote BFD message */

        if ((bfd_data->sess[sess_idx].remote.min_tx < BFD_MIN_TX_MIN) ||
            (bfd_data->sess[sess_idx].remote.min_tx > BFD_MIN_TX_MAX))
        {       
            BFD_AUDIT_ERROR (sess_idx, "invalid 'remote.min_tx' %u, "
                "set to %u\n", bfd_data->sess[sess_idx].remote.min_tx,
                BFD_MIN_TX_DEF);
            bfd_data->sess[sess_idx].remote.min_tx = BFD_MIN_TX_DEF;
            bfd_data->stats.int_audit_minor++;
        }
        else if ((bfd_data->sess[sess_idx].remote.min_tx % BFD_MIN_TX_UNIT)
            != 0)
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'remote.min_tx' %u, "
                "set to %u\n", bfd_data->sess[sess_idx].remote.min_tx,
                ( bfd_data->sess[sess_idx].remote.min_tx / BFD_MIN_TX_UNIT) *
                BFD_MIN_TX_UNIT);
            bfd_data->sess[sess_idx].remote.min_tx =
                bfd_data->sess[sess_idx].remote.min_tx / BFD_MIN_TX_UNIT *
                BFD_MIN_TX_UNIT;
            bfd_data->stats.int_audit_minor++;
        }   

        if ((bfd_data->sess[sess_idx].remote.min_rx < BFD_MIN_RX_MIN) ||
            (bfd_data->sess[sess_idx].remote.min_rx > BFD_MIN_RX_MAX))
        {       
            BFD_AUDIT_ERROR (sess_idx, "invalid 'remote.min_rx' %u, "
                "set to %u\n", bfd_data->sess[sess_idx].remote.min_rx,
                BFD_MIN_RX_DEF);
            bfd_data->sess[sess_idx].remote.min_rx = BFD_MIN_RX_DEF;
            bfd_data->stats.int_audit_minor++;
        }   
        else if ((bfd_data->sess[sess_idx].remote.min_rx % BFD_MIN_TX_UNIT)
            != 0)
        {
            BFD_AUDIT_ERROR (sess_idx, "invalid 'remote.min_rx' %u, "
                "set to %u\n", bfd_data->sess[sess_idx].remote.min_rx,
                ( bfd_data->sess[sess_idx].remote.min_rx / BFD_MIN_TX_UNIT) *
                BFD_MIN_TX_UNIT);
            bfd_data->sess[sess_idx].remote.min_rx =
                ( bfd_data->sess[sess_idx].remote.min_rx / BFD_MIN_TX_UNIT) *
                BFD_MIN_TX_UNIT;
            bfd_data->stats.int_audit_minor++;
        }
    }




#ifdef BFD_LISTEN_TIMER_ENABLED

    if (bfd_data->sess[sess_idx].listen_timer != 0)
    {
        if (bfd_data->sess[sess_idx].transmission_timer != 0)
        {
            BFD_AUDIT_ERROR (sess_idx, "both listening and transmission "
                "timers are on, stop listening timer\n");
            BFD_timer_stop_listen_timer (sess_idx);
            bfd_data->stats.int_audit_minor++;
        }
        else if ((bfd_data->sess[sess_idx].listen_timer < BFD_TIMER_MIN) ||
            (bfd_data->sess[sess_idx].listen_timer > BFD_TIMER_MAX))
        {
            BFD_AUDIT_ERROR (sess_idx, "invalid 'listen_timer' "
                "%u, stop listening timer\n",
                bfd_data->sess[sess_idx].listen_timer);
            BFD_timer_stop_listen_timer (sess_idx);
            if (bfd_data->sess[sess_idx].transmission_timer == 0)
            {
                BFD_timer_start_transmission_timer (sess_idx);
            }
            bfd_data->stats.int_audit_minor++;
        }
    }
    else
    {
        if (bfd_data->sess[sess_idx].transmission_timer == 0)
        {
            BFD_AUDIT_ERROR (sess_idx, "both listening and transmission "
                "timers are off, start transmission timer\n");
            BFD_timer_start_transmission_timer (sess_idx);
            bfd_data->stats.int_audit_minor++;
        }
    }

    if (bfd_data->sess[sess_idx].listen_timer_countdown >
        bfd_data->sess[sess_idx].listen_timer)
    {
        BFD_AUDIT_ERROR (sess_idx, "invalid 'listen_timer_countdown' "
            "%u, set to %u\n", 
            bfd_data->sess[sess_idx].listen_timer_countdown,
            bfd_data->sess[sess_idx].listen_timer);
        bfd_data->sess[sess_idx].listen_timer_countdown =
            bfd_data->sess[sess_idx].listen_timer;
        bfd_data->stats.int_audit_minor++;
    }

#else /* #ifdef BFD_LISTEN_TIMER_ENABLED */

    if (bfd_data->sess[sess_idx].transmission_timer == 0)
    {
        BFD_AUDIT_ERROR (sess_idx, "transmission timer is off, "
            "start transmission timer\n");
        BFD_timer_start_transmission_timer (sess_idx);
        bfd_data->stats.int_audit_minor++;
    }

#endif /* #ifdef BFD_LISTEN_TIMER_ENABLED */

    if (bfd_data->sess[sess_idx].transmission_timer != 0)
    {
        if ((bfd_data->sess[sess_idx].transmission_timer < BFD_TIMER_MIN) ||
            (bfd_data->sess[sess_idx].transmission_timer > BFD_TIMER_MAX))
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'transmission_timer' "
                "%u, re-start transmission timer\n",
                bfd_data->sess[sess_idx].transmission_timer);
            BFD_timer_start_transmission_timer (sess_idx);
            bfd_data->stats.int_audit_minor++;
        }
    }

    if (bfd_data->sess[sess_idx].transmission_timer_countdown >
        bfd_data->sess[sess_idx].transmission_timer)
    {        
        BFD_AUDIT_ERROR (sess_idx, "invalid 'transmission_timer_countdown' "
            "%u, set to %u\n",
            bfd_data->sess[sess_idx].transmission_timer_countdown,
            bfd_data->sess[sess_idx].transmission_timer);
        bfd_data->sess[sess_idx].transmission_timer_countdown =
            bfd_data->sess[sess_idx].transmission_timer;
        bfd_data->stats.int_audit_minor++;
    }   

    if ((bfd_data->sess[sess_idx].local.sess_state == BFD_SESS_STATE_INIT) ||
        (bfd_data->sess[sess_idx].local.sess_state == BFD_SESS_STATE_UP))
    {
        if (bfd_data->sess[sess_idx].fault_detect_timer == 0)
        {
            BFD_AUDIT_ERROR (sess_idx, "fault detection timer is off in "
                "INIT or UP session state, start fault_detection timer\n");
            BFD_timer_start_fault_detect_timer (sess_idx);
            bfd_data->stats.int_audit_minor++;
        }
    }
    else
    {
        if (bfd_data->sess[sess_idx].fault_detect_timer != 0)
        {
            BFD_AUDIT_ERROR (sess_idx, "fault detection timer is on in "
                "ADMIN_DOWN or DOWN session state, stop fault_detection "
                "timer\n");
            BFD_timer_stop_fault_detect_timer (sess_idx);
            bfd_data->stats.int_audit_minor++;
        }
    }

    if (bfd_data->sess[sess_idx].fault_detect_timer != 0)
    {
        if ((bfd_data->sess[sess_idx].fault_detect_timer < BFD_TIMER_MIN) ||
            (bfd_data->sess[sess_idx].fault_detect_timer > BFD_TIMER_MAX))  
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'fault_detect_timer' "
                "%u, restart fault detection timer\n",
                bfd_data->sess[sess_idx].fault_detect_timer);
            BFD_timer_start_fault_detect_timer (sess_idx);
            bfd_data->stats.int_audit_minor++;
        }   

        if (bfd_data->sess[sess_idx].fault_detect_timer_fire_num >=
            bfd_data->sess[sess_idx].remote.detect_time_mult)
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid "
                "'fault_detect_timer_fire_num' %u, clear it\n",
            bfd_data->sess[sess_idx].fault_detect_timer_fire_num);
            bfd_data->sess[sess_idx].fault_detect_timer_fire_num = 0;
            bfd_data->stats.int_audit_minor++;
        }   
    }
    else
    {
        if (bfd_data->sess[sess_idx].fault_detect_timer_fire_num != 0)
        {
            BFD_AUDIT_ERROR (sess_idx, "invalid "
                "'fault_detect_timer_fire_num' %u, clear it\n",  
                bfd_data->sess[sess_idx].fault_detect_timer_fire_num);
            bfd_data->sess[sess_idx].fault_detect_timer_fire_num = 0;
            bfd_data->stats.int_audit_minor++;
        }   
    }

    if (bfd_data->sess[sess_idx].fault_detect_timer_countdown >
        bfd_data->sess[sess_idx].fault_detect_timer)
    {   
        BFD_AUDIT_ERROR (sess_idx, "invalid 'fault_detect_timer_countdown' "
            "%u, set to %u\n",
            bfd_data->sess[sess_idx].fault_detect_timer_countdown,
            bfd_data->sess[sess_idx].fault_detect_timer);
        bfd_data->sess[sess_idx].fault_detect_timer_countdown =
            bfd_data->sess[sess_idx].fault_detect_timer;
        bfd_data->stats.int_audit_minor++;
    }   





    if ((bfd_data->sess[sess_idx].recv_sock < BFD_SOCK_MIN) ||
        (bfd_data->sess[sess_idx].recv_sock > BFD_SOCK_MAX))
    {       
        BFD_AUDIT_ERROR (sess_idx, "invalid 'recv_sock' %u, "
            "close and re-create the socket\n",
            bfd_data->sess[sess_idx].recv_sock);
        (void) close (bfd_data->sess[sess_idx].recv_sock);
        BFD_trans_create_recv_sock (sess_idx);
        bfd_data->stats.int_audit_minor++;
    }
 
    if (BFD_sess_check_sock (sess_idx, bfd_data->sess[sess_idx].recv_sock)
        != BFD_SUCCESS)
    {
        BFD_AUDIT_ERROR (sess_idx, "two or more sockets with the same "
            "file descriptor, close and re-create the sockets\n");
        (void) close (bfd_data->sess[sess_idx].recv_sock);
        BFD_trans_create_recv_sock (sess_idx);
        bfd_data->stats.int_audit_minor++;
    }

    /* no audit on 'recv_msg' */

    if (bfd_data->sess[sess_idx].recv_msg_iov[0].iov_base !=
        &bfd_data->sess[sess_idx].recv_msg)
    {
        BFD_AUDIT_ERROR (sess_idx, "invalid 'recv_msg_iov.iov_base' %p, "
            "set to %p\n",
            bfd_data->sess[sess_idx].recv_msg_iov[0].iov_base,
            &bfd_data->sess[sess_idx].recv_msg);
        bfd_data->sess[sess_idx].recv_msg_iov[0].iov_base =
            &bfd_data->sess[sess_idx].recv_msg;
        bfd_data->stats.int_audit_minor++; 
    }

    if (bfd_data->sess[sess_idx].recv_msg_iov[0].iov_len != BFD_MAX_MSG_SIZE)
    {
        BFD_AUDIT_ERROR (sess_idx, "invalid 'recv_msg_iov.iov_len' "
            "%u, set to %u\n",
            bfd_data->sess[sess_idx].recv_msg_iov[0].iov_len,
            BFD_MAX_MSG_SIZE);
        bfd_data->sess[sess_idx].recv_msg_iov[0].iov_len = BFD_MAX_MSG_SIZE;
        bfd_data->stats.int_audit_minor++;
    }

    recv_msg_hdr = &bfd_data->sess[sess_idx].recv_msg_hdr;

    if (recv_msg_hdr->msg_iov != bfd_data->sess[sess_idx].recv_msg_iov)
    {
        BFD_AUDIT_ERROR (sess_idx, "invalid 'recv_msg_hdr.msg_iov' %p, "
            "set to %p\n", recv_msg_hdr->msg_iov,
            bfd_data->sess[sess_idx].recv_msg_iov);
        recv_msg_hdr->msg_iov = bfd_data->sess[sess_idx].recv_msg_iov;
        bfd_data->stats.int_audit_minor++;
    }

    if (recv_msg_hdr->msg_iovlen != 1)
    {
        BFD_AUDIT_ERROR (sess_idx, "invalid 'recv_msg_hdr.msg_iovlen' " 
            "%u, set to 1\n", recv_msg_hdr->msg_iovlen);
        recv_msg_hdr->msg_iovlen = 1;
        bfd_data->stats.int_audit_minor++;
    }

    if (recv_msg_hdr->msg_control != bfd_data->sess[sess_idx].recv_ttl_buffer)
    {
        BFD_AUDIT_ERROR (sess_idx, "invalid 'recv_msg_hdr.msg_control' %p, "
            "set to %p\n", recv_msg_hdr->msg_control,
            bfd_data->sess[sess_idx].recv_ttl_buffer);
        recv_msg_hdr->msg_control = bfd_data->sess[sess_idx].recv_ttl_buffer;
        bfd_data->stats.int_audit_minor++;
    }

    if (recv_msg_hdr->msg_controllen !=
        sizeof(bfd_data->sess[0].recv_ttl_buffer))
    {
        BFD_AUDIT_ERROR (sess_idx, "invalid 'recv_msg_hdr.msg_controllen' "
            "%u, set to %u\n", recv_msg_hdr->msg_controllen,
            sizeof(bfd_data->sess[0].recv_ttl_buffer));
        recv_msg_hdr->msg_controllen =
            sizeof(bfd_data->sess[0].recv_ttl_buffer);
        bfd_data->stats.int_audit_minor++;
    }

    if (bfd_data->sess[sess_idx].remote_ip.addrtype == IPM_IPV4)
    {
        if (recv_msg_hdr->msg_name !=
            &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv4)
        {
            BFD_AUDIT_ERROR (sess_idx, "invalid 'recv_msg_hdr.msg_name' %p, "
                "set to %p\n", recv_msg_hdr->msg_name,
                &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv4);
            recv_msg_hdr->msg_name =
                &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv4;
            bfd_data->stats.int_audit_minor++;
        }

        if (recv_msg_hdr->msg_namelen != sizeof(struct sockaddr_in))
        {
            BFD_AUDIT_ERROR (sess_idx, "invalid 'recv_msg_hdr.msg_namelen' "
                "%u, set to %u\n", recv_msg_hdr->msg_namelen,
                sizeof(struct sockaddr_in));
            recv_msg_hdr->msg_namelen = sizeof(struct sockaddr_in);
            bfd_data->stats.int_audit_minor++;
        }

        if (bfd_data->sess[sess_idx].recv_port !=
            &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv4.sin_port)
        {
            BFD_AUDIT_ERROR (sess_idx, "invalid 'recv_port' "
                "%p, set to %p\n", bfd_data->sess[sess_idx].recv_port,
                &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv4.sin_port);
            bfd_data->sess[sess_idx].recv_port =
                &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv4.sin_port;
            bfd_data->stats.int_audit_minor++;
        }
    }
    else
    {
        if (recv_msg_hdr->msg_name !=
            &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv6)
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'recv_msg_hdr.msg_name' %p, "
                "set to %p\n", recv_msg_hdr->msg_name,  
                &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv6);
            recv_msg_hdr->msg_name =
                &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv6;
            bfd_data->stats.int_audit_minor++;
        }
     
        if (recv_msg_hdr->msg_namelen != sizeof(struct sockaddr_in6))
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'recv_msg_hdr.msg_namelen' "
                "%u, set to %u\n", recv_msg_hdr->msg_namelen,  
                sizeof(struct sockaddr_in6));
            recv_msg_hdr->msg_namelen = sizeof(struct sockaddr_in6); 
            bfd_data->stats.int_audit_minor++;
        }   
         
        if (bfd_data->sess[sess_idx].recv_port != 
            &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv6.sin6_port)
        {
            BFD_AUDIT_ERROR (sess_idx, "invalid 'recv_port' "  
                "%p, set to %p\n", bfd_data->sess[sess_idx].recv_port,
                &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv6.sin6_port);
            bfd_data->sess[sess_idx].recv_port = 
                &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv6.sin6_port;
            bfd_data->stats.int_audit_minor++;
        }   
    }

    if (recv_msg_hdr->msg_flags != 0)
    {
        BFD_AUDIT_ERROR (sess_idx, "invalid 'recv_msg_hdr.msg_flags' "
            "%u, clear it\n",
            recv_msg_hdr->msg_flags);
        recv_msg_hdr->msg_flags = 0;
        bfd_data->stats.int_audit_minor++;
    }

    recv_msg_hdr_checksum =
        (unsigned long) bfd_data->sess[sess_idx].recv_msg_iov[0].iov_base ^
        (unsigned long) bfd_data->sess[sess_idx].recv_msg_hdr.msg_iov ^
        (unsigned long) bfd_data->sess[sess_idx].recv_msg_hdr.msg_control ^
        (unsigned long) bfd_data->sess[sess_idx].recv_msg_hdr.msg_name ^
        (unsigned long) bfd_data->sess[sess_idx].recv_port ^
        BFD_CHECKSUM_SEED;

    if (recv_msg_hdr_checksum !=
        bfd_data->sess[sess_idx].recv_msg_hdr_checksum)
    {   
        bfd_data->sess[sess_idx].recv_msg_hdr_checksum =
            (unsigned long) bfd_data->sess[sess_idx].recv_msg_iov[0].iov_base ^
            (unsigned long) bfd_data->sess[sess_idx].recv_msg_hdr.msg_iov ^
            (unsigned long) bfd_data->sess[sess_idx].recv_msg_hdr.msg_control ^
            BFD_CHECKSUM_SEED;
            
        BFD_AUDIT_ERROR (sess_idx, "invalid 'recv_msg_hdr_checksum', "
            "set to %lu\n", bfd_data->sess[sess_idx].recv_msg_hdr_checksum);
        bfd_data->stats.int_audit_minor++;
    }       




    if (bfd_data->sess[sess_idx].local_send_port != (unsigned short)
        (BFD_SEND_CTL_PORT_BASE + sess_idx))
    {
        BFD_AUDIT_ERROR (sess_idx, "invalid 'local_send_sock' "
            "%u, set to %u\n", bfd_data->sess[sess_idx].local_send_port,
            BFD_SEND_CTL_PORT_BASE + sess_idx);
        bfd_data->sess[sess_idx].local_send_port = (unsigned short)
            (BFD_SEND_CTL_PORT_BASE + sess_idx);
        bfd_data->stats.int_audit_minor++;
    }

    if ((bfd_data->sess[sess_idx].send_sock < BFD_SOCK_MIN) ||
        (bfd_data->sess[sess_idx].send_sock > BFD_SOCK_MAX))
    {
        BFD_AUDIT_ERROR (sess_idx, "invalid 'send_sock' %u, "   
            "close and re-create the socket\n",
            bfd_data->sess[sess_idx].send_sock);
        (void) close (bfd_data->sess[sess_idx].send_sock);
        BFD_trans_create_send_sock (sess_idx);
        bfd_data->stats.int_audit_minor++;
    }

    if (BFD_sess_check_sock (sess_idx, bfd_data->sess[sess_idx].send_sock)
        != BFD_SUCCESS)
    {
        BFD_AUDIT_ERROR (sess_idx, "two or more sockets with the same "
            "file descriptor, close and re-create the sockets\n");
        (void) close (bfd_data->sess[sess_idx].send_sock);
        BFD_trans_create_send_sock (sess_idx);
        bfd_data->stats.int_audit_minor++;
    }

    /* no audit on 'send_msg' */

    if (bfd_data->sess[sess_idx].remote_ip.addrtype == IPM_IPV4)
    {
        remote_sock_addr_ipv4 = (struct sockaddr_in *)
            &bfd_data->sess[sess_idx].send_remote_sock_addr_ipv4;

        if (remote_sock_addr_ipv4->sin_family != AF_INET)
        {
            BFD_AUDIT_ERROR (sess_idx, "invalid 'remote_sock_addr.family' "
                "%u, set to %u\n",
                remote_sock_addr_ipv4->sin_family, AF_INET);
            remote_sock_addr_ipv4->sin_family = AF_INET;
            bfd_data->stats.int_audit_minor++;
        }

        /* sin_port is in network byte-order */
        if (remote_sock_addr_ipv4->sin_port != htons (BFD_RECV_CTL_PORT))
        {
            BFD_AUDIT_ERROR (sess_idx, "invalid 'remote_sock_addr.port' %u, "
                "set to %u\n", remote_sock_addr_ipv4->sin_port,
                BFD_RECV_CTL_PORT);
            remote_sock_addr_ipv4->sin_port = htons (BFD_RECV_CTL_PORT);
            bfd_data->stats.int_audit_minor++;
        }

        /* sin_addr.s_addr and remote_ip.ipaddr[0] are in network byte-order */
        if (remote_sock_addr_ipv4->sin_addr.s_addr !=
            bfd_data->sess[sess_idx].remote_ip.ipaddr[0])
        {
            BFD_AUDIT_ERROR (sess_idx, "invalid 'remote_sock_addr.ip', "
                "set to 0x%08x\n",
                bfd_data->sess[sess_idx].remote_ip.ipaddr[0]);
            remote_sock_addr_ipv4->sin_addr.s_addr =
                bfd_data->sess[sess_idx].remote_ip.ipaddr[0];
            bfd_data->stats.int_audit_minor++;
        }

        if (bfd_data->sess[sess_idx].send_remote_sock_addr_len !=
            sizeof(*remote_sock_addr_ipv4))
        {
            BFD_AUDIT_ERROR (sess_idx, "invalid 'remote_sock_addr_len' %u, "
                "set to %u\n",
                bfd_data->sess[sess_idx].send_remote_sock_addr_len,
                sizeof(*remote_sock_addr_ipv4));
            bfd_data->sess[sess_idx].send_remote_sock_addr_len =
                sizeof(*remote_sock_addr_ipv4);
            bfd_data->stats.int_audit_minor++;
        }

        if (bfd_data->sess[sess_idx].send_remote_sock_addr !=
            (struct sockaddr *) remote_sock_addr_ipv4)
        {
            BFD_AUDIT_ERROR (sess_idx, "invalid 'remote_sock_addr' %p, "
                "set to %p\n",
                bfd_data->sess[sess_idx].send_remote_sock_addr,
                remote_sock_addr_ipv4);
            bfd_data->sess[sess_idx].send_remote_sock_addr =
                (struct sockaddr *) remote_sock_addr_ipv4;
            bfd_data->stats.int_audit_minor++;
        }   
    }
    else
    {
        remote_sock_addr_ipv6 = (struct sockaddr_in6 *)
            &bfd_data->sess[sess_idx].send_remote_sock_addr_ipv6;

        if (remote_sock_addr_ipv6->sin6_family != AF_INET6)
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'remote_sock_addr.family' "
                "%u, set to %u\n",
                remote_sock_addr_ipv6->sin6_family, AF_INET6);
            remote_sock_addr_ipv6->sin6_family = AF_INET6;
            bfd_data->stats.int_audit_minor++;
        }       
 
        /* sin6_port is in network byte-order */
        if (remote_sock_addr_ipv6->sin6_port != htons (BFD_RECV_CTL_PORT))
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'remote_sock_addr.port' %u, "
                "set to %u\n", remote_sock_addr_ipv6->sin6_port,
                BFD_RECV_CTL_PORT);
            remote_sock_addr_ipv6->sin6_port = htons (BFD_RECV_CTL_PORT);
            bfd_data->stats.int_audit_minor++;
        }   

        if (remote_sock_addr_ipv6->sin6_flowinfo != 0)
        {
            BFD_AUDIT_ERROR (sess_idx, "invalid 'remote_sock_addr.flowinfo' "
                "%u, clear it\n", remote_sock_addr_ipv6->sin6_flowinfo);
            remote_sock_addr_ipv6->sin6_flowinfo = 0;
            bfd_data->stats.int_audit_minor++;
        }

        /*
         * sin6_addr.s6_addr and remote_ip.ipaddr[*] are in network
         * byte-order
         */
        if (memcmp (remote_sock_addr_ipv6->sin6_addr.s6_addr,
            bfd_data->sess[sess_idx].remote_ip.ipaddr,
            sizeof(bfd_data->sess[sess_idx].remote_ip.ipaddr)) != 0)
        {
            BFD_AUDIT_ERROR (sess_idx, "invalid 'remote_sock_addr.ip', "
                "set to 0x%08x%08x%08x%08x\n",
                bfd_data->sess[sess_idx].remote_ip.ipaddr[0],
                bfd_data->sess[sess_idx].remote_ip.ipaddr[1],
                bfd_data->sess[sess_idx].remote_ip.ipaddr[2],
                bfd_data->sess[sess_idx].remote_ip.ipaddr[3]);
            memcpy (remote_sock_addr_ipv6->sin6_addr.s6_addr,
                bfd_data->sess[sess_idx].remote_ip.ipaddr,
                sizeof(bfd_data->sess[sess_idx].remote_ip.ipaddr));
            bfd_data->stats.int_audit_minor++;
        }

        bfd_data->sess[sess_idx].send_remote_sock_addr =
            (struct sockaddr *) remote_sock_addr_ipv6;

        if (bfd_data->sess[sess_idx].send_remote_sock_addr_len !=
            sizeof(*remote_sock_addr_ipv6))
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'remote_sock_addr_len' %u, "
                "set to %u\n",
                bfd_data->sess[sess_idx].send_remote_sock_addr_len,
                sizeof(*remote_sock_addr_ipv6));
            bfd_data->sess[sess_idx].send_remote_sock_addr_len = 
                sizeof(*remote_sock_addr_ipv6);
            bfd_data->stats.int_audit_minor++;
        }

        if (bfd_data->sess[sess_idx].send_remote_sock_addr !=
            (struct sockaddr *) remote_sock_addr_ipv6)
        {   
            BFD_AUDIT_ERROR (sess_idx, "invalid 'remote_sock_addr' %p, "
                "set to %p\n",
                bfd_data->sess[sess_idx].send_remote_sock_addr,
                remote_sock_addr_ipv6);
            bfd_data->sess[sess_idx].send_remote_sock_addr =
                (struct sockaddr *) remote_sock_addr_ipv6;
            bfd_data->stats.int_audit_minor++; 
        }
    }

    if (((unsigned long) bfd_data->sess[sess_idx].send_remote_sock_addr ^
        (unsigned long) BFD_CHECKSUM_SEED) !=
        bfd_data->sess[sess_idx].send_remote_sock_addr_checksum)
    {
        bfd_data->sess[sess_idx].send_remote_sock_addr_checksum =
            (unsigned long) bfd_data->sess[sess_idx].send_remote_sock_addr ^
            (unsigned long) BFD_CHECKSUM_SEED;

        BFD_AUDIT_ERROR (sess_idx, "invalid 'remote_sock_addr_checksum', "
            "set to 0x%lx\n",
            bfd_data->sess[sess_idx].send_remote_sock_addr_checksum);
        bfd_data->stats.int_audit_minor++; 
    }




    /* no audit on 'recv_count' and 'send_count' */

    if ((bfd_data->sess[sess_idx].audited != FALSE) &&
        (bfd_data->sess[sess_idx].audited != TRUE))
    {
        BFD_AUDIT_ERROR (sess_idx, "invalid 'auditted' %u, set to 0\n",
            bfd_data->sess[sess_idx].audited);
        bfd_data->sess[sess_idx].audited = FALSE;
        bfd_data->stats.int_audit_minor++;
    }



    /* no aduit on 'mised_hb' */
}

