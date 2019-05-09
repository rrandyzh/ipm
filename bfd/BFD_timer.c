/*************************************************************************
 *
 * File:     BFD_timer.c
 *
 * Abstract: implementation file of BFD timer module
 *           this module handles BFD timers
 *
 * Data:     none
 *
 * Functions:
 *     BFD_timer_start_listen_timer         - function to start
 *                                            listening timer
 *     BFD_timer_stop_listen_timer          - function to stopt
 *                                            listening timer
 *     BFD_timer_fire_listen_timer          - function to call when
 *                                            listening timer fires
 *
 *
 *     BFD_timer_start_transmission_timer   - function to start
 *                                            transmission timer
 *     BFD_timer_restart_transmission_timer - function to retstart
 *                                            transmission timer
 *     BFD_timer_stop_transmission_timer    - function to stop
 *                                            transmission timer
 *     BFD_timer_fire_transmission_timer    - function to call when
 *                                            transmission timer fires
 *
 *
 *     BFD_timer_start_fault_detect_timer   - function to start
 *                                            fault detection timer
 *     BFD_timer_restart_fault_detect_timer - function to retstart
 *                                            fault detection timer
 *     BFD_timer_stop_fault_detect_timer    - function to stop
 *                                            fault detection timer
 *     BFD_timer_fire_fault_detect_timer    - function to call when
 *                                            transmission timer fires
 *
 ************************************************************************/

#include "BFD_int_hdr.h"



#ifdef BFD_LISTEN_TIMER_ENABLED

/*
 * Name:        BFD_timer_start_listen_timer
 *
 * Abstract:    function to start listening timer
 *
 * Parameters:
 *     float_sess_idx - floating-IP BFD session index
 *
 *     fixed_sess_idx - fixed-IP BFD session index;
 *                      fixed_sess_idx might be invalid, i.e. no fixed-IP
 *                      BFD session
 *
 * Retunrs:     none
 */
void BFD_timer_start_listen_timer (int float_sess_idx, int fixed_sess_idx)
{
    int new_listen_timer;

    if (fixed_sess_idx == BFD_INV_SESS_IDX)
    {
        /*
         * no fixed-IP BFD session;
         * use default: 100 ms * 3 = 900 ms
         */
        new_listen_timer = BFD_MIN_TX_DEF * BFD_DETECT_TIME_MULT_DEF;
    }
    else
    {
        /*
         * listening timer is fixed-IP BFD session's
         * fault detection timer * remote detection time multiplier
         */
        new_listen_timer =
           bfd_data->sess[fixed_sess_idx].fault_detect_timer *
           bfd_data->sess[fixed_sess_idx].remote.detect_time_mult;
    }

    if (new_listen_timer != bfd_data->sess[float_sess_idx].listen_timer)
    {
        /* listening timer changes */

        BFD_history_add (float_sess_idx, BFD_HISTORY_LISTEN_TIMER,
            (uint32_t) new_listen_timer);

        bfd_data->sess[float_sess_idx].listen_timer = new_listen_timer;
    }

    bfd_data->sess[float_sess_idx].listen_timer_countdown =
        bfd_data->sess[float_sess_idx].listen_timer;
}


/*
 * Name:        BFD_timer_stop_listen_timer
 *
 * Abstract:    function to stop listening timer
 *
 * Parameters:
 *     sess_idx - BFD session index
 *
 * Retunrs:     none
 */
void BFD_timer_stop_listen_timer (int sess_idx)
{
    if (bfd_data->sess[sess_idx].listen_timer != 0)
    {
        BFD_history_add (sess_idx, BFD_HISTORY_LISTEN_TIMER,
            (uint32_t) 0);
    }

    bfd_data->sess[sess_idx].listen_timer = 0;
    bfd_data->sess[sess_idx].listen_timer_countdown = 0;
}


/*
 * Name:        BFD_timer_fire_listen_timer
 *
 * Abstract:    function to call when listening timer fires
 *
 * Parameters:
 *     sess_idx - BFD session index
 *
 * Retunrs:     none
 */
void BFD_timer_fire_listen_timer (int sess_idx)
{
    /* stop listening timer */
    BFD_timer_stop_listen_timer (sess_idx);

    /* start transmission timer */
    BFD_timer_start_transmission_timer (sess_idx);
}

#endif /* #ifdef BFD_LISTEN_TIMER_ENABLED */



/*
 * Name:        BFD_timer_start_transmission_timer
 *
 * Abstract:    function to start transmission timer
 *
 * Parameters:
 *     sess_idx - BFD session index
 *
 * Retunrs:     none
 */
void BFD_timer_start_transmission_timer (int sess_idx)
{
    int new_transmission_timer;

    if (bfd_data->sess[sess_idx].remote.min_rx == 0)
    {                         
        /* remote does not want to receive message */
        BFD_timer_stop_transmission_timer (sess_idx);
        return;
    }

    /*
     * transmission timer is the larger of:
     *     local desired min Tx interval
     *     remote required min Rx interval
     */
    if (bfd_data->sess[sess_idx].local.ofc.min_tx >=
        bfd_data->sess[sess_idx].remote.min_rx)
    {
        /* local desire min Tx interval is larger. Use it */
        new_transmission_timer = bfd_data->sess[sess_idx].local.ofc.min_tx;
    }
    else
    {
        /* remote required min Rx interval is larger. Use it */
        new_transmission_timer = bfd_data->sess[sess_idx].remote.min_rx;
    }

    if (new_transmission_timer != bfd_data->sess[sess_idx].transmission_timer)
    {
        /* transmission timer changes */

        BFD_history_add (sess_idx, BFD_HISTORY_TRANSMISSION_TIMER,
            (uint32_t) new_transmission_timer);

        bfd_data->sess[sess_idx].transmission_timer = new_transmission_timer;
    }

    /* restart transmission timer */
    BFD_timer_restart_transmission_timer (sess_idx);
}


/*
 * Name:        BFD_timer_restart_transmission_timer
 *
 * Abstract:    function to restart transmission timer
 *
 * Parameters:
 *     sess_idx - BFD session index
 *
 * Retunrs:     none
 */
void BFD_timer_restart_transmission_timer (int sess_idx)
{
    int jitter_time;

    /* calculate jitter time */
    if (bfd_data->sess[sess_idx].local.detect_time_mult == 1)
    {
        /* local detection time multiplier is 1 */

        /* calculate jitter from 10% to 25% ((0% - 15%) + 10%) */
        jitter_time = (rand() %
            (bfd_data->sess[sess_idx].transmission_timer * 15 / 100))
            + (bfd_data->sess[sess_idx].transmission_timer * 10 / 100);
    }
    else
    {
        /* local detection time multiplier is greater than 1 */

        /* calculate jitter time from 5% to 25% ((0% - 20%) + 5%) */
        jitter_time = (rand() %
            (bfd_data->sess[sess_idx].transmission_timer * 20 / 100))
            + (bfd_data->sess[sess_idx].transmission_timer * 5 / 100);
    }

    /* calc transmission timer countdown with jitter time */
    bfd_data->sess[sess_idx].transmission_timer_countdown =
        bfd_data->sess[sess_idx].transmission_timer - jitter_time;
}


/*
 * Name:        BFD_timer_stop_transmission_timer
 *
 * Abstract:    function to stop transmission timer
 *
 * Parameters:
 *     sess_idx - BFD session index
 *
 * Retunrs:     none
 */
void BFD_timer_stop_transmission_timer (int sess_idx)
{
    if (bfd_data->sess[sess_idx].transmission_timer != 0)
    {
        BFD_history_add (sess_idx, BFD_HISTORY_TRANSMISSION_TIMER,
            (uint32_t) 0);
    }

    bfd_data->sess[sess_idx].transmission_timer = 0;
    bfd_data->sess[sess_idx].transmission_timer_countdown = 0;
}


/*
 * Name:        BFD_timer_fire_transmission_timer
 *
 * Abstract:    function to call when transmission timer fires
 *
 * Parameters:
 *     sess_idx - BFD session index
 *
 * Retunrs:     none
 */
void BFD_timer_fire_transmission_timer (int sess_idx)
{
    BOOL send_msg;

    if (bfd_data->sess[sess_idx].remote.min_rx != 0)
    {                         
        /* remote wants to receive message */
        send_msg = TRUE;
    }
    else
    {
        /* remote does not want to receive message */
        send_msg = FALSE;
    }

    if ((bfd_data->sess[sess_idx].active_passive == BFD_ROLE_PASSIVE) &&
        (bfd_data->sess[sess_idx].remote.discriminator == 0))
    {
        /*
         * in passive role and
         * no remote discriminator (has not received remote message)
         */
        send_msg = FALSE;
    }

    if ((bfd_data->sess[sess_idx].remote.discriminator != 0) &&
        (bfd_data->sess[sess_idx].remote.min_rx == 0))
    {
        /*
         * has remote discriminator (has received remote message) and
         * remote required min Rx interval is 0
         *
         * remote does not want to receive message
         */
        send_msg = FALSE;
    }

    if (send_msg == TRUE)
    {
        /* send non-final message periodically */

        BFD_msg_encode (sess_idx, /*final_flag*/ FALSE);

        (void) BFD_trans_send (sess_idx);
    }

    /* restart transmission timer */
    BFD_timer_restart_transmission_timer (sess_idx);
}




/*
 * Name:        BFD_timer_start_fault_detect_timer
 *
 * Abstract:    function to start fault detection timer
 *
 * Parameters:
 *     sess_idx - BFD session index
 *
 * Retunrs:     none
 */
void BFD_timer_start_fault_detect_timer (int sess_idx)
{
    int new_fault_detect_timer;

    /*
     * fault detection timer is the larger of:
     *     local required min Rx interval
     *     remote desired min Tx interval
     */
    if (bfd_data->sess[sess_idx].local.ofc.min_rx >=
        bfd_data->sess[sess_idx].remote.min_tx)
    {
        /* Local required min Rx interval is larger. Use it */
        new_fault_detect_timer = bfd_data->sess[sess_idx].local.ofc.min_rx;
    }
    else
    {
        /* Remote desired min Tx interval is larger. Use it */
        new_fault_detect_timer = bfd_data->sess[sess_idx].remote.min_tx;
    }

    if (new_fault_detect_timer != bfd_data->sess[sess_idx].fault_detect_timer)
    {
        /* fault_detect timer changes */

        BFD_history_add (sess_idx, BFD_HISTORY_FAULT_DETECT_TIMER,
            (uint32_t) new_fault_detect_timer);

        bfd_data->sess[sess_idx].fault_detect_timer = new_fault_detect_timer;
    }

    /* reset fault_detect_timer_fire_num */
    bfd_data->sess[sess_idx].fault_detect_timer_fire_num = 0;

    /* restart fault detection timer */
    BFD_timer_restart_fault_detect_timer (sess_idx);
}


/*
 * Name:        BFD_timer_restart_fault_detect_timer
 *
 * Abstract:    function to restart fault detection timer
 *
 * Parameters:
 *     sess_idx - BFD session index
 *
 * Retunrs:     none
 */
void BFD_timer_restart_fault_detect_timer (int sess_idx)
{
    /* restart timer's countdown */
    /* no jitter for fault detection timer */
    bfd_data->sess[sess_idx].fault_detect_timer_countdown =
        bfd_data->sess[sess_idx].fault_detect_timer;

    /* reset has received message flag */
    bfd_data->sess[sess_idx].has_recv_msg = FALSE;
}


/*
 * Name:        BFD_timer_stop_fault_detect_timer
 *
 * Abstract:    function to stop fault detection timer
 *
 * Parameters:
 *     sess_idx - BFD session index
 *
 * Retunrs:     none
 */
void BFD_timer_stop_fault_detect_timer (int sess_idx)
{
    if (bfd_data->sess[sess_idx].fault_detect_timer != 0)
    {
        BFD_history_add (sess_idx, BFD_HISTORY_FAULT_DETECT_TIMER,
            (uint32_t) 0);
    }

    bfd_data->sess[sess_idx].fault_detect_timer = 0;
    bfd_data->sess[sess_idx].fault_detect_timer_countdown = 0;
    bfd_data->sess[sess_idx].fault_detect_timer_fire_num = 0;
}


/*
 * Name:        BFD_timer_fire_fault_detect_timer
 *
 * Abstract:    function to call when fault detection timer fires
 *
 * Parameters:
 *     sess_idx - BFD session index
 *
 * Retunrs:     none
 */
void BFD_timer_fire_fault_detect_timer (int sess_idx)
{
    if (bfd_data->sess[sess_idx].has_recv_msg == TRUE)
    {
        /*
         * has received message for current fault detection timer interval
         */

        /* reset fault_detect_timer_fire_num */
	bfd_data->sess[sess_idx].fault_detect_timer_fire_num = 0;

        /* restart fault detection timer */
        BFD_timer_restart_fault_detect_timer (sess_idx);
        return;
    }

#if 0
    if (bfd_data->sess[sess_idx].local.diagnostic !=
        BFD_DIAG_CTL_DETECT_TIME_EXPIRED)
    {
        /* local diagnostic changes */

        BFD_history_add (sess_idx, BFD_HISTORY_LOCAL_DIAGNOSTIC,
            (uint32_t) BFD_DIAG_CTL_DETECT_TIME_EXPIRED);

        bfd_data->sess[sess_idx].local.diagnostic =
            BFD_DIAG_CTL_DETECT_TIME_EXPIRED;
    }
#endif

    bfd_data->sess[sess_idx].fault_detect_timer_fire_num++;
    if (bfd_data->sess[sess_idx].fault_detect_timer_fire_num <
        bfd_data->sess[sess_idx].remote.detect_time_mult)
    {
        /* has not reached remote detection time multiplier yet */

        /* do not reset fault_detect_timer_fire_num */

        /* restart fault detection timer */
        BFD_timer_restart_fault_detect_timer (sess_idx);
        return;
    }

    /* has reached remote detection time multiplier */
    bfd_data->sess[sess_idx].missed_hb++;

    /* run finite state machine with fault detection timeout */
    if (BFD_fsm_run (sess_idx, BFD_EVENT_FAULT_DETECT_TIMEOUT) !=
        BFD_SUCCESS)
    {
        /* stop fault detection timer */
        BFD_timer_stop_fault_detect_timer (sess_idx);
    }

    /* a successful run of BFD FSM stops fault detection timer */
}
