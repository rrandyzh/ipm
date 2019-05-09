/*************************************************************************
 *
 * File:     ARPNDP_timer.c
 *
 * Abstract: implementation file of ARP/NDP timer module
 *           this module handles ARP/NDP timers
 *
 * Data:     none
 *
 * Functions:
 *     ARPNDP_timer_start_transmission_timer   - function to start
 *                                               transmission timer
 *     ARPNDP_timer_restart_transmission_timer - function to retstart
 *                                               transmission timer
 *     ARPNDP_timer_stop_transmission_timer    - function to stop
 *                                               transmission timer
 *     ARPNDP_timer_fire_transmission_timer    - function to call when
 *                                               transmission timer fires
 *
 ************************************************************************/

#include "ARPNDP_int_hdr.h"


/*
 * Name:        ARPNDP_timer_start_transmission_timer
 *
 * Abstract:    function to start transmission timer
 *
 * Parameters:
 *     sess_idx - ARP/NDP session index
 *
 * Retunrs:     none
 */
void ARPNDP_timer_start_transmission_timer (int sess_idx)
{
    int new_transmission_timer;

    /*
     * transmission timer is the larger of:
     *     desired min Tx interval
     *     required min Rx interval
     */
    if (arpndp_data->sess[sess_idx].min_tx >=
        arpndp_data->sess[sess_idx].min_rx)
    {
        /* desire min Tx interval is larger. Use it */
        new_transmission_timer = arpndp_data->sess[sess_idx].min_tx;
    }
    else
    {
        /* required min Rx interval is larger. Use it */
        new_transmission_timer = arpndp_data->sess[sess_idx].min_rx;
    }

    if (new_transmission_timer !=
        arpndp_data->sess[sess_idx].transmission_timer)
    {
        /* transmission timer changes */

        ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_TRANSMISSION_TIMER,
            (uint32_t) new_transmission_timer);

        arpndp_data->sess[sess_idx].transmission_timer =
            new_transmission_timer;
    }

    /* reset fault_detect_timer_fire_num */
    arpndp_data->sess[sess_idx].fault_detect_timer_fire_num = 0;

    /* restart transmission timer */
    ARPNDP_timer_restart_transmission_timer (sess_idx);
}


/*
 * Name:        ARPNDP_timer_restart_transmission_timer
 *
 * Abstract:    function to restart transmission timer
 *
 * Parameters:
 *     sess_idx - ARP/NDP session index
 *
 * Retunrs:     none
 */
void ARPNDP_timer_restart_transmission_timer (int sess_idx)
{
    /* restart timer's countdown */
    arpndp_data->sess[sess_idx].transmission_timer_countdown =
        arpndp_data->sess[sess_idx].transmission_timer;

    /* reset has received message flag */
    arpndp_data->sess[sess_idx].has_recv_msg = FALSE;
}


/*
 * Name:        ARPNDP_timer_stop_transmission_timer
 *
 * Abstract:    function to stop transmission timer
 *
 * Parameters:
 *     sess_idx - ARP/NDP session index
 *
 * Retunrs:     none
 */
void ARPNDP_timer_stop_transmission_timer (int sess_idx)
{
    if (arpndp_data->sess[sess_idx].transmission_timer != 0)
    {
        ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_TRANSMISSION_TIMER,
            (uint32_t) 0);
    }

    arpndp_data->sess[sess_idx].transmission_timer = 0;
    arpndp_data->sess[sess_idx].transmission_timer_countdown = 0;
    arpndp_data->sess[sess_idx].fault_detect_timer_fire_num = 0;
    arpndp_data->sess[sess_idx].has_recv_msg = FALSE;
}


/*
 * Name:        ARPNDP_timer_fire_transmission_timer
 *
 * Abstract:    function to call when transmission timer fires
 *
 * Parameters:
 *     sess_idx - ARP/NDP session index
 *
 * Retunrs:     none
 */
void ARPNDP_timer_fire_transmission_timer (int sess_idx)
{
    /* always send message when transmission timer fires */
    (void) ARPNDP_trans_send (sess_idx);

    if (arpndp_data->sess[sess_idx].has_recv_msg == TRUE)
    {
        /*
         * has received message for current fault detection timer interval
         */

        /* reset fault_detect_timer_fire_num */
        arpndp_data->sess[sess_idx].fault_detect_timer_fire_num = 0;

        /* restart fault detection timer */
        ARPNDP_timer_restart_transmission_timer (sess_idx);
        return;
    }

    arpndp_data->sess[sess_idx].fault_detect_timer_fire_num++;
    if (arpndp_data->sess[sess_idx].fault_detect_timer_fire_num <
        arpndp_data->sess[sess_idx].detect_time_mult)
    {
        /* has not reached detection time multiplier yet */

        /* do not reset fault_detect_timer_fire_num */

        /* restart fault detection timer */
        ARPNDP_timer_restart_transmission_timer (sess_idx);
        return;
    }

    /* has reached detection time multiplier */

    arpndp_data->sess[sess_idx].missed_hb++;

    /* reset fault_detect_timer_fire_num */
    arpndp_data->sess[sess_idx].fault_detect_timer_fire_num = 0;

    /* restart fault detection timer */
    ARPNDP_timer_restart_transmission_timer (sess_idx);

    /* run finite state machine with fault detection timeout */
    (void) ARPNDP_fsm_run (sess_idx, ARPNDP_EVENT_FAULT_DETECT_TIMEOUT);
}
