/*************************************************************************
 *
 * File:     BFD_fsm.c
 *
 * Abstract: implementation file of BFD FSM module
 *           this module handles BFD FSM (finite state machine)
 *
 * Data:     none
 *
 * Functions:
 *     BFD_fsm_report_state_change      - module-internal function to report
 *                                        sesstion state change to LCP
 *
 *     BFD_fsm_hdl_history              - module-internal function to handle
 *                                        history after session state change
 *     BFD_fsm_hdl_transmission_timer   - module-internal function to handle
 *                                        transmission timer after session
 *                                        state change
 *     BFD_fsm_hdl_fault_detect_timer   - module-internal function to handle
 *                                        fault detection timer after session
 *                                        state change
 *     BFD_fsm_hdl_local_diagnostic     - module-internal function to handle
 *                                        local diagnostic after session
 *                                        state change
 *     BFD_fsm_hdl_remote_discriminator - module-internal function to handle
 *                                        remote discriminator after session
 *                                        state change
 *     BFD_fsm_hdl_report_state_change  - module-internal function to decide
 *                                        whether to report session state
 *                                        change
 *
 *     BFD_fsm_run                      - function to run BFD finite state
 *                                        machine
 *
 ************************************************************************/

#include "BFD_int_hdr.h"


/* shortcut for old/previous local session state */
#define BFD_OLD_SESS_STATE         bfd_data->sess[sess_idx].local.sess_state


/*
 * Name:        BFD_fsm_report_state_change
 *
 * Abstract:    module-internal function to report session state change to
 *              LCP
 *
 * Parameters:
 *     sess_idx - BFD session index
 *
 * Returns:     none
 */
static void BFD_fsm_report_state_change (int sess_idx)
{
    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];

    if (((unsigned long) bfd_state_change_cb_func ^
         (unsigned long) BFD_CHECKSUM_SEED) !=
        bfd_state_change_cb_func_checksum)
    {
        BFD_LOCAL_ERROR ("corrupted call-back function for BFD to report "
            "sesstion state change\n");
        bfd_data->stats.corrupt_state_change_cb_func++;
        return;
    }

    if (bfd_state_change_cb_func == NULL)
    {
        /* no call-back function */
        return;
    }

    if (BFD_LOG_ENABLED)
    {
        IPM_ipaddr2p (&bfd_data->sess[sess_idx].local_ip, &local_ip_str[0],
            sizeof(local_ip_str));
        IPM_ipaddr2p (&bfd_data->sess[sess_idx].remote_ip, &remote_ip_str[0],
            sizeof(remote_ip_str));

        BFD_LOG (
            "BFD_fsm_report_state_change: "
            "local_ip %s, "
            "remote_ip %s, "
            "sess_state %s\n",
            &local_ip_str[0],
            &remote_ip_str[0],
            BFD_SESS_STATE_to_str (bfd_data->sess[sess_idx].local.sess_state)
            );
    }

    /* call LCP-provided call-back function to report session state change */
    (* bfd_state_change_cb_func)(
        &bfd_data->sess[sess_idx].local_ip,
        &bfd_data->sess[sess_idx].remote_ip,
        bfd_data->sess[sess_idx].local.sess_state);
}


/*
 * Name:        BFD_fsm_hdl_history
 *
 * Abstract:    module-internal function to handle history
 *              after sesstion state change
 *
 * Parameters:
 *     sess_idx - BFD session index
 *
 * Returns:     none
 */
static void BFD_fsm_hdl_history (int sess_idx)
{
    /* collect receiving message count while in old session state */
    BFD_history_add (sess_idx, BFD_HISTORY_RECV_COUNT,
        (uint32_t) bfd_data->sess[sess_idx].recv_count);
    bfd_data->sess[sess_idx].recv_count = 0;

    /* collect sending message count while in old session state */
    BFD_history_add (sess_idx, BFD_HISTORY_SEND_COUNT,
        (uint32_t) bfd_data->sess[sess_idx].send_count);
    bfd_data->sess[sess_idx].send_count = 0;
}


/*
 * Name:        BFD_fsm_hdl_transmission_timer
 *
 * Abstract:    module-internal function to handle transmission timer
 *              after sesstion state change
 *
 * Parameters:
 *     sess_idx       - BFD session index
 *     new_sess_state - new session state
 *
 * Returns:     none
 */
static void BFD_fsm_hdl_transmission_timer (int sess_idx,
    BFD_SESS_STATE new_sess_state)
{
    if (new_sess_state == BFD_SESS_STATE_UP)
    {
        /* session state changes from (ADMIN DOWN, DOWN, or INIT) to UP */

        if (bfd_data->sess[sess_idx].local.ofc.min_tx !=
            BFD_SLOW_TRANSMISSION_TIMER)
        {
            BFD_SESS_ERROR (sess_idx, "invalid local.ofc.min_tx %u; "
                "slow transmission timer expected\n",
                bfd_data->sess[sess_idx].local.ofc.min_tx);
            bfd_data->stats.inv_local_ofc_min_tx++;
        }

        /*
         * use real/fast transmission timer
         *
         * do not wait for local poll sequence
         * because local.ofc.min_tx decreases
         */

        BFD_history_add (sess_idx, BFD_HISTORY_LOCAL_USED_MIN_TX,
            (uint32_t) bfd_data->sess[sess_idx].local.cfg_min_tx);

        bfd_data->sess[sess_idx].local.ofc.min_tx =
            bfd_data->sess[sess_idx].local.cfg_min_tx;

        /* (re)start transmission timer */
        BFD_timer_start_transmission_timer (sess_idx);

        /*
         * do a fake local poll sequence;
         * real/fast transmission timer already takes affect but
         * remote does not know about it
         */
        bfd_data->sess[sess_idx].local_poll_seq = TRUE;
        bfd_data->sess[sess_idx].local.trans.min_tx =
            bfd_data->sess[sess_idx].local.cfg_min_tx;
        bfd_data->sess[sess_idx].local.trans.min_rx =
            bfd_data->sess[sess_idx].local.ofc.min_rx;
    }
    else if (BFD_OLD_SESS_STATE == BFD_SESS_STATE_UP)
    {
        /* session state changes from UP to (ADMIN DOWN, DOWN, or INIT) */

        if (bfd_data->sess[sess_idx].local.ofc.min_tx ==
            BFD_SLOW_TRANSMISSION_TIMER)
        {
            BFD_SESS_ERROR (sess_idx, "invalid slow transmission timer; "
                "fast transmission timer expected\n");
            bfd_data->stats.inv_local_ofc_min_tx++;
        }

        /*
         * use slow transmission timer
         *
         * do not do local poll sequence
         * because new session state is non-UP
         */

        BFD_history_add (sess_idx, BFD_HISTORY_LOCAL_USED_MIN_TX,
            (uint32_t) BFD_SLOW_TRANSMISSION_TIMER);

        bfd_data->sess[sess_idx].local.ofc.min_tx =
            BFD_SLOW_TRANSMISSION_TIMER;

        /* (re)start transmission timer */
        BFD_timer_start_transmission_timer (sess_idx);

        if (bfd_data->sess[sess_idx].local_poll_seq == TRUE)
        {
            /* in local poll sequence */
            /* cancel it */
            bfd_data->sess[sess_idx].local_poll_seq = FALSE;
            bfd_data->sess[sess_idx].local.trans.min_tx = 0;
            bfd_data->sess[sess_idx].local.trans.min_rx = 0;
        }
    }
}


/*
 * Name:        BFD_fsm_hdl_fault_detect_timer
 *
 * Abstract:    module-internal function to handle fault detection timer
 *              after sesstion state change
 *
 * Parameters:
 *     sess_idx       - BFD session index
 *     new_sess_state - new session state
 *
 * Returns:     none
 */
static void BFD_fsm_hdl_fault_detect_timer (int sess_idx,
    BFD_SESS_STATE new_sess_state)
{
    if ((new_sess_state == BFD_SESS_STATE_ADMIN_DOWN) ||
        (new_sess_state == BFD_SESS_STATE_DOWN))
    {
        /* new session state is ADMIN DOWN or DOWN */

        /* stop fault detection timer */
        BFD_timer_stop_fault_detect_timer (sess_idx);
    }
    else
    {
        /* new session state is INIT or UP */

        if (bfd_data->sess[sess_idx].fault_detect_timer == 0)
        {
            /* fault detection timer is not running */

            /* start fault detection timer */
            BFD_timer_start_fault_detect_timer (sess_idx);
        }
    }
}


/*
 * Name:        BFD_fsm_hdl_local_diagnostic
 *
 * Abstract:    module-internal function to handle local diagnostic
 *              after sesstion state change
 *
 * Parameters:
 *     sess_idx       - BFD session index
 *     new_sess_state - new session state
 *     event          - BFD event
 *
 * Returns:     none
 *
 * Notes:
 * Supported local diagnostic :
 *     BFD_DIAG_CTL_DETECT_TIME_EXPIRED
 *     BFD_DIAG_NEIGHBOR_SIG_SESS_DOWN
 *     BFD_DIAG_ADMIN_DOWN
 *     BFD_DIAG_NONE
 *
 * Unsupported local diagnostic :
 *     BFD_DIAG_ECHO_FUNC_FAILED
 *     BFD_DIAG_FWD_PLANE_RESET
 *     BFD_DIAG_PATH_DOWN
 *     BFD_DIAG_CONCAT_PATH_DOWN
 *     BFD_DIAG_REVERSE_CONCAT_PATH_DOWN
 */
static void BFD_fsm_hdl_local_diagnostic (int sess_idx,
    BFD_SESS_STATE new_sess_state, BFD_EVENT event)
{
    BFD_DIAGNOSTIC new_diagnostic = bfd_data->sess[sess_idx].local.diagnostic;

    if (event == BFD_EVENT_FAULT_DETECT_TIMEOUT)
    {
        /* fault detection timer fires */

        /* control detection time expired */
        new_diagnostic = BFD_DIAG_CTL_DETECT_TIME_EXPIRED;
    }
    else if ((event == BFD_EVENT_REMOTE_ADMIN_DOWN) &&
        (BFD_OLD_SESS_STATE != BFD_SESS_STATE_DOWN))
    {
        /*
         * remote session state is ADMIN DOWN and
         * previous local session state is non-DOWN
         */

        /* neighbor signaled session down */
        new_diagnostic = BFD_DIAG_NEIGHBOR_SIG_SESS_DOWN;
    }
    else if ((event == BFD_EVENT_REMOTE_DOWN) &&
        (BFD_OLD_SESS_STATE == BFD_SESS_STATE_UP))
    {
        /*
         * remote session state is DOWN and
         * previous local session state is UP
         */

        /* neighbor signaled session down */
        new_diagnostic = BFD_DIAG_NEIGHBOR_SIG_SESS_DOWN;
    }
    else if (new_sess_state == BFD_SESS_STATE_ADMIN_DOWN)
    {
        /* new session state is ADMIN DOWN */

        /* administratively down */
        new_diagnostic = BFD_DIAG_ADMIN_DOWN;
    }
    else if (new_sess_state == BFD_SESS_STATE_UP)
    {
        /* new session state is UP */

        /* clear local BFD diagnostic */
        new_diagnostic = BFD_DIAG_NONE;
    }

    if (new_diagnostic != bfd_data->sess[sess_idx].local.diagnostic)
    {
        /* local diagnostic changes */

        BFD_history_add (sess_idx, BFD_HISTORY_LOCAL_DIAGNOSTIC,
            (uint32_t) new_diagnostic);

        bfd_data->sess[sess_idx].local.diagnostic = new_diagnostic;
    }
}


/*
 * Name:        BFD_fsm_hdl_remote_discriminator
 *
 * Abstract:    module-internal function to handle remote discriminator
 *              after sesstion state change
 *
 * Parameters:
 *     sess_idx       - BFD session index
 *     new_sess_state - new session state
 *
 * Returns:     none
 */
static void BFD_fsm_hdl_remote_discriminator (int sess_idx,
    BFD_SESS_STATE new_sess_state)
{
    if ((new_sess_state == BFD_SESS_STATE_DOWN) ||
        (new_sess_state == BFD_SESS_STATE_ADMIN_DOWN))
    {
        /* clear remote discriminator */
        BFD_history_add (sess_idx, BFD_HISTORY_REMOTE_DISCRIMINATOR,
            (uint32_t) 0);
        bfd_data->sess[sess_idx].remote.discriminator = 0;
    }
}


/*
 * Name:        BFD_fsm_hdl_report_state_change
 *
 * Abstract:    module-internal function to decide whether to report
 *              session state change to LCP
 *
 * Parameters:
 *     sess_idx            - BFD session index
 *     new_sess_state      - new session state
 *
 * Returns:
 *     report_state_change - whether to report session state change to LCP
 */
static BOOL BFD_fsm_hdl_report_state_change (int sess_idx,
    BFD_SESS_STATE new_sess_state)
{
    /* start with not reporting sesstion state change to LCP */
    BOOL report_state_change = FALSE;

    switch (BFD_OLD_SESS_STATE)
    {
    case BFD_SESS_STATE_ADMIN_DOWN:
    case BFD_SESS_STATE_DOWN:
    case BFD_SESS_STATE_INIT:
        if (new_sess_state == BFD_SESS_STATE_UP)
        {
            /*
             * session state changes from (ADMIN DOWN, DOWN, or INIT) to UP
             */

            /* report session state change to LCP */
            report_state_change = TRUE;
        }
        break;

    case BFD_SESS_STATE_UP:
        switch (new_sess_state)
        {
        case BFD_SESS_STATE_ADMIN_DOWN:
        case BFD_SESS_STATE_DOWN:
        case BFD_SESS_STATE_INIT:
            /*
             * session state changes from UP to (ADMIN DOWN, DOWN, or INIT)
             */

            /* report session state change to LCP */
            report_state_change = TRUE;
            break;

        default:
            break;
        }
        break;

    default:
        break;
    }

    return report_state_change;
}


/*
 * Name:        BFD_fsm_run
 *
 * Abstract:    function to run BFD finite state machine
 *
 * Parameters:
 *     sess_idx - BFD session index
 *     event    - BFD event that includes
 *                    4 remote session state
 *                    2 local administrative state
 *                    1 fault detection timeout
 *
 * Returns:
 *     ret_val  - success or failure
 *
 * Notes: to keep BFD FSM simple and manageable, the output should be:
 *     Stay in the same state (only break statemenent)
 *     Move to a new state
 *     Error
 * Do not put complicated code in BFD finite state machine
 */
BFD_RETVAL BFD_fsm_run (int sess_idx, BFD_EVENT event)
{
    BFD_SESS_STATE new_sess_state = BFD_INV_SESS_STATE;
    BOOL report_state_change;

    switch (bfd_data->sess[sess_idx].local.sess_state)
    {
    case BFD_SESS_STATE_ADMIN_DOWN:
        switch (event)
        {
        case BFD_EVENT_REMOTE_ADMIN_DOWN:
        case BFD_EVENT_REMOTE_DOWN:
        case BFD_EVENT_REMOTE_INIT:
        case BFD_EVENT_REMOTE_UP:
            BFD_SESS_ERROR (sess_idx, "unexpected event %d in local session "
                "state %d\n", event,
                bfd_data->sess[sess_idx].local.sess_state);
            bfd_data->stats.unexpect_event++;
            return BFD_SESS_FAIL;

        case BFD_EVENT_LOCAL_ADMIN_DOWN:
            BFD_LOCAL_ERROR ("unexpected event %d in local session "
                "state %d\n", event,
                bfd_data->sess[sess_idx].local.sess_state);
            bfd_data->stats.unexpect_event++;
            return BFD_LOCAL_FAIL;
        case BFD_EVENT_LOCAL_ADMIN_UP:
            /* this is the only way to get out of ADMIN DOWN state */
            /* start to bring up BFD session */
            new_sess_state = BFD_SESS_STATE_DOWN;
            break;

        case BFD_EVENT_FAULT_DETECT_TIMEOUT:
            BFD_SESS_ERROR (sess_idx, "unexpected event %d in local session "
                "state %d\n", event,
                bfd_data->sess[sess_idx].local.sess_state);
            bfd_data->stats.unexpect_event++;
            return BFD_SESS_FAIL;

        default:
            BFD_INTERNAL_ERROR ("invalid event %d\n", event);
            bfd_data->stats.inv_event++;
            return BFD_INTERNAL_FAIL;
        }
        break;

    case BFD_SESS_STATE_DOWN:
        switch (event)
        {
        case BFD_EVENT_REMOTE_ADMIN_DOWN:
            break;
        case BFD_EVENT_REMOTE_DOWN:
            new_sess_state = BFD_SESS_STATE_INIT;
            break;
        case BFD_EVENT_REMOTE_INIT:
            new_sess_state = BFD_SESS_STATE_UP;
            break;
        case BFD_EVENT_REMOTE_UP:

#ifdef BFD_LISTEN_TIMER_ENABLED

            if (bfd_data->sess[sess_idx].listen_timer != 0)
            {
                /* listening timer is running */
                /* go directly to UP session state */
                new_sess_state = BFD_SESS_STATE_UP;
            }

#endif /* #ifdef BFD_LISTEN_TIMER_ENABLED */

            break;

        case BFD_EVENT_LOCAL_ADMIN_DOWN:
            new_sess_state = BFD_SESS_STATE_ADMIN_DOWN;
            break;
        case BFD_EVENT_LOCAL_ADMIN_UP:
            BFD_LOCAL_ERROR ("unexpected event %d in local session "
                "state %d\n", event,
                bfd_data->sess[sess_idx].local.sess_state);
            bfd_data->stats.unexpect_event++;
            return BFD_LOCAL_FAIL;

        case BFD_EVENT_FAULT_DETECT_TIMEOUT:
            BFD_SESS_ERROR (sess_idx, "unexpected event %d in local session "
                "state %d\n", event,
                bfd_data->sess[sess_idx].local.sess_state);
            bfd_data->stats.unexpect_event++;
            return BFD_SESS_FAIL;

        default:
            BFD_INTERNAL_ERROR ("invalid event %d\n", event);
            bfd_data->stats.inv_event++;
            return BFD_INTERNAL_FAIL;
        }
        break;

    case BFD_SESS_STATE_INIT:
        switch (event)
        {
        case BFD_EVENT_REMOTE_ADMIN_DOWN:
            new_sess_state = BFD_SESS_STATE_DOWN;
            break;
        case BFD_EVENT_REMOTE_DOWN:
            break;
        case BFD_EVENT_REMOTE_INIT:
            new_sess_state = BFD_SESS_STATE_UP;
            break;
        case BFD_EVENT_REMOTE_UP:
            new_sess_state = BFD_SESS_STATE_UP;
            break;

        case BFD_EVENT_LOCAL_ADMIN_DOWN:
            new_sess_state = BFD_SESS_STATE_ADMIN_DOWN;
            break;
        case BFD_EVENT_LOCAL_ADMIN_UP:
            BFD_LOCAL_ERROR ("unexpected event %d in local session "
                "state %d\n", event,
                bfd_data->sess[sess_idx].local.sess_state);
            bfd_data->stats.unexpect_event++;
            return BFD_LOCAL_FAIL;

        case BFD_EVENT_FAULT_DETECT_TIMEOUT:
            new_sess_state = BFD_SESS_STATE_DOWN;
            break;

        default:
            BFD_INTERNAL_ERROR ("invalid event %d\n", event);
            bfd_data->stats.inv_event++;
            return BFD_INTERNAL_FAIL;
        }
        break;

    case BFD_SESS_STATE_UP:
        switch (event)
        {
        case BFD_EVENT_REMOTE_ADMIN_DOWN:
            new_sess_state = BFD_SESS_STATE_DOWN;
            break;
        case BFD_EVENT_REMOTE_DOWN:
            new_sess_state = BFD_SESS_STATE_DOWN;
            break;
        case BFD_EVENT_REMOTE_INIT:
            break;
        case BFD_EVENT_REMOTE_UP:
            break;

        case BFD_EVENT_LOCAL_ADMIN_DOWN:
            new_sess_state = BFD_SESS_STATE_ADMIN_DOWN;
            break;
        case BFD_EVENT_LOCAL_ADMIN_UP:
            BFD_LOCAL_ERROR ("unexpected event %d in local session "
                "state %d\n", event,
                bfd_data->sess[sess_idx].local.sess_state);
            bfd_data->stats.unexpect_event++;
            return BFD_LOCAL_FAIL;

        case BFD_EVENT_FAULT_DETECT_TIMEOUT:
            new_sess_state = BFD_SESS_STATE_DOWN;
            break;

        default:
            BFD_INTERNAL_ERROR ("invalid event %d\n", event);
            bfd_data->stats.inv_event++;
            return BFD_INTERNAL_FAIL;
        }
        break;

    default:
        BFD_INTERNAL_ERROR ("invalid local session state %d\n",
            bfd_data->sess[sess_idx].local.sess_state);
        bfd_data->stats.inv_local_state++;
        return BFD_INTERNAL_FAIL;
    }

    if (new_sess_state != (BFD_SESS_STATE) BFD_INV_SESS_STATE)
    {
        /* session state changes */

        BFD_fsm_hdl_transmission_timer (sess_idx, new_sess_state);

        BFD_fsm_hdl_fault_detect_timer (sess_idx, new_sess_state);

        BFD_fsm_hdl_local_diagnostic (sess_idx, new_sess_state, event);

        BFD_fsm_hdl_remote_discriminator (sess_idx, new_sess_state);

        report_state_change = BFD_fsm_hdl_report_state_change (sess_idx,
            new_sess_state);

        BFD_fsm_hdl_history (sess_idx);

        /* save new session state */
        BFD_history_add (sess_idx, BFD_HISTORY_LOCAL_SESS_STATE,
            (uint32_t) new_sess_state);
        bfd_data->sess[sess_idx].local.sess_state = new_sess_state;

        if (report_state_change == TRUE)
        {
            /* report session state change to LCP */
            BFD_fsm_report_state_change (sess_idx);
        }
    }

    return BFD_SUCCESS;
}
