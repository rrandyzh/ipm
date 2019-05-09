/*************************************************************************
 *
 * File:     ARPNDP_fsm.c
 *
 * Abstract: implementation file of ARP/NDP FSM module
 *           this module handles ARP/NDP FSM (finite state machine)
 *
 * Data:     none
 *
 * Functions:
 *     ARPNDP_fsm_hdl_history            - module-internal function to handle
 *                                         history after session state change
 *     ARPNDP_fsm_hdl_transmission_timer - module-internal function to handle
 *                                         transmission timer after session
 *                                         state change
 *
 *     ARPNDP_fsm_run                    - function to run ARP/NDP finite
 *                                         state machine
 *
 ************************************************************************/

#include "ARPNDP_int_hdr.h"


/*
 * Name:        ARPNDP_fsm_hdl_history
 *
 * Abstract:    module-internal function to handle ARP/NDP history
 *              after sesstion state change
 *
 * Parameters:
 *     sess_idx - ARP/NDP session index
 *
 * Returns:     none
 */
static void ARPNDP_fsm_hdl_history (int sess_idx)
{
    /* collect receiving message count while in old session state */
    ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_RECV_COUNT,
        (uint32_t) arpndp_data->sess[sess_idx].recv_count);
    arpndp_data->sess[sess_idx].recv_count = 0;

    /* collect sending message count while in old session state */
    ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_SEND_COUNT,
        (uint32_t) arpndp_data->sess[sess_idx].send_count);
    arpndp_data->sess[sess_idx].send_count = 0;
}


/*
 * Name:        ARPNDP_fsm_hdl_transmission_timer
 *
 * Abstract:    module-internal function to handle transmission timer
 *              after sesstion state change
 *
 * Parameters:
 *     sess_idx       - ARP/NDP session index
 *     new_sess_state - new session state
 *
 * Returns:     none
 */
static void ARPNDP_fsm_hdl_transmission_timer (int sess_idx,
    ARPNDP_SESS_STATE new_sess_state)
{
    if (new_sess_state == ARPNDP_SESS_STATE_ADMIN_DOWN)
    {
        /* session state changes from (DOWN, INIT, or UP) to ADMIN DOWN */

        /* stop transmission timer */
        ARPNDP_timer_stop_transmission_timer (sess_idx);
    }
    else
    {
        /* new session state is DOWN, INIT, or UP */

        if (arpndp_data->sess[sess_idx].transmission_timer == 0)
        {
            /* transmission timer is not running */

            /* start transmission timer */
            ARPNDP_timer_start_transmission_timer (sess_idx);
        }
    }
}


/*
 * Name:        ARPNDP_fsm_run
 *
 * Abstract:    function to run ARP/NDP finite state machine
 *
 * Parameters:
 *     sess_idx - ARP/NDP session index
 *     event    - ARP/NDP event that includes
 *                    2 administrative state
 *                    1 receive message 
 *                    1 fault detection timeout
 *
 * Returns:
 *     ret_val  - success or failure
 *
 * Notes: to keep ARP/NDP FSM simple and manageable, the output should be:
 *     Stay in the same state (only break statemenent)
 *     Move to a new state
 *     Error
 * Do not put complicated code in ARP/NDP finite state machine
 */
ARPNDP_RETVAL ARPNDP_fsm_run (int sess_idx, ARPNDP_EVENT event)
{
    ARPNDP_SESS_STATE new_sess_state = ARPNDP_INV_SESS_STATE;

    switch (arpndp_data->sess[sess_idx].sess_state)
    {
    case ARPNDP_SESS_STATE_ADMIN_DOWN:
        switch (event)
        {
        case ARPNDP_EVENT_ADMIN_DOWN:
            ARPNDP_LOCAL_ERROR ("unexpected event %d in session state %d\n",
                event, arpndp_data->sess[sess_idx].sess_state);
            arpndp_data->stats.unexpect_event++;
            return ARPNDP_LOCAL_FAIL;
        case ARPNDP_EVENT_ADMIN_UP:
            /* this is the only way to get out of ADMIN DOWN state */
            new_sess_state = ARPNDP_SESS_STATE_INIT;
            break;

        case ARPNDP_EVENT_FAULT_DETECT_TIMEOUT:
            ARPNDP_SESS_ERROR (sess_idx, "unexpected event %d in session "
                "state %d\n", event, arpndp_data->sess[sess_idx].sess_state);
            arpndp_data->stats.unexpect_event++;
            return ARPNDP_SESS_FAIL;

        case ARPNDP_EVENT_RECV_MSG:
            ARPNDP_SESS_ERROR (sess_idx, "unexpected event %d in session "
                "state %d\n", event, arpndp_data->sess[sess_idx].sess_state);
            arpndp_data->stats.unexpect_event++;
            return ARPNDP_SESS_FAIL;

        default:
            ARPNDP_INTERNAL_ERROR ("invalid event %d\n", event);
            arpndp_data->stats.inv_event++;
            return ARPNDP_INTERNAL_FAIL;
        }
        break;

    case ARPNDP_SESS_STATE_DOWN:
        switch (event)
        {
        case ARPNDP_EVENT_ADMIN_DOWN:
            new_sess_state = ARPNDP_SESS_STATE_ADMIN_DOWN;
            break;
        case ARPNDP_EVENT_ADMIN_UP:
            ARPNDP_LOCAL_ERROR ("unexpected event %d in session state %d\n",
                event, arpndp_data->sess[sess_idx].sess_state);
            arpndp_data->stats.unexpect_event++;
            return ARPNDP_LOCAL_FAIL;

        case ARPNDP_EVENT_FAULT_DETECT_TIMEOUT:
            break;

        case ARPNDP_EVENT_RECV_MSG:
            new_sess_state = ARPNDP_SESS_STATE_UP;
            break;

        default:
            ARPNDP_INTERNAL_ERROR ("invalid event %d\n", event);
            arpndp_data->stats.inv_event++;
            return ARPNDP_INTERNAL_FAIL;
        }
        break;

    case ARPNDP_SESS_STATE_INIT:
        switch (event)
        {
        case ARPNDP_EVENT_ADMIN_DOWN:
            new_sess_state = ARPNDP_SESS_STATE_ADMIN_DOWN;
            break;
        case ARPNDP_EVENT_ADMIN_UP:
            ARPNDP_LOCAL_ERROR ("unexpected event %d in session state %d\n",
                event, arpndp_data->sess[sess_idx].sess_state);
            arpndp_data->stats.unexpect_event++;
            return ARPNDP_LOCAL_FAIL;

        case ARPNDP_EVENT_FAULT_DETECT_TIMEOUT:
            new_sess_state = ARPNDP_SESS_STATE_DOWN;
            break;

        case ARPNDP_EVENT_RECV_MSG:
            new_sess_state = ARPNDP_SESS_STATE_UP;
            break;

        default:
            ARPNDP_INTERNAL_ERROR ("invalid event %d\n", event);
            arpndp_data->stats.inv_event++;
            return ARPNDP_INTERNAL_FAIL;
        }
        break;

    case ARPNDP_SESS_STATE_UP:
        switch (event)
        {
        case ARPNDP_EVENT_ADMIN_DOWN:
            new_sess_state = ARPNDP_SESS_STATE_ADMIN_DOWN;
            break;
        case ARPNDP_EVENT_ADMIN_UP:
            ARPNDP_LOCAL_ERROR ("unexpected event %d in session state %d\n",
                event, arpndp_data->sess[sess_idx].sess_state);
            arpndp_data->stats.unexpect_event++;
            return ARPNDP_LOCAL_FAIL;

        case ARPNDP_EVENT_FAULT_DETECT_TIMEOUT:
            new_sess_state = ARPNDP_SESS_STATE_DOWN;
            break;

        case ARPNDP_EVENT_RECV_MSG:
            break;

        default:
            ARPNDP_INTERNAL_ERROR ("invalid event %d\n", event);
            arpndp_data->stats.inv_event++;
            return ARPNDP_INTERNAL_FAIL;
        }
        break;

    default:
        ARPNDP_INTERNAL_ERROR ("invalid session state %d\n",
            arpndp_data->sess[sess_idx].sess_state);
        arpndp_data->stats.inv_sess_state++;
        return ARPNDP_INTERNAL_FAIL;
    }

    if (new_sess_state != (ARPNDP_SESS_STATE) ARPNDP_INV_SESS_STATE)
    {
        /* session state changes */

        ARPNDP_fsm_hdl_transmission_timer (sess_idx, new_sess_state);

        ARPNDP_fsm_hdl_history (sess_idx);

        /* save new session state */
        ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_SESS_STATE,
            (uint32_t) new_sess_state);
        arpndp_data->sess[sess_idx].sess_state = new_sess_state;
    }

    return ARPNDP_SUCCESS;
}
