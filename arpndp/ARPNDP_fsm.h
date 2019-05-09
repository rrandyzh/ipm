/*************************************************************************
 *
 * File:     ARPNDP_fsm.h
 *
 * Abstract: internal header file of ARP/NDP FSM module
 *           this module handles ARP/NDP FSM (finite state machine)
 *
 * Nodes:    ARP/NDP implemenation should include only ARPNDP_int_data.h
 *           instead of this file
 *
 ************************************************************************/

#ifndef ARPNDP_FSM_H
#define ARPNDP_FSM_H


/* invalid ARP/NDP session state */
#define ARPNDP_INV_SESS_STATE       -1


/*
 * ARP/NDP event
 *
 * It is a combination of:
 *     2 administrative states
 *     1 receive message
 *     1 fault detection timeout
 */
typedef enum{
    ARPNDP_EVENT_ADMIN_DOWN  = ARPNDP_ADMIN_STATE_DOWN,      /* = 0 */
    ARPNDP_EVENT_ADMIN_UP    = ARPNDP_ADMIN_STATE_UP,        /* = 1 */

    ARPNDP_EVENT_FAULT_DETECT_TIMEOUT                           = 2,
    ARPNDP_EVENT_RECV_MSG                                       = 3
} ARPNDP_EVENT;


/* function to run ARP/NDP finite state machine */
ARPNDP_RETVAL ARPNDP_fsm_run (int sess_idx, ARPNDP_EVENT event);


#endif /* #ifndef ARPNDP_FSM_H */
