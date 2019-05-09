/*************************************************************************
 *
 * File:     BFD_fsm.h
 *
 * Abstract: internal header file of BFD FSM module
 *           this module handles BFD FSM (finite state machine)
 *
 * Nodes:    BFD implemenation should include only BFD_int_data.h instead
 *           of this file
 *
 ************************************************************************/

#ifndef BFD_FSM_H
#define BFD_FSM_H


/* invalid BFD session state */
#define BFD_INV_SESS_STATE       -1


/*
 * BFD event
 *
 * It is a combination of:
 *     4 remote session states
 *     2 local administrative states
 *     1 fault detection timeout
 */
typedef enum{
    BFD_EVENT_REMOTE_ADMIN_DOWN = BFD_SESS_STATE_ADMIN_DOWN, /* = 0 */
    BFD_EVENT_REMOTE_DOWN       = BFD_SESS_STATE_DOWN,       /* = 1 */
    BFD_EVENT_REMOTE_INIT       = BFD_SESS_STATE_INIT,       /* = 2 */
    BFD_EVENT_REMOTE_UP         = BFD_SESS_STATE_UP,         /* = 3 */

    BFD_EVENT_LOCAL_ADMIN_DOWN  = BFD_ADMIN_STATE_DOWN,      /* = 4 */
    BFD_EVENT_LOCAL_ADMIN_UP    = BFD_ADMIN_STATE_UP,        /* = 5 */

    /* do not use values in BFD_SESS_STATE and BFD_ADMIN_STATE */
    BFD_EVENT_FAULT_DETECT_TIMEOUT                              = 6
} BFD_EVENT;


/* function to run BFD finite state machine */
BFD_RETVAL BFD_fsm_run (int sess_idx, BFD_EVENT event);


#endif /* #ifndef BFD_FSM_H */
