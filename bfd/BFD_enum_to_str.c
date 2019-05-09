/*************************************************************************
 *
 * File:     BFD_enum_to_str.c
 *
 * Abstract: implementation file of BFD enum-to-string module
 *           this module displays BFD enumerations as string
 *
 * Data:     none
 *
 * Functions:
 *     BFD_BOOL_to_str        - function to display boolean as string
 *     BFD_SESS_STATE_to_str  - function to display BFD session state as
 *                              string
 *     BFD_ADMIN_STATE_to_str - function to display BFD administrative state
 *                              as string
 *     BFD_DIAGNOSTIC_to_str  - function to display BFD diagnostic as string
 *     BFD_HISTORY_to_str     - function to display BFD history type as
 *                              string
 *     BFD_ROLE_to_str        - function to display BFD role as string
 *     BFD_INIT_TYPE_to_str   - function to display BFD initialization type
 *                              as string
 *     BFD_AUDIT_SEQ_to_str   - function to display BFD audit sequence as
 *                              string
 *
 ************************************************************************/

#include "BFD_int_hdr.h"


/*
 * Name:        BFD_BOOL_to_str
 *
 * Abstract:    function to display boolean as string
 *
 * Parameters:
 *     false_true - boolean value
 *
 * Retunrs:
 *     string
 */
const char *BFD_BOOL_to_str (BOOL false_true)
{
    switch (false_true)
    {
    case FALSE:
        return "FALSE";
    case TRUE:
        return "TRUE";
    default:
        return "UNKNOWN";
    }
}


/*
 * Name:        BFD_SESS_STATE_to_str
 *
 * Abstract:    function to display BFD session state as string
 *
 * Parameters:
 *     sess_state - BFD session state
 *
 * Retunrs:
 *     string
 */
const char *BFD_SESS_STATE_to_str (BFD_SESS_STATE sess_state)
{
    switch (sess_state)
    {
    case BFD_SESS_STATE_ADMIN_DOWN:
        return "BFD_SESS_STATE_ADMIN_DOWN";
    case BFD_SESS_STATE_DOWN:
        return "BFD_SESS_STATE_DOWN";
    case BFD_SESS_STATE_INIT:
        return "BFD_SESS_STATE_INIT";
    case BFD_SESS_STATE_UP:
        return "BFD_SESS_STATE_UP";
    default:
        return "UNKNOWN";
    }
}


/*
 * Name:        BFD_ADMIN_STATE_to_str
 *
 * Abstract:    function to display BFD administrative state as string
 *
 * Parameters:
 *     admin_state - BFD administrative state
 *
 * Retunrs:
 *     string
 */
const char *BFD_ADMIN_STATE_to_str (BFD_ADMIN_STATE admin_state)
{
    switch (admin_state)
    {
    case BFD_ADMIN_STATE_DOWN:
        return "BFD_ADMIN_STATE_DOWN";
    case BFD_ADMIN_STATE_UP:
        return "BFD_ADMIN_STATE_UP";
    default:
        return "UNKNOWN";
    }
}


/*
 * Name:        BFD_DIAGNOSTIC_to_str
 *
 * Abstract:    function to display BFD diagnostic as string
 *
 * Parameters:
 *     diagnostic - BFD diagnostic
 *
 * Retunrs:
 *     string
 */
const char *BFD_DIAGNOSTIC_to_str (BFD_DIAGNOSTIC diagnostic)
{
    switch (diagnostic)
    {
    case BFD_DIAG_NONE:
        return "BFD_DIAG_NONE";
    case BFD_DIAG_CTL_DETECT_TIME_EXPIRED:
        return "BFD_DIAG_CTL_DETECT_TIME_EXPIRED";
    case BFD_DIAG_ECHO_FUNC_FAILED:
        return "BFD_DIAG_ECHO_FUNC_FAILED";
    case BFD_DIAG_NEIGHBOR_SIG_SESS_DOWN:
        return "BFD_DIAG_NEIGHBOR_SIG_SESS_DOWN";
    case BFD_DIAG_FWD_PLANE_RESET:
        return "BFD_DIAG_FWD_PLANE_RESET";
    case BFD_DIAG_PATH_DOWN:
        return "BFD_DIAG_PATH_DOWN";
    case BFD_DIAG_CONCAT_PATH_DOWN:
        return "BFD_DIAG_CONCAT_PATH_DOWN";
    case BFD_DIAG_ADMIN_DOWN:
        return "BFD_DIAG_ADMIN_DOWN";
    case BFD_DIAG_REVERSE_CONCAT_PATH_DOWN:
        return "BFD_DIAG_REVERSE_CONCAT_PATH_DOWN";
    default:
        return "UNKNOWN";
    }
}


/*
 * Name:        BFD_HISTORY_TYPE_to_str
 *
 * Abstract:    function to display BFD history type as string
 *
 * Parameters:
 *     history_type - BFD history type
 *
 * Retunrs:
 *     string
 */
const char *BFD_HISTORY_TYPE_to_str (BFD_HISTORY_TYPE history_type)
{
    switch (history_type)
    {
    case BFD_HISTORY_REMOTE_SESS_STATE:
        return "BFD_HISTORY_REMOTE_SESS_STATE";
    case BFD_HISTORY_REMOTE_DIAGNOSTIC:
        return "BFD_HISTORY_REMOTE_DIAGNOSTIC";
    case BFD_HISTORY_REMOTE_DISCRIMINATOR:
        return "BFD_HISTORY_REMOTE_DISCRIMINATOR";
    case BFD_HISTORY_REMOTE_DETECT_TIME_MULT:
        return "BFD_HISTORY_REMOTE_DETECT_TIME_MULT";
    case BFD_HISTORY_REMOTE_MIN_TX:
        return "BFD_HISTORY_REMOTE_MIN_TX";
    case BFD_HISTORY_REMOTE_MIN_RX:
        return "BFD_HISTORY_REMOTE_MIN_RX";
    case BFD_HISTORY_LOCAL_ADMIN_STATE:
        return "BFD_HISTORY_LOCAL_ADMIN_STATE";
    case BFD_HISTORY_LOCAL_SESS_STATE:
        return "BFD_HISTORY_LOCAL_SESS_STATE";
    case BFD_HISTORY_LOCAL_DIAGNOSTIC:
        return "BFD_HISTORY_LOCAL_DIAGNOSTIC";
    case BFD_HISTORY_LOCAL_DETECT_TIME_MULT:
        return "BFD_HISTORY_LOCAL_DETECT_TIME_MULT";
    case BFD_HISTORY_LOCAL_CFG_MIN_TX:
        return "BFD_HISTORY_LOCAL_CFG_MIN_TX";
    case BFD_HISTORY_LOCAL_USED_MIN_TX:
        return "BFD_HISTORY_LOCAL_USED_MIN_TX";
    case BFD_HISTORY_LOCAL_MIN_RX:
        return "BFD_HISTORY_LOCAL_MIN_RX";

#ifdef BFD_LISTEN_TIMER_ENABLED

    case BFD_HISTORY_LISTEN_TIMER:
        return "BFD_HISTORY_LISTEN_TIMER";

#endif /* #ifdef BFD_LISTEN_TIMER_ENABLED */

    case BFD_HISTORY_TRANSMISSION_TIMER:
        return "BFD_HISTORY_TRANSMISSION_TIMER";
    case BFD_HISTORY_FAULT_DETECT_TIMER:
        return "BFD_HISTORY_FAULT_DETECT_TIMER";
    case BFD_HISTORY_RECV_COUNT:
        return "BFD_HISTORY_RECV_COUNT";
    case BFD_HISTORY_SEND_COUNT:
        return "BFD_HISTORY_SEND_COUNT";
    default:
        return "UNKNOWN";
    }
}


/*
 * Name:        BFD_ROLE_to_str
 *
 * Abstract:    function to display BFD role as string
 *
 * Parameters:
 *     active_passive - BFD role
 *
 * Retunrs:
 *     string
 */
const char *BFD_ROLE_to_str (BFD_ROLE active_passive)
{
    switch (active_passive)
    {
    case BFD_ROLE_ACTIVE:
        return "BFD_ROLE_ACTIVE";
    case BFD_ROLE_PASSIVE:
        return "BFD_ROLE_PASSIVE";
    default:
        return "UNKNOWN";
    }
}


/*
 * Name:        BFD_INIT_TYPE_to_str
 *
 * Abstract:    function to display BFD initialization type as string
 *
 * Parameters:
 *     init_type - BFD initialization type
 *
 * Retunrs:
 *     string
 */
const char *BFD_INIT_TYPE_to_str (BFD_INIT_TYPE init_type)
{
    switch (init_type)
    {
    case BFD_INIT_TYPE_FULL:
        return "BFD_INIT_TYPE_FULL";
    case BFD_INIT_TYPE_RESTART:
        return "BFD_INIT_TYPE_RESTERT";
    default:
        return "UNKNOWN";
    }
}


/*     
 * Name:        BFD_AUDIT_SEQ_to_str  
 *     
 * Abstract:    function to display BFD audit sequence as string
 *     
 * Parameters:
 *     begin_middle_end - BFD audit sequence
 *     
 * Retunrs:
 *     string
 */
const char *BFD_AUDIT_SEQ_to_str (BFD_AUDIT_SEQ begin_middle_end)
{
    switch (begin_middle_end)
    {
    case BFD_AUDIT_SEQ_BEGIN:
        return "BFD_AUDIT_SEQ_BEGIN";
    case BFD_AUDIT_SEQ_MIDDLE:
        return "BFD_AUDIT_SEQ_MIDDLE";
    case BFD_AUDIT_SEQ_END:
        return "BFD_AUDIT_SEQ_END";
    default:  
        return "UNKNOWN";
    }
}

