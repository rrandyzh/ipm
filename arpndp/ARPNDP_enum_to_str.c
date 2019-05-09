/*************************************************************************
 *
 * File:     ARPNDP_enum_to_str.c
 *
 * Abstract: implementation file of ARP/NDP enum-to-string module
 *           this module displays ARP/NDP enumerations as string
 *
 * Data:     none
 *
 * Functions:
 *     ARPNDP_BOOL_to_str        - function to display boolean as string
 *     ARPNDP_SESS_STATE_to_str  - function to display ARP/NDP session state
 *                                 as string
 *     ARPNDP_ADMIN_STATE_to_str - function to display ARP/NDP administrative
 *                                 state as string
 *     ARPNDP_HISTORY_to_str     - function to display ARP/NDP history type
 *                                 as string
 *     ARPNDP_INIT_TYPE_to_str   - function to display ARP/NDP initialization
 *                                 type as string
 *     ARPNDP_AUDIT_SEQ_to_str   - function to display ARP/NDP audit sequence
 *                                 as string
 *     ARPNDP_PROTOCOL_to_str    - function to display ARP/NDP prtocol
 *                                 as string
 *
 ************************************************************************/

#include "ARPNDP_int_hdr.h"


/*
 * Name:        ARPNDP_BOOL_to_str
 *
 * Abstract:    function to display boolean as string
 *
 * Parameters:
 *     false_true - boolean value
 *
 * Retunrs:
 *     string
 */
const char *ARPNDP_BOOL_to_str (BOOL false_true)
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
 * Name:        ARPNDP_SESS_STATE_to_str
 *
 * Abstract:    function to display ARP/NDP session state as string
 *
 * Parameters:
 *     sess_state - ARP/NDP session state
 *
 * Retunrs:
 *     string
 */
const char *ARPNDP_SESS_STATE_to_str (ARPNDP_SESS_STATE sess_state)
{
    switch (sess_state)
    {
    case ARPNDP_SESS_STATE_ADMIN_DOWN:
        return "ARPNDP_SESS_STATE_ADMIN_DOWN";
    case ARPNDP_SESS_STATE_DOWN:
        return "ARPNDP_SESS_STATE_DOWN";
    case ARPNDP_SESS_STATE_INIT:
        return "ARPNDP_SESS_STATE_INIT";
    case ARPNDP_SESS_STATE_UP:
        return "ARPNDP_SESS_STATE_UP";
    default:
        return "UNKNOWN";
    }
}


/*
 * Name:        ARPNDP_ADMIN_STATE_to_str
 *
 * Abstract:    function to display ARP/NDP administrative state as string
 *
 * Parameters:
 *     admin_state - ARP/NDP administrative state
 *
 * Retunrs:
 *     string
 */
const char *ARPNDP_ADMIN_STATE_to_str (ARPNDP_ADMIN_STATE admin_state)
{
    switch (admin_state)
    {
    case ARPNDP_ADMIN_STATE_DOWN:
        return "ARPNDP_ADMIN_STATE_DOWN";
    case ARPNDP_ADMIN_STATE_UP:
        return "ARPNDP_ADMIN_STATE_UP";
    default:
        return "UNKNOWN";
    }
}


/*
 * Name:        ARPNDP_HISTORY_TYPE_to_str
 *
 * Abstract:    function to display ARPNDP history type as string
 *
 * Parameters:
 *     history_type - ARPNDP history type
 *
 * Retunrs:
 *     string
 */
const char *ARPNDP_HISTORY_TYPE_to_str (ARPNDP_HISTORY_TYPE history_type)
{
    switch (history_type)
    {
    case ARPNDP_HISTORY_ADMIN_STATE:
        return "ARPNDP_HISTORY_ADMIN_STATE";
    case ARPNDP_HISTORY_SESS_STATE:
        return "ARPNDP_HISTORY_SESS_STATE";

    case ARPNDP_HISTORY_LOCAL_IP_IPV4:
        return "ARPNDP_HISTORY_LOCAL_IP_IPV4";
    case ARPNDP_HISTORY_LOCAL_IP_IPV6_1:
        return "ARPNDP_HISTORY_LOCAL_IP_IPV6";

    case ARPNDP_HISTORY_DETECT_TIME_MULT:
        return "ARPNDP_HISTORY_DETECT_TIME_MULT";
    case ARPNDP_HISTORY_MIN_TX:
        return "ARPNDP_HISTORY_MIN_TX";
    case ARPNDP_HISTORY_MIN_RX:
        return "ARPNDP_HISTORY_MIN_RX";

    case ARPNDP_HISTORY_TRANSMISSION_TIMER:
        return "ARPNDP_HISTORY_TRANSMISSION_TIMER";
    case ARPNDP_HISTORY_FAULT_DETECT_TIMER:
        return "ARPNDP_HISTORY_FAULT_DETECT_TIMER";

    case ARPNDP_HISTORY_RECV_COUNT:
        return "ARPNDP_HISTORY_RECV_COUNT";
    case ARPNDP_HISTORY_SEND_COUNT:
        return "ARPNDP_HISTORY_SEND_COUNT";

    case ARPNDP_HISTORY_LOCAL_IP_IPV6_2:
    case ARPNDP_HISTORY_LOCAL_IP_IPV6_3:
    case ARPNDP_HISTORY_LOCAL_IP_IPV6_4:
        return "ERROR";

    default:
        return "UNKNOWN";
    }
}


/*
 * Name:        ARPNDP_INIT_TYPE_to_str
 *
 * Abstract:    function to display ARP/NDP initialization type as string
 *
 * Parameters:
 *     init_type - ARP/NDP initialization type
 *
 * Retunrs:
 *     string
 */
const char *ARPNDP_INIT_TYPE_to_str (ARPNDP_INIT_TYPE init_type)
{
    switch (init_type)
    {
    case ARPNDP_INIT_TYPE_FULL:
        return "ARPNDP_INIT_TYPE_FULL";
    case ARPNDP_INIT_TYPE_RESTART:
        return "ARPNDP_INIT_TYPE_RESTERT";
    default:
        return "UNKNOWN";
    }
}


/*     
 * Name:        ARPNDP_AUDIT_SEQ_to_str  
 *     
 * Abstract:    function to display ARP/NDP audit sequence as string
 *     
 * Parameters:
 *     begin_middle_end - ARP/NDP audit sequence
 *     
 * Retunrs:
 *     string
 */
const char *ARPNDP_AUDIT_SEQ_to_str (ARPNDP_AUDIT_SEQ begin_middle_end)
{
    switch (begin_middle_end)
    {
    case ARPNDP_AUDIT_SEQ_BEGIN:
        return "ARPNDP_AUDIT_SEQ_BEGIN";
    case ARPNDP_AUDIT_SEQ_MIDDLE:
        return "ARPNDP_AUDIT_SEQ_MIDDLE";
    case ARPNDP_AUDIT_SEQ_END:
        return "ARPNDP_AUDIT_SEQ_END";
    default:  
        return "UNKNOWN";
    }
}


/*     
 * Name:        ARPNDP_PROTOCOL_to_str  
 *     
 * Abstract:    function to display ARP/NDP protocol as string
 *     
 * Parameters:
 *     protocol - ARP/NDP protocol
 *     
 * Retunrs:
 *     string
 */
const char *ARPNDP_PROTOCOL_to_str (ARPNDP_PROTOCOL protocol)
{
    switch (protocol)
    {
    case ARPNDP_PROTOCOL_ARP:
        return "ARPNDP_PROTOCOL_ARP";
    case ARPNDP_PROTOCOL_NDP:
        return "ARPNDP_PROTOCOL_NDP";
    default:  
        return "UNKNOWN";
    }
}

