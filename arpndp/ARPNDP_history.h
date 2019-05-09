/*************************************************************************
 *
 * File:     ARPNDP_history.h
 *
 * Abstract: internal header file of ARP/NDP history module
 *           this module handles ARP/NDP history
 *
 * Nodes:    ARP/NDP implemenation should include only ARPNDP_int_data.h
 *           instead of this file
 *
 ************************************************************************/
#ifndef ARPNDP_HISTORY_H
#define ARPNDP_HISTORY_H


/* size of each ARP/NDP history */
#define ARPNDP_HISTORY_SIZE                5


/* ARP/NDP history type */
typedef enum
{
    ARPNDP_HISTORY_NOT_USED,            /* =  0 */

    ARPNDP_HISTORY_ADMIN_STATE,         /* =  1 */
    ARPNDP_HISTORY_SESS_STATE,          /* =  2 */

    ARPNDP_HISTORY_LOCAL_IP_IPV4,       /* =  3 */
    ARPNDP_HISTORY_LOCAL_IP_IPV6_1,     /* =  4 */
    ARPNDP_HISTORY_LOCAL_IP_IPV6_2,     /* =  5 */
    ARPNDP_HISTORY_LOCAL_IP_IPV6_3,     /* =  6 */
    ARPNDP_HISTORY_LOCAL_IP_IPV6_4,     /* =  7 */

    ARPNDP_HISTORY_DETECT_TIME_MULT,    /* =  8 */
    ARPNDP_HISTORY_MIN_TX,              /* =  9 */
    ARPNDP_HISTORY_MIN_RX,              /* = 10 */

    ARPNDP_HISTORY_TRANSMISSION_TIMER,  /* = 11 */
    ARPNDP_HISTORY_FAULT_DETECT_TIMER,  /* = 12 */

    ARPNDP_HISTORY_RECV_COUNT,          /* = 13 */
    ARPNDP_HISTORY_SEND_COUNT           /* = 14 */
} ARPNDP_HISTORY_TYPE;


/* function to initialize ARP/NDP history module */
void ARPNDP_history_init();


/* function to add a new ARP/NDP history */
void ARPNDP_history_add (int sess_idx, ARPNDP_HISTORY_TYPE history_type,
    uint32_t history_data);

/* function to log ARP/NDP history for an ARP/NDP session */
void ARPNDP_history_log (int sess_idx);


#endif /* #ifndef ARPNDP_HISTORY_H */
