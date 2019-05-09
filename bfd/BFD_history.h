/*************************************************************************
 *
 * File:     BFD_history.h
 *
 * Abstract: internal header file of BFD history module
 *           this module handles BFD history
 *
 * Nodes:    BFD implemenation should include only BFD_int_data.h instead
 *           of this file
 *
 ************************************************************************/
#ifndef BFD_HISTORY_H
#define BFD_HISTORY_H


/* size of each BFD history */
#define BFD_HISTORY_SIZE                5


/* BFD history type */
typedef enum
{
    BFD_HISTORY_NOT_USED,                       /* =  0 */

    BFD_HISTORY_REMOTE_SESS_STATE,              /* =  1 */
    BFD_HISTORY_REMOTE_DIAGNOSTIC,              /* =  2 */
    BFD_HISTORY_REMOTE_DISCRIMINATOR,           /* =  3 */

    BFD_HISTORY_REMOTE_DETECT_TIME_MULT,        /* =  4 */
    BFD_HISTORY_REMOTE_MIN_TX,                  /* =  5 */
    BFD_HISTORY_REMOTE_MIN_RX,                  /* =  6 */

    BFD_HISTORY_LOCAL_ADMIN_STATE,              /* =  7 */
    BFD_HISTORY_LOCAL_SESS_STATE,               /* =  8 */
    BFD_HISTORY_LOCAL_DIAGNOSTIC,               /* =  9 */

    BFD_HISTORY_LOCAL_DETECT_TIME_MULT,         /* = 10 */
    BFD_HISTORY_LOCAL_CFG_MIN_TX,               /* = 11 */
    BFD_HISTORY_LOCAL_USED_MIN_TX,              /* = 12 */
    BFD_HISTORY_LOCAL_MIN_RX,                   /* = 13 */

#ifdef BFD_LISTEN_TIMER_ENABLED
    BFD_HISTORY_LISTEN_TIMER,                   /* = 14 */
#endif

    BFD_HISTORY_TRANSMISSION_TIMER,             /* = 15 */
    BFD_HISTORY_FAULT_DETECT_TIMER,             /* = 16 */

    BFD_HISTORY_RECV_COUNT,                     /* = 17 */
    BFD_HISTORY_SEND_COUNT                      /* = 18 */
} BFD_HISTORY_TYPE;


/* function to initialize BFD history module */
void BFD_history_init();


/* function to add a new BFD history */
void BFD_history_add (int sess_idx, BFD_HISTORY_TYPE history_type,
    uint32_t history_data);

/* function to log BFD history for a BFD session */
void BFD_history_log (int sess_idx);


#endif /* #ifndef BFD_HISTORY_H */
