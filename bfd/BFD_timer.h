/*************************************************************************
 *
 * File:     BFD_timer.h
 *
 * Abstract: internal header file of BFD timer module
 *           this module handles BFD timers
 *
 * Nodes:    BFD implemenation should include only BFD_int_data.h instead
 *           of this file
 *
 *           BFD time/timer is in milli-seconds
 *
 ************************************************************************/

#ifndef BFD_TIMER_H
#define BFD_TIMER_H


/* LCP call BFD API BFD_timer() every 5 milli-second */
#define BFD_TIMER_INTERVAL            5

/*
 * slow transmision timer used when local session state is non-UP;
 * 1 second
 */
#define BFD_SLOW_TRANSMISSION_TIMER   1000 /*ms*/



/* timer to internally audit BFD session - 1 minute */
#define BFD_AUDIT_TIMER               (60 * 1000 / BFD_TIMER_INTERVAL)

/* timer to log BFD statistics/counts - 15 minutes */
#define BFD_LOG_STATS_TIMER           (15 * 60 * 1000 / BFD_TIMER_INTERVAL)



/* number of microseconds in a millisecond */
#define BFD_USEC_IN_MSEC              1000

/* whether to support listening timer for redudancy */
#ifdef BFD_LISTEN_TIMER_ENABLED



/* function to start listening timer */
void BFD_timer_start_listen_timer (int float_sess_idx, int fixed_sess_idx);

/* function to stop listening timer */
void BFD_timer_stop_listen_timer (int sess_idx);

/* function to call when listening timer fires */
void BFD_timer_fire_listen_timer (int sess_idx);

#endif /* #ifdef BFD_LISTEN_TIMER_ENABLED */


/* function to start transmission timer */
void BFD_timer_start_transmission_timer (int sess_idx);

/* function to restart transmission timer */
void BFD_timer_restart_transmission_timer (int sess_idx);

/* function to stop transmission timer */
void BFD_timer_stop_transmission_timer (int sess_idx);

/* function to call when transmission timer fires */
void BFD_timer_fire_transmission_timer (int sess_idx);


/* function to start fault detection timer */
void BFD_timer_start_fault_detect_timer (int sess_idx);

/* function to restart fault detection timer */
void BFD_timer_restart_fault_detect_timer (int sess_idx);

/* function to stop fault detection timer */
void BFD_timer_stop_fault_detect_timer (int sess_idx);

/* function to call when fault detection timer fires */
void BFD_timer_fire_fault_detect_timer (int sess_idx);


#endif /* #ifndef BFD_TIMER_H */
