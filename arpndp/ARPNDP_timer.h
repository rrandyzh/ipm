/*************************************************************************
 *
 * File:     ARPNDP_timer.h
 *
 * Abstract: internal header file of ARP/NDP timer module
 *           this module handles ARP/NDP timers
 *
 * Nodes:    ARP/NDP implemenation should include only ARPNDP_int_data.h
 *           instead of this file
 *
 *           ARP/NDP time/timer is in milli-seconds
 *
 ************************************************************************/

#ifndef ARPNDP_TIMER_H
#define ARPNDP_TIMER_H


/* LCP call ARP/NDP API ARPNDP_timer() every 5 milli-second */
#define ARPNDP_TIMER_INTERVAL       5


/* timer to internally audit ARP/NDP session - 1 minute */
#define ARPNDP_AUDIT_TIMER          (60 * 1000 / ARPNDP_TIMER_INTERVAL)

/* timer to log ARP/NDP statistics/counts - 15 minutes */
#define ARPNDP_LOG_STATS_TIMER      (15 * 60 * 1000 / ARPNDP_TIMER_INTERVAL)



/* number of microseconds in a millisecond */
#define ARPNDP_USEC_IN_MSEC         1000



/* function to start transmission timer */
void ARPNDP_timer_start_transmission_timer (int sess_idx);

/* function to restart transmission timer */
void ARPNDP_timer_restart_transmission_timer (int sess_idx);

/* function to stop transmission timer */
void ARPNDP_timer_stop_transmission_timer (int sess_idx);

/* function to call when transmission timer fires */
void ARPNDP_timer_fire_transmission_timer (int sess_idx);


#endif /* #ifndef ARPNDP_TIMER_H */
