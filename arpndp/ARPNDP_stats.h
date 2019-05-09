/*************************************************************************
 *
 * File:     ARPNDP_stats.h
 *
 * Abstract: internal header file of ARP/NDP statistic module
 *           this module handles ARP/NDP statistics/counts
 *
 * Nodes:    ARP/NDP implemenation should include only ARPNDP_int_data.h
 *           instead of this file
 *
 ************************************************************************/

#ifndef ARPNDP_STATS_H
#define ARPNDP_STATS_H


/* function to initialize ARP/NDP statistic module */
void ARPNDP_stats_init();


/* function to log statistics/counts of ARP/NDP protocol */
void ARPNDP_stats_log_arpndp();

/* function to log statistics/counts of an ARP/NDP session */
void ARPNDP_stats_log_sess (int sess_idx);


#endif /* #ifndef ARPNDP_STATS_H */
