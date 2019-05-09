/*************************************************************************
 *
 * File:     BFD_stats.h
 *
 * Abstract: internal header file of BFD statistic module
 *           this module handles BFD statistics/counts
 *
 * Nodes:    BFD implemenation should include only BFD_int_data.h instead
 *           of this file
 *
 ************************************************************************/

#ifndef BFD_STATS_H
#define BFD_STATS_H


/* function to initialize BFD statistic module */
void BFD_stats_init();


/* function to log BFD statistics/counts of BFD protocol */
void BFD_stats_log_bfd();

/* function to log BFD statistics/counts of a BFD session */
void BFD_stats_log_sess (int sess_idx);


#endif /* #ifndef BFD_STATS_H */
