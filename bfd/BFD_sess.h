/*************************************************************************
 *
 * File:     BFD_sess.h
 *
 * Abstract: internal header file of BFD session module
 *           this module handles BFD session
 *
 * Nodes:    BFD implemenation should include only BFD_int_data.h instead
 *           of this file
 *
 ************************************************************************/

#ifndef BFD_SESS_H
#define BFD_SESS_H


/* function to create a new BFD session */
BFD_RETVAL BFD_sess_create (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    uint8_t detect_time_mult, uint32_t min_tx, uint32_t min_rx);

/*
 * function to change BFD session parameters after BFD session has been
 * created
 */
BFD_RETVAL BFD_sess_change_cfg (int sess_idx, uint8_t detect_time_mult,
    uint32_t min_tx, uint32_t min_rx);

/* function to destroy an existing BFD session */
void BFD_sess_destroy (int sess_idx);


/* function to get session state of a BFD session */
void BFD_sess_get_sess_state (int sess_idx, BFD_SESS_STATE *sess_state);

/* function to set adminstrative state of a BFD session */
BFD_RETVAL BFD_sess_set_admin_state (int sess_idx,
    BFD_ADMIN_STATE new_admin_state);


/* function to get statistics/counts of a BFD session */
void BFD_sess_get_stats (int sess_idx, uint32_t *missed_hb, uint32_t *corrupt_pkt);

/* function to clear statistics/counts of a BFD session */
void BFD_sess_clear_stats (int sess_idx);


/* function to call every 5 milli-seconds to implement BFD timers */
void BFD_sess_timer (int sess_idx);

/* function to process a received BFD message */
BFD_RETVAL BFD_sess_recv (int sess_idx);


/* function to externally audit BFD session */
void BFD_sess_ext_audit (int sess_idx);

/* function to internally audit BFD session */
void BFD_sess_int_audit (int sess_idx);


#endif /* #ifndef BFD_SESS_H */
