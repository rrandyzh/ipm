/*************************************************************************
 *
 * File:     ARPNDP_sess.h
 *
 * Abstract: internal header file of ARP/NDP session module
 *           this module handles ARP/NDP session
 *
 * Nodes:    ARP/NDP implemenation should include only ARPNDP_int_data.h
 *           instead of this file
 *
 ************************************************************************/

#ifndef ARPNDP_SESS_H
#define ARPNDP_SESS_H


/* function to create a new ARP/NDP session */
ARPNDP_RETVAL ARPNDP_sess_create (int intf_idx, IPM_IPADDR *remote_ip,
    IPM_IPADDR *local_ip, uint8_t detect_time_mult, uint32_t min_tx,
    uint32_t min_rx);

/*
 * function to change ARP/NDP session parameters after ARP/NDP session has
 * been created
 */
ARPNDP_RETVAL ARPNDP_sess_change_cfg (int sess_idx, IPM_IPADDR *local_ip,
    uint8_t detect_time_mult, uint32_t min_tx, uint32_t min_rx);

/* function to destroy an existing ARP/NDP session */
void ARPNDP_sess_destroy (int sess_idx);


/* function to get session state of an ARP/NDP session */
void ARPNDP_sess_get_sess_state (int sess_idx, ARPNDP_SESS_STATE *sess_state);

/* function to set adminstrative state of an ARP/NDP session */
ARPNDP_RETVAL ARPNDP_sess_set_admin_state (int sess_idx,
    ARPNDP_ADMIN_STATE new_admin_state);


/* function to get statistics/counts of an ARP/NDP session */
void ARPNDP_sess_get_stats (int sess_idx, uint32_t *missed_hb);

/* function to clear statistics/counts of an ARP/NDP session */
void ARPNDP_sess_clear_stats (int sess_idx);


/* function to call every 5 milli-seconds to implement ARP/NDP timers */
void ARPNDP_sess_timer (int sess_idx);

/* function to process a received ARP/NDP message */
ARPNDP_RETVAL ARPNDP_sess_recv (int sess_idx);


/* function to externally audit ARP/NDP session */
void ARPNDP_sess_ext_audit (int sess_idx);

/* function to internally audit ARP/NDP session */
void ARPNDP_sess_int_audit (int sess_idx);


#endif /* #ifndef ARPNDP_SESS_H */
