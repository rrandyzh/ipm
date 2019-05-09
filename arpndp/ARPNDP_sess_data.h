/*************************************************************************
 *
 * File:     ARPNDP_sess_data.h
 *
 * Abstract: internal header file of ARP/NDP session data module
 *           this module handles ARP/NDP session data
 *
 * Nodes:    ARP/NDP implemenation should include only ARPNDP_int_data.h
 *           instead of this file
 *
 ************************************************************************/

#ifndef ARPNDP_SESS_DATA_H
#define ARPNDP_SESS_DATA_H


/* invalid ARP/NDP session index */
#define ARPNDP_INV_SESS_IDX                -1


/* function to initialize ARP/NDP session data module */
void ARPNDP_sess_data_init();


/*
 * function to calculate keys of ARP/NDP session data using OS interface
 * index and remote IP
 */
uint32_t /*key_add*/ ARPNDP_sess_data_calc_keys (int intf_idx,
    IPM_IPADDR *remote_ip, uint32_t *key_xor);

/* function to check keys with other ARP/NDP sessions */
ARPNDP_RETVAL ARPNDP_sess_data_chk_keys (int sess_idx, uint32_t key_add,
    uint32_t key_xor, int *other_sess_idx);


/* function to allocate a new ARP/NDP session */
ARPNDP_RETVAL ARPNDP_sess_data_alloc (int intf_idx, IPM_IPADDR *remote_ip,
    int *sess_idx);

/* function to free an existing ARP/NDP session */
void ARPNDP_sess_data_free (int sess_idx);


/*
 * function to get/find an ARP/NDP session with OS interface index and
 * remote IP
 */
ARPNDP_RETVAL ARPNDP_sess_data_get (int intf_idx, IPM_IPADDR *remote_ip,
    int *sess_idx);


/* function to get first ARP/NDP session */
int ARPNDP_sess_data_get_first();

/* function to get next ARP/NDP session */
int ARPNDP_sess_data_get_next (int sess_id);


/* function to log ARP/NDP session data for an ARP/NDP session */
void ARPNDP_sess_data_log (int sess_idx);


#endif /* #ifndef ARPNDP_SESS_DATA_H */
