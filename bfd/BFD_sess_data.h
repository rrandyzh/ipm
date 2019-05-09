/*************************************************************************
 *
 * File:     BFD_sess_data.h
 *
 * Abstract: internal header file of BFD session data module
 *           this module handles BFD session data
 *
 * Nodes:    BFD implemenation should include only BFD_int_data.h instead
 *           of this file
 *
 ************************************************************************/

#ifndef BFD_SESS_DATA_H
#define BFD_SESS_DATA_H


/* invalid BFD session index */
#define BFD_INV_SESS_IDX                -1

/* local discriminator is this base plus BFD session index */
#define BFD_LOCAL_DISCRIMINATOR_BASE    1


/* function to initialize BFD session data module */
void BFD_sess_data_init();


/*
 * function to calculate keys of BFD session data using local IP and remote
 * IP
 */
uint32_t /*key_add*/ BFD_sess_data_calc_keys (IPM_IPADDR *local_ip,
    IPM_IPADDR *remote_ip, uint32_t *key_xor);

/* function to check keys with other BFD sessions */
BFD_RETVAL BFD_sess_data_chk_keys (int sess_idx, uint32_t key_add,
    uint32_t key_xor, int *other_sess_idx);


/* function to allocate a new BFD session */
BFD_RETVAL BFD_sess_data_alloc (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    int *sess_idx);

/* function to free an existing BFD session */
void BFD_sess_data_free (int sess_idx);


/* function to get/find a BFD session with local IP and remote IP */
BFD_RETVAL BFD_sess_data_get (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    int *sess_idx);

/*
 * function to get/find another fixed-IP BFD sesssion with the same remote
 * IP and its local session state is UP
 */
BFD_RETVAL BFD_sess_data_get_fixed (IPM_IPADDR *remote_ip,
    int float_sess_idx, int *fixed_sess_idx);

/* function to get first BFD session */
int BFD_sess_data_get_first();

/* function to get next BFD session */
int BFD_sess_data_get_next (int sess_id);


/* function to log BFD session data for a BFD session */
void BFD_sess_data_log (int sess_idx);


#endif /* #ifndef BFD_SESS_DATA_H */
