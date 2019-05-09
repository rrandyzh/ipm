/*************************************************************************
 *
 * File:     BFD_cfg.h
 *
 * Abstract: internal header file of BFD config module
 *           this module handles BFD configuration data
 *
 * Nodes:    BFD implemenation should include only BFD_int_data.h instead
 *           of this file
 *
 ************************************************************************/

#ifndef BFD_CFG_H
#define BFD_CFG_H


/* Call-back function for BFD to audit BFD session with LCP */
extern BFD_AUDIT_CB_FUNC bfd_audit_cb_func;

/* Checksum of the above function pointer to detect memory corruption */
extern unsigned long bfd_audit_cb_func_checksum;


/* Call-back function for BFD to report session state change to LCP */
extern BFD_STATE_CHANGE_CB_FUNC bfd_state_change_cb_func;

/* Checksum of the above function pointer to detect memory corruption */
extern unsigned long bfd_state_change_cb_func_checksum;


#endif /* #ifndef BFD_CFG_H */
