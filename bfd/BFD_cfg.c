/*************************************************************************
 *
 * File:      BFD_cfg.c
 *
 * Abstract:  implementation file of BFD config module
 *            this module handles BFD configuration data
 *            parameters
 *
 * Data:
 *     bfd_audit_cb_func               - call-back function for BFD to
 *                                       audit BFD session with LCP
 *     bfd_audit_cb_func_chksum        - checksum of the above function
 *                                       pointer to detect memory corruption
 *
 *     bfd_state_change_cb_func        - call-back function for BFD to
 *                                       report session state change to LCP
 *     bfd_state_change_cb_func_chksum - checksum of the above function
 *                                       pointer to detect memory corruption
 *
 * Functions: none
 *
 ************************************************************************/
 
#include "BFD_int_hdr.h"


/* call-back function for BFD to audit BFD session with LCP */
BFD_AUDIT_CB_FUNC bfd_audit_cb_func = NULL;

/* checksum of the above function pointer to detect memory corruption */
unsigned long bfd_audit_cb_func_checksum = 0;


/* call-back function for BFD to report session state change to LCP */
BFD_STATE_CHANGE_CB_FUNC bfd_state_change_cb_func = NULL;

/* checksum of the above function pointer to detect memory corruption */
unsigned long bfd_state_change_cb_func_checksum = 0;
