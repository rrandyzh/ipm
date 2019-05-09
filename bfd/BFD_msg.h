/*************************************************************************
 *
 * File:     BFD_msg.h
 *
 * Abstract: internal header file of BFD message module
 *           this module encodes/decodes BFD message
 *
 * Nodes:    BFD implemenation should include only BFD_int_data.h instead
 *           of this file
 *
 ************************************************************************/

#ifndef BFD_MSG_H
#define BFD_MSG_H


/* BFD version is always 1*/
#define BFD_PROTO_VERSION           1

/* BFD mesage length is always 24 without optional authentication */
#define BFD_MSG_LENGTH              24


/* function to encode a BFD message */
void BFD_msg_encode (int sess_idx, BOOL final_flag);

/* function to decode/process a BFD message */
BFD_RETVAL BFD_msg_decode (int sess_idx, BOOL *start_transmission_timer,
    BOOL *start_fault_detect_timer);


/* function to log a BFD message */
void BFD_msg_log (int sess_idx);


#endif /* #ifndef BFD_MSG_H */
