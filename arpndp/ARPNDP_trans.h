/*************************************************************************
 *
 * File:     ARPNDP_trans.h
 *
 * Abstract: internal header file of ARP/NDP transport module
 *           this module sends/receives ARP/NDP message
 *
 * Nodes:    ARP/NDP implemenation should include only ARPNDP_int_data.h
 *           instead of this file
 *
 ************************************************************************/

#ifndef ARPNDP_TRANS_H
#define ARPNDP_TRANS_H


/* base port for temporary socket to connect */
#define ARPNDP_TEMP_SOCK_PORT_BASE     1025

/* number of attemps for temporary socket to connect */
#define ARPNDP_TEMP_SOCK_CONNECT_MAX    2

/* receive buffer size */
#define ARPNDP_RECV_BUF_SIZE            256


/* function to get OS interface data (name, MAC address, etc. */
ARPNDP_RETVAL ARPNDP_trans_get_intf_data (int sess_idx);


/* function to create a socket to send/receive ARP/NDP message */
ARPNDP_RETVAL ARPNDP_trans_create_sock (int sess_idx);

/* function to close ARP/NDP socket */
void ARPNDP_trans_close_sock (int sess_idx);


/* function to receive ARP/NDP message */
ARPNDP_RETVAL ARPNDP_trans_recv (int sess_idx);

/* function to send ARP/NDP message */
ARPNDP_RETVAL ARPNDP_trans_send (int sess_idx);


#endif /* #ifndef ARPNDP_TRANS_H */
