/*************************************************************************
 *
 * File:     BFD_trans.h
 *
 * Abstract: internal header file of BFD transport module
 *           this module sends/receives BFD message using UDP/IP
 *
 * Nodes:    BFD implemenation should include only BFD_int_data.h instead
 *           of this file
 *
 ************************************************************************/

#ifndef BFD_TRANS_H
#define BFD_TRANS_H


/* popular UDP port to receive BFD control message */
#define BFD_RECV_CTL_PORT           3784

/*
 * UDP port to send BFD control messages is 49152 to 65535
 * with 16383 possible values
 */
#define BFD_SEND_CTL_PORT_BASE      49152

/* IPv4 TTL that MME sends to first-hop router */
#define BFD_IPV4_SEND_TTL            255

/* IPv4 TTL that MME receives from first-hop router */
#define BFD_IPV4_RECV_TTL            255

/* IPv6 hop limit that MME sends to first-hop router */
#define BFD_IPV6_SEND_HOP_LIMIT      255

/* IPv6 hop limit that MME receives from first-hop router */
#define BFD_IPV6_RECV_HOP_LIMIT      255


/* function to create a UDP socket to receive BFD control message */
BFD_RETVAL BFD_trans_create_recv_sock (int sess_idx);

/* function to create a UDP socket to send BFD control message */
BFD_RETVAL BFD_trans_create_send_sock (int sess_idx);


/* function to close receive and send UDP sockets */
void BFD_trans_close_sockets (int sess_idx);


/* function to receive BFD/UDP message */
BFD_RETVAL BFD_trans_recv (int sess_idx);

/* function to send BFD/UDP message */
BFD_RETVAL BFD_trans_send (int sess_idx);


#endif /* #ifndef BFD_TRANS_H */
