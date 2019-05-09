/*************************************************************************
 *
 * File:     ARPNDP_int_hdr.h
 *
 * Abstract: internal header file of ARP/NDP implemenation
 *
 * Nodes:    ARP/NDP implementation files should include only this file
 *
 ************************************************************************/

#ifndef ARPNDP_INT_HDR_H
#define ARPNDP_INT_HDR_H


/* standard header files for all platforms */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef ARPNDP_STAND_ALONE
/* standard header files for stand-alone or simulators */

#include "ARPNDP_stand_alone.h"

#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#define __USE_GNU
#include <netinet/in.h>
#include <sys/select.h>
#include <arpa/inet.h>

#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <netinet/icmp6.h>

struct arp_pkt
{
    struct ethhdr eth_hdr;
    struct ether_arp arp;
} __attribute__((packed));

struct arp6_pkt {
    struct nd_neighbor_advert na;
    struct nd_opt_hdr opt_hdr;
    char hw_addr[ETH_ALEN];
} __attribute__((packed));

#else /* #ifdef ARPNDP_STAND_ALONE */

/* standard header files for official LCP */
#include "EIPM_include.h"

#endif /* #ifdef ARPNDP_STAND_ALONE */


/* ARP/NDP API/external header file */
#include "ARPNDP_api.h"

/* ARP/NDP internal header files */

#include "ARPNDP_error.h"

#include "ARPNDP_sess_data.h"
#include "ARPNDP_history.h"
#include "ARPNDP_enum_to_str.h"

#include "ARPNDP_timer.h"
#include "ARPNDP_trans.h"

#include "ARPNDP_fsm.h"
#include "ARPNDP_sess.h"

#include "ARPNDP_stats.h"


/* seed to calculation checksum */
#define ARPNDP_CHECKSUM_SEED       0x5a5a5a5a5a5a5a5aULL


/* pointer to all ARP/NDP data in shared memory */
extern ARPNDP_DATA *arpndp_data;

/* current time */
extern unsigned int arpndp_cur_time;


/*
 * Call-back function for ARP/NDP implementation to audit ARP/NDP session
 * with LCP
 */
extern ARPNDP_AUDIT_CB_FUNC arpndp_audit_cb_func;

/* Checksum of the above function pointer to detect memory corruption */
extern unsigned long arpndp_audit_cb_func_checksum;


#endif /* #ifndef ARPNDP_INT_HDR_H */
