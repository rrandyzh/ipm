/************************************************************************
 * File:	EIPM_arpndp.h
 *
 * Abstract:	Defines EIPM code to use ARP/NDP as defined in the
 *		ipm/arpndp directory
 *
 ***********************************************************************/

#ifndef EIPM_ARPNDP_H		/* { */
#define EIPM_ARPNDP_H

#include "EIPM_include.h"
#include "ARPNDP_api.h"

/****************************************************************/
/*			Macros		 			*/
/****************************************************************/

/* Maps an EIPM interface index (i.e. index in the SHM intf_data[] array)
 * to an OS interface index (i.e. lsn0_iface_indx or lsn1_iface_indx).
 * The interface contains a BFD Transport. If it's a Left Transport
 * then lsn0_iface_indx will be populated but lsn1_iface_indx might
 * also be populated is it shares an EIPM_INTF with a BFD Service
 * subnet. If it's Right Transport then lsn1_iface_indx will be
 * populated and lsn0_iface_indx will not be populated.
 */
#define EIPM2OS_INTF_IDX(eidx) (					\
  ( ((EIPM_DATA *)EIPM_shm_ptr)->intf_data[eidx].specData.lsn0_iface_indx > 0 )\
    ? ((EIPM_DATA *)EIPM_shm_ptr)->intf_data[eidx].specData.lsn0_iface_indx \
    : ((EIPM_DATA *)EIPM_shm_ptr)->intf_data[eidx].specData.lsn1_iface_indx \
  )
	

/****************************************************************/
/*			Function Templates			*/
/****************************************************************/

extern int EIPM_arpndp_fsm_init(ARPNDP_INIT_TYPE);
extern int EIPM_arpndp_fsm_start();
extern int EIPM_arpndp_fsm_restart();
extern int EIPM_arpndp_fsm_add_sockets(fd_set *, int *);
extern int EIPM_arpndp_fsm_recv(fd_set *);
extern int EIPM_arpndp_start(int, int);
extern int EIPM_arpndp_stop(int, int);
extern int EIPM_arpndp_get_status(int, int, EIPM_STATUS*);
extern int EIPM_arpndp_admin_change_cfg_sess(int, EIPM_SUBNET*, IPM_IPADDR*);
extern int EIPM_arpndp_admin_create_sess(int, EIPM_SUBNET*, IPM_IPADDR*);
extern int EIPM_arpndp_admin_destroy_sess(int, IPM_IPADDR*);
extern int EIPM_arpndp_admin_set_state_sess(int, IPM_IPADDR*, IPM_IPADDR*,
		ARPNDP_ADMIN_STATE);
extern int EIPM_arpndp_dump_sessions( EIPM_INTF*, int, IPM_IPADDR*,
                IPM_IPADDR*, IPM_IPADDR*, int, bool*);
extern int EIPM_arpndp_dump_sess(EIPM_INTF*, int);
extern int EIPM_arpndp_tout();
extern int EIPM_arpndp_tout_intf(EIPM_INTF*, int);
extern int EIPM_arpndp_tout_sn(EIPM_INTF*, int);
extern void EIPM_arpndp_alarm_sn_set(EIPM_INTF*, int);
extern void EIPM_arpndp_alarm_sn_clr(EIPM_INTF*, int);

#endif				/* } EIPM_ARPNDP_H */
