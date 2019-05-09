/************************************************************************
 * File:	EIPM_bfd.h
 *
 * Abstract:	Defines EIPM code to use the Bidirectional Forward Detection
 *		(BFD) protocol.
 *
 ***********************************************************************/

#ifndef EIPM_BFD_H		/* { */
#define EIPM_BFD_H

#include "EIPM_include.h"
#include "BFD_api.h"


/****************************************************************/
/*			Data Definitions			*/
/****************************************************************/

/* Mapping of EIPM_INTFs that contain BFD Service Subnets to
 * EIPM_INTFs that contain BFD Transport Subnets. Array index
 * and elements are both EIPM_INTF indices.
 */
typedef struct {
	int			intf_idx;
	int			sn_idx;
} EIPM_INTF_SN_IDX;

typedef struct {
	EIPM_INTF_SN_IDX	left;
	EIPM_INTF_SN_IDX	right;
	EIPM_INTF_SN_IDX	svc;
	IPM_IPADDRTYPE		ip_type;
	bool			is_bfd_sn;
} EIPM_BFD_MAP_SNGRP;

typedef struct {
	EIPM_BFD_MAP_SNGRP	sns[EIPM_MAX_SUBNETS];
	bool			has_bfd_sn;
} EIPM_BFD_MAP_INTFC;

typedef struct {
	/* Mappings of interface index + subnet index to related subnets
	 * for each of BFD Service, Left BFD Transport, and Right BFD
	 * Transport subnets.
	 */
	EIPM_BFD_MAP_INTFC	intfcs[EIPM_MAX_EXT_SUB];
	bool			populated;	/* Has array been populated? */
} EIPM_BFD_SUBNET_MAP;


/* List of BFD sessions with the fields for auditing against the
 * BFD FSM (see the bfd sub-directory) data.
 */
#define EIPM_BFD_SESS_MAX BFD_SESS_MAX

typedef struct {
	IPM_IPADDR	ipaddr;
	IPM_IPADDR	gateway;
	uint8_t		detection_multiplier;
	uint32_t	desired_min_tx_interval;
	uint32_t	required_min_rx_interval;
} EIPM_BFD_SESS_PARAMS;

typedef struct {
	EIPM_BFD_SESS_PARAMS sessions[EIPM_BFD_SESS_MAX];
	int num_sess;
	int sess_nr;
} EIPM_BFD_SESSIONS_LIST;


/****************************************************************/
/*			Macro Definitions			*/
/****************************************************************/


/****************************************************************/
/*			Function Templates			*/
/****************************************************************/

/* BFD admin functions */
extern int EIPM_bfd_admin_change_cfg_sess(int, int, IPM_IPADDR*);
extern int EIPM_bfd_admin_create_sess(int, int, IPM_IPADDR*, IPM_REDUNDANCY_MODE);
extern int EIPM_bfd_admin_destroy_sess(int, int, IPM_IPADDR*);
extern int EIPM_bfd_admin_set_state_sess(int, int, EIPM_IPDATA*,
                BFD_ADMIN_STATE);

/* BFD Session FSM initialization, stimulus, and call-backs */
extern int EIPM_bfd_fsm_init(BFD_INIT_TYPE);
extern int EIPM_bfd_fsm_start();
extern int EIPM_bfd_fsm_restart();
extern int EIPM_bfd_fsm_add_sockets(fd_set*, int*);
extern int EIPM_bfd_fsm_recv(fd_set*);
extern BFD_RETVAL EIPM_bfd_fsm_cb_audit_sess(IPM_IPADDR*, IPM_IPADDR*,
	uint8_t, uint32_t, uint32_t);

/* Utility functions */
extern void EIPM_bfd_init_subnet_map();
extern int EIPM_bfd_bld_subnet_map();
extern int EIPM_bfd_get_subnet_map(EIPM_BFD_MAP_SNGRP **, int, int);
extern int EIPM_bfd_map_left2right(int, int, int*, int*);
extern int EIPM_bfd_map_right2left(int, int, int*, int*);
extern int EIPM_bfd_map_svc2trans(int, int, int*, int*, int*, int*);
extern int EIPM_bfd_bld_sessions_list();
extern bool EIPM_bfd_admin_state_valid(BFD_ADMIN_STATE);
extern int EIPM_bfd_dump_sessions(EIPM_INTF*, int, IPM_IPADDR*,
                IPM_IPADDR*, IPM_IPADDR*, int, bool*);
extern int EIPM_bfd_dump_sess(EIPM_INTF*, int, int );
extern int EIPM_is_bfd_trans_rsr_svc_sn( int, int );
extern void EIPM_bfd_rsr_svc_sn_trans_sn_chk( int, int );
extern void EIPM_bfd_prt_route( int, int, int, bool);

/* IP Configuration */
extern int EIPM_bfd_ipcfg_check_sn(bool, EIPM_INTF*, EIPM_SUBNET*,
	EIPM_IPDATA*, EIPM_TABLE_ENTRY*, EIPM_INTF_SPEC*, EIPM_NET, int);

/* Stats */
extern void EIPM_bfd_get_stats();
extern int EIPM_bfd_get_stats_intf(register EIPM_INTF*);
extern int EIPM_bfd_get_stats_transports(register EIPM_INTF*);
extern int EIPM_bfd_get_stats_tran_sn(register EIPM_INTF*, int);
extern int EIPM_bfd_get_stats_sess(register EIPM_INTF*, int, int);
extern void EIPM_bfd_clr_stats();
extern int EIPM_bfd_clr_stats_intf(register EIPM_INTF*);
extern int EIPM_bfd_clr_stats_transports(register EIPM_INTF*);
extern int EIPM_bfd_clr_stats_tran_sn(register EIPM_INTF*, int);
extern int EIPM_bfd_clr_stats_sess(register EIPM_INTF*, int, int);

/* Timeouts */
extern int EIPM_bfd_tout();
extern int EIPM_bfd_tout_intf(register EIPM_INTF*, int);
extern int EIPM_bfd_tout_transports(register EIPM_INTF*);
extern int EIPM_bfd_tout_tran_sn(register EIPM_INTF*, int);
extern int EIPM_bfd_tout_sess(register EIPM_INTF*, int, int);
extern int EIPM_bfd_tout_services(register EIPM_INTF*, int);
extern int EIPM_bfd_tout_svc_sn(register EIPM_INTF*, int, int);

/* Audits */
extern int EIPM_bfd_audit();
extern int EIPM_bfd_audit_intf(register EIPM_INTF*, int);
extern int EIPM_bfd_audit_transports(register EIPM_INTF*);
extern int EIPM_bfd_audit_tran_sn(register EIPM_INTF*, int);
extern int EIPM_bfd_audit_sess(register EIPM_INTF*, int, int);
extern int EIPM_bfd_audit_services(register EIPM_INTF*, int);
extern int EIPM_bfd_audit_svc_sn(register EIPM_INTF*, int, int);

/* Alarms */
extern void EIPM_bfd_alarm_sess_set(register EIPM_INTF*,int,int,int,int,char*);
extern void EIPM_bfd_alarm_sess_set_down(register EIPM_INTF*,int,int);
extern void EIPM_bfd_alarm_sess_clr(register EIPM_INTF*,int,int);
extern void EIPM_bfd_alarm_svc_sn_set(register EIPM_INTF*,int,int,int,char*);
extern void EIPM_bfd_alarm_svc_sn_set_miss_tran(register EIPM_INTF*,int,bool,bool);
extern void EIPM_bfd_alarm_svc_sn_clr_miss_tran(register EIPM_INTF*,int);
extern void EIPM_bfd_alarm_svc_sn_chk_miss_tran(int,int);
extern void EIPM_bfd_alarm_svc_sn_set_tran_down(register EIPM_INTF*,int);
extern void EIPM_bfd_alarm_svc_sn_clr_tran_down(register EIPM_INTF*,int);
extern void EIPM_bfd_alarm_tran_sn_set(register EIPM_INTF*,int,int,int,char*);
extern void EIPM_bfd_alarm_tran_sn_set_no_sess(register EIPM_INTF*,int);
extern void EIPM_bfd_alarm_tran_sn_set_sess_down(register EIPM_INTF*,int);
extern void EIPM_bfd_alarm_tran_sn_clr(register EIPM_INTF*,int);

#endif				/* } EIPM_BFD_H */
