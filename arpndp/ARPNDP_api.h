/*************************************************************************
 *
 * File:     ARPNDP_api.h
 *
 * Abstract: external header file of ARP/NDP API module
 *           this module hides internal detailed ARP/NDP implemenation from
 *           external user (EIPM)
 *
 * Nodes:    ARP/NDP external user should include only this file
 *
 ************************************************************************/

#ifndef ARPNDP_API_H
#define ARPNDP_API_H

/* maximum number of ARP/NDP sessions */
#define ARPNDP_SESS_MAX                    256

/*
 * number of IPM sockets excluding ARP/NDP sockets;
 * 100 for IPM sockets
 * 256 * 2 for BFD sockets
 */
#define ARPNDP_NUM_OF_IPM_SOCKS            (100 + (256 * 2))


/* range of OS interface index */
#define ARPNDP_INTF_IDX_MIN                1
#define ARPNDP_INTF_IDX_MAX                256

/* range and default of ARP/NDP detection time multiplier */
#define ARPNDP_DETECT_TIME_MULT_MIN        1
#define ARPNDP_DETECT_TIME_MULT_MAX        50
#define ARPNDP_DETECT_TIME_MULT_DEF        1

/* range and default of ARP/NDP desired min Tx */
#define ARPNDP_MIN_TX_UNIT                 100
#define ARPNDP_MIN_TX_MIN                  (1 * ARPNDP_MIN_TX_UNIT)
#define ARPNDP_MIN_TX_MAX                  (1000 * ARPNDP_MIN_TX_UNIT)
#define ARPNDP_MIN_TX_DEF                  (1 * ARPNDP_MIN_TX_UNIT)

/* range and default of ARP/NDP required min Rx */
#define ARPNDP_MIN_RX_UNIT                 100
#define ARPNDP_MIN_RX_MIN                  (1 * ARPNDP_MIN_RX_UNIT)
#define ARPNDP_MIN_RX_MAX                  (1000 * ARPNDP_MIN_RX_UNIT)
#define ARPNDP_MIN_RX_DEF                  (1 * ARPNDP_MIN_RX_UNIT)


/* ARP/NDP return value */
typedef enum
{
    ARPNDP_SUCCESS,

    ARPNDP_INTERNAL_FAIL, /* failure at LCP inside ARP/NDP outside session */
    ARPNDP_SESS_FAIL,     /* failure at LCP inside ARP/NDP inside session */
    ARPNDP_LOCAL_FAIL,    /* failure at LCP outside ARP/NDP */
    ARPNDP_REMOTE_FAIL,   /* failure at gateway */

    ARPNDP_IGNORE,        /*
                           * neither success nor failure;
                           * ARPNDP_trans_recv() gets other messages;
                           * ignore those messages;
                           */
} ARPNDP_RETVAL;

/* ARP/NDP session state */
typedef enum
{
    ARPNDP_SESS_STATE_ADMIN_DOWN = 0, /* administratively down */
    ARPNDP_SESS_STATE_DOWN       = 1,
    ARPNDP_SESS_STATE_INIT       = 2, /* initialzation */
    ARPNDP_SESS_STATE_UP         = 3,
} ARPNDP_SESS_STATE;

/* ARP/NDP administrative state */
typedef enum
{
    ARPNDP_ADMIN_STATE_DOWN      = 0,
    ARPNDP_ADMIN_STATE_UP        = 1
} ARPNDP_ADMIN_STATE;

/* ARP/NDP initialization type */
typedef enum
{
    ARPNDP_INIT_TYPE_FULL,
    ARPNDP_INIT_TYPE_RESTART
} ARPNDP_INIT_TYPE;

/* ARP/NDP audit sequence */
typedef enum
{
    ARPNDP_AUDIT_SEQ_BEGIN,
    ARPNDP_AUDIT_SEQ_MIDDLE,
    ARPNDP_AUDIT_SEQ_END
} ARPNDP_AUDIT_SEQ;

/* ARP/NDP protocol */
typedef enum
{
    ARPNDP_PROTOCOL_ARP,
    ARPNDP_PROTOCOL_NDP
} ARPNDP_PROTOCOL;


/*
 * call-back function for ARP/NDP implementation to audit an ARP/NDP session
 * with LCP;
 *
 * LCP should implement the following logic:
 *
 * if ARP/NDP session exists at LCP
 *     if ARP/NDP session parameters are the same
 *         return ARPNDP_SUCCESS
 *     else
 *         ARPNDP_change_cfg()
 *         return ARPNDP_SUCCESS
 *     end if
 * else
 *     return ARPNDP_INTERNAL_FAIL
 * end if
 */
typedef ARPNDP_RETVAL (* ARPNDP_AUDIT_CB_FUNC)(int intf_idx,
    IPM_IPADDR *remote_ip, IPM_IPADDR *local_ip, uint8_t detect_time_mult,
    uint32_t min_tx, uint32_t min_rx);


/* function to initialize all ARP/NDP modules */
ARPNDP_RETVAL ARPNDP_init (ARPNDP_AUDIT_CB_FUNC audit_cb_func,
    void *_arpndp_data, ARPNDP_INIT_TYPE init_type);


/* function to create a new ARP/NDP session */
ARPNDP_RETVAL ARPNDP_create_sess (int intf_idx, IPM_IPADDR *remote_ip,
    IPM_IPADDR *local_ip, uint8_t detect_time_mult, uint32_t min_tx,
    uint32_t min_rx);

/* function to destroy an existing ARPND/ND session */
void ARPNDP_destroy_sess (int intf_idx, IPM_IPADDR *remote_ip);

/*
 * function to change ARP/NDP session parameters after ARP/NDP session has
 * been created
 */
ARPNDP_RETVAL ARPNDP_change_cfg (int intf_idx, IPM_IPADDR *remote_ip,
    IPM_IPADDR *local_ip, uint8_t detect_time_mult, uint32_t min_tx,
    uint32_t min_rx);


/* function to get session state of an ARP/NDP session */
ARPNDP_RETVAL ARPNDP_get_sess_state (int intf_idx, IPM_IPADDR *remote_ip,
    ARPNDP_SESS_STATE *sess_state);

/* function to set administrative state of an ARP/NDP session */
ARPNDP_RETVAL ARPNDP_set_admin_state (int intf_idx, IPM_IPADDR *remote_ip,
    ARPNDP_ADMIN_STATE admin_state);


/* function to get statistics/counts of an ARP/NDP session */
ARPNDP_RETVAL ARPNDP_get_stats (int intf_idx, IPM_IPADDR *remote_ip,
    uint32_t *missed_hb);

/* function to clear statistics/counts of an ARP/NDP session */
void ARPNDP_clear_stats (int intf_idx, IPM_IPADDR *remote_ip);


/* function to call every 5 milli-seconds to implement ARP/NDP timers */
void ARPNDP_timer();

/* function to call before pselect() to add ARP/NDP sockets */
void ARPNDP_add_sockets (fd_set *read_sock_set, int *max_fd);

/*
 * function to call when ARP/NDP sockets have incoming messages;
 * read_sock_set has all IPM sockets, including non-ARP/NDP sockets
 */
void ARPNDP_recv (fd_set *read_sock_set);

/* function for LCP to audit an ARP/NDP session with ARP/NDP implementation */
void ARPNDP_audit (int intf_idx, IPM_IPADDR *remote_ip,
    IPM_IPADDR *local_ip, uint8_t detect_time_mult, uint32_t min_tx,
    uint32_t min_rx, ARPNDP_AUDIT_SEQ begin_middle_end);


/* function for CLI to log internal data of all ARP/NDP sessions */
void ARPNDP_log_data();

/*
 * function for CLI to log statistics/counts of ARP/NDP protocol
 * and all ARP/NDP sessions
 */
void ARPNDP_log_stats();



/* end of ARP/NDP API */

/*
 * the following constants and data types are internal to ARP/NDP;
 * they are here for shared memory allocation;
 * external user should not use them
 */



/* maximum number of ARP/NDP history per ARP/NDP session */
#define ARPNDP_HISTORY_MAX              100

/*
 * whether to log ARP/NDP session data and ARP/NDP history
 * when logging ARP/NDP statistics/counts
 */
/* #define ARPNDP_LOG_SESS_HIST_W_STATS */

/* maximum string length of OS interface name */
#define ARPNDP_INTF_NAME_LEN_MAX       50

/* range of socket file descriptor */
#define ARPNDP_SOCK_MIN                 3
#define ARPNDP_SOCK_MAX                 (ARPNDP_SOCK_MIN + ARPNDP_NUM_OF_IPM_SOCKS + ARPNDP_SESS_MAX)


/* range of timer */
#define ARPNDP_TIMER_MIN                ARPNDP_MIN_RX_MIN
#define ARPNDP_TIMER_MAX                (ARPNDP_MIN_RX_MAX * ARPNDP_DETECT_TIME_MULT_MAX)



/* ARP/NDP session data */
#pragma pack (push)
#pragma pack (1)
typedef struct _ARPNDP_SESS
{
    uint32_t        key_add;
    uint32_t        key_xor;            /*
                                         * keys of ARP/NDP session data using
                                         * OS interface index and remote IP
                                         */

    int             intf_idx;           /* OS interface index */
    IPM_IPADDR      remote_ip;          /* remote IP */

    IPM_IPADDR      local_ip;           /* local IP */
    uint32_t        local_ip_checksum;

    uint8_t         detect_time_mult;   /* detection time multiplier */
    uint32_t        min_tx;             /* desired min Tx */
    uint32_t        min_rx;             /* required min Rx */

                                        /* OS interface name */
    char            intf_name[ARPNDP_INTF_NAME_LEN_MAX + 1];
    unsigned char   mac_addr[ETH_ALEN]; /* MAC address */
    unsigned char   intf_data_checksum;

    ARPNDP_PROTOCOL protocol;           /* ARP, NDP, etc. */
    ARPNDP_ADMIN_STATE admin_state;     /* administrative state */
    ARPNDP_SESS_STATE sess_state;       /* session state */
    BOOL            has_recv_msg;       /*
                                         * whether has received message for
                                         * current fault detection timer
                                         * interval
                                         */



    int transmission_timer;
    int transmission_timer_countdown;

    int fault_detect_timer_fire_num;    /*
                                         * number of times fault detection
                                         * timer has fired since last timer
                                         * (re)start
                                         */



    int             sock;               /*
                                         * socket to send/receive ARP/NDP
                                         * message
                                         */

    uint32_t        recv_count;         /*
                                         * number of messages received since
                                         * last session state change
                                         */
    uint32_t        send_count;         /*
                                         * number of messages sent since
                                         * last session state change
                                         */



    BOOL            audited;            /*
                                         * whether this ARP/NDP session has been
                                         * audited
                                         */



    uint32_t        missed_hb;        /* missing ARP/NDP heartbeats */
} ARPNDP_SESS;
#pragma pack (pop)



/* ARN/NDP history */
#pragma pack (push)
#pragma pack (1)
typedef struct _ARPNDP_HISTORY
{
    uint8_t   history_type;
    uint32_t  history_data;
} ARPNDP_HISTORY;
#pragma pack (pop)



/* statistics/counts of ARP/NDP protocol */
typedef struct _ARPNDP_STATS
{
    uint32_t good_create;
    uint32_t good_change_cfg;
    uint32_t good_destroy;
    uint32_t good_get_sess_state;
    uint32_t good_set_admin_state;
    uint32_t good_get_stats;
    uint32_t good_timer;
    uint32_t good_add_sockets;
    uint32_t good_audit;
    uint32_t good_recv;
    uint32_t recv_no_sess;

    uint32_t arpndp_size_error;

    uint32_t not_single_thread;
    uint32_t arpndp_has_init;

    uint32_t inv_init_type;

    uint32_t inv_intf_idx;
    uint32_t inv_remote_ip;
    uint32_t inv_local_ip;
    uint32_t inv_local_ip_type;
    uint32_t inv_detect_time_mult;
    uint32_t inv_min_tx;
    uint32_t inv_min_rx;
    uint32_t inv_protocol;

    uint32_t inv_sess_state_ptr;
    uint32_t inv_admin_state;
    uint32_t inv_missed_hb_ptr;
    uint32_t inv_read_sock_set_ptr;
    uint32_t inv_begin_middle_end;

    uint32_t corrupt_audit_cb_func;
    uint32_t ext_audit;

    uint32_t not_enough_sess;
    uint32_t inv_arpndp_sess_num;
    uint32_t sess_not_found;
    uint32_t inv_intf_idx_remote_ip;

    uint32_t int_audit_minor;
    uint32_t int_audit_major;

    uint32_t inv_history_cur_idx;

    uint32_t inv_sess_state;
    uint32_t inv_event;
    uint32_t unexpect_event;

    uint32_t socket_fail;
    uint32_t bind_fail;
    uint32_t ioctl_fail;
    uint32_t set_sock_opt_fail;
    uint32_t connect_fail;
    uint32_t close_fail;

    uint32_t send_msg_fail;
    uint32_t send_fail;

    uint32_t recv_msg_fail;
    uint32_t recv_fail;

    uint32_t ctl_len_zero;
    uint32_t inv_cmsg_type;
    uint32_t inv_cmsg_level;
} ARPNDP_STATS;


/* statistics/counts of ARP/NDP sessions */
typedef struct _ARPNDP_SESS_STATS
{
    uint32_t good_recv;
    uint32_t good_send;

    uint32_t inv_recv_intf_idx;

    uint32_t not_arp_reply;
    uint32_t not_nd_advert;
    uint32_t diff_remote_ip;
    uint32_t diff_local_ip;
} ARPNDP_SESS_STATS;



/* all of ARP/NDP data */
typedef struct _ARPNDP_DATA
{
    ARPNDP_SESS       sess[ARPNDP_SESS_MAX];
    int               sess_num;

    ARPNDP_HISTORY    hist[ARPNDP_SESS_MAX][ARPNDP_HISTORY_MAX];
    int               hist_cur_idx[ARPNDP_SESS_MAX];

    ARPNDP_STATS      stats;
    ARPNDP_SESS_STATS sess_stats[ARPNDP_SESS_MAX];
} ARPNDP_DATA;



#endif /* #ifndef ARPNDP_API_H */
