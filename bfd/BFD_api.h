/*************************************************************************
 *
 * File:     BFD_api.h
 *
 * Abstract: external header file of BFD API module
 *           this module hides internal detailed BFD implemenation from
 *           external user (EIPM)
 *
 * Nodes:    BFD external user should include only this file
 *
 ************************************************************************/

#ifndef BFD_API_H
#define BFD_API_H

/* maximum number of BFD sessions */
#define BFD_SESS_MAX                    256


/*
 * number of IPM sockets excluding BFD sockets;
 * 100 for IPM
 * 256 for ARP/NDP
 */
#define BFD_NUM_OF_IPM_SOCKS            (100 + 256)


/* range and default of BFD detection time multiplier */
#define BFD_DETECT_TIME_MULT_MIN        3
#define BFD_DETECT_TIME_MULT_MAX        50
#define BFD_DETECT_TIME_MULT_DEF        3

/* range and default of BFD desired min Tx */
#define BFD_MIN_TX_UNIT                 100
#define BFD_MIN_TX_MIN                  (1 * BFD_MIN_TX_UNIT)
#define BFD_MIN_TX_MAX                  (1000 * BFD_MIN_TX_UNIT)
#define BFD_MIN_TX_DEF                  (1 * BFD_MIN_TX_UNIT)

/* range and default of BFD required min Rx */
#define BFD_MIN_RX_UNIT                 100
#define BFD_MIN_RX_MIN                  (1 * BFD_MIN_RX_UNIT)
#define BFD_MIN_RX_MAX                  (1000 * BFD_MIN_RX_UNIT)
#define BFD_MIN_RX_DEF                  (1 * BFD_MIN_RX_UNIT)



/* BFD return value */
typedef enum
{
    BFD_SUCCESS,

    BFD_INTERNAL_FAIL, /* failure at LCP inside BFD outside session */
    BFD_SESS_FAIL,     /* failure at LCP inside BFD inside session */
    BFD_LOCAL_FAIL,    /* failure at LCP outside BFD */
    BFD_REMOTE_FAIL,   /* failure at first-hop router */

    BFD_IGNORE,        /*
                        * neither success nor failure;
                        * BFD_trans_recv() gets other messages;
                        * ignore those messages;
                        */
} BFD_RETVAL;

/* BFD session state */
typedef enum
{
    BFD_SESS_STATE_ADMIN_DOWN = 0, /* administratively down */
    BFD_SESS_STATE_DOWN       = 1,
    BFD_SESS_STATE_INIT       = 2, /* initialzation */
    BFD_SESS_STATE_UP         = 3,
} BFD_SESS_STATE;

/* BFD administrative state */
typedef enum
{
    /* do not use values in BFD_SESS_STATE */
    BFD_ADMIN_STATE_DOWN      = 4,
    BFD_ADMIN_STATE_UP        = 5
} BFD_ADMIN_STATE;

/* BFD initialization type */
typedef enum
{
    BFD_INIT_TYPE_FULL,
    BFD_INIT_TYPE_RESTART
} BFD_INIT_TYPE;

/* BFD audit sequence */
typedef enum
{
    BFD_AUDIT_SEQ_BEGIN,
    BFD_AUDIT_SEQ_MIDDLE,
    BFD_AUDIT_SEQ_END
} BFD_AUDIT_SEQ;


/*
 * call-back function for BFD implementation to audit a BFD session with
 * LCP;
 *
 * LCP should implement the following logic:
 *
 * if BFD session exists at LCP
 *     if BFD session parameters are the same
 *         return BFD_SUCCESS
 *     else
 *         BFD_change_cfg()
 *         return BFD_SUCCESS
 *     end if
 * else
 *     return BFD_INTERNAL_FAIL
 * end if
 */
typedef BFD_RETVAL (* BFD_AUDIT_CB_FUNC)(IPM_IPADDR *local_ip,
    IPM_IPADDR *remote_ip, uint8_t detect_time_mult,
    uint32_t min_tx, uint32_t min_rx);

/*
 * call-back function for BFD to report session state change to LCP
 */
typedef void (* BFD_STATE_CHANGE_CB_FUNC)(IPM_IPADDR *local_ip,
    IPM_IPADDR *remote_ip, BFD_SESS_STATE sess_state);


/* function to initialize all BFD modules */
BFD_RETVAL BFD_init (BFD_AUDIT_CB_FUNC audit_cb_func,
    BFD_STATE_CHANGE_CB_FUNC state_change_cb_func,
    void *_bfd_data, BFD_INIT_TYPE init_type);



/* function to create a new BFD session */
BFD_RETVAL BFD_create_sess (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    uint8_t detect_time_mult, uint32_t min_tx, uint32_t min_rx);

/*
 * function to change BFD session parameters after BFD session has been
 * created
 */
BFD_RETVAL BFD_change_cfg (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    uint8_t detect_time_mult, uint32_t min_tx, uint32_t min_rx);

/* function to destroy an existing BFD session */
void BFD_destroy_sess (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip);


/* function to get session state of a BFD session */
BFD_RETVAL BFD_get_sess_state (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    BFD_SESS_STATE *sess_state);

/* function to set administrative state of a BFD session */
BFD_RETVAL BFD_set_admin_state (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    BFD_ADMIN_STATE admin_state);


/* function to get statistics/counts of a BFD session */
BFD_RETVAL BFD_get_stats (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    uint32_t *missed_hb, uint32_t *corrupt_pkt);

/* function to clear statistics/counts of a BFD session */
void BFD_clear_stats (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip);


/* function to call every 5 milli-seconds to implement BFD timers */
void BFD_timer();


/* function to call before pselect() to add BFD sockets */
void BFD_add_sockets (fd_set *read_sock_set, int *max_fd);

/*
 * function to call when BFD sockets have incoming messages;
 * read_sock_set has all IPM sockets, including non-BFD sockets
 */
void BFD_recv (fd_set *read_sock_set);


/* function for LCP to audit BFD session with BFD implemention */
void BFD_audit (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    uint8_t detect_time_mult, uint32_t min_tx, uint32_t min_rx,
    BFD_AUDIT_SEQ begin_middle_end);


/* function for CLI to log BFD internal data of all BFD sessions */
void BFD_log_data();

/*
 * function for CLI to log BFD statistics/counts of BFD protocol
 * and all BFD sessions
 */
void BFD_log_stats();




/* end of BFD API */

/*
 * the following constants and data types are internal to BFD;
 * they are here for shared memory allocation;
 * external user should not use them
 */



/* maximum size of received BFD message */
#define BFD_MAX_MSG_SIZE		25

/* maximum number of BFD history per BFD session */
#define BFD_HISTORY_MAX                 100

/*
 * whether to log BFD session data and BFD history
 * when logging BFD statistics/counts
 */
/* #define BFD_LOG_SESS_HIST_W_STATS */

/* whether to enable listening timer functionality */
#define BFD_LISTEN_TIMER_ENABLED


/* range of socket file descriptor */
#define BFD_SOCK_MIN                    3
#define BFD_SOCK_MAX  (BFD_SOCK_MIN + BFD_NUM_OF_IPM_SOCKS + (BFD_SESS_MAX * 2))


/* range of timer */
#define BFD_TIMER_MIN                  BFD_MIN_RX_MIN
#define BFD_TIMER_MAX  (BFD_MIN_RX_MAX * BFD_DETECT_TIME_MULT_MAX)



/* active or passive role */
typedef enum
{
    BFD_ROLE_ACTIVE  = 0,
    BFD_ROLE_PASSIVE = 1
} BFD_ROLE;


/* BFD diagnostic code */
typedef enum
{
    BFD_DIAG_NONE                     = 0,
    BFD_DIAG_CTL_DETECT_TIME_EXPIRED  = 1, /* control detection time expired */
    BFD_DIAG_ECHO_FUNC_FAILED         = 2, /* echo function failed */
    BFD_DIAG_NEIGHBOR_SIG_SESS_DOWN   = 3, /* neighbor signaled session down */
    BFD_DIAG_FWD_PLANE_RESET          = 4, /* forwarding planed reset */
    BFD_DIAG_PATH_DOWN                = 5, /* path down */
    BFD_DIAG_CONCAT_PATH_DOWN         = 6, /* concatenated path down */
    BFD_DIAG_ADMIN_DOWN               = 7, /* administratively down */
    BFD_DIAG_REVERSE_CONCAT_PATH_DOWN = 8  /* reverse concatenated path down */
} BFD_DIAGNOSTIC;


/*
 * BFD message of BFD protocol;
 * used between 2 ends of a BFD session
 */
#pragma pack (push)
#pragma pack (1)
typedef struct _BFD_MSG
{
#if BYTE_ORDER == LITTLE_ENDIAN
    unsigned int diagnostic           :5;
    unsigned int version              :3;
#else /* #if BYTE_ORDER == LITTLE_ENDIAN */
    unsigned int version              :3;
    unsigned int diagnostic           :5;
#endif /* #if BYTE_ORDER == LITTLE_ENDIAN */

#if BYTE_ORDER == LITTLE_ENDIAN
    unsigned int multi_point_flag     :1;
    unsigned int demand_flag          :1;
    unsigned int auth_present_flag    :1; /* authentication present */
    unsigned int ctl_plane_indpd_flag :1; /* control plane independent */
    unsigned int final_flag           :1;
    unsigned int poll_flag            :1;

    unsigned int sess_state           :2; /* session state */
#else /* #if BYTE_ORDER == LITTLE_ENDIAN */
    unsigned int sess_state           :2; /* session state */

    unsigned int poll_flag            :1;
    unsigned int final_flag           :1;
    unsigned int ctl_plane_indpd_flag :1; /* control plane independent */
    unsigned int auth_present_flag    :1; /* authentication present */
    unsigned int demand_flag          :1;
    unsigned int multi_point_flag     :1;
#endif /* #if BYTE_ORDER == LITTLE_ENDIAN */

    unsigned int detect_time_mult     :8; /* detection time multiplier */
    unsigned int length               :8;

    uint32_t     my_discr;         /* my discriminator */
    uint32_t     your_discr;       /* your descriminator */
    uint32_t     min_tx;           /* desired min Tx interval */
    uint32_t     min_rx;           /* required min Rx interval */
    uint32_t     min_echo_rx;      /* required min echo Rx interval */
} BFD_MSG;
#pragma pack (pop)


/* BFD session data */
#pragma pack (push)
#pragma pack (1)
typedef struct _BFD_SESS
{
    uint32_t        key_add;
    uint32_t        key_xor;          /*
                                       * keys of BFD session data using
                                       * local IP and remote IP
                                       */

    IPM_IPADDR      local_ip;         /* local IP of this BFD session */
    IPM_IPADDR      remote_ip;        /* remote IP of this BFD session */

    BFD_ROLE        active_passive;   /* active or passive role */
    BFD_ADMIN_STATE admin_state;      /* administrative state */
    BOOL            local_poll_seq;   /* whether in local poll sequence */
    BOOL            has_recv_msg;     /*
                                       * whether has received message for
                                       * current fault detection timer
                                       * interval
                                       */


    struct
    {
        BFD_DIAGNOSTIC diagnostic;
        BFD_SESS_STATE sess_state;    /* session state */
        uint8_t        detect_time_mult; /* detection time multiplier */
        uint32_t       discriminator;

        uint32_t       cfg_min_tx;    /* configured desired min Tx interval */

        struct
        {
            uint32_t   min_tx;        /* official desired min Tx interval */
            uint32_t   min_rx;        /* official required min Rx interval */
        } ofc;

        struct
        {
            uint32_t   min_tx;        /* transition desired min Tx interval */
            uint32_t   min_rx;        /*
                                       * transition required min Rx interval
                                       */
        } trans;
    } local;

    struct
    {
        BFD_DIAGNOSTIC diagnostic;
        BFD_SESS_STATE sess_state;    /* session state */
        uint8_t        detect_time_mult; /* detection time multiplier */
        uint32_t       discriminator;

        uint32_t       min_tx;        /* desired min Tx interval */
        uint32_t       min_rx;        /* required min Rx interval */
    } remote;



#ifdef BFD_LISTEN_TIMER_ENABLED
    int listen_timer;                 /* listening timer */
    int listen_timer_countdown;
#endif /* #ifdef BFD_LISTEN_TIMER_ENABLED */

    int transmission_timer;
    int transmission_timer_countdown;

    int fault_detect_timer;           /* fault detection timer */
    int fault_detect_timer_countdown;
    int fault_detect_timer_fire_num;  /*
                                       * number of times fault detection
                                       * timer has fired since last timer
                                       * (re)start
                                       */



    int             recv_sock;        /* socket to receive BFD message */

    char            recv_msg[BFD_MAX_MSG_SIZE];
				      /* received BFD/UDP message */

    struct iovec    recv_msg_iov[1];  /* I/O vector for recv_msg */

    char            recv_ttl_buffer[CMSG_SPACE(sizeof(int))];
                                      /*
                                       * buffer for control message to
                                       * receive TTL
                                       */

    struct msghdr   recv_msg_hdr;     /* message header for recvmsg() */

    unsigned long   recv_msg_hdr_checksum;



    unsigned short  local_send_port;  /*
                                       * local UDP port to send BFD message;
                                       * in host byte-order
                                       */
    int             send_sock;        /* socket to send BFD message */

    BFD_MSG         send_msg;         /* BFD/UDP message to send */

                                      /* remote socket address to send */
    struct sockaddr_in  send_remote_sock_addr_ipv4;
    struct sockaddr_in6 send_remote_sock_addr_ipv6;
    struct sockaddr *   send_remote_sock_addr;
    int                 send_remote_sock_addr_len;

    unsigned long       send_remote_sock_addr_checksum;

                                      /* remote socket address to receive */
    struct sockaddr_in  recv_remote_sock_addr_ipv4;
    struct sockaddr_in6 recv_remote_sock_addr_ipv6;
    unsigned short *    recv_port;



    uint32_t        recv_count;       /*
                                       * number of messages received since
                                       * last local session state change
                                       */
    uint32_t        send_count;       /*
                                       * number of messages sent since
                                       * last local session state change
                                       */



    BOOL            audited;          /*
                                       * whether this BFD session has been
                                       * audited
                                       */



    uint32_t        missed_hb;        /* missing BFD heartbeats */
    uint32_t        corrupt_pkt;      /* corrupt BFD packets */
} BFD_SESS;
#pragma pack (pop)



/* BFD history */
#pragma pack (push)
#pragma pack (1)
typedef struct _BFD_HISTORY
{
    uint8_t   history_type;
    uint32_t  history_data;
} BFD_HISTORY;
#pragma pack (pop)



/* BFD statistics/counts of BFD protocol */
typedef struct _BFD_STATS
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

    uint32_t bfd_size_error;

    uint32_t not_single_thread;
    uint32_t bfd_has_init;

    uint32_t inv_init_type;

    uint32_t inv_local_ip;
    uint32_t inv_remote_ip;
    uint32_t inv_remote_local_ip_type;
    uint32_t inv_detect_time_mult;
    uint32_t inv_min_tx;
    uint32_t inv_min_rx;

    uint32_t inv_sess_state_ptr;
    uint32_t inv_admin_state;
    uint32_t inv_missed_hb_ptr;
    uint32_t inv_corrupt_pkt_ptr;
    uint32_t inv_read_sock_set_ptr;
    uint32_t inv_begin_middle_end;

    uint32_t corrupt_audit_cb_func;
    uint32_t ext_audit;

    uint32_t corrupt_state_change_cb_func;
    uint32_t inv_local_ofc_min_tx;

    uint32_t not_enough_sess;
    uint32_t inv_bfd_sess_num;
    uint32_t sess_not_found;
    uint32_t inv_local_ip_remote_ip;

    uint32_t local_poll_seq_in_progress;

    uint32_t int_audit_minor;
    uint32_t int_audit_major;

    uint32_t inv_history_cur_idx;

    uint32_t inv_local_state;
    uint32_t inv_event;
    uint32_t unexpect_event;

    uint32_t socket_fail;
    uint32_t set_sock_opt_fail;
    uint32_t close_fail;

    uint32_t corrupt_remote_sock_addr;
    uint32_t send_to_fail;

    uint32_t corrupt_recv_msg_hdr;
    uint32_t recv_msg_fail;
    uint32_t ctl_len_zero;
    uint32_t inv_cmsg_type;
    uint32_t inv_cmsg_level;
} BFD_STATS;


/* BFD statistics/counts of BFD sessions */
typedef struct _BFD_SESS_STATS
{
    uint32_t good_encode;
    uint32_t good_decode;

    uint32_t inv_remote_version;
    uint32_t inv_remote_diagnostic;
    uint32_t inv_remote_sess_state;

    uint32_t remote_both_poll_and_final;
    uint32_t inv_remote_auth_present_flag;
    uint32_t inv_remote_demand_flag;
    uint32_t inv_remote_multi_point_flag;

    uint32_t inv_remote_detect_time_mult;
    uint32_t inv_remote_length;
    uint32_t inv_remote_my_discr;
    uint32_t inv_remote_your_discr;
    uint32_t inv_remote_min_echo_rx;

    uint32_t good_recv;
    uint32_t good_send;

    uint32_t recv_sock_bind_fail;
    uint32_t send_sock_bind_fail;

    uint32_t inv_recv_ttl;
    uint32_t inv_recv_hop_limit;
} BFD_SESS_STATS;



/* all of BFD data */
typedef struct _BFD_DATA
{
    BFD_SESS        sess[BFD_SESS_MAX];
    int             sess_num;

    BFD_HISTORY     hist[BFD_SESS_MAX][BFD_HISTORY_MAX];
    int             hist_cur_idx[BFD_SESS_MAX];

    BFD_STATS       stats;
    BFD_SESS_STATS  sess_stats[BFD_SESS_MAX];
} BFD_DATA;



#endif /* #ifndef BFD_API_H */
