/*************************************************************************
 *
 * File:     ARPNDP_api.c
 *
 * Abstract: implementation file of ARP/NDP API module
 *           this module hides internal detailed ARP/NDP implemenation from
 *           external user (EIPM)
 *
 * Data:
 *     arpndp_has_init                   - whether ARP/NDP has initialized
 *                                         successfully
 *
 *     arpndp_data                       - pointer to all ARP/NDP data in
 *                                         shared memory
 *     arpndp_data_checksum              - checksum of the above pointer to
 *                                         detect memory corruption
 *
 *     arpndp_thread_id                  - current thread that executes
 *                                         ARP/NDP code
 *
 *     arpndp_cur_time                   - current time in multiples of 5
 *                                         milli-seconds
 *
 *     arpndp_audit_timer                - internal audit timer
 *     arpndp_audit_timer_first_sess     - whether first ARP/NDP session in a   
 *                                         round of internal audit
 *     arpndp_audit_sess_idx             - current ARP/NDP session index of 
 *                                         internal audit 
 *     
 *     arpndp_log_stats_timer            - log statistics/counts timer
 *     arpndp_log_stats_timer_first_sess - wheher first ARP/NDP session in a
 *                                         round of statistic/count log
 *     arpndp_log_stats_sess_idx         - current ARP/NDP session index of
 *                                         statistic/count log
 *
 *     arpndp_audit_cb_func              - call-back function for ARP/NDP
 *                                         implementation to audit ARP/NDP
 *                                         session with LCP
 *     arpndp_audit_cb_func_checksum     - checksum of the above function
 *                                         pointer to detect memory corruption
 *
 * Functions:
 *     ARPNDP_check_thread    - module-internal function to check running
 *                              thread to enforce single thread execution
 *     ARPNDP_check_key       - module-internal function to check OS interface
 *                              index and remote IP
 *     ARPNDP_check_cfg       - module-internal function to check ARP/NDP
 *                              session parameters
 *     ARPNDP_check_init      - module-internal function to check ARP/NDP
 *                              initialization
 *
 *     ARPNDP_init            - function to initialize all ARP/NDP modules
 *
 *     ARPNDP_create_sess     - function to create a new ARP/NDP session
 *     ARPNDP_change_cfg      - function to change ARP/NDP session parameters
 *                              after ARP/NDP session has been created
 *     ARPNDP_destroy_sess    - function to destroy an existing ARP/NDP
 *                              sesssion
 *
 *     ARPNDP_get_sess_state  - function to get sesstion state of an ARP/NDP
 *                              sesssion
 *     ARPNDP_set_admin_state - function to set administrative state of an
 *                              ARP/NDP session
 *
 *     ARPNDP_get_stats       - function to get statistics/counts of an ARP/NDP
 *                              session
 *     ARPNDP_clear_stats     - function to clear statistics/counts of an
 *                              ARP/NDP session
 *
 *     ARPNDP_timer           - function to call every 5 milli-seconds to
 *                              implement ARP/NDP timers
 *
 *     ARPNDP_add_sockets     - function to call before pselect() to add
 *                              ARP/NDP sockets
 *     ARPNDP_recv            - function to call when ARP/NDP sockets have
 *                              incomming messages
 *
 *     ARPNDP_audit           - function for LCP to audit an ARP/NDP session
 *                              with ARP/NDP implementation
 *
 *     ARPNDP_log_data        - function for CLI to log ARP/NDP internal
 *                              data of all ARP/NDP sessions
 *     ARPNDP_log_stats       - function for CLI to log statistics/counts
 *                              of ARP/NDP protocol and all ARP/NDP sessions
 *
 ************************************************************************/

#include "ARPNDP_int_hdr.h"

/* check pointer for NULL */
#define IS_VALID_PTR(ptr)             (ptr != NULL)


/* whether ARP/NDP has initialized successfully */
static BOOL arpndp_has_init = FALSE;

/* pointer to all ARP/NDP data in shared memory */
ARPNDP_DATA *arpndp_data = NULL;

/* checksum of the above pointer to detect memory corruption */
static unsigned long arpndp_data_checksum = 0;

/* current thread that executes ARP/NDP code */
static pthread_t arpndp_thread_id = 0;

/* current time in 5 milli-seconds */
unsigned int arpndp_cur_time = 0;

/* internal audit timer */
static unsigned int arpndp_audit_timer = ARPNDP_AUDIT_TIMER;

/* whether first ARP/NDP session in a round of internal audit */
static BOOL arpndp_audit_timer_first_sess = TRUE;

/* current ARP/NDP session index of internal audit */
static int arpndp_audit_sess_idx = ARPNDP_INV_SESS_IDX;
    
/* log statistics/counts timer */
static unsigned int arpndp_log_stats_timer = ARPNDP_LOG_STATS_TIMER;

/* whether first ARP/NDP session in a round of statistic/count log */
static BOOL arpndp_log_stats_timer_first_sess = TRUE;

/* current ARP/NDP session index of statistic/count log */
static int arpndp_log_stats_sess_idx = ARPNDP_INV_SESS_IDX;

/*
 * call-back function for ARP/NDP implementation to audit an ARP/NDP session
 * with LCP
 */
ARPNDP_AUDIT_CB_FUNC arpndp_audit_cb_func = NULL;

/* checksum of the above function pointer to detect memory corruption */
unsigned long arpndp_audit_cb_func_checksum = 0;



/*
 * Name:        ARPNDP_check_thread
 *
 * Abstract:    module-internal function to check running thread to enforce
 *              single thread execution
 *
 * Parameters:  none
 *
 * Retunrs:     none
 */
static void ARPNDP_check_thread()
{
    if (arpndp_thread_id == 0)
    {
        /* first run */
        /* save thread ID */
        arpndp_thread_id = pthread_self();
    }
    else
    {
        /* subsequent run */
        /* check thread ID */
        if (pthread_self() != arpndp_thread_id)
        {
             ARPNDP_LOCAL_ERROR ("not single thread; currrent thread ID %lu, "
                "previous thread ID %lu\n", pthread_self(), arpndp_thread_id);
            arpndp_data->stats.not_single_thread++;

            arpndp_thread_id = pthread_self();
        }
    }
}



/* 
 * Name:        ARPNDP_check_key
 * 
 * Abstract:    module-internal function to check OS interface index and
 *              remote IP
 * 
 * Parameters:
 *     intf_idx  - OS interface index
 *     remote_ip - remote IP
 * 
 * Retunrs:
 *     ret_val   - success or failure
 */
static ARPNDP_RETVAL ARPNDP_check_key (int intf_idx, IPM_IPADDR *remote_ip)
{
    ARPNDP_check_thread();

    if ((intf_idx < ARPNDP_INTF_IDX_MIN) || (intf_idx > ARPNDP_INTF_IDX_MAX))
    {
        ARPNDP_LOCAL_ERROR ("invalid OS interface index %d, "
            "%d to %d expected\n", intf_idx, ARPNDP_INTF_IDX_MIN,
            ARPNDP_INTF_IDX_MAX);
        arpndp_data->stats.inv_intf_idx++;
        return ARPNDP_LOCAL_FAIL;
    }

    if (IS_VALID_PTR (remote_ip) == FALSE)
    {
        ARPNDP_LOCAL_ERROR ("invalid remote_ip pointer %p\n", remote_ip);
        arpndp_data->stats.inv_remote_ip++;
        return ARPNDP_LOCAL_FAIL;
    }
    else if ((remote_ip->addrtype != IPM_IPV4) &&
        (remote_ip->addrtype != IPM_IPV6))
    {
        ARPNDP_LOCAL_ERROR ("invalid remote_ip address type %d; "
            "%d or %d expected\n", remote_ip->addrtype, IPM_IPV4, IPM_IPV6);
        arpndp_data->stats.inv_remote_ip++;
        return ARPNDP_LOCAL_FAIL;
    }

    return ARPNDP_SUCCESS;
}



/*
 * Name:        ARPNDP_check_cfg
 *
 * Abstract:    module-internal function to check ARP/NDP session parameters
 *
 * Parameters:
 *     remote_ip        - remote IP;
 *                        remote IP is not an ARP/NDP session parameter,
 *                        but here to cross check with local IP
 *     local_ip         - local IP
 *     detect_time_mult - detection time multiplier
 *     min_tx           - desired min Tx interval
 *     min_rx           - required min Tx interval
 *
 * Retunrs:
 *     ret_val          - success or failure
 *     min_tx           - rounded down desired min Tx interval if error
 *     min_rx           - rounded down required min Rx interval if error
 */
static ARPNDP_RETVAL ARPNDP_check_cfg (IPM_IPADDR *remote_ip,
    IPM_IPADDR *local_ip, uint8_t detect_time_mult, uint32_t *min_tx,
    uint32_t *min_rx)
{   
    if (IS_VALID_PTR (local_ip) == FALSE)
    {
        ARPNDP_LOCAL_ERROR ("invalid local_ip pointer %p\n", local_ip);
        arpndp_data->stats.inv_local_ip++;
        return ARPNDP_LOCAL_FAIL;
    }
    else if ((local_ip->addrtype != IPM_IPV4) &&
        (local_ip->addrtype != IPM_IPV6))
    {
        ARPNDP_LOCAL_ERROR ("invalid local_ip address type %d; "
            "%d or %d expected\n", local_ip->addrtype, IPM_IPV4, IPM_IPV6);
        arpndp_data->stats.inv_local_ip++;
        return ARPNDP_LOCAL_FAIL;
    }

    if (local_ip->addrtype != remote_ip->addrtype)
    {
        ARPNDP_LOCAL_ERROR ("local_ip address type %d != remote_ip address "
            "type %d; they must be the same\n",
            local_ip->addrtype, remote_ip->addrtype);
        arpndp_data->stats.inv_local_ip_type++;
        return ARPNDP_LOCAL_FAIL;
    }

    if ((detect_time_mult < ARPNDP_DETECT_TIME_MULT_MIN) ||
        (detect_time_mult > ARPNDP_DETECT_TIME_MULT_MAX))
    {
        ARPNDP_LOCAL_ERROR ("invalid local detection time multiplier %u, "
            "%u to %u expected\n", detect_time_mult,
            ARPNDP_DETECT_TIME_MULT_MIN, ARPNDP_DETECT_TIME_MULT_MAX);
        arpndp_data->stats.inv_detect_time_mult++;
        return ARPNDP_LOCAL_FAIL;
    }

    if ((*min_tx < ARPNDP_MIN_TX_MIN) || (*min_tx > ARPNDP_MIN_TX_MAX))
    {
        ARPNDP_LOCAL_ERROR ("invalid local desired min Tx interval %u, "
            "%u to %u expected\n", *min_tx, ARPNDP_MIN_TX_MIN,
            ARPNDP_MIN_TX_MAX);
        arpndp_data->stats.inv_min_tx++;
        return ARPNDP_LOCAL_FAIL;
    }
    else if ((*min_tx % ARPNDP_MIN_TX_UNIT) != 0)
    {
        ARPNDP_LOCAL_ERROR ("invalid local desired min Tx interval %u, "
            "multiples of %u expected\n", *min_tx, ARPNDP_MIN_TX_UNIT);
        arpndp_data->stats.inv_min_tx++;

        /* round down */
        *min_tx = ( *min_tx / ARPNDP_MIN_TX_UNIT) * ARPNDP_MIN_TX_UNIT;
    }

    if ((*min_rx < ARPNDP_MIN_RX_MIN) || (*min_rx > ARPNDP_MIN_RX_MAX))
    {
        ARPNDP_LOCAL_ERROR ("invalid local desired min Tx interval %u, "
            "%u to %u expected\n", *min_rx, ARPNDP_MIN_RX_MIN,
            ARPNDP_MIN_RX_MAX);
        arpndp_data->stats.inv_min_rx++;
        return ARPNDP_LOCAL_FAIL;
    }
    else if ((*min_rx % ARPNDP_MIN_RX_UNIT) != 0)
    {
        ARPNDP_LOCAL_ERROR ("invalid local desired min Tx interval %u, "
            "multiples of %u expected\n", *min_rx, ARPNDP_MIN_RX_UNIT);
        arpndp_data->stats.inv_min_rx++;

        /* round down */
        *min_rx = ( *min_rx / ARPNDP_MIN_RX_UNIT) * ARPNDP_MIN_RX_UNIT;
    }

    return ARPNDP_SUCCESS;
}



/*
 * Name:        ARPNDP_check_init
 *
 * Abstract:    module-internal function to check ARP/NDP initialization
 *
 * Parameters:  none
 *
 * Retunrs:
 *     ret_val   - success or failure
 */
static ARPNDP_RETVAL ARPNDP_check_init()
{
    if (arpndp_has_init == FALSE)
    {
        ARPNDP_LOCAL_ERROR ("ARP/NDP has not initialized successfully\n");
        return ARPNDP_LOCAL_FAIL;
    }

    if (((unsigned long) arpndp_data ^ (unsigned long) ARPNDP_CHECKSUM_SEED)
        != arpndp_data_checksum)
    {
        ARPNDP_LOCAL_ERROR ("corrupted pointer to all ARP/NDP data in shared "
            "memory\n");
        return ARPNDP_LOCAL_FAIL;
    }

    return ARPNDP_SUCCESS;
}   



/*
 * Name:        ARPNDP_init
 *
 * Abstract:    function to initialize all ARP/NDP modules
 *
 * Parameters:
 *     audit_cb_func        - call-back function for ARP/NDP implementation
 *                            to audit ARP/NDP session with LCP
 *     _arpndp_data         - pointer to ARP/NDP data in shared memory
 *     init_type            - whether full-initialization or process restart
 *
 * Retunrs:
 *     ret_val              - success or failure
 */
ARPNDP_RETVAL ARPNDP_init (ARPNDP_AUDIT_CB_FUNC audit_cb_func,
    void *_arpndp_data, ARPNDP_INIT_TYPE init_type)
{
    int sess_idx;

    if (ARPNDP_LOG_ENABLED)
    {
        ARPNDP_LOG (
            "ARPNDP_init: "
            "audit_cb_func %p, "
            "_arpndp_data %p, "
            "init_type %s\n",
            audit_cb_func,
            _arpndp_data,
            ARPNDP_INIT_TYPE_to_str (init_type));
    }

    /* process _arpndp_data first */

    if (IS_VALID_PTR (_arpndp_data) == FALSE)
    {
        ARPNDP_LOCAL_ERROR ("invalid data pointer %p\n", _arpndp_data);
        /* no stats.inv_data_ptr++ */
        return ARPNDP_LOCAL_FAIL;
    }

    /* save all ARP/NDP data pointer */
    arpndp_data = _arpndp_data;

    /* no ARPNDP_check_thread */

    if (arpndp_has_init == TRUE)
    {
        ARPNDP_LOCAL_ERROR ("ARP/NDP has initialized before\n");
        arpndp_data->stats.arpndp_has_init++;
        return ARPNDP_LOCAL_FAIL;
    }

    if (sizeof(ARPNDP_HISTORY) != ARPNDP_HISTORY_SIZE)
    {
        ARPNDP_INTERNAL_ERROR ("size of ARPNDP_HISTORY structure is %d, "
            "%d expected\n", (int) sizeof(ARPNDP_HISTORY),
            (int) ARPNDP_HISTORY_SIZE);
        arpndp_data->stats.arpndp_size_error++;
        return ARPNDP_INTERNAL_FAIL;
    }

    /* no audit_cb_func check since it might be NULL */

    if ((init_type != ARPNDP_INIT_TYPE_FULL) &&
        (init_type != ARPNDP_INIT_TYPE_RESTART))
    {
        ARPNDP_LOCAL_ERROR ("invalid ARP/NDP initialization type %d; "
            "%d or %d expected\n", init_type, ARPNDP_INIT_TYPE_FULL,
            ARPNDP_INIT_TYPE_RESTART);
        arpndp_data->stats.inv_init_type++;
        return ARPNDP_LOCAL_FAIL;
    }

    /* 
     * save call-back function for ARP/NDP implementation to audit an ARP/NDP
     * session with LCP;
     * it might be NULL
     */
    arpndp_audit_cb_func = audit_cb_func;
    
    /*
     * checksum the "arpndp_audit_cb_func" pointer to detect memory corruption
     */
    arpndp_audit_cb_func_checksum =
        (unsigned long) arpndp_audit_cb_func ^
        (unsigned long) ARPNDP_CHECKSUM_SEED;
    
    /* checksum the "arpndp_data" pointer to detect memory corruption */
    arpndp_data_checksum =
        (unsigned long) arpndp_data ^
        (unsigned long) ARPNDP_CHECKSUM_SEED;

    if (init_type == ARPNDP_INIT_TYPE_FULL)
    {
        /* full initialization */

        /* initialize other ARPNDP modules */

        /* initialize ARP/NDP session data module */
        ARPNDP_sess_data_init();

        /* initialize ARP/NDP history module */
        ARPNDP_history_init();

        /* initialize ARP/NDP statistics module */
        ARPNDP_stats_init();
    }
    else
    {
        /* process restart */

        /* go through all ARP/NDP sessions to re-create sockets */

        /* get first ARP/NDP session */
        sess_idx = ARPNDP_sess_data_get_first();

        /* loop until no more ARP/NDP session */
        while (sess_idx != ARPNDP_INV_SESS_IDX)
        {
            /*
             * call the corresponding function in ARP/NDP transport module to
             * re-create sockets
             */
            ARPNDP_trans_create_sock (sess_idx);

            /* get next ARP/NDP session */
            sess_idx = ARPNDP_sess_data_get_next (sess_idx);
        }
    }

    arpndp_has_init = TRUE;
    return ARPNDP_SUCCESS;
}


/*
 * Name:        ARPNDP_create_sess
 *
 * Abstract:    function to create a new ARP/NDP session
 *
 * Parameters:
 *     intf_idx         - OS interface index
 *     remote_ip        - remote IP
 *
 *     local_ip         - local IP
 *     detect_time_mult - detection time multiplier
 *     min_tx           - desired min Tx interval
 *     min_rx           - required min Tx interval
 *
 * Returns:
 *     ret_val          - success or failure
 *
 * Notes: Local and remote IPs can be IPv4 or IPv6
 */
ARPNDP_RETVAL ARPNDP_create_sess (int intf_idx, IPM_IPADDR *remote_ip,
    IPM_IPADDR *local_ip, uint8_t detect_time_mult, uint32_t min_tx,
    uint32_t min_rx)
{
    ARPNDP_RETVAL ret_val;

    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];

    if (ARPNDP_LOG_ENABLED)
    {
        IPM_ipaddr2p (local_ip, &local_ip_str[0], sizeof(local_ip_str));
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));

        ARPNDP_LOG (
            "ARPNDP_create_sess: "
            "intf_idx %d, "
            "remote_ip %s, "
            "local_ip %s, "
            "detect_time_mult %u, "
            "min_tx %u, "
            "min_rx %u\n",
            intf_idx,
            &remote_ip_str[0],
            &local_ip_str[0],
            detect_time_mult,
            min_tx,
            min_rx);
    }

    ret_val = ARPNDP_check_key (intf_idx, remote_ip);
    if (ret_val != ARPNDP_SUCCESS)
    {
        return ret_val;
    }

    ret_val = ARPNDP_check_cfg (remote_ip, local_ip, detect_time_mult,
        &min_tx, &min_rx);
    if (ret_val != ARPNDP_SUCCESS)
    {
        return ret_val;
    }

    ret_val = ARPNDP_check_init();
    if (ret_val != ARPNDP_SUCCESS)
    {
        return ret_val;
    }

    /*
     * call the corresponding function in ARP/NDP session to create a new
     * ARP/NDP session
     */
    ret_val = ARPNDP_sess_create (intf_idx, remote_ip, local_ip,
        detect_time_mult, min_tx, min_rx);
    if (ret_val != ARPNDP_SUCCESS)
    {
        return ret_val;
    }

    arpndp_data->stats.good_create++;
    return ARPNDP_SUCCESS;
}

/*
 * Name:        ARPNDP_change_cfg
 *
 * Abstract:    function to change ARP/NDP session parameters after ARP/NDP
 *              session has been created
 *
 * Parameters:
 *     intf_idx         - OS interface index
 *     remote_ip        - remote IP
 *
 *     local_ip         - local IP
 *     detect_time_mult - new detection time multiplier
 *     min_tx           - new desired min Tx interval
 *     min_rx           - new required min Tx interval
 *
 * Returns:
 *     ret_val          - success or failure
 */
ARPNDP_RETVAL ARPNDP_change_cfg (int intf_idx, IPM_IPADDR *remote_ip,
    IPM_IPADDR *local_ip, uint8_t detect_time_mult, uint32_t min_tx,
    uint32_t min_rx)
{
    ARPNDP_RETVAL ret_val;
    int sess_idx;

    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];

    if (ARPNDP_LOG_ENABLED)
    {
        IPM_ipaddr2p (local_ip, &local_ip_str[0], sizeof(local_ip_str));
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));

        ARPNDP_LOG (
            "ARPNDP_change_cfg: "
            "intf_idx %u, "
            "remote_ip %s, "
            "local_ip %s, "
            "detect_time_mult %u, "
            "min_tx %u, "
            "min_rx %u\n",
            intf_idx,
            &remote_ip_str[0],
            &local_ip_str[0],
            detect_time_mult,
            min_tx,
            min_rx);
    }

    ret_val = ARPNDP_check_key (intf_idx, remote_ip);
    if (ret_val != ARPNDP_SUCCESS)
    {
        return ret_val;
    }

    ret_val = ARPNDP_check_cfg (remote_ip, local_ip, detect_time_mult,
        &min_tx, &min_rx);
    if (ret_val != ARPNDP_SUCCESS)
    {
        return ret_val;
    }

    ret_val = ARPNDP_check_init();
    if (ret_val != ARPNDP_SUCCESS)
    {
        return ret_val;
    }  

    /* get ARP/NDP session with OS interface index and remote IP */
    ret_val = ARPNDP_sess_data_get (intf_idx, remote_ip, &sess_idx);
    if (ret_val != ARPNDP_SUCCESS)
    {
        /* cannot find ARP/NDP session */
        return ret_val;
    }

    /*
     * call the corresponding function in ARP/NDP session to change ARP/NDP
     * session parameters
     */
    ret_val = ARPNDP_sess_change_cfg (sess_idx, local_ip, detect_time_mult,
        min_tx, min_rx);
    if (ret_val != ARPNDP_SUCCESS)
    {
        return ret_val;
    }

    arpndp_data->stats.good_change_cfg++;
    return ARPNDP_SUCCESS;
}


/*
 * Name:        ARPNDP_destroy_sess
 *
 * Abstract:    function to destroy an existing ARP/NDP session
 *
 * Parameters:
 *     intf_idx  - OS interface index
 *     remote_ip - remote IP of this ARP/NDP session
 *
 * Returns:     none
 */
void ARPNDP_destroy_sess (int intf_idx, IPM_IPADDR *remote_ip)
{
    ARPNDP_RETVAL ret_val;
    int sess_idx;

    char remote_ip_str[IPM_IPMAXSTRSIZE];

    if (ARPNDP_LOG_ENABLED)
    {
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));

        ARPNDP_LOG (
            "ARPNDP_destroy_sess: "
            "intf_idx %d, "
            "remote_ip %s\n",
            intf_idx,
            &remote_ip_str[0]);
    }

    ret_val = ARPNDP_check_key (intf_idx, remote_ip);
    if (ret_val != ARPNDP_SUCCESS)
    {
        return;
    }

    ret_val = ARPNDP_check_init();
    if (ret_val != ARPNDP_SUCCESS)
    {  
        return;
    }  

    /* get ARP/NDP session with OS interface index and remote IP */
    ret_val = ARPNDP_sess_data_get (intf_idx, remote_ip, &sess_idx);
    if (ret_val != ARPNDP_SUCCESS)
    {
        /* cannot find ARPNDP session */
        return;
    }

    /*
     * call the corresponding function in ARP/NDP session module to destroy
     * ARP/NDP session
     */
    ARPNDP_sess_destroy (sess_idx);

    arpndp_data->stats.good_destroy++;
}


/*
 * Name:        ARPNDP_get_sess_state
 *
 * Abstract:    function to get sesstion state of an ARP/NDP session
 *
 * Parameters:
 *     intf_idx   - OS interface index
 *     remote_ip  - remote IP
 *
 * Returns:
 *     ret_val    - success or failure
 *
 *     sess_state - session state
 */
ARPNDP_RETVAL ARPNDP_get_sess_state (int intf_idx, IPM_IPADDR *remote_ip,
    ARPNDP_SESS_STATE *sess_state)
{
    ARPNDP_RETVAL ret_val;
    int sess_idx;

    char remote_ip_str[IPM_IPMAXSTRSIZE];

    ret_val = ARPNDP_check_key (intf_idx, remote_ip);
    if (ret_val != ARPNDP_SUCCESS)
    {
        return ret_val;
    }

    if (IS_VALID_PTR (sess_state) == FALSE)
    {
        ARPNDP_LOCAL_ERROR ("invalid sess_state pointer %p\n", sess_state);
        arpndp_data->stats.inv_sess_state_ptr++;
        return ARPNDP_LOCAL_FAIL;
    }

    ret_val = ARPNDP_check_init();
    if (ret_val != ARPNDP_SUCCESS)
    {  
        return ret_val;
    }  

    /* get ARP/NDP session with OS interface index and remote IP */
    ret_val = ARPNDP_sess_data_get (intf_idx, remote_ip, &sess_idx);
    if (ret_val != ARPNDP_SUCCESS)
    {
        /* cannot find ARP/NDP session */
        return ret_val;
    }

    /*
     * call the corresponding function in ARP/NDP session module to get
     * session state
     */
    ARPNDP_sess_get_sess_state (sess_idx, sess_state);

    if (ARPNDP_LOG_ENABLED)
    {
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));

        ARPNDP_LOG (
            "ARPNDP_get_sess_state: "
            "intf_idx %d, "
            "remote_ip %s, "
            "sess_state %s\n",
            intf_idx,
            &remote_ip_str[0],
            ARPNDP_SESS_STATE_to_str (*sess_state));
    }

    arpndp_data->stats.good_get_sess_state++;
    return ARPNDP_SUCCESS;
}


/*
 * Name:        ARPNDP_set_admin_state
 *
 * Abstract:    function to set administrative states of an ARP/NDP session
 *
 * Parameters:
 *     intf_idx    - OS interface index
 *     remote_ip   - remote IP
 *
 *     admin_state - new administrative state
 *
 * Returns:
 *     ret_val     - success or failure
 */
ARPNDP_RETVAL ARPNDP_set_admin_state (int intf_idx, IPM_IPADDR *remote_ip,
    ARPNDP_ADMIN_STATE new_admin_state)
{
    ARPNDP_RETVAL ret_val;
    int sess_idx;

    char remote_ip_str[IPM_IPMAXSTRSIZE];

    if (ARPNDP_LOG_ENABLED)
    {
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));

        ARPNDP_LOG (
            "ARPNDP_set_admin_state: "
            "intf_idx %d, "
            "remote_ip %s, "
            "admin_state %s\n",
            intf_idx,
            &remote_ip_str[0],
            ARPNDP_ADMIN_STATE_to_str (new_admin_state));
    }

    ret_val = ARPNDP_check_key (intf_idx, remote_ip);
    if (ret_val != ARPNDP_SUCCESS)
    {
        return ret_val;
    }

    if ((new_admin_state != ARPNDP_ADMIN_STATE_UP) &&
        (new_admin_state != ARPNDP_ADMIN_STATE_DOWN))
    {
        ARPNDP_LOCAL_ERROR ("invalid new_admin_state %d; %d or %d expected\n",
            new_admin_state, ARPNDP_ADMIN_STATE_UP, ARPNDP_ADMIN_STATE_DOWN);
        arpndp_data->stats.inv_admin_state++;
        return ARPNDP_LOCAL_FAIL;
    }

    ret_val = ARPNDP_check_init();
    if (ret_val != ARPNDP_SUCCESS)
    {
        return ret_val;
    }

    /* get ARP/NDP session with OS interface index and remote IP */
    ret_val = ARPNDP_sess_data_get (intf_idx, remote_ip, &sess_idx);
    if (ret_val != ARPNDP_SUCCESS)
    {
        /* cannot find ARP/NDP session */
        return ret_val;
    }

    /*
     * call the corresponding function in ARP/NDP session module to set
     * administrative state
     */
    ret_val = ARPNDP_sess_set_admin_state (sess_idx, new_admin_state);
    if (ret_val != ARPNDP_SUCCESS)
    {
        return ret_val;
    }

    arpndp_data->stats.good_set_admin_state++;
    return ARPNDP_SUCCESS;
}


/*
 * Name:        ARPNDP_get_stats
 *
 * Abstract:    function to get statistics/counts of an ARP/NDP session
 *
 * Parameters:
 *     intf_idx  - OS interface index
 *     remote_ip - remote IP
 *
 * Returns:
 *     ret_val   - success or failure
 *
 *     missed_hb - missed heartbeat count
 */
ARPNDP_RETVAL ARPNDP_get_stats (int intf_idx, IPM_IPADDR *remote_ip,
    uint32_t *missed_hb)
{
    ARPNDP_RETVAL ret_val;
    int sess_idx;

    char remote_ip_str[IPM_IPMAXSTRSIZE];

    ret_val = ARPNDP_check_key (intf_idx, remote_ip);
    if (ret_val != ARPNDP_SUCCESS)
    {
        return ret_val;
    }

    if (IS_VALID_PTR (missed_hb) == FALSE)
    {
        ARPNDP_LOCAL_ERROR ("invalid missed_hb pointer %p\n", missed_hb);
        arpndp_data->stats.inv_missed_hb_ptr++;
        return ARPNDP_LOCAL_FAIL;
    }

    ret_val = ARPNDP_check_init();
    if (ret_val != ARPNDP_SUCCESS)
    {
        return ret_val;
    }

    /* get ARP/NDP session with OS interface index and remote IP */
    ret_val = ARPNDP_sess_data_get (intf_idx, remote_ip, &sess_idx);
    if (ret_val != ARPNDP_SUCCESS)
    {
        /* cannot find ARPNDP session */
        return ret_val;
    }

    /*
     * call the corresponding function in ARP/NDP session module to get
     * ARP/NDP statistics/counts
     */
    ARPNDP_sess_get_stats (sess_idx, missed_hb);

    if (ARPNDP_LOG_ENABLED)
    {
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));

        ARPNDP_LOG (
            "ARPNDP_get_stats: "
            "intf_idx %d, "
            "remote_ip %s, "
            "missed_hb %u\n",
            intf_idx,
            &remote_ip_str[0],
            *missed_hb);
    }

    arpndp_data->stats.good_get_stats++;
    return ARPNDP_SUCCESS;
}


/*  
 * Name:        ARPNDP_clear_stats
 * 
 * Abstract:    function to clear statistics/counts of an ARP/NDP session
 * 
 * Parameters:
 *     intf_idx  - OS interface index
 *     remote_ip - remote IP
 *     
 * Returns:     none
 */    
void ARPNDP_clear_stats (int intf_idx, IPM_IPADDR *remote_ip)
{   
    ARPNDP_RETVAL ret_val;
    int sess_idx;
    
    char remote_ip_str[IPM_IPMAXSTRSIZE];
    
    if (ARPNDP_LOG_ENABLED)
    {
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));
     
        ARPNDP_LOG (
            "ARPNDP_clear_stats: "
            "intf_idx %d, "  
            "remote_ip %s\n",
            intf_idx,
            &remote_ip_str[0]);
    }       

    ret_val = ARPNDP_check_key (intf_idx, remote_ip);
    if (ret_val != ARPNDP_SUCCESS)
    {
        return;
    }
     
    ret_val = ARPNDP_check_init();
    if (ret_val != ARPNDP_SUCCESS)
    {
        return;
    }
     
    /* get ARP/NDP session with OS interface index and remote IP */
    ret_val = ARPNDP_sess_data_get (intf_idx, remote_ip, &sess_idx);
    if (ret_val != ARPNDP_SUCCESS) 
    {
        /* cannot find ARP/NDP session */
        return;
    }
     
    /*
     * call the corresponding function in ARP/NDP session module to clear
     * ARP/NDP statistics/counts
     */
    ARPNDP_sess_clear_stats (sess_idx);
}


/*
 * Name:        ARPNDP_timer
 *
 * Abstract:    function to call every 5 milli-seconds to implement ARP/NDP
 *              timers
 *
 * Parameters:  none
 *
 * Returns:     none
 */
void ARPNDP_timer()
{
    ARPNDP_RETVAL ret_val;
    int sess_idx;

    /* no log */

    ARPNDP_check_thread();

    ret_val = ARPNDP_check_init();
    if (ret_val != ARPNDP_SUCCESS)
    {
        return;
    }

    /* maintain current time */
    arpndp_cur_time++;




    if (arpndp_cur_time >= arpndp_audit_timer)
    {
        /* audit timer expires */

        if (arpndp_audit_timer_first_sess == TRUE)
        {   
            /* first time */
            arpndp_audit_timer_first_sess = FALSE;

            arpndp_audit_sess_idx = ARPNDP_sess_data_get_first();
            if (arpndp_audit_sess_idx == ARPNDP_INV_SESS_IDX)
            {
                /* restart audit timer */
                arpndp_audit_timer += ARPNDP_AUDIT_TIMER;
                arpndp_audit_timer_first_sess = TRUE;
            }
            else
            {
                /* internally audit ARP/NDP session */
                ARPNDP_sess_int_audit (arpndp_audit_sess_idx);
            }
        }
        else
        {   
            /* subsequence */

            arpndp_audit_sess_idx = ARPNDP_sess_data_get_next (
                arpndp_audit_sess_idx);
            if (arpndp_audit_sess_idx == ARPNDP_INV_SESS_IDX)
            {
                /* restart audit timer */
                arpndp_audit_timer += ARPNDP_AUDIT_TIMER;
                arpndp_audit_timer_first_sess = TRUE;
            }
            else
            {
                /* internally audit ARP/NDP session */
                ARPNDP_sess_int_audit (arpndp_audit_sess_idx);
            }
        }
    }




#ifdef ARPNDP_LOG_STATS_TIMER_ENABLED
    if (arpndp_cur_time >= arpndp_log_stats_timer)
    {
        /* log ARP/NDP statistics/counts timer expires */

        if (arpndp_log_stats_timer_first_sess == TRUE)
        {
            /* first time */
            arpndp_log_stats_timer_first_sess = FALSE;

            /* log statistics/counts of ARP/NDP protocol */
            if (arpndp_data->sess_num != 0)
            {
                ARPNDP_stats_log_arpndp();
            }

            arpndp_log_stats_sess_idx = ARPNDP_sess_data_get_first();
            if (arpndp_log_stats_sess_idx == ARPNDP_INV_SESS_IDX)
            {
                /* restart log ARP/NDP statistics/counts timer */
                arpndp_log_stats_timer += ARPNDP_LOG_STATS_TIMER;
                arpndp_log_stats_timer_first_sess = TRUE;
            }
            else
            {
                /* log statistics/counts of ARP/NDP session */
                if (arpndp_data->sess_num != 0)
                {
                    ARPNDP_stats_log_sess (arpndp_log_stats_sess_idx);
                }

#ifdef ARPNDP_LOG_SESS_HIST_W_STATS
                if (arpndp_data->sess_num != 0)
                {
                    /* log ARP/NDP session */
                    ARPNDP_sess_data_log (arpndp_log_stats_sess_idx);

                    /* log ARP/NDP history */
                    ARPNDP_history_log (arpndp_log_stats_sess_idx);
                }
#endif /* #ifdef ARPNDP_LOG_SESS_HIST_W_STATS */
            }
        }
        else
        {
            /* subsequence */

            arpndp_log_stats_sess_idx = ARPNDP_sess_data_get_next(
                arpndp_log_stats_sess_idx);
            if (arpndp_log_stats_sess_idx == ARPNDP_INV_SESS_IDX)
            {
                /* restart log ARP/NDP statistics/counts timer */
                arpndp_log_stats_timer += ARPNDP_LOG_STATS_TIMER;
                arpndp_log_stats_timer_first_sess = TRUE;
            }
            else
            {
                /* log statistics/counts of ARP/NDP session */
                if (arpndp_data->sess_num != 0)
                {
                    ARPNDP_stats_log_sess (arpndp_log_stats_sess_idx);
                }

#ifdef ARPNDP_LOG_SESS_HIST_W_STATS
                if (arpndp_data->sess_num != 0)
                {
                    /* log ARP/NDP session */
                    ARPNDP_sess_data_log (arpndp_log_stats_sess_idx);

                    /* log ARP/NDP history */
                    ARPNDP_history_log (arpndp_log_stats_sess_idx);
                }
#endif /* #ifdef ARPNDP_LOG_SESS_HIST_W_STATS */
            }
        }
    }
#endif /* #ifdef ARPNDP_LOG_STATS_TIMER_ENABLED */




    /* go through all ARP/NDP sessions to check all ARP/NDP timers */

    /* get first ARP/NDP session */
    sess_idx = ARPNDP_sess_data_get_first();

    /* loop until no more ARP/NDP session */
    while (sess_idx != ARPNDP_INV_SESS_IDX)
    {
        /*
         * call the corresponding function in ARP/NDP session module to check
         * all ARP/NDP timers
         */
        ARPNDP_sess_timer (sess_idx);

        /* get next ARP/NDP session */
        sess_idx = ARPNDP_sess_data_get_next (sess_idx);
    }

    arpndp_data->stats.good_timer++;
}


/*
 * Name:        ARPNDP_add_sockets
 *
 * Abstract:    function to call before pselect() to add ARP/NDP sockets
 *
 * Parameters:  none
 *
 * Returns:
 *     read_sock_set - set of all IPM read sockets
 *                     including ARP/NDP sockets
 *     max_sock      - maximum value of all IPM read sockets
 */
void ARPNDP_add_sockets (fd_set *read_sock_set, int *max_sock)
{

#if 1

    ARPNDP_RETVAL ret_val;
    int sess_idx;
    int sock;

    /* no log */

    ARPNDP_check_thread();

    if (IS_VALID_PTR (read_sock_set) == FALSE)
    {
        ARPNDP_LOCAL_ERROR ("invalid read_sock_set pointer %p\n",
            read_sock_set);
        arpndp_data->stats.inv_read_sock_set_ptr++;
        return;
    }

    ret_val = ARPNDP_check_init();
    if (ret_val != ARPNDP_SUCCESS)
    {
        return;
    }

    /* go through all ARP/NDP sessions to add sockets */

    /* get first ARP/NDP session */
    sess_idx = ARPNDP_sess_data_get_first();

    /* loop until no more ARP/NDP session */
    while (sess_idx != ARPNDP_INV_SESS_IDX)
    {
        sock = arpndp_data->sess[sess_idx].sock;

        if (sock == -1)
        {
            /* socket is not created and bind yet */
            sess_idx = ARPNDP_sess_data_get_next (sess_idx);
            continue;
        }

        /*
         * add this socket to set of all IPM sockets;
         * it is OK to add multiple times
         */
        FD_SET (sock, read_sock_set);

        /* maintain maximum value of all IPM sockets */
        if (sock > *max_sock)
        {
            *max_sock = sock;
        }

        /* get next ARP/NDP session */
        sess_idx = ARPNDP_sess_data_get_next (sess_idx);
    }

    arpndp_data->stats.good_add_sockets++;

#else

    ARPNDP_RETVAL ret_val;
    int sess_idx;
    int sock;

    /* no log */

    ARPNDP_check_thread();

    if (IS_VALID_PTR (read_sock_set) == FALSE)
    {
        ARPNDP_LOCAL_ERROR ("invalid read_sock_set pointer %p\n",
            read_sock_set);
        arpndp_data->stats.inv_read_sock_set_ptr++;
        return;
    }

    ret_val = ARPNDP_check_init();
    if (ret_val != ARPNDP_SUCCESS)
    {
        return;
    }

    /* go through all ARP/NDP sessions to add sockets */

    /* get first ARP/NDP session */
    sess_idx = ARPNDP_sess_data_get_first();

    /* loop until no more ARP/NDP session */
    while (sess_idx != ARPNDP_INV_SESS_IDX)
    {
        sock = arpndp_data->sess[sess_idx].sock;

        /*
         * add this socket to set of all IPM sockets;
         * it is OK to add multiple times
         */
        FD_SET (sock, read_sock_set);

        /* maintain maximum value of all IPM sockets */
        if (sock > *max_sock)
        {
            *max_sock = sock;
        }

        /* get next ARP/NDP session */
        sess_idx = ARPNDP_sess_data_get_next (sess_idx);
    }

    arpndp_data->stats.good_add_sockets++;

#endif

}


/*
 * Name:        ARPNDP_recv
 *
 * Abstract:    function to call when ARP/NDP sockets have incoming messages
 *
 * Parameters:
 *     read_sock_set - set of all IPM read sockets
 *                     including ARP/NDP sockets
 *
 * Returns:     none
 */
void ARPNDP_recv (fd_set *read_sock_set)
{
#if 1

    ARPNDP_RETVAL ret_val;
    ARPNDP_RETVAL sess_ret_val;
    int sess_idx;
    int num_of_sess = 0;

    /* no log */

    ARPNDP_check_thread();

    if (IS_VALID_PTR (read_sock_set) == FALSE)
    {
        ARPNDP_LOCAL_ERROR ("invalid read_sock_set pointer %p\n",
            read_sock_set);
        arpndp_data->stats.inv_read_sock_set_ptr++;
        return;
    }

    ret_val = ARPNDP_check_init();
    if (ret_val != ARPNDP_SUCCESS)
    {
        return;
    }

    /* go through all ARP/NDP sessions to check for incoming message */

    /* get first ARP/NDP session */
    sess_idx = ARPNDP_sess_data_get_first();

    /* loop until no more ARP/NDP session */
    ret_val = ARPNDP_SUCCESS;
    while (sess_idx != ARPNDP_INV_SESS_IDX)
    {
        if (arpndp_data->sess[sess_idx].sock == -1)
        {
            /* socket is not created and bind yet */
            sess_idx = ARPNDP_sess_data_get_next (sess_idx);
            continue;
        }

        if (FD_ISSET (arpndp_data->sess[sess_idx].sock, read_sock_set) != 0)
        {
            /* this ARP/NDP session has incoming message */

            num_of_sess++;

            /*
             * call the corresponding function in ARP/NDP transport module
             * to receive ARP/NDP message
             */
            sess_ret_val = ARPNDP_trans_recv (sess_idx);
            if (sess_ret_val == ARPNDP_IGNORE)
            {
                /* received message is not ours */
                sess_idx = ARPNDP_sess_data_get_next (sess_idx);
                continue;
            }
            else if (sess_ret_val != ARPNDP_SUCCESS)
            {
                /* error */
                ret_val = sess_ret_val;
                sess_idx = ARPNDP_sess_data_get_next (sess_idx);
                continue;
            }

            /*
             * call the corresponding function in ARP/NDP session module
             * to process ARP/NDP message
             */
            sess_ret_val = ARPNDP_sess_recv (sess_idx);
            if (sess_ret_val != ARPNDP_SUCCESS)
            {
                ret_val = sess_ret_val;
                sess_idx = ARPNDP_sess_data_get_next (sess_idx);
                continue;
            }
        }

        /* get next ARP/NDP session */
        sess_idx = ARPNDP_sess_data_get_next (sess_idx);
    }

    if (ret_val == ARPNDP_SUCCESS)
    {
        if (num_of_sess > 0)
        {
            arpndp_data->stats.good_recv++;
        }
        else
        {
            arpndp_data->stats.recv_no_sess++;
        }
    }

#else

    ARPNDP_RETVAL ret_val;
    ARPNDP_RETVAL sess_ret_val;
    int sess_idx;
    int num_of_sess = 0;

    /* no log */

    ARPNDP_check_thread();

    if (IS_VALID_PTR (read_sock_set) == FALSE)
    {
        ARPNDP_LOCAL_ERROR ("invalid read_sock_set pointer %p\n",
            read_sock_set);
        arpndp_data->stats.inv_read_sock_set_ptr++;
        return;
    }

    ret_val = ARPNDP_check_init();
    if (ret_val != ARPNDP_SUCCESS)
    {
        return;
    }

    /* go through all ARP/NDP sessions to check for incoming message */

    /* get first ARP/NDP session */
    sess_idx = ARPNDP_sess_data_get_first();

    /* loop until no more ARP/NDP session */
    ret_val = ARPNDP_SUCCESS;
    while (sess_idx != ARPNDP_INV_SESS_IDX)
    {
        if (FD_ISSET (arpndp_data->sess[sess_idx].sock, read_sock_set) != 0)
        {
            /* this ARP/NDP session has incoming message */

            num_of_sess++;

            /*
             * call the corresponding function in ARP/NDP transport module
             * to receive ARP/NDP message
             */
            sess_ret_val = ARPNDP_trans_recv (sess_idx);
            if (sess_ret_val == ARPNDP_IGNORE)
            {
                /* received message is not ours */
                sess_idx = ARPNDP_sess_data_get_next (sess_idx);
                continue;
            }
            else if (sess_ret_val != ARPNDP_SUCCESS)
            {
                /* error */
                ret_val = sess_ret_val;
                sess_idx = ARPNDP_sess_data_get_next (sess_idx);
                continue;
            }

            /*
             * call the corresponding function in ARP/NDP session module
             * to process ARP/NDP message
             */
            sess_ret_val = ARPNDP_sess_recv (sess_idx);
            if (sess_ret_val != ARPNDP_SUCCESS)
            {
                ret_val = sess_ret_val;
                sess_idx = ARPNDP_sess_data_get_next (sess_idx);
                continue;
            }
        }

        /* get next ARP/NDP session */
        sess_idx = ARPNDP_sess_data_get_next (sess_idx);
    }

    if (ret_val == ARPNDP_SUCCESS)
    {
        if (num_of_sess > 0)
        {
            arpndp_data->stats.good_recv++;
        }
        else
        {
            arpndp_data->stats.recv_no_sess++;
        }
    }

#endif

}


/*  
 * Name:        ARPNDP_audit
 * 
 * Abstract:    function for LCP to audit ARP/NDP session with ARP/NDP
 *              implementation
 * 
 * Parameters:
 *     intf_idx         - OS interface index
 *     remote_ip        - remote IP
 *     
 *     local_ip         - local IP
 *     detect_time_mult - detection time multiplier
 *     min_tx           - desired min Tx interval  
 *     min_rx           - required min Tx interval  
 *     
 *     begin_middle_end - ARP/NDP audit sequence
 *     
 * Returns:     none
 */
void ARPNDP_audit (int intf_idx, IPM_IPADDR *remote_ip,
    IPM_IPADDR *local_ip, uint8_t detect_time_mult, uint32_t min_tx,
    uint32_t min_rx, ARPNDP_AUDIT_SEQ begin_middle_end)
{   
    ARPNDP_RETVAL ret_val;
    int sess_idx;

    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];
     
    if (ARPNDP_LOG_ENABLED)
    {
        IPM_ipaddr2p (local_ip, &local_ip_str[0], sizeof(local_ip_str));
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));
     
        ARPNDP_LOG (
            "ARPNDP_audit: "
            "intf_idx %d, "
            "remote_ip %s, "
            "local_ip %s, "
            "detect_time_mult %u, "
            "min_tx %u, "
            "min_rx %u, "
            "begin_middle_end %s\n",
            intf_idx, 
            &remote_ip_str[0], 
            &local_ip_str[0], 
            detect_time_mult,
            min_tx,
            min_rx,
            ARPNDP_AUDIT_SEQ_to_str (begin_middle_end));
    }       
            
    ret_val = ARPNDP_check_key (intf_idx, remote_ip);
    if (ret_val != ARPNDP_SUCCESS)
    {
        return;
    }

    ret_val = ARPNDP_check_cfg (remote_ip, local_ip, detect_time_mult,
        &min_tx, &min_rx);
    if (ret_val != ARPNDP_SUCCESS)
    {
        return;
    }

    if ((begin_middle_end != ARPNDP_AUDIT_SEQ_BEGIN) &&
        (begin_middle_end != ARPNDP_AUDIT_SEQ_MIDDLE) &&
        (begin_middle_end != ARPNDP_AUDIT_SEQ_END))
    {
        ARPNDP_LOCAL_ERROR ("invalid ARP/NDP audit sequence %d, "
            "%d, %d, or %d expected\n", begin_middle_end,
            ARPNDP_AUDIT_SEQ_BEGIN, ARPNDP_AUDIT_SEQ_MIDDLE,
            ARPNDP_AUDIT_SEQ_END);
        arpndp_data->stats.inv_begin_middle_end++;
        return;
    }
     
    ret_val = ARPNDP_check_init();
    if (ret_val != ARPNDP_SUCCESS)
    {
        return;
    }

    if (((unsigned long) arpndp_audit_cb_func ^
         (unsigned long) ARPNDP_CHECKSUM_SEED) !=
        arpndp_audit_cb_func_checksum)
    {
        ARPNDP_LOCAL_ERROR ("corrupted call-back function for ARP/NDP "
            "implmentation ito audit ARP/NDP sesstion with LCP\n");
        arpndp_data->stats.corrupt_audit_cb_func++;
        return;
    }

    if (begin_middle_end == ARPNDP_AUDIT_SEQ_BEGIN)
    {
        /* begin of ARP/NDP audit sequence */

        /* mark all ARP/NDP sessions as not-audited */

        /* get first ARP/NDP session */
        sess_idx = ARPNDP_sess_data_get_first();

        /* loop until no more ARP/NDP session */
        while (sess_idx != ARPNDP_INV_SESS_IDX)
        {
            /* mark this ARP/NDP sessions as not-audited */
            arpndp_data->sess[sess_idx].audited = FALSE;

            /* get next ARP/NDP session */
            sess_idx = ARPNDP_sess_data_get_next (sess_idx);
        }
    }

    ret_val = ARPNDP_SUCCESS;

    /* get ARP/NDP session index with OS interface index and remote IP */
    ret_val = ARPNDP_sess_data_get (intf_idx, remote_ip, &sess_idx);
    if (ret_val != ARPNDP_SUCCESS)
    {
        /* ARP/NDP session does not exist */

        ARPNDP_INTERNAL_ERROR ("audit: ARP/NDP session exists at LCP, "
            "but not at ARP/NDP implemenation, create it\n");
        arpndp_data->stats.ext_audit++;

        /* automatically create a new ARP/NDP session */
        ret_val = ARPNDP_create_sess (intf_idx, remote_ip, local_ip,
            detect_time_mult, min_tx, min_rx);
        if (ret_val == ARPNDP_SUCCESS)
        {
            /* successfully create new ARP/NDP session */

            /*
             * get ARP/NDP session index with OS interface index and remote IP
             */
            ret_val = ARPNDP_sess_data_get (intf_idx, remote_ip, &sess_idx);
        }
    }
    else if ((memcmp (&arpndp_data->sess[sess_idx].local_ip, local_ip,
            sizeof(IPM_IPADDR)) != 0) ||
        (arpndp_data->sess[sess_idx].detect_time_mult != detect_time_mult) ||
        (arpndp_data->sess[sess_idx].min_tx != min_tx) ||
        (arpndp_data->sess[sess_idx].min_rx != min_rx))
    {
        /* ARP/NDP session parameters are different */

        ARPNDP_INTERNAL_ERROR ("audit: ARP/NDP session parameters are "
            "different, change them\n");
        arpndp_data->stats.ext_audit++;

        /* automatically change ARP/NDP session parameters */
        ret_val = ARPNDP_change_cfg (intf_idx, remote_ip, local_ip,
            detect_time_mult, min_tx, min_rx);
    }

    if (ret_val == ARPNDP_SUCCESS)
    {
        /* mark this ARP/NDP session as audited */
        arpndp_data->sess[sess_idx].audited = TRUE;
    }
     
    if (begin_middle_end == ARPNDP_AUDIT_SEQ_END)
    {
        /* end of ARP/NDP audit sequence */

        /*
         * find all not-audited ARP/NDP sessions;
         * audit them with LCP
         */

        /* get first ARP/NDP session */
        sess_idx = ARPNDP_sess_data_get_first();

        /* loop until no more ARP/NDP session */
        while (sess_idx != ARPNDP_INV_SESS_IDX)
        {
            if (arpndp_data->sess[sess_idx].audited == FALSE)
            {
                /* this ARP/NDP sessions is not-audited */

                if (arpndp_audit_cb_func != NULL)
                {
                    /* externally audit this ARP/NDP session with LCP */
                    ARPNDP_sess_ext_audit (sess_idx);
                }
            }

            /* get next ARP/NDP session */
            sess_idx = ARPNDP_sess_data_get_next (sess_idx);
        }

    }

    arpndp_data->stats.good_audit++;
}   


/*
 * Name:        ARPNDP_log_data
 *
 * Abstract:    function for CLI to log ARP/NDP internal data of all ARP/NDP
 *              sessions
 *
 * Parameters:  none
 *
 * Returns:     none
 */
void ARPNDP_log_data()
{
    ARPNDP_RETVAL ret_val;

    char buffer[ARPNDP_ERR_LOG_BUF_SIZE];
    char *ptr = buffer;
    int size = sizeof(buffer);

    int sess_idx;
    int count;

    /* no log */

    ARPNDP_check_thread();

    ret_val = ARPNDP_check_init();
    if (ret_val != ARPNDP_SUCCESS)
    {
        return;
    }

    /* count number of ARP/NDP sessions */
    count = 0;
    sess_idx = ARPNDP_sess_data_get_first();
    while (sess_idx != ARPNDP_INV_SESS_IDX)
    {
        count++;
        sess_idx = ARPNDP_sess_data_get_next (sess_idx);
    }

    ARPNDP_PRINTF (ptr, size,
        "ARPNDP protocol data:\n"

        "    arpndp_has_init                         %u\n"
        "\n"
        "    arpndp_audit_cb_func                    %p\n"
        "    arpndp_audit_cb_func_checksum           0x%lx\n"
        "\n"
        "    arpndp_data                             %p\n"
        "    arpndp_data_checksum                    0x%lx\n"
        "\n"
        "    arpndp_thread_id                        0x%lx\n"
        "\n"
        "    arpndp_cur_time                         %u\n"
        "\n"
        "    arpndp_audit_timer                      %u\n"
        "    arpndp_audit_timer_first_sess           %u\n"
        "    arpndp_audit_sess_idx                   %d\n"
        "\n"
        "    arpndp_log_stats_timer                  %u\n"
        "    arpndp_log_stats_timer_first_sess       %u\n"
        "    arpndp_log_stats_sess_idx               %d\n"
        "\n"
        "    arpndp_data.sess_num                    %u\n"
        "    number of ARP/NDP sessions              %u\n",

        arpndp_has_init,

        arpndp_audit_cb_func,
        arpndp_audit_cb_func_checksum,

        arpndp_data,
        arpndp_data_checksum,

        arpndp_thread_id,

        arpndp_cur_time,

        arpndp_audit_timer,
        arpndp_audit_timer_first_sess,
        arpndp_audit_sess_idx,

        arpndp_log_stats_timer,
        arpndp_log_stats_timer_first_sess,
        arpndp_log_stats_sess_idx,

        arpndp_data->sess_num,
        count);


    ARPNDP_LOG_FORCED (buffer);


    /* go through all ARP/NDP sessions to log ARP/NDP session data */

    /* get first ARP/NDP session */
    sess_idx = ARPNDP_sess_data_get_first();

    /* loop until no more ARP/NDP session */
    while (sess_idx != ARPNDP_INV_SESS_IDX)
    {
        /*
         * call the corresponding function in ARP/NDP session data module to
         * log ARP/NDP internal data
         */
        ARPNDP_sess_data_log (sess_idx);

        /*
         * call the corresponding function in ARP/NDP session data module to
         * log ARP/NDP history
         */
        ARPNDP_history_log (sess_idx);

        /* get next ARP/NDP session */
        sess_idx = ARPNDP_sess_data_get_next (sess_idx);
    }
}


/*
 * Name:        ARPNDP_log_stats
 *
 * Abstract:    function for CLI to log statistics/counts of ARP/NDP
 *              protocol and all ARP/NDP sessions
 *
 * Parameters:  none
 *
 * Returns:     none
 */
void ARPNDP_log_stats()
{
    ARPNDP_RETVAL ret_val;
    int sess_idx;

    /* no log */

    ARPNDP_check_thread();

    ret_val = ARPNDP_check_init();
    if (ret_val != ARPNDP_SUCCESS)
    {
        return;
    }

    /*
     * call the corresponding function in ARP/NDP statistic module to log
     * statistics/counts of ARP/NDP protocol
     */
    ARPNDP_stats_log_arpndp();

    /* go through all ARP/NDP sessions to log statistics/counts */

    /* get first ARP/NDP session */
    sess_idx = ARPNDP_sess_data_get_first();

    /* loop until no more ARP/NDP session */
    while (sess_idx != ARPNDP_INV_SESS_IDX)
    {
        /*
         * call the corresponding function in ARP/NDP statistic module to log
         * statistics/counts of an ARP/NDP session
         */
        ARPNDP_stats_log_sess (sess_idx);

        /* get next ARP/NDP session */
        sess_idx = ARPNDP_sess_data_get_next (sess_idx);
    }
}
