/*************************************************************************
 *
 * File:     BFD_api.c
 *
 * Abstract: implementation file of BFD API module
 *           this module hides internal detailed BFD implemenation from
 *           external user (EIPM)
 *
 * Data:
 *     bfd_has_init                   - whether BFD has initialized
 *                                      successfully
 *
 *     bfd_data                       - pointer to all BFD data in shared
 *                                      memory
 *     bfd_data_checksum              - checksum of the above pointer to
 *                                      detect memory corruption
 *
 *     bfd_thread_id                  - current thread that executes BFD code
 *
 *     bfd_cur_time                   - current time in multiples of 5
 *                                      milli-seconds
 *
 *     bfd_audit_timer                - internal audit timer
 *     bfd_audit_timer_first_sess     - whether first BFD session in a
 *                                      round of internal audit
 *     bfd_audit_sess_idx             - current BFD session index of
 *                                      internal audit
 *
 *     bfd_log_stats_timer            - log statistics/counts timer
 *     bfd_log_stats_timer_first_sess - wheher first BFD session in a
 *                                      round of statistic/count log
 *     bfd_log_stats_sess_idx         - current BFD session index of
 *                                      statistic/count log
 *
 * Functions:
 *     BFD_check_thread    - module-internal function to check running
 *                           thread to enforce single thread execution
 *     BFD_check_ip        - module-internal function to check local IP and
 *                           remote IP
 *     BFD_check_cfg       - module-internal function to check BFD session
 *                           parameters
 *     BFD_check_init      - module-internal function to check BFD
 *                           initialization
 *
 *     BFD_init            - function to initialize all BFD modules
 *
 *     BFD_create_sess     - function to create a new BFD session
 *     BFD_change_cfg      - function to change BFD session parameters
 *                           after BFD session has been created
 *     BFD_destroy_sess    - function to destroy an existing BFD session
 *
 *     BFD_get_sess_state  - function to get sesstion state of a BFD session
 *     BFD_set_admin_state - function to set administrative state of a
 *                           BFD session
 *
 *     BFD_get_stats       - function to get statistics/counts of a BFD
 *                           session
 *     BFD_clear_stats     - function to clear statistics/counts of a BFD
 *                           session
 *
 *     BFD_timer           - function to call every 5 milli-seconds to
 *                           implement BFD timers
 *
 *     BFD_add_sockets     - function to call before pselect() to add BFD
 *                           sockets
 *     BFD_recv            - function to call when BFD sockets have
 *                           incomming messages
 *
 *     BFD_audit           - function for LCP to audit BFD session with BFD
 *
 *     BFD_log_data        - function for CLI to log BFD internal data of
 *                           all BFD sessions
 *     BFD_log_stats       - function for CLI to log BFD statistics/counts
 *                           of BFD protocol and all BFD sessions
 *
 ************************************************************************/

#include "BFD_int_hdr.h"

/* check pointer for NULL */
#define IS_VALID_PTR(ptr)             (ptr != NULL)


/* whether BFD has initialized successfully */
static BOOL bfd_has_init = FALSE;

/* pointer to all BFD data in shared memory */
BFD_DATA *bfd_data = NULL;

/* checksum of the above pointer to detect memory corruption */
static unsigned long bfd_data_checksum = 0;

/* current thread that executes BFD code */
static pthread_t bfd_thread_id = 0;

/* current time in 5 milli-seconds */
unsigned int bfd_cur_time = 0;

/* internal audit timer */
static unsigned int bfd_audit_timer = BFD_AUDIT_TIMER;

/* whether first BFD session in a round of internal audit */
static BOOL bfd_audit_timer_first_sess = TRUE;

/* current BFD session index of internal audit */
static int bfd_audit_sess_idx = BFD_INV_SESS_IDX;
    
/* log statistics/counts timer */
static unsigned int bfd_log_stats_timer = BFD_LOG_STATS_TIMER;

/* whether first BFD session in a round of statistic/count log */
static BOOL bfd_log_stats_timer_first_sess = TRUE;

/* current BFD session index of statistic/count log */
static int bfd_log_stats_sess_idx = BFD_INV_SESS_IDX;



/*
 * Name:        BFD_check_thread
 *
 * Abstract:    module-internal function to check running thread to enforce
 *              single thread execution
 *
 * Parameters:  none
 *
 * Retunrs:     none
 */
static void BFD_check_thread()
{
    if (bfd_thread_id == 0)
    {
        /* first run */
        /* save thread ID */
        bfd_thread_id = pthread_self();
    }
    else
    {
        /* subsequent run */
        /* check thread ID */
        if (pthread_self() != bfd_thread_id)
        {
            BFD_LOCAL_ERROR ("not single thread; currrent thread ID %lu, "
                "previous thread ID %lu\n", pthread_self(), bfd_thread_id);
            bfd_data->stats.not_single_thread++;

            bfd_thread_id = pthread_self();
        }
    }
}



/* 
 * Name:        BFD_check_ip
 * 
 * Abstract:    module-internal function to check local IP and remote IP
 * 
 * Parameters:
 *     local_ip  - local IP
 *     remote_ip - remote IP
 * 
 * Retunrs:
 *     ret_val   - success or failure
 */
static BFD_RETVAL BFD_check_ip (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip)
{
    BFD_check_thread();

    if (IS_VALID_PTR (local_ip) == FALSE)
    {
        BFD_LOCAL_ERROR ("invalid local_ip pointer %p\n", local_ip);
        bfd_data->stats.inv_local_ip++;
        return BFD_LOCAL_FAIL;
    }
    else if ((local_ip->addrtype != IPM_IPV4) &&
        (local_ip->addrtype != IPM_IPV6))
    {
        BFD_LOCAL_ERROR ("invalid local_ip address type %d; "
            "%d or %d expected\n", local_ip->addrtype, IPM_IPV4, IPM_IPV6);
        bfd_data->stats.inv_local_ip++;
        return BFD_LOCAL_FAIL;
    }

    if (IS_VALID_PTR (remote_ip) == FALSE)
    {
        BFD_LOCAL_ERROR ("invalid remote_ip pointer %p\n", remote_ip);
        bfd_data->stats.inv_remote_ip++;
        return BFD_LOCAL_FAIL;
    }
    else if ((remote_ip->addrtype != IPM_IPV4) &&
        (remote_ip->addrtype != IPM_IPV6))
    {
        BFD_LOCAL_ERROR ("invalid remote_ip address type %d; "
            "%d or %d expected\n", remote_ip->addrtype, IPM_IPV4, IPM_IPV6);
        bfd_data->stats.inv_remote_ip++;
        return BFD_LOCAL_FAIL;
    }

    if (remote_ip->addrtype != local_ip->addrtype)
    {
        BFD_LOCAL_ERROR ("remote_ip address type %d != local_ip address "
            "type %d; they must be the same\n",
            remote_ip->addrtype, local_ip->addrtype);
        bfd_data->stats.inv_remote_local_ip_type++;
        return BFD_LOCAL_FAIL;
    }

    return BFD_SUCCESS;
}



/*
 * Name:        BFD_check_cfg
 *
 * Abstract:    module-internal function to check BFD session parameters
 *
 * Parameters:
 *     detect_time_mult - detection time multiplier
 *     min_tx           - desired min Tx interval
 *     min_rx           - required min Tx interval
 *
 * Retunrs:
 *     ret_val          - success or failure
 *     min_tx           - rounded down desired min Tx interval if error
 *     min_rx           - rounded down required min Rx interval if error
 */
static BFD_RETVAL BFD_check_cfg (uint8_t detect_time_mult, uint32_t *min_tx,
    uint32_t *min_rx)
{   
    if ((detect_time_mult < BFD_DETECT_TIME_MULT_MIN) ||
        (detect_time_mult > BFD_DETECT_TIME_MULT_MAX))
    {
        BFD_LOCAL_ERROR ("invalid local detection time multiplier %u, "
            "%u to %u expected\n", detect_time_mult,
            BFD_DETECT_TIME_MULT_MIN, BFD_DETECT_TIME_MULT_MAX);
        bfd_data->stats.inv_detect_time_mult++;
        return BFD_LOCAL_FAIL;
    }

    if ((*min_tx < BFD_MIN_TX_MIN) || (*min_tx > BFD_MIN_TX_MAX))
    {
        BFD_LOCAL_ERROR ("invalid local desired min Tx interval %u, "
            "%u to %u expected\n", *min_tx, BFD_MIN_TX_MIN, BFD_MIN_TX_MAX);
        bfd_data->stats.inv_min_tx++;
        return BFD_LOCAL_FAIL;
    }
    else if ((*min_tx % BFD_MIN_TX_UNIT) != 0)
    {
        BFD_LOCAL_ERROR ("invalid local desired min Tx interval %u, "
            "multiples of %u expected\n", *min_tx, BFD_MIN_TX_UNIT);
        bfd_data->stats.inv_min_tx++;

        /* round down */
        *min_tx = ( *min_tx / BFD_MIN_TX_UNIT) * BFD_MIN_TX_UNIT;
    }

    if ((*min_rx < BFD_MIN_RX_MIN) || (*min_rx > BFD_MIN_RX_MAX))
    {
        BFD_LOCAL_ERROR ("invalid local desired min Tx interval %u, "
            "%u to %u expected\n", *min_rx, BFD_MIN_RX_MIN, BFD_MIN_RX_MAX);
        bfd_data->stats.inv_min_rx++;
        return BFD_LOCAL_FAIL;
    }
    else if ((*min_rx % BFD_MIN_RX_UNIT) != 0)
    {
        BFD_LOCAL_ERROR ("invalid local desired min Tx interval %u, "
            "multiples of %u expected\n", *min_rx, BFD_MIN_RX_UNIT);
        bfd_data->stats.inv_min_rx++;

        /* round down */
        *min_rx = ( *min_rx / BFD_MIN_RX_UNIT) * BFD_MIN_RX_UNIT;
    }

    return BFD_SUCCESS;
}



/*
 * Name:        BFD_check_init
 *
 * Abstract:    module-internal function to check BFD initialization
 *
 * Parameters:  none
 *
 * Retunrs:
 *     ret_val   - success or failure
 */
static BFD_RETVAL BFD_check_init()
{
    if (bfd_has_init == FALSE)
    {
        BFD_LOCAL_ERROR ("BFD has not initialized successfully\n");
        return BFD_LOCAL_FAIL;
    }

    if (((unsigned long) bfd_data ^ (unsigned long) BFD_CHECKSUM_SEED) !=
        bfd_data_checksum)
    {
        BFD_LOCAL_ERROR ("corrupted pointer to all BFD data in shared "
            "memory\n");
        return BFD_LOCAL_FAIL;
    }

    return BFD_SUCCESS;
}   



/*
 * Name:        BFD_init
 *
 * Abstract:    function to initialize all BFD modules
 *
 * Parameters:
 *     audit_cb_func        - call-back function for BFD implementation to
 *                            audit BFD session with LCP
 *     state_change_cb_func - call-back function for BFD to report
 *                            session state change to LCP;
 *                            use NULL if no call-back function
 *     _bfd_data            - pointer to BFD data in shared memory
 *     init_type            - whether full-initialization or process restart
 *
 * Retunrs:
 *     ret_val              - success or failure
 */
BFD_RETVAL BFD_init (BFD_AUDIT_CB_FUNC audit_cb_func,
    BFD_STATE_CHANGE_CB_FUNC state_change_cb_func,
    void *_bfd_data, BFD_INIT_TYPE init_type)
{
    int sess_idx;

    if (BFD_LOG_ENABLED)
    {
        BFD_LOG (
            "BFD_init: "
            "audit_cb_func %p, "
            "state_change_cb_func %p, "
            "_bfd_data %p, "
            "init_type %s\n",
            audit_cb_func,
            state_change_cb_func,
            _bfd_data,
            BFD_INIT_TYPE_to_str (init_type));
    }

    /* process _bfd_data first */

    if (IS_VALID_PTR (_bfd_data) == FALSE)
    {
        BFD_LOCAL_ERROR ("invalid data pointer %p\n", _bfd_data);
        /* no stats.inv_data_ptr++ */
        return BFD_LOCAL_FAIL;
    }

    /* save all BFD data pointer */
    bfd_data = _bfd_data;

    /* no BFD_check_thread */

    if (bfd_has_init == TRUE)
    {
        BFD_LOCAL_ERROR ("BFD has initialized before\n");
        bfd_data->stats.bfd_has_init++;
        return BFD_LOCAL_FAIL;
    }

    if (sizeof(BFD_MSG) != BFD_MSG_LENGTH)
    {
        BFD_INTERNAL_ERROR ("size of BFD_MSG structure is %d, "
            "%d expected\n", (int) sizeof(BFD_MSG), (int) BFD_MSG_LENGTH);
        bfd_data->stats.bfd_size_error++;
        return BFD_INTERNAL_FAIL;
    }

    if (sizeof(BFD_HISTORY) != BFD_HISTORY_SIZE)
    {
        BFD_INTERNAL_ERROR ("size of BFD_HISTORY structure is %d, "
            "%d expected\n", (int) sizeof(BFD_HISTORY),
            (int) BFD_HISTORY_SIZE);
        bfd_data->stats.bfd_size_error++;
        return BFD_INTERNAL_FAIL;
    }

    /* no audit_cb_func check since it might be NULL */

    /* no state_change_cb_func check since it might be NULL */

    if ((init_type != BFD_INIT_TYPE_FULL) &&
        (init_type != BFD_INIT_TYPE_RESTART))
    {
        BFD_LOCAL_ERROR ("invalid BFD initialization type %d; "
            "%d or %d expected\n", init_type, BFD_INIT_TYPE_FULL,
            BFD_INIT_TYPE_RESTART);
        bfd_data->stats.inv_init_type++;
        return BFD_LOCAL_FAIL;
    }

    /* 
     * save call-back function for BFD to audit BFD session with LCP;
     * it might be NULL
     */
    bfd_audit_cb_func = audit_cb_func;
    
    /*
     * checksum the "bfd_audit_cb_func" pointer to detect memory corruption
     */
    bfd_audit_cb_func_checksum =
        (unsigned long) bfd_audit_cb_func ^
        (unsigned long) BFD_CHECKSUM_SEED;
    
    /*
     * save call-back function for BFD to report session state change
     * to LCP; it might be NULL
     */
    bfd_state_change_cb_func = state_change_cb_func;

    /*
     * checksum the "bfd_state_change_cb_func" pointer to detect memory
     * corruption
     */
    bfd_state_change_cb_func_checksum =
        (unsigned long) bfd_state_change_cb_func ^
        (unsigned long) BFD_CHECKSUM_SEED;

    /* checksum the "bfd_data" pointer to detect memory corruption */
    bfd_data_checksum =
        (unsigned long) bfd_data ^
        (unsigned long) BFD_CHECKSUM_SEED;

    if (init_type == BFD_INIT_TYPE_FULL)
    {
        /* full initialization */

        /* initialize other BFD modules */

        /* initialize BFD session data module */
        BFD_sess_data_init();

        /* initialize BFD history module */
        BFD_history_init();

        /* initialize BFD statistics module */
        BFD_stats_init();
    }
    else
    {
        /* process restart */

        /* go through all BFD sessions to re-create sockets */

        /* get first BFD session */
        sess_idx = BFD_sess_data_get_first();

        /* loop until no more BFD session */
        while (sess_idx != BFD_INV_SESS_IDX)
        {
            /*
             * call the corresponding function in BFD transport module to
             * re-create sockets
             */
            if (BFD_trans_create_recv_sock (sess_idx) == BFD_SUCCESS)
            {
                BFD_trans_create_send_sock (sess_idx);
            }

            /* get next BFD session */
            sess_idx = BFD_sess_data_get_next (sess_idx);
        }
    }

    bfd_has_init = TRUE;
    return BFD_SUCCESS;
}


/*
 * Name:        BFD_create_sess
 *
 * Abstract:    function to create a new BFD session
 *
 * Parameters:
 *     local_ip         - local IP of this BFD session
 *     remote_ip        - remote IP
 *
 *     detect_time_mult - detection time multiplier
 *     min_tx           - desired min Tx interval
 *     min_rx           - required min Tx interval
 *
 * Returns:
 *     ret_val          - success or failure
 *
 * Notes: Local and remote IPs can be IPv4 or IPv6
 */
BFD_RETVAL BFD_create_sess (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    uint8_t detect_time_mult, uint32_t min_tx, uint32_t min_rx)
{
    BFD_RETVAL ret_val;

    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];

    if (BFD_LOG_ENABLED)
    {
        IPM_ipaddr2p (local_ip, &local_ip_str[0], sizeof(local_ip_str));
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));

        BFD_LOG (
            "BFD_create_sess: "
            "local_ip %s, "
            "remote_ip %s, "
            "detect_time_mult %u, "
            "min_tx %u, "
            "min_rx %u\n",
            &local_ip_str[0],
            &remote_ip_str[0],
            detect_time_mult,
            min_tx,
            min_rx);
    }

    ret_val = BFD_check_ip (local_ip, remote_ip);
    if (ret_val != BFD_SUCCESS)
    {
        return ret_val;
    }

    ret_val = BFD_check_cfg (detect_time_mult, &min_tx, &min_rx);
    if (ret_val != BFD_SUCCESS)
    {
        return ret_val;
    }

    ret_val = BFD_check_init();
    if (ret_val != BFD_SUCCESS)
    {
        return ret_val;
    }

    /*
     * call the corresponding function in BFD session to create a new BFD
     * session
     */
    ret_val = BFD_sess_create (local_ip, remote_ip, detect_time_mult,
        min_tx, min_rx);
    if (ret_val != BFD_SUCCESS)
    {
        return ret_val;
    }

    bfd_data->stats.good_create++;
    return BFD_SUCCESS;
}

/*
 * Name:        BFD_change_cfg
 *
 * Abstract:    function to change BFD session parameters after BFD session
 *              has been created
 *
 * Parameters:
 *     local_ip         - local IP of this BFD session
 *     remote_ip        - remote IP
 *
 *     detect_time_mult - new detection time multiplier
 *     min_tx           - new desired min Tx interval
 *     min_rx           - new required min Tx interval
 *
 * Returns:
 *     ret_val          - success or failure
 */
BFD_RETVAL BFD_change_cfg (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    uint8_t detect_time_mult, uint32_t min_tx, uint32_t min_rx)
{
    BFD_RETVAL ret_val;
    int sess_idx;

    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];

    if (BFD_LOG_ENABLED)
    {
        IPM_ipaddr2p (local_ip, &local_ip_str[0], sizeof(local_ip_str));
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));

        BFD_LOG (
            "BFD_change_cfg: "
            "local_ip %s, "
            "remote_ip %s, "
            "detect_time_mult %u, "
            "min_tx %u, "
            "min_rx %u\n",
            &local_ip_str[0],
            &remote_ip_str[0],
            detect_time_mult,
            min_tx,
            min_rx);
    }

    ret_val = BFD_check_ip (local_ip, remote_ip);
    if (ret_val != BFD_SUCCESS)
    {
        return ret_val;
    }

    ret_val = BFD_check_cfg (detect_time_mult, &min_tx, &min_rx);
    if (ret_val != BFD_SUCCESS)
    {
        return ret_val;
    }

    ret_val = BFD_check_init();
    if (ret_val != BFD_SUCCESS)
    {
        return ret_val;
    }  

    /* get BFD session with local IP and remote IP */
    ret_val = BFD_sess_data_get (local_ip, remote_ip, &sess_idx);
    if (ret_val != BFD_SUCCESS)
    {
        /* cannot find BFD session */
        return ret_val;
    }

    /*
     * call the corresponding function in BFD session to change BFD config
     * data
     */
    ret_val = BFD_sess_change_cfg (sess_idx, detect_time_mult, min_tx,
        min_rx);
    if (ret_val != BFD_SUCCESS)
    {
        return ret_val;
    }

    bfd_data->stats.good_change_cfg++;

    return BFD_SUCCESS;
}


/*
 * Name:        BFD_destroy_sess
 *
 * Abstract:    function to destroy an existing BFD session
 *
 * Parameters:
 *     local_ip  - local IP of this BFD session
 *     remote_ip - remote IP
 *
 * Returns:     none
 */
void BFD_destroy_sess (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip)
{
    BFD_RETVAL ret_val;
    int sess_idx;

    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];

    if (BFD_LOG_ENABLED)
    {
        IPM_ipaddr2p (local_ip, &local_ip_str[0], sizeof(local_ip_str));
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));

        BFD_LOG (
            "BFD_destroy_sess: "
            "local_ip %s, "
            "remote_ip %s\n",
            &local_ip_str[0],
            &remote_ip_str[0]);
    }

    ret_val = BFD_check_ip (local_ip, remote_ip);
    if (ret_val != BFD_SUCCESS)
    {
        return;
    }

    ret_val = BFD_check_init();
    if (ret_val != BFD_SUCCESS)
    {  
        return;
    }  

    /* get BFD session with local IP and remote IP */
    ret_val = BFD_sess_data_get (local_ip, remote_ip, &sess_idx);
    if (ret_val != BFD_SUCCESS)
    {
        /* cannot find BFD session */
        return;
    }

    /*
     * call the corresponding function in BFD session module to destroy BFD
     * session
     */
    BFD_sess_destroy (sess_idx);

    bfd_data->stats.good_destroy++;
}


/*
 * Name:        BFD_get_sess_state
 *
 * Abstract:    function to get sesstion state of a BFD session
 *
 * Parameters:
 *     local_ip   - local IP of this BFD session
 *     remote_ip  - remote IP
 *
 * Returns:
 *     ret_val    - success or failure
 *
 *     sess_state - local session state
 */
BFD_RETVAL BFD_get_sess_state (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    BFD_SESS_STATE *sess_state)
{
    BFD_RETVAL ret_val;
    int sess_idx;

    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];

    ret_val = BFD_check_ip (local_ip, remote_ip);
    if (ret_val != BFD_SUCCESS)
    {
        return ret_val;
    }

    if (IS_VALID_PTR (sess_state) == FALSE)
    {
        BFD_LOCAL_ERROR ("invalid sess_state pointer %p\n", sess_state);
        bfd_data->stats.inv_sess_state_ptr++;
        return BFD_LOCAL_FAIL;
    }

    ret_val = BFD_check_init();
    if (ret_val != BFD_SUCCESS)
    {  
        return ret_val;
    }  

    /* get BFD session with local IP and remote IP */
    ret_val = BFD_sess_data_get (local_ip, remote_ip, &sess_idx);
    if (ret_val != BFD_SUCCESS)
    {
        /* cannot find BFD session */
        return ret_val;
    }

    /*
     * call the corresponding function in BFD session module to get session
     * state
     */
    BFD_sess_get_sess_state (sess_idx, sess_state);

    if (BFD_LOG_ENABLED)
    {
        IPM_ipaddr2p (local_ip, &local_ip_str[0], sizeof(local_ip_str));
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));

        BFD_LOG (
            "BFD_get_sess_state: "
            "local_ip %s, "
            "remote_ip %s, "
            "sess_state %s\n",
            &local_ip_str[0],
            &remote_ip_str[0],
            BFD_SESS_STATE_to_str (*sess_state));
    }

    bfd_data->stats.good_get_sess_state++;
    return BFD_SUCCESS;
}


/*
 * Name:        BFD_set_admin_state
 *
 * Abstract:    function to set administrative states of a BFD session
 *
 * Parameters:
 *     local_ip    - local IP of this BFD session
 *     remote_ip   - remote IP
 *
 *     admin_state - new administrative state
 *
 * Returns:
 *     ret_val     - success or failure
 */
BFD_RETVAL BFD_set_admin_state (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    BFD_ADMIN_STATE new_admin_state)
{
    BFD_RETVAL ret_val;
    int sess_idx;

    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];

    if (BFD_LOG_ENABLED)
    {
        IPM_ipaddr2p (local_ip, &local_ip_str[0], sizeof(local_ip_str));
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));

        BFD_LOG (
            "BFD_set_admin_state: "
            "local_ip %s, "
            "remote_ip %s, "
            "admin_state %s\n",
            &local_ip_str[0],
            &remote_ip_str[0],
            BFD_ADMIN_STATE_to_str (new_admin_state));
    }

    ret_val = BFD_check_ip (local_ip, remote_ip);
    if (ret_val != BFD_SUCCESS)
    {
        return ret_val;
    }

    if ((new_admin_state != BFD_ADMIN_STATE_UP) &&
        (new_admin_state != BFD_ADMIN_STATE_DOWN))
    {
        BFD_LOCAL_ERROR ("invalid new_admin_state %d; %d or %d expected\n",
            new_admin_state, BFD_ADMIN_STATE_UP, BFD_ADMIN_STATE_DOWN);
        bfd_data->stats.inv_admin_state++;
        return BFD_LOCAL_FAIL;
    }

    ret_val = BFD_check_init();
    if (ret_val != BFD_SUCCESS)
    {
        return ret_val;
    }

    /* get BFD session with local IP and remote IP */
    ret_val = BFD_sess_data_get (local_ip, remote_ip, &sess_idx);
    if (ret_val != BFD_SUCCESS)
    {
        /* cannot find BFD session */
        return ret_val;
    }

    /*
     * call the corresponding function in BFD session module to set
     * administrative state
     */
    ret_val = BFD_sess_set_admin_state (sess_idx, new_admin_state);
    if (ret_val != BFD_SUCCESS)
    {
        return ret_val;
    }

    bfd_data->stats.good_set_admin_state++;
    return BFD_SUCCESS;
}


/*
 * Name:        BFD_get_stats
 *
 * Abstract:    function to get statistics/counts of a BFD session
 *
 * Parameters:
 *     local_ip  - local IP of this BFD session
 *     remote_ip - remote IP
 *
 * Returns:
 *     ret_val   - success or failure
 *
 *     missed_hb - missed heartbeat count
 *     corrupt_pkt - corrupt packet count
 */
BFD_RETVAL BFD_get_stats (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    uint32_t *missed_hb, uint32_t *corrupt_pkt)
{
    BFD_RETVAL ret_val;
    int sess_idx;

    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];

    ret_val = BFD_check_ip (local_ip, remote_ip);
    if (ret_val != BFD_SUCCESS)
    {
        return ret_val;
    }

    if (IS_VALID_PTR (missed_hb) == FALSE)
    {
        BFD_LOCAL_ERROR ("invalid missed_hb pointer %p\n", missed_hb);
        bfd_data->stats.inv_missed_hb_ptr++;
        return BFD_LOCAL_FAIL;
    }

    if (IS_VALID_PTR (corrupt_pkt) == FALSE)
    {
        BFD_LOCAL_ERROR ("invalid corrupt_pkt pointer %p\n", corrupt_pkt);
        bfd_data->stats.inv_corrupt_pkt_ptr++;
        return BFD_LOCAL_FAIL;
    }

    ret_val = BFD_check_init();
    if (ret_val != BFD_SUCCESS)
    {
        return ret_val;
    }

    /* get BFD session with local IP and remote IP */
    ret_val = BFD_sess_data_get (local_ip, remote_ip, &sess_idx);
    if (ret_val != BFD_SUCCESS)
    {
        /* cannot find BFD session */
        return ret_val;
    }

    /*
     * call the corresponding function in BFD session module to get BFD
     * statistics/counts
     */
    BFD_sess_get_stats (sess_idx, missed_hb, corrupt_pkt);

    if (BFD_LOG_ENABLED)
    {
        IPM_ipaddr2p (local_ip, &local_ip_str[0], sizeof(local_ip_str));
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));

        BFD_LOG (
            "BFD_get_stats: "
            "local_ip %s, "
            "remote_ip %s, "
            "missed_hb %u, "
            "corrupt_pkt %u\n",
            &local_ip_str[0],
            &remote_ip_str[0],
            *missed_hb,
            *corrupt_pkt);
    }

    bfd_data->stats.good_get_stats++;
    return BFD_SUCCESS;
}


/*  
 * Name:        BFD_clear_stats
 * 
 * Abstract:    function to clear statistics/counts of a BFD session
 * 
 * Parameters:
 *     local_ip  - local IP of this BFD session
 *     remote_ip - remote IP
 *     
 * Returns:     none
 */    
void BFD_clear_stats (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip)
{   
    BFD_RETVAL ret_val;
    int sess_idx;
    
    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];
    
    if (BFD_LOG_ENABLED)
    {
        IPM_ipaddr2p (local_ip, &local_ip_str[0], sizeof(local_ip_str));
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));
     
        BFD_LOG (
            "BFD_clear_stats: "
            "local_ip %s, "  
            "remote_ip %s\n",
            &local_ip_str[0],
            &remote_ip_str[0]);
    }       

    ret_val = BFD_check_ip (local_ip, remote_ip);
    if (ret_val != BFD_SUCCESS)
    {
        return;
    }
     
    ret_val = BFD_check_init();
    if (ret_val != BFD_SUCCESS)
    {
        return;
    }
     
    /* get BFD session with local IP and remote IP */
    ret_val = BFD_sess_data_get (local_ip, remote_ip, &sess_idx);
    if (ret_val != BFD_SUCCESS) 
    {
        /* cannot find BFD session */
        return;
    }
     
    /*
     * call the corresponding function in BFD session module to clear BFD
     * statistics/counts
     */
    BFD_sess_clear_stats (sess_idx);
}


/*
 * Name:        BFD_timer
 *
 * Abstract:    function to call every 5 milli-seconds to implement BFD
 *              timers
 *
 * Parameters:  none
 *
 * Returns:     none
 */
void BFD_timer()
{
    BFD_RETVAL ret_val;
    int sess_idx;

    /* no log */

    BFD_check_thread();

    ret_val = BFD_check_init();
    if (ret_val != BFD_SUCCESS)
    {
        return;
    }

    /* maintain current time */
    bfd_cur_time++;




    if (bfd_cur_time >= bfd_audit_timer)
    {
        /* audit timer expires */

        if (bfd_audit_timer_first_sess == TRUE)
        {   
            /* first time */
            bfd_audit_timer_first_sess = FALSE;

            bfd_audit_sess_idx = BFD_sess_data_get_first();
            if (bfd_audit_sess_idx == BFD_INV_SESS_IDX)
            {
                /* restart audit timer */
                bfd_audit_timer += BFD_AUDIT_TIMER;
                bfd_audit_timer_first_sess = TRUE;
            }
            else
            {
                /* internally audit BFD session */
                BFD_sess_int_audit (bfd_audit_sess_idx);
            }
        }
        else
        {   
            /* subsequence */

            bfd_audit_sess_idx = BFD_sess_data_get_next (bfd_audit_sess_idx);
            if (bfd_audit_sess_idx == BFD_INV_SESS_IDX)
            {
                /* restart audit timer */
                bfd_audit_timer += BFD_AUDIT_TIMER;
                bfd_audit_timer_first_sess = TRUE;
            }
            else
            {
                /* internally audit BFD session */
                BFD_sess_int_audit (bfd_audit_sess_idx);
            }
        }
    }




#ifdef BFD_LOG_STATS_TIMER_ENABLED
    if (bfd_cur_time >= bfd_log_stats_timer)
    {
        /* log BFD statistics/counts timer expires */

        if (bfd_log_stats_timer_first_sess == TRUE)
        {
            /* first time */
            bfd_log_stats_timer_first_sess = FALSE;

            /* log BFD statistics/counts of BFD protocol */
            if (bfd_data->sess_num != 0)
            {
                BFD_stats_log_bfd();
            }

            bfd_log_stats_sess_idx = BFD_sess_data_get_first();
            if (bfd_log_stats_sess_idx == BFD_INV_SESS_IDX)
            {
                /* restart log BFD statistics/counts timer */
                bfd_log_stats_timer += BFD_LOG_STATS_TIMER;
                bfd_log_stats_timer_first_sess = TRUE;
            }
            else
            {
                /* log BFD statistics/counts of BFD session */
                if (bfd_data->sess_num != 0)
                {
                    BFD_stats_log_sess (bfd_log_stats_sess_idx);
                }

#ifdef BFD_LOG_SESS_HIST_W_STATS
                if (bfd_data->sess_num != 0)
                {
                    /* log BFD session */
                    BFD_sess_data_log (bfd_log_stats_sess_idx);

                    /* log BFD history */
                    BFD_history_log (bfd_log_stats_sess_idx);
                }
#endif /* #ifdef BFD_LOG_SESS_HIST_W_STATS */
            }
        }
        else
        {
            /* subsequence */

            bfd_log_stats_sess_idx = BFD_sess_data_get_next(
                bfd_log_stats_sess_idx);
            if (bfd_log_stats_sess_idx == BFD_INV_SESS_IDX)
            {
                /* restart log BFD statistics/counts timer */
                bfd_log_stats_timer += BFD_LOG_STATS_TIMER;
                bfd_log_stats_timer_first_sess = TRUE;
            }
            else
            {
                /* log BFD statistics/counts of BFD session */
                if (bfd_data->sess_num != 0)
                {
                    BFD_stats_log_sess (bfd_log_stats_sess_idx);
                }

#ifdef BFD_LOG_SESS_HIST_W_STATS
                if (bfd_data->sess_num != 0)
                {
                    /* log BFD session */
                    BFD_sess_data_log (bfd_log_stats_sess_idx);

                    /* log BFD history */
                    BFD_history_log (bfd_log_stats_sess_idx);
                }
#endif /* #ifdef BFD_LOG_SESS_HIST_W_STATS */
            }
        }
    }
#endif /* #ifdef BFD_LOG_STATS_TIMER_ENABLED */




    /* go through all BFD sessions to check all BFD timers */

    /* get first BFD session */
    sess_idx = BFD_sess_data_get_first();

    /* loop until no more BFD session */
    while (sess_idx != BFD_INV_SESS_IDX)
    {
        /*
         * call the corresponding function in BFD session module to check
         * all BFD timers
         */
        BFD_sess_timer (sess_idx);

        /* get next BFD session */
        sess_idx = BFD_sess_data_get_next (sess_idx);
    }

    bfd_data->stats.good_timer++;
}


/*
 * Name:        BFD_add_sockets
 *
 * Abstract:    function to call before pselect() to add BFD sockets
 *
 * Parameters:  none
 *
 * Returns:
 *     read_sock_set - set of all IPM read sockets
 *                     including BFD sockets
 *     max_sock      - maximum value of all IPM read sockets
 */
void BFD_add_sockets (fd_set *read_sock_set, int *max_sock)
{
#if 1

    BFD_RETVAL ret_val;
    int sess_idx;
    int recv_sock;

    /* no log */

    BFD_check_thread();

    if (IS_VALID_PTR (read_sock_set) == FALSE)
    {
        BFD_LOCAL_ERROR ("invalid read_sock_set pointer %p\n",
            read_sock_set);
        bfd_data->stats.inv_read_sock_set_ptr++;
        return;
    }

    ret_val = BFD_check_init();
    if (ret_val != BFD_SUCCESS)
    {
        return;
    }

    /* go through all BFD sessions to add sockets */

    /* get first BFD session */
    sess_idx = BFD_sess_data_get_first();

    /* loop until no more BFD session */
    while (sess_idx != BFD_INV_SESS_IDX)
    {
        recv_sock = bfd_data->sess[sess_idx].recv_sock;

        if (recv_sock == -1)
        {
            /* socket is not created and bind yet */
            sess_idx = BFD_sess_data_get_next (sess_idx);
            continue;
        }


        /*
         * add this socket to set of all IPM sockets;
         * it is OK to add multiple times
         */
        FD_SET (recv_sock, read_sock_set);

        /* maintain maximum value of all IPM sockets */
        if (recv_sock > *max_sock)
        {
            *max_sock = recv_sock;
        }

        /* get next BFD session */
        sess_idx = BFD_sess_data_get_next (sess_idx);
    }

    bfd_data->stats.good_add_sockets++;

#else

    BFD_RETVAL ret_val;
    int sess_idx;
    int recv_sock;

    /* no log */

    BFD_check_thread();

    if (IS_VALID_PTR (read_sock_set) == FALSE)
    {
        BFD_LOCAL_ERROR ("invalid read_sock_set pointer %p\n",
            read_sock_set);
        bfd_data->stats.inv_read_sock_set_ptr++;
        return;
    }

    ret_val = BFD_check_init();
    if (ret_val != BFD_SUCCESS)
    {
        return;
    }

    /* go through all BFD sessions to add sockets */

    /* get first BFD session */
    sess_idx = BFD_sess_data_get_first();

    /* loop until no more BFD session */
    while (sess_idx != BFD_INV_SESS_IDX)
    {
        recv_sock = bfd_data->sess[sess_idx].recv_sock;

        /*
         * add this socket to set of all IPM sockets;
         * it is OK to add multiple times
         */
        FD_SET (recv_sock, read_sock_set);

        /* maintain maximum value of all IPM sockets */
        if (recv_sock > *max_sock)
        {
            *max_sock = recv_sock;
        }

        /* get next BFD session */
        sess_idx = BFD_sess_data_get_next (sess_idx);
    }

    bfd_data->stats.good_add_sockets++;

#endif

}


/*
 * Name:        BFD_recv
 *
 * Abstract:    function to call when BFD sockets have incoming messages
 *
 * Parameters:
 *     read_sock_set - set of all IPM read sockets
 *                     including BFD sockets
 * Returns:     none
 */
void BFD_recv (fd_set *read_sock_set)
{

#if 1

    BFD_RETVAL ret_val;
    BFD_RETVAL sess_ret_val;
    int sess_idx;
    int num_of_sess = 0;

    /* no log */

    BFD_check_thread();

    if (IS_VALID_PTR (read_sock_set) == FALSE)
    {
        BFD_LOCAL_ERROR ("invalid read_sock_set pointer %p\n",
            read_sock_set);
        bfd_data->stats.inv_read_sock_set_ptr++;
        return;
    }

    ret_val = BFD_check_init();
    if (ret_val != BFD_SUCCESS)
    {
        return;
    }

    /* go through all BFD sessions to check for incoming message */

    /* get first BFD session */
    sess_idx = BFD_sess_data_get_first();

    /* loop until no more BFD session */
    ret_val = BFD_SUCCESS;
    while (sess_idx != BFD_INV_SESS_IDX)
    {
        if (bfd_data->sess[sess_idx].recv_sock == -1)
        {
            /* socket is not created and bind yet */
            sess_idx = BFD_sess_data_get_next (sess_idx);
            continue;
        }

        if (FD_ISSET (bfd_data->sess[sess_idx].recv_sock, read_sock_set) != 0)
        {
            /* this BFD session has incoming message */

            num_of_sess++;

            /*
             * call the corresponding function in BFD transport module
             * to receive BFD/UDP message
             */
            sess_ret_val = BFD_trans_recv (sess_idx);
            if (sess_ret_val != BFD_SUCCESS)
            {
                ret_val = sess_ret_val;
                sess_idx = BFD_sess_data_get_next (sess_idx);
                continue;
            }

            /*
             * call the corresponding function in BFD session module
             * to process BFD/UDP message
             */
            sess_ret_val = BFD_sess_recv (sess_idx);
            if (sess_ret_val != BFD_SUCCESS)
            {
                ret_val = sess_ret_val;
                sess_idx = BFD_sess_data_get_next (sess_idx);
                continue;
            }
        }

        /* get next BFD session */
        sess_idx = BFD_sess_data_get_next (sess_idx);
    }

    if (ret_val == BFD_SUCCESS)
    {
        if (num_of_sess > 0)
        {
            bfd_data->stats.good_recv++;
        }
        else
        {
            bfd_data->stats.recv_no_sess++;
        }
    }

#else

    BFD_RETVAL ret_val;
    BFD_RETVAL sess_ret_val;
    int sess_idx;
    int num_of_sess = 0;

    /* no log */

    BFD_check_thread();

    if (IS_VALID_PTR (read_sock_set) == FALSE)
    {
        BFD_LOCAL_ERROR ("invalid read_sock_set pointer %p\n",
            read_sock_set);
        bfd_data->stats.inv_read_sock_set_ptr++;
        return;
    }

    ret_val = BFD_check_init();
    if (ret_val != BFD_SUCCESS)
    {
        return;
    }

    /* go through all BFD sessions to check for incoming message */

    /* get first BFD session */
    sess_idx = BFD_sess_data_get_first();

    /* loop until no more BFD session */
    ret_val = BFD_SUCCESS;
    while (sess_idx != BFD_INV_SESS_IDX)
    {
        if (FD_ISSET (bfd_data->sess[sess_idx].recv_sock, read_sock_set) != 0)
        {
            /* this BFD session has incoming message */

            num_of_sess++;

            /*
             * call the corresponding function in BFD transport module
             * to receive BFD/UDP message
             */
            sess_ret_val = BFD_trans_recv (sess_idx);
            if (sess_ret_val != BFD_SUCCESS)
            {
                ret_val = sess_ret_val;
                sess_idx = BFD_sess_data_get_next (sess_idx);
                continue;
            }

            /*
             * call the corresponding function in BFD session module
             * to process BFD/UDP message
             */
            sess_ret_val = BFD_sess_recv (sess_idx);
            if (sess_ret_val != BFD_SUCCESS)
            {
                ret_val = sess_ret_val;
                sess_idx = BFD_sess_data_get_next (sess_idx);
                continue;
            }
        }

        /* get next BFD session */
        sess_idx = BFD_sess_data_get_next (sess_idx);
    }

    if (ret_val == BFD_SUCCESS)
    {
        if (num_of_sess > 0)
        {
            bfd_data->stats.good_recv++;
        }
        else
        {
            bfd_data->stats.recv_no_sess++;
        }
    }

#endif

}


/*  
 * Name:        BFD_audit
 * 
 * Abstract:    function for LCP to audit BFD session with BFD
 * 
 * Parameters:
 *     local_ip         - local IP of this BFD session
 *     remote_ip        - remote IP
 *     
 *     detect_time_mult - detection time multiplier
 *     min_tx           - desired min Tx interval  
 *     min_rx           - required min Tx interval  
 *     
 *     begin_middle_end - BFD audit sequence
 *     
 * Returns:     none
 */
void BFD_audit (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    uint8_t detect_time_mult, uint32_t min_tx, uint32_t min_rx,
    BFD_AUDIT_SEQ begin_middle_end)
{   
    BFD_RETVAL ret_val;
    int sess_idx;

    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];
     
    if (BFD_LOG_ENABLED)
    {
        IPM_ipaddr2p (local_ip, &local_ip_str[0], sizeof(local_ip_str));
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));
     
        BFD_LOG (
            "BFD_audit: "
            "local_ip %s, "
            "remote_ip %s, "
            "detect_time_mult %u, "
            "min_tx %u, "
            "min_rx %u, "
            "begin_middle_end %s\n",
            &local_ip_str[0], 
            &remote_ip_str[0], 
            detect_time_mult,
            min_tx,
            min_rx,
            BFD_AUDIT_SEQ_to_str (begin_middle_end));
    }       
            
    ret_val = BFD_check_ip (local_ip, remote_ip);
    if (ret_val != BFD_SUCCESS)
    {
        return;
    }

    ret_val = BFD_check_cfg (detect_time_mult, &min_tx, &min_rx);
    if (ret_val != BFD_SUCCESS)
    {
        return;
    }

    if ((begin_middle_end != BFD_AUDIT_SEQ_BEGIN) &&
        (begin_middle_end != BFD_AUDIT_SEQ_MIDDLE) &&
        (begin_middle_end != BFD_AUDIT_SEQ_END))
    {
        BFD_LOCAL_ERROR ("invalid BFD audit sequence %d, "
            "%d, %d, or %d expected\n", begin_middle_end,
            BFD_AUDIT_SEQ_BEGIN, BFD_AUDIT_SEQ_MIDDLE, BFD_AUDIT_SEQ_END);
        bfd_data->stats.inv_begin_middle_end++;
        return;
    }
     
    ret_val = BFD_check_init();
    if (ret_val != BFD_SUCCESS)
    {
        return;
    }

    if (((unsigned long) bfd_audit_cb_func ^
         (unsigned long) BFD_CHECKSUM_SEED) !=
        bfd_audit_cb_func_checksum)
    {
        BFD_LOCAL_ERROR ("corrupted call-back function for BFD to audit "
            "BFD sesstion with LCP\n");
        bfd_data->stats.corrupt_audit_cb_func++;
        return;
    }

    if (begin_middle_end == BFD_AUDIT_SEQ_BEGIN)
    {
        /* begin of BFD audit sequence */

        /* mark all BFD sessions as not-audited */

        /* get first BFD session */
        sess_idx = BFD_sess_data_get_first();

        /* loop until no more BFD session */
        while (sess_idx != BFD_INV_SESS_IDX)
        {
            /* mark this BFD sessions as not-audited */
            bfd_data->sess[sess_idx].audited = FALSE;

            /* get next BFD session */
            sess_idx = BFD_sess_data_get_next (sess_idx);
        }
    }

    ret_val = BFD_SUCCESS;

    /* get BFD session index with local IP and remote IP */
    ret_val = BFD_sess_data_get (local_ip, remote_ip, &sess_idx);
    if (ret_val != BFD_SUCCESS)
    {
        /* BFD session does not exist */

        BFD_INTERNAL_ERROR ("audit: BFD session exists at LCP, but not at "
            "BFD implementation, create it\n");
        bfd_data->stats.ext_audit++;

        /* automatically create a new BFD session */
        ret_val = BFD_create_sess (local_ip, remote_ip, detect_time_mult,
            min_tx, min_rx);
        if (ret_val == BFD_SUCCESS)
        {
            /* successfully create new BFD session */

            /* get BFD session index with local IP and remote IP */
            ret_val = BFD_sess_data_get (local_ip, remote_ip, &sess_idx);
        }
    }
    else if ((bfd_data->sess[sess_idx].local.detect_time_mult !=
            detect_time_mult) ||
        (bfd_data->sess[sess_idx].local.cfg_min_tx != min_tx) ||
        (bfd_data->sess[sess_idx].local.ofc.min_rx != min_rx))
    {
        /* BFD session parameters are different */

        BFD_INTERNAL_ERROR ("audit: BFD session parameters are different, "
            "change them\n");
        bfd_data->stats.ext_audit++;

        /* automatically change BFD session parameters */
        ret_val = BFD_change_cfg (local_ip, remote_ip, detect_time_mult,
            min_tx, min_rx);
    }

    if (ret_val == BFD_SUCCESS)
    {
        /* mark this BFD session as audited */
        bfd_data->sess[sess_idx].audited = TRUE;
    }
     
    if (begin_middle_end == BFD_AUDIT_SEQ_END)
    {
        /* end of BFD audit sequence */

        /*
         * find all not-audited BFD sessions;
         * audit them with LCP
         */

        /* get first BFD session */
        sess_idx = BFD_sess_data_get_first();

        /* loop until no more BFD session */
        while (sess_idx != BFD_INV_SESS_IDX)
        {
            if (bfd_data->sess[sess_idx].audited == FALSE)
            {
                /* this BFD sessions is not-audited */

                if (bfd_audit_cb_func != NULL)
                {
                    /* externally audit this BFD session with LCP */
                    BFD_sess_ext_audit (sess_idx);
                }
            }

            /* get next BFD session */
            sess_idx = BFD_sess_data_get_next (sess_idx);
        }

    }

    bfd_data->stats.good_audit++;
}   


/*
 * Name:        BFD_log_data
 *
 * Abstract:    function for CLI to log BFD internal data of all BFD
 *              sessions
 *
 * Parameters:  none
 *
 * Returns:     none
 */
void BFD_log_data()
{
    BFD_RETVAL ret_val;

    char buffer[BFD_ERR_LOG_BUF_SIZE];
    char *ptr = buffer;
    int size = sizeof(buffer);

    int sess_idx;
    int count;

    /* no log */

    BFD_check_thread();

    ret_val = BFD_check_init();
    if (ret_val != BFD_SUCCESS)
    {
        return;
    }

    /* count number of BFD sessions */
    count = 0;
    sess_idx = BFD_sess_data_get_first();
    while (sess_idx != BFD_INV_SESS_IDX)
    {
        count++;
        sess_idx = BFD_sess_data_get_next (sess_idx);
    }

    BFD_PRINTF (ptr, size,
        "BFD protocol data:\n"

        "    bfd_has_init                         %u\n"
        "\n"
        "    bfd_audit_cb_func                    %p\n"
        "    bfd_audit_cb_func_checksum           0x%lx\n"
        "\n"
        "    bfd_state_change_cb_func             %p\n"
        "    bfd_state_change_cb_func_checksum    0x%lx\n"
        "\n"
        "    bfd_data                             %p\n"
        "    bfd_data_checksum                    0x%lx\n"
        "\n"
        "    bfd_thread_id                        0x%lx\n"
        "\n"
        "    bfd_cur_time                         %u\n"
        "\n"
        "    bfd_audit_timer                      %u\n"
        "    bfd_audit_timer_first_sess           %u\n"
        "    bfd_audit_sess_idx                   %d\n"
        "\n"
        "    bfd_log_stats_timer                  %u\n"
        "    bfd_log_stats_timer_first_sess       %u\n"
        "    bfd_log_stats_sess_idx               %d\n"
        "\n"
        "    bfd_data.sess_num                    %u\n"
        "    number of BFD sessions               %u\n",

        bfd_has_init,

        bfd_audit_cb_func,
        bfd_audit_cb_func_checksum,

        bfd_state_change_cb_func,
        bfd_state_change_cb_func_checksum,

        bfd_data,
        bfd_data_checksum,

        bfd_thread_id,

        bfd_cur_time,

        bfd_audit_timer,
        bfd_audit_timer_first_sess,
        bfd_audit_sess_idx,

        bfd_log_stats_timer,
        bfd_log_stats_timer_first_sess,
        bfd_log_stats_sess_idx,

        bfd_data->sess_num,
        count);


    BFD_LOG_FORCED (buffer);


    /* go through all BFD sessions to log BFD session data */

    /* get first BFD session */
    sess_idx = BFD_sess_data_get_first();

    /* loop until no more BFD session */
    while (sess_idx != BFD_INV_SESS_IDX)
    {
        /*
         * call the corresponding function in BFD session data module to
         * log BFD internal data
         */
        BFD_sess_data_log (sess_idx);

        /*
         * call the corresponding function in BFD session data module to
         * log BFD history
         */
        BFD_history_log (sess_idx);

        /* get next BFD session */
        sess_idx = BFD_sess_data_get_next (sess_idx);
    }
}


/*
 * Name:        BFD_log_stats
 *
 * Abstract:    function for CLI to log BFD statistics/counts of BFD
 *              protocol and all BFD sessions
 *
 * Parameters:  none
 *
 * Returns:     none
 */
void BFD_log_stats()
{
    BFD_RETVAL ret_val;
    int sess_idx;

    /* no log */

    BFD_check_thread();

    ret_val = BFD_check_init();
    if (ret_val != BFD_SUCCESS)
    {
        return;
    }

    /*
     * call the corresponding function in BFD statistic module to log BFD
     * statistics/counts of BFD protocol
     */
    BFD_stats_log_bfd();

    /* go through all BFD sessions to log BFD statistics/counts */

    /* get first BFD session */
    sess_idx = BFD_sess_data_get_first();

    /* loop until no more BFD session */
    while (sess_idx != BFD_INV_SESS_IDX)
    {
        /*
         * call the corresponding function in BFD statistic module to log
         * BFD statistics/counts of a BFD session
         */
        BFD_stats_log_sess (sess_idx);

        /* get next BFD session */
        sess_idx = BFD_sess_data_get_next (sess_idx);
    }
}
