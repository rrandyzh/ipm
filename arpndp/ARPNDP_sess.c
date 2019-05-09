/*************************************************************************
 *
 * File:     ARPNDP_sess.c
 *
 * Abstract: implementation file of ARP/NDP session module
 *           this module handles ARP/NDP session
 *
 * Data:     none
 *
 * Functions:
 *     ARPNDP_sess_create          - function to create a new ARP/NDP session
 *                                   without creating socket and binding
 *     ARPNDP_sess_change_cfg      - function to change ARP/NDP session
 *                                   parameters after ARP/NDP session has
 *                                   been created
 *     ARPNDP_sess_destroy         - function to destroy an existing ARP/NDP
 *                                   session
 *
 *     ARPNDP_sess_get_sess_state  - function to get session state an ARP/NDP
 *                                   session
 *     ARPNDP_sess_set_admin_state - function to set administrative state of
 *                                   an ARP/NDP session
 *
 *     ARPNDP_sess_get_stats       - function to get statistics/counts of an
 *                                   ARP/NDP session
 *     ARPNDP_sess_clear_stats     - function to clear statistics/counts of
 *                                   an ARP/NDP session
 *
 *     ARPNDP_sess_timer           - function to call every 5 milli-seconds
 *                                   to implement ARP/NDP timers
 *     ARPNDP_sess_recv            - function to process a received ARP/NDP
 *                                   message
 *
 *     ARPNDP_sess_check_sock      - function to check this socket in this
 *                                   ARP/NDP session with sockets in all
 *                                   other ARP/NDP sessions
 *
 *     ARPNDP_sess_ext_audit       - function to externally audit ARP/NDP
 *                                   session
 *     ARPNDP_sess_int_audit       - function to internally audit ARP/NDP
 *                                   session
 *
 ************************************************************************/

#include "ARPNDP_int_hdr.h"


/*
 * Name:        ARPNDP_sess_create
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
ARPNDP_RETVAL ARPNDP_sess_create (int intf_idx, IPM_IPADDR *remote_ip,
    IPM_IPADDR *local_ip, uint8_t detect_time_mult, uint32_t min_tx,
    uint32_t min_rx)
{
    ARPNDP_RETVAL ret_val;
    int sess_idx = ARPNDP_INV_SESS_IDX;

    /* allocate a new ARP/NDP session data */
    ret_val = ARPNDP_sess_data_alloc (intf_idx, remote_ip, &sess_idx);
    if (ret_val != ARPNDP_SUCCESS)
    {
        return ret_val;
    }


    /* save LCP data in ARP/NDP session */

    arpndp_data->sess[sess_idx].intf_idx = intf_idx;
    arpndp_data->sess[sess_idx].remote_ip = *remote_ip;

    arpndp_data->sess[sess_idx].local_ip = *local_ip;
    arpndp_data->sess[sess_idx].detect_time_mult = detect_time_mult;
    arpndp_data->sess[sess_idx].min_tx = min_tx;
    arpndp_data->sess[sess_idx].min_rx = min_rx;

    /* checksum local IP */
    if (local_ip->addrtype == IPM_IPV4)
    {
        arpndp_data->sess[sess_idx].local_ip_checksum =
            arpndp_data->sess[sess_idx].local_ip.ipaddr[0] ^
            (uint32_t) ARPNDP_CHECKSUM_SEED;
    }
    else
    {
        arpndp_data->sess[sess_idx].local_ip_checksum =
            arpndp_data->sess[sess_idx].local_ip.ipaddr[0] ^
            arpndp_data->sess[sess_idx].local_ip.ipaddr[1] ^
            arpndp_data->sess[sess_idx].local_ip.ipaddr[2] ^
            arpndp_data->sess[sess_idx].local_ip.ipaddr[3] ^
            (uint32_t) ARPNDP_CHECKSUM_SEED;
    }

    /* record ARP/NDP history */

    if (local_ip->addrtype == IPM_IPV4)
    {
        ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_LOCAL_IP_IPV4,
            (uint32_t) local_ip->ipaddr[0]);
    }
    else
    {
        ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_LOCAL_IP_IPV6_1,
            (uint32_t) local_ip->ipaddr[0]);
        ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_LOCAL_IP_IPV6_2,
            (uint32_t) local_ip->ipaddr[1]);
        ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_LOCAL_IP_IPV6_3,
            (uint32_t) local_ip->ipaddr[2]);
        ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_LOCAL_IP_IPV6_4,
            (uint32_t) local_ip->ipaddr[3]);
    }

    ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_DETECT_TIME_MULT,
        (uint32_t) detect_time_mult);
    ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_MIN_TX,
        (uint32_t) min_tx);
    ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_MIN_RX,
        (uint32_t) min_rx);


    /* populate default values in ARP/NDP session */

    if (local_ip->addrtype == IPM_IPV4)
    {
        arpndp_data->sess[sess_idx].protocol = ARPNDP_PROTOCOL_ARP;
    }
    else
    {
        arpndp_data->sess[sess_idx].protocol = ARPNDP_PROTOCOL_NDP;
    }

    arpndp_data->sess[sess_idx].admin_state = ARPNDP_ADMIN_STATE_DOWN;
    arpndp_data->sess[sess_idx].sess_state = ARPNDP_SESS_STATE_ADMIN_DOWN;
    arpndp_data->sess[sess_idx].has_recv_msg = FALSE;


    /*
     * transmission timer is not started 
     * until session state is DOWN, INIT, or UP
     */
    ARPNDP_timer_stop_transmission_timer (sess_idx);


    /* get OS interface data (name and MAC address) */
    ret_val = ARPNDP_trans_get_intf_data (sess_idx);
    if (ret_val != ARPNDP_SUCCESS)
    {
        ARPNDP_sess_data_free (sess_idx);
        return ret_val;
    }


    /* create sockets and bind later */
    arpndp_data->sess[sess_idx].sock = -1;

    arpndp_data->sess[sess_idx].recv_count = 0;
    arpndp_data->sess[sess_idx].send_count = 0;

    return ARPNDP_SUCCESS;
}


/*
 * Name:        ARPNDP_sess_change_cfg
 *
 * Abstract:    function to change ARP/NDP session parameters after ARP/NDP
 *              session has been created
 *
 * Parameters:
 *     sess_idx         - ARP/NDP session index
 *
 *     local_ip         - new local IP
 *     detect_time_mult - new detection time multiplier
 *     min_tx           - new desired min Tx interval
 *     min_rx           - new required min Tx interval
 *
 * Returns:
 *     ret_val          - success or failure
 */
ARPNDP_RETVAL ARPNDP_sess_change_cfg (int sess_idx, IPM_IPADDR *local_ip,
    uint8_t detect_time_mult, uint32_t min_tx, uint32_t min_rx)
{
    if (local_ip->addrtype == IPM_IPV4)
    {
        if (local_ip->ipaddr[0] !=
            arpndp_data->sess[sess_idx].local_ip.ipaddr[0])
        {
            ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_LOCAL_IP_IPV4,
                (uint32_t) local_ip->ipaddr[0]);

            arpndp_data->sess[sess_idx].local_ip = *local_ip;

            arpndp_data->sess[sess_idx].local_ip_checksum =
                arpndp_data->sess[sess_idx].local_ip.ipaddr[0] ^
                (uint32_t) ARPNDP_CHECKSUM_SEED;
        }
    }
    else
    {
        if (memcmp( local_ip->ipaddr, 
            arpndp_data->sess[sess_idx].local_ip.ipaddr,
            sizeof(arpndp_data->sess[sess_idx].local_ip.ipaddr)) != 0)
        {
            ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_LOCAL_IP_IPV6_1,
                (uint32_t) local_ip->ipaddr[0]);
            ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_LOCAL_IP_IPV6_2,
                (uint32_t) local_ip->ipaddr[1]);
            ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_LOCAL_IP_IPV6_3,
                (uint32_t) local_ip->ipaddr[2]);
            ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_LOCAL_IP_IPV6_4,
                (uint32_t) local_ip->ipaddr[3]);

            arpndp_data->sess[sess_idx].local_ip = *local_ip;

            arpndp_data->sess[sess_idx].local_ip_checksum =
                arpndp_data->sess[sess_idx].local_ip.ipaddr[0] ^
                arpndp_data->sess[sess_idx].local_ip.ipaddr[1] ^
                arpndp_data->sess[sess_idx].local_ip.ipaddr[2] ^
                arpndp_data->sess[sess_idx].local_ip.ipaddr[3] ^
                (uint32_t) ARPNDP_CHECKSUM_SEED;
        }
    }

    if (detect_time_mult != arpndp_data->sess[sess_idx].detect_time_mult)
    {
        /* detection time multiplier changes */

        ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_DETECT_TIME_MULT,
            (uint32_t) detect_time_mult);

        arpndp_data->sess[sess_idx].detect_time_mult = detect_time_mult;
    }

    if (min_tx != arpndp_data->sess[sess_idx].min_tx)
    {
        /* desired min Tx changes */

        ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_MIN_TX,
            (uint32_t) min_tx);

        arpndp_data->sess[sess_idx].min_tx = min_tx;
    }

    if (min_rx != arpndp_data->sess[sess_idx].min_rx)
    {
        /* required min Rx changes */

        ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_MIN_RX,
            (uint32_t) min_rx);

        arpndp_data->sess[sess_idx].min_rx = min_rx;
    }

    if (arpndp_data->sess[sess_idx].sess_state !=
        ARPNDP_SESS_STATE_ADMIN_DOWN)
    {
        /* send message immediately when not in ADMIN DOWN state */
        (void) ARPNDP_trans_send (sess_idx);

        /* restart transmission timer */
        ARPNDP_timer_start_transmission_timer (sess_idx);
    }

    return ARPNDP_SUCCESS;
}


/*
 * Name:        ARPNDP_sess_destroy
 *
 * Abstract:    function to destroy an existing ARP/NDP session
 *
 * Parameters:
 *     sess_idx - ARP/NDP sesion index
 *
 * Returns:     none
 */
void ARPNDP_sess_destroy (int sess_idx)
{
    /* close socket */
    ARPNDP_trans_close_sock (sess_idx);

    /* free ARP/NDP session data */
    ARPNDP_sess_data_free (sess_idx);
}


/*
 * Name:        ARPNDP_sess_get_sess_state
 *
 * Abstract:    function to get session state of an ARP/NDP session
 *
 * Parameters:
 *     sess_idx - ARP/NDP sesion index
 *
 * Returns:     none
 */
void ARPNDP_sess_get_sess_state (int sess_idx, ARPNDP_SESS_STATE *sess_state)
{
    /* return session state */
    *sess_state = arpndp_data->sess[sess_idx].sess_state;
}


/*
 * Name:        ARPNDP_sess_set_admin_state
 *
 * Abstract:    function to set administrative state of an ARP/NDP session
 *
 * Parameters:
 *     sess_idx        - ARP/NDP sesion index
 *     new_admin_state - new administrative state
 *
 * Returns:
 *     ret_val         - success or failure
 */
ARPNDP_RETVAL ARPNDP_sess_set_admin_state (int sess_idx,
    ARPNDP_ADMIN_STATE new_admin_state)
{
    ARPNDP_RETVAL ret_val;

    if (new_admin_state == arpndp_data->sess[sess_idx].admin_state)
    {
        /* no change in admin state */
        return ARPNDP_SUCCESS;
    }

    ARPNDP_history_add (sess_idx, ARPNDP_HISTORY_ADMIN_STATE,
        (uint32_t) new_admin_state);

    /* run finite state machine with new admin state */
    ret_val = ARPNDP_fsm_run (sess_idx, (ARPNDP_EVENT) new_admin_state);
    if (ret_val != ARPNDP_SUCCESS)
    {
        return ret_val;
    }

    /* save new admin state */
    arpndp_data->sess[sess_idx].admin_state = new_admin_state;

    return ARPNDP_SUCCESS;
}


/*
 * Name:        ARPNDP_sess_get_stats
 *
 * Abstract:    function to get statistics/counts of an ARP/NDP session
 *
 * Parameters:
 *     sess_idx - ARP/NDP sesion index
 *
 * Returns:
 *     missed_hb - missed heartbeat
 */
void ARPNDP_sess_get_stats (int sess_idx, uint32_t *missed_hb)
{
    /* return missed heartbeat */
    *missed_hb = arpndp_data->sess[sess_idx].missed_hb;
}


/*     
 * Name:        ARPNDP_sess_clear_stats
 *
 * Abstract:    function to clear statistics/counts of an ARP/NDP session
 *
 * Parameters:
 *     sess_idx - ARP/NDP sesion index
 * 
 * Returns:     none
 */
void ARPNDP_sess_clear_stats (int sess_idx)
{
    /* clear missed heartbeat */
    arpndp_data->sess[sess_idx].missed_hb = 0;
}


/*
 * Name:        ARPNDP_sess_timer
 *
 * Abstract:    function to call every 5 milli-seconds to implement ARP/NDP
 *              timers
 *
 * Parameters:
 *     sess_idx - ARP/NDP sesion index
 *
 * Returns:     none
 */
void ARPNDP_sess_timer (int sess_idx)
{
    ARPNDP_RETVAL ret_val;

    /* create socket and bind if having not done so */
    if (arpndp_data->sess[sess_idx].sock == -1)
    {
        ret_val = ARPNDP_trans_create_sock (sess_idx);
        if (ret_val != ARPNDP_SUCCESS)
        {
            /* fail to create socket and bind; try again later */
            return;
        }
    }

    if (arpndp_data->sess[sess_idx].transmission_timer != 0)
    {
        /* transmission timer is running */

        arpndp_data->sess[sess_idx].transmission_timer_countdown -=
            ARPNDP_TIMER_INTERVAL;
        if (arpndp_data->sess[sess_idx].transmission_timer_countdown <= 0)
        {
            /* transmision timer fires */
            ARPNDP_timer_fire_transmission_timer (sess_idx);
        }
    }
}


/*
 * Name:        ARPNDP_sess_recv
 *
 * Abstract:    function to process a received ARP/NDP message
 *
 * Parameters:
 *     sess_idx - ARP/NDP sesion index
 *
 * Returns:
 *     ret_val  - success or failure
 */
ARPNDP_RETVAL ARPNDP_sess_recv (int sess_idx)
{
    ARPNDP_RETVAL ret_val;

    if (arpndp_data->sess[sess_idx].sess_state ==
        ARPNDP_SESS_STATE_ADMIN_DOWN)
    {
        /* ignore all incoming messages while in ADMIN DOWN state */
        return ARPNDP_SUCCESS;
    }

    /* incoming message is good */
    arpndp_data->sess[sess_idx].has_recv_msg = TRUE;

    /* run finite state machine */
    ret_val = ARPNDP_fsm_run (sess_idx, ARPNDP_EVENT_RECV_MSG);
    if (ret_val != ARPNDP_SUCCESS)
    {
        return ret_val;
    }

    return ARPNDP_SUCCESS;
}


/* 
 * Name:        ARPNDP_sess_check_sock
 * 
 * Abstract:    function to check this socket in this ARP/NDP session with
 *              sockets in all other ARP/NDP sessions
 * 
 * Parameters:
 *     sess_idx - ARP/NDP sesion index
 *     sock     - socket to check
 * 
 * Returns:
  *     ret_val - success or failure
*/
ARPNDP_RETVAL ARPNDP_sess_check_sock (int sess_idx, int sock)
{
    ARPNDP_RETVAL ret_val = ARPNDP_SUCCESS;
    int other_sess_idx;

    /* get first ARP/NDP session */
    other_sess_idx = ARPNDP_sess_data_get_first();

    /* loop until no more ARP/NDP session */
    while (other_sess_idx != ARPNDP_INV_SESS_IDX)
    {
        if (sess_idx != sess_idx)
        {
            if (sock == arpndp_data->sess[other_sess_idx].sock)
            {
                ARPNDP_INTERNAL_ERROR ("two or more sockets with the same "
                    "file descriptor, close and re-create the sockets\n");
                (void) close (arpndp_data->sess[other_sess_idx].sock);
                ARPNDP_trans_create_sock (other_sess_idx);
                ret_val = ARPNDP_INTERNAL_FAIL;
            }
        }

        /* get next ARP/NDP session */
        other_sess_idx = ARPNDP_sess_data_get_next (other_sess_idx);
    }

    return ret_val;
}


/*
 * Name:        ARPNDP_sess_ext_audit
 *
 * Abstract:    function to externally audit an ARP/NDP session
 * 
 * Parameters:
 *     sess_idx - ARP/NDP sesion index 
 * 
 * Returns:     none
 */    
void ARPNDP_sess_ext_audit (int sess_idx) 
{      
    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];

    if (ARPNDP_LOG_ENABLED)
    {
        IPM_ipaddr2p (&arpndp_data->sess[sess_idx].local_ip,
            &local_ip_str[0], sizeof(local_ip_str));
        IPM_ipaddr2p (&arpndp_data->sess[sess_idx].remote_ip,
            &remote_ip_str[0], sizeof(remote_ip_str));

        ARPNDP_LOG (
            "ARPNDP_fsm_report_state_change: "
            "intf_idx %d, "
            "remote_ip %s, "
            "local_ip %s, "
            "detect_time_mult %u\n"
            "min_tx %u\n"
            "min_rx %u\n",
            arpndp_data->sess[sess_idx].intf_idx,
            &remote_ip_str[0],
            &local_ip_str[0],
            arpndp_data->sess[sess_idx].detect_time_mult,
            arpndp_data->sess[sess_idx].min_tx,
            arpndp_data->sess[sess_idx].min_rx);
    }

    if ((* arpndp_audit_cb_func)(
        arpndp_data->sess[sess_idx].intf_idx,
        &arpndp_data->sess[sess_idx].remote_ip,
        &arpndp_data->sess[sess_idx].local_ip,
        arpndp_data->sess[sess_idx].detect_time_mult,
        arpndp_data->sess[sess_idx].min_tx,
        arpndp_data->sess[sess_idx].min_rx) != ARPNDP_SUCCESS)
    {
        /* LCP does not have this ARP/NDP session */

        ARPNDP_AUDIT_ERROR (sess_idx, "ARP/NDP session exists at ARP/NDP "
            "implementation, but not at LCP, destroy it\n");
        arpndp_data->stats.ext_audit++;

        /* automatically destroy ARP/NDP session */
        ARPNDP_destroy_sess (arpndp_data->sess[sess_idx].intf_idx,
            &arpndp_data->sess[sess_idx].remote_ip);
    }
    else
    {
        /* ths ARP/NDP session was created recently */

        /* there might be an ARPNDP_change_cfg() */

        /* mark this ARP/NDP session as audited */
        arpndp_data->sess[sess_idx].audited = TRUE;
    }
}


/*
 * Name:        ARPNDP_sess_int_audit
 *
 * Abstract:    function to internally audit ARP/NDP session
 *
 * Parameters:
 *     sess_idx - ARP/NDP sesion index
 *
 * Returns:     none
 */
void ARPNDP_sess_int_audit (int sess_idx)
{
    ARPNDP_RETVAL ret_val;
    uint32_t key_add;
    uint32_t key_xor;
    int other_sess_idx;

    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];
    char other_remote_ip_str[IPM_IPMAXSTRSIZE];

    uint32_t local_ip_checksum;

    int i;
    unsigned char *ptr;
    unsigned char checksum;
    char mac_addr_str[(ETH_ALEN * 3) + 1];


    key_add = ARPNDP_sess_data_calc_keys (
        arpndp_data->sess[sess_idx].intf_idx,
        &arpndp_data->sess[sess_idx].remote_ip, &key_xor);
    if ((key_add != arpndp_data->sess[sess_idx].key_add) ||
        (key_xor != arpndp_data->sess[sess_idx].key_xor))
    {
        IPM_ipaddr2p (&arpndp_data->sess[sess_idx].remote_ip,
            &remote_ip_str[0], sizeof(remote_ip_str));

        ARPNDP_AUDIT_ERROR (sess_idx, "invalid key_add 0x%08x, "
            "key_xor 0x%08x, intf_idx %d, or remote_ip %s, "
            "destroy this ARP/NDP session\n",
            key_add, key_xor, arpndp_data->sess[sess_idx].intf_idx,
            &remote_ip_str[0]);
        ARPNDP_sess_destroy (sess_idx);
        arpndp_data->stats.int_audit_major++;
        return;
    }

    ret_val = ARPNDP_sess_data_chk_keys (sess_idx, key_add, key_xor,
        &other_sess_idx);
    if (ret_val != ARPNDP_SUCCESS)
    {
        IPM_ipaddr2p (&arpndp_data->sess[sess_idx].remote_ip,
            &remote_ip_str[0], sizeof(remote_ip_str));

        IPM_ipaddr2p (&arpndp_data->sess[other_sess_idx].remote_ip,
            &other_remote_ip_str[0], sizeof(other_remote_ip_str));

        ARPNDP_LOCAL_ERROR (sess_idx, "this ARP/NDP session with intf_idx %d "
            "and remote IP %s has the same key_add 0x%08x and key_xor 0x%08x "
            " as another ARP/NDP session with intf_idx %d and remote IP %s, "
            "destroy both ARP/NDP sessions\n",
            arpndp_data->sess[sess_idx].intf_idx, &remote_ip_str[0],
            key_add, key_xor,
            arpndp_data->sess[other_sess_idx].intf_idx,
            &other_remote_ip_str[0]);
        ARPNDP_sess_destroy (sess_idx);
        ARPNDP_sess_destroy (other_sess_idx);
        arpndp_data->stats.int_audit_major++;
        return;
    }

    if ((arpndp_data->sess[sess_idx].remote_ip.addrtype != IPM_IPV4) &&
        (arpndp_data->sess[sess_idx].remote_ip.addrtype != IPM_IPV6))
    {
        ARPNDP_LOCAL_ERROR (sess_idx, "invalid remote_ip address type %d; "
            "%d or %d expected; destroy this ARP/NDP session\n",
            arpndp_data->sess[sess_idx].remote_ip.addrtype,
            IPM_IPV4, IPM_IPV6);
        ARPNDP_sess_destroy (sess_idx);
        arpndp_data->stats.int_audit_major++;
        return;
    }

    if ((arpndp_data->sess[sess_idx].local_ip.addrtype != IPM_IPV4) &&
        (arpndp_data->sess[sess_idx].local_ip.addrtype != IPM_IPV6))
    {
        ARPNDP_LOCAL_ERROR (sess_idx, "invalid local_ip address type %d; "
            "%d or %d expected; destroy this ARP/NDP session\n",
            arpndp_data->sess[sess_idx].local_ip.addrtype,
            IPM_IPV4, IPM_IPV6);
        ARPNDP_sess_destroy (sess_idx);
        arpndp_data->stats.int_audit_major++;
        return;
    }

    if (arpndp_data->sess[sess_idx].local_ip.addrtype !=
        arpndp_data->sess[sess_idx].remote_ip.addrtype)
    {
        ARPNDP_LOCAL_ERROR (sess_idx, "local_ip address type %d != "
            "remote_ip address type %d; they must be the same; "
            "destroy this ARP/NDP session\n",
            arpndp_data->sess[sess_idx].local_ip.addrtype,
            arpndp_data->sess[sess_idx].remote_ip.addrtype);
        ARPNDP_sess_destroy (sess_idx);
        arpndp_data->stats.int_audit_major++;
        return;
    }

    if (arpndp_data->sess[sess_idx].local_ip.addrtype == IPM_IPV4)
    {
        local_ip_checksum =
            arpndp_data->sess[sess_idx].local_ip.ipaddr[0] ^
            (uint32_t) ARPNDP_CHECKSUM_SEED;
    }
    else
    {
        local_ip_checksum =
            arpndp_data->sess[sess_idx].local_ip.ipaddr[0] ^
            arpndp_data->sess[sess_idx].local_ip.ipaddr[1] ^
            arpndp_data->sess[sess_idx].local_ip.ipaddr[2] ^
            arpndp_data->sess[sess_idx].local_ip.ipaddr[3] ^
            (uint32_t) ARPNDP_CHECKSUM_SEED;
    }

    if (local_ip_checksum != arpndp_data->sess[sess_idx].local_ip_checksum)
    {
        ARPNDP_LOCAL_ERROR (sess_idx, "invalid 'local_ip'; "
            "destroy this ARP/NDP session\n");
        ARPNDP_sess_destroy (sess_idx);
        arpndp_data->stats.int_audit_major++;
        return;
    }



    if ((arpndp_data->sess[sess_idx].detect_time_mult <
            ARPNDP_DETECT_TIME_MULT_MIN) ||
        (arpndp_data->sess[sess_idx].detect_time_mult >
            ARPNDP_DETECT_TIME_MULT_MAX))
    {
        ARPNDP_AUDIT_ERROR (sess_idx, "invalid 'mult_time_mult' %u, "
            "set to %u\n", arpndp_data->sess[sess_idx].detect_time_mult,
            ARPNDP_DETECT_TIME_MULT_DEF);
        arpndp_data->sess[sess_idx].detect_time_mult =
            ARPNDP_DETECT_TIME_MULT_DEF;
        arpndp_data->stats.int_audit_minor++;
    }

    if ((arpndp_data->sess[sess_idx].min_tx < ARPNDP_MIN_TX_MIN) ||
        (arpndp_data->sess[sess_idx].min_tx > ARPNDP_MIN_TX_MAX))
    {
        ARPNDP_AUDIT_ERROR (sess_idx, "invalid 'min_tx' %u, "
            "set to %u\n", arpndp_data->sess[sess_idx].min_tx,
            ARPNDP_MIN_TX_DEF);
        arpndp_data->sess[sess_idx].min_tx = ARPNDP_MIN_TX_DEF;
        arpndp_data->stats.int_audit_minor++;
    }
    else if ((arpndp_data->sess[sess_idx].min_tx % ARPNDP_MIN_TX_UNIT) != 0)
    {
        ARPNDP_AUDIT_ERROR (sess_idx, "invalid 'min_tx' %u, "
            "set to %u\n", arpndp_data->sess[sess_idx].min_tx,
            ( arpndp_data->sess[sess_idx].min_tx / ARPNDP_MIN_TX_UNIT) *
            ARPNDP_MIN_TX_UNIT);
        arpndp_data->sess[sess_idx].min_tx =
            ( arpndp_data->sess[sess_idx].min_tx / ARPNDP_MIN_TX_UNIT) *
            ARPNDP_MIN_TX_UNIT;
        arpndp_data->stats.int_audit_minor++;
    }

    if ((arpndp_data->sess[sess_idx].min_rx < ARPNDP_MIN_RX_MIN) ||
        (arpndp_data->sess[sess_idx].min_rx > ARPNDP_MIN_RX_MAX))
    {
        ARPNDP_AUDIT_ERROR (sess_idx, "invalid 'min_rx' %u, "
            "set to %u\n", arpndp_data->sess[sess_idx].min_rx,
            ARPNDP_MIN_RX_DEF);
        arpndp_data->sess[sess_idx].min_rx = ARPNDP_MIN_RX_DEF;
        arpndp_data->stats.int_audit_minor++;
    }
    else if ((arpndp_data->sess[sess_idx].min_rx % ARPNDP_MIN_RX_UNIT) != 0)
    {
        ARPNDP_AUDIT_ERROR (sess_idx, "invalid 'min_rx' %u, "
            "set to %u\n", arpndp_data->sess[sess_idx].min_rx,
            ( arpndp_data->sess[sess_idx].min_rx / ARPNDP_MIN_RX_UNIT) *
            ARPNDP_MIN_RX_UNIT);
        arpndp_data->sess[sess_idx].min_rx =
            ( arpndp_data->sess[sess_idx].min_rx / ARPNDP_MIN_RX_UNIT) *
            ARPNDP_MIN_RX_UNIT;
        arpndp_data->stats.int_audit_minor++;
    }

    checksum = (unsigned char) ARPNDP_CHECKSUM_SEED;

    ptr = (unsigned char *) arpndp_data->sess[sess_idx].intf_name;
    while (*ptr != 0)
    {
        checksum ^= *ptr;
        ptr++;
    }

    ptr = (unsigned char *) arpndp_data->sess[sess_idx].mac_addr;
    for (i = 0; i < ETH_ALEN; i++)
    {
        checksum ^= ptr[i];
    }

    if (checksum != arpndp_data->sess[sess_idx].intf_data_checksum)
    {
        sprintf (mac_addr_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            ptr[0], ptr[1],  ptr[2], ptr[3], ptr[4], ptr[5]);

        ARPNDP_LOCAL_ERROR (sess_idx, "invalid intf_name %s or mac_addr %s; "
            "get them again from OK\n",
            arpndp_data->sess[sess_idx].intf_name, &mac_addr_str[0]);
        ARPNDP_trans_get_intf_data (sess_idx);
        arpndp_data->stats.int_audit_minor++;
        return;
    }

    if ((arpndp_data->sess[sess_idx].protocol != ARPNDP_PROTOCOL_ARP) &&
        (arpndp_data->sess[sess_idx].protocol != ARPNDP_PROTOCOL_NDP))
    {
        ARPNDP_PROTOCOL protocol;
        if (arpndp_data->sess[sess_idx].local_ip.addrtype == IPM_IPV4)
        {
            protocol = ARPNDP_PROTOCOL_ARP;
        }
        else
        {
            protocol = ARPNDP_PROTOCOL_NDP;
        }

        ARPNDP_AUDIT_ERROR (sess_idx, "invalid 'protocol' %u, "
            "set to %u\n", arpndp_data->sess[sess_idx].protocol,
            protocol);
        arpndp_data->sess[sess_idx].protocol = protocol;
        arpndp_data->stats.int_audit_minor++;

    }

    if (((int) arpndp_data->sess[sess_idx].sess_state <
            ARPNDP_SESS_STATE_ADMIN_DOWN) ||
        (arpndp_data->sess[sess_idx].sess_state > ARPNDP_SESS_STATE_UP))
    {
        ARPNDP_SESS_STATE sess_state;
        if (arpndp_data->sess[sess_idx].transmission_timer == 0)
        {
            sess_state = ARPNDP_SESS_STATE_ADMIN_DOWN;
        }
        else
        {
            sess_state = ARPNDP_SESS_STATE_DOWN;
        }

        ARPNDP_AUDIT_ERROR (sess_idx, "invalid 'sess_state' %u, "
            "set to %u\n", arpndp_data->sess[sess_idx].sess_state,
            sess_state);
        arpndp_data->sess[sess_idx].sess_state = sess_state;
        arpndp_data->stats.int_audit_minor++;
    }

    if ((arpndp_data->sess[sess_idx].admin_state != ARPNDP_ADMIN_STATE_DOWN)
        && (arpndp_data->sess[sess_idx].admin_state != ARPNDP_ADMIN_STATE_UP))
    {   
        ARPNDP_ADMIN_STATE admin_state;
        if (arpndp_data->sess[sess_idx].sess_state ==
            ARPNDP_SESS_STATE_ADMIN_DOWN)
        {   
            admin_state = ARPNDP_ADMIN_STATE_DOWN;
        }   
        else
        {
            admin_state = ARPNDP_ADMIN_STATE_UP;
        }

        ARPNDP_AUDIT_ERROR (sess_idx, "invalid 'admin_state' %u, "
            "set to %u\n", arpndp_data->sess[sess_idx].admin_state,
            admin_state);

        arpndp_data->sess[sess_idx].admin_state = admin_state;
        arpndp_data->stats.int_audit_minor++;
    }

    if ((arpndp_data->sess[sess_idx].has_recv_msg != FALSE) &&
        (arpndp_data->sess[sess_idx].has_recv_msg != TRUE))
    {
        ARPNDP_AUDIT_ERROR (sess_idx, "invalid 'has_recv_msg' %u, "
            "set to %u\n", arpndp_data->sess[sess_idx].has_recv_msg, FALSE);
        arpndp_data->sess[sess_idx].has_recv_msg = FALSE;
        arpndp_data->stats.int_audit_minor++;
    }   



    if ((arpndp_data->sess[sess_idx].transmission_timer == 0) &&
        ( arpndp_data->sess[sess_idx].admin_state == ARPNDP_ADMIN_STATE_UP))
    {
        ARPNDP_AUDIT_ERROR (sess_idx, "transmission timer is off "
            "in UP admin state, start transmission timer\n");
        ARPNDP_timer_start_transmission_timer (sess_idx);
        arpndp_data->stats.int_audit_minor++;
    }

    if (arpndp_data->sess[sess_idx].transmission_timer == 0)
    {
        if (arpndp_data->sess[sess_idx].fault_detect_timer_fire_num != 0)
        {
            ARPNDP_AUDIT_ERROR (sess_idx, "invalid "
                "'fault_detect_timer_fire_num' %u, clear it\n",
                arpndp_data->sess[sess_idx].fault_detect_timer_fire_num);
            arpndp_data->sess[sess_idx].fault_detect_timer_fire_num = 0;
            arpndp_data->stats.int_audit_minor++;
        }
    }
    else
    {
        if ((arpndp_data->sess[sess_idx].transmission_timer <
                ARPNDP_TIMER_MIN) ||
            (arpndp_data->sess[sess_idx].transmission_timer >
                ARPNDP_TIMER_MAX))
        {   
            ARPNDP_AUDIT_ERROR (sess_idx, "invalid 'transmission_timer' "
                "%u, re-start transmission timer\n",
                arpndp_data->sess[sess_idx].transmission_timer);
            ARPNDP_timer_start_transmission_timer (sess_idx);
            arpndp_data->stats.int_audit_minor++;
        }

        if (arpndp_data->sess[sess_idx].fault_detect_timer_fire_num >=
            arpndp_data->sess[sess_idx].detect_time_mult)
        { 
            ARPNDP_AUDIT_ERROR (sess_idx, "invalid "
                "'fault_detect_timer_fire_num' %u, clear it\n",
                arpndp_data->sess[sess_idx].fault_detect_timer_fire_num);
            arpndp_data->sess[sess_idx].fault_detect_timer_fire_num = 0;
            arpndp_data->stats.int_audit_minor++;
        } 
    }

    if (arpndp_data->sess[sess_idx].transmission_timer_countdown >
        arpndp_data->sess[sess_idx].transmission_timer)
    {        
        ARPNDP_AUDIT_ERROR (sess_idx, "invalid "
            "'transmission_timer_countdown' %u, set to %u\n",
            arpndp_data->sess[sess_idx].transmission_timer_countdown,
            arpndp_data->sess[sess_idx].transmission_timer);
        arpndp_data->sess[sess_idx].transmission_timer_countdown =
            arpndp_data->sess[sess_idx].transmission_timer;
        arpndp_data->stats.int_audit_minor++;
    }   



    if ((arpndp_data->sess[sess_idx].sock < ARPNDP_SOCK_MIN) ||
        (arpndp_data->sess[sess_idx].sock > ARPNDP_SOCK_MAX))
    {
        ARPNDP_AUDIT_ERROR (sess_idx, "invalid 'sock' %u, "   
            "close and re-create the socket\n",
            arpndp_data->sess[sess_idx].sock);
        (void) close (arpndp_data->sess[sess_idx].sock);
        ARPNDP_trans_create_sock (sess_idx);
        arpndp_data->stats.int_audit_minor++;
    }

    if (ARPNDP_sess_check_sock (sess_idx, arpndp_data->sess[sess_idx].sock)
        != ARPNDP_SUCCESS)
    {
        ARPNDP_AUDIT_ERROR (sess_idx, "two or more sockets with the same "
            "file descriptor, close and re-create the sockets\n");
        (void) close (arpndp_data->sess[sess_idx].sock);
        ARPNDP_trans_create_sock (sess_idx);
        arpndp_data->stats.int_audit_minor++;
    }

    /* no audit on 'recv_count' and 'send_count' */

    if ((arpndp_data->sess[sess_idx].audited != FALSE) &&
        (arpndp_data->sess[sess_idx].audited != TRUE))
    {
        ARPNDP_AUDIT_ERROR (sess_idx, "invalid 'auditted' %u, set to 0\n",
            arpndp_data->sess[sess_idx].audited);
        arpndp_data->sess[sess_idx].audited = FALSE;
        arpndp_data->stats.int_audit_minor++;
    }

    /* no audit on 'missed_hb' */
}

