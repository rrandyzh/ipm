/*************************************************************************
 *
 * File:     ARPNDP_sess_data.c
 *
 * Abstract: implementation file of ARP/NDP session data module
 *           this module handles ARP/NDP session data
 *           ARP/NDP session data is implemented with an array
 *
 * Data:     none
 *
 * Functions:
 *     ARPNDP_sess_data_init      - function to initialize ARP/NDP session
 *                                  data module
 *
 *     ARPNDP_sess_data_calc_kyes - function to calculate keys of ARP/NDP
 *                                  session data using OS interface index
 *                                  and remote IP
 *     ARPNDP_sess_data_chk_keys  - function to check keys with other ARP/NDP
 *                                  sessions
 *
 *     ARPNDP_sess_data_alloc     - function to allocate a new ARP/NDP session
 *     ARPNDP_sess_data_free      - function to free an existing ARP/NDP
 *                                  session
 *
 *     ARPNDP_sess_data_get       - function to get/find an ARP/NDP session
 *                                  with OS interface index and remote IP
 *
 *     ARPNDP_sess_data_get_first - function to get first ARP/NDP session
 *     ARPNDP_sess_data_get_next  - function to get next ARP/NDP session
 *
 *     ARPNDP_sess_data_log       - function to log ARP/NDP session data for
 *                                  an ARP/NDP session
 *
 ************************************************************************/

#include "ARPNDP_int_hdr.h"


/*
 * Name:        ARPNDP_sess_data_init
 *
 * Abstract:    function to initialize ARP/NDP session data module
 *
 * Parameters:  none
 *
 * Retunrs:     none
 */
void ARPNDP_sess_data_init()
{
    memset (arpndp_data->sess, 0, sizeof(arpndp_data->sess));
    arpndp_data->sess_num = 0;
}


/* 
 * Name:        ARPNDP_sess_data_calc_keys
 * 
 * Abstract:    function to calculate keys of ARP/NDP session data using OS
 *              interface index and remote IP
 * 
 * Parameters:  none
 *     intf_idx  - OS interface index
 *     remote_ip - remote IP
 * 
 * Retunrs:
 *     key_add   - calculated key_add
 *     key_xor   - calculated key_xor
 */
uint32_t /*key_add*/ ARPNDP_sess_data_calc_keys (int intf_idx,
    IPM_IPADDR *remote_ip, uint32_t *key_xor)
{   
    uint32_t add = (uint32_t) ARPNDP_CHECKSUM_SEED;
    uint32_t xor = 0;

    add += intf_idx;
    xor ^= add;

    if (remote_ip->addrtype == IPM_IPV4)
    {
        add = ((add << 4) | (add >> 28)) + remote_ip->ipaddr[0];
        xor ^= add;

        add = ((add << 4) | (add >> 28)) + remote_ip->ipaddr[0];
        xor ^= add;
    }
    else
    {
        add = ((add << 2) | (add >> 30)) + remote_ip->ipaddr[0];
        xor ^= add;

        add = ((add << 2) | (add >> 30)) + remote_ip->ipaddr[1];
        xor ^= add;

        add = ((add << 2) | (add >> 30)) + remote_ip->ipaddr[2];
        xor ^= add;

        add = ((add << 2) | (add >> 30)) + remote_ip->ipaddr[3];
        xor ^= add;
    }

    *key_xor = xor;

    if (add == 0)
    {
        add = (uint32_t) ARPNDP_CHECKSUM_SEED;
    }

    return add;
}


/*  
 * Name:        ARPNDP_sess_data_chk_keys
 * 
 * Abstract:    function to check keys with other ARP/NDP sessions
 *          
 * Parameters:  none
 *     sess_idx           - ARP/NDP session index
 *     key_add            - key_add of this ARP/NDP session
 *     key_xor            - key_xor of this ARP/NDP session
 *     
 * Retunrs:
 *     ret_val            - success or failure
 *     other_sess_idx_ptr - other ARP/NDP session index that has matching keys
 */    
ARPNDP_RETVAL ARPNDP_sess_data_chk_keys (int sess_idx, uint32_t key_add,
    uint32_t key_xor, int *other_sess_idx_ptr)
{   
    int other_sess_idx;
    
    /* get first ARP/NDP session */
    other_sess_idx = ARPNDP_sess_data_get_first();
    
    /* loop until no more ARP/NDP session */
    while (other_sess_idx != ARPNDP_INV_SESS_IDX)
    {
        if ((other_sess_idx != sess_idx) &&
            (arpndp_data->sess[other_sess_idx].key_add == key_add) &&
            (arpndp_data->sess[other_sess_idx].key_xor == key_xor))
        {
            *other_sess_idx_ptr = other_sess_idx;
            return ARPNDP_LOCAL_FAIL;
        }   
            
        /* get next ARP/NDP session */
        other_sess_idx = ARPNDP_sess_data_get_next (other_sess_idx);
    }

    return ARPNDP_SUCCESS;
}


/*
 * Name:        ARPNDP_sess_data_alloc
 *
 * Abstract:    function to allocate a new ARP/NDP session
 *
 * Parameters:
 *     intf_idx  - OS interface index
 *     remote_ip - remote IP
 *
 * Retunrs:
 *     ret_val  - success or failure
 *
 *     sess_idx - newly allocated ARP/NDP session index
 */
ARPNDP_RETVAL ARPNDP_sess_data_alloc (int intf_idx, IPM_IPADDR *remote_ip,
    int *sess_idx)
{
    ARPNDP_RETVAL ret_val;
    int i;

    uint32_t key_add;
    uint32_t key_xor;
    int other_sess_idx;

    char remote_ip_str[IPM_IPMAXSTRSIZE];
    char other_remote_ip_str[IPM_IPMAXSTRSIZE];

    /*
     * calculate keys of ARP/NDP session data using local IP and remote IP
     */
    key_add = ARPNDP_sess_data_calc_keys (intf_idx, remote_ip, &key_xor);

    /*
     * make sure no other ARP/NDP session with the same keys, i.e. same
     * OS interface index and remote IP
     */
    ret_val = ARPNDP_sess_data_chk_keys (ARPNDP_INV_SESS_IDX, key_add,
        key_xor, &other_sess_idx);
    if (ret_val != ARPNDP_SUCCESS)
    {
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));
            
        IPM_ipaddr2p (&arpndp_data->sess[other_sess_idx].remote_ip,
            &other_remote_ip_str[0], sizeof(other_remote_ip_str));
            
        ARPNDP_LOCAL_ERROR ("this ARP/NDP session with OS interface index %d "
            "and remote IP %s has the same key_add 0x%08x and key_xor 0x%08x "
            "as another ARP/NDP session with OS interface index %d and "
            "remote IP %s\n", intf_idx, &remote_ip_str[0], key_add, key_xor,
            arpndp_data->sess[other_sess_idx].intf_idx,
            &other_remote_ip_str[0]);
        arpndp_data->stats.inv_intf_idx_remote_ip++;
        return ret_val;
    }

    /* go through the whole ARP/NDP session array */
    for (i = 0; i < ARPNDP_SESS_MAX; i++)
    {
        /* look for free ARP/NDP session entry */
        if (arpndp_data->sess[i].key_add == 0)
        {
            /* found free ARP/NDP session entry */

            memset (&arpndp_data->sess[i], 0, sizeof(ARPNDP_SESS));

            /* mark this entry as in use */
            arpndp_data->sess[i].key_add = key_add;
            arpndp_data->sess[i].key_xor = key_xor;

            /* return ARP/NDP session index */
            *sess_idx = i;

            /* update arpndp_data->sess_num if needed */
            if (i >= arpndp_data->sess_num)
            {
                arpndp_data->sess_num = i + 1;
            }

            return ARPNDP_SUCCESS;
        }
    }

    ARPNDP_INTERNAL_ERROR ("%d ARP/NDP sessions are not enough\n",
        ARPNDP_SESS_MAX);
    arpndp_data->stats.not_enough_sess++;
    return ARPNDP_INTERNAL_FAIL;
}


/*
 * Name:        ARPNDP_sess_data_free
 *
 * Abstract:    function to free an existing ARP/NDP session
 *
 * Parameters:
 *     sess_idx - ARP/NDP session index to free
 *
 * Retunrs:     none
 */
void ARPNDP_sess_data_free (int sess_idx)
{
    /* mark this ARP/NDP session entry as not in use */
    arpndp_data->sess[sess_idx].key_add = 0;

    /* update arpndp_data->sess_num if needed */
    if ((sess_idx + 1) == arpndp_data->sess_num)
    {
        /* skip previously freed entries if needed */
        while ((sess_idx > 0) &&
            (arpndp_data->sess[sess_idx - 1].key_add == 0))
        {
            sess_idx--;
        }

        arpndp_data->sess_num = sess_idx;
    }
}


/*
 * Name:        ARPNDP_sess_data_get
 *
 * Abstract:    function to get/find an ARP/NDP session with OS interface
 *              index and remote IP
 *
 * Parameters:
 *     intf_idx  - OS interface index
 *     remote_ip - remote IP
 *
 * Retunrs:
 *     ret_val   - success or failure
 *
 *     sess_idx  - ARP/NDP session index
 */
ARPNDP_RETVAL ARPNDP_sess_data_get (int intf_idx, IPM_IPADDR *remote_ip,
    int *sess_idx)
{
    int i;
    uint32_t key_add;
    uint32_t key_xor;

    char remote_ip_str[IPM_IPMAXSTRSIZE];

    if (arpndp_data->sess_num > ARPNDP_SESS_MAX)
    {
        ARPNDP_INTERNAL_ERROR ("invalid arpndp_data->sess_num %d, "
            "<= %d expected\n", arpndp_data->sess_num, ARPNDP_SESS_MAX);
        arpndp_data->stats.inv_arpndp_sess_num++;
        return ARPNDP_INTERNAL_FAIL;
    }

    /*
     * calculate keys of ARP/NDP session data using OS interface index and
     * remote IP
     */
    key_add = ARPNDP_sess_data_calc_keys (intf_idx, remote_ip, &key_xor);

    /* go through current number of ARP/NDP sessions */
    for (i = 0; i < arpndp_data->sess_num; i++)
    {
        if ((arpndp_data->sess[i].key_add != key_add) ||
            (arpndp_data->sess[i].key_xor != key_xor))
        {
            /* not in use or different OS interface index or remote IP */
            continue;
        }
        else
        {
            /* found matching OS interface index and remote IP */

            /* return ARP/NDP session index */
            *sess_idx = i;

            return ARPNDP_SUCCESS;
        }
    }

    IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));

    ARPNDP_LOCAL_ERROR ("OS interface index %d and remote IP %s not found "
        "in ARP/NDP sessions\n", intf_idx, &remote_ip_str[0]);
    arpndp_data->stats.sess_not_found++;
    return ARPNDP_LOCAL_FAIL;
}


/*
 * Name:        ARPNDP_sess_data_get_first
 *
 * Abstract:    function to get first ARP/NDP session
 *
 * Parameters:  none
 *
 * Retunrs:
 *     sess_idx - first ARP/NDP session index
 *                ARPNDP_INV_IDX (-1) if end of list
 */
int ARPNDP_sess_data_get_first()
{
    int sess_idx;

    if (arpndp_data->sess_num > ARPNDP_SESS_MAX)
    {
        ARPNDP_INTERNAL_ERROR ("invalid arpndp_data->sess_num %d, "
            "<= %d expected\n", arpndp_data->sess_num, ARPNDP_SESS_MAX);
        arpndp_data->stats.inv_arpndp_sess_num++;
        return ARPNDP_INTERNAL_FAIL;
    }

    /*
     * go through current number of ARP/NDP sessions
     * start with first ARP/NDP session entry (array index == 0)
     */
    for (sess_idx = 0; sess_idx < arpndp_data->sess_num; sess_idx++)
    {
        if (arpndp_data->sess[sess_idx].key_add != 0)
        {
            /* in use */

            return sess_idx;
        }
    }

    /* end of list */
    return ARPNDP_INV_SESS_IDX;
}


/*
 * Name:        ARPNDP_sess_data_get_next
 *
 * Abstract:    function to get next ARP/NDP session
 *
 * Parameters:
 *     sess_idx - previous ARP/NDP session index
 *
 * Retunrs:
 *     sess_idx - next ARP/NDP sess index
 *                ARPNDP_INV_IDX (-1) if end of list
 */
int ARPNDP_sess_data_get_next (int sess_idx)
{
    /* no arpndp_data->sess_num check */

    /*
     * go through current number of ARP/NDP sessions
     * resume from previous ARP/NDP session
     */
    for (sess_idx++; sess_idx < arpndp_data->sess_num; sess_idx++)
    {
        if (arpndp_data->sess[sess_idx].key_add != 0)
        {
            /* in use */

            return sess_idx;
        }
    }

    /* end of list */
    return ARPNDP_INV_SESS_IDX;
}


/*
 * Name:        ARPNDP_sess_data_log
 *
 * Abstract:    function to log ARP/NDP session data for an ARP/NDP session
 *
 * Parameters:
 *     sess_idx  - ARPNDP session index
 *
 * Returns:     none
 */
void ARPNDP_sess_data_log (int sess_idx)
{
    int i;

    char buffer[ARPNDP_ERR_LOG_BUF_SIZE];
    char *ptr = buffer;
    int size = sizeof(buffer);

    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];

    char mac_addr_str[(ETH_ALEN * 3) + 1];

    /* prepare local IP */
    IPM_ipaddr2p (&arpndp_data->sess[sess_idx].local_ip, &local_ip_str[0],
        sizeof(local_ip_str));

    /* prepare remote IP */
    IPM_ipaddr2p (&arpndp_data->sess[sess_idx].remote_ip, &remote_ip_str[0],
        sizeof(remote_ip_str));

    /* prepare MAC address */
    ptr = &mac_addr_str[0];
    for (i = 0; i < ETH_ALEN; i++)
    {
        if (i != 0)
        {
            *ptr = ':';
            ptr++;
        }

        ptr += sprintf (ptr, "%02x", arpndp_data->sess[sess_idx].mac_addr[i]);
    }

    ptr = &buffer[0];
    size = sizeof(buffer);

    ARPNDP_PRINTF (ptr, size,
        "ARP/NDP session data at index %d:\n"

        "    key_add                              0x%08x\n"
        "    key_xor                              0x%08x\n"
        "\n"
        "    intf_idx                             %d\n"
        "    remote_ip                            %s\n"
        "\n"
        "    local_ip                             %s\n"
        "    local_ip_checkum                     0x%08x\n"
        "\n"
        "    detect_time_mult                     %u\n"
        "    min_tx                               %u\n"
        "    min_rx                               %u\n"
        "\n"
        "    intf_name                            %s\n"
        "    mac_addr                             %s\n"
        "    intf_data_checkum                    0x%02x\n"
        "\n"
        "    protocol                             %s\n"
        "    admin_state                          %s\n"
        "    sess_state                           %s\n"
        "    has_recv_msg                         %s\n"
        "\n"
        "    transmission_timer                   %u\n"
        "    transmission_timer_countdown         %u\n"
        "    fault_detect_timer_fire_num          %u\n"
        "\n"
        "    sock                                 %u\n"
        "\n"
        "    recv_count                           %u\n"
        "    send_count                           %u\n"
        "\n"
        "    audited                              %u\n"
        "\n" 
        "    missed_hb                            %u\n",

        sess_idx,

        arpndp_data->sess[sess_idx].key_add,
        arpndp_data->sess[sess_idx].key_xor,

        arpndp_data->sess[sess_idx].intf_idx,
        &remote_ip_str[0],

        &local_ip_str[0],
        arpndp_data->sess[sess_idx].local_ip_checksum,

        arpndp_data->sess[sess_idx].detect_time_mult,
        arpndp_data->sess[sess_idx].min_tx,
        arpndp_data->sess[sess_idx].min_rx,

        arpndp_data->sess[sess_idx].intf_name,
        &mac_addr_str[0],
        arpndp_data->sess[sess_idx].intf_data_checksum,

        ARPNDP_PROTOCOL_to_str (arpndp_data->sess[sess_idx].protocol),
        ARPNDP_ADMIN_STATE_to_str (arpndp_data->sess[sess_idx].admin_state),
        ARPNDP_SESS_STATE_to_str (arpndp_data->sess[sess_idx].sess_state),
        ARPNDP_BOOL_to_str (arpndp_data->sess[sess_idx].has_recv_msg),

        arpndp_data->sess[sess_idx].transmission_timer,
        arpndp_data->sess[sess_idx].transmission_timer_countdown,
        arpndp_data->sess[sess_idx].fault_detect_timer_fire_num,

        arpndp_data->sess[sess_idx].sock,

        arpndp_data->sess[sess_idx].recv_count,
        arpndp_data->sess[sess_idx].send_count,

        arpndp_data->sess[sess_idx].audited,

        arpndp_data->sess[sess_idx].missed_hb);

    ARPNDP_LOG_FORCED (buffer);
}
