/*************************************************************************
 *
 * File:     BFD_sess_data.c
 *
 * Abstract: implementation file of BFD session data module
 *           this module handles BFD session data
 *           BFD session data is implemented with an array
 *
 * Data:     none
 *
 * Functions:
 *     BFD_sess_data_init      - function to initialize BFD session data
 *                               module
 *
 *     BFD_sess_data_calc_kyes - function to calculate keys of BFD
 *                               session data using local IP and remote IP
 *     BFD_sess_data_chk_keys  - function to check keys with other BFD
 *                               sessions
 *
 *     BFD_sess_data_alloc     - function to allocate a new BFD session
 *     BFD_sess_data_free      - function to free an existing BFD session
 *
 *     BFD_sess_data_get       - function to get/find a BFD session with
 *                               local IP and remote IP
 *     BFD_sess_data_get_fixed - function to get/find another fixed-IP BFD
 *                               session with the same IP and its local
 *                               session state is UP
 *
 *     BFD_sess_data_get_first - function to get first BFD session
 *     BFD_sess_data_get_next  - function to get next BFD session
 *
 *     BFD_sess_data_log       - function to log BFD session data for a BFD
 *                               session
 *
 ************************************************************************/

#include "BFD_int_hdr.h"


/*
 * Name:        BFD_sess_data_init
 *
 * Abstract:    function to initialize BFD session data module
 *
 * Parameters:  none
 *
 * Retunrs:     none
 */
void BFD_sess_data_init()
{
    memset (bfd_data->sess, 0, sizeof(bfd_data->sess));
    bfd_data->sess_num = 0;
}


/* 
 * Name:        BFD_sess_data_calc_keys
 * 
 * Abstract:    function to calculate keys of BFD session data using local
 *              IP and remote IP
 * 
 * Parameters:  none
 *     local_ip  - local IP of this BFD session
 *     remote_ip - remote IP
 * 
 * Retunrs:
 *     key_add   - calculated key_add
 *     key_xor   - calculated key_xor
 */
uint32_t /*key_add*/ BFD_sess_data_calc_keys (IPM_IPADDR *local_ip,
    IPM_IPADDR *remote_ip, uint32_t *key_xor)
{   
    uint32_t add = (uint32_t) BFD_CHECKSUM_SEED;
    uint32_t xor = 0;

    if (local_ip->addrtype == IPM_IPV4)
    {
        add += local_ip->ipaddr[0];
        xor ^= add;

        add = ((add << 4) | (add >> 28)) + local_ip->ipaddr[0];
        xor ^= add;
    }
    else
    {
        add += local_ip->ipaddr[0];
        xor ^= add;

        add = ((add << 2) | (add >> 30)) + local_ip->ipaddr[1];
        xor ^= add;

        add = ((add << 2) | (add >> 30)) + local_ip->ipaddr[2];
        xor ^= add;

        add = ((add << 2) | (add >> 30)) + local_ip->ipaddr[3];
        xor ^= add;
    }

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
        add = (uint32_t) BFD_CHECKSUM_SEED;
    }

    return add;
}


/*  
 * Name:        BFD_sess_data_chk_keys
 * 
 * Abstract:    function to check keys with other BFD sessions
 *          
 * Parameters:  none
 *     sess_idx           - BFD session index
 *     key_add            - key_add of this BFD session
 *     key_xor            - key_xor of this BFD session
 *     
 * Retunrs:
 *     ret_val            - success or failure
 *     other_sess_idx_ptr - other BFD session index that has matching keys
 */    
BFD_RETVAL BFD_sess_data_chk_keys (int sess_idx, uint32_t key_add,
    uint32_t key_xor, int *other_sess_idx_ptr)
{   
    int other_sess_idx;
    
    /* get first BFD session */
    other_sess_idx = BFD_sess_data_get_first();
    
    /* loop until no more BFD session */
    while (other_sess_idx != BFD_INV_SESS_IDX)
    {
        if ((other_sess_idx != sess_idx) &&
            (bfd_data->sess[other_sess_idx].key_add == key_add) &&
            (bfd_data->sess[other_sess_idx].key_xor == key_xor))
        {
            *other_sess_idx_ptr = other_sess_idx;
            return BFD_LOCAL_FAIL;
        }   
            
        /* get next BFD session */
        other_sess_idx = BFD_sess_data_get_next (other_sess_idx);
    }

    return BFD_SUCCESS;
}


/*
 * Name:        BFD_sess_data_alloc
 *
 * Abstract:    function to allocate a new BFD session
 *
 * Parameters:
 *     local_ip  - local IP
 *     remote_ip - remote IP
 *
 * Retunrs:
 *     ret_val   - success or failure
 *
 *     sess_idx  - newly allocated BFD session index
 */
BFD_RETVAL BFD_sess_data_alloc (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    int *sess_idx)
{
    BFD_RETVAL ret_val;
    int i;

    uint32_t key_add;
    uint32_t key_xor;
    int other_sess_idx;

    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];

    char other_local_ip_str[IPM_IPMAXSTRSIZE];
    char other_remote_ip_str[IPM_IPMAXSTRSIZE];

    /*
     * calculate keys of BFD session data using local IP and remote IP
     */
    key_add = BFD_sess_data_calc_keys (local_ip, remote_ip, &key_xor);

    /*
     * make sure no other BFD session with the same keys, i.e. same
     * local IP and remote IP
     */
    ret_val = BFD_sess_data_chk_keys (BFD_INV_SESS_IDX, key_add, key_xor,
        &other_sess_idx);
    if (ret_val != BFD_SUCCESS)
    {
        IPM_ipaddr2p (local_ip, &local_ip_str[0], sizeof(local_ip_str));
        IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));
            
        IPM_ipaddr2p (&bfd_data->sess[other_sess_idx].local_ip,
            &other_local_ip_str[0], sizeof(other_local_ip_str));
        IPM_ipaddr2p (&bfd_data->sess[other_sess_idx].remote_ip,
            &other_remote_ip_str[0], sizeof(other_remote_ip_str));
            
        BFD_LOCAL_ERROR ("this BFD session with local IP %s and remote "
            "IP %s has the same key_add 0x%08x and key_xor 0x%08x as "
            "another BFD session with local IP %s and remote IP %s\n",
            &local_ip_str[0], &remote_ip_str[0],
            key_add, key_xor,
            &other_local_ip_str[0], &other_remote_ip_str[0]);
        bfd_data->stats.inv_local_ip_remote_ip++;
        return ret_val;
    }

    /* go through the whole BFD session array */
    for (i = 0; i < BFD_SESS_MAX; i++)
    {
        /* look for free BFD session entry */
        if (bfd_data->sess[i].key_add == 0)
        {
            /* found free BFD session entry */

            memset (&bfd_data->sess[i], 0, sizeof(BFD_SESS));

            /* mark this entry as in use */
            bfd_data->sess[i].key_add = key_add;
            bfd_data->sess[i].key_xor = key_xor;

            /* return BFD session index */
            *sess_idx = i;

            /* update bfd_data->sess_num if needed */
            if (i >= bfd_data->sess_num)
            {
                bfd_data->sess_num = i + 1;
            }

            return BFD_SUCCESS;
        }
    }

    BFD_INTERNAL_ERROR ("%d BFD sessions are not enough\n", BFD_SESS_MAX);
    bfd_data->stats.not_enough_sess++;
    return BFD_INTERNAL_FAIL;
}


/*
 * Name:        BFD_sess_data_free
 *
 * Abstract:    function to free an existing BFD session
 *
 * Parameters:
 *     sess_idx - BFD session index to free
 *
 * Retunrs:     none
 */
void BFD_sess_data_free (int sess_idx)
{
    /* mark this BFD session entry as not in use */
    bfd_data->sess[sess_idx].key_add = 0;

    /* update bfd_data->sess_num if needed */
    if ((sess_idx + 1) == bfd_data->sess_num)
    {
        /* skip previously freed entries if needed */
        while ((sess_idx > 0) && (bfd_data->sess[sess_idx - 1].key_add == 0))
        {
            sess_idx--;
        }

        bfd_data->sess_num = sess_idx;
    }
}


/*
 * Name:        BFD_sess_data_get
 *
 * Abstract:    function to get/find a BFD session with local IP and
 *              remote IP
 *
 * Parameters:
 *     local_ip  - local IP of this BFD session
 *     remote_ip - remote IP
 *
 * Retunrs:
 *     ret_val   - success or failure
 *
 *     sess_idx  - BFD session index
 */
BFD_RETVAL BFD_sess_data_get (IPM_IPADDR *local_ip, IPM_IPADDR *remote_ip,
    int *sess_idx)
{
    int i;
    uint32_t key_add;
    uint32_t key_xor;

    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];

    if (bfd_data->sess_num > BFD_SESS_MAX)
    {
        BFD_INTERNAL_ERROR ("invalid bfd_data->sess_num %d, <= %d expected\n",
            bfd_data->sess_num, BFD_SESS_MAX);
        bfd_data->stats.inv_bfd_sess_num++;
        return BFD_INTERNAL_FAIL;
    }

    /*
     * calculate keys of BFD session data using local IP and remote IP
     */
    key_add = BFD_sess_data_calc_keys (local_ip, remote_ip, &key_xor);

    /* go through current number of BFD sessions */
    for (i = 0; i < bfd_data->sess_num; i++)
    {
        if ((bfd_data->sess[i].key_add != key_add) ||
            (bfd_data->sess[i].key_xor != key_xor))
        {
            /* not in use or different local/remote IPs */
            continue;
        }
        else
        {
            /* found matching local IPs and remote IPs */

            /* return BFD session index */
            *sess_idx = i;

            return BFD_SUCCESS;
        }
    }

    IPM_ipaddr2p (local_ip, &local_ip_str[0], sizeof(local_ip_str));
    IPM_ipaddr2p (remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));

    BFD_LOCAL_ERROR ("local IP %s and remote IP %s not found "
        "in BFD sessions\n", &local_ip_str[0], &remote_ip_str[0]);
    bfd_data->stats.sess_not_found++;
    return BFD_LOCAL_FAIL;
}


/*
 * Name:        BFD_sess_data_get_fixed
 *
 * Abstract:    function to get/find another fixed-IP BFD session with
 *              the same remote IP and its local session state is UP
 *
 * Parameters:
 *     remote_ip       - remote IP
 *     float_sess_idx  - floating-IP BFD session index
 *
 * Retunrs:
 *     ret_val         - success or failure
 *
 *     fixed_sess_idx  - fixed-IP BFD session index
 */
BFD_RETVAL BFD_sess_data_get_fixed (IPM_IPADDR *remote_ip,
    int float_sess_idx, int *fixed_sess_idx)
{
    int i;

    if (bfd_data->sess_num > BFD_SESS_MAX)
    {
        BFD_INTERNAL_ERROR ("invalid bfd_data->sess_num %d, <= %d expected\n",
            bfd_data->sess_num, BFD_SESS_MAX);
        bfd_data->stats.inv_bfd_sess_num++;
        return BFD_INTERNAL_FAIL;
    }

    /* go through current number of BFD sessions */
    for (i = 0; i < bfd_data->sess_num; i++)
    {
        if (i == float_sess_idx)
        {
            /* want different BFD session */
            continue;
        }
        else if (bfd_data->sess[i].key_add == 0)
        {
            /* not in use */
            continue;
        }
        else if (memcmp (&bfd_data->sess[i].remote_ip, remote_ip,
            sizeof(IPM_IPADDR)) != 0)
        {
            /* remote IPs do not match */
            continue;
        }
        else if (bfd_data->sess[i].local.sess_state != BFD_SESS_STATE_UP)
        {
            /* local session state is not UP */
            continue;
        }
        else
        {
            /*
             * found another BFD session with the same remote IP and local
             * session state is UP
             */

            /* return BFD session index */
            *fixed_sess_idx = i;

            return BFD_SUCCESS;
        }
    }

    return BFD_SESS_FAIL;
}


/*
 * Name:        BFD_sess_data_get_first
 *
 * Abstract:    function to get first BFD session
 *
 * Parameters:  none
 *
 * Retunrs:
 *     sess_idx - first BFD session index
 *                BFD_INV_IDX (-1) if end of list
 */
int BFD_sess_data_get_first()
{
    int sess_idx;

    if (bfd_data->sess_num > BFD_SESS_MAX)
    {
        BFD_INTERNAL_ERROR ("invalid bfd_data->sess_num %d, <= %d expected\n",
            bfd_data->sess_num, BFD_SESS_MAX);
        bfd_data->stats.inv_bfd_sess_num++;
        return BFD_INTERNAL_FAIL;
    }

    /*
     * go through current number of BFD sessions
     * start with first BFD session entry (array index == 0)
     */
    for (sess_idx = 0; sess_idx < bfd_data->sess_num; sess_idx++)
    {
        if (bfd_data->sess[sess_idx].key_add != 0)
        {
            /* in use */

            return sess_idx;
        }
    }

    /* end of list */
    return BFD_INV_SESS_IDX;
}


/*
 * Name:        BFD_sess_data_get_next
 *
 * Abstract:    function to get next BFD session
 *
 * Parameters:
 *     sess_idx - previous BFD session index
 *
 * Retunrs:
 *     sess_idx - next BFD sess index
 *                BFD_INV_IDX (-1) if end of list
 */
int BFD_sess_data_get_next (int sess_idx)
{
    /* no bfd_data->sess_num check */

    /*
     * go through current number of BFD sessions
     * resume from previous BFD session
     */
    for (sess_idx++; sess_idx < bfd_data->sess_num; sess_idx++)
    {
        if (bfd_data->sess[sess_idx].key_add != 0)
        {
            /* in use */

            return sess_idx;
        }
    }

    /* end of list */
    return BFD_INV_SESS_IDX;
}


/*
 * Name:        BFD_sess_data_log
 *
 * Abstract:    function to log BFD session data for a BFD session
 *
 * Parameters:
 *     sess_idx  - BFD session index
 *
 * Returns:     none
 */
void BFD_sess_data_log (int sess_idx)
{
    char buffer[BFD_ERR_LOG_BUF_SIZE];
    char *ptr = &buffer[0];
    int size = sizeof(buffer);

    char local_ip_str[IPM_IPMAXSTRSIZE];
    char remote_ip_str[IPM_IPMAXSTRSIZE];

    struct sockaddr_in *remote_sock_addr_ipv4;
    struct sockaddr_in6 *remote_sock_addr_ipv6;
    int remote_sock_addr_family;
    unsigned short remote_sock_addr_port;
    IPM_IPADDR remote_sock_addr_ip;
    char remote_sock_addr_ip_str[IPM_IPMAXSTRSIZE];

    /* prepare local IP */
    IPM_ipaddr2p (&bfd_data->sess[sess_idx].local_ip, &local_ip_str[0],
        sizeof(local_ip_str));

    /* prepare remote IP */
    IPM_ipaddr2p (&bfd_data->sess[sess_idx].remote_ip, &remote_ip_str[0],
        sizeof(remote_ip_str));

    /* prepare remote socket address */

    IPM_ipaddr_init (&remote_sock_addr_ip);

    if (bfd_data->sess[sess_idx].remote_ip.addrtype == IPM_IPV4)
    {
        remote_sock_addr_ipv4 = (struct sockaddr_in *)
            bfd_data->sess[sess_idx].send_remote_sock_addr;

        remote_sock_addr_family = remote_sock_addr_ipv4->sin_family;

        /* sin_port is in network byte-order */
        remote_sock_addr_port = ntohs (remote_sock_addr_ipv4->sin_port);

        remote_sock_addr_ip.addrtype = IPM_IPV4;

        /* ipaddr[0] and sin_addr.s_addr are in network byte-order */
        remote_sock_addr_ip.ipaddr[0] =
            remote_sock_addr_ipv4->sin_addr.s_addr;
    }
    else
    {
        remote_sock_addr_ipv6 = (struct sockaddr_in6 *)
            bfd_data->sess[sess_idx].send_remote_sock_addr;

        remote_sock_addr_family = remote_sock_addr_ipv6->sin6_family;

        /* sin6_port is in network byte-order */
        remote_sock_addr_port = ntohs (remote_sock_addr_ipv6->sin6_port);

        remote_sock_addr_ip.addrtype = IPM_IPV6;

        /* ipaddr[*] and sin6_addr.s6_addr are in network byte-order */
        memcpy (remote_sock_addr_ip.ipaddr,
            remote_sock_addr_ipv6->sin6_addr.s6_addr,
            sizeof(remote_sock_addr_ip.ipaddr));
    }

    IPM_ipaddr2p (&remote_sock_addr_ip, &remote_sock_addr_ip_str[0],
        sizeof(remote_sock_addr_ip_str));


    BFD_PRINTF (ptr, size,
        "BFD session data at index %d report 1/2:\n"

        "    key_add                              0x%08x\n"
        "    key_xor                              0x%08x\n"
        "\n"
        "    local_ip                             %s\n"
        "    remote_ip                            %s\n"
        "\n"
        "    active_passive                       %s\n"
        "    admin_state                          %s\n"
        "    local_poll_seq                       %s\n"
        "    has_recv_msg                         %s\n"
        "\n"
        "    local.diagnostic                     %s\n"
        "    local.sess_state                     %s\n"
        "    local.detect_time_mult               %u\n"
        "    local.discriminator                  %u\n"
        "\n"
        "    local.cfg_min_tx                     %u\n"
        "\n"
        "    local.ofc.min_tx                     %u\n"
        "    local.ofc.min_rx                     %u\n"
        "    local.trans.min_tx                   %u\n"
        "    local.trans.min_rx                   %u\n"
        "\n"
        "    remote.diagnostic                    %s\n"
        "    remote.sess_state                    %s\n"
        "    remote.detect_time_mult              %u\n"
        "    remote.discriminator                 %u\n"
        "\n"
        "    remote.min_tx                        %u\n"
        "    remote.min_rx                        %u\n"
        "\n"

#ifdef BFD_LISTEN_TIMER_ENABLED
        "    listen_timer                         %u\n"
        "    listen_timer_countdown               %u\n"
        "\n"
#endif /* #ifdef BFD_LISTEN_TIMER_ENABLED */

        "    transmission_timer                   %u\n"
        "    transmission_timer_countdown         %u\n"
        "\n"
        "    fault_detect_timer                   %u\n"
        "    fault_detect_timer_countdown         %u\n"
        "    fault_detect_timer_fire_num          %u\n",

        sess_idx,

        bfd_data->sess[sess_idx].key_add,
        bfd_data->sess[sess_idx].key_xor,

        &local_ip_str[0],
        remote_ip_str,

        BFD_ROLE_to_str (bfd_data->sess[sess_idx].active_passive),
        BFD_ADMIN_STATE_to_str (bfd_data->sess[sess_idx].admin_state),
        BFD_BOOL_to_str (bfd_data->sess[sess_idx].local_poll_seq),
        BFD_BOOL_to_str (bfd_data->sess[sess_idx].has_recv_msg),

        BFD_DIAGNOSTIC_to_str (bfd_data->sess[sess_idx].local.diagnostic),
        BFD_SESS_STATE_to_str (bfd_data->sess[sess_idx].local.sess_state),
        bfd_data->sess[sess_idx].local.detect_time_mult,
        bfd_data->sess[sess_idx].local.discriminator,

        bfd_data->sess[sess_idx].local.cfg_min_tx,

        bfd_data->sess[sess_idx].local.ofc.min_tx,
        bfd_data->sess[sess_idx].local.ofc.min_rx,
        bfd_data->sess[sess_idx].local.trans.min_tx,
        bfd_data->sess[sess_idx].local.trans.min_rx,

        BFD_DIAGNOSTIC_to_str (bfd_data->sess[sess_idx].remote.diagnostic),
        BFD_SESS_STATE_to_str (bfd_data->sess[sess_idx].remote.sess_state),
        bfd_data->sess[sess_idx].remote.detect_time_mult,
        bfd_data->sess[sess_idx].remote.discriminator,

        bfd_data->sess[sess_idx].remote.min_tx,
        bfd_data->sess[sess_idx].remote.min_rx,

#ifdef BFD_LISTEN_TIMER_ENABLED
        bfd_data->sess[sess_idx].listen_timer,
        bfd_data->sess[sess_idx].listen_timer_countdown,
#endif /* #ifdef BFD_LISTEN_TIMER_ENABLED */

        bfd_data->sess[sess_idx].transmission_timer,
        bfd_data->sess[sess_idx].transmission_timer_countdown,

        bfd_data->sess[sess_idx].fault_detect_timer,
        bfd_data->sess[sess_idx].fault_detect_timer_countdown,
        bfd_data->sess[sess_idx].fault_detect_timer_fire_num);

    BFD_LOG_FORCED (buffer);


    ptr = buffer;
    size = sizeof(buffer);

    BFD_PRINTF (ptr, size,
        "BFD session data at index %d report 2/2:\n"

        "    recv_sock                            %u\n"
        "    recv_msg                             %p\n"
        "\n" 
        "    recv_ttl_buffer                      %p\n"
        "    sizeof(recv_ttl_buffer)              %u\n"  
        "\n" 
        "    recv_msg_iov[0].iov_base             %p\n"
        "    recv_msg_iov[0].iov_len              %u\n"  
        "    recv_msg_iov[0]                      %p\n"
        "\n" 
        "    recv_remote_sock_addr_ipv4           %p\n"
        "    recv_remote_sock_addr_ipv6           %p\n"
        "    recv_port                            %p\n"
        "\n" 
        "    recv_msg_hdr.msg_iov                 %p\n"
        "    recv_msg_hdr.msg_iovlen              %u\n"  
        "\n" 
        "    recv_msg_hdr.msg_control             %p\n"
        "    recv_msg_hdr.msg_controllen          %u\n"  
        "\n" 
        "    recv_msg_hdr.msg_name                %p\n"
        "    recv_msg_hdr.msg_namelen             %u\n"  
        "\n" 
        "    recv_msg_hdr_checksum                0x%lx\n"  
        "\n" 
        "    local_send_port                      %u\n"
        "    send_sock                            %u\n"
        "\n" 
        "    send_remote_sock_addr_ipv4           %p\n"
        "    send_remote_sock_addr_ipv6           %p\n"
        "    send_remote_sock_addr                %p\n"
        "        family                           %u\n"  
        "        ip                               %s\n"  
        "        port                             %u\n"  
        "    send_remote_sock_addr_len            %u\n"  
        "\n" 
        "    send_remote_sock_addr_checksum       0x%lx\n"  
        "\n" 
        "    recv_count                           %u\n"
        "    send_count                           %u\n"
        "\n" 
        "    audited                              %u\n"
        "\n" 
        "    missed_hb                            %u\n"
        "\n" 
        "    corrupt_pkt                          %u\n",

        sess_idx,

        bfd_data->sess[sess_idx].recv_sock,
        &bfd_data->sess[sess_idx].recv_msg,

        bfd_data->sess[sess_idx].recv_ttl_buffer,
        sizeof (bfd_data->sess[sess_idx].recv_ttl_buffer),

        &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv4,
        &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv6,
        bfd_data->sess[sess_idx].recv_port,

        bfd_data->sess[sess_idx].recv_msg_iov[0].iov_base,
        bfd_data->sess[sess_idx].recv_msg_iov[0].iov_len,
        &bfd_data->sess[sess_idx].recv_msg_iov[0],

        bfd_data->sess[sess_idx].recv_msg_hdr.msg_iov,
        bfd_data->sess[sess_idx].recv_msg_hdr.msg_iovlen,

        bfd_data->sess[sess_idx].recv_msg_hdr.msg_control,
        bfd_data->sess[sess_idx].recv_msg_hdr.msg_controllen,

        bfd_data->sess[sess_idx].recv_msg_hdr.msg_name,
        bfd_data->sess[sess_idx].recv_msg_hdr.msg_namelen,

        bfd_data->sess[sess_idx].recv_msg_hdr_checksum,

        bfd_data->sess[sess_idx].local_send_port,
        bfd_data->sess[sess_idx].send_sock,

        &bfd_data->sess[sess_idx].send_remote_sock_addr_ipv4,
        &bfd_data->sess[sess_idx].send_remote_sock_addr_ipv6,
        bfd_data->sess[sess_idx].send_remote_sock_addr,
        remote_sock_addr_family,
        &remote_sock_addr_ip_str[0],
        remote_sock_addr_port,
        bfd_data->sess[sess_idx].send_remote_sock_addr_len,

        bfd_data->sess[sess_idx].send_remote_sock_addr_checksum,

        bfd_data->sess[sess_idx].recv_count,
        bfd_data->sess[sess_idx].send_count,

        bfd_data->sess[sess_idx].audited,

        bfd_data->sess[sess_idx].missed_hb,
        bfd_data->sess[sess_idx].corrupt_pkt);

    BFD_LOG_FORCED (buffer);
}
