/*************************************************************************
 *
 * File:     BFD_trans.c
 *
 * Abstract: implementation file of BFD transport module
 *           this module sends/receives BFD messages using UDP/IP
 *
 * Data:     none
 *
 * Functions:
 *     BFD_trans_create_recv_sock - function to create a UDP socket to
 *                                  receive BFD control message
 *     BFD_trans_create_send_sock - function to create a UDP socket to
 *                                  send BFD control message
 *
 *     BFD_trans_close_sockets    - function to close receive and send
 *                                  UDP sockets
 *
 *     BFD_trans_recv             - function to receive BFD/UDP message
 *     BFD_trans_send             - function to send BFD/UDP message
 *
 ************************************************************************/

#include "BFD_int_hdr.h"


/*
 * Name:        BFD_trans_create_recv_sock
 *
 * Abstract:    function to create a UDP socket to receive BFD control
 *              message
 *
 * Parameters:
 *     sess_idx  - BFD session index
 *
 * Returns:
 *     ret_val   - success or failure
 */
BFD_RETVAL BFD_trans_create_recv_sock (int sess_idx)
{
    int family;

    struct sockaddr_in local_sock_addr_ipv4;
    struct sockaddr_in6 local_sock_addr_ipv6;
    struct sockaddr *local_sock_addr;
    int local_sock_addr_len;

    char local_ip_str[IPM_IPMAXSTRSIZE];
    int setsockopt_value;

    struct msghdr *recv_msg_hdr;

    /* support both IPv4 and IPv6 */
    if (bfd_data->sess[sess_idx].local_ip.addrtype == IPM_IPV4)
    {
        family = AF_INET;
    }
    else
    {
        family = AF_INET6;
    }

    /* create a UDP socket to receive BFD control message */
    bfd_data->sess[sess_idx].recv_sock = socket (family, SOCK_DGRAM, 0);
    if (bfd_data->sess[sess_idx].recv_sock == -1)
    {
        BFD_INTERNAL_ERROR ("socket() fails, error %d - %s, family %d\n",
            errno, strerror (errno), family);
        bfd_data->stats.socket_fail++;
        return BFD_INTERNAL_FAIL;
    }

    /* prepare local socket address to bind */
    if (bfd_data->sess[sess_idx].local_ip.addrtype == IPM_IPV4)
    {
        memset (&local_sock_addr_ipv4, 0, sizeof(local_sock_addr_ipv4));

        local_sock_addr_ipv4.sin_family = family;

        /* sin_port is in network byte-order */
        local_sock_addr_ipv4.sin_port = htons (BFD_RECV_CTL_PORT);

        /*
         * sin_addr.s_addr and remote_ip.ipaddr[0] are in network byte-order
         */
        local_sock_addr_ipv4.sin_addr.s_addr =
            bfd_data->sess[sess_idx].local_ip.ipaddr[0];

        local_sock_addr = (struct sockaddr *) &local_sock_addr_ipv4;
        local_sock_addr_len = sizeof(local_sock_addr_ipv4);
    }
    else
    {
        memset (&local_sock_addr_ipv6, 0, sizeof(local_sock_addr_ipv6));

        local_sock_addr_ipv6.sin6_family = family;

        /* sin6_port is in network byte-order */
        local_sock_addr_ipv6.sin6_port = htons (BFD_RECV_CTL_PORT);

        /*
         * sin6_addr.s6_addr and remote_ip.ipaddr[*] are in network byte-order
         */
        memcpy (local_sock_addr_ipv6.sin6_addr.s6_addr,
            bfd_data->sess[sess_idx].local_ip.ipaddr,
            sizeof(bfd_data->sess[sess_idx].local_ip.ipaddr));

        local_sock_addr = (struct sockaddr *) &local_sock_addr_ipv6;
        local_sock_addr_len = sizeof(local_sock_addr_ipv6);
    }

    /* bind socket to local IP and popular receive port */
    if (bind (bfd_data->sess[sess_idx].recv_sock, local_sock_addr,
        local_sock_addr_len) == -1)
    {
        /*
         * do not display error if local IP is not available in the first
         * 1 second (5 ms * 200 = 1 sec)
         */
        if ((errno == EADDRNOTAVAIL) &&
            (bfd_data->sess_stats[sess_idx].recv_sock_bind_fail >= 200))
        {
            IPM_ipaddr2p (&bfd_data->sess[sess_idx].local_ip,
                &local_ip_str[0], sizeof(local_ip_str));

            BFD_LOCAL_ERROR ("bind() fails, error %d - %s, family %d, "
                "local_ip %s, popular port %u\n", errno, strerror (errno),
                family, &local_ip_str[0], BFD_RECV_CTL_PORT);
        }
        bfd_data->sess_stats[sess_idx].recv_sock_bind_fail++;
        close (bfd_data->sess[sess_idx].recv_sock);
	bfd_data->sess[sess_idx].recv_sock = -1;
        return BFD_LOCAL_FAIL;
    }

    if (bfd_data->sess[sess_idx].local_ip.addrtype == IPM_IPV4)
    {
        /* want to receive specific IPv4 TTL */
        setsockopt_value = 1;
        if (setsockopt (bfd_data->sess[sess_idx].recv_sock, SOL_IP,
            IP_RECVTTL, (char*) &setsockopt_value,
            sizeof(setsockopt_value)) < 0)
        {
            BFD_INTERNAL_ERROR ("setsockopts(SOL_IP, IP_RECVTTL) fails, "
                "error %d - %s, setsockopt_value %d\n",
                errno, strerror (errno), setsockopt_value);
            bfd_data->stats.set_sock_opt_fail++;
            close (bfd_data->sess[sess_idx].recv_sock);
	    bfd_data->sess[sess_idx].recv_sock = -1;
            return BFD_INTERNAL_FAIL;
        }
    }
    else
    {
        /* want to receive specific IPv6 hop limit */
        setsockopt_value = 1;
        if (setsockopt (bfd_data->sess[sess_idx].recv_sock, SOL_IPV6,
            IPV6_RECVHOPLIMIT, (char*) &setsockopt_value,
            sizeof(setsockopt_value)) < 0)
        {
            BFD_INTERNAL_ERROR ("setsockopts(SOL_IPV6, IP_RECVHOPLIMIT) "
                "fails, error %d - %s, setsockopt_value %d\n",
                errno, strerror (errno), setsockopt_value);
            bfd_data->stats.set_sock_opt_fail++;
            close (bfd_data->sess[sess_idx].recv_sock);
	    bfd_data->sess[sess_idx].recv_sock = -1;
            return BFD_INTERNAL_FAIL;
        }
    }

    /* prepare message header */
    recv_msg_hdr = &bfd_data->sess[sess_idx].recv_msg_hdr;
    memset (recv_msg_hdr, 0, sizeof(*recv_msg_hdr));

    /* prepare I/O vector */

    memset (bfd_data->sess[sess_idx].recv_msg_iov, 0,
        sizeof( bfd_data->sess[sess_idx].recv_msg_iov[0]));
    bfd_data->sess[sess_idx].recv_msg_iov[0].iov_base =
        &bfd_data->sess[sess_idx].recv_msg[0];
    bfd_data->sess[sess_idx].recv_msg_iov[0].iov_len =
	sizeof(bfd_data->sess[sess_idx].recv_msg);

    recv_msg_hdr->msg_iov = bfd_data->sess[sess_idx].recv_msg_iov;
    recv_msg_hdr->msg_iovlen = 1;

    /* prepare control message to receive IPv4 TTL or IPv6 hop limit */
    recv_msg_hdr->msg_control = &bfd_data->sess[sess_idx].recv_ttl_buffer[0];
    recv_msg_hdr->msg_controllen =
        sizeof(bfd_data->sess[0].recv_ttl_buffer);

    /* prepare address to receive remote UDP port */
    if (bfd_data->sess[sess_idx].remote_ip.addrtype == IPM_IPV4)
    {
        memset (&bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv4, 0,
            sizeof(struct sockaddr_in));

        recv_msg_hdr->msg_name =
            &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv4;
        recv_msg_hdr->msg_namelen = sizeof(struct sockaddr_in);

        bfd_data->sess[sess_idx].recv_port =
            &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv4.sin_port;
    }
    else
    {
        memset (&bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv6, 0,
            sizeof(struct sockaddr_in6));

        recv_msg_hdr->msg_name =
            &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv6;
        recv_msg_hdr->msg_namelen = sizeof(struct sockaddr_in6);

        bfd_data->sess[sess_idx].recv_port =
            &bfd_data->sess[sess_idx].recv_remote_sock_addr_ipv6.sin6_port;
    }

    /* checksum the pointers to detect memory corruption */
    bfd_data->sess[sess_idx].recv_msg_hdr_checksum =
        (unsigned long) bfd_data->sess[sess_idx].recv_msg_iov[0].iov_base ^
        (unsigned long) bfd_data->sess[sess_idx].recv_msg_hdr.msg_iov ^
        (unsigned long) bfd_data->sess[sess_idx].recv_msg_hdr.msg_control ^
        (unsigned long) bfd_data->sess[sess_idx].recv_msg_hdr.msg_name ^
        (unsigned long) bfd_data->sess[sess_idx].recv_port ^
        BFD_CHECKSUM_SEED;

    return BFD_SUCCESS;
}


/*
 * Name:        BFD_trans_create_send_sock
 *
 * Abstract:    function to create a UDP socket to send BFD control
 *              message
 *
 * Parameters:
 *     sess_idx  - BFD session index
 *
 * Returns:
 *     ret_val   - success or failure
 */
BFD_RETVAL BFD_trans_create_send_sock (int sess_idx)
{
    int family;

    struct sockaddr_in local_sock_addr_ipv4;
    struct sockaddr_in6 local_sock_addr_ipv6;
    struct sockaddr *local_sock_addr;
    int local_sock_addr_len;

    char local_ip_str[IPM_IPMAXSTRSIZE];
    int setsockopt_value;

    struct sockaddr_in *remote_sock_addr_ipv4;
    struct sockaddr_in6 *remote_sock_addr_ipv6;

    /* support both IPv4 and IPv6 */
    if (bfd_data->sess[sess_idx].local_ip.addrtype == IPM_IPV4)
    {
        family = AF_INET;
    }
    else
    {
        family = AF_INET6;
    }

    /* create a socket to send BFD control message */
    bfd_data->sess[sess_idx].send_sock = socket (family, SOCK_DGRAM, 0);
    if (bfd_data->sess[sess_idx].send_sock == -1)
    {
        BFD_INTERNAL_ERROR ("socket() fails, error %d - %s, family %d\n",
            errno, strerror (errno), family);
        bfd_data->stats.socket_fail++;
        return BFD_INTERNAL_FAIL;
    }

    /* assign an unique local UDP port to send */
    bfd_data->sess[sess_idx].local_send_port = (unsigned short)
        (BFD_SEND_CTL_PORT_BASE + sess_idx);

    /* prepare local socket address to bind */
    if (bfd_data->sess[sess_idx].local_ip.addrtype == IPM_IPV4)
    {
        memset (&local_sock_addr_ipv4, 0, sizeof(local_sock_addr_ipv4));
    
        local_sock_addr_ipv4.sin_family = family;

        /* sin_port is in network byte-order */
        local_sock_addr_ipv4.sin_port =
            htons (bfd_data->sess[sess_idx].local_send_port);

        /* sin_addr.s_addr and remote_ip.ipaddr[0] are in network byte-order */
        local_sock_addr_ipv4.sin_addr.s_addr =
            bfd_data->sess[sess_idx].local_ip.ipaddr[0];

        local_sock_addr = (struct sockaddr *) &local_sock_addr_ipv4;
        local_sock_addr_len = sizeof(local_sock_addr_ipv4);
    }
    else
    {
        memset (&local_sock_addr_ipv6, 0, sizeof(local_sock_addr_ipv6));

        local_sock_addr_ipv6.sin6_family = family;

        /* sin6_port is in network byte-order */
        local_sock_addr_ipv6.sin6_port =
            htons (bfd_data->sess[sess_idx].local_send_port);

        /*
         * sin6_addr.s6_addr and remote_ip.ipaddr[*] are in network byte-order
         */
        memcpy (local_sock_addr_ipv6.sin6_addr.s6_addr,
            bfd_data->sess[sess_idx].local_ip.ipaddr,
            sizeof(bfd_data->sess[sess_idx].local_ip.ipaddr));

        local_sock_addr = (struct sockaddr *) &local_sock_addr_ipv6;
        local_sock_addr_len = sizeof(local_sock_addr_ipv6);
    }

    /* bind socket to local IP and unique sending port */
    while (bind (bfd_data->sess[sess_idx].send_sock, local_sock_addr,
        local_sock_addr_len) == -1)
    {
        /*
         * if local IP is not available, BFD_trans_create_recv_sock() fails;
         * do not need to check
         */

        if (bfd_data->sess[sess_idx].local_send_port < BFD_SEND_CTL_PORT_BASE)
        {
            IPM_ipaddr2p (&bfd_data->sess[sess_idx].local_ip,
                &local_ip_str[0], sizeof(local_ip_str));
            
            BFD_LOCAL_ERROR ("bind() fails, error %d - %s, family %d, "
                "local_ip %s, local_send_port (base %u + sess_idx %u, "
                "increment %u\n", errno, strerror (errno),
                family, &local_ip_str[0], BFD_SEND_CTL_PORT_BASE, sess_idx,
                BFD_SESS_MAX * 2);
            bfd_data->sess_stats[sess_idx].send_sock_bind_fail++;
            close (bfd_data->sess[sess_idx].send_sock);
            bfd_data->sess[sess_idx].send_sock = -1;
            return BFD_LOCAL_FAIL;
        }

        /* bind() fails; try a different local sending port */
        bfd_data->sess[sess_idx].local_send_port += BFD_SESS_MAX * 2;

        if (bfd_data->sess[sess_idx].local_ip.addrtype == IPM_IPV4)
        {
            /* sin_port is in network byte-order */
            local_sock_addr_ipv4.sin_port =
                htons (bfd_data->sess[sess_idx].local_send_port);
        }
        else
        {
            /* sin6_port is in network byte-order */
            local_sock_addr_ipv6.sin6_port =
                htons (bfd_data->sess[sess_idx].local_send_port);
        }
    }

    if (bfd_data->sess[sess_idx].local_ip.addrtype == IPM_IPV4)
    {
        /* want to send specific IPv4 TTL */
        setsockopt_value = BFD_IPV4_SEND_TTL;
        if (setsockopt (bfd_data->sess[sess_idx].send_sock, SOL_IP, IP_TTL,
            (char*) &setsockopt_value, sizeof(setsockopt_value)) < 0)
        {

            BFD_INTERNAL_ERROR ("setsockopts(SOL_IP, IP_TTL) fails, "
                "error %d - %s, setsockopt_value %d\n",
                errno, strerror (errno), setsockopt_value);
            bfd_data->stats.set_sock_opt_fail++;
            close (bfd_data->sess[sess_idx].send_sock);
	    bfd_data->sess[sess_idx].send_sock = -1;
            return BFD_INTERNAL_FAIL;
        }
    }
    else
    {
        /* want to send specific IPv6 hop limit */
        setsockopt_value = BFD_IPV6_SEND_HOP_LIMIT;
        if (setsockopt (bfd_data->sess[sess_idx].send_sock, SOL_IPV6,
            IPV6_UNICAST_HOPS, (char*) &setsockopt_value,
            sizeof(setsockopt_value)) < 0)
        {

            BFD_INTERNAL_ERROR ("setsockopts(SOL_IPV6, IPV6_UNICAST_HOPS) "
                "fails, error %d - %s, setsockopt_value %d\n",
                errno, strerror (errno), setsockopt_value);
            bfd_data->stats.set_sock_opt_fail++;
            close (bfd_data->sess[sess_idx].send_sock);
	    bfd_data->sess[sess_idx].send_sock = -1;
            return BFD_INTERNAL_FAIL;
        }
    }

    /* prepare remote socket address to send */
    if (bfd_data->sess[sess_idx].remote_ip.addrtype == IPM_IPV4)
    {
        remote_sock_addr_ipv4 = (struct sockaddr_in *)
            &bfd_data->sess[sess_idx].send_remote_sock_addr_ipv4;

        memset (remote_sock_addr_ipv4, 0, sizeof(*remote_sock_addr_ipv4));

        remote_sock_addr_ipv4->sin_family = family;

        /* sin_port is in network byte-order */
        remote_sock_addr_ipv4->sin_port = htons (BFD_RECV_CTL_PORT);

        /* sin_addr.s_addr and remote_ip.ipaddr[0] are in network byte-order */
        remote_sock_addr_ipv4->sin_addr.s_addr =
            bfd_data->sess[sess_idx].remote_ip.ipaddr[0];

        bfd_data->sess[sess_idx].send_remote_sock_addr =
            (struct sockaddr *) remote_sock_addr_ipv4;
        bfd_data->sess[sess_idx].send_remote_sock_addr_len =
            sizeof(*remote_sock_addr_ipv4);
    }
    else
    {
        remote_sock_addr_ipv6 = (struct sockaddr_in6 *)
            &bfd_data->sess[sess_idx].send_remote_sock_addr_ipv6;

        memset (remote_sock_addr_ipv6, 0, sizeof(*remote_sock_addr_ipv6));

        remote_sock_addr_ipv6->sin6_family = family;

        /* sin6_port is in network byte-order */
        remote_sock_addr_ipv6->sin6_port = htons (BFD_RECV_CTL_PORT);

        /*
         * sin6_addr.s6_addr and remote_ip.ipaddr[*] are in network
         * byte-order
         */   
        memcpy (remote_sock_addr_ipv6->sin6_addr.s6_addr,
            bfd_data->sess[sess_idx].remote_ip.ipaddr,
            sizeof(bfd_data->sess[sess_idx].remote_ip.ipaddr));

        bfd_data->sess[sess_idx].send_remote_sock_addr =
            (struct sockaddr *) remote_sock_addr_ipv6;
        bfd_data->sess[sess_idx].send_remote_sock_addr_len =
            sizeof(*remote_sock_addr_ipv6);
    }

    /* checksum the pointer to detect memory corruption */
    bfd_data->sess[sess_idx].send_remote_sock_addr_checksum =
        (unsigned long) bfd_data->sess[sess_idx].send_remote_sock_addr ^
        (unsigned long) BFD_CHECKSUM_SEED;

    return BFD_SUCCESS;
}


/*
 * Name:        BFD_trans_close_sockets
 *
 * Abstract:    function to close receive and send UDP sockets
 *
 * Parameters:
 *     sess_idx - BFD session index
 *
 * Returns:     none
 */
void BFD_trans_close_sockets (int sess_idx)
{
    int os_ret_val;

    os_ret_val = close (bfd_data->sess[sess_idx].recv_sock);
    if (os_ret_val != 0)
    {
        BFD_INTERNAL_ERROR ("close(recv_sock) fails, error %d - %s, "
            "socket %d, os_ret_val %d\n", errno, strerror (errno),
            bfd_data->sess[sess_idx].recv_sock, os_ret_val);
        bfd_data->stats.close_fail++;
    }

    os_ret_val = close (bfd_data->sess[sess_idx].send_sock);
    if (os_ret_val != 0)
    {
        BFD_INTERNAL_ERROR ("close(send_sock) fails, error %d - %s, "
            "socket %d, os_ret_val %d\n", errno, strerror (errno),
            bfd_data->sess[sess_idx].send_sock, os_ret_val);
        bfd_data->stats.close_fail++;
    }   
}


/*
 * Name:        BFD_trans_recv
 *
 * Abstract:    function to receive BFD control message
 *
 * Parameters:
 *     sess_idx - BFD session index
 *
 * Returns:
 *     ret_val   - success or failure
 */
BFD_RETVAL BFD_trans_recv (int sess_idx)
{
    unsigned long recv_msg_hdr_checksum;
    int os_ret_val;

    struct msghdr* recv_msg_hdr;
    struct cmsghdr *cmsg_hdr;
    int recv_ttl;
    int recv_hop_limit;

    recv_msg_hdr_checksum =
        (unsigned long) bfd_data->sess[sess_idx].recv_msg_iov[0].iov_base ^
        (unsigned long) bfd_data->sess[sess_idx].recv_msg_hdr.msg_iov ^
        (unsigned long) bfd_data->sess[sess_idx].recv_msg_hdr.msg_control ^
        (unsigned long) bfd_data->sess[sess_idx].recv_msg_hdr.msg_name ^
        (unsigned long) bfd_data->sess[sess_idx].recv_port ^
        BFD_CHECKSUM_SEED;

    if (recv_msg_hdr_checksum !=
        bfd_data->sess[sess_idx].recv_msg_hdr_checksum)
    {
        BFD_LOCAL_ERROR ("corrupted message header to receive BFD message\n");
        bfd_data->stats.corrupt_recv_msg_hdr++;
        return BFD_LOCAL_FAIL;
    }

    recv_msg_hdr = &bfd_data->sess[sess_idx].recv_msg_hdr;

    /* call socket API to receive */
    /* recv_msg_hdr has been prepared before */
    os_ret_val = recvmsg (bfd_data->sess[sess_idx].recv_sock, recv_msg_hdr,
        MSG_DONTWAIT);
    if (os_ret_val < 0)
    {
        if ((errno == EAGAIN) || (errno == EINTR))
        {
            /* try again or interrupted */
            /* not an error */
            return BFD_IGNORE;
        }
        else
        {
            BFD_INTERNAL_ERROR (
                "recvmsg() fails, error %d - %s, socket %d, os_ret_val %d\n"
                "    recv_msg                     %p\n"
                "\n"
                "    recv_ttl_buffer              %p\n"
                "    sizeof(recv_ttl_buffer)      %u\n"
                "\n"
                "    recv_msg_iov[0].iov_base     %p\n"
                "    recv_msg_iov[0].iov_len      %u\n"
                "    recv_msg_iov[0]              %p\n"
                "\n"
                "    recv_msg_hdr.msg_iov         %p\n"
                "    recv_msg_hdr.msg_iovlen      %u\n"
                "\n"
                "    recv_msg_hdr.msg_control     %p\n"
                "    recv_msg_hdr.msg_controllen  %u\n",

                errno, strerror (errno), bfd_data->sess[sess_idx].recv_sock,
                os_ret_val,

                &bfd_data->sess[sess_idx].recv_msg,

                &bfd_data->sess[sess_idx].recv_ttl_buffer[0],
                sizeof (bfd_data->sess[sess_idx].recv_ttl_buffer),

                bfd_data->sess[sess_idx].recv_msg_iov[0].iov_base,
                bfd_data->sess[sess_idx].recv_msg_iov[0].iov_len,
                &bfd_data->sess[sess_idx].recv_msg_iov[0],

                bfd_data->sess[sess_idx].recv_msg_hdr.msg_iov,
                bfd_data->sess[sess_idx].recv_msg_hdr.msg_iovlen,

                bfd_data->sess[sess_idx].recv_msg_hdr.msg_control,
                bfd_data->sess[sess_idx].recv_msg_hdr.msg_controllen);

            bfd_data->stats.recv_msg_fail++;
            return BFD_INTERNAL_FAIL;
        }
    }
    else if (os_ret_val == 0)
    {
        /* no message */
        /* not an error */
        return BFD_IGNORE;
    }
    else if (os_ret_val != BFD_MSG_LENGTH)
    {
        /* BFD message length is not 24 */
        BFD_REMOTE_ERROR ("invalid received UDP message length %u, "
            "%u expected\n", os_ret_val, BFD_MSG_LENGTH);
        bfd_data->sess_stats[sess_idx].inv_remote_length++;
	bfd_data->sess[sess_idx].corrupt_pkt++;
        return BFD_REMOTE_FAIL;
    }

    if (ntohs (*bfd_data->sess[sess_idx].recv_port) < BFD_SEND_CTL_PORT_BASE)
    {
        /* invalid remote UDP port */
        /* not an error */
        return BFD_IGNORE;
    }

    if (recv_msg_hdr->msg_controllen == 0)
    {
        BFD_INTERNAL_ERROR ("control message length is 0; "
            "non-zero expected\n");
        bfd_data->stats.ctl_len_zero++;
        return BFD_INTERNAL_FAIL;
    }

    /* go through all comtrol messages */
    for (cmsg_hdr = CMSG_FIRSTHDR (recv_msg_hdr); cmsg_hdr != NULL;
        cmsg_hdr = CMSG_NXTHDR (recv_msg_hdr, cmsg_hdr))
    {
        if (cmsg_hdr->cmsg_level == SOL_IP)
        {
            /* control message level is IPv4 */

            if (cmsg_hdr->cmsg_type == IP_TTL)
            {
                /* control message type is IPv4 TTL */

                recv_ttl = *((int *) CMSG_DATA (cmsg_hdr));

                if (recv_ttl != BFD_IPV4_RECV_TTL)
                {
                    BFD_INTERNAL_ERROR ("invalid received IPv4 TTL %u; "
                        "%u expected\n", recv_ttl, BFD_IPV4_RECV_TTL);
                    bfd_data->sess_stats[sess_idx].inv_recv_ttl++;
                    return BFD_INTERNAL_FAIL;
                }

                /* receive IPv4 TTL is good */
            }
            else
            {
                BFD_INTERNAL_ERROR ("unexpected control message type %d "
                    "for IPv4; %d expected\n", cmsg_hdr->cmsg_type, IP_TTL);
                bfd_data->stats.inv_cmsg_type++;
                return BFD_INTERNAL_FAIL;
            }
        }
        else if (cmsg_hdr->cmsg_level == SOL_IPV6)
        {
            /* control message level is IPv6 */

            if (cmsg_hdr->cmsg_type == IPV6_HOPLIMIT)
            {
                /* control message type is IPv6 hop limit */

                recv_hop_limit = *((int *) CMSG_DATA (cmsg_hdr));

                if (recv_hop_limit != BFD_IPV6_RECV_HOP_LIMIT)
                {
                    BFD_INTERNAL_ERROR ("invalid received IPv6 hop limit %u; "
                        "%u expected\n", recv_hop_limit,
                        BFD_IPV6_RECV_HOP_LIMIT);
                    bfd_data->sess_stats[sess_idx].inv_recv_hop_limit++;
                    return BFD_INTERNAL_FAIL;
                }

                /* receive IPv6 hop limit is good */
            }
            else
            {
                BFD_INTERNAL_ERROR ("unexpected control message type %d "
                    "for IPv6; %d expected\n", cmsg_hdr->cmsg_type,
                    IPV6_HOPLIMIT);
                bfd_data->stats.inv_cmsg_type++;
                return BFD_INTERNAL_FAIL;
            }
        }
        else
        {
            BFD_INTERNAL_ERROR ("unexpected control message level %d; "
                "%d or %d expected\n", cmsg_hdr->cmsg_level,
                SOL_IP, SOL_IPV6);
            bfd_data->stats.inv_cmsg_level++;
            return BFD_INTERNAL_FAIL;
        }
    }

    /* received TTL is good; process this message */

    bfd_data->sess[sess_idx].recv_count++;
    bfd_data->sess_stats[sess_idx].good_recv++;

    return BFD_SUCCESS;
}


/*
 * Name:        BFD_trans_send
 *
 * Abstract:    function to send BFD control message
 *
 * Parameters:
 *     sess_idx - BFD session index
 *
 * Returns:
 *     ret_val   - success or failure
 */
BFD_RETVAL BFD_trans_send (int sess_idx)
{
    int os_ret_val;

    struct sockaddr_in *remote_sock_addr_ipv4;
    struct sockaddr_in6 *remote_sock_addr_ipv6;

    int family;
    unsigned short port;

    IPM_IPADDR remote_ip;
    char remote_ip_str[IPM_IPMAXSTRSIZE];

    if (((unsigned long) bfd_data->sess[sess_idx].send_remote_sock_addr ^ 
        (unsigned long) BFD_CHECKSUM_SEED) !=
        bfd_data->sess[sess_idx].send_remote_sock_addr_checksum)
    {
        BFD_LOCAL_ERROR ("corrupted remote socket address to send BFD "
            "message\n");
        bfd_data->stats.corrupt_remote_sock_addr++;
        return BFD_LOCAL_FAIL;
    }

    /* call socket API to send */
    /* remote_sock_addr and remote_sock_addr_len has been prepared before */
    os_ret_val = sendto (bfd_data->sess[sess_idx].send_sock,
        &bfd_data->sess[sess_idx].send_msg, sizeof(BFD_MSG), /*flags*/ 0,
        bfd_data->sess[sess_idx].send_remote_sock_addr, 
        bfd_data->sess[sess_idx].send_remote_sock_addr_len);
    if (os_ret_val != sizeof(BFD_MSG))
    {
        IPM_ipaddr_init (&remote_ip);

        if (bfd_data->sess[sess_idx].remote_ip.addrtype == IPM_IPV4)
        {
            remote_sock_addr_ipv4 = (struct sockaddr_in *)
                bfd_data->sess[sess_idx].send_remote_sock_addr;

            family = remote_sock_addr_ipv4->sin_family;

            /* sin_port is in network byte-order */
            port = ntohs (remote_sock_addr_ipv4->sin_port);

            remote_ip.addrtype = IPM_IPV4;

           /*
            * sin_addr.s_addr and remote_ip.ipaddr[0] are in network
            * byte-order
            */
            remote_ip.ipaddr[0] = remote_sock_addr_ipv4->sin_addr.s_addr;
        }
        else
        {
            remote_sock_addr_ipv6 = (struct sockaddr_in6 *)
                bfd_data->sess[sess_idx].send_remote_sock_addr;

            family = remote_sock_addr_ipv6->sin6_family;

            /* sin6_port is in network byte-order */
            port = ntohs (remote_sock_addr_ipv6->sin6_port);

            remote_ip.addrtype = IPM_IPV6;

            /*
             * sin6_addr.s6_addr and remote_ip.ipaddr[*] are in network
             * byte-order
             */   
            memcpy (remote_ip.ipaddr,
                remote_sock_addr_ipv6->sin6_addr.s6_addr,
                sizeof(remote_ip.ipaddr));
        }

        IPM_ipaddr2p (&remote_ip, &remote_ip_str[0], sizeof(remote_ip_str));

        BFD_LOCAL_ERROR ("sendto() fails, error %d - %s, socket %d, "
            "os_ret_val %d, family %d, remote ip %s, remote port %u\n",
            errno, strerror (errno), bfd_data->sess[sess_idx].send_sock,
            os_ret_val, family, &remote_ip_str[0], port);
        bfd_data->stats.send_to_fail++;
        return BFD_LOCAL_FAIL;
    }

    bfd_data->sess[sess_idx].send_count++;
    bfd_data->sess_stats[sess_idx].good_send++;

    return BFD_SUCCESS;
}
