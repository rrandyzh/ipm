/*************************************************************************
 *
 * File:     ARPNDP_trans.c
 *
 * Abstract: implementation file of ARP/NDP transport module
 *           this module sends/receives ARP/NDP message
 *
 * Data:     none
 *
 * Functions:
 *     ARPNDP_trans_get_intf_data    - function to get OS interface data
 *                                     (name, MAC address, etc.)
 *
 *     ARPNDP_trans_create_sock      - function to create a socket to
 *                                     send/receive ARP/NDP message
 *     ARPNDP_trans_close_sock       - function to close ARP/NDP socket
 *
 *     ARPNDP_trans_recv             - function to receive ARP/NDP message
 *
 *     ARPNDP_connect_temp_sock      - module-internal function to create
 *                                     a temporary socket, bind, setsockopt,
 *                                     and connect before sending ARP message;
 *                                     this is needed due to a bug in Wind
 *                                     River Linux; we do this every time we
 *                                     send ARP message
 *
 *     ARPNDP_trans_send             - function to send ARP/NDP message
 *
 ************************************************************************/
#if defined (_X86)
#define _GNU_SOURCE
#include <netinet/in.h>
#endif
#include <netinet/ip6.h>
#include "ARPNDP_int_hdr.h"


/*
 * Name:        ARPNDP_trans_get_intf_data
 *
 * Abstract:    function to get OS interface data (name, MAC address, etc.)
 *
 * Parameters:
 *     sess_idx  - ARP/NDP session index
 *
 * Returns:
 *     ret_val   - success or failure
 */
ARPNDP_RETVAL ARPNDP_trans_get_intf_data (int sess_idx)
{
    int os_ret_val;
    int family;
    int sock;
    struct ifreq if_req;
    int intf_name_len;

    int i;
    unsigned char *ptr;
    unsigned char checksum;

    /* support both IPv4 and IPv6 */
    if (arpndp_data->sess[sess_idx].local_ip.addrtype == IPM_IPV4)
    {
        family = AF_INET;
    }
    else
    {
        family = AF_INET6;
    }

    /* create a temporary socket */
    sock = socket (family, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1)
    {
        ARPNDP_INTERNAL_ERROR ("socket(temp) fails, error %d - %s\n",
            errno, strerror (errno));
        arpndp_data->stats.socket_fail++;
        return ARPNDP_INTERNAL_FAIL;
    }

    /* prepare interface request data structure */
    memset (&if_req, 0, sizeof(if_req));
    if_req.ifr_ifindex = arpndp_data->sess[sess_idx].intf_idx;

    /* get OS interface name */
    os_ret_val = ioctl (sock, SIOCGIFNAME, &if_req);
    if (os_ret_val != 0)
    {
        ARPNDP_INTERNAL_ERROR ("ioctl(SIOCGIFNAME) fails, os_ret_val %d, "
            "error %d - %s, intf_idx %d\n", os_ret_val, errno,
            strerror (errno), if_req.ifr_ifindex);
        arpndp_data->stats.ioctl_fail++;
        return ARPNDP_INTERNAL_FAIL;
    }

    /* check string length of OS interface name */
    intf_name_len = strlen (if_req.ifr_name);
    if (intf_name_len > ARPNDP_INTF_NAME_LEN_MAX)
    {
        ARPNDP_INTERNAL_ERROR ("intf_name_len %d > buffer size %d\n",
            intf_name_len, ARPNDP_INTF_NAME_LEN_MAX);
        arpndp_data->stats.arpndp_size_error++;
        return ARPNDP_INTERNAL_FAIL;
    }

    /* save OS interface name */
    memcpy (arpndp_data->sess[sess_idx].intf_name, if_req.ifr_name,
        intf_name_len + 1);

    /* get MAC address of this OS interface */
    os_ret_val = ioctl (sock, SIOCGIFHWADDR, &if_req);
    if (os_ret_val != 0)
    {
        ARPNDP_INTERNAL_ERROR ("ioctl(SIOCGIFHWADDR) fails, os_ret_val %d, "
            "error %d - %s, intf_idx %d, intf_name %s\n", os_ret_val, errno,
            strerror (errno), if_req.ifr_ifindex, if_req.ifr_name);
        arpndp_data->stats.ioctl_fail++;
        return ARPNDP_INTERNAL_FAIL;
    }

    /* save MAC address */
    memcpy (arpndp_data->sess[sess_idx].mac_addr,
        if_req.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);

    /* close temporary socket */
    os_ret_val = close (sock);
    if (os_ret_val != 0)
    {
        ARPNDP_INTERNAL_ERROR ("close(temp) fails, os_ret_val %d, "
            "error %d - %s, socket %d\n", os_ret_val, errno,
            strerror (errno), sock);
        arpndp_data->stats.close_fail++;
        return ARPNDP_INTERNAL_FAIL;
    }

    /* checksum OS interface data */

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

    arpndp_data->sess[sess_idx].intf_data_checksum = checksum;

    return ARPNDP_SUCCESS;
}


/*
 * Name:        ARPNDP_trans_create_sock
 *
 * Abstract:    function to create a socket to send/receive ARP/NDP mesage
 *
 * Parameters:
 *     sess_idx  - ARP/NDP session index
 *
 * Returns:
 *     ret_val   - success or failure
 */
ARPNDP_RETVAL ARPNDP_trans_create_sock (int sess_idx)
{
    int os_ret_val;

    /* ARP */
    struct sockaddr_ll arp_sock_addr;

    /* NDP */
    int setsockopt_value;
    struct icmp6_filter filter;

    if (arpndp_data->sess[sess_idx].protocol == ARPNDP_PROTOCOL_ARP)
    {
        /* create an ARP socket to send/receive ARP message */
        arpndp_data->sess[sess_idx].sock = socket (PF_PACKET, SOCK_RAW,
            htons (ETH_P_ARP));
        if (arpndp_data->sess[sess_idx].sock == -1)
        {
            ARPNDP_INTERNAL_ERROR ("socket(ARP) fails, error %d - %s\n",
                errno, strerror (errno));
            arpndp_data->stats.socket_fail++;
            return ARPNDP_INTERNAL_FAIL;
        }

        /* bind socket to OS interface */

        memset (&arp_sock_addr, 0, sizeof(arp_sock_addr));
        arp_sock_addr.sll_family = PF_PACKET;
        arp_sock_addr.sll_protocol = htons (ETH_P_ARP);
        arp_sock_addr.sll_ifindex  = arpndp_data->sess[sess_idx].intf_idx;
        /* sll_hatype, sll_pkttype, sll_halen, sll_addr are 0 */

        os_ret_val = bind (arpndp_data->sess[sess_idx].sock,
            (struct sockaddr *) &arp_sock_addr, sizeof(struct sockaddr_ll));
        if (os_ret_val != 0)
        {
            ARPNDP_LOCAL_ERROR ("bind(ARP) fails, os_ret_val %d, "
            "error %d - %s, intf_idx %d\n", os_ret_val, errno,
            strerror (errno), arpndp_data->sess[sess_idx].intf_idx);
            arpndp_data->stats.bind_fail++;
	    close (arpndp_data->sess[sess_idx].sock);
            arpndp_data->sess[sess_idx].sock = -1;
            return ARPNDP_LOCAL_FAIL;
        }
    }
    else if (arpndp_data->sess[sess_idx].protocol == ARPNDP_PROTOCOL_NDP)
    {
        /* create an IPv6 ICMP socket to send/receive NDP message */
        arpndp_data->sess[sess_idx].sock = socket (AF_INET6, SOCK_RAW,
            IPPROTO_ICMPV6);
        if (arpndp_data->sess[sess_idx].sock == -1)
        {
            ARPNDP_INTERNAL_ERROR ("socket(ICMP) fails, error %d - %s\n",
                errno, strerror (errno));
            arpndp_data->stats.socket_fail++;
            arpndp_data->sess[sess_idx].sock = -1;
            return ARPNDP_INTERNAL_FAIL;
        }

        /* bind to OS interface name */
        os_ret_val = setsockopt (arpndp_data->sess[sess_idx].sock,
            SOL_SOCKET, SO_BINDTODEVICE,
            arpndp_data->sess[sess_idx].intf_name,
            strlen (arpndp_data->sess[sess_idx].intf_name) + 1);
        if (os_ret_val != 0)
        {
            ARPNDP_INTERNAL_ERROR ("setsockopts(SO_BINDTODEVICE) fails, "
                "os_ret_val %d, error %d - %s, intf_name '%s'\n",
                os_ret_val, errno, strerror (errno),
                arpndp_data->sess[sess_idx].intf_name);
            arpndp_data->stats.set_sock_opt_fail++;
	    close (arpndp_data->sess[sess_idx].sock);
            arpndp_data->sess[sess_idx].sock = -1;
            return ARPNDP_INTERNAL_FAIL;
        }

        /* set multicast interface to this OS interface */
        setsockopt_value = 1;
        os_ret_val = setsockopt (arpndp_data->sess[sess_idx].sock,
            SOL_IPV6, IPV6_MULTICAST_IF,
            (char*) &arpndp_data->sess[sess_idx].intf_idx,
            sizeof(arpndp_data->sess[sess_idx].intf_idx));
        if (os_ret_val != 0)
        {
            ARPNDP_INTERNAL_ERROR ("setsockopts(IPV6_MULTICAST_IF) fails, "
                "os_ret_val %d, error %d - %s, setsockopt_value %d\n",
                os_ret_val, errno, strerror (errno), setsockopt_value);
            arpndp_data->stats.set_sock_opt_fail++;
	    close (arpndp_data->sess[sess_idx].sock);
            arpndp_data->sess[sess_idx].sock = -1;
            return ARPNDP_INTERNAL_FAIL;
        }

        /* send multicast hop limit 255 */
        setsockopt_value = 255;
        os_ret_val = setsockopt (arpndp_data->sess[sess_idx].sock,
            SOL_IPV6, IPV6_MULTICAST_HOPS,
            (char*) &setsockopt_value, sizeof(setsockopt_value));
        if (os_ret_val != 0)
        {
            ARPNDP_INTERNAL_ERROR ("setsockopts(IPV6_MULTICAST_HOPS) fails, "
                "os_ret_val %d, error %d - %s, setsockopt_value %d\n",
                os_ret_val, errno, strerror (errno), setsockopt_value);
            arpndp_data->stats.set_sock_opt_fail++;
	    close (arpndp_data->sess[sess_idx].sock);
            arpndp_data->sess[sess_idx].sock = -1;
            return ARPNDP_INTERNAL_FAIL;
        }

        /* receive IPv6 package info */
        setsockopt_value = 1;
        os_ret_val = setsockopt (arpndp_data->sess[sess_idx].sock,
            SOL_IPV6, IPV6_RECVPKTINFO,
            (char*) &setsockopt_value, sizeof(setsockopt_value));
        if (os_ret_val != 0)
        {
            ARPNDP_INTERNAL_ERROR ("setsockopts(IPV6_RECVPKTINFO) fails, "
                "os_ret_val %d, error %d - %s, setsockopt_value %d\n",
                os_ret_val, errno, strerror (errno), setsockopt_value);
            arpndp_data->stats.set_sock_opt_fail++;
	    close (arpndp_data->sess[sess_idx].sock);
            arpndp_data->sess[sess_idx].sock = -1;
            return ARPNDP_INTERNAL_FAIL;
        }

        /* receive only neighbor advertisement */

        ICMP6_FILTER_SETBLOCKALL (&filter);
        ICMP6_FILTER_SETPASS (ND_NEIGHBOR_ADVERT, &filter);

        os_ret_val = setsockopt (arpndp_data->sess[sess_idx].sock,
            SOL_ICMPV6, ICMP6_FILTER, (char*) &filter, sizeof(filter));
        if (os_ret_val != 0)
        {
            ARPNDP_INTERNAL_ERROR ("setsockopts(ICMP6_FILTER) fails, "
                "os_ret_val %d, error %d - %s\n",
                os_ret_val, errno, strerror (errno));
            arpndp_data->stats.set_sock_opt_fail++;
	    close (arpndp_data->sess[sess_idx].sock);
            arpndp_data->sess[sess_idx].sock = -1;
            return ARPNDP_INTERNAL_FAIL;
        }
    }
    else
    {
        ARPNDP_INTERNAL_ERROR ("invalid ARP/NDP protocol %d\n",
            arpndp_data->sess[sess_idx].protocol);
        arpndp_data->stats.inv_protocol++;
        return ARPNDP_INTERNAL_FAIL;
    }

    return ARPNDP_SUCCESS;
}


/*
 * Name:        ARPNDP_trans_close_sock
 *
 * Abstract:    function to close ARP/NDP socket
 *
 * Parameters:
 *     sess_idx - ARP/NDP session index
 *
 * Returns:     none
 */
void ARPNDP_trans_close_sock (int sess_idx)
{
    int os_ret_val;

    os_ret_val = close (arpndp_data->sess[sess_idx].sock);
    if (os_ret_val != 0)
    {
        ARPNDP_INTERNAL_ERROR ("close() fails, os_ret_val %d, "
            "error %d - %s, socket %d\n", os_ret_val, errno, strerror (errno),
            arpndp_data->sess[sess_idx].sock);
        arpndp_data->stats.close_fail++;
    }
}


/*
 * Name:        ARPNDP_trans_recv
 *
 * Abstract:    function to receive ARP/NDP message
 *
 * Parameters:
 *     sess_idx - ARP/NDP session index
 *
 * Returns:
 *     ret_val   - success or failure
 */
ARPNDP_RETVAL ARPNDP_trans_recv (int sess_idx)
{
    int os_ret_val;
    char recv_buf[ARPNDP_RECV_BUF_SIZE];

    /* ARP */
    struct arp_pkt *arp_msg;

    /* NDP */
    char cmsg_buf[ARPNDP_RECV_BUF_SIZE];
    struct iovec msg_iov[1];
    struct msghdr msg_hdr;
    struct cmsghdr *cmsg_hdr;
    struct in6_pktinfo *pkt_info_ptr;
    struct nd_neighbor_advert *ndp_msg;

    if (arpndp_data->sess[sess_idx].protocol == ARPNDP_PROTOCOL_ARP)
    {
        /* call socket API to receive ARP message */
        os_ret_val = recv (arpndp_data->sess[sess_idx].sock, &recv_buf[0],
            sizeof(recv_buf), MSG_DONTWAIT);
        if (os_ret_val < 0)
        {
            if ((errno == EAGAIN) || (errno == EINTR))
            {
                /* try again or interrupted */
                /* not an error */
                return ARPNDP_IGNORE;
            }
            else
            {
                ARPNDP_INTERNAL_ERROR ("recv() fails, os_ret_val %d, "
                    "error %d - %s, socket %d\n", os_ret_val, errno,
                    strerror(errno), arpndp_data->sess[sess_idx].sock);
                arpndp_data->stats.recv_fail++;
                return ARPNDP_INTERNAL_FAIL;
            }
        }
        else if (os_ret_val == 0)
        {
            /* no message */
            /* not an error */
            return ARPNDP_IGNORE;
        }

        /*
         * recv_buf might be larger than arp_msg with trailer;
         * process only arp_msg and ignore trailer
         */
        arp_msg = (struct arp_pkt *) recv_buf;
        
        /* ARP operation is in network byte-order */
        if (ntohs (arp_msg->arp.ea_hdr.ar_op) != ARPOP_REPLY)
        {
            /* ignore not ARP REPLY */
            arpndp_data->sess_stats[sess_idx].not_arp_reply++;
            return ARPNDP_IGNORE;
        }
        else if ( *((uint32_t *) &arp_msg->arp.arp_tpa) !=
            arpndp_data->sess[sess_idx].local_ip.ipaddr[0])
        {
            /* ignore different local IP */
            arpndp_data->sess_stats[sess_idx].diff_local_ip++;
            return ARPNDP_IGNORE;
        }
        else if ( *((uint32_t *) &arp_msg->arp.arp_spa) !=
            arpndp_data->sess[sess_idx].remote_ip.ipaddr[0])
        {
            /* ignore different remote IP */
            arpndp_data->sess_stats[sess_idx].diff_remote_ip++;
            return ARPNDP_IGNORE;
        }

        /* good and expected ARP Reply message */
    }
    else if (arpndp_data->sess[sess_idx].protocol == ARPNDP_PROTOCOL_NDP)
    {
        /* prepare message header */
        memset (&msg_hdr, 0, sizeof(msg_hdr));

        /* prepare I/O vector */

        memset (&msg_iov, 0, sizeof(msg_iov[0]));
        msg_iov[0].iov_base = &recv_buf[0];
        msg_iov[0].iov_len = sizeof(recv_buf);

        msg_hdr.msg_iov = msg_iov;
        msg_hdr.msg_iovlen = 1;
        msg_hdr.msg_flags = 0;

        /*
         * prepare control message to receive OS interface index and local IP
         */
        msg_hdr.msg_control = &cmsg_buf[0];
        msg_hdr.msg_controllen = sizeof(cmsg_buf);

        /* msg_hdr.msg_name and msg_hdr.msg_namelen = 0 when memset() */

        /* call socket API to receive NDP message */
        os_ret_val = recvmsg (arpndp_data->sess[sess_idx].sock, &msg_hdr,
            MSG_DONTWAIT);
        if (os_ret_val < 0)
        {
            if ((errno == EAGAIN) || (errno == EINTR))
            {
                /* try again or interrupted */
                /* not an error */
                return ARPNDP_IGNORE;
            }
            else
            {
                ARPNDP_INTERNAL_ERROR ("recvmsg() fails, os_ret_val %d, "
                    "error %d - %s, socket %d\n", os_ret_val, errno,
                    strerror(errno), arpndp_data->sess[sess_idx].sock);
                arpndp_data->stats.recv_msg_fail++;
                return ARPNDP_INTERNAL_FAIL;
            }
        }
        else if (os_ret_val == 0)
        {
            /* not an error */
            return ARPNDP_IGNORE;
        }
    
        if (msg_hdr.msg_controllen == 0){
            ARPNDP_INTERNAL_ERROR ("control message length is 0; "
                "non-zero expected\n");
            arpndp_data->stats.ctl_len_zero++;
            return ARPNDP_INTERNAL_FAIL;
        }

        /* go through all comtrol messages */
        for (cmsg_hdr = CMSG_FIRSTHDR (&msg_hdr); cmsg_hdr != NULL;
            cmsg_hdr = CMSG_NXTHDR (&msg_hdr, cmsg_hdr))
        {
            if (cmsg_hdr->cmsg_level == SOL_IPV6)
            {
                /* control message level is IPv6 */

                if (cmsg_hdr->cmsg_type == IPV6_PKTINFO)
                {
                    /* control message type is IPv6 package info */

                    pkt_info_ptr = (struct in6_pktinfo *) CMSG_DATA (cmsg_hdr);

                    if (pkt_info_ptr->ipi6_ifindex !=
                        (unsigned int) arpndp_data->sess[sess_idx].intf_idx)
                    {
                        ARPNDP_INTERNAL_ERROR ("invalid recv_intf_idx %d; "
                            "%u expected\n", pkt_info_ptr->ipi6_ifindex,
                            arpndp_data->sess[sess_idx].intf_idx);
                        arpndp_data->sess_stats[sess_idx].inv_recv_intf_idx++;
                        return ARPNDP_INTERNAL_FAIL;
                    }

                    if (memcmp( &pkt_info_ptr->ipi6_addr,
                        arpndp_data->sess[sess_idx].local_ip.ipaddr,
                        sizeof(arpndp_data->sess[sess_idx].local_ip.ipaddr))
                        != 0)
                    {
                        /* ingore different local IP */
                        arpndp_data->sess_stats[sess_idx].diff_local_ip++;
                        return ARPNDP_IGNORE;
                    }

                    /*
                     * recv_buf might be larger than ndp_msg with ICMPv6
                     * optional headers like target link-layer address;
                     * process only ndp_msg and ignore option headers
                     */
                    ndp_msg = (struct nd_neighbor_advert *) &recv_buf[0];

                    if (ndp_msg->nd_na_hdr.icmp6_type != ND_NEIGHBOR_ADVERT)
                    {
                        /* not neighbor advertisement */
                        arpndp_data->sess_stats[sess_idx].not_nd_advert++;
                        return ARPNDP_IGNORE;
                    }

                    if (memcmp( &ndp_msg->nd_na_target,
                        arpndp_data->sess[sess_idx].remote_ip.ipaddr,
                        sizeof(arpndp_data->sess[sess_idx].remote_ip.ipaddr))
                        != 0)
                    {
                        /* ingore different remote IP */
                        arpndp_data->sess_stats[sess_idx].diff_remote_ip++;
                        return ARPNDP_IGNORE;
                    }
                }
                else
                {
                    ARPNDP_INTERNAL_ERROR ("unexpected control message type "
                        "%d for IPv6; %d expected\n", cmsg_hdr->cmsg_type,
                        IPV6_PKTINFO);
                    arpndp_data->stats.inv_cmsg_type++;
                    return ARPNDP_INTERNAL_FAIL;
                }
            }
            else
            {
                ARPNDP_INTERNAL_ERROR ("unexpected control message level %d; "
                    "%d expected\n", cmsg_hdr->cmsg_level, SOL_IPV6);
                arpndp_data->stats.inv_cmsg_level++;
                return ARPNDP_INTERNAL_FAIL;
            }
        }
    }
    else
    {
        ARPNDP_INTERNAL_ERROR ("invalid ARP/NDP protocol %d\n",
            arpndp_data->sess[sess_idx].protocol);
        arpndp_data->stats.inv_protocol++;
        return ARPNDP_INTERNAL_FAIL;
    }

    arpndp_data->sess[sess_idx].recv_count++;
    arpndp_data->sess_stats[sess_idx].good_recv++;

    return ARPNDP_SUCCESS;
}


/*
 * Name:        ARPNDP_trans_connect_temp_sock
 *
 * Abstract:    module-internal function to create a temporary socket, bind,
 *              setsockopt, and connect before seding ARP message;
 *              this is needed due to a bug in Wind Reiver Linux;
 *              we do this every time we send ARP message
 *
 * Parameters:
 *     sess_idx  - ARP/NDP session index
 *
 * Returns:
 *     ret_val   - success or failure
 */
static ARPNDP_RETVAL ARPNDP_connect_temp_sock (int sess_idx)
{
    int os_ret_val;
    int family;
    int sock;
    int setsockopt_value;
 
    struct sockaddr_in sock_addr_ipv4;
    struct sockaddr_in6 sock_addr_ipv6;
    struct sockaddr *sock_addr_ptr;
    int sock_addr_len;
    unsigned short *sock_addr_port_ptr;
    unsigned short new_port;

    char remote_ip_str[IPM_IPMAXSTRSIZE];

    /* support both IPv4 and IPv6 */
    if (arpndp_data->sess[sess_idx].remote_ip.addrtype == IPM_IPV4)
    {
        family = AF_INET;
    }
    else
    {
        family = AF_INET6;
    }

    /* create a temporary socket */
    sock = socket (family, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1)
    {
        ARPNDP_INTERNAL_ERROR ("socket(temp) fails, error %d - %s\n",
            errno, strerror (errno));
        arpndp_data->stats.socket_fail++;
        return ARPNDP_INTERNAL_FAIL;
    }

    /* bind to OS interface name */
    os_ret_val = setsockopt (sock, SOL_SOCKET, SO_BINDTODEVICE,
        arpndp_data->sess[sess_idx].intf_name,
        strlen (arpndp_data->sess[sess_idx].intf_name) + 1);
    if (os_ret_val != 0)
    {
        ARPNDP_INTERNAL_ERROR ("setsockopts(SO_BINDTODEVICE) fails, "
            "os_ret_val %d, error %d - %s, intf_name '%s'\n",
            os_ret_val, errno, strerror (errno),
            arpndp_data->sess[sess_idx].intf_name);
        arpndp_data->stats.set_sock_opt_fail++;
        return ARPNDP_INTERNAL_FAIL;
    }

    /* do not route */
    setsockopt_value = 1;
    os_ret_val = setsockopt (sock, SOL_SOCKET, SO_DONTROUTE,
        (char*) &setsockopt_value, sizeof(setsockopt_value));
    if (os_ret_val != 0)
    {
        ARPNDP_INTERNAL_ERROR ("setsockopts(SO_DONTROUTE) fails, "
            "os_ret_val %d, error %d - %s, setsockopt_value %d\n",
            os_ret_val, errno, strerror (errno), setsockopt_value);
        arpndp_data->stats.set_sock_opt_fail++;
        return ARPNDP_INTERNAL_FAIL;
    }

    /* prepare remote socket address to connect */

    if (arpndp_data->sess[sess_idx].remote_ip.addrtype == IPM_IPV4)
    {
        memset (&sock_addr_ipv4, 0, sizeof(sock_addr_ipv4));
        sock_addr_ipv4.sin_family = AF_INET;

        /* sin_port is in network byte-order */
        sock_addr_ipv4.sin_port = htons (ARPNDP_TEMP_SOCK_PORT_BASE);

        /* sin_addr.s_addr and remote_ip.ipaddr[0] are in network byte-order */
        sock_addr_ipv4.sin_addr.s_addr =
            arpndp_data->sess[sess_idx].remote_ip.ipaddr[0];

        sock_addr_ptr = (struct sockaddr *) &sock_addr_ipv4;
        sock_addr_len = sizeof(sock_addr_ipv4);
        sock_addr_port_ptr = &sock_addr_ipv4.sin_port;
    }
    else
    {
        memset (&sock_addr_ipv6, 0, sizeof(sock_addr_ipv6));
        sock_addr_ipv6.sin6_family = AF_INET6;

        /* sin6_port is in network byte-order */
        sock_addr_ipv6.sin6_port = htons (ARPNDP_TEMP_SOCK_PORT_BASE);

        /*
         * sin6_addr.s6_addr and remote_ip.ipaddr[*] are in network byte-order
         */
        memcpy (&sock_addr_ipv6.sin6_addr.s6_addr,
            arpndp_data->sess[sess_idx].remote_ip.ipaddr,
            sizeof(arpndp_data->sess[sess_idx].remote_ip.ipaddr));

        sock_addr_ptr = (struct sockaddr *) &sock_addr_ipv6;
        sock_addr_len = sizeof(sock_addr_ipv6);
        sock_addr_port_ptr = &sock_addr_ipv6.sin6_port;
    }

    /* connect temporary socket to remote IP and port 1025, 1026, etc. */
    while (connect (sock, sock_addr_ptr, sock_addr_len) == -1)
    {
        /* connect() fails */

        /* try again with next port */
        new_port = ntohs (*sock_addr_port_ptr) + 1;

        if (new_port == (ARPNDP_TEMP_SOCK_PORT_BASE +
            ARPNDP_TEMP_SOCK_CONNECT_MAX))
        {
            /* has tried 2 times */

            IPM_ipaddr2p (&arpndp_data->sess[sess_idx].remote_ip,
                &remote_ip_str[0], sizeof(remote_ip_str));

            ARPNDP_INTERNAL_ERROR ("connect() fails, os_ret_val %d, "
                "error %d - %s, remote_ip %s, port %u to %u\n",
                os_ret_val, errno, strerror (errno), &remote_ip_str[0],
                ARPNDP_TEMP_SOCK_PORT_BASE, new_port - 1);
            arpndp_data->stats.connect_fail++;
            /* continue */
            break;
        }

        *sock_addr_port_ptr = htons (new_port);
    }

    /* close temporary socket */
    os_ret_val = close (sock);
    if (os_ret_val != 0)
    {
        ARPNDP_INTERNAL_ERROR ("close(temp) fails, os_ret_val %d, "
            "error %d - %s, socket %d\n", os_ret_val, errno, strerror (errno),
            sock);
        arpndp_data->stats.close_fail++;
        /* continue */
    }

    return ARPNDP_SUCCESS;
}


/*
 * Name:        ARPNDP_trans_send
 *
 * Abstract:    function to send ARP/NDP message
 *
 * Parameters:
 *     sess_idx - ARP/NDP session index
 *
 * Returns:
 *     ret_val   - success or failure
 */
ARPNDP_RETVAL ARPNDP_trans_send (int sess_idx)
{
    int os_ret_val;

    /* ARP */
    struct arp_pkt arp_msg;

    /* NDP */
    struct arp6_pkt ndp_msg;
    struct sockaddr_in6 ndp_sock_addr;
    struct msghdr msg_hdr;
    struct iovec msg_iov[1];
    char pkt_info_buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    struct cmsghdr *cmsg_hdr;
    struct in6_pktinfo *pkt_info_ptr;

    ARPNDP_connect_temp_sock (sess_idx);

    if (arpndp_data->sess[sess_idx].protocol == ARPNDP_PROTOCOL_ARP)
    {
        /* IPv4 ARP */

        /*
         * MAC address, IPv4 address, fields in Ethernet header and ARP
         * message are in network byte-order
         */

        memset (&arp_msg, 0, sizeof(arp_msg));

        /* prepare Ethernet header */

        /* destination is broadcast MAC address */
        memset (arp_msg.eth_hdr.h_dest, 0xff, ETH_ALEN);

        /* source is this OS interface MAC address */
        memcpy (arp_msg.eth_hdr.h_source,
            arpndp_data->sess[sess_idx].mac_addr, ETH_ALEN);
        
        /* Ethernet protocol is ARP */
        arp_msg.eth_hdr.h_proto = htons (ETH_P_ARP);

        /* prepare ARP message */

        /* hardware type is Ethernet */
        arp_msg.arp.ea_hdr.ar_hrd = htons (ARPHRD_ETHER);

        /* ARP protocol is IP */
        arp_msg.arp.ea_hdr.ar_pro = htons (ETH_P_IP);

        /* hardware address length = MAC addresss length */
        arp_msg.arp.ea_hdr.ar_hln = ETH_ALEN;

        /* protocol addresss length = IP address length */
        arp_msg.arp.ea_hdr.ar_pln = sizeof(uint32_t);

        /* ARP operation is REQUEST */
        arp_msg.arp.ea_hdr.ar_op = htons (ARPOP_REQUEST);

        /* sender MAC address is this OS interface MAC address */
        memcpy (arp_msg.arp.arp_sha, arpndp_data->sess[sess_idx].mac_addr,
            ETH_ALEN);

        /* sender IP address is local IP */
        *((uint32_t *) &arp_msg.arp.arp_spa) =
            arpndp_data->sess[sess_idx].local_ip.ipaddr[0];

        /* target MAC address is unknown */
        /* arp_msg.arp.arp_tha is 0 when memset() */

        /* target IP address is remote IP */
        *((uint32_t *) &arp_msg.arp.arp_tpa) =
            arpndp_data->sess[sess_idx].remote_ip.ipaddr[0];

        /* call socket API to send ARP message */
        os_ret_val = send (arpndp_data->sess[sess_idx].sock, &arp_msg,
            sizeof( arp_msg), /*flags*/ 0);
        if (os_ret_val != sizeof(arp_msg))
        {
            ARPNDP_LOCAL_ERROR ("sendto() fails, os_ret_val %d, "
                "error %d - %s, socket %d, intf_idx %d\n",
                os_ret_val, errno, strerror (errno),
                arpndp_data->sess[sess_idx].sock,
                arpndp_data->sess[sess_idx].intf_idx);
            arpndp_data->stats.send_fail++;
            return ARPNDP_LOCAL_FAIL;
        }
    }
    else if (arpndp_data->sess[sess_idx].protocol == ARPNDP_PROTOCOL_NDP)
    {
        /* IPv6 NDP */

        memset (&ndp_msg, 0, sizeof(ndp_msg));

        /* ICMPv6 required header */

        /* type = neighbor solicitation */
        ndp_msg.na.nd_na_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;

        /* code */
        ndp_msg.na.nd_na_hdr.icmp6_code = 0;

        /* checksum will be calculate in Linux kernel */
        ndp_msg.na.nd_na_hdr.icmp6_cksum = 0;

        /* target IPv6 address */
        memcpy (&ndp_msg.na.nd_na_target,
            arpndp_data->sess[sess_idx].remote_ip.ipaddr,
            sizeof(arpndp_data->sess[sess_idx].remote_ip.ipaddr));

        /* ICMPv6 optional header for source link-layer address */
        ndp_msg.opt_hdr.nd_opt_type = ND_OPT_SOURCE_LINKADDR;

        /*
         * optional header length = MAC address length + optional header length
         * in 8-byte units
         */
        ndp_msg.opt_hdr.nd_opt_len =
            (ETH_ALEN + sizeof(struct nd_opt_hdr)) / 8;

        /* source link-layer address is OS interface MAC address */
        memcpy (ndp_msg.hw_addr, arpndp_data->sess[sess_idx].mac_addr,
            ETH_ALEN );

        /* prepare socket address */
        memset (&ndp_sock_addr, 0, sizeof(ndp_sock_addr));

        ndp_sock_addr.sin6_family = AF_INET6;
        ndp_sock_addr.sin6_port = 0;

        EIPM_get_solicited_node_multicast_addr (ndp_msg.na.nd_na_target,
            &ndp_sock_addr.sin6_addr);

        msg_hdr.msg_name = &ndp_sock_addr;
        msg_hdr.msg_namelen = sizeof(ndp_sock_addr);

        /* prepare IO vectore */

        msg_iov[0].iov_base = &ndp_msg;
        msg_iov[0].iov_len = sizeof(ndp_msg);

        msg_hdr.msg_iov = msg_iov;
        msg_hdr.msg_iovlen = 1;
        msg_hdr.msg_flags = 0;

        /* prepare control message */
        msg_hdr.msg_control = &pkt_info_buf[0];
        msg_hdr.msg_controllen = sizeof(pkt_info_buf);

        cmsg_hdr = CMSG_FIRSTHDR (&msg_hdr);
        cmsg_hdr->cmsg_len = CMSG_LEN (sizeof(struct in6_pktinfo));
        cmsg_hdr->cmsg_level = IPPROTO_IPV6;
        cmsg_hdr->cmsg_type = IPV6_PKTINFO;

        pkt_info_ptr = (struct in6_pktinfo *) CMSG_DATA (cmsg_hdr);
        pkt_info_ptr->ipi6_ifindex = arpndp_data->sess[sess_idx].intf_idx;
 
        memcpy (&pkt_info_ptr->ipi6_addr,
            arpndp_data->sess[sess_idx].local_ip.ipaddr,
            sizeof(arpndp_data->sess[sess_idx].local_ip.ipaddr));
        os_ret_val = sendmsg (arpndp_data->sess[sess_idx].sock, &msg_hdr,
            /*flags*/ 0);
        if (os_ret_val != sizeof(ndp_msg))
        {
            ARPNDP_LOCAL_ERROR ("sendmsg() fails, os_ret_val %d, "
                "error %d - %s, socket %d, intf_idx %d\n",
                os_ret_val, errno, strerror (errno),
                arpndp_data->sess[sess_idx].sock,
                arpndp_data->sess[sess_idx].intf_idx);
            arpndp_data->stats.send_msg_fail++;
            return ARPNDP_LOCAL_FAIL;
        }
    }
    else
    {
        ARPNDP_INTERNAL_ERROR ("invalid ARP/NDP protocol %d\n",
            arpndp_data->sess[sess_idx].protocol);
        arpndp_data->stats.inv_protocol++;
        return ARPNDP_INTERNAL_FAIL;
    }

    arpndp_data->sess[sess_idx].send_count++;
    arpndp_data->sess_stats[sess_idx].good_send++;

    return ARPNDP_SUCCESS;
}
