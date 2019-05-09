/*************************************************************************
 *
 * File:     ARPNDP_stats.c
 *
 * Abstract: implementation file of ARP/NDP statistic module
 *           this module handles ARP/NDP statistics/counts
 *
 * Data:     none
 *
 * Functions:
 *     ARPNDP_stats_init       - function to initialize ARP/NDP statistic module
 *
 *     ARPNDP_stats_log_arpndp - function to log statistics/counts of ARP/NDP
 *                               protocol
 *     ARPNDP_stats_log_sess   - function to log statistics/counts of an ARP/NDP
 *                               session
 *
 ************************************************************************/

#include "ARPNDP_int_hdr.h"


/*
 * Name:        ARPNDP_stats_init
 *
 * Abstract:    function to initialize ARP/NDP statistic module
 *
 * Parameters:  none
 *
 * Retunrs:     none
 */
void ARPNDP_stats_init()
{
    memset (&arpndp_data->stats, 0, sizeof(arpndp_data->stats));
    memset (arpndp_data->sess_stats, 0, sizeof(arpndp_data->sess_stats));
}


/*
 * Name:        ARPNDP_stats_log_arpndp
 *
 * Abstract:    function to log statistics/counts of ARP/NDP protocol
 *
 * Parameters:  none
 *
 * Retunrs:     none
 */
void ARPNDP_stats_log_arpndp()
{
    char buffer[ARPNDP_ERR_LOG_BUF_SIZE];
    char *ptr = &buffer[0];
    int size = sizeof(buffer);

    ARPNDP_PRINTF (ptr, size,
        "ARP/NDP protocol statistics report 1/2:\n"

        "    good_create                          %u\n"
        "    good_change_cfg                      %u\n"
        "    good_destroy                         %u\n"
        "    good_get_sess_state                  %u\n"
        "    good_set_admin_state                 %u\n"
        "    good_get_stats                       %u\n"
        "    good_timer                           %u\n"
        "    good_add_sockets                     %u\n"
        "    good_audit                           %u\n"
        "    good_recv                            %u\n"
        "    recv_no_sess                         %u\n"
        "\n"
        "    arpndp_size_error                    %u\n"
        "\n"
        "    not_single_thread                    %u\n"
        "    arpndp_has_init                      %u\n"
        "\n"
        "    inv_init_type                        %u\n"
        "\n"
        "    inv_intf_idx                         %u\n"
        "    inv_remote_ip                        %u\n"
        "    inv_local_ip                         %u\n"
        "    inv_local_ip_type                    %u\n"
        "    inv_detect_time_mult                 %u\n"
        "    inv_min_tx                           %u\n"
        "    inv_min_rx                           %u\n"
        "    inv_protocol                         %u\n"
        "\n"
        "    inv_sess_state_ptr                   %u\n"
        "    inv_admin_state                      %u\n"
        "    inv_missed_hb_ptr                    %u\n"
        "    inv_read_sock_set_ptr                %u\n"
        "    inv_begin_middle_end                 %u\n",

        arpndp_data->stats.good_create,
        arpndp_data->stats.good_change_cfg,
        arpndp_data->stats.good_destroy,
        arpndp_data->stats.good_get_sess_state,
        arpndp_data->stats.good_set_admin_state,
        arpndp_data->stats.good_get_stats,
        arpndp_data->stats.good_timer,
        arpndp_data->stats.good_add_sockets,
        arpndp_data->stats.good_audit,
        arpndp_data->stats.good_recv,
        arpndp_data->stats.recv_no_sess,

        arpndp_data->stats.arpndp_size_error,

        arpndp_data->stats.not_single_thread,
        arpndp_data->stats.arpndp_has_init,

        arpndp_data->stats.inv_init_type,

        arpndp_data->stats.inv_intf_idx,
        arpndp_data->stats.inv_remote_ip,
        arpndp_data->stats.inv_local_ip,
        arpndp_data->stats.inv_local_ip_type,
        arpndp_data->stats.inv_detect_time_mult,
        arpndp_data->stats.inv_min_tx,
        arpndp_data->stats.inv_min_rx,
        arpndp_data->stats.inv_protocol,

        arpndp_data->stats.inv_sess_state_ptr,
        arpndp_data->stats.inv_admin_state,
        arpndp_data->stats.inv_missed_hb_ptr,
        arpndp_data->stats.inv_read_sock_set_ptr,
        arpndp_data->stats.inv_begin_middle_end);

    ARPNDP_LOG_FORCED (buffer);

    ptr = buffer;
    size = sizeof(buffer);

    ARPNDP_PRINTF (ptr, size,
        "ARP/NDP protocol statistics report 2/2:\n"

        "    corrupt_audit_cb_func                %u\n"
        "    ext_audit                            %u\n"
            "\n" 
        "    not_enough_sess                      %u\n"
        "    inv_arpndp_sess_num                  %u\n"
        "    sess_not_found                       %u\n"
        "    inv_intf_idx_remote_ip               %u\n"
        "\n" 
        "    int_audit_minor                      %u\n"
        "    int_audit_major                      %u\n"
        "\n" 
        "    inv_history_cur_idx                  %u\n"
        "\n" 
        "    inv_sess_state                       %u\n"
        "    inv_event                            %u\n"
        "    unexpect_event                       %u\n"
        "\n" 
        "    socket_fail                          %u\n"
        "    bind_fail                            %u\n"
        "    ioctl_fail                           %u\n"
        "    set_sock_opt_fail                    %u\n"
        "    close_fail                           %u\n"
        "    connect_fail                         %u\n"
        "\n" 
        "    send_msg_fail                        %u\n"
        "    send_fail                            %u\n"
        "\n" 
        "    recv_msg_fail                        %u\n"
        "    recv_fail                            %u\n"
        "\n" 
        "    ctl_len_zero                         %u\n"
        "    inv_cmsg_type                        %u\n"
        "    inv_cmsg_level                       %u\n",

        arpndp_data->stats.corrupt_audit_cb_func,
        arpndp_data->stats.ext_audit,

        arpndp_data->stats.not_enough_sess,
        arpndp_data->stats.inv_arpndp_sess_num,
        arpndp_data->stats.sess_not_found,
        arpndp_data->stats.inv_intf_idx_remote_ip,

        arpndp_data->stats.int_audit_minor,
        arpndp_data->stats.int_audit_major,

        arpndp_data->stats.inv_history_cur_idx,

        arpndp_data->stats.inv_sess_state,
        arpndp_data->stats.inv_event,
        arpndp_data->stats.unexpect_event,

        arpndp_data->stats.socket_fail,
        arpndp_data->stats.bind_fail,
        arpndp_data->stats.ioctl_fail,
        arpndp_data->stats.set_sock_opt_fail,
        arpndp_data->stats.connect_fail,
        arpndp_data->stats.close_fail,

        arpndp_data->stats.send_msg_fail,
        arpndp_data->stats.send_fail,

        arpndp_data->stats.recv_msg_fail,
        arpndp_data->stats.recv_fail,

        arpndp_data->stats.ctl_len_zero,
        arpndp_data->stats.inv_cmsg_type,
        arpndp_data->stats.inv_cmsg_level);

    ARPNDP_LOG_FORCED (buffer);

    memset (&arpndp_data->stats, 0, sizeof(arpndp_data->stats));
}


/*
 * Name:        ARPNDP_stats_log_sess
 *
 * Abstract:    function to log statistics/counts of an ARP/NDP session
 *
 * Parameters:
 *     sess_idx - ARP/NDP session index
 *
 * Retunrs:     none
 */
void ARPNDP_stats_log_sess (int sess_idx)
{
    char buffer[ARPNDP_ERR_LOG_BUF_SIZE];
    char *ptr = &buffer[0];
    int size = sizeof(buffer);

    ARPNDP_PRINTF (ptr, size,
        "ARP/NDP session statistics at index %d:\n"

        "    good_recv                            %u\n"
        "    good_send                            %u\n"
        "\n"
        "    inv_recv_intf_idx                    %u\n"
        "\n"
        "    not_arp_reply                        %u\n"
        "    not_nd_advert                        %u\n"
        "    diff_remote_ip                       %u\n"
        "    diff_local_ip                        %u\n",

        sess_idx,

        arpndp_data->sess_stats[sess_idx].good_recv,
        arpndp_data->sess_stats[sess_idx].good_send,

        arpndp_data->sess_stats[sess_idx].inv_recv_intf_idx,

        arpndp_data->sess_stats[sess_idx].not_arp_reply,
        arpndp_data->sess_stats[sess_idx].not_nd_advert,
        arpndp_data->sess_stats[sess_idx].diff_remote_ip,
        arpndp_data->sess_stats[sess_idx].diff_local_ip);

    ARPNDP_LOG_FORCED (buffer);

    memset (&arpndp_data->sess_stats[sess_idx], 0,
        sizeof(arpndp_data->sess_stats[0]));
}
