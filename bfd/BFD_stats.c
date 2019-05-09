/*************************************************************************
 *
 * File:     BFD_stats.c
 *
 * Abstract: implementation file of BFD statistic module
 *           this module handles BFD statistics/counts
 *
 * Data:     none
 *
 * Functions:
 *     BFD_stats_init     - function to initialize BFD statistic module
 *
 *     BFD_stats_log_bfd  - function to log BFD statistics/counts of BFD
 *                          protocol
 *     BFD_stats_log_sess - function to log BFD statistics/counts of BFD
 *                          session
 *
 ************************************************************************/

#include "BFD_int_hdr.h"


/*
 * Name:        BFD_stats_init
 *
 * Abstract:    function to initialize BFD statistic module
 *
 * Parameters:  none
 *
 * Retunrs:     none
 */
void BFD_stats_init()
{
    memset (&bfd_data->stats, 0, sizeof(bfd_data->stats));
    memset (bfd_data->sess_stats, 0, sizeof(bfd_data->sess_stats));
}


/*
 * Name:        BFD_stats_log_bfd
 *
 * Abstract:    function to log BFD statistics/counts of BFD protocol
 *
 * Parameters:  none
 *
 * Retunrs:     none
 */
void BFD_stats_log_bfd()
{
    char buffer[BFD_ERR_LOG_BUF_SIZE];
    char *ptr = &buffer[0];
    int size = sizeof(buffer);

    BFD_PRINTF (ptr, size,
        "BFD protocol statistics report 1/2:\n"

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
        "    bfd_size_error                       %u\n"
        "\n"
        "    not_single_thread                    %u\n"
        "    bfd_has_init                         %u\n"
        "\n"
        "    inv_init_type                        %u\n"
        "\n"
        "    inv_local_ip                         %u\n"
        "    inv_remote_ip                        %u\n"
        "    inv_remote_local_ip_type             %u\n"
        "    inv_detect_time_mult                 %u\n"
        "    inv_min_tx                           %u\n"
        "    inv_min_rx                           %u\n"
        "\n"
        "    inv_sess_state_ptr                   %u\n"
        "    inv_admin_state                      %u\n"
        "    inv_missed_hb_ptr                    %u\n"
        "    inv_corrupt_pkt_ptr                  %u\n"
        "    inv_read_sock_set_ptr                %u\n"
        "    inv_begin_middle_end                 %u\n",

        bfd_data->stats.good_create,
        bfd_data->stats.good_change_cfg,
        bfd_data->stats.good_destroy,
        bfd_data->stats.good_get_sess_state,
        bfd_data->stats.good_set_admin_state,
        bfd_data->stats.good_get_stats,
        bfd_data->stats.good_timer,
        bfd_data->stats.good_add_sockets,
        bfd_data->stats.good_audit,
        bfd_data->stats.good_recv,
        bfd_data->stats.recv_no_sess,

        bfd_data->stats.bfd_size_error,

        bfd_data->stats.not_single_thread,
        bfd_data->stats.bfd_has_init,

        bfd_data->stats.inv_init_type,

        bfd_data->stats.inv_local_ip,
        bfd_data->stats.inv_remote_ip,
        bfd_data->stats.inv_remote_local_ip_type,
        bfd_data->stats.inv_detect_time_mult,
        bfd_data->stats.inv_min_tx,
        bfd_data->stats.inv_min_rx,

        bfd_data->stats.inv_sess_state_ptr,
        bfd_data->stats.inv_admin_state,
        bfd_data->stats.inv_missed_hb_ptr,
        bfd_data->stats.inv_corrupt_pkt_ptr,
        bfd_data->stats.inv_read_sock_set_ptr,
        bfd_data->stats.inv_begin_middle_end);

    BFD_LOG_FORCED (buffer);

    ptr = buffer;
    size = sizeof(buffer);

    BFD_PRINTF (ptr, size,
        "BFD protocol statistics report 2/2:\n"

        "    corrupt_audit_cb_func                %u\n"
        "    ext_audit                            %u\n"
        "\n" 
        "    corrupt_state_change_cb_func         %u\n"
        "    inv_local_ofc_min_tx                 %u\n"
        "\n" 
        "    not_enough_sess                      %u\n"
        "    inv_bfd_sess_num                     %u\n"
        "    sess_not_found                       %u\n"
        "    inv_local_ip_remote_ip               %u\n"
        "\n" 
        "    local_poll_seq_in_progress           %u\n"
        "\n" 
        "    int_audit_minor                      %u\n"
        "    int_audit_major                      %u\n"
        "\n" 
        "    inv_history_cur_idx                  %u\n"
        "\n" 
        "    inv_local_state                      %u\n"
        "    inv_event                            %u\n"
        "    unexpect_event                       %u\n"
        "\n" 
        "    socket_fail                          %u\n"
        "    set_sock_opt_fail                    %u\n"
        "    close_fail                           %u\n"
        "\n" 
        "    corrupt_remote_sock_addr             %u\n"
        "    send_to_fail                         %u\n"
        "\n" 
        "    corrupt_recv_msg_hdr                 %u\n"
        "    recv_msg_fail                        %u\n"
        "    ctl_len_zero                         %u\n"
        "    inv_cmsg_type                        %u\n"
        "    inv_cmsg_level                       %u\n",

        bfd_data->stats.corrupt_audit_cb_func,
        bfd_data->stats.ext_audit,

        bfd_data->stats.corrupt_state_change_cb_func,
        bfd_data->stats.inv_local_ofc_min_tx,

        bfd_data->stats.not_enough_sess,
        bfd_data->stats.inv_bfd_sess_num,
        bfd_data->stats.sess_not_found,
        bfd_data->stats.inv_local_ip_remote_ip,

        bfd_data->stats.local_poll_seq_in_progress,

        bfd_data->stats.int_audit_minor,
        bfd_data->stats.int_audit_major,

        bfd_data->stats.inv_history_cur_idx,

        bfd_data->stats.inv_local_state,
        bfd_data->stats.inv_event,
        bfd_data->stats.unexpect_event,

        bfd_data->stats.socket_fail,
        bfd_data->stats.set_sock_opt_fail,
        bfd_data->stats.close_fail,

        bfd_data->stats.corrupt_remote_sock_addr,
        bfd_data->stats.send_to_fail,

        bfd_data->stats.corrupt_recv_msg_hdr,
        bfd_data->stats.recv_msg_fail,
        bfd_data->stats.ctl_len_zero,
        bfd_data->stats.inv_cmsg_type,
        bfd_data->stats.inv_cmsg_level);

    BFD_LOG_FORCED (buffer);

    memset (&bfd_data->stats, 0, sizeof(bfd_data->stats));
}


/*
 * Name:        BFD_stats_log_sess
 *
 * Abstract:    function to log BFD statistics/counts of a BFD session
 *
 * Parameters:
 *     sess_idx - BFD session index
 *
 * Retunrs:     none
 */
void BFD_stats_log_sess (int sess_idx)
{
    char buffer[BFD_ERR_LOG_BUF_SIZE];
    char *ptr = &buffer[0];
    int size = sizeof(buffer);

    BFD_PRINTF (ptr, size,
        "BFD session statistics at index %d:\n"

        "    good_encode                          %u\n"
        "    good_decode                          %u\n"
        "\n"
        "    inv_remote_version                   %u\n"
        "    inv_remote_diagnostic                %u\n"
        "    inv_remote_sess_state                %u\n"
        "\n"
        "    remote_both_poll_and_final           %u\n"
        "    inv_remote_auth_present_flag         %u\n"
        "    inv_remote_demand_flag               %u\n"
        "    inv_remote_multi_point_flag          %u\n"
        "\n"
        "    inv_remote_detect_time_mult          %u\n"
        "    inv_remote_length                    %u\n"
        "    inv_remote_my_discr                  %u\n"
        "    inv_remote_your_discr                %u\n"
        "    inv_remote_min_echo_rx               %u\n"
        "\n"
        "    good_recv                            %u\n"
        "    good_send                            %u\n"
        "\n"
        "    recv_sock_bind_fail                  %u\n"
        "    send_sock_bind_fail                  %u\n"
        "\n"
        "    inv_recv_ttl                         %u\n"
        "    inv_recv_hop_limit                   %u\n",

        sess_idx,

        bfd_data->sess_stats[sess_idx].good_encode,
        bfd_data->sess_stats[sess_idx].good_decode,
        
        bfd_data->sess_stats[sess_idx].inv_remote_version,
        bfd_data->sess_stats[sess_idx].inv_remote_diagnostic,
        bfd_data->sess_stats[sess_idx].inv_remote_sess_state,

        bfd_data->sess_stats[sess_idx].remote_both_poll_and_final,
        bfd_data->sess_stats[sess_idx].inv_remote_auth_present_flag,
        bfd_data->sess_stats[sess_idx].inv_remote_demand_flag,
        bfd_data->sess_stats[sess_idx].inv_remote_multi_point_flag,

        bfd_data->sess_stats[sess_idx].inv_remote_detect_time_mult,
        bfd_data->sess_stats[sess_idx].inv_remote_length,
        bfd_data->sess_stats[sess_idx].inv_remote_my_discr,
        bfd_data->sess_stats[sess_idx].inv_remote_your_discr,
        bfd_data->sess_stats[sess_idx].inv_remote_min_echo_rx,

        bfd_data->sess_stats[sess_idx].good_recv,
        bfd_data->sess_stats[sess_idx].good_send,

        bfd_data->sess_stats[sess_idx].recv_sock_bind_fail,
        bfd_data->sess_stats[sess_idx].send_sock_bind_fail,

        bfd_data->sess_stats[sess_idx].inv_recv_ttl,
        bfd_data->sess_stats[sess_idx].inv_recv_hop_limit);

    BFD_LOG_FORCED (buffer);

    memset (&bfd_data->sess_stats[sess_idx], 0,
        sizeof(bfd_data->sess_stats[0]));
}
