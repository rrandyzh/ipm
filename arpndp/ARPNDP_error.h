/*************************************************************************
 *
 * File:     ARPNDP_error.h
 *
 * Abstract: internal header file of ARP/NDP error module
 *           this module handles ARP/NDP error and logging
 *
 * Nodes:    ARP/NDP implemenation should include only ARPNDP_int_data.h
 *           instead of this file
 *
 ************************************************************************/

#ifndef ARPNDP_ERROR_H
#define ARPNDP_ERROR_H


/* ARPNDP logging class */
#define ARPNDP_LOG_CLASS             0

/* buffer size for ARP/NDP error/log message */
#define ARPNDP_ERR_LOG_BUF_SIZE      (2 * 1024 - 48)


/* error internval - 10 minutes */
#define ARPNDP_ERR_INTERVAL          (10 * 60 * 1000 / ARPNDP_TIMER_INTERVAL)

/* number of errors allowed per interval */
#define ARPNDP_ERR_NUM_PER_INTERVAL  10



/*
 * snprint with buffer overflow protection
 *
 * it is only for ARPNDP_LOG, ARPNDP_*_ERROR macros 
 */
#define ARPNDP_PRINTF(_parmPtr_, _parmSize_, ...)                         \
{                                                                         \
    int _localSize_ = snprintf ((_parmPtr_), (_parmSize_), __VA_ARGS__);  \
    if ((_localSize_ <= -1) || (_localSize_ >= (_parmSize_)))             \
    {                                                                     \
        (_parmPtr_)[(_parmSize_) - 1] = 0;                                \
        (_parmPtr_) += (_parmSize_);                                      \
        (_parmSize_) = 0;                                                 \
    }                                                                     \
    else                                                                  \
    {                                                                     \
        (_parmPtr_) += _localSize_;                                       \
        (_parmSize_) -= _localSize_;                                      \
    }                                                                     \
}



/* whether logging is enabled */
#define ARPNDP_LOG_ENABLED                                              \
    (ipm_get_log_level(ARPNDP_LOG_CLASS) >= LOG_MEDIUM)


/*
 * force to log a message regardless of log level;
 * message has been formated
 */
#define ARPNDP_LOG_FORCED(buffer)                                       \
    LOG_FORCE (ARPNDP_LOG_CLASS, buffer)



/*
 * begin part of ARP/NDP error/log message with brevity control;
 * this macro opens a C block (last {) that is closed by macro
 * ARPNDP_ERROR_LOG_END_W_BREV_CTL
 *
 * it is only for ARPNDP_LOG, ARPNDP_*_ERROR macros 
 */
#define ARPNDP_ERROR_LOG_BEGIN_W_BREV_CTL                               \
    static unsigned int _next_err_time_ = 0;                            \
    static unsigned int _num_of_pass_err_ = 0;                          \
                                                                        \
    char _buffer_[ARPNDP_ERR_LOG_BUF_SIZE];                             \
    char *_ptr_ = &_buffer_[0];                                         \
    int _size_ = sizeof(_buffer_);                                      \
                                                                        \
    if (arpndp_cur_time >= _next_err_time_)                             \
    {                                                                   \
        _next_err_time_ = arpndp_cur_time + ARPNDP_ERR_INTERVAL;        \
        _num_of_pass_err_ = 0;                                          \
    }                                                                   \
                                                                        \
    if (_num_of_pass_err_ < ARPNDP_ERR_NUM_PER_INTERVAL)                \
    {                                                                   \
        _num_of_pass_err_++;

/*
 * begin part of ARP/NDP error/log message without brevity control;
 *
 * it is only for ARPNDP_LOG, ARPNDP_*_ERROR macros
 */
#define ARPNDP_ERROR_LOG_BEGIN_WO_BREV_CTL                              \
    char _buffer_[ARPNDP_ERR_LOG_BUF_SIZE];                             \
    char *_ptr_ = &_buffer_[0];                                         \
    int _size_ = sizeof(_buffer_);


/*
 * end part of ARP/NDP error/log message with brevity control
 * this macro closes C block that is opended by macro
 * ARPNDP_ERROR_LOG_BEGIN_W_BREV_CTL
 *
 * it is only for ARPNDP_LOG, ARPNDP_*_ERROR macros 
 */
#define ARPNDP_ERROR_LOG_END_W_BREV_CTL                                \
    }


/*
 * end part of ARP/NDP error/log message without brevity control
 *
 * it is only for ARPNDP_LOG, ARPNDP_*_ERROR macros
 */
#define ARPNDP_ERROR_LOG_END_WO_BREV_CTL 



/*
 * log a message;
 * message is not formated yet;
 * no brevity control
 *
 * the following stack local variables are used:
 *     _buffer_
 *     _ptr_
 *     _size_
 */
#define ARPNDP_LOG(...)                                                 \
{                                                                       \
    ARPNDP_ERROR_LOG_BEGIN_WO_BREV_CTL                                  \
                                                                        \
    ARPNDP_PRINTF (_ptr_, _size_, __VA_ARGS__);                         \
                                                                        \
    LOG_FORCE (ARPNDP_LOG_CLASS, _buffer_);                             \
                                                                        \
    ARPNDP_ERROR_LOG_END_WO_BREV_CTL                                    \
}


/*
 * LCP ARP/NDP error without ARP/NDP session/history/statistic log;
 * message is not formated yet;
 * has brevity control
 * 
 * the following static local variables are used:
 *     _next_err_time_
 *     _num_of_pass_err_
 *     
 * the following stack local variables are used:
 *     _buffer_
 *     _ptr_
 *     _size_
 */
#define ARPNDP_INTERNAL_ERROR(...)                                      \
{                                                                       \
    ARPNDP_ERROR_LOG_BEGIN_W_BREV_CTL                                   \
                                                                        \
    ARPNDP_PRINTF (_ptr_, _size_, "ARP/NDP ERROR (PROTOCOL): ");        \
    ARPNDP_PRINTF (_ptr_, _size_, __VA_ARGS__);                         \
                                                                        \
    LOG_FORCE (ARPNDP_LOG_CLASS, _buffer_);                             \
                                                                        \
    ARPNDP_ERROR_LOG_END_W_BREV_CTL                                     \
}

/*
 * LCP ARP/NDP error with ARP/NDP session/history/statistic log;
 * message is not formated yet;
 * has brevity control
 *
 * the following static local variables are used:
 *     _next_err_time_
 *     _num_of_pass_err_
 *
 * the following stack local variables are used:
 *     _buffer_
 *     _ptr_
 *     _size_
 */
#define ARPNDP_AUDIT_ERROR(sess_idx, ...)                               \
{                                                                       \
    ARPNDP_ERROR_LOG_BEGIN_W_BREV_CTL                                   \
                                                                        \
    ARPNDP_PRINTF (_ptr_, _size_, "ARP/NDP ERROR (AUDIT): index %u, ",  \
        sess_idx);                                                      \
    ARPNDP_PRINTF (_ptr_, _size_, __VA_ARGS__);                         \
                                                                        \
    LOG_FORCE (ARPNDP_LOG_CLASS, _buffer_);                             \
                                                                        \
    ARPNDP_sess_data_log (sess_idx);                                    \
    ARPNDP_history_log (sess_idx);                                      \
    ARPNDP_stats_log_sess (sess_idx);                                   \
                                                                        \
    ARPNDP_ERROR_LOG_END_W_BREV_CTL                                     \
}

/*
 * LCP ARP/NDP error with ARP/NDP session/histtory/statistic log;
 * message is not formated yet;
 * has brevity control
 * 
 * the following static local variables are used:
 *     _next_err_time_
 *     _num_of_pass_err_
 *     
 * the following stack local variables are used:
 *     _buffer_
 *     _ptr_
 *     _size_
 */
#define ARPNDP_SESS_ERROR(sess_idx, ...)                                \
{                                                                       \
    ARPNDP_ERROR_LOG_BEGIN_W_BREV_CTL                                   \
                                                                        \
    ARPNDP_PRINTF (_ptr_, _size_, "ARP/NDP ERROR (SESSION): index %u, ", \
        sess_idx);                                                      \
    ARPNDP_PRINTF (_ptr_, _size_, __VA_ARGS__);                         \
                                                                        \
    LOG_FORCE (ARPNDP_LOG_CLASS, _buffer_);                             \
                                                                        \
    ARPNDP_sess_data_log (sess_idx);                                    \
    ARPNDP_history_log (sess_idx);                                      \
    ARPNDP_stats_log_sess (sess_idx);                                   \
                                                                        \
    ARPNDP_ERROR_LOG_END_W_BREV_CTL                                     \
    }

/*
 * LCP error;
 * message is not formated yet;
 * has brevity control
 * 
 * the following static local variables are used:
 *     _next_err_time_
 *     _num_of_pass_err_
 *     
 * the following stack local variables are used:
 *     _buffer_
 *     _ptr_
 *     _size_
 */
#define ARPNDP_LOCAL_ERROR(...)                                         \
{                                                                       \
    ARPNDP_ERROR_LOG_BEGIN_W_BREV_CTL                                   \
                                                                        \
    ARPNDP_PRINTF (_ptr_, _size_, "ARP/NDP ERROR (LCP): ");             \
    ARPNDP_PRINTF (_ptr_, _size_, __VA_ARGS__);                         \
                                                                        \
    LOG_FORCE (ARPNDP_LOG_CLASS, _buffer_);                             \
                                                                        \
    ARPNDP_ERROR_LOG_END_W_BREV_CTL                                     \
}

/*
 * Gateway error;
 * message is not formated yet;
 * has brevity control
 * 
 * the following static local variables are used:
 *     _next_err_time_
 *     _num_of_pass_err_
 *     
 * the following stack local variables are used:
 *     _buffer_
 *     _ptr_
 *     _size_
 */
#define ARPNDP_REMOTE_ERROR(...)                                        \
{                                                                       \
    ARPNDP_ERROR_LOG_BEGIN_W_BREV_CTL                                   \
                                                                        \
    ARPNDP_PRINTF (_ptr_, _size_, "ARP/NDP ERROR (GATEWAY): ");         \
    ARPNDP_PRINTF (_ptr_, _size_, __VA_ARGS__);                         \
                                                                        \
    LOG_FORCE (ARPNDP_LOG_CLASS, _buffer_);                             \
                                                                        \
    ARPNDP_msg_log (sess_idx);                                          \
                                                                        \
    ARPNDP_sess_data_log (sess_idx);                                    \
    ARPNDP_history_log (sess_idx);                                      \
    ARPNDP_stats_log_sess (sess_idx);                                   \
                                                                        \
    ARPNDP_ERROR_LOG_END_W_BREV_CTL                                     \
}


#endif /* #ifndef ARPNDP_ERROR_H */
