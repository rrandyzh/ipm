/*************************************************************************
 *
 * File:     BFD_error.h
 *
 * Abstract: internal header file of BFD error module
 *           this module handles BFD error and logging
 *
 * Nodes:    BFD implemenation should include only BFD_int_data.h instead
 *           of this file
 *
 ************************************************************************/

#ifndef BFD_ERROR_H
#define BFD_ERROR_H


/* BFD logging class */
#define BFD_LOG_CLASS                   0

/* buffer size for BFD error/log message */
#define BFD_ERR_LOG_BUF_SIZE            (2 * 1024 - 48)


/* error internval - 10 minutes */
#define BFD_ERR_INTERVAL                (10 * 60 * 1000 / BFD_TIMER_INTERVAL)

/* number of errors allowed per interval */
#define BFD_ERR_NUM_PER_INTERVAL        10



/*
 * snprint with buffer overflow protection
 *
 * it is only for BFD_LOG, BFD_*_ERROR macros 
 */
#define BFD_PRINTF(_parmPtr_, _parmSize_, ...)                            \
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
#define BFD_LOG_ENABLED                                             \
    (ipm_get_log_level(BFD_LOG_CLASS) >= LOG_MEDIUM)


/*
 * force to log a message regardless of log level;
 * message has been formated
 */
#define BFD_LOG_FORCED(buffer)                                      \
    LOG_FORCE (BFD_LOG_CLASS, buffer)



/*
 * begin part of BFD error/log message with brevity control;
 * this macro opens a C block (last {) that is closed by macro
 * BFD_ERROR_LOG_END_W_BREV_CTL
 *
 * it is only for BFD_LOG, BFD_*_ERROR macros 
 */
#define BFD_ERROR_LOG_BEGIN_W_BREV_CTL                              \
    static unsigned int _next_err_time_ = 0;                        \
    static unsigned int _num_of_pass_err_ = 0;                      \
                                                                    \
    char _buffer_[BFD_ERR_LOG_BUF_SIZE];                            \
    char *_ptr_ = &_buffer_[0];                                     \
    int _size_ = sizeof(_buffer_);                                  \
                                                                    \
    if (bfd_cur_time >= _next_err_time_)                            \
    {                                                               \
        _next_err_time_ = bfd_cur_time + BFD_ERR_INTERVAL;          \
        _num_of_pass_err_ = 0;                                      \
    }                                                               \
                                                                    \
    if (_num_of_pass_err_ < BFD_ERR_NUM_PER_INTERVAL)               \
    {                                                               \
        _num_of_pass_err_++;

/*
 * begin part of BFD error/log message without brevity control;
 *
 * it is only for BFD_LOG, BFD_*_ERROR macros
 */
#define BFD_ERROR_LOG_BEGIN_WO_BREV_CTL                             \
    char _buffer_[BFD_ERR_LOG_BUF_SIZE];                            \
    char *_ptr_ = &_buffer_[0];                                     \
    int _size_ = sizeof(_buffer_);


/*
 * end part of BFD error/log message with brevity control
 * this macro closes C block that is opended by macro
 * BFD_ERROR_LOG_BEGIN_W_BREV_CTL
 *
 * it is only for BFD_LOG, BFD_*_ERROR macros 
 */
#define BFD_ERROR_LOG_END_W_BREV_CTL                               \
    }

/*
 * end part of BFD error/log message without brevity control
 *
 * it is only for BFD_LOG, BFD_*_ERROR macros
 */
#define BFD_ERROR_LOG_END_WO_BREV_CTL


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
#define BFD_LOG(...)                                                \
{                                                                   \
    BFD_ERROR_LOG_BEGIN_WO_BREV_CTL                                 \
                                                                    \
    BFD_PRINTF (_ptr_, _size_, __VA_ARGS__);                        \
                                                                    \
    LOG_FORCE (BFD_LOG_CLASS, _buffer_);                            \
                                                                    \
    BFD_ERROR_LOG_END_WO_BREV_CTL                                   \
}


/*
 * LCP BFD error without BFD session/history/statistic log;
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
#define BFD_INTERNAL_ERROR(...)                                     \
{                                                                   \
    BFD_ERROR_LOG_BEGIN_W_BREV_CTL                                  \
                                                                    \
    BFD_PRINTF (_ptr_, _size_, "BFD ERROR (PROTOCOL): ");           \
    BFD_PRINTF (_ptr_, _size_, __VA_ARGS__);                        \
                                                                    \
    LOG_FORCE (BFD_LOG_CLASS, _buffer_);                            \
                                                                    \
    BFD_ERROR_LOG_END_W_BREV_CTL                                    \
}

/* 
 * LCP BFD error with BFD session/history/statistic log;
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
#define BFD_AUDIT_ERROR(sess_idx, ...)                              \
{                                                                   \
    BFD_ERROR_LOG_BEGIN_W_BREV_CTL                                  \
                                                                    \
    BFD_PRINTF (_ptr_, _size_, "BFD ERROR (AUDIT): index %u, ",     \
        sess_idx);                                                  \
    BFD_PRINTF (_ptr_, _size_, __VA_ARGS__);                        \
                                                                    \
    LOG_FORCE (BFD_LOG_CLASS, _buffer_);                            \
                                                                    \
    BFD_sess_data_log (sess_idx);                                   \
    BFD_history_log (sess_idx);                                     \
    BFD_stats_log_sess (sess_idx);                                  \
                                                                    \
    BFD_ERROR_LOG_END_W_BREV_CTL                                    \
}  

/*
 * LCP BFD error with BFD session/histtory/statistic log;
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
#define BFD_SESS_ERROR(sess_idx, ...)                               \
{                                                                   \
    BFD_ERROR_LOG_BEGIN_W_BREV_CTL                                  \
                                                                    \
    BFD_PRINTF (_ptr_, _size_, "BFD ERROR (SESSION): index %u, ",   \
        sess_idx);                                                  \
    BFD_PRINTF (_ptr_, _size_, __VA_ARGS__);                        \
                                                                    \
    LOG_FORCE (BFD_LOG_CLASS, _buffer_);                            \
                                                                    \
    BFD_sess_data_log (sess_idx);                                   \
    BFD_history_log (sess_idx);                                     \
    BFD_stats_log_sess (sess_idx);                                  \
                                                                    \
    BFD_ERROR_LOG_END_W_BREV_CTL                                    \
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
#define BFD_LOCAL_ERROR(...)                                        \
{                                                                   \
    BFD_ERROR_LOG_BEGIN_W_BREV_CTL                                  \
                                                                    \
    BFD_PRINTF (_ptr_, _size_, "BFD ERROR (LCP): ");                \
    BFD_PRINTF (_ptr_, _size_, __VA_ARGS__);                        \
                                                                    \
    LOG_FORCE (BFD_LOG_CLASS, _buffer_);                            \
                                                                    \
    BFD_ERROR_LOG_END_W_BREV_CTL                                    \
}

/*
 * First-hop router error;
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
#define BFD_REMOTE_ERROR(...)                                       \
{                                                                   \
    BFD_ERROR_LOG_BEGIN_W_BREV_CTL                                  \
                                                                    \
    BFD_PRINTF (_ptr_, _size_, "BFD ERROR (ROUTER): ");             \
    BFD_PRINTF (_ptr_, _size_, __VA_ARGS__);                        \
                                                                    \
    LOG_FORCE (BFD_LOG_CLASS, _buffer_);                            \
                                                                    \
    BFD_msg_log (sess_idx);                                         \
                                                                    \
    BFD_sess_data_log (sess_idx);                                   \
    BFD_history_log (sess_idx);                                     \
    BFD_stats_log_sess (sess_idx);                                  \
                                                                    \
    BFD_ERROR_LOG_END_W_BREV_CTL                                    \
}


#endif /* #ifndef BFD_ERROR_H */
