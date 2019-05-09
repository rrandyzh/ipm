/*************************************************************************
 *
 * File:     BFD_int_hdr.h
 *
 * Abstract: internal header file of BFD implemenation
 *
 * Nodes:    BFD implementation files should include only this file
 *
 ************************************************************************/

#ifndef BFD_INT_HDR_H
#define BFD_INT_HDR_H


/* standard header files for all platforms */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef BFD_STAND_ALONE
/* standard header files for stand-alone or simulators */
#include "BFD_stand_alone.h"

/* standard header files for GCC (stand-alone/simulators) */
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#define __USE_GNU
#include <netinet/in.h>
#include <sys/select.h>
#include <arpa/inet.h>      

#else /* #ifdef BFD_STAND_ALONE */

/* standard header files for official LCP */
#include "EIPM_include.h"

#endif /* #ifdef BFD_STAND_ALONE */


/* BFD API/external header file */
#include "BFD_api.h"

/* BFD internal header files */

#include "BFD_error.h"
#include "BFD_cfg.h"
#include "BFD_msg.h"

#include "BFD_sess_data.h"
#include "BFD_history.h"
#include "BFD_enum_to_str.h"

#include "BFD_timer.h"
#include "BFD_trans.h"

#include "BFD_fsm.h"
#include "BFD_sess.h"

#include "BFD_stats.h"


/* seed to calculation checksum */
#define BFD_CHECKSUM_SEED       0x5a5a5a5a5a5a5a5aULL


/* pointer to all BFD data in shared memory */
extern BFD_DATA *bfd_data;

/* current time */
extern unsigned int bfd_cur_time;


#endif /* #ifndef BFD_INT_HDR_H */
