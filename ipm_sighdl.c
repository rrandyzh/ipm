/* Name:	IPM_signhdl.c
**
** Description: This file contain the signal handler used by IPM which overwrite default
**				handler. It includes signal handler process and setup API called by nma_main
**
**  NOTE:	
**		1. it is mostly ported from OSinterface.c
**		2. Now this handler is not supported in VCP/host env, will support it later
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/times.h>
#include <limits.h>
#include <ucontext.h>
#include <setjmp.h>
#include <stdint.h>

#include "nma_log.h"
/*
** This function is used to override the default signal handlers that are
** provided by Linux.  The following signal handler will be called for signals
** that normally generate a core dump, but because the code maybe running on
** netboot cards, any core files that are generated are lost. 
** So it will send function backtrace information to the
** master.log file that helps localize the source of the exception.
** The following is the signal handled by this handler.
** 1. SIGSEGV
** 2. SIGILL
** 3. SIGABRT
** 4. SIGFPE
** 5. SIGBUS
** 6. SIGPIPE
*/

static void
IPM_signal_handler(int sig_no, siginfo_t *sip, void *uap_arg)
{
#ifndef _VHE
	ucontext_t		*uap = NULL;		/* Context pointer. */

	/* Current stack pointer (read only!). */
	BSPFRAMEINFO	fi;
	BSP_DECLARE_SP(stackp);
	BSP_DECLARE_SP(framep);	

	/* The stack pointer used for dumping.
	** First choice is from the signal context data.
	** Second is the current register value (stackp).
	** Third is from the jump stack if available (here it is not supported).
	*/
	uintptr_t		*dumpstk = NULL;	/* Used for raw stack dump. */

	/* Buff to hold stack information */
	char			log_msg_buff[UMAX_LOG_SIZE];    /* Log buffer. */
	char *		log_msg = &(log_msg_buff[0]);  /* Leave room for the log header. */

	/* Msg characters in Buffer */
	uint16_t		msg_ct;            /* Number of characters in the log  buffer */
	uint16_t		omsg_ct;           /* Number of characters in the log buffer header */

	uint16_t		event = 0;         /* Unique number identifying the  exception */
	uint16_t		i;                 /* Loop counter */
	uint16_t		j;                 /* Loop counter */

	BOOL			sig_stack;         /* Flag indicating whether the stack
	      			                   ** is from the signal handler or the
   		   			                   ** thread causing this exception */
	FSLOG_MSGCLASS_T	msg_class;	   /* Output message class. */


	/* Instantiate locals */
	sig_stack = FALSE;

	/* Most reports will be for exceptions. */
	msg_class = LOG_EXCEPTION;


	/* Get a unique event number for the log buffer.  */
	event = ARGET_AREVENT();

	/* Get the stack pointer for dumping data. */
	if(uap_arg != NULL)
	{
		uap = (ucontext_t *) uap_arg;
		BSPbldFrameFromContext(&fi, uap);
	}
	else
	{
		BSPFRAMENULL(fi);
	}

	if(IS_VALID_FRAME(fi) == FALSE)
	{
		BSPbldFrameFromRaw(&fi, stackp, framep, 0, 0);
		if(IS_VALID_FRAME(fi) == FALSE)
		{
			BSPbldFrameFromRaw(&fi, 0, 0, 0, 0);
		}
		else
		{
			sig_stack = TRUE;
		}
	}

	/* Go thru each of the signals and print out the signal type.  Note,
	** actually step of of assigning this signal handler for these signals is
	** done separately when the application process is started.
	*/
	msg_ct = 0;
	msg_ct += sprintf(log_msg+msg_ct, "Task %s ", "IPM");

	switch(sig_no) {
	case SIGSEGV:
	{
		msg_ct += sprintf(log_msg+msg_ct, "Segmentation Violation ");
		break;
	}
	case SIGILL:
	{
		msg_ct += sprintf(log_msg+msg_ct, "Illegal Instruction Exception ");

		if(sip != NULL)
		{
			msg_ct += sprintf(log_msg+msg_ct, "SI code = %d ", sip->si_code);

			switch(sip->si_code) {
			case ILL_ILLOPC:
				msg_ct += sprintf(log_msg+msg_ct, "(Illegal opcode) ");
				break;
			case ILL_ILLOPN:
				msg_ct += sprintf(log_msg+msg_ct, "(Illegal operand) ");
				break;
			case ILL_ILLADR:
				msg_ct += sprintf(log_msg+msg_ct, "(Illegal addressing mode) ");
				break;
			case ILL_ILLTRP:
				msg_ct += sprintf(log_msg+msg_ct, "(Illegal trap) ");
				break;
			case ILL_PRVOPC:
				msg_ct += sprintf(log_msg+msg_ct, "(Privileged opcode) ");
				break;
			case ILL_PRVREG:
				msg_ct += sprintf(log_msg+msg_ct, "(Privileged register) ");
				break;
			case ILL_COPROC:
				msg_ct += sprintf(log_msg+msg_ct, "(Coprocessor error) ");
				break;
			case ILL_BADSTK:
				msg_ct += sprintf(log_msg+msg_ct, "(Internal stack error) ");
				break;
			default:
				msg_ct += sprintf(log_msg+msg_ct, "(Unknown SI Code) ");
				break;
			} /* end switch si_code */
		} /* end check sip validity */
		break;
	}
	case SIGABRT:
		msg_ct += sprintf(log_msg+msg_ct, "Abnormal Termination Exception ");
		break;

	case SIGFPE:
		msg_ct += sprintf(log_msg+msg_ct, "Arithmetic Exception ");
		break;

	case SIGBUS:
		msg_ct += sprintf(log_msg+msg_ct, "Bus Error ");
		break;

	case SIGPIPE:
		msg_ct += sprintf(log_msg+msg_ct, "Pipe Error ");
		break;

	default:
	{
		/* These are actually function calls so cannot be in switch statement as a case.  */
		msg_ct += sprintf(log_msg, "User Specified ");
		break;
	}
	} /* End switch(sig_no). */


	msg_ct += sprintf(log_msg+msg_ct, "(Signal=%d, SIGRTMIN=%d) Event=%d\n", sig_no, SIGRTMIN, event);

	/* Save the index so we don't have to keep generating the above
	** message.
	*/
	omsg_ct = msg_ct;
	if(IS_VALID_FRAME(fi))
	{
		msg_ct += sprintf (log_msg+msg_ct, "Report 1 of 7\n");
	}
	else
	{
		msg_ct += sprintf (log_msg+msg_ct, "Report 1 of 3\n");
	}

	if(IS_VALID_FRAME(fi))
	{
		int		sz;
		int		ct;
		uintptr_t	trace[BSP_TRACE_LIMIT+1];

		msg_ct += sprintf(log_msg+msg_ct, "Function trace (from %s):\n",
				(sig_stack ? "signal stack" : "signal context"));

		sz = sizeof(log_msg) - msg_ct;
		if (BSPsymtab_available)
		{
			/* The log will be formatted with
			** the symbolic trace first followed
			** by the raw trace.   Need to leave
			** room for the raw trace (24 addrs)
			** and its header (24 chars).
			*/
			sz -= BSP_FBT_STRSZ(24) + 24;
		}
		ct = BSPpc_symbol(log_msg+msg_ct, &fi);
		sz -= ct;
		msg_ct += ct;

		trace[0]=fi.pc;
		ct = BSPfbt_symbols(BSPSIGNALSTART, sz, log_msg+msg_ct, &trace[1], &fi);
		if (ct < 0)
		{
			/* A negative count means overflow.  NP
			*/
			ct = -ct;
		}
		msg_ct += ct;

		if (BSPsymtab_available)
		{
			/* Now add in the raw dump
			*/
			msg_ct += sprintf(log_msg+msg_ct, "\nRaw Function trace:\n");
			msg_ct += BSPfbt_convfmt(trace, 24, log_msg+msg_ct);
		}
	}


	/* Send the first[FBT] message of the exception report to the master.log file.  Print
	** it locally, if there were problems sending it the the config server or the request
	** was a context event.  Note, the first message contains the function backtrace
	** right prior to the exception.
	*/
	LOG_EXCEPT(0, log_msg);

	msg_ct = omsg_ct;
	if(IS_VALID_FRAME(fi))
	{
		msg_ct += sprintf (log_msg+msg_ct, "Report 2 of 7\n");
	}
	else
	{
		msg_ct += sprintf (log_msg+msg_ct, "Report 2 of 3\n");
	}
	msg_ct += BSPctx_regs_dump(log_msg+msg_ct, (void *) (uap));
  
	/* Send the second[REGISTER] message of the exception report to the master.log file.  Print
	** it locally, if there were problems sending it the the config server or the request
	** was a context event.  Note, the second message contains the general-purpose and
	** special-purpose register dumps.
	*/
	LOG_EXCEPT(0, log_msg);

	/* Dump the stack. */
	dumpstk = fi.sp;

	for(j = 0; (j < 5) && (dumpstk != NULL); j++)
	{
		msg_ct = omsg_ct;
		msg_ct += sprintf(log_msg+msg_ct, "Report %d of 7\n", j+3);
		msg_ct += sprintf(log_msg+msg_ct, "Stack dump (from %s):\n",
				(sig_stack ? "signal stack" : "signal context"));

		msg_ct += BSPstk_dump(log_msg+msg_ct, 512, &dumpstk);

		LOG_EXCEPT(0, log_msg);
	}

	if(j == 0)
	{
		msg_ct = omsg_ct;
		msg_ct += sprintf(log_msg+msg_ct, "Report 3 of 3\n");
		msg_ct += sprintf(log_msg+msg_ct, "Stack dump is not available\n");
		LOG_EXCEPT(0, log_msg);
	}
	exit(255);
#endif
}

/*
** This function is invoked to redefine the default Linux Signal Handler for
** fault related signals, so application specific information can be dumped
** when the signal occurs.
*/
void IPM_setup_signal_handler(void)
{
#ifndef _VHE
	struct sigaction act;  /* new handler for signal */

	/* Setup Fault Signal Handler */
	(void)memset(&act, 0, sizeof(act));

	/* Set-up the new signal handler.  */
	act.sa_sigaction = IPM_signal_handler;
	act.sa_flags = SA_SIGINFO;

	/* Override the default signal handler for the following signals.  Note,
	** these signals normally result in a core dump of the running process.
	*/
	sigaction(SIGSEGV, &act, NULL);
	sigaction(SIGBUS, &act, NULL);
	sigaction(SIGFPE, &act, NULL);
	sigaction(SIGILL, &act, NULL);
	sigaction(SIGABRT, &act, NULL);
	sigaction(SIGPIPE, &act, NULL);
#endif
	return;
}
