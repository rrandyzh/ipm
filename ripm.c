/*
 * FILE:	ripm.c
 *
 * DESCRIPTION:	The Remote IP Management (RIPM) module will provide a mechanism
 *		to detect the connectivity status between Host nodes and the
 *		Alcatel-Lucent ATCAv2 Shelf Management Controller (ShMC). 
 *		It maintains the route table by deleting the bad route path
 *		and adding the good route path to guarantee the current route
 *		path in use works well.  In some conditions, ShMC will be
 *		requested to switched over.
 *
 * SYNOPSIS:	ripm [shelves]
 *
 *		RIPM is normally called as a daemon from the ripm Linux startup
 *		script, but the startup script will first call ripm with the
 *		"shelves" option to get the number of shelves in configuration
 *		found to manage.  If 0, the startup script will not start the
 *		ripm daemon (e.g., in pure RMS environment).
 *
 * ENVIRONMENT:	The following environment variables must be set up:
 *
 *		RIPM_IFC_LSN0		- LSN0 interface name
 *		RIPM_IFC_LSN1		- LSN1 interface name
 *		RIPM_IP_LSN0		- LSN0 IP address
 *		RIPM_IP_LSN1		- LSN1 IP address
 *		RIPM_IP_VLSN		- Virtual LSN hw IP address
 *
 * FILES:	The ShMC configuration (equipped shelves and IP addresses) are
 *		discovered by interrogating the following directories:
 *
 *		/opt/config/servers/R-C-S	    - directory for equipped
 *						      rack (R) and chassis (C).
 *		/opt/config/conf/shelfman.conf.R-C  - ATCAv2 ShMC config file
 *
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <net/if.h>
#include <netinet/in.h>
#include <libgen.h>

#include "assert_hdr.h"
#include "nnn_define.h"
#include "nma_route.h"
#include "ripm.h"
#include "ripm_db.h"

// Signal Actions definitions
//
#define SIGNAL_NONE	0
#define SIGNAL_RELOAD	1
#define SIGNAL_TERM	2

// Local Prototypes
static void	catchSigHup( int signal );
static void	catchSigTerm( int signal );
AtcaHost_t*	loadConfiguration( int inetsocket, int netlinksocket );
int		ripm_route_add( int sock, AtcaShelf_t* shelf_p );
int		ripm_route_del( int sock, Interface_t* ifc_p, AtcaShelf_t* shelf_p );
char		switch_ShMC( AtcaShelf_t* shelf_p );
void		ripm_send_alarm( AtcaShelf_t* shelf_p );
void		ripm_clear_alarm( AtcaShelf_t* shelf_p );
char		isActiveHost();
int		ping( char* dest, char* src, int count );
int		execute( char* command );

// External Variables
extern AtcaHost_t	Host;			// from ripm_db.c

// Global Variables
int 		logger_ready	= TRUE;		// for IPM logging
unsigned short	ipm_log_remote = TRUE;
int		sigAction = SIGNAL_NONE;
int		atLeastOneEquipped = FALSE;

unsigned short	ipm_get_log_level(int _error)
{
	return 0;
}

const char*	ResourceFormat	= "Machine=%s%cResource_type=ShMC%cShelf=%d%cSlot=15";
const char*	clusterFileName = "/opt/RCC/var/clusterfile";

/*
 * Function:	main()
 *
 * Description:	Main working function for ripm process. 			
 *
 *		The Internal IP Manager (IIPM) is in charge of the route/VLAN
 *		selection on host for internal communication. But the IIPM
 *		working mechanism is relied on the IIPM running on both sides
 *		of the link.  Since IIPM is not running on the Shelf Management
 *		Controllers (ShMC), the link between the Host nodes and ShMC
 *		floater IP address can not be managered by IIPM, this is why
 *		there is Remote IP Manager (RIPM) process.
 *
 *		RIPM uses "ping" to check if the ShMC floater is accessible
 *		based on current routing, if not, ripm will shift the current
 *		route for ShMC floater from current Ethernet interface
 *		(e.g., eth0) to the other Ethernet interface (e.g. eth1).
 *
 * Arguments:	argc		- argument count
 *		argv		- pointer to argument vector
 *
 * Returns:	does not return
 */

int
main ( int argc, char *argv[] )
{
	int			netlinksocket, inetsocket;
	AtcaShelf_t*		shelf_p;	// shelf configuration
	ShelfData_t*		data_p;		// pointer to shelfFlag[shelfno]
	struct sigaction	sigcntl;
	int			lsn;
	int			ret;		// OS return value.
	char			pidloc[30] = "/var/opt/run";

	// Create signal handler for SIGHUP
	sigemptyset( &sigcntl.sa_mask );
	sigcntl.sa_handler = catchSigHup;
	sigcntl.sa_flags = 0;
	if ( sigaction( SIGHUP, &sigcntl, NULL ) < 0 )
	{
		ASRT_EXIT( ASFAULT, 0,
			"Cannot create signal handler for SIGHUP, errno %d (%s)\n",
			errno, strerror( errno ) );
	}
	
	// Create signal handler for TERM
	sigemptyset( &sigcntl.sa_mask );
	sigcntl.sa_handler = catchSigTerm;
	sigcntl.sa_flags = 0;
	if ( sigaction( SIGTERM, &sigcntl, NULL ) < 0 )
	{
		ASRT_EXIT( ASFAULT, 0,
			"Cannot create signal handler for SIGTERM, errno %d (%s)\n",
			errno, strerror( errno ) );
	}
	
	// Set to run as daemon under monit
	ret = daemon(0, 0);
	if(ret != 0)
	{
		ASRT_RPT_SEV(ASOSFNFAIL, ASRT_CRITICAL, 0,
			"Failed to start as a daemon. Errno=%d [%s].\nIf this process dies and this host later reboots it may require\nmanual action to restart.\n",
			errno, strerror(errno));
	}
	else if ( access(pidloc, F_OK|R_OK|W_OK) == 0 )
	{
		char pidfile[100];
		FILE *fp;

		sprintf(pidfile, "%s/%s.pid", pidloc, basename(argv[0]));

		fp = fopen(pidfile, "w");
		if(fp == NULL)
		{
			ASRT_RPT_SEV(ASOSFNFAIL, ASRT_CRITICAL, 0,
				"Failed fopen for '%s'. Errno=%d [%s].\nIf this process dies and this host later reboots it may require\nmanual action to restart.\n",
				pidfile, errno, strerror(errno));
                }
		else
		{
                	fprintf(fp, "%d", getpid());
                	ret = fclose(fp);
                	if(ret < 0)
                	{
                        	ASRT_RPT(ASUNEXP_RETURN, 0,
					"fclose() failed with errno=%d [%s]",
					errno, strerror(errno));
                	}
		}
	}
	else
	{
		ASRT_RPT_SEV(ASOSFNFAIL, ASRT_CRITICAL, 0,
			"Failed access for directory %s. Errno=%d [%s].\nIf this process dies and this host later reboots it may require\nmanual action to restart.\n",
			pidloc, errno, strerror(errno)
		);
	}

	// Create NETLINK socket.
	if ( (netlinksocket = socket( AF_NETLINK, SOCK_RAW, 0 )) < 0 )
	{
		ASRT_EXIT( ASFAULT, 0,
			   "Cannot create NETLINK socket, errno %d (%s)\n",
			   errno, strerror(errno) );
	}

	// Create INET socket.
	if ( (inetsocket = socket( PF_INET, SOCK_DGRAM,0 )) < 0 )
	{
		ASRT_EXIT( ASFAULT, 0,
			"Can not continue, inetsocket returned %d, errno %d(%s)\n",
			inetsocket, errno, strerror( errno ) );
	}

	
	// validate argument if given
	if ( argc > 1 )
	{
		int	nShelves = 0;
		
		// validate command line usage 
		if ( argc != 2 || strcmp( argv[1], "shelves" ) != 0 )
		{
			LOG_FORCE( "Invalid ripm command usage\n"
				   "USAGE: ripm [shelves]\n" );
		}
		
		// Call GetHostConfiguration to get the number of shelves
		if ( GetHostConfiguration( inetsocket, &nShelves ) == NULL )
		{
			ASRT_EXIT( ASBAD_DATA, 0, "Cannot get Host configuration!\n" );
		}

		// exit with the number of shelves discovered
		exit( nShelves );
	}

	// Get the Host and ShMC configuration
	if ( loadConfiguration( inetsocket, netlinksocket ) == NULL )
	{
		ASRT_EXIT( ASBAD_DATA, 0, "Cannot get Host configuration!\n" );
	}
	
	/*
	 *  Working loop to ping ShMC floater to make sure at least one ShMC
	 *  is accessible.  If cannot access floater, may starting pinging
	 *  specific ShMC cards on specific LSNs to determine if we can reach
	 *  one ShMC on a specific LSN and request a ShMC switchover if 
	 *  necessary.
	 */
	while ( sigAction != SIGNAL_TERM )
	{
		// TODO: Handle/detect chassis growth here

		for ( shelf_p = GetShelf( NULL );
		      shelf_p != NULL;
		      shelf_p = GetShelf( shelf_p ) )
		{
			// get pointer to user area
			data_p  = (ShelfData_t *) &shelf_p->userArea[0];

			// if shelf is not equipped, skip it
			if ( !shelf_p->equipped ) continue;
			atLeastOneEquipped = TRUE;
			
			// ----------------------------------------------------
			//  Ping ShMC Floater...
			//
			//  Using default route initially set up
			// ----------------------------------------------------
			if ( ping( shelf_p->ipShMCfloater, Host.ipVLSN, 3 ) == 0 )
			{
				/*
				 *  The current route works fine,
				 *  clear ALARM if there was one generated
				 */
				if ( data_p->alarmGenerated )
				{
					// send alarm clear
					ripm_clear_alarm( shelf_p );

					// log message
					LOG_OTHER( "%s ShMC Floater access recovered on interface %s\n",
						   shelf_p->name,
						   Host.ifcLSN[ data_p->ifcInUse ].name );

					// clear alarm generated flag
					data_p->alarmGenerated = FALSE;
				}

				// wait 3 seconds, and try next loop.
				sleep( 3 );
				continue;
			}

			/*
			 *  ShMC ACCESS FAILURE - using default route
			 */
                       	LOG_OTHER( "Access %s ShMC floater failure on interface %s\n",
				   shelf_p->name,
				   Host.ifcLSN[ data_p->ifcInUse ].name );

			// generate alarm here if not generated yet
			if ( !data_p->alarmGenerated )
			{
				// send alarm
				ripm_send_alarm( shelf_p );

				// set alarm generated flag
				data_p->alarmGenerated = TRUE;
			}

			/*
			 *  If route path has not been added, attempt to
			 *  add route prior to next ping attempt
			 */
			if ( !data_p->pathAdded )
			{
				// try other interrface
				data_p->ifcInUse = 1 - data_p->ifcInUse;

                               	LOG_OTHER( "Trying add route on interface %s for %s.\n", 
					   Host.ifcLSN[ data_p->ifcInUse ].name,
					   shelf_p->name );

				// update the route table
				if ( ripm_route_add( netlinksocket, shelf_p ) == 0 )
				{
					// flush route table
					ipm_route_flush();

					// go to next loop to try ping again
					data_p->pathAdded = TRUE;
					continue;
				}
			}

			/*
			 *  There is bad route added, or adding route failure
			 *  above.  Delete all possible existing host-host
			 *  routes for ShMC floater. If there is a routing on
			 *  current ifinuse interface, this route must be
			 *  wrong, so try to delete it at first.
			 */
			if ( ripm_route_del( netlinksocket,
					     &Host.ifcLSN[ data_p->ifcInUse ],
					     shelf_p ) == 0 )
			{

				// delete success, current route is bad.
				data_p->pathAdded = FALSE;
			}
			else
			{
				// try to delete the route on the other LSN 
				data_p->ifcInUse = 1 - data_p->ifcInUse;

				// delete the current route.
				if ( ripm_route_del( netlinksocket,
						     &Host.ifcLSN[ data_p->ifcInUse ],
						     shelf_p ) == 0 )
				{
					// delete success, current route is bad.
					data_p->pathAdded = FALSE;
				}
			}

			/*
			 *  The route with the ifinuse interface is bad and
			 *  has been deleted above, so add a new route from
			 *  the other ifinuse interface.
			 */
			data_p->ifcInUse = 1 - data_p->ifcInUse;

                       	LOG_OTHER( "trying add route on interface %s for %s.\n", 
				   Host.ifcLSN[ data_p->ifcInUse ].name,
				   shelf_p->name );

			if ( ripm_route_add( netlinksocket, shelf_p ) == 0 )
			{
                               	// flush route table
				ipm_route_flush();

				data_p->pathAdded = TRUE;
			}

			// ----------------------------------------------------
			//  Ping ShMC Floater...
			//
			//  Ping the ShMC on the floater IP again with the
			//  new route just added on the other LSN.
			// ----------------------------------------------------
			if ( ping( shelf_p->ipShMCfloater, Host.ipVLSN, 3 ) == 0 )
			{
				continue;
			}

			/*
			 *  Still cannot ping floater IP with new route, try
			 *  deleting this one again and re-add the other LSN
			 *  route and try again.
			 */
                       	LOG_FORCE( "Access %s ShMC floater failure on interface %s\n",
				   shelf_p->name,
				   Host.ifcLSN[ data_p->ifcInUse ].name );

			// delete existing route
			if ( ripm_route_del( netlinksocket,
					     &Host.ifcLSN[ data_p->ifcInUse ],
					     shelf_p ) == 0 )
			{
				data_p->pathAdded = FALSE;
			}

                       	// add the other path to try that one again
			data_p->ifcInUse = 1 - data_p->ifcInUse;

                        LOG_OTHER( "trying add route on interface %s for %s\n", 
				   Host.ifcLSN[ data_p->ifcInUse ].name,
				   shelf_p->name );

			// add new route on other LSN
			if ( ripm_route_add( netlinksocket, shelf_p ) == 0 )
                       	{
				// flush route table
				ipm_route_flush();

				data_p->pathAdded = TRUE;
			}

			// ----------------------------------------------------
			//  Ping ShMC Floater...
			//
			//  Ping the ShMC on the floater IP again with the
			//  new route just added on the other LSN.
			// ----------------------------------------------------
			if ( ping( shelf_p->ipShMCfloater, Host.ipVLSN, 3 ) == 0 )
                       	{
                               	continue;
                       	}

			/*
			 *  ShMC ACCESS FAILURE - Using routes from either LSN0
			 *  or LSN1.
			 */
                        LOG_FORCE( "Access %s ShMC floater failure using either interface\n",
				   shelf_p->name );

			// ----------------------------------------------------
			//  Ping ShMC (Top) via LSN0...
			//
			//  Ping the Top ShMC card via LSN0 to see if we can
			//  contact it.  If we can, then make sure that the
			//  Top ShMC is active.
			// ----------------------------------------------------
			if ( ping( shelf_p->ipShMCtopLSN0, Host.ipLSN[0], 1 ) == 0 )
			{
				/*
				 *  ShMC card can be reached via LSN0,
				 *  so try to  make the top ShMC active.
				 */
				// add the route on LSN0
				data_p->ifcInUse = 0;

				// switch ShMC to this LSN
				(void) switch_ShMC( shelf_p );

				(void) ripm_route_del( netlinksocket, NULL, shelf_p );
				(void) ripm_route_add( netlinksocket, shelf_p );
				continue;
			}

			// ----------------------------------------------------
			//  Ping ShMC (Bottom) via LSN1...
			//
			//  Ping the Bottom ShMC card via LSN1 to see if we
			//  can contact it.  If we can, then make sure that
			//  the Bottom ShMC is active.
			// ----------------------------------------------------
			if ( ping( shelf_p->ipShMCbtmLSN1, Host.ipLSN[1], 1 ) == 0 )
                       	{
				/*
				 *  ShMC card can be reached via LSN1,
				 *  so try to  make the bottom ShMC active.
				 */
				// add the route on LSN1
				data_p->ifcInUse = 1;

				// switch ShMC to this LSN
				(void) switch_ShMC( shelf_p );

				(void) ripm_route_del( netlinksocket, NULL, shelf_p );
				(void) ripm_route_add( netlinksocket, shelf_p );
                               	continue;
                       	}

			/*
			 *  Either this host has been isolated or both ShMC
			 *  down.  Not much we can do here.
			 */
			LOG_FORCE( "Could not access %s ShMC from floater, LSN0, LSN1\n",
				   shelf_p->name );

			// wait 1 second, and try next loop.
			sleep( 1 );

		} // end of for loop per shelf
		
		// wait 1 second before going through all shelfs again unless
		// one was equiped.
		if ( atLeastOneEquipped == FALSE ) sleep( 1 );
		
		if (sigAction == SIGNAL_RELOAD)
		{
			// Reload the Host and ShMC configuration
			if ( loadConfiguration( inetsocket, netlinksocket ) == NULL )
			{
				ASRT_EXIT( ASBAD_DATA, 0, "Cannot get Host configuration!\n" );
			}
			sigAction = SIGNAL_NONE;
		}
		
	} // end of the infinite while loop

	exit( 0 );
}

/*
 * Function:	catchSigHup()
 *
 * Description:	Signal handler for the SIGHUP signal
 *
 * Arguments:	signum	signal number
 *
 * Returns:	void
 */
static void
catchSigHup( int signal )
{
	sigAction = SIGNAL_RELOAD;
}	

/*
 * Function:	catchSigTerm()
 *
 * Description:	Signal handler for the SIGTERM signal
 *
 * Arguments:	signum	signal number
 *
 * Returns:	void
 */
static void
catchSigTerm( int signal )
{
	sigAction = SIGNAL_TERM;
}	

/*
 * Function:	loadConfiguration()
 *
 * Description:	Gets the host and ShMC configuration data and makes some integrity
 *		checks on the data as well as doing some initialization of the routes.
 *
 * Arguments:	inetsocket, netlinksocket - sockets for communication
 *
 * Returns:	pointer to pilot configuration data or NULL if error
 */

AtcaHost_t*
loadConfiguration( int inetsocket, int netlinksocket )
{
	AtcaHost_t*	HostPtr;
	AtcaShelf_t*	shelf_p;
	ShelfData_t*	data_p;
	IPM_IPADDR	network;
	int		nShelves = 0;
	
	HostPtr = GetHostConfiguration( inetsocket, &nShelves );
	if (HostPtr == NULL )
	{
		return (NULL);
	}
	
	// we are in daemon mode, verify we have shelves to manage
	if ( nShelves == 0 )
	{
		ASRT_EXIT( ASBAD_DATA, 0, "Cannot get Shelf configuration!\n" );
	}

	// verification of integrity of structures
	if ( sizeof(ShelfData_t) > RIPM_USERAREA_SZ )
	{
		ASRT_EXIT( ASBAD_DATA, 0,
			   "AtcaShelf_t userArea too small, need %ul bytes!\n",
			   sizeof(ShelfData_t) );
	}

	LOG_OTHER( "Starting Management of %d ATCA Shelves", nShelves );

	/*
	 *  Before we go into the main working loop, we will check if there 
	 *  exists a default route path for each shelf. If there is not, we
	 *  need to add one for that shelf from Host LSN0.  We will clear all
	 *  alarms in case there is an alarm not cleared the last time the
	 *  process stopped.  New alarm will be sent by this process if the
	 *  IP problem remains.
	 *
	 *  NOTE: Since shelf userArea is zeroed upon creation, ifcInUse=0
	 *	  and pathAdded=FALSE initially.
	 */
	for ( shelf_p = GetShelf( NULL );
	      shelf_p != NULL;
	      shelf_p = GetShelf( shelf_p ) )
	{
		// get pointer to user area
		data_p  = (ShelfData_t *) &shelf_p->userArea[0];

		// if shelf is not equipped, skip it
		if ( !shelf_p->equipped ) continue;

		IPM_ipaddr_init( &network );
		network.addrtype = IPM_IPV4;
		memcpy( network.ipaddr, &shelf_p->ipAddrFloater.s_addr,
			sizeof(struct in_addr) );

		// try to add route to shelf ShMC from LSN0
		if ( nma_route_chk( netlinksocket,
				    Host.ifcLSN[0].index,
				    Host.ifcLSN[0].name,
				    &network, 32, NULL, NULL ) == 1 )
		{
			// route exists from LSN0 on this shelf
			LOG_OTHER( "default route exists on interface %s for %s\n",
				   Host.ifcLSN[0].name, shelf_p->name );

			// record it
			data_p->ifcInUse  = 0;
			data_p->pathAdded = TRUE;
		}
		else if ( nma_route_chk( netlinksocket,
					 Host.ifcLSN[1].index,
					 Host.ifcLSN[1].name,
					 &network, 32, NULL, NULL ) == 1 )
		{
			// route exists from LSN1 on this shelf
			LOG_OTHER( "default route exists on interface %s for %s\n",
				   Host.ifcLSN[1].name, shelf_p->name );

			// record it
			data_p->ifcInUse  = 1;
			data_p->pathAdded = TRUE;
		}
		else
		{
			// attempt to add default route on LSN0
			if ( ripm_route_add( netlinksocket, shelf_p ) == 0 )
			{
				// flush route table
				ipm_route_flush();

				// update interface route flags
				data_p->ifcInUse = 0;
				data_p->pathAdded = TRUE;
			}
		}

		// clear alarms for this shelf
		ripm_clear_alarm( shelf_p );
	}
	
	return (HostPtr);
}

/*
 * Function:	ripm_route_add()
 *
 * Description:	Add the route to certain interface, if the ShMC is accessible
 *		on that interface.
 *
 *		Note that this function will print all necessary log messages
 *		to detail the route add progress.
 *
 * Arguments:	sock		- socket for communication
 *		shelf_p		- shelf configuration structure pointer
 *
 * Returns:	0 - success
 *		1 - does not need to add route
 *		others - error
 */

int
ripm_route_add ( int sock, AtcaShelf_t* shelf_p )
{
	IPM_IPADDR	network;

	// get the LSN currently in use on this shelf
	int	     lsn   = ((ShelfData_t *) &shelf_p->userArea[0])->ifcInUse;
	Interface_t* ifc_p = &Host.ifcLSN[ lsn ];

	if ( ping( (lsn == 0 ? shelf_p->ipShMCtopLSN0 :
			       shelf_p->ipShMCbtmLSN1),
		   Host.ipLSN[ lsn ], 1 ) != 0 )
        {
                LOG_ERROR( "Add Route: %s ShMC is not accessible on LSN%d, "
			   "cancel switching route to LSN%d",
			   shelf_p->name, lsn, lsn );
		return 1;
	}

	LOG_OTHER( "Add Route: %s ShMC is accessible on LSN%d, "
		   "switching the route to LSN%d", shelf_p->name, lsn, lsn );

	IPM_ipaddr_init( &network );
	network.addrtype = IPM_IPV4;
	memcpy( network.ipaddr, &shelf_p->ipAddrFloater.s_addr,
		sizeof(struct in_addr) );

	// does route already exist on interface?
	if ( nma_route_chk( sock, ifc_p->index, ifc_p->name,
			    &network, 32, NULL, NULL ) == 1 )
	{
		LOG_OTHER( "Add Route: Route to %s ShMC already exists on LSN%d",
			   shelf_p->name, lsn );
		return 0;
	}

	// attempt to add route on this LSN
	int rc = nma_route_add( sock, ifc_p->index, ifc_p->name, 0,
				&network, 32, NULL, NULL );

	if ( rc == 0 )
	{
		LOG_OTHER( "Add Route: Route added on interface %s for %s ShMC\n",
			   Host.ifcLSN[ lsn ].name, shelf_p->name );
	}
	else
	{
		// cannot add default route on current shelf
		ASRT_RPT( ASFAULT, 0, "Add Route: FAILED to add route on "
			  "interface %s for %s ShMC, code %d.\n",
			  Host.ifcLSN[ lsn ].name, shelf_p->name, rc );
	}

        return rc;
}


/*
 * Function:	ripm_route_del()
 *
 * Description:	If ther is a route on a certain interface, delete it.
 *
 * Arguments:	sock		- socket
 *		ifc_p		- interface data pointer
 *		shelf_p		- shelf configuration structure pointer
 *
 * Returns:	0 - success
 *		others - error
 */

int
ripm_route_del ( int sock, Interface_t* ifc_p, AtcaShelf_t* shelf_p )
{
	IPM_IPADDR network;

	// set up the interface index and name
	int	ifindex = (ifc_p == NULL ? NOPARAMETER : ifc_p->index);
	char*	ifname  = (ifc_p == NULL ? NULL	       : ifc_p->name );

	IPM_ipaddr_init( &network );
	network.addrtype = IPM_IPV4;
	memcpy( network.ipaddr, &shelf_p->ipAddrFloater.s_addr,
		sizeof(struct in_addr) );

	// does a route currently exist?
        if ( nma_route_chk( sock, ifindex, ifname, &network, 32, NULL, NULL) != 1 )
        {
		// no need to delete route, return 0
                LOG_OTHER( "Delete Route: No route exists to %s ShMC",
			   shelf_p->name );
		return 0;
	}

	int rc = nma_route_del( sock, ifindex, ifname, &network, 32, NULL );

	// route exists, attempt to delete it
	LOG_OTHER( "Delete Route: On interface %s to %s ShMC, code %d.\n",
		   (ifname == NULL ? "<nil>" : ifname), shelf_p->name, rc );

        return rc;
}

/*
 * Function:	switch_ShMC()
 *
 * Description:	Request ShMC switchover.
 *
 * Arguments:	shelf_p		- shelf configuration structure pointer
 *
 * Returns:	TRUE if the ShMC's got switched
 *		FALSE if the ShMC's didn't switchover
 */

char
switch_ShMC ( AtcaShelf_t* shelf_p )
{
	char	command[ 128 ];
	int	rc;

	// get user area section of shelf structure
	ShelfData_t* data_p = (ShelfData_t *) &shelf_p->userArea[0];

	// do not switchover ShMC if not on Active Host
	if ( !isActiveHost() )
	{
		LOG_OTHER( "Switch ShMC: %s: INHIBITED - Not Active Host",
			   shelf_p->name );
		return FALSE;
	}

	// Check if switch over is administratively prohibited
	if ( shelf_p->inhibit_switchover == TRUE )
	{
		LOG_OTHER( "Switch ShMC: %s: INHIBITED - administrative request",
			   shelf_p->name );
		return FALSE;
	}
	
	// get proposed current time of switchover
	time_t	curTime = time( (time_t*)0 );

	// is it too soon to attempt another ShMC switchover?
	if ( curTime < data_p->lastSwitchTime + ShMC_SWITCH_DELAY )
	{
		LOG_OTHER( "Switch ShMC: %s: CANCELLED - Too soon after last switch",
			   shelf_p->name );
		return FALSE;
	}

	/*
	 *  Execute script to request ShMC switchover to desired ShMC.
	 */
	const char*	target = (data_p->ifcInUse == 0 ? "Top" : "Bottom");

	sprintf( command, "/opt/LSS/sbin/shmc_activate %s",
		 (data_p->ifcInUse == 0 ? shelf_p->ipShMCtopLSN0 :
					  shelf_p->ipShMCbtmLSN1) );

	LOG_DEBUG( "Switch ShMC: %s: Execute [%s]", shelf_p->name, command );

	switch ( (rc = execute( command )) ) {
	case 0:			// ShMC is Already Active
		LOG_ERROR( "Switch ShMC: %s %s ShMC already Active\n",
			   target, shelf_p->name );
		return FALSE;

	case 1:			// ShMC Switchover Completed
		break;

	default:		// ShMC Switchover Failed
		// command execution or switch over failed
		LOG_FORCE( "Switch ShMC: FAILED to switch to %s %s ShMC.\n"
			"Command [%s] returned %d",
			   target, shelf_p->name, command, rc );
		return FALSE;
	}

	/*
	 *  Switch ShMC Successful!
	 */
	LOG_OTHER( "Switch ShMC: Successfully switched to %s %s ShMC\n",
		   target, shelf_p->name );

	// switchover completed - update last switchover time
	data_p->lastSwitchTime = curTime;

	// sleep 3 seconds to wait for switchover to complete
	sleep( 3 );
	return TRUE;
}

/*
 * Function:	ripm_send_alarm()
 *
 * Description:	Send alarm to FTOAM for this shelf
 *
 * Arguments:	shelf_p		- shelf configuration structure pointer
 *
 * Returns:	none
 */

void
ripm_send_alarm ( AtcaShelf_t* shelf_p )
{
	char	alt_resource[ 256 ];
	char	user_text[ 128 ];

	// generate alternate resource.
	sprintf( alt_resource, ResourceFormat,
		 Host.hostname,
		 FSALARM_RESOURCE_FIELD_DELIMITER,
		 FSALARM_RESOURCE_FIELD_DELIMITER,
		 ((shelf_p->rack * 2) + shelf_p->chassis),
		 FSALARM_RESOURCE_FIELD_DELIMITER );

	// set user buffer
	sprintf( user_text, "ShMC floating IP unreachable via LSN%d", 
			    ((ShelfData_t *) &shelf_p->userArea[0])->ifcInUse );

	/*
	 * Class:               Ethernet
	 * Severity:            Major (Active Host) / Minor (Standby Host)
	 * Cause/Type:          Ethernet error
	 * Resource type:       link
	 * Resource:            Set above.
	 * Far-end Resource:    Usused (NULL)
	 * User-String:         Set above.
	 * Description Type:    Unused (as specified in API)
	 * Recovery Type:       Unused (as specified in API)
	 */
	SEND_ALARM( FSAC_ethernet,
		    (isActiveHost() ? FSAS_major : FSAS_minor),
		    FSAP_ethernetError,
		    FSAR_Link,
		    alt_resource,
		    NULL,
		    user_text,
		    FSADK_UNUSED,
		    FSARK_UNUSED );
}


/*
 * Function:	ripm_clear_alarm()
 *
 * Description:	Send clear alarm to FTOAM for this shelf
 *
 * Arguments:	shelf_p		- shelf configuration structure pointer
 *
 * Returns:	none
 */

void
ripm_clear_alarm ( AtcaShelf_t* shelf_p )
{
	char	alt_resource[ 256 ];
	char	user_text[ 128 ];

	// generate alternate resource.
	sprintf( alt_resource, ResourceFormat,
		 Host.hostname,
		 FSALARM_RESOURCE_FIELD_DELIMITER,
		 FSALARM_RESOURCE_FIELD_DELIMITER,
		 ((shelf_p->rack * 2) + shelf_p->chassis),
		 FSALARM_RESOURCE_FIELD_DELIMITER );

	// set user buffer
	sprintf( user_text, "ShMC floating IP is reachable via LSN%d", 
			    ((ShelfData_t *) &shelf_p->userArea[0])->ifcInUse );

	/*
	 * Class:               Ethernet
	 * Severity:            Cleared
	 * Cause/Type:          Ethernet error
	 * Resource type:       link
	 * Resource:            Set above.
	 * Far-end Resource:    Usused (NULL)
	 * User-String:         Set above.
	 * Description Type:    Unused (as specified in API)
	 * Recovery Type:       Unused (as specified in API)
         */        
	SEND_ALARM( FSAC_ethernet,
		    FSAS_cleared,
		    FSAP_ethernetError,
		    FSAR_Link,
		    alt_resource,
		    NULL,
		    user_text,
		    FSADK_UNUSED,
		    FSARK_UNUSED );
}

/*
 * Function:	isActiveHost()
 *
 * Description:	Is this host the active host?  Active host
 *		is defined as the blade where MI service
 *		is active.
 *
 * Arguments:	none
 *
 * Returns:	TRUE if this host is active host, FALSE if not
 */

char
isActiveHost ()
{
	int	rc;
	char	hostname[40];
	char	command[100];
	
	rc = gethostname(hostname, 40);
	if (rc != 0)
	{
		LOG_OTHER( "The status of MI VM can not be determined, "
			"unable to obtain host name (rc = %d).  "
			"ShMC switchover is inhibited.",
			rc );
		return FALSE;
	}
	sprintf( command, "grep MIVM %s | grep %s | grep STATE=A > /dev/null 2>&1\n",
		clusterFileName, hostname );
	rc = execute( command );
	switch( rc )
	{
	case 0:
		// This host is active
		break;
	case 1:
		// This host is not active
		return FALSE;
	default:
		LOG_OTHER( "The status of MI VM can not be determined, "
			"command %s failed.  ShMC switchover is inhibited.",
			command );
		return FALSE;
	}
	
	return TRUE;
}


/*
 * Function:	ping()
 *
 * Description:	Execute ping command and return ping exit status.
 *
 * Arguments:	dest		- destination IP address
 *		src		- source IP address
 *		count		- packet count
 *
 * Returns:	exit status of ping command
 */

int
ping ( char* dest, char* src, int count )
{
	char	pingCmd[ 128 ];

	sprintf( pingCmd, "/bin/ping -c %d -W 1 -I %s %s", count, src, dest );

	return execute( pingCmd );
}


/*
 * Function:	execute()
 *
 * Description:	Execute command and return exit status
 *
 * Arguments:	command		- command to run
 *
 * Returns:	exit status
 */

int
execute ( char* command )
{
	// execute the command and get return status
	int status = system( command );

	// if command exited normally, return exit status otherwise failure
	return( WIFEXITED( status ) ? WEXITSTATUS( status ) : -1 );
}

