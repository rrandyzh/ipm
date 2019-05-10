/*
 * FILE:	ripm_db.c
 *
 * DESCRIPTION:	Remote IP Management (RIPM) database configuration interface.
 *
 * CONTENTS:	GetHostConfiguration()
 *		AllocateShelf()
 *		GetShelf()
 */

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <net/if.h>
#include <netinet/in.h>
#include <assert_hdr.h>
#include "ripm.h"
#include <ripm_db.h>
#include <arpa/inet.h>

// Local Prototypes
static int	AllocateShelf( FILE* ripmConfFile, char* ripmConf, char* valueOfRack );

// Local Data
#define RIPM_KEYWORDS	5
#define RIPM_IFC_LSN0	0
#define RIPM_IFC_LSN1	1
#define RIPM_IP_LSN0	2
#define RIPM_IP_LSN1	3
#define RIPM_IP_VLSN	4

#define RELEASE_HOST_MEM(_host) \
	if (_host.ifcLSN[0].name != NULL) free(_host.ifcLSN[0].name); \
	if (_host.ifcLSN[1].name != NULL) free(_host.ifcLSN[1].name); \
	if (_host.ipLSN[0] != NULL) free(_host.ipLSN[0]); \
	if (_host.ipLSN[1] != NULL) free(_host.ipLSN[1]); \
	if (_host.ipVLSN != NULL) free((void*)_host.ipVLSN);
	
const char*	keywordNames[RIPM_KEYWORDS] =
	{
		"RIPM_IFC_LSN0",
		"RIPM_IFC_LSN1",
		"RIPM_IP_LSN0",
		"RIPM_IP_LSN1",
		"RIPM_IP_VLSN",
	};

// Global Data
		// directory paths
const char*	ConfDir		= "/etc/opt/LSS/ripmd";

		// storage for Host and Shelf configuration data
AtcaHost_t	Host;
AtcaShelf_t*	ShelfHead	= NULL;

/*
 * Function:	GetHostConfiguration()
 *
 * Description:	Get pilot blade host configuration from environment.
 *
 * Arguments:	sock		- socket to use for interface ioctl
 *
 * Returns:	pointer to pilot configuration data or NULL if error
 */

AtcaHost_t*
GetHostConfiguration ( int sock, int* nShelvesPtr )
{
	int		rc;
	int		x;
	struct ifreq	ifr;
	char		line[ 128 ];
	char*		keyword;
	char*		value;
	char*		lasts;
	char		ripmConf[ 128 ];
	char		keywords[RIPM_KEYWORDS] = {0, 0, 0, 0, 0};

	// construct full path name of ripm configuration file
	//
	sprintf( ripmConf, "%s/%s", ConfDir, "ripmd.conf" );
	
	// open the ripm.conf file
	//
	FILE* ripmConfFile = fopen( ripmConf, "r" );
	if ( ripmConfFile == NULL )
	{
		ASRT_RPT( ASMISSING_DATA, 0,
			  "Failed to open %s, errno %d (%s)\n",
			  ripmConf, errno, strerror(errno) );
		return NULL;
	}
	*nShelvesPtr = 0;
	if (ShelfHead != NULL)
	{
		// More than likely, ripm is re-reading configuration
		// file.  Clean up old data before proceeding
		//
		AtcaShelf_t*	shelfPtr;
		while (ShelfHead != NULL)
		{
			shelfPtr = ShelfHead;
			ShelfHead = shelfPtr->next;
			free( shelfPtr );
		}
	}
	
	// process the contents of the ripm.conf file
	//
	while ( fgets( line, sizeof(line), ripmConfFile ) != NULL )
	{
		// get keyword attribute
		//
		keyword = strtok_r( line, " \t=", &lasts );
		if ( keyword == NULL ) continue;

		// get keyword value attribute
		//
		value = strtok_r( NULL, " \t\n", &lasts );
		if ( value == NULL ) continue;

		// Process keyword=value pair
		//
		if ( strcmp( keyword, "RIPM_IFC_LSN0" ) == 0 )
		{
			// LSN0 Interface Name
			//
			Host.ifcLSN[0].name = calloc( 1, strlen(value) + 1 );
			if ( Host.ifcLSN[0].name == NULL )
			{
				ASRT_RPT( ASOSFNFAIL, 0,
					"Failed to malloc %d bytes, errno %d (%s)\n",
					strlen(value) + 1, errno, strerror(errno) );
				(void) fclose( ripmConfFile );
				RELEASE_HOST_MEM(Host);
				return NULL;
			}
			strcpy(Host.ifcLSN[0].name, value);
			keywords[RIPM_IFC_LSN0] = 1;
		}
		else if ( strcmp( keyword, "RIPM_IFC_LSN1" ) == 0 )
		{
			// LNS1 Interface Name
			//
			Host.ifcLSN[1].name = calloc( 1, strlen(value) + 1 );
			if ( Host.ifcLSN[1].name == NULL )
			{
				ASRT_RPT( ASOSFNFAIL, 0,
					"Failed to malloc %d bytes, errno %d (%s)\n",
					strlen(value + 1), errno, strerror(errno) );
				(void) fclose( ripmConfFile );
				RELEASE_HOST_MEM(Host);
				return NULL;
			}
			strcpy(Host.ifcLSN[1].name, value);
			keywords[RIPM_IFC_LSN1] = 1;
		}
		else if ( strcmp( keyword, "RIPM_IP_LSN0" ) == 0 )
		{
			// LSN0 IP Address
			//
			Host.ipLSN[0] = calloc( 1, strlen(value) + 1 );
			if ( Host.ipLSN[0] == NULL )
			{
				ASRT_RPT( ASOSFNFAIL, 0,
					"Failed to malloc %d bytes, errno %d (%s)\n",
					strlen(value + 1), errno, strerror(errno) );
				(void) fclose( ripmConfFile );
				RELEASE_HOST_MEM(Host);
				return NULL;
			}
			strcpy(Host.ipLSN[0], value);
			keywords[RIPM_IP_LSN0] = 1;
		}
		else if ( strcmp( keyword, "RIPM_IP_LSN1" ) == 0 )
		{
			// LSN0 IP Address
			//
			Host.ipLSN[1] = calloc( 1, strlen(value) + 1 );
			if ( Host.ipLSN[1] == NULL )
			{
				ASRT_RPT( ASOSFNFAIL, 0,
					"Failed to malloc %d bytes, errno %d (%s)\n",
					strlen(value + 1), errno, strerror(errno) );
				(void) fclose( ripmConfFile );
				RELEASE_HOST_MEM(Host);
				return NULL;
			}
			strcpy(Host.ipLSN[1], value);
			keywords[RIPM_IP_LSN1] = 1;
		}
		else if ( strcmp( keyword, "RIPM_IP_VLSN" ) == 0 )
		{
			// The VLSN IP address
			//
			Host.ipVLSN = calloc( 1, strlen(value) + 1 );
			if ( Host.ipVLSN == NULL )
			{
				ASRT_RPT( ASOSFNFAIL, 0,
					"Failed to malloc %d bytes, errno %d (%s)\n",
					strlen(value + 1), errno, strerror(errno) );
				(void) fclose( ripmConfFile );
				RELEASE_HOST_MEM(Host);
				return NULL;
			}
			strcpy(Host.ipVLSN, value);
			keywords[RIPM_IP_VLSN] = 1;
			
			// get the hostname for this host
			//
			if ( gethostname( Host.hostname, SYS_NMLN ) < 0 )
			{
				ASRT_RPT( ASOSFNFAIL, 0, "Cannot get hostname, errno %d (%s)\n",
				  errno, strerror(errno) );
				strcpy( Host.hostname, "unknown" );
			}
		}
		else if ( strcmp( keyword, "RACK_NUMBER" ) == 0 )
		{
			// Start the definition of a ShMC
			*nShelvesPtr += AllocateShelf( ripmConfFile, ripmConf, value );
		}

	}
	(void) fclose( ripmConfFile );
	
	// Check to make sure we have all data we need from config file
	//
	for (x = 0; x < RIPM_KEYWORDS; x++)
	{
		if (keywords[x] == 0)
		{
			ASRT_RPT( ASFAULT, 0,
				"RIPM Configuration file %s missing %s keyword\n",
				ripmConf, keywordNames[x]);
			RELEASE_HOST_MEM(Host);
			return NULL;
		}
	}

	// For each LSN, get the interface name and IP address from the
	// environment, then convert the interface name to index.
	//
	for (x = 0; x <= 1; x++ )
	{
		// get the interface index for the interface name
		//
		strcpy( ifr.ifr_name, Host.ifcLSN[ x ].name );

		if ( (rc = ioctl( sock, SIOCGIFINDEX, &ifr )) < 0 )
		{
			ASRT_RPT( ASFAULT, 0, 
				 "Cannot get Interface Index for interface %s, errno %d (%s)\n", 
				 ifr.ifr_name, errno, strerror(errno) );
			RELEASE_HOST_MEM(Host);
			return NULL;
		}

		// save the interface index
		Host.ifcLSN[ x ].index = ifr.ifr_ifindex;
	}
	
	// everything is good, return the host configuration structure
	return &Host;
}

/*
 * Function:	AllocateShelf()
 *
 * Description:	Allocate new ATCA shelf based on shelfman.conf conf file
 *		discovered during configuration load process.
 *
 * Arguments:	shelfmanConf	- shelfman.conf file found
 *
 * Returns:	none
 */

int
AllocateShelf ( FILE* ripmConfFile, char* ripmConf, char* valueOfRack )
{
	char	line[ 128 ];
	char*	keyword;
	char*	value;
	char*	lasts;
	int	rack	= -1;
	int	chassis = -1;

	// allocate a new shelf structure (initialized to zero)
	AtcaShelf_t* shelf_p = (AtcaShelf_t *) calloc( 1, sizeof(AtcaShelf_t) );
	if ( shelf_p == NULL )
	{
		ASRT_RPT( ASOSFNFAIL, 0,
			  "Failed to malloc %d bytes, errno %d (%s)\n",
			  sizeof(AtcaShelf_t), errno, strerror(errno) );
		return 0;
	}
	rack = atoi( valueOfRack);
	shelf_p->equipped = FALSE;
	shelf_p->inhibit_switchover = FALSE;
	
	// continue to process the contents of the ripm.conf file
	//
	while ( fgets( line, sizeof(line), ripmConfFile ) != NULL )
	{
		// get next keyword attribute
		//
		keyword = strtok_r( line, " \t=", &lasts );
		if ( keyword == NULL ) continue;

		// get next keyword value attribute
		//
		value = strtok_r( NULL, " \t\n", &lasts );
		if ( value == NULL ) continue;

		// Process keyword=value pair
		//
		if ( strcmp( keyword, "SUBRACK_NUMBER" ) == 0 )
		{
			// chassis definition
			chassis = atoi( value );
		}
		else if ( strcmp( keyword, "RMCP_IP_ADDRESS" ) == 0 )
		{
			// ShMC Virtual IP Address definition
			strncpy( shelf_p->ipShMCfloater, value,
				 INET_ADDRSTRLEN-1 );
		}
		else if ( strcmp( keyword, "SHMC1_IP_ADDR1" ) == 0 )
		{
			// Top ShMC LSN0 IP Address definition
			strncpy( shelf_p->ipShMCtopLSN0, value,
				 INET_ADDRSTRLEN-1 );
		}
		else if ( strcmp( keyword, "SHMC2_IP_ADDR2" ) == 0 )
		{
			// Bottom ShMC LSN1 IP Address definition
			strncpy( shelf_p->ipShMCbtmLSN1, value,
				 INET_ADDRSTRLEN-1 );
		}
		else if ( strcmp( keyword, "SHMC_EQUIPPED" ) == 0 )
		{
			// Are there other cards on this shelf?
			if ( strcmp( value, "TRUE" ) == 0 )
			{
				shelf_p->equipped = TRUE;
			}
		}
		else if ( strcmp( keyword, "SHMC_SWITCHOVER" ) == 0 )
		{
			// Are there other cards on this shelf?
			if ( strcmp( value, "INHIBITED" ) == 0 )
			{
				shelf_p->inhibit_switchover = TRUE;
			}
		}
		else if ( strcmp( keyword, "SHMC_DEFINITION_END" ) == 0)
		{
			// End of this ShMC Definition, break out
			//
			break;
		}
	}

	// did we get all the info?
	if ( rack < 0 || chassis < 0 )
	{
		ASRT_RPT( ASMISSING_DATA, 0,
			 "Incomplete ShMC config file %s, no RACK or SUBRACK\n",
			 ripmConf );
		free( shelf_p );
		return 0;
	}
	if ( shelf_p->ipShMCfloater[0] == '\0' ||
	     shelf_p->ipShMCtopLSN0[0] == '\0' ||
	     shelf_p->ipShMCbtmLSN1[0] == '\0' )
	{
		ASRT_RPT( ASMISSING_DATA, 0,
			  "Missing IP address(es) in ShMC config file %s\n",
			  ripmConf );
		free( shelf_p );
		return 0;
	}

	/*
	 *  Have all the information, now populate the rest of the shelf
	 *  configuration structure.
	 */
	shelf_p->rack	 = rack;
	shelf_p->chassis = chassis;

	// construct the shelf name
	sprintf( shelf_p->name, "Shelf=%d-%d", rack, chassis );

	// convert floater IP address to binary format
	if ( inet_pton( AF_INET, shelf_p->ipShMCfloater,
				 &shelf_p->ipAddrFloater ) <= 0 )
	{
		ASRT_RPT( ASBAD_DATA, 0, 
			  "Failed to convert ShMC VLSN IP %s for %s\n",
			  shelf_p->ipShMCfloater, shelf_p->name );
	}

	// link the new shelf at the head of the list
	shelf_p->next = ShelfHead;
	ShelfHead = shelf_p;
	return 1;
}


/*
 * Function:	GetShelf()
 *
 * Description:	Get ATCAv2 shelf from configuration.
 *
 * Arguments:	shelf_p		- shelf to search from
 *
 * Returns:	Next shelf after input shelf_p (or first shelf if shelf_p
 *		is NULL).  Returns NULL if no shelfs left in search.
 */

AtcaShelf_t*
GetShelf ( AtcaShelf_t* shelf_p )
{
	return( shelf_p == NULL ? ShelfHead : shelf_p->next );
}


