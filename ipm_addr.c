/* File: 	
 *		glob/src/ipm/ipm_addr.c
 *
 * Description:	This file provides the implementation of the abstraction
 * 		for IP Addresses. The prime goal of this API is to abstract
 *		the types of IP Address in use, E.G. V4, V6 or V12. It is
 *		intended that this abstraction will grow beyond the pure
 *		use of IP addresses.
 */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <net/if.h>
#include <errno.h>
#include <string.h>

#include "ipm_addr.h"
#include "EIPM_include.h"
#include "nma_log.h"

#define IS_VALID_PTR(_x) (_x != NULL)

/*
 * Name:	IPM_ipaddr_init()
 * Description:	Initialises an IPM_IPADDR structure
 */
void IPM_ipaddr_init(IPM_IPADDR *ipmip)
{
	if(!IS_VALID_PTR(ipmip))
	{
		ASRT_RPT(ASBAD_DATA, 0, "ipmip is null");
		return;
	}

	memset(ipmip,0,IPM_IPADDRSIZE);

	ipmip->addrtype = IPM_IPBADVER;
}


/*
 * Name:	IPM_ipaddr2p
 * Description:	Function to convert an IPM_IPADDR to a string (presentation form)
 * Arguments:	Pointer to the source IPM_IPADDR structure, and
 *		a pointer to a buffer and the buffer size. 
 * Returns:	The pointer to the buffer. If it was successful
 *		the buffer contains the string.
 *		If it fails a null string "" is placed in bufptr.
 *		NULL is returned if bufsize <= 0
 */
char *IPM_ipaddr2p(const IPM_IPADDR *ipmip_ptr,char *bufptr,int bufsize)
{
	const char *p = NULL;

	if(bufsize <= 0)
	{
		ASRT_RPT(ASBAD_DATA, 0, "bufsize is invalid %d", bufsize);
		return NULL;
	}
	if(!IS_VALID_PTR(bufptr))
	{
		ASRT_RPT(ASBAD_DATA, 0, "bufptr is null");
		return NULL;
	}
	if(!IS_VALID_PTR(ipmip_ptr))
	{
		ASRT_RPT(ASBAD_DATA, 0, "ipmip_ptr is null");
		bufptr[0] = '\0';
		return bufptr;
	}

	memset(bufptr, 0, bufsize);
	if(ipmip_ptr->addrtype == IPM_IPV4)
	{
		struct in_addr addr;

		/* Check size of the buffer is big enough. */
		if(bufsize < INET_ADDRSTRLEN) /* xxx.xxx.xxx.xxx + \0 */
		{
			ASRT_RPT(ASBAD_DATA, 0, "buffer(size = %d) is too small", bufsize);
			bufptr[0] = '\0';
			return bufptr;
		}
		p = inet_ntop(AF_INET, ipmip_ptr->ipaddr, bufptr, bufsize);
		if(p == NULL)
		{
			ASRT_RPT(ASOSFNFAIL, 1, sizeof(*ipmip_ptr), ipmip_ptr, 
						"inet_ntop(AF_INET,...) failed");
			bufptr[0] = '\0';
		}
	}
	else
	if(ipmip_ptr->addrtype == IPM_IPV6)
	{
		struct in6_addr addr;

		/* Check size of the buffer is big enough. */
		/* xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx + \0 */
		if(bufsize < INET6_ADDRSTRLEN)
		{
			ASRT_RPT(ASBAD_DATA, 0, "buffer(size = %d) is too small", bufsize);
			bufptr[0] = '\0';
			return bufptr;
		}
		p = inet_ntop(AF_INET6, ipmip_ptr->ipaddr, bufptr, bufsize);
		if(p == NULL)
		{
			ASRT_RPT(ASOSFNFAIL, 1, sizeof(*ipmip_ptr), ipmip_ptr,
						 "inet_ntop(AF_INET6,...) failed");
			bufptr[0] = '\0';
		}
	}
	else
	{
		ASRT_RPT(ASBAD_DATA, 1, sizeof(*ipmip_ptr), ipmip_ptr, 
					"Invalid address type");
		bufptr[0] = '\0';
	}
	return bufptr;
}

/*
 * Name:	IPM_chkipaddr2p
 * Description:	Function to check for a valid IPM format and then convert an IPM_IPADDR 
 *		to a string (presentation form)
 * Arguments:	Pointer to the source IPM_IPADDR structure, and
 *		a pointer to a buffer and the buffer size. 
 * Returns:	The pointer to the buffer. If it was successful
 *		the buffer contains the string.
 *		If it fails a null string "" is placed in bufptr.
 *		NULL is returned if bufsize <= 0
 */
char *IPM_chkipaddr2p(const IPM_IPADDR *ipmip_ptr,char *bufptr,int bufsize)
{
	if(bufsize <= 0)
	{
		ASRT_RPT(ASBAD_DATA, 0, "bufsize is invalid %d", bufsize);
		return NULL;
	}

	if(!IS_VALID_PTR(bufptr))
	{
		ASRT_RPT(ASBAD_DATA, 0, "bufptr is null");
		return NULL;
	}

	if(!IS_VALID_PTR(ipmip_ptr))
	{
		ASRT_RPT(ASBAD_DATA, 0, "ipmip_ptr is null");
		bufptr[0] = '\0';
		return bufptr;
	}

	if((ipmip_ptr->addrtype == IPM_IPV6) || 
	   (ipmip_ptr->addrtype == IPM_IPV4))
	{
		return IPM_ipaddr2p( ipmip_ptr, bufptr, bufsize);
	}
	else
	{
		bufptr[0] = '\0';
		return bufptr;
	}
}

/*
 * Name:	IPM_p2ipaddr
 * Description:	Function to convert a string to an IPM_IPADDR structure
 * Notes:	This function will strip a port number from the address
 *		if one is provided. Examples:
 *		ddd.ddd.ddd.ddd
 *		ddd.ddd.ddd.ddd:yyyy
 *		xxxx::x
 *		[xxxx::x]:yyyy
 *		[::ddd.ddd.ddd.ddd]:yyyy
 * Arguments:	Pointer to the string and the IPM_IPADDR structure.
 *		The IPM_IPADDR structure will be filled.
 * Returns:	IPM_SUCCESS if the conversion worked - else IPM_FAILURE
 */
IPM_RETVAL IPM_p2ipaddr(const char *p_ptr,IPM_IPADDR *ipmip_ptr)
{
	char *dot = NULL, *colon = NULL, *cptr;
	char *brkt = NULL;
	int rc;

	if(!IS_VALID_PTR(p_ptr))
	{
		ASRT_RPT(ASBAD_DATA, 0, "p_ptr is null");
		return IPM_FAILURE;
	}
	if(!IS_VALID_PTR(ipmip_ptr))
	{
		ASRT_RPT(ASBAD_DATA, 0, "ipmip_ptr is null");
		return IPM_FAILURE;
	}

	IPM_ipaddr_init(ipmip_ptr);

	/* Search for :s and .s to determine the type of address */
	cptr = (char *) p_ptr;
	while(*cptr != '\0')
	{
		if(!dot && *cptr == '.')
		{
			dot = cptr;
		}
		else
		if(!colon && *cptr == ':')
		{
			colon = cptr;
		}
		else
		if(!brkt && *cptr == '[')
		{
			brkt = cptr;
		}
		if(dot && colon)
		{
			break;
		}
		cptr++;
	}

	/* x.x.x.x or x.x.x.x:y but not ::x.x.x.x */
	if(dot && (!colon || (colon && colon > dot)))
	{
		/* IPV4 */
		struct in_addr addr;
		char ipcpy[INET_ADDRSTRLEN];
		char *cp_ptr;

		/* Remove the port from the string */
		if(colon)
		{
			int len = colon - p_ptr;

			/* Redirect the string being converted to the array */
			cp_ptr = ipcpy;

			if(len >= INET_ADDRSTRLEN)
			{
				ASRT_RPT(ASBAD_DATA, 0, "ipv4 string is too long (%d) to strip the port", len);
				return IPM_FAILURE;
			}

			/* Copy the IP address but not the port */
			strncpy(ipcpy,p_ptr,len);
			ipcpy[len] = '\0';
		}
		else
		{
			cp_ptr = (char *) p_ptr;
		}

		rc = (int) inet_pton(AF_INET,cp_ptr,&addr);
		if(rc <= 0)
		{
			ASRT_RPT(ASOSFNFAIL, 1, strlen(p_ptr), p_ptr,"inet_pton() failed");
			return IPM_FAILURE;
		}
		memcpy(ipmip_ptr->ipaddr,&addr,sizeof(addr));
		ipmip_ptr->addrtype = IPM_IPV4;
	}
	else
	{
		/* IPV6 */
		struct in6_addr addr;
		char ipcpy[INET6_ADDRSTRLEN];
		char *cp_ptr;

		/* Remove the port from the string */
		if(brkt)
		{
			char *cbrkt;

			/* Find the close bracket ']' */
			cbrkt = strrchr(brkt,']');
			if(cbrkt)
			{
				int len = (cbrkt - brkt) - 1;

				if(len >= INET6_ADDRSTRLEN)
				{
					ASRT_RPT(ASBAD_DATA, 0, "ipv6 string is too long(%d) to strip the port", len);
					return IPM_FAILURE;
				}

				/* Copy the IP address but not the port */
				strncpy(ipcpy,brkt + 1,len);
				ipcpy[len] = '\0';

				/* Redirect the string being converted to the array */
				cp_ptr = ipcpy;
			}
			else
			{
				cp_ptr = (char *) p_ptr;
			}
		}
		else
		{
			cp_ptr = (char *) p_ptr;
		}
		rc = (int) inet_pton(AF_INET6,cp_ptr,&addr);
		if(rc <= 0)
		{
			ASRT_RPT(ASOSFNFAIL, 1, strlen(p_ptr),
				p_ptr,"inet_pton() failed");
			return IPM_FAILURE;
		}
		memcpy(ipmip_ptr->ipaddr,&addr,sizeof(addr));
		ipmip_ptr->addrtype = IPM_IPV6;
	}

	return IPM_SUCCESS;
}

/*
 * Name:	IPM_ipcmpstr
 * Description:	IPM_ipcmpstr compares two strings to identify whether
 * 		they are the same IP address. By converting the
 *		strings to binary any complications from zero
 *		compression are removed.
 * Arguments:	Pointer to the two strings
 * Returns:	IPM_SUCCESS if the addresses match
 */
IPM_RETVAL IPM_ipcmpstr(const char *str1,const char *str2)
{
	IPM_IPADDR a1,a2;
	IPM_RETVAL r1,r2;

	IPM_ipaddr_init(&a1);
	IPM_ipaddr_init(&a2);

	r1 = IPM_p2ipaddr(str1,&a1);
	if(r1 != IPM_SUCCESS)
	{
		return r1;
	}
	r2 = IPM_p2ipaddr(str2,&a2);
	if(r2 != IPM_SUCCESS)
	{
		return r2;
	}
	if (memcmp(&a1, &a2, sizeof(IPM_IPADDR)) == 0)
	{
		return IPM_SUCCESS;
	}
	else
	{
		return IPM_FAILURE;
	}
}

/*
 * Name:        IPM_ipgetmasklen
 * Description: gets the netmask lengh base on the
 *              input netmask address for IPv4/Ipv6.
 * Arguments:   IPM_IPADDR structure.
 * Returns:	Netmask length, or IPM_FAILURE for failure.
 */
int
IPM_ipgetmasklen( const IPM_IPADDR *netmask )
{
	int	rc=0;
	int	i,j;
	unsigned char *mask;
	unsigned int max_size = 0;
	unsigned int max_prefix = 0;


	if(!IS_VALID_PTR(netmask))
	{
		ASRT_RPT( ASRTBADPARAM, 0, 
				"Invalid netmask pointer, netmask=NULL\n" );
		return IPM_FAILURE;
	}

	if( netmask->addrtype == IPM_IPV4 )
	{
		max_size = AF_RAWIPV4SIZE;
		max_prefix = IPM_IPV4MAXMASKLEN;
	}
	else if (netmask->addrtype == IPM_IPV6)
	{
		max_size = AF_RAWIPV6SIZE;
		max_prefix = IPM_IPV6MAXMASKLEN;
	}
	else
	{
		ASRT_RPT( ASRTBADPARAM, 1, sizeof(*netmask), netmask, "invalid address type");
		return IPM_FAILURE;
	}

	mask = (unsigned char *)&(netmask->ipaddr[0]);
	for (i = max_size - 1; i >= 0; i--)
	{
		for (j = 0; j < 8; j++)
		{
			if ((mask[i] & ( 1 << j)) != 0)
			{
				return (max_prefix - ((max_size  - i - 1) * 8 + j) );
			}
		}
	}

	/* return 0 to indicate failure */
	ASRT_RPT( ASBAD_DATA, 0, "Failed to caculate the netmask length\n" );
	return IPM_FAILURE;
}

/*
 * Name:	IPM_ipmkmask
 * Description:	IPM_ipmkmask creates a mask using an IPM_IPADDR structure from 
 *		the number of bits in the mask. E.G. a mask length of 24
 *		yields a mask of 0xffffff00. The mask is in network byte order.
 * Arguments:	IPM_IPADDR structure to fill and the mask length.
 */
IPM_RETVAL IPM_ipmkmask(IPM_IPADDR *mask,IPM_IPADDRTYPE addrtype, unsigned int len)
{
	char *c_ptr;
	char m = 0;
	unsigned int max_prefix;

	if (!IS_VALID_PTR(mask)) {          
		ASRT_RPT(ASRTBADPARAM, 0, " mask is null");
		return IPM_FAILURE; 
	}

	IPM_ipaddr_init(mask);
	if (addrtype == IPM_IPV4)
	{
		mask->addrtype  = IPM_IPV4;
		max_prefix = IPM_IPV4MAXMASKLEN;
	}
	else if (addrtype == IPM_IPV6)
	{
		mask->addrtype  = IPM_IPV6;
		max_prefix = IPM_IPV6MAXMASKLEN;
	}
	else
	{
		ASRT_RPT(ASRTBADPARAM, 0, "invalid addrtype %d\n", addrtype);
		return IPM_FAILURE;
	}

	if (len > max_prefix) {
		ASRT_RPT(ASUNEXPECTEDVAL, 0, "len %d too long. Must be <= %d\n", len, IPM_IPV4MAXMASKLEN);
		return IPM_FAILURE;
	}

	c_ptr = (char *)&(mask->ipaddr[0]);
	while (len >= 8)
	{
		*c_ptr = 0xff;
		len -= 8;
		c_ptr++;
	}
	if (len > 0)
	{
		do
		{
			m >>= 1;
			m |= 0x80;
			--len;
		} while(len > 0);
		*c_ptr= m;
	}
	return IPM_SUCCESS;

}

/*
 * Name:	IPM_ipaddr2in
 * Description:	IPM_ipaddr2in converts an IPM_IPADDR to an in_addr or in6_addr
 *		depending on its type.
 * Arguments:	Pointer to IPM_IPADDR and in_addr/in6_addr structures
 * Returns:	Number of bytes copied (or -1 if it failed)
 */
int IPM_ipaddr2in(const IPM_IPADDR *ipmip_ptr,void *in_ptr)
{
	if(!IS_VALID_PTR(ipmip_ptr))
	{
		ASRT_RPT(ASBAD_DATA, 0, "ipmip_ptr is null");
		return IPM_FAILURE;
	}
	if (!IS_VALID_PTR(in_ptr))
	{
		ASRT_RPT(ASBAD_DATA, 0, "in_ptr is null");
		return IPM_FAILURE;
	}
	if(ipmip_ptr->addrtype == IPM_IPV4)
	{
		struct in_addr *addr = (struct in_addr *) in_ptr;
		memcpy(addr, ipmip_ptr->ipaddr, sizeof(*addr)); 
		return sizeof(*addr);
	}
	else
	if(ipmip_ptr->addrtype == IPM_IPV6)
	{
		struct in6_addr *addr = (struct in6_addr *) in_ptr;
		memcpy(addr,ipmip_ptr->ipaddr,sizeof(*addr));
		return sizeof(*addr);
	}
	else
	{
		ASRT_RPT(ASBAD_DATA, 1, 
			sizeof(*ipmip_ptr), ipmip_ptr, "Invalid Address Type");
		return IPM_FAILURE;
	}
}

/* 
 * Name:	IPM_in2ipaddr
 * Description:	IPM_in2ipaddr converts a ulong/in_addr or in6_addr in host byte format
 *		to an IPM_IPADDR structure.
 * Arguments:	Pointer to in_addr/in6_addr structures, size of address in longs
 *		Pointer to IPM_IPADDR
 * Returns:	IPM_SUCCESS or IPM_FAILURE
 */
IPM_RETVAL IPM_in2ipaddr(const void *in_ptr,int in_size,IPM_IPADDR *ipmip_ptr)
{
	int idx;
	uint32_t *l_ptr = (uint32_t *) in_ptr;

	if(!IS_VALID_PTR(ipmip_ptr))
	{
		ASRT_RPT(ASBAD_DATA, 0, "ipmip_ptr is null");
		return IPM_FAILURE;
	}

	if(!IS_VALID_PTR(in_ptr))
	{
		ASRT_RPT(ASBAD_DATA, 0, "in_ptr is null");
		return IPM_FAILURE;
	}

	IPM_ipaddr_init(ipmip_ptr);
	if(in_size == sizeof(struct in_addr))
	{
		ipmip_ptr->addrtype = IPM_IPV4;
	}
	else
	if(in_size == sizeof(struct in6_addr))
	{
		ipmip_ptr->addrtype = IPM_IPV6;
	}
	else
	{
		ASRT_RPT(ASRTBADPARAM, 0, "in_size is invalid (%d)", in_size);
		return IPM_FAILURE;
	}
	memcpy(ipmip_ptr->ipaddr, in_ptr, in_size);

	return IPM_SUCCESS;
}

/*
 * Name:        IPM_ipstrType
 * Description: Judge a string form IP address to see it's IPv4 or Ipv6
 *              It can also handle such ip string that has both address and port
 *              i.e. ddd.ddd.ddd.ddd:yyyyy
 *                   [IPv6address]:yyyyy (RFC3986)
 *              Any space in the string is not allowed
 * Arguments:   ipstr -- pointer to the IP address
 * Returns:     IPM_IPADDRTYPE, IPM_IPV4/IPM_IPV6 for success
 *              IPM_IPBADVER for failure
 *
 * IPv4address = 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT
 * IPv6address = hexpart [ ":" IPv4address ]
 * hexpart = hexseq / hexseq "::" [ hexseq ] / "::" [ hexseq ]
 * hexseq = hex4 *( ":" hex4)
 * hex4 = 1*4HEXDIG
 */
IPM_IPADDRTYPE IPM_ipstrType(const char *ipstr)
{
        bool dot;
        bool colon;
        bool digit;
        bool xdigit;
        bool lbrkt;             /* [IPv6address]:yyyyy */
        bool rbrkt;
        char *firstDotPtr;      /* d.d.d.d:y is V4 and ::d.d.d.d is V6 */
        char *firstColonPtr;

        dot = FALSE;
        colon = FALSE;
        digit = FALSE;
        xdigit = FALSE;
        lbrkt = FALSE;
        rbrkt = FALSE;
        firstDotPtr = NULL;
        firstColonPtr = NULL;

        if(!IS_VALID_PTR(ipstr))
        {
                ASRT_RPT(ASRTBADPARAM, 0, "IPM_ipstrType: ipstr is null");
                return IPM_IPBADVER;
        }

        while (*ipstr != '\0')
        {
                if (isdigit(*ipstr))
                {
                        /* All numbers */
                        digit=TRUE;
                }
                else if (isxdigit(*ipstr))
                {
                        /* All hex numbers */
                        xdigit=TRUE;
                }
                else if (*ipstr == ':')
                {
                        colon = TRUE;
                        if (firstColonPtr == NULL)
                        {
                                firstColonPtr = (char *)ipstr;
                        }
                }
                else if (*ipstr == '.')
                {
                        dot = TRUE;
                        if (firstDotPtr == NULL)
                        {
                                firstDotPtr = (char *)ipstr;
                        }
                }
                else if (*ipstr == '[')
                {
                        lbrkt = TRUE;
                }
                else if (*ipstr == ']')
                {
                        rbrkt = TRUE;
                }
                else
                {
                        return IPM_IPBADVER;
                }
                ipstr++;
        }

        if (dot && digit && !xdigit && !lbrkt && !rbrkt
                && (!colon || (colon && ( firstColonPtr > firstDotPtr))))
        {
                return IPM_IPV4;
        }
        else if (colon)
        {
                if ((lbrkt && !rbrkt) || (!lbrkt && rbrkt))
                {
                        return IPM_IPBADVER;
                }
                return IPM_IPV6;
        }
        else
        {
                return IPM_IPBADVER;
        }
}

/*
 * Name:	IPM_ipcmpaddrpflen
 * Description:	IPM_ipcmpaddrpflen checks to see if the IP addresses match up to
 *		the mask length
 * Arguments:	Pointers to an IPM_IPADDR structure for comparison along with mask size
 * Returns:	IPM_SUCCESS if debugging is enabled for this IP Addresses subnet
 */
IPM_RETVAL IPM_ipcmpaddrpflen( IPM_IPADDR *ip1, IPM_IPADDR *ip2, int prefix_len )
{
	IPM_IPADDR	mask;
	IPM_RETVAL	ret;
	int 		size,pos;

		
	if(!IS_VALID_PTR(ip1))
	{
		ASRT_RPT(ASRTBADPARAM, 0, "ip1 is null");
		return IPM_FAILURE;
	}
	if(!IS_VALID_PTR(ip2))
	{
		ASRT_RPT(ASRTBADPARAM, 0, "ip2 is null");
		return IPM_FAILURE;
	}
												
	if(ip1->addrtype != ip2->addrtype)
	{
		/* Constraint exists but different network types.
		 * Debugging can not be active.
		 */
		return IPM_FAILURE;
	}
	
	switch (ip1->addrtype)
	{
	case IPM_IPV4:
		size = 1;
		break;
	case IPM_IPV6:
		size = 4;
		break;
	default:
		ASRTA_D2(ASBAD_DATA, sizeof(*ip1), ip1,
		sizeof(*ip2), ip2, "Bad addrtype");
		return IPM_FAILURE;
	}
	
	ret = IPM_ipmkmask( &mask, ip1->addrtype, prefix_len );
	if( ret != IPM_SUCCESS )
	{
		/* IPM_IPMKMASK will assert on a failure */
		return IPM_FAILURE;
	}

	pos = 0;
	do
	{
		/* Mask the IP address and compare to the subnet to see if its
		 * the same subnet.
		 */
		/* IP doesn't match subnet */
		if((ip1->ipaddr[pos] & mask.ipaddr[pos]) !=
		   (ip2->ipaddr[pos] & mask.ipaddr[pos]))
		{
			return IPM_FAILURE;
		}
		pos++;

	} while(pos < size);

	return IPM_SUCCESS;
}
