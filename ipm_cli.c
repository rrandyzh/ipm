
#include <types.h>
#include <stdio.h>
#include <time.h>
#include <sys/socket.h>
#include <string.h>

#include <netinet/in.h>
#include "nnn_socket.h"
#include "ipm_msg.h"
#include "ipm_clnt_snd.h"
#include "nma_log.h"
#include "EIPM_include.h"
#if defined(_LIBRARY_IPM_CLI)
#include "ipmcomm.h"
#endif
#include "BFD_api.h"

void ipm_cli_menu();

/*
 * This function will try to common all code in this file call
 * strcpy(). Since strcpy has potential risk to overflow the 
 * dest buffer, it has to use strncpy. However, this function
 * has peformance issue. 
 * Therefore, 
 * 1. if dest capacity is small, then it is high performance
 * by the following code
 * 	strncpy(dest, src, DEST_MAX_SIZE-1);
 * 	dest[DEST_MAX_SIZE-1] = 0;
 * 2. if dest capacity is big, fg, DEST_MAX_SIZE is 128, the 
 * src len is 3, then you can try the following function and 
 * it has high performance than the item 1.
 */
inline void ipm_strncpy( char *dest, char *src, unsigned int dest_max_size)
{

        if((dest != NULL) && (src != NULL))
        {

                unsigned int copy_size = strlen(src);
                if (copy_size >= dest_max_size )
                {
                        copy_size = dest_max_size - 1;
                }
                strncpy(dest, src, copy_size);
                dest[copy_size] = 0;
        }
}

int
ipm_handle_base_request( char *action, char *left, char *right, char *subnet_type )
{
struct nma_msgsocket_t msg;

    // ipm_cli -a [add,del] -t base -l <iface> -r <iface> {-s [internal,external]}

    memset(&msg, 0, sizeof(msg));
	
    msg.h.size = sizeof(struct cmd_base_iface);

    if( strcmp(action, "add") == 0 )
    {
        msg.h.type = IPM_ADD_BASEIF;
    }
    else if( strcmp(action, "del") == 0 )
    {
        msg.h.type = IPM_DEL_BASEIF;
    }
    else
    {
        CLI_LOG("ipm_cli: ipm_handle_base_request() Unsupported Action %s\n", action);
        return IPM_CLI_RET_BAD_ACTION;
    }

    if ((strlen(left) == 0) && ( strlen(right) == 0 ))
    {
        CLI_LOG("ipm_cli: ipm_handle_base_request() Both Interface are Null\n");
        return IPM_CLI_RET_BAD_IFACE;
    }

    if( strlen(left) > 0 )
    {
        char *left_alias = strchr(left, ':');

        if( left_alias == NULL )
        {
            ipm_strncpy(msg.cmd_base_iface.base_if[0], left, MAX_NLEN_DEV);
        }
        else
        {
            strncpy(msg.cmd_base_iface.base_if[0], left, left_alias-left);
        }
    }

    if( strlen(right) > 0 )
    {
        char *right_alias = strchr(right, ':');

        if( right_alias == NULL )
        {
            ipm_strncpy(msg.cmd_base_iface.base_if[1], right, MAX_NLEN_DEV);
        }
        else
        {
            strncpy(msg.cmd_base_iface.base_if[1], right, right_alias-right);
        }
    }

    if( strlen(subnet_type) > 0 &&
        strcmp(subnet_type, "external") == 0 )
    {
        msg.cmd_base_iface.subnet_type = IPM_SUBNET_EXTERNAL;
    }

    return ipm_send_client_msg(&msg);
}

int
ipm_handle_alias_request( char *action, 
                          char *type, 
                          char *left, 
                          char *right, 
                          char *gateway )
{
struct nma_msgsocket_t msg;
int    ret;

    // wcnp management IP should only be plumbed on one single interfaces, there are defensived check
    // in IPM instead of the front end CLI routine.

    // ipm_cli -a [add,del] -t [lsn,internal,external,alias,wcnp_fix,wcnp_active,wcnp_standby] 
    //        {-l <iface,ip/prefix>} {-r <iface,ip/prefix>} {-g <subnet gateway>}

    memset(&msg, 0, sizeof(msg));

    msg.h.size = sizeof(struct cmd_alias_ip);

    ret = IPM_CLI_RET_BAD_LEFT;

    if( strlen(left) > 0 )
    {
        ret = ipm_populate_alias_msg(action, type, left,
                                     0,
                                     &msg.h.type,
                                     &msg.cmd_alias_ip.alias_t[0]);

        if( ret != IPM_CLI_RET_SUCCESS )
        {
            return ret;
        }
    }

    if( strlen(right) > 0 )
    {
        ret = ipm_populate_alias_msg(action, type, right,
                                     0,
                                     &msg.h.type,
                                     &msg.cmd_alias_ip.alias_t[1]);

        if( ret != IPM_CLI_RET_SUCCESS )
        {
            return ret;
        }
    }

    strncpy(msg.cmd_alias_ip.gateway, gateway, IPM_IPMAXSTRSIZE);

    return ipm_send_client_msg(&msg);
}



int
ipm_handle_arp_request( char *action, char *ip, char *priority, char* left, char *right )
{
struct nma_msgsocket_t msg;
char *  arp_ip;
char * prefix_str;
int prefix;

    // ipm_cli -a [add,del] -t arp -i <ip/prefix> -p <priority>

    memset(&msg, 0, sizeof(msg));

    if( strcmp(action, "add") == 0 )
    {
        msg.h.type = IPM_ADD_ARP;
    }
    else if( strcmp(action, "del") == 0 )
    {
        msg.h.type = IPM_DEL_ARP;
    }
    else
    {
        CLI_LOG("ipm_cli: ipm_handle_arp_request() Unsupported Action %s\n", action);
        return IPM_CLI_RET_BAD_ACTION;
    }

    msg.h.size = sizeof(struct cmd_arp_list);

    if( sscanf(priority, "%d", &msg.cmd_arp_list.priority ) != 1 ||
        msg.cmd_arp_list.priority < 1 ||
        msg.cmd_arp_list.priority > 4 )
    {
        CLI_LOG("ipm_cli: ipm_handle_arp_request() Priority Format Error: %s\n", priority);
        return IPM_CLI_RET_BAD_PRIORITY;
    }

    if( strlen(ip) < 9 )
    {
        CLI_LOG("ipm_cli: ipm_handle_arp_request() IP Format Error: %s\n", ip);
        return IPM_CLI_RET_BAD_IP;
    }
    
    prefix_str = strchr(ip, '/');
    if( prefix_str  == NULL )
    {
        CLI_LOG(" ipm_cli: ipm_handle_arp_request() IP Prefix Format Error - prefix_str %s\n", ip);
        return IPM_CLI_RET_BAD_PREFIX;
    }

    prefix = atoi(prefix_str + 1);
    if( prefix < 0 || 
        prefix > 128 )
    {
        CLI_LOG("ipm_cli: ipm_handle_arp_request() IP Prefix Format Error - out of range %s\n", ip);
        return IPM_CLI_RET_BAD_PREFIX;
    }
    else
    {
        msg.cmd_arp_list.prefix = prefix;
    }

    arp_ip = strtok(ip,"/");
    if (arp_ip == NULL)
    {
        CLI_LOG("ipm_cli: ipm_handle_arp_request() IP Format Error: %s\n", ip);
        return IPM_CLI_RET_BAD_IP;
    }

    if( strlen(arp_ip) > IPM_IPMAXSTRSIZE )
    {
        CLI_LOG("ipm_cli: ipm_handle_arp_request() IP Size Error: %s\n", arp_ip);
        return IPM_CLI_RET_BAD_IP;
    }

    strncpy(msg.cmd_arp_list.ip, arp_ip, IPM_IPMAXSTRSIZE);

     if( strlen(left) > 0 )
     {
         char *left_alias = strchr(left, ':');

         if( left_alias == NULL )
         {
             ipm_strncpy(msg.cmd_arp_list.iface[0], left, MAX_NLEN_DEV);
         }
         else
         {
             strncpy(msg.cmd_arp_list.iface[0], left, left_alias-left);
         }
     }

     if( strlen(right) > 0 )
     {
         char *right_alias = strchr(right, ':');

         if( right_alias == NULL )
         {
             ipm_strncpy(msg.cmd_arp_list.iface[1], right, MAX_NLEN_DEV);
         }
         else
         {
             strncpy(msg.cmd_arp_list.iface[1], right, right_alias-right);
         }
     }
    return ipm_send_client_msg(&msg);
}

int
ipm_handle_garp_request( char *action, char *type, char *subnet_type, char *ip )
{
struct nma_msgsocket_t msg;

    // ipm_cli -a garp -i <[interface,]ip>
    // ipm_cli -a garp -t [fixed,float,all] -s [internal,external,all]

    memset(&msg, 0, sizeof(msg));

    if( strcmp(action, "garp") != 0 )
    {
        CLI_LOG("ipm_cli: ipm_handle_garp_request() Unsupported Action %s\n", action);
        return IPM_CLI_RET_BAD_ACTION;
    }

    msg.h.type = IPM_GARP_REQUEST;
    msg.h.size = sizeof(struct cmd_garp_request);

    if( strlen(ip) > 0 )
    {
        ipm_strncpy(msg.cmd_garp_request.ip, ip, IPM_IPMAXSTRSIZE + MAX_NLEN_DEV + 1);

        return ipm_send_client_msg(&msg);
    }

    if( strcmp(type, "fixed") == 0 )
    {
        msg.cmd_garp_request.address_type = 0;
    }
    else if( strcmp(type, "float") == 0 )
    {
        msg.cmd_garp_request.address_type = 1;
    }
    else if( strcmp(type, "all") == 0 )
    {
        msg.cmd_garp_request.address_type = 2;
    }
    else
    {
        CLI_LOG("ipm_cli: ipm_handle_garp_request() Unsupported Address Type %s\n", type);
        return IPM_CLI_RET_BAD_TYPE;
    }

    if( strcmp(subnet_type, "internal") == 0 )
    {
        msg.cmd_garp_request.subnet_type = IPM_SUBNET_INTERNAL;
    }
    else if( strcmp(subnet_type, "external") == 0 )
    {
        msg.cmd_garp_request.subnet_type = IPM_SUBNET_EXTERNAL;
    }
    else if( strcmp(subnet_type, "all") == 0 )
    {
        msg.cmd_garp_request.subnet_type = IPM_SUBNET_BOTH;
    }
    else
    {
        CLI_LOG("ipm_cli: ipm_handle_garp_request() Unsupported Subnet Type %s\n", subnet_type);
        return IPM_CLI_RET_BAD_TYPE;
    }

    return ipm_send_client_msg(&msg);
}

int
ipm_handle_route_request( char *action, char *dest, char *gateway , char *left, char *right, char *pivot_id, char* ip, char *vlan_id)
{
struct nma_msgsocket_t msg;
char *dest_ip;
char *prefix_str;
int prefix;

    // ipm_cli -a add -t route -d <dest/prefix> -g <gateway> [-i <source ip>]
    // ipm_cli -a del -t route -d <dest/prefix>

    memset(&msg, 0, sizeof(msg));

    if( strcmp(action, "add") == 0 )
    {
        msg.h.type = IPM_ADD_ROUTE;
    }
    else if( strcmp(action, "del") == 0 )
    {
        msg.h.type = IPM_DEL_ROUTE;
    }
    else
    {
        CLI_LOG("ipm_cli: ipm_handle_route_request() Unsupported Action %s\n", action);
        return IPM_CLI_RET_BAD_ACTION;
    }

    msg.h.size = sizeof(struct cmd_route_upd);

    
    prefix_str = strchr(dest, '/');
    if( prefix_str == NULL )
    {
        CLI_LOG("ipm_cli: ipm_handle_route_request() IP Prefix Format Error - prefix_str %s\n", dest);
        return IPM_CLI_RET_BAD_PREFIX;
    }

    prefix = atoi(prefix_str + 1);
    if( prefix < 0 || 
        prefix > 128 )
    {
        CLI_LOG("ipm_cli: ipm_handle_route_request() IP Prefix Format Error - out of range %s\n", dest);
        return IPM_CLI_RET_BAD_PREFIX;
    }
    else
    {
        msg.cmd_route_upd.prefix = prefix;
    }

    dest_ip = strtok(dest,"/");
    if (dest_ip == NULL)
    {
        CLI_LOG("ipm_cli: ipm_handle_route_request() IP Format Error: %s\n", dest);
        return IPM_CLI_RET_BAD_IP;
    }

    if( strlen(dest_ip) > IPM_IPMAXSTRSIZE )
    {
        CLI_LOG("ipm_cli: ipm_handle_arp_request() Dest IP Size Error: %s\n", dest_ip);
        return IPM_CLI_RET_BAD_IP;
    }

    strncpy(msg.cmd_route_upd.dest, dest_ip, IPM_IPMAXSTRSIZE);

    if( msg.h.type == IPM_ADD_ROUTE )
    {
        if( strlen(gateway) > IPM_IPMAXSTRSIZE )
        {
            CLI_LOG("ipm_cli: ipm_handle_arp_request() Gateway IP Size Error: %s\n", gateway);
            return IPM_CLI_RET_BAD_IP;
        }

        strncpy(msg.cmd_route_upd.nexthop, gateway, IPM_IPMAXSTRSIZE);
    }

    if( strlen(left) > 0 )
    {
        char *left_alias = strchr(left, ':');

        if( left_alias == NULL )
        {
            ipm_strncpy(msg.cmd_route_upd.iface[0], left, MAX_NLEN_DEV);
        }
        else
        {
            strncpy(msg.cmd_route_upd.iface[0], left, left_alias-left);
        }
    }

    if( strlen(right) > 0 )
    {
        char *right_alias = strchr(right, ':');

        if( right_alias == NULL )
        {
            ipm_strncpy(msg.cmd_route_upd.iface[1], right, MAX_NLEN_DEV);
        }
        else
        {
            strncpy(msg.cmd_route_upd.iface[1], right, right_alias-right);
        }
    }

    if ( msg.h.type == IPM_ADD_ROUTE && strlen( ip ) > 0 )
    {
        strncpy(msg.cmd_route_upd.source_ip, ip, IPM_IPMAXSTRSIZE);
    }
    if (strlen(pivot_id) > 0)
    {
	long tmp_pivot_id = strtol(pivot_id, (char**)NULL, 10);
        if (tmp_pivot_id < 0 || tmp_pivot_id >= MAX_NUM_PIVOT)
        {
            CLI_LOG("ipm_cli: ipm_handle_route_request() pivot id is out of range: %d\n", tmp_pivot_id);
            return IPM_CLI_RET_BAD_VALUE;
        }
        msg.cmd_route_upd.pivot_id = (unsigned char)tmp_pivot_id;
    }

    if (strlen(vlan_id) > 0)
    {
        int tmp_vlanid = strtol(vlan_id, (char**) NULL, 10);
        if (tmp_vlanid < 0 || tmp_vlanid >= 4096)
        {
            CLI_LOG("ipm_cli: ipm_handle_route_request() vlan id is out of range: %d\n", tmp_vlanid);
            return IPM_CLI_RET_BAD_VALUE;
        }
        msg.cmd_route_upd.vlanId = (unsigned short)tmp_vlanid;
    }

    return ipm_send_client_msg(&msg);
}

unsigned int
b64atoi(char ch)
{
char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789__";
unsigned int val;

    for( val=0; b64[val]; val++ )
    {
        if( b64[val] == ch )
        {
            return val;
        }
    }

    return 0;
}


int
ipm_populate_alias_msg(char *action,
                       char *type,
                       char *value,
                       int  notification,
                       int  *msg_type,
                       struct alias_ip_t *alias_ip)
{
char *prefix_str;
char *iface_str;
char *ip_str;

// ipm_cli -a [add,del] -t alias -l <eth0.800:XNAAA,1.2.3.4/20> -r <eth1.801:XNAAA,1.2.3.5/20>

    alias_ip->expedite_notification = notification;

    // Handle prefix before strtok() messes with the value string 
    prefix_str = strrchr(value, '/');
    if( prefix_str == NULL )
    {
        CLI_LOG("ipm_cli: ipm_populate_alias_msg() IP Prefix Format Error: %s\n", value);

        return IPM_CLI_RET_BAD_PREFIX;
    }

    alias_ip->prefix = atoi(prefix_str + 1);

    if( alias_ip->prefix < 0 ||
        alias_ip->prefix > 128 )
    {
        CLI_LOG("ipm_cli: ipm_populate_alias_msg() Prefix Conversion Error: %s %d\n", 
                 prefix_str + 1, alias_ip->prefix);

        return IPM_CLI_RET_BAD_PREFIX;
    }

    if ( strchr(value, ',') == NULL  )
    {
        CLI_LOG("ipm_cli: ipm_populate_alias_msg() Iface Format Error: %s\n", value);
        return IPM_CLI_RET_BAD_IFACE;
    }

    iface_str = strtok(value, ",");
    if( iface_str == NULL )
    {
        CLI_LOG("ipm_cli: ipm_populate_alias_msg() Iface Format Error: %s\n", value);
        return IPM_CLI_RET_BAD_IFACE;
    }

    if( strlen(iface_str) > MAX_NLEN_DEV )
    {
        CLI_LOG("ipm_cli: ipm_populate_alias_msg() Iface Size Error: %s\n", iface_str);
        return IPM_CLI_RET_BAD_IFACE;
    }

    strncpy(alias_ip->alias_if, iface_str, MAX_NLEN_DEV);

    ip_str = strtok(NULL, "/");
    if( ip_str == NULL )
    {
        CLI_LOG("ipm_cli: ipm_populate_alias_msg() IP Format Error: %s\n", value);

        return IPM_CLI_RET_BAD_IP;
    }

    if( strlen(ip_str) > IPM_IPMAXSTRSIZE )
    {
        CLI_LOG("ipm_cli: ipm_populate_alias_msg() IP Size Error: %s\n", ip_str);
        return IPM_CLI_RET_BAD_IP;
    }

    if( strcmp(ip_str, "0") == 0 ) 
    {
        CLI_LOG("ipm_cli: ipm_populate_alias_msg() IP invalid %s\n", ip_str);
        return IPM_CLI_RET_BAD_IP;
    }

    strncpy(alias_ip->ip, ip_str, IPM_IPMAXSTRSIZE);

    if( strcmp(type, "lsn") == 0 )
    {
        alias_ip->subnet_type = IPM_SUBNET_INTERNAL;

        if( strcmp(action, "add") == 0 )
        {
            *msg_type = IPM_ADD_LSN_ALIAS;
        }
        else if( strcmp(action, "del") == 0 )
        {
            *msg_type = IPM_DEL_LSN_ALIAS;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_alias_request() Unsupported Action %s for Type %s\n", action, type);

            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if( strcmp(type, "internal") == 0 )
    {
        alias_ip->subnet_type = IPM_SUBNET_INTERNAL;

        if( strcmp(action, "add") == 0 )
        {
            *msg_type = IPM_ADD_INT_ALIAS;
        }
        else if( strcmp(action, "del") == 0 )
        {
            *msg_type = IPM_DEL_INT_ALIAS;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_alias_request() Unsupported Action %s for Type %s\n", action, type);

            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if( strcmp(type, "external") == 0 )
    {
        alias_ip->subnet_type = IPM_SUBNET_EXTERNAL;

        if( strcmp(action, "add") == 0 )
        {
            *msg_type = IPM_ADD_EXT_ALIAS;
        }
        else if( strcmp(action, "del") == 0 )
        {
            *msg_type = IPM_DEL_EXT_ALIAS;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_alias_request() Unsupported Action %s for Type %s\n", action, type);

            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if( strcmp(type, "wcnp_fix") == 0 )
    {
        alias_ip->subnet_type = IPM_SUBNET_EXTERNAL;

        if( strcmp(action, "add") == 0 )
        {
            *msg_type = IPM_ADD_WCNP_FIX;
        }
        else if( strcmp(action, "del") == 0 )
        {
            *msg_type = IPM_DEL_WCNP_FIX;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_alias_request() Unsupported Action %s for Type %s\n", action, type);

            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if( strcmp(type, "wcnp_active") == 0 )
    {
        alias_ip->subnet_type = IPM_SUBNET_EXTERNAL;

        if( strcmp(action, "add") == 0 )
        {
            *msg_type = IPM_ADD_WCNP_ACTIVE;
        }
        else if( strcmp(action, "del") == 0 )
        {
            *msg_type = IPM_DEL_WCNP_ACTIVE;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_alias_request() Unsupported Action %s for Type %s\n", action, type);

            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if( strcmp(type, "wcnp_standby") == 0 )
    {
        alias_ip->subnet_type = IPM_SUBNET_EXTERNAL;

        if( strcmp(action, "add") == 0 )
        {
            *msg_type = IPM_ADD_WCNP_STANDBY;
        }
        else if( strcmp(action, "del") == 0 )
        {
            *msg_type = IPM_DEL_WCNP_STANDBY;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_alias_request() Unsupported Action %s for Type %s\n", action, type);

            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if( strcmp(type, "alias") == 0 )
    {
        char *alias_str = strchr(alias_ip->alias_if, ':');

        if( alias_str == NULL  || strlen (alias_str) < 2 )
        {
            CLI_LOG("ipm_cli: ipm_populate_alias_msg() Iface Format Error: %s\n", alias_ip->alias_if);

            return IPM_CLI_RET_BAD_IFACE;
        }

        alias_str++;

        if( strcmp(alias_str, "0") == 0 ) /* lsn */
        {
            alias_ip->subnet_type = IPM_SUBNET_INTERNAL;
            alias_ip->expedite_notification = 0;

            if( strcmp(action, "add") == 0 )
            {
                *msg_type = IPM_ADD_LSN_ALIAS;
            }
            else if( strcmp(action, "del") == 0 )
            {
                *msg_type = IPM_DEL_LSN_ALIAS;
            }
            else
            {
                CLI_LOG("ipm_cli: ipm_handle_alias_request() Unsupported Action %s for Type %s\n", action, type);

                return IPM_CLI_RET_BAD_ACTION;
            }
        }
        else if( strcmp(alias_str, "1") == 0 ) /* Host */
        {
            alias_ip->subnet_type = IPM_SUBNET_INTERNAL;
            alias_ip->expedite_notification = 0;

            if( strcmp(action, "add") == 0 )
            {
                *msg_type = IPM_ADD_INT_ALIAS;
            }
            else if( strcmp(action, "del") == 0 )
            {
                *msg_type = IPM_DEL_INT_ALIAS;
            }
            else
            {
                CLI_LOG("ipm_cli: ipm_handle_alias_request() Unsupported Action %s for Type %s\n", action, type);

                return IPM_CLI_RET_BAD_ACTION;
            }
        }
        else
        {
            /* Need to decode the alias to derive information in the first digit.
             *
             * The instance value is a string that is encoded from attributes
             * in the IPCFG_SERVICE_IP_SET and CARD_POOL_INFO structures.
             * These attributes are encoded into a 30 bit value and then converted
             * into a 5 digit base-64 number.
             * 
             * The 30 bit value is encoded using the following format:
             * 
             * Base-64 Digit   5      4      3      2      1
             * -----------------------------------------------
             * Attribute ID zyzzzz zzyyyx tiziyy yyxxxx xasfii
             * 
             * Attribute ID Description
             * ------------------------
             * iiii     - 4 bit IP address number
             * 
             * f        - 1 bit IP address family: 0 is IPv4, 1 is IPv6
             * 
             * s        - 1 bit subnet type: 0 is internal, 1 is external
             * 
             * a        - 1 bit IP address Type: 0 is fixed, 1 is floating
             * 
             * xxxxxx   - 6 bit Pool type
             * 
             * yyyyyyyy - 8 bit Pool ID
             * 
             * zzzzzzzz - 8 bit Pool Member ID
             * 
             * t - Truncation flag. Set to zero if the fourth and fifth digits
             * of the instance are zero. Otherwise set to one.  This flags
             * other tools or utilities that additional information is hidden.
             * 
             * The base-64 digits are stored in the instance buffer with least
             * significant digits first, ie: "12345".
             * 
             * The instance value is 5 digits long but the last two are truncated by
             * the ifconfig command. The encoding is engineered so the last two digits
             * (4 and 5) are normally zero.
             *
             */
#if BYTE_ORDER == LITTLE_ENDIAN

            union digit1 {
                    struct {
                            unsigned int    i : 2;
                            unsigned int    f : 1;
                            unsigned int    s : 1;
                            unsigned int    a : 1;
                            unsigned int    x : 1;
                            unsigned int    r : 26;
                    } bits;

                    unsigned int    val;
            };

#else

            union digit1 {
                    struct {
                            unsigned int    r : 26;
                            unsigned int    x : 1;
                            unsigned int    a : 1;
                            unsigned int    s : 1;
                            unsigned int    f : 1;
                            unsigned int    i : 2;
                    } bits;

                    unsigned int    val;
            };
#endif

            union digit1 d1;

            d1.val = b64atoi(*alias_str);

            /* Expedite Notification for Floating IPs */
            alias_ip->expedite_notification = d1.bits.a;

            /* Values the same, so can just copy */
            alias_ip->subnet_type = d1.bits.s;
 

            if( alias_ip->subnet_type == IPM_SUBNET_INTERNAL )
            {
                if( strcmp(action, "add") == 0 )
                {
                    *msg_type = IPM_ADD_INT_ALIAS;
                }
                else if( strcmp(action, "del") == 0 )
                {
                    *msg_type = IPM_DEL_INT_ALIAS;
                }
                else
                {
                    CLI_LOG("ipm_cli: ipm_handle_alias_request() Unsupported Action %s for Type %s\n", 
                             action, type);

                    return IPM_CLI_RET_BAD_ACTION;
                }
            }
            else
            {
                if( strcmp(action, "add") == 0 )
                {
                    *msg_type = IPM_ADD_EXT_ALIAS;
                }
                else if( strcmp(action, "del") == 0 )
                {
                    *msg_type = IPM_DEL_EXT_ALIAS;
                }
                else
                {
                    CLI_LOG("ipm_cli: ipm_handle_alias_request() Unsupported Action %s for Type %s\n", 
                             action, type) ;

                    return IPM_CLI_RET_BAD_ACTION;
                }
            }
        }
    }
    else
    {
        CLI_LOG("ipm_cli: ipm_populate_alias_msg() Unsupported Type %s\n", type);

        return IPM_CLI_RET_BAD_TYPE;
    }

    return IPM_CLI_RET_SUCCESS;
}
int
ipm_populate_subnet_msg(
	char *action,
	char *type,
	char *value,
	int *msg_type,
        int mode_type,
	struct dev_alias_t *device
)
{
	char *base_iface_ptr;
	char *alias_ptr;
	char *vlan;

	/* strip : ALIAS if came in w/ : */
	base_iface_ptr = strtok(value, ":");
	if ( base_iface_ptr == NULL )
	{
		base_iface_ptr = value;
	}
        
	if ( (IPM_REDUNDANCY_MODE) mode_type == IPM_RED_IIPM )
	{
		if ( strcmp(action, "add") == 0 )
		{
			*msg_type		= IPM_ADD_INT_SUBNET;
			device->subnet_type	= IPM_SUBNET_INTERNAL;
		}
		else if (strcmp(action, "del") == 0 )
		{
			*msg_type		= IPM_DEL_INT_SUBNET;
			device->subnet_type	= IPM_SUBNET_INTERNAL;
		}
		else
		{
			CLI_LOG(
				"ipm_cli: %s() unsupported Action %s for Type %s\n",
				__FUNCTION__,
				action,
				type
			);
			return IPM_CLI_RET_BAD_ACTION;
		}
        }
	else
	{
		if ( strcmp(action, "add") == 0 )
		{
			*msg_type		= IPM_ADD_EXT_SUBNET;
			device->subnet_type	= IPM_SUBNET_EXTERNAL;
		}
		else if (strcmp(action, "del") == 0 )
		{
			*msg_type		= IPM_DEL_EXT_SUBNET;
			device->subnet_type	= IPM_SUBNET_EXTERNAL;
		}
		else
		{
			CLI_LOG(
				"ipm_cli: %s() unsupported Action %s for Type %s\n",
				__FUNCTION__,
				action,
				type
			);
			return IPM_CLI_RET_BAD_ACTION;
		}
	}

	strncpy(device->dev_if, base_iface_ptr, MAX_NLEN_DEV - 1);
	device->dev_if[MAX_NLEN_DEV - 1] = '\0';

	return IPM_CLI_RET_SUCCESS;
}


int
ipm_handle_admin_request( char *action, char *type, char *i_arg, char *gateway, char *w_arg, char *v_arg)
{
struct nma_msgsocket_t msg;

    // ipm_cli -a [alw,inh] -t [ipm,iipm,eipm,pipm,syslog,log{local,remote,check,action}]
    // ipm_cli -a [alw,inh] -t cfgchk -i <idx>
    // ipm_cli -a report -t events
    // ipm_cli -a clr -t events
    // ipm_cli -a dump -t [data,stats,status,shm,ctx,session] [-i <local ip> -g <gw ip address>]
    // ipm_cli -a [set,clr] -t {iipm,eipm}debug {-i <idx>}

    memset(&msg, 0, sizeof(msg));
	
    msg.h.size = sizeof(struct cmd_ipm_admin);

    if( strcmp(type, "ipm") == 0 )
    {
        if( strcmp(action, "alw") == 0 )
        {
            msg.h.type = IPM_ALW_IPM;
        }
        else if( strcmp(action, "inh") == 0 )
        {
            msg.h.type = IPM_INH_IPM;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if( strcmp(type, "iipm" ) == 0 )
    {
        if( strcmp(action, "alw") == 0 )
        {
            msg.h.type = IPM_ALW_IIPM;
        }
        else if( strcmp(action, "inh") == 0 )
        {
            msg.h.type = IPM_INH_IIPM;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if( strcmp(type, "eipm") == 0 )
    {
        if( strcmp(action, "alw") == 0  )
        {
            msg.h.type = IPM_ALW_EIPM;
        }
        else if( strcmp(action, "inh") == 0 )
        {
            msg.h.type = IPM_INH_EIPM;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }
        
    }
    else if (strcmp(type, "proxyserv") == 0)
    {
        if( strcmp(action, "alw") == 0  )
        {
            msg.h.type = IPM_ALW_PROXY_SERVER;
        }
        else if( strcmp(action, "inh") == 0 )
        {
            msg.h.type = IPM_INH_PROXY_SERVER;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if( strcmp(type, "pipm") == 0 )
    {
        if( strcmp(action, "alw") == 0  )
        {
            msg.h.type = IPM_ALW_PIPM;
        }
        else if( strcmp(action, "inh") == 0 )
        {
            msg.h.type = IPM_INH_PIPM;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }
        
    }
    else if( strcmp(type, "pipm_l2_path") == 0 )
    {
        if( strcmp(action, "alw") == 0  )
        {
            msg.h.type = IPM_ALW_PIPM_L2_PATH;
        }
        else if( strcmp(action, "inh") == 0 )
        {
            msg.h.type = IPM_INH_PIPM_L2_PATH;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }
        
    }
    else if( strcmp(type, "loglocal") == 0 ||
             strcmp(type, "syslog") == 0 )
    {
        if( strcmp(action, "alw") == 0 )
        {
            msg.h.type = IPM_ALW_SYSLOG;
        }
        else if( strcmp(action, "inh") == 0 )
        {
            msg.h.type = IPM_INH_SYSLOG;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if( strcmp(type, "logremote") == 0 )
    {
        if( strcmp(action, "alw") == 0 )
        {
            msg.h.type = IPM_ALW_REMOTE_LOG;
        }
        else if( strcmp(action, "inh") == 0 )
        {
            msg.h.type = IPM_INH_REMOTE_LOG;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if( strcmp(type, "logcheck") == 0 )
    {
        if( strcmp(action, "alw") == 0 )
        {
            msg.h.type = IPM_ALW_CHECK_LOG;
        }
        else if( strcmp(action, "inh") == 0 )
        {
            msg.h.type = IPM_INH_CHECK_LOG;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if( strcmp(type, "logaction") == 0 )
    {
        if( strcmp(action, "alw") == 0 )
        {
            msg.h.type = IPM_ALW_ACTION_LOG;
        }
        else if( strcmp(action, "inh") == 0 )
        {
            msg.h.type = IPM_INH_ACTION_LOG;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if( strcmp(type, "cfgchk") == 0 )
    {
        if( strcmp(action, "alw") == 0 )
        {
            msg.h.type = IPM_ALW_CFGCHK;
        }
        else if( strcmp(action, "inh") == 0 )
        {
            msg.h.type = IPM_INH_CFGCHK;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }

        if( i_arg == NULL ||
            strlen(i_arg) == 0 )
        {
            msg.cmd_ipm_admin.data = EIPM_MAX_EXT_SUB;
        }
        else
        {
            msg.cmd_ipm_admin.data = atoi(i_arg);

            if( msg.cmd_ipm_admin.data < 0 || 
                msg.cmd_ipm_admin.data > EIPM_MAX_EXT_SUB )
            {
                CLI_LOG("ipm_cli: ipm_handle_admin_request() CfgChk Idx - out of range %s\n", i_arg);
                return IPM_CLI_RET_BAD_VALUE;
            }
        }
    }
    else if( strcmp(type, "events") == 0 )
    {
        if( strcmp(action, "report") == 0 )
        {
            msg.h.type = IPM_REPORT_EVENTS;
        }
        else if( strcmp(action, "clr") == 0 )
        {
            msg.h.type = IPM_CLEAR_EVENTS;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if( strcmp(type, "status") == 0 )
    {
        if( strcmp(action, "dump") == 0 )
        {
            msg.h.type = IPM_DUMP_STATUS;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if( strcmp(type, "shm") == 0 )
    {
        if( strcmp(action, "dump") == 0 )
        {
            msg.h.type = IPM_DUMP_SHM;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if( strcmp(type, "ctx") == 0 )
    {
        if( strcmp(action, "dump") == 0 )
        {
            msg.h.type = IPM_DUMP_CTX;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }
    }
	else if (strcmp(type, "alarm") == 0)
	{
        if( strcmp(action, "dump") == 0 )
        {
            msg.h.type = IPM_DUMP_ALARM;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }
	}
    else if( strcmp(type, "iipmdebug") == 0 )
    {
        if( strcmp(action, "set") == 0 )
        {
            msg.h.type = IPM_SET_IIPM_DEBUG;

            if( i_arg != NULL &&
                strlen(i_arg) > 0 )
            {
                msg.cmd_ipm_admin.data = atoi(i_arg);
            }
            else
            {
                msg.cmd_ipm_admin.data = 1;
            }
        }
        else if( strcmp(action, "clr") == 0 )
        {
            msg.h.type = IPM_CLR_IIPM_DEBUG;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if( strcmp(type, "eipmdebug") == 0 )
    {
        if( strcmp(action, "set") == 0 )
        {
            msg.h.type = IPM_SET_EIPM_DEBUG;

            if( i_arg != NULL &&
                strlen(i_arg) > 0 )
            {
                msg.cmd_ipm_admin.data = atoi(i_arg);
            }
            else
            {
                msg.cmd_ipm_admin.data = 1;
            }
        }
        else if( strcmp(action, "clr") == 0 )
        {
            msg.h.type = IPM_CLR_EIPM_DEBUG;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if ( strcmp(type, "stats") == 0 )
    {
        if ( strcmp(action, "dump") == 0 )
        {
            msg.h.type = IPM_DUMP_STATS;
        }
        else
        {
            CLI_LOG(
                "ipm_cli: %s() Unsupported Action %s Type %s\n",
                __FUNCTION__,
                action,
                type
            );
            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if ( strcmp(type, "data") == 0 )
    {
        if ( strcmp(action, "dump") == 0 )
        {
            msg.h.type = IPM_DUMP_DATA;
        }
        else
        {
            CLI_LOG(
                "ipm_cli: %s() Unsupported Action %s Type %s\n",
                __FUNCTION__,
                action,
                type
            );
            return IPM_CLI_RET_BAD_ACTION;
        }
    }
    else if (strcmp(type, "soak_timer") == 0)
    {
	if (strcmp(action, "set") == 0)
	{
		if ((atoi(v_arg) < MIN_SOAK_TIME) || (atoi(v_arg) > MAX_SOAK_TIME))
		{
			CLI_LOG("ipm_cli: %s() Unsupported Value %s for Action %s Type %s\n",
				__FUNCTION__, v_arg, action, type);

			return IPM_CLI_RET_BAD_VALUE;
		}

		msg.h.type = IPM_SET_SOAK_TIMER;
		msg.cmd_ipm_admin.data = atoi(v_arg);
	}
	else
	{
		return IPM_CLI_RET_BAD_ACTION;
	}
    }
    else if ( strcmp(type, "session") == 0 )
    {
	if ( strcmp(action, "dump") == 0 )
	{
		msg.h.type = IPM_DUMP_SESSION;

		if ( strlen(i_arg) > 0 && strlen(gateway) == 0 )
		{
            		CLI_LOG(
 				"ipm_cli: %s() ip argument [%s] specified but not gateway\n",
				__FUNCTION__,
				i_arg
			);

			return IPM_CLI_RET_BAD_ACTION;
		}

		if ( strlen(gateway) > 0 && strlen(i_arg) == 0 )
		{
            		CLI_LOG(
 				"ipm_cli: %s() gateway argument [%s] specified but not ip\n",
				__FUNCTION__,
				i_arg
			);

			return IPM_CLI_RET_BAD_ACTION;
		}

		if ( strlen(i_arg) > 0 )
		{
			char *prefix_str;

    			prefix_str = strchr(i_arg, '/');
			if ( prefix_str != NULL )
			{
        			CLI_LOG(
					"ipm_cli: %s() incorrect format of ip [%s], don't need to specify prefix length\n",
					__FUNCTION__,
					i_arg
				);

				return IPM_CLI_RET_BAD_PREFIX;
			}

			strncpy(msg.cmd_ipm_admin.ip, i_arg, IPM_IPMAXSTRSIZE - 1);
			msg.cmd_ipm_admin.ip[IPM_IPMAXSTRSIZE - 1] = '\0';
		}

		if ( strlen(gateway) > 0 )
		{
			char *prefix_str;

    			prefix_str = strchr(gateway, '/');
			if ( prefix_str != NULL )
			{
        			CLI_LOG(
					"ipm_cli: %s() incorrect format of gateway [%s], don't need to specify prefix length\n",
					__FUNCTION__,
					gateway
				);

				return IPM_CLI_RET_BAD_PREFIX;
			}

			strncpy(msg.cmd_ipm_admin.gateway, gateway, IPM_IPMAXSTRSIZE -1);
			msg.cmd_ipm_admin.gateway[IPM_IPMAXSTRSIZE - 1] = '\0';
		}
	}
	else if ( strcmp(action, "set" ) == 0 )
	{
		msg.h.type = IPM_SET_SESSION;

		if ( strlen(i_arg) == 0 || strlen(gateway) == 0 || strlen(w_arg) == 0 )
		{
        		CLI_LOG(
				"ipm_cli: %s() the following was provided for ip [%s] gateway [%s] state [%s]\n",
				__FUNCTION__,
				( strlen(i_arg) > 0 ? i_arg : "empty" ),
				( strlen(gateway) > 0 ? gateway : "empty" ),
				( strlen(w_arg) > 0 ? w_arg : "empty" )
			);

			return IPM_CLI_RET_BAD_OPTION;
		}

		strncpy(msg.cmd_ipm_admin.ip, i_arg, IPM_IPMAXSTRSIZE - 1);
		msg.cmd_ipm_admin.ip[IPM_IPMAXSTRSIZE - 1] = '\0';
		strncpy(msg.cmd_ipm_admin.gateway, gateway, IPM_IPMAXSTRSIZE - 1);
		msg.cmd_ipm_admin.gateway[IPM_IPMAXSTRSIZE - 1] = '\0';

		if ( strcmp(w_arg, "enable") == 0 )
		{
			msg.cmd_ipm_admin.state = (int) BFD_ADMIN_STATE_UP;
		}
		else if ( strcmp( w_arg, "disable") == 0 )
		{
			msg.cmd_ipm_admin.state = (int) BFD_ADMIN_STATE_DOWN;
		}
		else
		{
        		CLI_LOG(
				"ipm_cli: %s() invalid state; specified [%s] when \"enable\" or \"disable\" are valid\n",
				__FUNCTION__,
				w_arg
			);

			return IPM_CLI_RET_BAD_OPTION;
		}
	}
	else
	{
            CLI_LOG(
                "ipm_cli: %s() Unsupported Action %s Type %s\n",
                __FUNCTION__,
                action,
                type
            );
            return IPM_CLI_RET_BAD_ACTION;
	}
    }
    else
    {
        CLI_LOG("ipm_cli: ipm_handle_admin_request() Unsupported Action %s Type %s\n", action, type);
        return IPM_CLI_RET_BAD_ACTION;
    }
    
    return ipm_send_client_msg(&msg);
}

int ipm_handle_proxy_path( char *action, char *type, char *ip, char *left, char *right )
{
struct nma_msgsocket_t msg;
char *myip;
char *prefix_str;
int prefix;

    // ipm_cli -a [add,del] -t [proxy,path] -i <ip/prefix> -l <iface> -r <iface>

    memset(&msg, 0, sizeof(msg));

    msg.h.size = sizeof(struct cmd_proxy_path);

    if( strcmp(action, "add") == 0 )
    {
        if( strcmp(type, "proxy") == 0 )
        {
            msg.h.type = IPM_ADD_PROXY;
        }
        else if( strcmp(type, "path") == 0 )
        {
            msg.h.type = IPM_ADD_PATH;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_proxy_path() Unsupported type %s\n", type);
            return IPM_CLI_RET_BAD_TYPE;
        }
    }
    else if( strcmp(action, "del") == 0 )
    {
        if( strcmp(type, "proxy") == 0 )
        {
            msg.h.type = IPM_DEL_PROXY;
        }
        else if( strcmp(type, "path") == 0 )
        {
            msg.h.type = IPM_DEL_PATH;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_proxy_path() Unsupported type %s\n", type);
            return IPM_CLI_RET_BAD_TYPE;
        }
    }
    else
    {
        CLI_LOG("ipm_cli: ipm_handle_proxy_path() Unsupported Action %s\n", action);
        return IPM_CLI_RET_BAD_ACTION;
    }

    if( strlen(ip) < 9 )
    {
        CLI_LOG("ipm_cli: ipm_handle_proxy_path() IP Format Error: %s\n", ip);
        return IPM_CLI_RET_BAD_IP;
    }

    prefix_str = strchr(ip, '/');
    if( prefix_str  == NULL )
    {
        CLI_LOG(" ipm_cli: ipm_handle_proxy_path() IP Prefix Format Error - prefix_str %s\n", ip);
        return IPM_CLI_RET_BAD_PREFIX;
    }

    prefix = atoi(prefix_str + 1);
    if( prefix < 0 ||
        prefix > 128 )
    {
        CLI_LOG("ipm_cli: ipm_handle_proxy_path() IP Prefix Format Error - out of range %s\n", ip);
        return IPM_CLI_RET_BAD_PREFIX;
    }
    else
    {
        msg.cmd_proxy_path.prefix = prefix;
    }

    myip = strtok(ip,"/");
    if (myip == NULL)
    {
        CLI_LOG("ipm_cli: ipm_handle_proxy_path() IP Format Error: %s\n", ip);
        return IPM_CLI_RET_BAD_IP;
    }

    if( strlen(myip) > IPM_IPMAXSTRSIZE )
    {
        CLI_LOG("ipm_cli: ipm_handle_proxy_path() IP Size Error: %s\n", myip);
        return IPM_CLI_RET_BAD_IP;
    }

    strncpy(msg.cmd_proxy_path.ip, myip, IPM_IPMAXSTRSIZE);

    if ((strlen(left) == 0) && (strlen(right) == 0))
    {
        CLI_LOG("ipm_cli: ipm_handle_proxy_path() Both Interfaces are Null\n");
        return IPM_CLI_RET_BAD_IFACE;
    }

    if( strlen(left) > 0 )
    {
        char *left_alias = strchr(left, ':');

        if( left_alias == NULL )
        {
            ipm_strncpy(msg.cmd_proxy_path.iface[0], left, MAX_NLEN_DEV);
        }
        else
        {
            strncpy(msg.cmd_proxy_path.iface[0], left, left_alias-left);
        }
    }

    if( strlen(right) > 0 )
    {
        char *right_alias = strchr(right, ':');

        if( right_alias == NULL )
        {
            ipm_strncpy(msg.cmd_proxy_path.iface[1], right, MAX_NLEN_DEV);
        }
        else
        {
            strncpy(msg.cmd_proxy_path.iface[1], right, right_alias-right);
        }
    }

    return ipm_send_client_msg(&msg);
}

int ipm_handle_proxy_server( char *action, char *type, char *ip, char *left, char *right, char *be_left, char *be_right, char *intFloatIp, char *pivot_id, char *vlan_id)
{
struct nma_msgsocket_t msg;
char *myip;
char *prefix_str;
int prefix;

    // ipm_cli -a [add,del] -t proxyserver,proxyclientaddr -i <ip/prefix> -l <fe-intf1> -r <fe-intf2> -b <be-intf1> -c <be-intf2>
    //
    // ipm_cli -a [add,del] -t [proxyclient] -i <ip/prefix> -l <iface> -r <iface>

    memset(&msg, 0, sizeof(msg));

    msg.h.size = sizeof(struct cmd_proxy_server);

    if( strcmp(action, "add") == 0 )
    {
        if( strcmp(type, "proxyserver") == 0 )
        {
            msg.h.type = IPM_ADD_PROXY_SERVER;
        }
        else if( strcmp(type, "proxyclientaddr") == 0 )
        {
            msg.h.type = IPM_ADD_PROXY_CLIENT_ADDR;
        }
        else if( strcmp(type, "proxyclient") == 0 )
        {
            msg.h.type = IPM_ADD_PROXY_CLIENT;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_proxy_server() Unsupported type %s\n", type);
            return IPM_CLI_RET_BAD_TYPE;
        }
    }
    else if( strcmp(action, "del") == 0 )
    {
        if( strcmp(type, "proxyserver") == 0 )
        {
            msg.h.type = IPM_DEL_PROXY_SERVER;
        }
        else if( strcmp(type, "proxyclientaddr") == 0 )
        {
            msg.h.type = IPM_DEL_PROXY_CLIENT_ADDR;
        }
        else if( strcmp(type, "proxyclient") == 0 )
        {
            msg.h.type = IPM_DEL_PROXY_CLIENT;
        }
        else
        {
            CLI_LOG("ipm_cli: ipm_handle_proxy_server() Unsupported type %s\n", type);
            return IPM_CLI_RET_BAD_TYPE;
        }
    }
    else
    {
        CLI_LOG("ipm_cli: ipm_handle_proxy_server() Unsupported Action %s\n", action);
        return IPM_CLI_RET_BAD_ACTION;
    }

    if( strlen(ip) < 9 )
    {
        CLI_LOG("ipm_cli: ipm_handle_proxy_server() IP Format Error: %s\n", ip);
        return IPM_CLI_RET_BAD_IP;
    }

    prefix_str = strchr(ip, '/');
    if( prefix_str == NULL )
    {
        CLI_LOG(" ipm_cli: ipm_handle_proxy_server() IP Prefix Format Error - prefix_str %s\n", ip);
        return IPM_CLI_RET_BAD_PREFIX;
    }

    prefix = atoi(prefix_str + 1);
    if( prefix < 0 ||
        prefix > 128 )
    {
        CLI_LOG("ipm_cli: ipm_handle_proxy_server() IP Prefix Format Error - out of range %s\n", ip);
        return IPM_CLI_RET_BAD_PREFIX;
    }
    else
    {
        msg.cmd_proxy_server.prefix = prefix;
    }

    myip = strtok(ip,"/");
    if (myip == NULL)
    {
        CLI_LOG("ipm_cli: ipm_handle_proxy_server() IP Format Error: %s\n", ip);
        return IPM_CLI_RET_BAD_IP;
    }

    if( strlen(myip) > IPM_IPMAXSTRSIZE )
    {
        CLI_LOG("ipm_cli: ipm_handle_proxy_server() IP Size Error: %s\n", myip);
        return IPM_CLI_RET_BAD_IP;
    }

    strncpy(msg.cmd_proxy_server.ip, myip, IPM_IPMAXSTRSIZE);

    if ((strlen(left) == 0) && (strlen(right) == 0))
    {
        CLI_LOG("ipm_cli: ipm_handle_proxy_path() Both Front End Interfaces are Null\n");
        return IPM_CLI_RET_BAD_IFACE;
    }

    if( strlen(left) > 0 )
    {
        ipm_strncpy(msg.cmd_proxy_server.fe_iface[0], left, MAX_NLEN_DEV);
    }

    if( strlen(right) > 0 )
    {
        ipm_strncpy(msg.cmd_proxy_server.fe_iface[1], right, MAX_NLEN_DEV);
    }
    if (strlen(pivot_id) > 0)
    {
	long tmp_pivot_id = strtol(pivot_id, (char**)NULL, 10);
        if (tmp_pivot_id < 0 || tmp_pivot_id >= MAX_NUM_PIVOT)
        {
            CLI_LOG("ipm_cli: ipm_handle_proxy_server() pivot id is out of range: %d\n", tmp_pivot_id);
            return IPM_CLI_RET_BAD_VALUE;
        }
        msg.cmd_proxy_server.pivot_id = (unsigned char)tmp_pivot_id;
    }

    if (strlen(vlan_id) > 0)
    {
        long tmp_vlanid = strtol(vlan_id, (char**) NULL, 10);
        if (tmp_vlanid < 0 || tmp_vlanid >= 4096)
        {
            CLI_LOG("ipm_cli: ipm_handle_proxy_server() external vlan id is out of range: %d\n", tmp_vlanid);
            return IPM_CLI_RET_BAD_VALUE;
        }
        msg.cmd_proxy_server.vlanId = (unsigned short) tmp_vlanid;
    }

    if( msg.h.type == IPM_ADD_PROXY_SERVER ||
        msg.h.type == IPM_DEL_PROXY_SERVER ||
        msg.h.type == IPM_ADD_PROXY_CLIENT_ADDR ||
        msg.h.type == IPM_DEL_PROXY_CLIENT_ADDR )
    {
        if ((strlen(be_left) == 0) && (strlen(be_right) == 0))
        {
            CLI_LOG("ipm_cli: ipm_handle_proxy_server() Both Back End Interfaces are Null\n");
            return IPM_CLI_RET_BAD_IFACE;
        }

        if( strlen(be_left) > 0 )
        {
            ipm_strncpy(msg.cmd_proxy_server.be_iface[0], be_left, MAX_NLEN_DEV);
        }

        if( strlen(be_right) > 0 )
        {
            ipm_strncpy(msg.cmd_proxy_server.be_iface[1], be_right, MAX_NLEN_DEV);
        }

	if( strlen(intFloatIp) > 0 )
	{
	    strcpy(msg.cmd_proxy_server.intFloatIp, intFloatIp);
	}

    }

    return ipm_send_client_msg(&msg);
}

int ipm_handle_stats_request( char *action, char *iface, char *count, char *value )
{
struct nma_msgsocket_t msg;

    //  ipm_cli -a get -t stats -i [all,internal,external,<interface>]
    //  ipm_cli -a clr -t stats -i [all,internal,external,<interface>] [-c <count>]

    //  ipm_cli -a set -t stats -i [all,internal,external,<interface>] [-c <count>] [-d <value>]

    memset(&msg, 0, sizeof(msg));
    msg.h.size = sizeof(struct cmd_stats_request);

    if( strcmp(action, "get") == 0 )
    {
        msg.h.type = IPM_GET_STATS;
    }
    else if( strcmp(action, "clr") == 0 )
    {
        msg.h.type = IPM_CLR_STATS;
    }
    else if( strcmp(action, "set") == 0 )
    {
        msg.h.type = IPM_SET_STATS;
    }
    else
    {
        CLI_LOG("ipm_cli: ipm_handle_stats_request() Unsupported Action %s\n", action);
        return IPM_CLI_RET_BAD_ACTION;
    }

    if( strlen(iface) > 0 )
    {
        strncpy(msg.cmd_stats_request.iface, iface, MAX_NLEN_DEV);
    }
    else
    {
        CLI_LOG("ipm_cli: ipm_handle_stats_request() Interface is Null\n");
        return IPM_CLI_RET_BAD_IFACE;
    }

    if( strlen(count) > 0 )
    {
        strncpy(msg.cmd_stats_request.count, count, MAX_STATS_COUNT-1);
    }
    else
    {
        strcpy(msg.cmd_stats_request.count, "all");
    }

    if( strlen(value) > 0 )
    {
        msg.cmd_stats_request.value = atoi(value);
    }
    else
    {
        msg.cmd_stats_request.value = 1;
    }

    return ipm_send_client_msg(&msg);
}


int ipm_handle_side_request( char *action, char *iface )
{
struct nma_msgsocket_t msg;

    // ipm_cli -a [get,set] -t side -i [lsn0,lsn1,<interface>]

    memset(&msg, 0, sizeof(msg));
	
    msg.h.size = sizeof(struct cmd_side_selection);

    if( strcmp(action, "get") == 0 )
    {
        msg.h.type = IPM_GET_SIDE;
    }
    else if( strcmp(action, "set") == 0 )
    {
        msg.h.type = IPM_SET_SIDE;
    }
    else
    {
        CLI_LOG("ipm_cli: ipm_handle_side_request() Unsupported Action %s\n", action);
        return IPM_CLI_RET_BAD_ACTION;
    }

    if( strlen(iface) > 0 )
    {
        strncpy(msg.cmd_side_selection.iface, iface, MAX_NLEN_DEV);
    }
    else
    {
        CLI_LOG("ipm_cli: ipm_handle_side_request() Interface is Null\n");
        return IPM_CLI_RET_BAD_IFACE;
    }

    return ipm_send_client_msg(&msg);
}
int ipm_handle_subnet_request(
    char *action,
    char *type,
    char *ip,
    char *mode,
    char *tablenum_ptr,
    char *gateway,
    char *primary_iface,
    char *secondary_iface,
    char *u_arg,
    char *x_arg,
    char *y_arg
)
{
	struct nma_msgsocket_t msg;

	char *subnet_base;
	char *prefix_str;
	char *p_iface;
	char *s_iface;

	int prefix;
	int ret;
	int set_flag=0;
	int del_flag=0;
	int clr_rttable_flag=0;

	/* 
		ipm_cli -a [add,del] -t subnet -i <subnet base>/<prefix> -m <redundancy mode> -g <primary gw ip> -l <primary interface> -r <secondary interface>

		ipm_cli -a [add,del] -t subnet -i <subnet base>/<prefix> -m eipm_bfd -l <primary interface> -r <secondary interface>

		ipm_cli -a [add,del] -t subnet -i <subnet base>/<prefix> -m <redundancy mode> [{-l <primary interface>} | {-r <secondary interface>}] -u <detection multiplier> -x <desired min tx interval> -y <required min rxinterval> 

		- where redundancy mode must be bfd_transport or eipm_arpndp to set the additional parameters

		ipm_cli -a set -t subnet -i <subnet base>/<prefix> -u <detection multiplier> -x <desired min tx interval> -y <required min rx interval>

		ipm_cli -a set -t subnet -i <subnet base>/<prefix> -n <table number>
     */ 

	memset(&msg, 0, sizeof(msg));
	msg.h.size = sizeof(struct cmd_subnet_upd);

	/* set the message type of action performing */
	if ( strcmp(action, "add") == 0 )
	{
		if(strlen(tablenum_ptr) == 0)
		{
			clr_rttable_flag = 1;
		}
	}
	else if ( strcmp(action, "del") == 0 )
	{
		del_flag = 1;
	} 
	else if ( strcmp(action, "set") == 0 )
	{
		set_flag = 1;
		msg.h.type = IPM_SET_SUBNET;
		if((strlen(tablenum_ptr) == 0) && (strlen(u_arg) == 0 && strlen(x_arg) == 0 && strlen(y_arg) == 0))
		{
			CLI_LOG(
				"ipm_cli: %s() No arguments for action %s\n",
				__FUNCTION__,
				action
			);
			return IPM_CLI_RET_BAD_ACTION;
		}
	}
	else if ( strcmp(action, "clr") == 0 )
	{
		if(strlen(tablenum_ptr) != 0)
		{
			CLI_LOG(
				"ipm_cli: %s() tablenum should be none for action %s\n",
				__FUNCTION__,
				action
			);
			return IPM_CLI_RET_BAD_ACTION;
		}
		clr_rttable_flag = 1;
		msg.h.type = IPM_SET_SUBNET;
		set_flag = 1;
	}
	else
	{
		CLI_LOG(
			"ipm_cli: %s() Unsupported Action %s\n",
			__FUNCTION__,
			action
		);
		return IPM_CLI_RET_BAD_ACTION;
	}

	if(strlen(tablenum_ptr) > 0)
	{
		//Use long to accept the tablenum, otherwiese tablenum would be trunctated when it is larger than 256
		long tmp_table_num = strtol( tablenum_ptr, NULL, 10);
		if(tmp_table_num < 0 || tmp_table_num > EIPM_MAX_RTTABLES)
		{
			CLI_LOG("ipm_cli: %s() unsupported tablenum %d for action %s\n",
				__FUNCTION__,
				tmp_table_num,	
				action);
			return IPM_CLI_RET_BAD_TABLE_NUM;
		}
		msg.cmd_subnet_upd.table_num = (unsigned char) tmp_table_num;
	}
	else
	{
		//table number is not set, there are two cases
		//	1) "clr" action for SBPR: deactivate SBPR
		//	2) "set" action for parameters u, x, y: keep SBPR no change
		if(clr_rttable_flag == 1)
		{
			//default value is 0, deactivate SBPR
			msg.cmd_subnet_upd.table_num = (unsigned char) 0;
		}
		else
		{
			//ipm does not update table_num when received 255
			msg.cmd_subnet_upd.table_num = (unsigned char) 255;
		}
	}

	if ( strlen(ip) > 0 )
	{
		/* check valid subnet base and prefix */
		prefix_str = strchr(ip, '/'); 
		if ( prefix_str == NULL )
		{
			CLI_LOG(
				"ipm_cli: %s() <Subnet Base>/<prefix> Format Error - %s\n",
				__FUNCTION__,
				ip
			);
			return IPM_CLI_RET_BAD_PREFIX;
		}

		prefix = atoi(prefix_str + 1);
		if ( prefix < 0 ||
		     prefix > 128 )
		{
			CLI_LOG(
				"ipm_cli: %s() Prefix Format Error - %d\n",
				__FUNCTION__,
				prefix
			);
			return IPM_CLI_RET_BAD_PREFIX;
		}

		msg.cmd_subnet_upd.prefix = prefix;

		subnet_base = strtok(ip, "/");
		if ( subnet_base == NULL )
		{
			CLI_LOG(
				"ipm_cli: %s() <Subnet Base>/<prefix> Format Error - %s\n",
				__FUNCTION__,
				ip
			);
			return IPM_CLI_RET_BAD_PREFIX;
		}

		if ( strlen( subnet_base ) > IPM_IPMAXSTRSIZE )
		{
			CLI_LOG(
				"ipm_cli: %s() Subnet Base Format Error - %s\n",
				__FUNCTION__,
				subnet_base
			);
			return IPM_CLI_RET_BAD_IP;
		}

		strncpy(msg.cmd_subnet_upd.subnet_base, subnet_base, IPM_IPMAXSTRSIZE - 1);
		msg.cmd_subnet_upd.subnet_base[IPM_IPMAXSTRSIZE - 1] = '\0';
	}
	else
	{
		CLI_LOG(
			"ipm_cli: %s() <subnet base>/<prefix len> is not set\n",
			__FUNCTION__
		);
		return IPM_CLI_RET_BAD_PREFIX;
	}

	if ( strlen(mode) > 0 && !del_flag )
	{
		if ( strcmp( mode, "none" ) == 0 ||
		     strcmp( mode, "iipm" ) == 0 ||
		     strcmp( mode, "eipm_acm" ) == 0 ||
		     strcmp( mode, "eipm_bfd" ) == 0 ||
		     strcmp( mode, "eipm_wcnp" ) == 0 ||
		     strcmp( mode, "eipm_arpndp" ) == 0 ||
                     strcmp( mode, "bfd_rsr" ) == 0 ||
		     strcmp( mode, "bfd_transport" ) == 0 )
		{
			if ( strcmp( mode, "none" ) == 0 )
			{
				msg.cmd_subnet_upd.redundancy_mode = (int) IPM_RED_NONE;
			}
			else if ( strcmp( mode, "iipm" ) == 0 )
			{
				msg.cmd_subnet_upd.redundancy_mode = (int) IPM_RED_IIPM;
			}
			else if ( strcmp( mode, "eipm_acm" ) == 0 )
			{
				msg.cmd_subnet_upd.redundancy_mode = (int) IPM_RED_EIPM_ACM;
			}
			else if ( strcmp( mode, "eipm_bfd" ) == 0 )
			{
				msg.cmd_subnet_upd.redundancy_mode = (int) IPM_RED_EIPM_BFD;
			}
			else if ( strcmp( mode, "bfd_rsr" ) == 0 )
			{
				msg.cmd_subnet_upd.redundancy_mode = (int) IPM_RED_BFD_RSR;
			}
			else if ( strcmp( mode, "bfd_transport" ) == 0 )
			{
				msg.cmd_subnet_upd.redundancy_mode = (int) IPM_RED_BFD_TRANSPORT;
			}
			else if ( strcmp( mode, "eipm_wcnp" ) == 0 )
			{
				//There are 5 wcnp subnet types monitored by IPM, those subnet types 
				//is identified by wcnp IP types. So the real subnet type will be overwritten
				//at IP plumb time, here we only set a default value for the 1st time
				msg.cmd_subnet_upd.redundancy_mode = (int) IPM_RED_EIPM_WCNP_SERVICE;
			}
			else if ( strcmp( mode, "eipm_arpndp" ) == 0 )
			{
				msg.cmd_subnet_upd.redundancy_mode = (int) IPM_RED_EIPM_ARPNDP;
			}

		}
		else
		{
			CLI_LOG(
				"ipm_cli: %s() Redundancy Mode not supported - %s\n",
				__FUNCTION__,
				mode
			);
			return IPM_CLI_RET_BAD_RED_MODE;
		}
	}
	else
	{
		if ( !set_flag && !del_flag )
		{
			CLI_LOG(
				"ipm_cli: %s() Redundant Mode not specified\n",
				__FUNCTION__
			);
			return IPM_CLI_RET_BAD_RED_MODE;
		}
	}

	if ( strlen(gateway) > 0 && !set_flag && !del_flag )
	{
		if( strlen(gateway) > IPM_IPMAXSTRSIZE )
		{
			CLI_LOG(
				"ipm_cli: %s() Gateway IP Error: %s\n",
				__FUNCTION__,
				gateway
			);
			return IPM_CLI_RET_BAD_IP;
		}


		if ( (IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_EIPM_BFD ||
                     (IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_BFD_RSR )
		{
			CLI_LOG(
				"ipm_cli: %s() Gateway IP [%s] should not be specified for redundancy mode [%s]\n",
				__FUNCTION__,
				gateway,
				mode
			);
			return IPM_CLI_RET_BAD_IP;
		}

		strncpy(msg.cmd_subnet_upd.gateway, gateway, IPM_IPMAXSTRSIZE - 1);
		msg.cmd_subnet_upd.gateway[IPM_IPMAXSTRSIZE - 1] = '\0';
	}
	else
	{
		if ( !set_flag )
		{
			if ( (IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_BFD_TRANSPORT )
			{
				CLI_LOG(
					"ipm_cli: %s() Gateway IP empty\n",
					__FUNCTION__
				);
				return IPM_CLI_RET_BAD_IP;
			}
		}
	}

	if ( strlen(primary_iface) > 0 && !set_flag )
	{
		ret = ipm_populate_subnet_msg(
				action,
				type,
				primary_iface,
				&msg.h.type,
				msg.cmd_subnet_upd.redundancy_mode,
				&msg.cmd_subnet_upd.dev_t[0]
		);

		if (ret != IPM_CLI_RET_SUCCESS)
		{
			return ret;
		}
	}
	else
	{
		if ( !set_flag && !del_flag )
		{
			if ( !((IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_NONE || 
			       (IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_IIPM ||
			       (IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_EIPM_ARPNDP ||
			       (IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_BFD_TRANSPORT) )
			{
				CLI_LOG(
					"ipm_cli: %s() Primary Iface empty\n",
					__FUNCTION__
				);

				return IPM_CLI_RET_BAD_IFACE;
			}
		}
	}

	if ( strlen(secondary_iface) > 0 && !set_flag )
	{
		ret = ipm_populate_subnet_msg(
				action,
				type,
				secondary_iface,
				&msg.h.type,
				msg.cmd_subnet_upd.redundancy_mode,
				&msg.cmd_subnet_upd.dev_t[1] 
			);

		if ( ret != IPM_CLI_RET_SUCCESS )
		{
			return ret;
		}
	}
	else
	{
		if ( !set_flag && !del_flag )
		{
			if ( !((IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_NONE ||
			     (IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_IIPM ||
			     (IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_EIPM_ARPNDP ||
			     (IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_BFD_TRANSPORT) )
			{
				CLI_LOG(
		       			"ipm_cli: %s() Secondary Iface empty\n",
		        		__FUNCTION__
				);

				return IPM_CLI_RET_BAD_IFACE;
			}
		}
	}

	if ( del_flag )
	{
		if ( strlen( primary_iface ) == 0 && strlen( secondary_iface ) == 0 )
		{
			CLI_LOG(
				"ipm_cli: %s() didn't specify an iface\n",
				__FUNCTION__
			);

			return IPM_CLI_RET_BAD_IFACE;
		}
	}

	if ( (IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_NONE ||
	     (IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_EIPM_ARPNDP ||
	     (IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_BFD_TRANSPORT )
	{
		if ( strlen(primary_iface) > 0 && strlen(secondary_iface) > 0 )
		{
			CLI_LOG(
			        "ipm_cli: %s() can only specify one interface for redundancy mode of [%s]\n",
			        __FUNCTION__,
				mode
			);

			return IPM_CLI_RET_BAD_IFACE;
		}

		if ( strlen(primary_iface) == 0 && strlen(secondary_iface) == 0 )
		{
			CLI_LOG(
				"ipm_cli: %s() need to specify one interface for redundancy mode of [%s]\n",
				__FUNCTION__,
				mode
			);

			return IPM_CLI_RET_BAD_IFACE;
		}
	}

	/* go through this code only if any of these parameters were set */
	if ( strlen(u_arg) != 0 || strlen(x_arg) != 0 || strlen(y_arg) != 0 )
	{
		if ( (IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode != IPM_RED_INVALID )
		{
			if ( !((IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_BFD_TRANSPORT ||
			       (IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_EIPM_ARPNDP) )
			{
				CLI_LOG(
					"ipm_cli: %s() cannot specify session parameters for [%s]\n",
					__FUNCTION__,
					mode
				);

				return IPM_CLI_RET_BAD_SESSION_PARAMETER;
			}
		}

		/* check to make sure all the session arguments are set */
		if ( strlen(u_arg) == 0 || strlen(x_arg) == 0 || strlen(y_arg) == 0 )
		{
			CLI_LOG(
				"ipm_cli: %s() invalid session parameters: detection_multiplier [%s] desired_min_tx_interval [%s] required_min_rx_interval [%s]\n",
				__FUNCTION__,
				( strlen(u_arg) > 0 ? u_arg : "empty" ),
				( strlen(x_arg) > 0 ? x_arg : "empty" ),
				( strlen(y_arg) > 0 ? y_arg : "empty" )
			);

			return IPM_CLI_RET_BAD_SESSION_PARAMETER;
		}

		sscanf(u_arg, "%u", &msg.cmd_subnet_upd.detection_multiplier);
		if ( msg.cmd_subnet_upd.detection_multiplier < 3 || msg.cmd_subnet_upd.detection_multiplier > 50 )
		{
			CLI_LOG(
				"ipm_cli: %s() invalid detection_multiplier [%s]\n",
				__FUNCTION__,
				u_arg
			);

			return IPM_CLI_RET_BAD_SESSION_PARAMETER;
		}

		sscanf(x_arg, "%u", &msg.cmd_subnet_upd.desired_min_tx_interval);
		if ( msg.cmd_subnet_upd.desired_min_tx_interval < 1 || msg.cmd_subnet_upd.desired_min_tx_interval > 1000 )
		{
			CLI_LOG(
				"ipm_cli: %s() invalid desired_min_tx_interval [%s]\n",
				__FUNCTION__,
				x_arg
			);

			return IPM_CLI_RET_BAD_SESSION_PARAMETER;
		}
		msg.cmd_subnet_upd.desired_min_tx_interval *= 100;

		sscanf(y_arg, "%u", &msg.cmd_subnet_upd.required_min_rx_interval);
		if ( msg.cmd_subnet_upd.required_min_rx_interval < 1 || msg.cmd_subnet_upd.required_min_rx_interval > 1000 )
		{
			CLI_LOG(
				"ipm_cli: %s() invalid required_min_rx_interval [%s]\n",
				__FUNCTION__,
				y_arg
			);

			return IPM_CLI_RET_BAD_SESSION_PARAMETER;
		}
		msg.cmd_subnet_upd.required_min_rx_interval *= 100;

	}
	else
	{
			if ( !del_flag  &&
			     ( (IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_BFD_TRANSPORT ||
			       (IPM_REDUNDANCY_MODE) msg.cmd_subnet_upd.redundancy_mode == IPM_RED_EIPM_ARPNDP ) )
			{
				CLI_LOG(
					"ipm_cli: %s() no session parameters specified\n",
					__FUNCTION__
				);

				return IPM_CLI_RET_BAD_SESSION_PARAMETER;
			}
	}

	return ipm_send_client_msg(&msg);
}

int ipm_handle_tunnel_request(
    char *action,
    char *type,
    char *lepip,
    char *repip,
    char *name,
    char *opt //id:key:ttl
)
{
	struct nma_msgsocket_t msg;
	char key[16];
	char id[16];
	char ttl[16];
	char *token;
	char *lasts;
	char *search = ":";

	memset(&msg, 0, sizeof(msg));
	msg.h.size = sizeof(struct cmd_tunnel_upd);
	if(strcmp(action, "add") == 0)
	{
		msg.h.type = IPM_ADD_TUNNEL;
	}
	else if(strcmp(action, "del") == 0)
	{
		msg.h.type = IPM_DEL_TUNNEL;
	}
	else
	{
		CLI_LOG("ipm_cli: %s() invalid parameter: action [%s]\n",
		    __FUNCTION__, action);

		return IPM_CLI_RET_BAD_TUNNEL_PARAMETER;        
	}


	token = strtok_r(opt, search, &lasts);
	if(token == NULL || strlen(lasts) == 0)
	{
		CLI_LOG("ipm_cli: %s() invalid parameter: opt [%s]\n",
			__FUNCTION__, opt)
		return IPM_CLI_RET_BAD_TUNNEL_PARAMETER;
	}
	msg.cmd_tunnel_upd.id = atoi(token);
	if(msg.cmd_tunnel_upd.id == 0 || msg.cmd_tunnel_upd.id > 255)
	{
		CLI_LOG("ipm_cli: %s() invalid parameter: id [%d]\n",
		    __FUNCTION__, msg.cmd_tunnel_upd.id);

		return IPM_CLI_RET_BAD_TUNNEL_PARAMETER;
	}    

	token = strtok_r(NULL, search, &lasts);
	if(token == NULL || strlen(lasts) == 0)
	{
		CLI_LOG("ipm_cli: %s() invalid parameter: opt [%s]\n",
			__FUNCTION__, opt)
		return IPM_CLI_RET_BAD_TUNNEL_PARAMETER;
	}
	msg.cmd_tunnel_upd.key = atoi(token);
	if(msg.cmd_tunnel_upd.key == 0 || msg.cmd_tunnel_upd.key > 255)
	{
		CLI_LOG("ipm_cli: %s() invalid parameter: key [%d]\n",
		    __FUNCTION__,  msg.cmd_tunnel_upd.key);

		return IPM_CLI_RET_BAD_TUNNEL_PARAMETER;
	}    


	token = strtok_r(NULL, search, &lasts);
	/*Length of lasts is 0 this time as "id:key:ttl" contains 2 ":"*/
	if(token == NULL)
	{
		CLI_LOG("ipm_cli: %s() invalid parameter: opt [%s]\n",
			__FUNCTION__, opt)
		return IPM_CLI_RET_BAD_TUNNEL_PARAMETER;
	}
	msg.cmd_tunnel_upd.ttl = atoi(token);
	if(msg.cmd_tunnel_upd.ttl == 0 || msg.cmd_tunnel_upd.ttl > 255)
	{
		CLI_LOG("ipm_cli: %s() invalid parameter: ttl [%d]\n",
		    __FUNCTION__, msg.cmd_tunnel_upd.ttl);

		return IPM_CLI_RET_BAD_TUNNEL_PARAMETER;
	}

	ipm_strncpy(msg.cmd_tunnel_upd.lepip, lepip, sizeof(msg.cmd_tunnel_upd.lepip));
	ipm_strncpy(msg.cmd_tunnel_upd.repip, repip, sizeof(msg.cmd_tunnel_upd.repip));
	ipm_strncpy(msg.cmd_tunnel_upd.name, name, sizeof(msg.cmd_tunnel_upd.name));

	return ipm_send_client_msg(&msg);
}

int
ipm_cli_main( int argc, char *argv[] )
{
unsigned int MAX_PARA_SIZE=128;
int  opt_arg;
int  ret;
char action_arg[MAX_PARA_SIZE];
char type_arg[MAX_PARA_SIZE];
char subnet_type_arg[MAX_PARA_SIZE];
char left_arg[MAX_PARA_SIZE];
char right_arg[MAX_PARA_SIZE];
char be_left_arg[MAX_PARA_SIZE];
char be_right_arg[MAX_PARA_SIZE];
char ip_arg[MAX_PARA_SIZE];
char dest_arg[MAX_PARA_SIZE];
char gateway_arg[MAX_PARA_SIZE];
char priority_arg[MAX_PARA_SIZE];
char mode_arg[MAX_PARA_SIZE];
char p_arg[MAX_PARA_SIZE];
char u_arg[MAX_PARA_SIZE];
char w_arg[MAX_PARA_SIZE];
char x_arg[MAX_PARA_SIZE];
char y_arg[MAX_PARA_SIZE];
char v_arg[MAX_PARA_SIZE];
char vlan_arg[8];
char exvlan_arg[MAX_PARA_SIZE];
char tablenum_arg[8];
char tlepip_arg[MAX_PARA_SIZE]; //tunnel local end point IP
char trepip_arg[MAX_PARA_SIZE]; //tunnel remote end point IP
char tttl_arg[8];               //tunnel ttl
char tkey_arg[MAX_PARA_SIZE];   //tunnel key
char tname_arg[MAX_PARA_SIZE];  //tunnel name 
char topt_arg[MAX_PARA_SIZE];  //tunnel option id:key:ttl

extern char *optarg;
	
    action_arg[0] = '\0';
    type_arg[0] = '\0';
    subnet_type_arg[0] = '\0';
    left_arg[0] = '\0';
    right_arg[0] = '\0';
    be_left_arg[0] = '\0';
    be_right_arg[0] = '\0';
    ip_arg[0] = '\0';
    dest_arg[0] = '\0';
    gateway_arg[0] = '\0';
    priority_arg[0] = '\0';
    mode_arg[0] = '\0';
    p_arg[0] = '\0';
    u_arg[0] = '\0';
    w_arg[0] = '\0';
    x_arg[0] = '\0';
    y_arg[0] = '\0';
    v_arg[0] = '\0';
    vlan_arg[0] = '\0';
    exvlan_arg[0] = '\0';
    tablenum_arg[0] = '\0';
    tttl_arg[0] = '\0';
    tlepip_arg[0] = '\0';
    trepip_arg[0] = '\0';
    tkey_arg[0] = '\0';
    tname_arg[0] = '\0';
    topt_arg[0] = '\0';

#if 0
    while( (opt_arg = getopt(argc, argv, "a:t:s:l:r:b:c:i:d:g:p:nhm:u:x:y:w:")) != EOF )
#endif
    while( (opt_arg = getopt(argc, argv, "a:t:s:l:r:b:c:i:d:g:p:q:n:hm:u:x:y:w:v:e:f:k:o:z:")) != EOF )
    {
        switch( opt_arg )
        {
        case 'a':
            GETOPT_CHECK( "a" );
            ipm_strncpy(action_arg, optarg, MAX_PARA_SIZE);
            break;

        case 't':
            GETOPT_CHECK( "t" );
            ipm_strncpy(type_arg, optarg, MAX_PARA_SIZE);
            break;

        case 's':
            GETOPT_CHECK( "s" );
            ipm_strncpy(subnet_type_arg, optarg, MAX_PARA_SIZE);
            break;

        case 'l':
            GETOPT_CHECK( "l" );
            ipm_strncpy(left_arg, optarg, MAX_PARA_SIZE);
            break;

        case 'r':
            GETOPT_CHECK( "r" );
            ipm_strncpy(right_arg, optarg, MAX_PARA_SIZE);
            break;

        case 'b':
            GETOPT_CHECK( "b" );
            ipm_strncpy(be_left_arg, optarg, MAX_PARA_SIZE);
            break;

        case 'c':
            GETOPT_CHECK( "c" );
            ipm_strncpy(be_right_arg, optarg, MAX_PARA_SIZE);
            break;

        case 'i':
            GETOPT_CHECK( "i" );
            ipm_strncpy(ip_arg, optarg, MAX_PARA_SIZE);
            break;

        case 'd':
            GETOPT_CHECK( "d" );
            ipm_strncpy(dest_arg, optarg, MAX_PARA_SIZE);
            break;

        case 'g':
            GETOPT_CHECK( "g" );
            ipm_strncpy(gateway_arg, optarg, MAX_PARA_SIZE);
            break;

        case 'p':
            GETOPT_CHECK( "p" );
            ipm_strncpy(priority_arg, optarg, MAX_PARA_SIZE);
            break;

        case 'h':
            ipm_cli_menu();
            return IPM_CLI_RET_SUCCESS;
            break;

        case 'n':
	    GETOPT_CHECK( "n" );
	    strncpy(tablenum_arg, optarg, sizeof(tablenum_arg));
            break;
	case 'q':
                GETOPT_CHECK( "q" );
                strncpy(vlan_arg, optarg, 7);
		vlan_arg[7] = 0;
                break;


	case 'm':
		GETOPT_CHECK( "m" );
		ipm_strncpy(mode_arg, optarg, MAX_PARA_SIZE);
		break;

	case 'u':
		GETOPT_CHECK( "u" );
		ipm_strncpy(u_arg, optarg, MAX_PARA_SIZE);
		break;

	case 'w':
		GETOPT_CHECK( "w" );
		ipm_strncpy(w_arg, optarg, MAX_PARA_SIZE);
		break;

	case 'x':
		GETOPT_CHECK( "x" );
		ipm_strncpy(x_arg, optarg, MAX_PARA_SIZE);
		break;

	case 'y':
		GETOPT_CHECK( "y" );
		ipm_strncpy(y_arg, optarg, MAX_PARA_SIZE);
		break;

	case 'v':
		GETOPT_CHECK("v");
		ipm_strncpy(v_arg, optarg, MAX_PARA_SIZE);
		break;

        case 'e':
            GETOPT_CHECK("e");
            ipm_strncpy(tlepip_arg, optarg, MAX_PARA_SIZE);
            break;

        case 'f':
            GETOPT_CHECK("f");
            ipm_strncpy(trepip_arg, optarg, MAX_PARA_SIZE);
            break;

        case 'k':
            GETOPT_CHECK("k");
            ipm_strncpy(tname_arg, optarg, MAX_PARA_SIZE);
            break;

        case 'o':
            GETOPT_CHECK("o");
            ipm_strncpy(topt_arg, optarg, MAX_PARA_SIZE);
            break;            

	case 'z':
		GETOPT_CHECK("z");
		ipm_strncpy(exvlan_arg, optarg, MAX_PARA_SIZE);
		break;

        default:
            ipm_cli_menu();
            return IPM_CLI_RET_BAD_OPTION;
        }
    }

    if( strcmp(action_arg, "garp") == 0 )
    {
        ret = ipm_handle_garp_request(action_arg, type_arg, subnet_type_arg, ip_arg);
    }
    else if( strcmp(type_arg, "stats") == 0 && strcmp(action_arg, "dump") != 0 )
    {
        ret = ipm_handle_stats_request(action_arg, ip_arg, be_right_arg, dest_arg);
    }
    else if( strcmp(type_arg, "side") == 0 )
    {
        ret = ipm_handle_side_request(action_arg, ip_arg);
    }
    else if( strcmp(type_arg, "base") == 0 )
    {
        ret = ipm_handle_base_request(action_arg, left_arg, right_arg, subnet_type_arg);
    }
    else if( strcmp(type_arg, "alias") == 0 ||
             strcmp(type_arg, "lsn") == 0 ||
             strcmp(type_arg, "wcnp_fix") == 0 ||
             strcmp(type_arg, "wcnp_active") == 0 ||
             strcmp(type_arg, "wcnp_standby") == 0 ||
             strcmp(type_arg, "internal") == 0 ||
             strcmp(type_arg, "external") == 0 )
    {
        ret = ipm_handle_alias_request(action_arg, type_arg, left_arg, right_arg, gateway_arg);
    }
    else if( strcmp(type_arg, "arp") == 0 )
    {
        ret = ipm_handle_arp_request(action_arg, ip_arg, priority_arg, left_arg, right_arg);
    }
    else if( strcmp(type_arg, "route") == 0 )
    {
        ret = ipm_handle_route_request(action_arg, dest_arg, gateway_arg, left_arg, right_arg, vlan_arg, ip_arg, exvlan_arg);
    }
    else if( strcmp(type_arg, "ipm") == 0  ||
             strcmp(type_arg, "iipm") == 0 ||
             strcmp(type_arg, "eipm") == 0 ||
             strcmp(type_arg, "pipm") == 0 ||
             strcmp(type_arg, "pipm_l2_path") == 0 ||
             strcmp(type_arg, "proxyserv") == 0 ||
             strcmp(type_arg, "logaction") == 0 ||
             strcmp(type_arg, "logcheck") == 0 ||
             strcmp(type_arg, "logremote") == 0 ||
             strcmp(type_arg, "loglocal") == 0 ||
             strcmp(type_arg, "iipmdebug") == 0 ||
             strcmp(type_arg, "eipmdebug") == 0 ||
             strcmp(type_arg, "syslog") == 0 ||
             strcmp(type_arg, "cfgchk") == 0 ||
             strcmp(type_arg, "events") == 0 ||
             strcmp(type_arg, "status") == 0 ||
             strcmp(type_arg, "shm") == 0 || 
             strcmp(type_arg, "soak_timer") == 0 ||
             strcmp(type_arg, "ctx") == 0 ||
             strcmp(type_arg, "alarm") == 0 || 
             strcmp(type_arg, "data") == 0 ||
             strcmp(type_arg, "stats") == 0 ||
             strcmp(type_arg, "session") == 0 )
    {
        ret = ipm_handle_admin_request(action_arg, type_arg, ip_arg, gateway_arg, w_arg, v_arg);
    }
    else if ( strcmp(type_arg, "proxyserver") == 0  ||
              strcmp(type_arg, "proxyclientaddr") == 0 ||
              strcmp(type_arg, "proxyclient") == 0 )
    {
            ret = ipm_handle_proxy_server(action_arg, type_arg, ip_arg, left_arg, right_arg, be_left_arg, be_right_arg, dest_arg, vlan_arg, exvlan_arg);
    }
    else if ( strcmp(type_arg, "proxy") == 0  ||
              strcmp(type_arg, "path") == 0 )
    {
            ret = ipm_handle_proxy_path(action_arg, type_arg, ip_arg, left_arg, right_arg);
    }
    else if ( strcmp(type_arg, "subnet") == 0 )
    {
        ret = ipm_handle_subnet_request(action_arg, type_arg, ip_arg, mode_arg, tablenum_arg, gateway_arg, left_arg, right_arg, u_arg, x_arg, y_arg);
    }
    else if ( strcmp(type_arg, "tunnel") == 0 )
    {
        ret = ipm_handle_tunnel_request(action_arg, type_arg, tlepip_arg, trepip_arg, tname_arg, topt_arg);
    }    
    else if( strlen(type_arg) == 0 )
    {
        ipm_cli_menu();
        return IPM_CLI_RET_BAD_OPTION;
    }
    else
    {
        CLI_LOG("ipm_cli: Unsupported Type %s\n", type_arg);
        return IPM_CLI_RET_BAD_TYPE;
    }
       
    return ret;
}

#if defined(_LIBRARY_IPM_CLI)
#define IPM_ARGV_MAX	256

int
ipm_comml( const char *arg, ... )
{
    int			argc;
    int			ret;
    const char *	initial_argv[IPM_ARGV_MAX];
    const char **	argv = initial_argv;
    va_list		args;

    argv[0] = "ipm_comml";
    argv[1] = arg;

    va_start (args, arg);
    argc = 2;
    do
    {
	if (argc == IPM_ARGV_MAX)
	{
		CLI_LOG("ipm_comml: arg cnt %d exceeds maximum\n", argc);
		return -1;
	}

	argv[argc] = va_arg (args, const char *);
    }
    while (argv[argc++] != NULL);

    va_end (args);

    argc--;

    optind = 0;

    ret = ipm_cli_main( argc, argv);
    /* These are negative values */
    if ((IPM_CLI_RET_BAD_PARAM_START >= ret) &&
        (ret >= IPM_CLI_RET_BAD_PARAM_END))
    {
	int	i;
	char	msg[1024];
	char *	s;

	s = &(msg[0]);
	for (i = 0; i < argc; i++)
	{
		s += sprintf(s, "%s ", argv[i]);
	}
	CLI_LOG("bad arguments: %s\n", msg);
    }
    return ret;
}

int
ipm_commv( const int argc, char *argv[] )
{
    int			i;
    int			ret;
    const char *	initial_argv[IPM_ARGV_MAX];
    const char **	nargv = initial_argv;

    if (argc >= IPM_ARGV_MAX)
    {
	CLI_LOG("ipm_commv: arg cnt %d exceeds maximum\n", argc);
	return -1;
    }

    nargv[0] = "ipm_commv";
    for (i = 0; i < argc; i++) {
 	nargv[i+1] = argv[i];
    }

    optind = 0;

    ret = ipm_cli_main(argc+1, nargv);
    /* These are negative values */
    if ((IPM_CLI_RET_BAD_PARAM_START >= ret) &&
        (ret >= IPM_CLI_RET_BAD_PARAM_END))
    {
	int	i;
	char	msg[1024];
	char *	s;

	s = &(msg[0]);
	for (i = 0; i < argc; i++)
	{
		s += sprintf(s, "%s ", argv[i]);
	}
	CLI_LOG("bad arguments: %s\n", msg);
    }
   return ret;
}

#else

int
main( int argc, char *argv[] )
{
    return ipm_cli_main(argc, argv);
}

#endif

void
ipm_cli_menu()
{
#if !defined(_LIBRARY_IPM_CLI)
        fprintf(stdout, "\nAdministrative Options:\n");
        fprintf(stdout, "-----------------------\n");
        fprintf(stdout, "ipm_cli -a [inh,alw] -t [ipm,iipm,eipm,pipm,pipm_l2_path,proxyserv,syslog,log{local,remote,check,action}]\n");
        fprintf(stdout, "ipm_cli -a get -t stats -i [all,internal,external,<interface>] \n");
        fprintf(stdout, "ipm_cli -a clr -t stats -i [all,internal,external,<interface>] \n");
        fprintf(stdout, "ipm_cli -a get -t side -i [all,internal,external,<interface>]\n");
        fprintf(stdout, "ipm_cli -a set -t side -i [lsn0,lsn1,<interface>]\n");
        fprintf(stdout, "ipm_cli -a [set,clr] -t {iipm,eipm}debug {-i <idx>}\n");
        fprintf(stdout, "ipm_cli -a [inh,alw] -t cfgchk -i <idx>\n");
        fprintf(stdout, "ipm_cli -a garp -i <{interface,}ip>\n");
        fprintf(stdout, "ipm_cli -a garp -t [fixed,float,all] -s [internal,external,all]\n");
        fprintf(stdout, "ipm_cli -a dump -t [data,stats,status,shm,ctx,session] {-i <local ip address>/<prefix len> -g <gateway>}\n");
        fprintf(stdout, "ipm_cli -a clr -t events\n");
        fprintf(stdout, "ipm_cli -a report -t events\n");
        fprintf(stdout, "\nConfiguration Options:\n");
        fprintf(stdout, "----------------------\n");
        fprintf(stdout, "ipm_cli -a [add,del] -t base -l <iface> -r <iface> {-s [internal,external]}\n");
        fprintf(stdout, "\tiface = [dev,dev.vlanid]\n");
        fprintf(stdout, "\tsubnet = optional, defaults to internal\n");
        fprintf(stdout, "\n");
        fprintf(stdout, "ipm_cli -a [add,del] -t [lsn,internal,external,alias] {-l <iface,ip/prefix>} {-r <iface,ip/prefix>} {-g <subnet gateway>}\n");
        fprintf(stdout, "\tiface  = dev[[.vlanid[.custvlan]]:instance]\n");
        fprintf(stdout, "\tip     = presentation format\n");
        fprintf(stdout, "\tprefix = 0 -> 128\n");
        fprintf(stdout, "\tsubnet gateway = presentation format\n");
        fprintf(stdout, "\n");
	fprintf(stdout, "ipm_cli -a [add,del] -t [wcnp_fix|wcnp_active|wcnp_standby] -l <iface,ip/prefix> -r <iface,ip/prefix>\n");
	fprintf(stdout, "\tiface  = dev[[.vlanid[.custvlan]]:instance]\n");
	fprintf(stdout, "\tip     = presentation format\n");
	fprintf(stdout, "\tprefix = 0 -> 128\n");
	fprintf(stdout, "\n");
        fprintf(stdout, "ipm_cli -a [add,del] -t arp -i <ip/prefix> -p <priority>\n");
        fprintf(stdout, "\tip       = presentation format\n");
        fprintf(stdout, "\tprefix   = 0 -> 128\n");
        fprintf(stdout, "\tpriority = 1 (highest) -> 4 (lowest)\n");
        fprintf(stdout, "\n");
        fprintf(stdout, "ipm_cli -a add -t route -d <dest/prefix> -g <gateway> [-i <source ip>]\n");
        fprintf(stdout, "ipm_cli -a del -t route -d <dest/prefix>\n");
        fprintf(stdout, "\tdest    = presentation format\n");
        fprintf(stdout, "\tprefix  = 0 -> 128\n");
        fprintf(stdout, "\tgateway = presentation format\n");
        fprintf(stdout, "ipm_cli -a [add,del] -t [proxy,path,proxyclient] -i <ip/prefix> -l <iface> -r <iface>\n");
        fprintf(stdout, "\tip     = presentation format\n");
        fprintf(stdout, "\tprefix = 0 -> 128\n");
        fprintf(stdout, "\tiface  = dev[[.vlanid[.custvlan]]:instance]\n");
        fprintf(stdout, "ipm_cli -a [add,del] -t [proxyserver,proxyclientaddr] -i <ip/prefix> -l <fe-intf1> -r <fe-intf2> -b <be-intf1> -c <be-intf2>\n");
        fprintf(stdout, "\tip     = presentation format\n");
        fprintf(stdout, "\tprefix = 0 -> 128\n");
        fprintf(stdout, "\tfe-intf  = [dev[.vlanid[.custvlan]]:instance]\n");
        fprintf(stdout, "\tbe-intf  = [dev[.vlanid[.custvlan]]:instance]\n");
	fprintf(stdout, "ipm_cli -a [add,del] -t subnet -i <subnet base>/<prefix> -m <redundancy mode> [-g <gateway ip>] -l <primary interface> -r <secondary interface>\n");
	fprintf(stdout, "\tsubnet               = presentation format\n");
	fprintf(stdout, "\tprefix               = 0 ->128\n");
	fprintf(stdout, "\tredundancy mode      = [none|iipm|eipm_acm|eipm_wcnp|eipm_bfd|bfd_transport|eipm_arpndp]\n");
	fprintf(stdout, "\tgateway ip           = presentation format\n");
	fprintf(stdout, "\tprimary interface    = [dev,dev:instance,dev.vlanid:instance]\n");
	fprintf(stdout, "\tsecondary interface  = [dev,dev:instance,dev.vlanid:instance]\n\n");
	fprintf(stdout, "ipm_cli -a [add,del] -t subnet -i <subnet base>/<prefix> -m <redundancy mode> [-l <primary interface>] | [-r <secondary interface>] {-u <detection multiplier> -x <desired min tx interval> -y <required min rx interval>}\n");
	fprintf(stdout, "\tsubnet               = presentation format\n");
	fprintf(stdout, "\tprefix               = 0 ->128\n");
	fprintf(stdout, "\tredundancy mode      = none,iipm,eipm_acm,eipm_bfd,bfd_transport,eipm_arpndp\n");
	fprintf(stdout, "\tprimary interface    = [dev,dev:instance,dev.vlanid:instance]\n");
	fprintf(stdout, "\tsecondary interface  = [dev,dev:instance,dev.vlanid:instance]\n");
	fprintf(stdout, "\tdetection multiplier interface = [3-50]\n");
	fprintf(stdout, "\tdesired min tx interval        = [1-1000 number of 100 msec interval]\n");
	fprintf(stdout, "\trequired min rx interval       = [1-1000 number of 100 msec interval]\n\n");
	fprintf(stdout, "ipm_cli -a set -t subnet -i <subnet base>/<prefix> -u <detection multiplier> -x <desired min tx interval> -y <required min rx interval>\n");
	fprintf(stdout, "\tdetection multiplier interface = [3-50]\n");
	fprintf(stdout, "\tdesired min tx interval        = [1-1000 number of 100 msec interval]\n");
	fprintf(stdout, "\trequired min rx interval       = [1-1000 number of 100 msec interval]\n\n");
	fprintf(stdout, "ipm_cli -a set -t subnet -i <subnet base>/<prefix> -n <table number>\n");
	fprintf(stdout, "\ttable number = [1-252]\n\n");
	fprintf(stdout, "ipm_cli -a set -t session -i <local ip> -g <gateway ip> -w <state of bfd session>\n");
	fprintf(stdout, "\tlocal ip             = presentation format\n");
	fprintf(stdout, "\tgateway ip           = presentation format\n");
	fprintf(stdout, "\tstate of bfd session = enable,disable\n\n");
	fprintf(stdout, "ipm_cli -a [add,del] -t tunnel -e <endpoint local IP> -f <endpiont remote IP> -k <tunnel name> -o <optional parameter>\n");
	fprintf(stdout, "\tendpoint local IP	 = presentation format\n");
	fprintf(stdout, "\tendpoint remote IP	 = presentation format\n");
	fprintf(stdout, "\ttunnel name			 = name \n");
	fprintf(stdout, "\toptional parameter	 = [id:key:ttl] \n\n");
        fprintf(stdout, "\nConfiguration Usage Example:\n");
        fprintf(stdout, "----------------------------\n");
        fprintf(stdout, "ipm_cli -a add -t base -l eth0.800 -r eth1.801\n");
        fprintf(stdout, "ipm_cli -a add -t lsn -l eth0.800:0,10.21.32.16/20 -r eth1.801:1,10.21.48.16/20\n");
	fprintf(stdout, "ipm_cli -a add -t internal -l eth0.800:1,10.21.64.16/20 -r eth1.801:1,10.21.64.16/20\n");
	fprintf(stdout, "ipm_cli -a add -t internal -l eth0.800:ABAAA,10.21.130.0/17 -r eth1.801:ABAAA,10.21.130.0/17\n");
        fprintf(stdout, "ipm_cli -a add -t base -l eth0.400 -r eth1.401\n");
	fprintf(stdout, "ipm_cli -a add -t external -l eth0.400:oBAAA,135.1.60.99/28 -r eth1.401:oBAAA,135.1.60.99/28\n");
        fprintf(stdout, "ipm_cli -a add -t arp -i 135.1.60.110/28 -p 1\n");
        fprintf(stdout, "ipm_cli -a add -t route -d 135.2.69.0/28 -g 10.21.64.16\n");
        fprintf(stdout, "ipm_cli -a add -t tunnel -e 10.161.218.0 -f 10.161.232.0 -k pivot1 -o 1:1:255\n");
#endif
}

