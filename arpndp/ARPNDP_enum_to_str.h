/*************************************************************************
 *
 * File:     ARPNDP_enum_to_str.h
 *
 * Abstract: internal header file of ARP/NDP enum-to-string module
 *           this module displays ARP/NDP enumerations as string
 *
 * Nodes:    ARP/NDP implemenation should include only ARPNDP_int_data.h
 *           instead of this file
 *
 ************************************************************************/

#ifndef ARPNDP_ENUM_TO_STR_H
#define ARPNDP_ENUM_TO_STR_H


/* function to display boolean as string */
const char *ARPNDP_BOOL_to_str (BOOL false_true);

/* function to display ARP/NDP session state as string */
const char *ARPNDP_SESS_STATE_to_str (ARPNDP_SESS_STATE sess_state);

/* function to display ARP/NDP administrative state as string */
const char *ARPNDP_ADMIN_STATE_to_str (ARPNDP_ADMIN_STATE sess_state);

/* function to display ARP/NDP history type as string */
const char *ARPNDP_HISTORY_TYPE_to_str (ARPNDP_HISTORY_TYPE history_type);

/* function to display ARP/NDP initialization type as string */
const char *ARPNDP_INIT_TYPE_to_str (ARPNDP_INIT_TYPE init_type);

/* function to display ARP/NDP audit sequence as string */
const char *ARPNDP_AUDIT_SEQ_to_str (ARPNDP_AUDIT_SEQ begin_middle_end);

/* function to display ARP/NDP protocol as string */
const char *ARPNDP_PROTOCOL_to_str (ARPNDP_PROTOCOL protocol);

#endif /* #ifndef ARPNDP_ENUM_TO_STR_H */
