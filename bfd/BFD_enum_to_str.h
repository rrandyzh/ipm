/*************************************************************************
 *
 * File:     BFD_enum_to_str.h
 *
 * Abstract: internal header file of BFD enum-to-string module
 *           this module displays BFD enumerations as string
 *
 * Nodes:    BFD implemenation should include only BFD_int_data.h instead
 *           of this file
 *
 ************************************************************************/

#ifndef BFD_ENUM_TO_STR_H
#define BFD_ENUM_TO_STR_H


/* function to display boolean as string */
const char *BFD_BOOL_to_str (BOOL false_true);

/* function to display BFD session state as string */
const char *BFD_SESS_STATE_to_str (BFD_SESS_STATE sess_state);

/* function to display BFD administrative state as string */
const char *BFD_ADMIN_STATE_to_str (BFD_ADMIN_STATE sess_state);

/* function to display BFD diagnostic as string */
const char *BFD_DIAGNOSTIC_to_str (BFD_DIAGNOSTIC diagnostic);

/* function to display BFD history type as string */
const char *BFD_HISTORY_TYPE_to_str (BFD_HISTORY_TYPE history_type);

/* function to display BFD role as string */
const char *BFD_ROLE_to_str (BFD_ROLE active_passive);

/* function to display BFD initialization type as string */
const char *BFD_INIT_TYPE_to_str (BFD_INIT_TYPE init_type);

/* function to display BFD audit sequence as string */
const char *BFD_AUDIT_SEQ_to_str (BFD_AUDIT_SEQ begin_middle_end);


#endif /* #ifndef BFD_ENUM_TO_STR_H */
