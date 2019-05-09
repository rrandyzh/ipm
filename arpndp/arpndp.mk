include sel_operators.mk

ARPNDP_SRC = \
	ARPNDP_api.c \
	ARPNDP_enum_to_str.c \
	ARPNDP_fsm.c \
	ARPNDP_history.c \
	ARPNDP_sess.c \
	ARPNDP_sess_data.c \
	ARPNDP_stats.c \
	ARPNDP_timer.c \
	ARPNDP_trans.c \
	$(ENDLIST)

linux_x86_ipm :CC2LST: $(ARPNDP_SRC)
linux_vhe_ipm :CC2LST: $(ARPNDP_SRC)
linux_x86-64_nff_ipm :CC2LST: $(ARPNDP_SRC)
