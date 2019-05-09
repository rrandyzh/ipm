include sel_operators.mk

BFD_SRC = \
	BFD_api.c \
	BFD_cfg.c \
	BFD_enum_to_str.c \
	BFD_fsm.c \
	BFD_history.c \
	BFD_msg.c \
	BFD_sess.c \
	BFD_sess_data.c \
	BFD_stats.c \
	BFD_timer.c \
	BFD_trans.c \
	$(ENDLIST)

linux_x86_ipm :CC2LST: $(BFD_SRC)
linux_vhe_ipm :CC2LST: $(BFD_SRC)
linux_x86-64_nff_ipm :CC2LST: $(BFD_SRC)
