include $(VROOT)/lib/make/sel_operators.mk
include $(VROOT)/sde/database.mk

if "$(IS_VM)" == ""
SUB_DIRS :=
SUB_DIRS += $(VROOT)/glob/src/BSPcpsb
end

IPM_SRC = \
	ipm_spv.c \
	ipm_msg.c \
	ipm_init.c \
	ipm_util.c \
	nma_route.c \
	nma_gesip.c \
	nma_main.c \
	EIPM_init.c \
	EIPM_intf.c \
	EIPM_appl.c \
	EIPM_ipcfg.c \
	EIPM_route.c \
	EIPM_util.c \
	EIPM_bfd.c \
	EIPM_arpndp.c \
	ipm_addr.c \
	PIPM_appl.c \
	PIPM_init.c \
	PIPM_intf.c \
	PIPM_util.c \
	ipm_sighdl.c \
	$(ENDLIST)

VHE_IPM_SRC = \
	$(IPM_SRC) \
	EIPM_stubs.c \
	$(ENDLIST)

IPM_CLI_SRC = \
	ipm_cli.c \
	ipm_clnt_snd.c \
	$(ENDLIST)

RIPM_SRC = \
	nma_route.c \
	ripm.c \
	ripm_db.c \
	ipm_addr.c \
	$(ENDLIST)

TEST_SRC = \
	testapi.c \
	nma.c \
	$(ENDLIST)

WCNP_SRC = \
	EIPM_wcnp.c \
	$(ENDLIST)

ESALERT_SRC = \
	esalert.c \
	$(ENDLIST)

linux_x86_esalert :CC2LST: $(ESALERT_SRC)

linux_x86_ipm :CC2LST: $(IPM_SRC) $(WCNP_SRC)

linux_x86_ipm_cli :CC2LST: $(IPM_CLI_SRC)

linux_mips_ipm_cli :CC2LST: $(IPM_CLI_SRC)

linux_x86_ripm :CC2LST: $(RIPM_SRC)

linux_vhe_ipm :CC2LST: $(VHE_IPM_SRC)

linux_vhe_ipm_cli :CC2LST: $(IPM_CLI_SRC)

linux_x86-64_nff_ipm :CC2LST: $(VHE_IPM_SRC)

linux_x86-64_nff_ipm_cli :CC2LST: $(IPM_CLI_SRC)

LXLDFLAGS := -mt -shared

LX_LIBPATH_so = \
	-L$(SDE_RCC_LX)/lib \
	-L$(VROOT)/obj/$(SEL_TARGET)/glob/lib \
	-L$(VROOT)/obj/$(SEL_TARGET)/sde/lib \
	-L$(DB_LIB_DIR) \
	$(ENDLIST)

/* Define (archive) libraries which should be taken whole. */
LX_WALIBS :=
LX_WALIBS += libmaint_basic_api.a

LX_ALIBS = \
	libosutil.a \
	libcplmem.a \
	libbspcpsb.a \
	libbsplinux.a \
	libosutil.a \
	libbsplinux.a \
	libctxkmod.a \
	libLCPlogClient.a \
	$(LX_WALIBS) \
	$(ENDLIST)

/* This prevents nmake from removing the necessarily redundant libraries
*/
$(LX_ALIBS) : .MULTIPLE .SPECIAL

LX_LDFLAGS = -lpthread -lrt -lnsl -ldl

$(VROOT)/obj/$(SEL_TARGET)/glob/opt/LSS/sbin/esalert :LST2EXE: SEL=linux_x86_esalert \
		glob/src/ipm/linux_x86_esalert \
		glob/src/ipm/wcnp/linux_x86_ipm_wcnp_sim \
		$(ENDLIST)
	$(LNK) \
		$(LX_LDFLAGS) \
		$$(*.SOURCE.so:/^/-L) \
		$$(*:N=*.objfiles) \
		$$(*:M=^-l.*) \
		-Wl,-whole-archive \
		$$(*:N=*$(LX_WALIBS)) \
		-Wl,-no-whole-archive \
		$$(*:M=^.*\.a$) \
		-lrt \
		-lpthread \
		-o $$(<:D:B:S)

/* Generate the ipm process. */
$(VROOT)/obj/$(SEL_TARGET)/glob/opt/LSS/sbin/ipm :LST2EXE: SEL=linux_x86_ipm \
		glob/src/ipm/linux_x86_ipm \
		glob/src/ipm/bfd/linux_x86_ipm \
		glob/src/ipm/arpndp/linux_x86_ipm \
		glob/src/ipm/wcnp/linux_x86_ipm_wcnp \
		$(LX_ALIBS) \
		$(LX_LIBPATH_so) \
		$(ENDLIST)
	$(LNK) \
		$(LX_LDFLAGS) \
		$$(*.SOURCE.so:/^/-L) \
		$$(*:N=*.objfiles) \
		$$(*:M=^-l.*) \
		-Wl,-whole-archive \
		$$(*:N=*$(LX_WALIBS)) \
		-Wl,-no-whole-archive \
		$$(*:M=^.*\.a$) \
		-lrt \
		-lpthread \
		-o $$(<:D:B:S)

/* Generate the ipm_cli process. */
$(VROOT)/obj/$(SEL_TARGET)/glob/opt/LSS/sbin/ipm_cli :LST2EXE: SEL=linux_x86_ipm_cli \
		glob/src/ipm/linux_x86_ipm_cli \
		$(LX_ALIBS) \
		$(LX_LIBPATH_so) \
		$(ENDLIST)
	$(LNK) \
		$(LX_LDFLAGS) \
		$$(*.SOURCE.so:/^/-L) \
		$$(*:N=*.objfiles) \
		$$(*:M=^-l.*) \
		-Wl,-whole-archive \
		$$(*:N=*$(LX_WALIBS)) \
		-Wl,-no-whole-archive \
		$$(*:M=^.*\.a$) \
		-o $$(<:D:B:S)

$(VROOT)/obj/$(SEL_TARGET)/glob/opt/LSS/sbin/ipm_cli :LST2EXE: SEL=linux_mips_ipm_cli \
		glob/src/ipm/linux_mips_ipm_cli \
		$(LX_ALIBS) \
		-L$(VROOT)/obj/$(SEL_TARGET)/glob/lib \
		$(ENDLIST)
	$(LNK) \
		$(LX_LDFLAGS) \
		$$(*.SOURCE.so:/^/-L) \
		$$(*:N=*.objfiles) \
		$$(*:M=^-l.*) \
		-Wl,-whole-archive \
		$$(*:N=*$(LX_WALIBS)) \
		-Wl,-no-whole-archive \
		$$(*:M=^.*\.a$) \
		-o $$(<:D:B:S)

/* Generate the ipm process. */
$(VROOT)/obj/$(SEL_TARGET)/glob/opt/vcp/sbin/ipm :LST2EXE: SEL=linux_vhe_ipm \
		glob/src/ipm/linux_vhe_ipm \
		glob/src/ipm/bfd/linux_vhe_ipm \
		glob/src/ipm/arpndp/linux_vhe_ipm \
		$(ENDLIST)
	$(LNK) \
		$(LX_LDFLAGS) \
		$$(*.SOURCE.so:/^/-L) \
		$$(*:N=*.objfiles) \
		$$(*:M=^-l.*) \
		$$(*:M=^.*\.a$) \
		-lrt \
		-lpthread \
		-o $$(<:D:B:S)

/* Generate the ipm_cli process. */
$(VROOT)/obj/$(SEL_TARGET)/glob/opt/vcp/sbin/ipm_cli :LST2EXE: SEL=linux_vhe_ipm_cli \
		glob/src/ipm/linux_vhe_ipm_cli \
		$(ENDLIST)
	$(LNK) \
		$(LX_LDFLAGS) \
		$$(*.SOURCE.so:/^/-L) \
		$$(*:N=*.objfiles) \
		$$(*:M=^-l.*) \
		$$(*:M=^.*\.a$) \
		-o $$(<:D:B:S)

/* Generate the 64bit ipm process. */
$(VROOT)/obj/$(SEL_TARGET)/glob/opt/nff/sbin/ipm :LST2EXE: SEL=linux_x86-64_nff_ipm \
		glob/src/ipm/linux_x86-64_nff_ipm \
		glob/src/ipm/bfd/linux_x86-64_nff_ipm \
		glob/src/ipm/arpndp/linux_x86-64_nff_ipm \
		$(ENDLIST)
	$(LNK) \
		$(LX_LDFLAGS) \
		$$(*.SOURCE.so:/^/-L) \
		$$(*:N=*.objfiles) \
		$$(*:M=^-l.*) \
		$$(*:M=^.*\.a$) \
		-lrt \
		-lpthread \
		-o $$(<:D:B:S)

/* Generate the 64bit ipm_cli process. */
$(VROOT)/obj/$(SEL_TARGET)/glob/opt/nff/sbin/ipm_cli :LST2EXE: SEL=linux_x86-64_nff_ipm_cli \
		glob/src/ipm/linux_x86-64_nff_ipm_cli \
		$(ENDLIST)
	$(LNK) \
		$(LX_LDFLAGS) \
		$$(*.SOURCE.so:/^/-L) \
		$$(*:N=*.objfiles) \
		$$(*:M=^-l.*) \
		$$(*:M=^.*\.a$) \
		-o $$(<:D:B:S)

linux_x86_lib_ipm_cli :INHERITS: linux_x86_ipm_cli
linux_x86-64_lib_ipm_cli :INHERITS: linux_x86-64_ipm_cli
linux_mips_lib_ipm_cli :INHERITS: linux_mips_ipm_cli

linux_x86_lib_ipm_cli_c :ADD_OPT:	\
	-D_LIBRARY_IPM_CLI		\
	$(ENDLIST)

linux_x86-64_lib_ipm_cli_c :ADD_OPT:	\
	-D_LIBRARY_IPM_CLI		\
	$(ENDLIST)

linux_mips_lib_ipm_cli_c :ADD_OPT:	\
	-D_LIBRARY_IPM_CLI		\
	$(ENDLIST)

if "$(IS_MME)" != ""
linux_x86_lib_ipm_cli_c :ADD_OPT:	\
	-DMME
	$(ENDLIST)

linux_x86-64_lib_ipm_cli_c :ADD_OPT:	\
	-DMME
	$(ENDLIST)

linux_mips_lib_ipm_cli_c :ADD_OPT:	\
	-DMME
	$(ENDLIST)
end

TARGET_LIBDIR = $(VROOT)/obj/$(SEL_TARGET)/glob/lib

$(TARGET_LIBDIR)/libipm_cli.a :CC2AR: $(IPM_CLI_SRC)
		SEL=linux_x86_lib_ipm_cli		\
		SEL=linux_x86-64_lib_ipm_cli		\
		SEL=linux_mips_lib_ipm_cli		\
		$(ENDLIST)

/* Generate the ripm process. */
$(VROOT)/obj/$(SEL_TARGET)/glob/opt/LSS/sbin/ripmd :LST2EXE: SEL=linux_x86_ripm \
		glob/src/ipm/linux_x86_ripm \
		$(LX_ALIBS) \
		$(LX_LIBPATH_so) \
		$(ENDLIST)
	$(LNK) \
		$(LX_LDFLAGS) \
		$$(*:N=*.objfiles) \
		$$(*.SOURCE.so:C/^/-L/G) \
		-Wl,-whole-archive \
		$$(*:N=*$(LX_WALIBS)) \
		-Wl,-no-whole-archive \
		$$(*:M=^.*\.a$) \
		-lrt \
		-lpthread \
		-o $$(<:D:B:S)

$(VROOT)/obj/$(SEL_TARGET)/glob/etc/opt/LSS/ipm.cfg :FILEINSTALL: ipm.cfg.linux_x86  
	SEL=linux_x86

$(VROOT)/obj/$(SEL_TARGET)/glob/etc/opt/LSS/ipm.cfg :FILEINSTALL: ipm.cfg.linux_mips 
	SEL=linux_mips

$(VROOT)/obj/$(SEL_TARGET)/glob/etc/opt/vcp/ipm/ipm.cfg :FILEINSTALL: ipm.cfg.linux_vhe  
	SEL=linux_vhe

$(VROOT)/obj/$(SEL_TARGET)/glob/opt/LSS/sbin/shmc_activate :FILEINSTALL: shmc_activate.sh
	SEL=linux_x86

$(VROOT)/obj/$(SEL_TARGET)/glob/etc/opt/nff/ipm/ipm.cfg :FILEINSTALL: ipm.cfg.linux_nff
	SEL=linux_x86-64
