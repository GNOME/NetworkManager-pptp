INCLUDES = -I${top_srcdir}

libexec_PROGRAMS = nm-pptp-auth-dialog

nm_pptp_auth_dialog_CPPFLAGS =			\
	$(NM_CFLAGS)		\
	$(GTHREAD_CFLAGS)			\
	$(GTK_CFLAGS)				\
	$(GNOMEKEYRING_CFLAGS)			\
	-DICONDIR=\""$(datadir)/pixmaps"\"	\
	-DUIDIR=\""$(uidir)"\"			\
	-DBINDIR=\""$(bindir)"\"		\
	-DG_DISABLE_DEPRECATED			\
	-DGDK_DISABLE_DEPRECATED		\
	-DGTK_DISABLE_DEPRECATED		\
	-DVERSION=\"$(VERSION)\"

nm_pptp_auth_dialog_SOURCES = \
	main.c \
	vpn-password-dialog.c \
	vpn-password-dialog.h

nm_pptp_auth_dialog_LDADD =			\
	$(GTK_LIBS)				\
	$(top_builddir)/common-gnome/libnm-pptp-common-gnome.la

CLEANFILES = *~
