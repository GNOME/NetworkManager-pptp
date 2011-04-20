INCLUDES = -I${top_srcdir}

libexec_PROGRAMS = nm-pptp-auth-dialog

nm_pptp_auth_dialog_CPPFLAGS =			\
	$(NETWORKMANAGER_CFLAGS)		\
	$(GTHREAD_CFLAGS)			\
	$(GTK_CFLAGS)				\
	$(GCONF_CFLAGS)				\
	$(GNOMEKEYRING_CFLAGS)			\
	-DICONDIR=\""$(datadir)/pixmaps"\"	\
	-DUIDIR=\""$(uidir)"\"			\
	-DBINDIR=\""$(bindir)"\"		\
	-DG_DISABLE_DEPRECATED			\
	-DGNOME_DISABLE_DEPRECATED		\
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"	\
	-DVERSION=\"$(VERSION)\"

nm_pptp_auth_dialog_SOURCES =			\
	main.c					\
	gnome-two-password-dialog.c		\
	gnome-two-password-dialog.h

nm_pptp_auth_dialog_LDADD =			\
	$(GTK_LIBS)				\
	$(GCONF_LIBS)				\
	$(top_builddir)/common-gnome/libnm-pptp-common-gnome.la

CLEANFILES = *~
