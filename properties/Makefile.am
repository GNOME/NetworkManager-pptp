plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-pptp-properties.la libnm-pptp-properties-old.la

AM_CPPFLAGS = -I${top_srcdir}

libnm_pptp_properties_la_SOURCES = \
	nm-pptp.c \
	nm-pptp.h \
	advanced-dialog.c \
	advanced-dialog.h \
	import-export.c \
	import-export.h

libnm_pptp_properties_old_la_SOURCES = \
	$(libnm_pptp_properties_la_SOURCES)

uidir = $(datadir)/gnome-vpn-properties/pptp
ui_DATA = nm-pptp-dialog.ui

common_CFLAGS =                                         \
        $(GLIB_CFLAGS)                                  \
        $(GTK_CFLAGS)                                   \
        -I$(top_srcdir)/src                             \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DUIDIR=\""$(uidir)"\"                          \
        -DLOCALEDIR=\""$(datadir)/locale"\"             \
        -DG_DISABLE_DEPRECATED                          \
        -DVERSION=\"$(VERSION)\"

libnm_pptp_properties_la_CFLAGS =                       \
        $(common_CFLAGS)                                \
        $(LIBNM_CFLAGS)                                 \
        $(LIBNMA_CFLAGS)

libnm_pptp_properties_old_la_CFLAGS =                   \
        -DNM_PPTP_OLD                                   \
        $(common_CFLAGS)                                \
        $(LIBNM_GLIB_CFLAGS)                            \
        $(LIBNM_GTK_CFLAGS)

libnm_pptp_properties_la_LIBADD = \
        $(GTK_LIBS) \
        $(LIBNM_LIBS) \
        $(LIBNMA_LIBS)

libnm_pptp_properties_old_la_LIBADD = \
        $(GTK_LIBS) \
        $(LIBNM_GLIB_LIBS) \
        $(LIBNM_GTK_LIBS)

libnm_pptp_properties_la_LDFLAGS =   \
        -avoid-version

libnm_pptp_properties_old_la_LDFLAGS =   \
        $(libnm_pptp_properties_la_LDFLAGS)

CLEANFILES = *.bak *~

EXTRA_DIST =                            \
        $(ui_DATA)
