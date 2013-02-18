plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-pptp-properties.la

INCLUDES = -I${top_srcdir}

libnm_pptp_properties_la_SOURCES = \
	nm-pptp.c \
	nm-pptp.h \
	advanced-dialog.c \
	advanced-dialog.h \
	import-export.c \
	import-export.h

uidir = $(datadir)/gnome-vpn-properties/pptp
ui_DATA = nm-pptp-dialog.ui

libnm_pptp_properties_la_CFLAGS =                       \
        $(GTK_CFLAGS)                                   \
        $(NM_CFLAGS)                        \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DUIDIR=\""$(uidir)"\"                          \
        -DG_DISABLE_DEPRECATED                          \
        -DVERSION=\"$(VERSION)\"

libnm_pptp_properties_la_LIBADD = \
        $(GTK_LIBS) \
        $(NM_LIBS)

libnm_pptp_properties_la_LDFLAGS =   \
        -avoid-version

CLEANFILES = *.bak *~

EXTRA_DIST =                            \
        $(ui_DATA)
