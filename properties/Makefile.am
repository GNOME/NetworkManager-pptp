plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpn-plugin-pptp.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-pptp-properties.la
endif

AM_CPPFLAGS = -I${top_srcdir}

plugin_sources = \
    nm-pptp.c \
    nm-pptp.h \
    advanced-dialog.c \
    advanced-dialog.h \
    import-export.c \
    import-export.h

uidir = $(datadir)/gnome-vpn-properties/pptp
ui_DATA = nm-pptp-dialog.ui

common_CFLAGS = \
    $(GLIB_CFLAGS) \
    $(GTK_CFLAGS) \
    -I$(top_srcdir)/src \
    -DICONDIR=\""$(datadir)/pixmaps"\" \
    -DUIDIR=\""$(uidir)"\" \
    -DLOCALEDIR=\""$(datadir)/locale"\"

###############################################################################

libnm_vpn_plugin_pptp_la_SOURCES = \
    $(plugin_sources)

libnm_vpn_plugin_pptp_la_CFLAGS = \
    $(common_CFLAGS) \
    $(LIBNMA_CFLAGS) \
    $(LIBNM_CFLAGS)

libnm_vpn_plugin_pptp_la_LIBADD = \
    $(GTK_LIBS) \
    $(LIBNMA_LIBS) \
    $(LIBNM_LIBS)

libnm_vpn_plugin_pptp_la_LDFLAGS = \
    -avoid-version

###############################################################################

libnm_pptp_properties_la_SOURCES = \
    $(plugin_sources)

libnm_pptp_properties_la_CFLAGS = \
    -DNM_VPN_OLD \
    $(common_CFLAGS) \
    $(LIBNM_GLIB_CFLAGS) \
    $(LIBNM_GTK_CFLAGS)

libnm_pptp_properties_la_LIBADD = \
    $(GTK_LIBS) \
    $(LIBNM_GLIB_LIBS) \
    $(LIBNM_GTK_LIBS)

libnm_pptp_properties_la_LDFLAGS = \
    -avoid-version

###############################################################################

CLEANFILES = *.bak *~

EXTRA_DIST = \
    $(ui_DATA)
