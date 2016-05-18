plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-vpn-plugin-pptp.la
if WITH_LIBNM_GLIB
plugin_LTLIBRARIES += libnm-pptp-properties.la
endif

AM_CPPFLAGS = -I${top_srcdir}

plugin_sources = \
    nm-pptp-editor-plugin.c \
    nm-pptp-editor-plugin.h \
    import-export.c \
    import-export.h

editor_sources = \
    advanced-dialog.c \
    advanced-dialog.h \
    nm-pptp.c \
    nm-pptp.h

uidir = $(datadir)/gnome-vpn-properties/pptp
ui_DATA = nm-pptp-dialog.ui

common_CFLAGS = \
    $(GLIB_CFLAGS) \
    $(GTK_CFLAGS) \
    -I"$(top_srcdir)/shared" \
    -DICONDIR=\""$(datadir)/pixmaps"\" \
    -DUIDIR=\""$(uidir)"\" \
    -DLOCALEDIR=\""$(datadir)/locale"\"

###############################################################################

libnm_vpn_plugin_pptp_la_SOURCES = \
    $(plugin_sources) \
    $(editor_sources)

libnm_vpn_plugin_pptp_la_CFLAGS = \
    -DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
    $(common_CFLAGS) \
    $(LIBNMA_CFLAGS) \
    $(LIBNM_CFLAGS)

libnm_vpn_plugin_pptp_la_LIBADD = \
    $(GTK_LIBS) \
    $(LIBNMA_LIBS) \
    $(LIBNM_LIBS)

libnm_vpn_plugin_pptp_la_LDFLAGS = \
    -avoid-version \
    -Wl,--version-script="$(srcdir)/libnm-vpn-plugin-pptp.ver"

###############################################################################

libnm_pptp_properties_la_SOURCES = \
    $(plugin_sources) \
    $(editor_sources)

libnm_pptp_properties_la_CFLAGS = \
    -DNM_VPN_OLD \
    -DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB \
    $(common_CFLAGS) \
    $(LIBNM_GLIB_CFLAGS) \
    $(LIBNM_GTK_CFLAGS)

libnm_pptp_properties_la_LIBADD = \
    $(GTK_LIBS) \
    $(LIBNM_GLIB_LIBS) \
    $(LIBNM_GTK_LIBS)

libnm_pptp_properties_la_LDFLAGS = \
    -avoid-version \
    -Wl,--version-script="$(srcdir)/libnm-pptp-properties.ver"

###############################################################################

CLEANFILES = *.bak *~

EXTRA_DIST = \
    libnm-pptp-properties.ver \
    libnm-vpn-plugin-pptp.ver \
    nm-pptp-dialog.ui
