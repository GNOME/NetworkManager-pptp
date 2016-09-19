libexec_PROGRAMS = nm-pptp-service

noinst_LTLIBRARIES = libnm-pptp-pppd-service-dbus.la

shared_sources = \
    $(top_srcdir)/shared/nm-service-defines.h \
    $(top_srcdir)/shared/nm-utils/nm-vpn-plugin-macros.h

AM_CPPFLAGS = \
    $(GLIB_CFLAGS) \
    $(LIBNM_CFLAGS) \
    -I"${top_srcdir}/shared/" \
    -DBINDIR=\"$(bindir)\" \
    -DPREFIX=\""$(prefix)"\" \
    -DSYSCONFDIR=\""$(sysconfdir)"\" \
    -DLIBDIR=\""$(libdir)"\" \
    -DLIBEXECDIR=\""$(libexecdir)"\" \
    -DLOCALSTATEDIR=\""$(localstatedir)"\" \
    -DDATADIR=\"$(datadir)\" \
    -DNM_PPTP_LOCALEDIR=\"$(datadir)/locale\" \
    -DPLUGINDIR=\"$(PPPD_PLUGIN_DIR)\"

###############################################################################

nodist_libnm_pptp_pppd_service_dbus_la_SOURCES = \
    nm-pptp-pppd-service-dbus.c \
    nm-pptp-pppd-service-dbus.h

libnm_pptp_pppd_service_dbus_la_CPPFLAGS = $(filter-out -DGLIB_VERSION_MAX_ALLOWED%,$(AM_CPPFLAGS))

nm-pptp-pppd-service-dbus.h: $(top_srcdir)/src/nm-pptp-pppd-service.xml
	$(AM_V_GEN) gdbus-codegen \
		--generate-c-code $(basename $@) \
		--c-namespace NMDBus \
		--interface-prefix org.freedesktop.NetworkManager \
		$<

nm-pptp-pppd-service-dbus.c:
	@true

###############################################################################

nm_pptp_service_SOURCES = \
    $(shared_sources) \
    nm-pptp-service.c \
    nm-pptp-service.h

nm_pptp_service_LDADD = \
    $(GLIB_LIBS) \
    $(LIBNM_LIBS) \
    libnm-pptp-pppd-service-dbus.la

###############################################################################

pppd_plugindir = $(PPPD_PLUGIN_DIR)
pppd_plugin_LTLIBRARIES = nm-pptp-pppd-plugin.la

nm_pptp_pppd_plugin_la_SOURCES = \
    nm-pptp-pppd-plugin.c \
    nm-ppp-status.h

nm_pptp_pppd_plugin_la_CPPFLAGS = \
    -I"$(top_srcdir)/shared/" \
    $(GLIB_CFLAGS) \
    $(LIBNM_CFLAGS)

nm_pptp_pppd_plugin_la_LDFLAGS = -module -avoid-version

nm_pptp_pppd_plugin_la_LIBADD = \
    $(GLIB_LIBS) \
    $(LIBNM_LIBS)

###############################################################################

BUILT_SOURCES = \
    nm-pptp-pppd-service-dbus.h \
    nm-pptp-pppd-service-dbus.c

CLEANFILES = $(BUILT_SOURCES)

EXTRA_DIST = \
    nm-pptp-pppd-service.xml
