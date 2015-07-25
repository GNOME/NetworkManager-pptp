/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-pptp-service - PPTP VPN integration with NetworkManager
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2008 - 2014 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ctype.h>
#include <locale.h>

#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

#include <NetworkManager.h>

#include "nm-pptp-service.h"
#include "nm-ppp-status.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

static gboolean debug = FALSE;

/********************************************************/
/* ppp plugin <-> pptp-service object                   */
/********************************************************/

/* Have to have a separate objec to handle ppp plugin requests since
 * dbus-glib doesn't allow multiple interfaces registed on one GObject.
 */

#define NM_TYPE_PPTP_PPP_SERVICE            (nm_pptp_ppp_service_get_type ())
#define NM_PPTP_PPP_SERVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_PPTP_PPP_SERVICE, NMPptpPppService))
#define NM_PPTP_PPP_SERVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_PPTP_PPP_SERVICE, NMPptpPppServiceClass))
#define NM_IS_PPTP_PPP_SERVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_PPTP_PPP_SERVICE))
#define NM_IS_PPTP_PPP_SERVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_PPTP_PPP_SERVICE))
#define NM_PPTP_PPP_SERVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_PPTP_PPP_SERVICE, NMPptpPppServiceClass))

typedef struct {
	GObject parent;
} NMPptpPppService;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*plugin_alive) (NMPptpPppService *self);
	void (*ppp_state) (NMPptpPppService *self, guint32 state);
	void (*ip4_config) (NMPptpPppService *self, GHashTable *config_hash);
} NMPptpPppServiceClass;

GType nm_pptp_ppp_service_get_type (void);

G_DEFINE_TYPE (NMPptpPppService, nm_pptp_ppp_service, G_TYPE_OBJECT)

static gboolean impl_pptp_service_need_secrets (NMPptpPppService *self,
                                                char **out_username,
                                                char **out_password,
                                                GError **err);

static gboolean impl_pptp_service_set_state (NMPptpPppService *self,
                                             guint32 state,
                                             GError **err);

static gboolean impl_pptp_service_set_ip4_config (NMPptpPppService *self,
                                                  GHashTable *config,
                                                  GError **err);

#include "nm-pptp-pppd-service-glue.h"


#define NM_PPTP_PPP_SERVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_PPTP_PPP_SERVICE, NMPptpPppServicePrivate))

typedef struct {
	char *username;
	char *domain;
	char *password;

	/* IP of PPtP gateway in numeric and string format */
	guint32 naddr;
	char *saddr;
} NMPptpPppServicePrivate;

enum {
	PLUGIN_ALIVE,
	PPP_STATE,
	IP4_CONFIG,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

static gboolean
_service_lookup_gateway (NMPptpPppService *self,
                         const char *src,
                         GError **error)
{
	NMPptpPppServicePrivate *priv = NM_PPTP_PPP_SERVICE_GET_PRIVATE (self);
	const char *p = src;
	gboolean is_name = FALSE;
	struct in_addr naddr;
	struct addrinfo hints;
	struct addrinfo *result = NULL, *rp;
	int err;
	char buf[INET_ADDRSTRLEN + 1];

	g_return_val_if_fail (src != NULL, FALSE);

	while (*p) {
		if (*p != '.' && !isdigit (*p)) {
			is_name = TRUE;
			break;
		}
		p++;
	}

	if (is_name == FALSE) {
		errno = 0;
		if (inet_pton (AF_INET, src, &naddr) <= 0) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
			             _("couldn't convert PPTP VPN gateway IP address '%s' (%d)"),
			             src, errno);
			return FALSE;
		}
		priv->naddr = naddr.s_addr;
		priv->saddr = g_strdup (src);
		return TRUE;
	}

	/* It's a hostname, resolve it */
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_ADDRCONFIG;
	err = getaddrinfo (src, NULL, &hints, &result);
	if (err != 0) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             _("couldn't look up PPTP VPN gateway IP address '%s' (%d)"),
		             src, err);
		return FALSE;
	}

	/* If the hostname resolves to multiple IP addresses, use the first one.
	 * FIXME: maybe we just want to use a random one instead?
	 */
	memset (&naddr, 0, sizeof (naddr));
	for (rp = result; rp; rp = rp->ai_next) {
		if (   (rp->ai_family == AF_INET)
		    && (rp->ai_addrlen == sizeof (struct sockaddr_in))) {
			struct sockaddr_in *inptr = (struct sockaddr_in *) rp->ai_addr;

			memcpy (&naddr, &(inptr->sin_addr), sizeof (struct in_addr));
			break;
		}
	}
	freeaddrinfo (result);

	if (naddr.s_addr == 0) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             _("no usable addresses returned for PPTP VPN gateway '%s'"),
		             src);
		return FALSE;
	}

	memset (buf, 0, sizeof (buf));
	errno = 0;
	if (inet_ntop (AF_INET, &naddr, buf, sizeof (buf) - 1) == NULL) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             _("no usable addresses returned for PPTP VPN gateway '%s' (%d)"),
		             src, errno);
		return FALSE;
	}

	priv->naddr = naddr.s_addr;
	priv->saddr = g_strdup (buf);
	return TRUE;
}

static gboolean
_service_cache_credentials (NMPptpPppService *self,
                            NMConnection *connection,
                            GError **error)
{
	NMPptpPppServicePrivate *priv = NM_PPTP_PPP_SERVICE_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	const char *username, *password, *domain;

	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (connection != NULL, FALSE);

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                     _("Could not find secrets (connection invalid, no vpn setting)."));
		return FALSE;
	}

	/* Username; try PPTP specific username first, then generic username */
	username = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_USER);
	if (!username || !*username) {
		username = nm_setting_vpn_get_user_name (s_vpn);
		if (!username || !*username) {
			g_set_error_literal (error,
			                     NM_VPN_PLUGIN_ERROR,
			                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
			                     _("Missing or invalid VPN username."));
			return FALSE;
		}
	}

	password = nm_setting_vpn_get_secret (s_vpn, NM_PPTP_KEY_PASSWORD);
	if (!password || !strlen (password)) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                     _("Missing or invalid VPN password."));
		return FALSE;
	}

	domain = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_DOMAIN);
	if (domain && strlen (domain))
		priv->domain = g_strdup (domain);

	priv->username = g_strdup (username);
	priv->password = g_strdup (password);
	return TRUE;
}

static NMPptpPppService *
nm_pptp_ppp_service_new (const char *gwaddr,
                         NMConnection *connection,
                         GError **error)
{
	NMPptpPppService *self = NULL;
	DBusGConnection *bus;
	DBusGProxy *proxy;
	gboolean success = FALSE;
	guint result;

	bus = dbus_g_bus_get (DBUS_BUS_SYSTEM, error);
	if (!bus)
		return NULL;
	dbus_connection_set_change_sigpipe (TRUE);

	proxy = dbus_g_proxy_new_for_name (bus,
	                                   "org.freedesktop.DBus",
	                                   "/org/freedesktop/DBus",
	                                   "org.freedesktop.DBus");
	g_assert (proxy);
	success = dbus_g_proxy_call (proxy, "RequestName", error,
	                             G_TYPE_STRING, NM_DBUS_SERVICE_PPTP_PPP,
	                             G_TYPE_UINT, 0,
	                             G_TYPE_INVALID,
	                             G_TYPE_UINT, &result,
	                             G_TYPE_INVALID);
	g_object_unref (proxy);
	if (success == FALSE)
		goto out;

	self = (NMPptpPppService *) g_object_new (NM_TYPE_PPTP_PPP_SERVICE, NULL);
	g_assert (self);

	/* Look up the IP address of the PPtP server; if the server has multiple
	 * addresses, because we can't get the actual IP used back from pptp itself,
	 * we need to do name->addr conversion here and only pass the IP address
	 * down to pppd/pptp.  If only pptp could somehow return the IP address it's
	 * using for the connection, we wouldn't need to do this...
	 */
	if (!_service_lookup_gateway (self, gwaddr, error)) {
		g_object_unref (self);
		self = NULL;
		goto out;
	}

	/* Cache the username and password so we can relay the secrets to the pppd
	 * plugin when it asks for them.
	 */
	if (!_service_cache_credentials (self, connection, error)) {
		g_object_unref (self);
		self = NULL;
		goto out;
	}

	dbus_g_connection_register_g_object (bus, NM_DBUS_PATH_PPTP_PPP, G_OBJECT (self));

out:
	dbus_g_connection_unref (bus);
	return self;
}

static const char *
nm_pptp_ppp_service_get_gw_address_string (NMPptpPppService *self)
{
	return NM_PPTP_PPP_SERVICE_GET_PRIVATE (self)->saddr;
}

static void
nm_pptp_ppp_service_init (NMPptpPppService *self)
{
}

static void
finalize (GObject *object)
{
	NMPptpPppServicePrivate *priv = NM_PPTP_PPP_SERVICE_GET_PRIVATE (object);

	/* Get rid of the cached username and password */
	g_free (priv->username);
	if (priv->password) {
		memset (priv->password, 0, strlen (priv->password));
		g_free (priv->password);
	}
	g_free (priv->domain);
	g_free (priv->saddr);
}

static void
nm_pptp_ppp_service_class_init (NMPptpPppServiceClass *service_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (service_class);

	g_type_class_add_private (service_class, sizeof (NMPptpPppServicePrivate));

	/* virtual methods */
	object_class->finalize = finalize;

	/* Signals */
	signals[PLUGIN_ALIVE] = 
		g_signal_new ("plugin-alive", 
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMPptpPppServiceClass, plugin_alive),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	signals[PPP_STATE] = 
		g_signal_new ("ppp-state", 
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMPptpPppServiceClass, ppp_state),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__UINT,
		              G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[IP4_CONFIG] = 
		g_signal_new ("ip4-config", 
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMPptpPppServiceClass, ip4_config),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__POINTER,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (service_class),
									 &dbus_glib_nm_pptp_pppd_service_object_info);
}

static gboolean
impl_pptp_service_need_secrets (NMPptpPppService *self,
                                char **out_username,
                                char **out_password,
                                GError **error)
{
	NMPptpPppServicePrivate *priv = NM_PPTP_PPP_SERVICE_GET_PRIVATE (self);

	g_signal_emit (G_OBJECT (self), signals[PLUGIN_ALIVE], 0);

	if (!strlen (priv->username) || !strlen (priv->password)) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		             "%s",
		             _("No cached credentials."));
		goto error;
	}

	/* Success */
	if (priv->domain && strlen (priv->domain))
		*out_username = g_strdup_printf ("%s\\%s", priv->domain, priv->username);
	else
		*out_username = g_strdup (priv->username);
	*out_password = g_strdup (priv->password);
	return TRUE;

error:
	return FALSE;
}

static gboolean
impl_pptp_service_set_state (NMPptpPppService *self,
                             guint32 pppd_state,
                             GError **err)
{
	g_signal_emit (G_OBJECT (self), signals[PLUGIN_ALIVE], 0);
	g_signal_emit (G_OBJECT (self), signals[PPP_STATE], 0, pppd_state);
	return TRUE;
}

static gboolean
impl_pptp_service_set_ip4_config (NMPptpPppService *self,
                                  GHashTable *config_hash,
                                  GError **err)
{
	g_message ("PPTP service (IP Config Get) reply received.");
	g_signal_emit (G_OBJECT (self), signals[PLUGIN_ALIVE], 0);

	/* Just forward the pppd plugin config up to our superclass; no need to modify it */
	g_signal_emit (G_OBJECT (self), signals[IP4_CONFIG], 0, config_hash);

	return TRUE;
}


/********************************************************/
/* The VPN plugin service                               */
/********************************************************/

G_DEFINE_TYPE (NMPptpPlugin, nm_pptp_plugin, NM_TYPE_VPN_SERVICE_PLUGIN)

typedef struct {
	GPid pid;
	guint32 ppp_timeout_handler;
	NMPptpPppService *service;
	NMConnection *connection;
} NMPptpPluginPrivate;

#define NM_PPTP_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_PPTP_PLUGIN, NMPptpPluginPrivate))

#define NM_PPTP_PPPD_PLUGIN PLUGINDIR "/nm-pptp-pppd-plugin.so"
#define NM_PPTP_WAIT_PPPD 10000 /* 10 seconds */
#define PPTP_SERVICE_SECRET_TRIES "pptp-service-secret-tries"

typedef struct {
	const char *name;
	GType type;
	gboolean required;
} ValidProperty;

static ValidProperty valid_properties[] = {
	{ NM_PPTP_KEY_GATEWAY,           G_TYPE_STRING, TRUE },
	{ NM_PPTP_KEY_USER,              G_TYPE_STRING, FALSE },
	{ NM_PPTP_KEY_DOMAIN,            G_TYPE_STRING, FALSE },
	{ NM_PPTP_KEY_REFUSE_EAP,        G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REFUSE_PAP,        G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REFUSE_CHAP,       G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REFUSE_MSCHAP,     G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REFUSE_MSCHAPV2,   G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REQUIRE_MPPE,      G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REQUIRE_MPPE_40,   G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REQUIRE_MPPE_128,  G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_MPPE_STATEFUL,     G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_NOBSDCOMP,         G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_NODEFLATE,         G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_NO_VJ_COMP,        G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_LCP_ECHO_FAILURE,  G_TYPE_UINT, FALSE },
	{ NM_PPTP_KEY_LCP_ECHO_INTERVAL, G_TYPE_UINT, FALSE },
	{ NM_PPTP_KEY_UNIT_NUM,          G_TYPE_UINT, FALSE },
	{ NM_PPTP_KEY_PASSWORD"-flags",  G_TYPE_UINT, FALSE },
	{ NULL,                          G_TYPE_NONE, FALSE }
};

static ValidProperty valid_secrets[] = {
	{ NM_PPTP_KEY_PASSWORD,          G_TYPE_STRING, FALSE },
	{ NULL,                          G_TYPE_NONE,   FALSE }
};

static gboolean
validate_gateway (const char *gateway)
{
	const char *p = gateway;

	if (!gateway || !strlen (gateway))
		return FALSE;

	/* Ensure it's a valid DNS name or IP address */
	p = gateway;
	while (*p) {
		if (!isalnum (*p) && (*p != '-') && (*p != '.'))
			return FALSE;
		p++;
	}
	return TRUE;
}

typedef struct ValidateInfo {
	ValidProperty *table;
	GError **error;
	gboolean have_items;
} ValidateInfo;

static void
validate_one_property (const char *key, const char *value, gpointer user_data)
{
	ValidateInfo *info = (ValidateInfo *) user_data;
	int i;

	if (*(info->error))
		return;

	info->have_items = TRUE;

	/* 'name' is the setting name; always allowed but unused */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	for (i = 0; info->table[i].name; i++) {
		ValidProperty prop = info->table[i];
		long int tmp;

		if (strcmp (prop.name, key))
			continue;

		switch (prop.type) {
		case G_TYPE_STRING:
			if (   !strcmp (prop.name, NM_PPTP_KEY_GATEWAY)
			    && !validate_gateway (value)) {
				g_set_error (info->error,
				             NM_VPN_PLUGIN_ERROR,
				             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				             _("invalid gateway '%s'"),
				             key);
				return;
			}
			return; /* valid */
		case G_TYPE_UINT:
			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (errno == 0)
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid integer property '%s'"),
			             key);
			break;
		case G_TYPE_BOOLEAN:
			if (!strcmp (value, "yes") || !strcmp (value, "no"))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid boolean property '%s' (not yes or no)"),
			             key);
			break;
		default:
			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("unhandled property '%s' type %s"),
			             key, g_type_name (prop.type));
			break;
		}
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!info->table[i].name) {
		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("property '%s' invalid or not supported"),
		             key);
	}
}

static gboolean
nm_pptp_properties_validate (NMSettingVpn *s_vpn,
                             GError **error)
{
	ValidateInfo info = { &valid_properties[0], error, FALSE };
	int i;

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("No VPN configuration options."));
		return FALSE;
	}

	if (*error)
		return FALSE;

	/* Ensure required properties exist */
	for (i = 0; valid_properties[i].name; i++) {
		ValidProperty prop = valid_properties[i];
		const char *value;

		if (!prop.required)
			continue;

		value = nm_setting_vpn_get_data_item (s_vpn, prop.name);
		if (!value || !strlen (value)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Missing required option '%s'."),
			             prop.name);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
nm_pptp_secrets_validate (NMSettingVpn *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_secrets[0], error, FALSE };

	nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("No VPN secrets!"));
		return FALSE;
	}

	return *error ? FALSE : TRUE;
}

static void
pppd_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMPptpPlugin *plugin = NM_PPTP_PLUGIN (user_data);
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);
	guint error = 0;

	if (WIFEXITED (status)) {
		error = WEXITSTATUS (status);
		if (error != 0)
			g_warning ("pppd exited with error code %d", error);
	}
	else if (WIFSTOPPED (status))
		g_warning ("pppd stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		g_warning ("pppd died with signal %d", WTERMSIG (status));
	else
		g_warning ("pppd died from an unknown cause");

	/* Reap child if needed. */
	waitpid (priv->pid, NULL, WNOHANG);
	priv->pid = 0;

	/* Must be after data->state is set since signals use data->state */
	switch (error) {
	case 16:
		/* hangup */
		// FIXME: better failure reason
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	case 2:
		/* Couldn't log in due to bad user/pass */
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED);
		break;
	case 1:
		/* Other error (couldn't bind to address, etc) */
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	default:
		break;
	}

	nm_vpn_service_plugin_set_state (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_SERVICE_STATE_STOPPED);
}

static inline const char *
nm_find_pppd (void)
{
	static const char *pppd_binary_paths[] =
		{
			"/sbin/pppd",
			"/usr/sbin/pppd",
			"/usr/local/sbin/pppd",
			NULL
		};

	const char  **pppd_binary = pppd_binary_paths;

	while (*pppd_binary != NULL) {
		if (g_file_test (*pppd_binary, G_FILE_TEST_EXISTS))
			break;
		pppd_binary++;
	}

	return *pppd_binary;
}

static inline const char *
nm_find_pptp (void)
{
	static const char *pptp_binary_paths[] =
		{
			"/sbin/pptp",
			"/usr/sbin/pptp",
			"/usr/local/sbin/pptp",
			NULL
		};

	const char  **pptp_binary = pptp_binary_paths;

	while (*pptp_binary != NULL) {
		if (g_file_test (*pptp_binary, G_FILE_TEST_EXISTS))
			break;
		pptp_binary++;
	}

	return *pptp_binary;
}

static gboolean
pppd_timed_out (gpointer user_data)
{
	NMPptpPlugin *plugin = NM_PPTP_PLUGIN (user_data);

	g_warning ("Looks like pppd didn't initialize our dbus module");
	nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_CONNECTION_STATE_REASON_SERVICE_START_TIMEOUT);

	return FALSE;
}

static void
free_pppd_args (GPtrArray *args)
{
	int i;

	if (!args)
		return;

	for (i = 0; i < args->len; i++)
		g_free (g_ptr_array_index (args, i));
	g_ptr_array_free (args, TRUE);
}

static gboolean
str_to_int (const char *str, long int *out)
{
	long int tmp_int;

	if (!str)
		return FALSE;

	errno = 0;
	tmp_int = strtol (str, NULL, 10);
	if (errno == 0) {
		*out = tmp_int;
		return TRUE;
	}
	return FALSE;
}

static GPtrArray *
construct_pppd_args (NMPptpPlugin *plugin,
                     NMSettingVpn *s_vpn,
                     const char *pppd,
                     const char *gwaddr,
                     GError **error)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);
	NMPptpPppServicePrivate *service_priv = NULL;
	GPtrArray *args = NULL;
	const char *value, *pptp_binary;
	char *ipparam, *tmp;
	const char *loglevel0 = "--loglevel 0";
	const char *loglevel2 = "--loglevel 2";

	pptp_binary = nm_find_pptp ();
	if (!pptp_binary) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "%s",
		             _("Could not find pptp client binary."));
		return FALSE;
	}

	args = g_ptr_array_new ();
	g_ptr_array_add (args, (gpointer) g_strdup (pppd));

	/* PPTP options */
	if (!gwaddr || !strlen (gwaddr)) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		             "%s",
		             _("Missing VPN gateway."));
		goto error;
	}

	ipparam = g_strdup_printf ("nm-pptp-service-%d", getpid ());

	g_ptr_array_add (args, (gpointer) g_strdup ("pty"));
	tmp = g_strdup_printf ("%s %s --nolaunchpppd %s --logstring %s",
	                       pptp_binary, gwaddr,
	                       debug ? loglevel2 : loglevel0,
	                       ipparam);
	g_ptr_array_add (args, (gpointer) tmp);

	if (debug)
		g_ptr_array_add (args, (gpointer) g_strdup ("debug"));

	/* PPP options */
	g_ptr_array_add (args, (gpointer) g_strdup ("ipparam"));
	g_ptr_array_add (args, (gpointer) ipparam);

	g_ptr_array_add (args, (gpointer) g_strdup ("nodetach"));
	g_ptr_array_add (args, (gpointer) g_strdup ("lock"));
	g_ptr_array_add (args, (gpointer) g_strdup ("usepeerdns"));
	g_ptr_array_add (args, (gpointer) g_strdup ("noipdefault"));
	g_ptr_array_add (args, (gpointer) g_strdup ("nodefaultroute"));

	/* Don't need to auth the PPTP server */
	g_ptr_array_add (args, (gpointer) g_strdup ("noauth"));

	if (priv->service)
		service_priv = NM_PPTP_PPP_SERVICE_GET_PRIVATE (priv->service);
	if (service_priv && strlen (service_priv->username)) {
		g_ptr_array_add (args, (gpointer) g_strdup ("user"));
		g_ptr_array_add (args, (gpointer) g_strdup (service_priv->username));
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REFUSE_EAP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("refuse-eap"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REFUSE_PAP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("refuse-pap"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REFUSE_CHAP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("refuse-chap"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REFUSE_MSCHAP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("refuse-mschap"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REFUSE_MSCHAPV2);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("refuse-mschap-v2"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REQUIRE_MPPE);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("require-mppe"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REQUIRE_MPPE_40);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("require-mppe-40"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REQUIRE_MPPE_128);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("require-mppe-128"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_MPPE_STATEFUL);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("mppe-stateful"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_NOBSDCOMP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("nobsdcomp"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_NODEFLATE);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("nodeflate"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_NO_VJ_COMP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("novj"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_LCP_ECHO_FAILURE);
	if (value && strlen (value)) {
		long int tmp_int;

		/* Convert to integer and then back to string for security's sake
		 * because strtol ignores some leading and trailing characters.
		 */
		errno = 0;
		tmp_int = strtol (value, NULL, 10);
		if (errno == 0) {
			g_ptr_array_add (args, (gpointer) g_strdup ("lcp-echo-failure"));
			g_ptr_array_add (args, (gpointer) g_strdup_printf ("%ld", tmp_int));
		} else {
			g_warning ("failed to convert lcp-echo-failure value '%s'", value);
		}
	} else {
		g_ptr_array_add (args, (gpointer) g_strdup ("lcp-echo-failure"));
		g_ptr_array_add (args, (gpointer) g_strdup ("0"));
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_LCP_ECHO_INTERVAL);
	if (value && *value) {
		long int tmp_int;

		/* Convert to integer and then back to string for security's sake
		 * because strtol ignores some leading and trailing characters.
		 */
		if (str_to_int (value, &tmp_int)) {
			g_ptr_array_add (args, (gpointer) g_strdup ("lcp-echo-interval"));
			g_ptr_array_add (args, (gpointer) g_strdup_printf ("%ld", tmp_int));
		} else {
			g_warning ("failed to convert lcp-echo-interval value '%s'", value);
		}
	} else {
		g_ptr_array_add (args, (gpointer) g_strdup ("lcp-echo-interval"));
		g_ptr_array_add (args, (gpointer) g_strdup ("0"));
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_UNIT_NUM);
	if (value && *value) {
		long int tmp_int;
		if (str_to_int (value, &tmp_int)) {
			g_ptr_array_add (args, (gpointer) g_strdup ("unit"));
			g_ptr_array_add (args, (gpointer) g_strdup_printf ("%ld", tmp_int));
		} else
			g_warning ("failed to convert unit value '%s'", value);
	}

	g_ptr_array_add (args, (gpointer) g_strdup ("plugin"));
	g_ptr_array_add (args, (gpointer) g_strdup (NM_PPTP_PPPD_PLUGIN));

	g_ptr_array_add (args, NULL);

	return args;

error:
	free_pppd_args (args);
	return FALSE;
}

static gboolean
nm_pptp_start_pppd_binary (NMPptpPlugin *plugin,
                           NMSettingVpn *s_vpn,
                           const char *gwaddr,
                           GError **error)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);
	GPid pid;
	const char *pppd_binary;
	GPtrArray *pppd_argv;

	pppd_binary = nm_find_pppd ();
	if (!pppd_binary) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "%s",
		             _("Could not find the pppd binary."));
		return FALSE;
	}

	pppd_argv = construct_pppd_args (plugin, s_vpn, pppd_binary, gwaddr, error);
	if (!pppd_argv)
		return FALSE;

	if (!g_spawn_async (NULL, (char **) pppd_argv->pdata, NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, error)) {
		g_ptr_array_free (pppd_argv, TRUE);
		return FALSE;
	}
	free_pppd_args (pppd_argv);

	g_message ("pppd started with pid %d", pid);

	NM_PPTP_PLUGIN_GET_PRIVATE (plugin)->pid = pid;
	g_child_watch_add (pid, pppd_watch_cb, plugin);

	priv->ppp_timeout_handler = g_timeout_add (NM_PPTP_WAIT_PPPD, pppd_timed_out, plugin);

	return TRUE;
}

static void
remove_timeout_handler (NMPptpPlugin *plugin)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);
	
	if (priv->ppp_timeout_handler) {
		g_source_remove (priv->ppp_timeout_handler);
		priv->ppp_timeout_handler = 0;
	}
}

static void
service_plugin_alive_cb (NMPptpPppService *service,
                         NMPptpPlugin *plugin)
{
	remove_timeout_handler (plugin);
}

static void
service_ppp_state_cb (NMPptpPppService *service,
                      guint32 ppp_state,
                      NMPptpPlugin *plugin)
{
	NMVpnServiceState plugin_state = nm_vpn_service_plugin_get_state (NM_VPN_SERVICE_PLUGIN (plugin));

	switch (ppp_state) {
	case NM_PPP_STATUS_DEAD:
	case NM_PPP_STATUS_DISCONNECT:
		if (plugin_state == NM_VPN_SERVICE_STATE_STARTED)
			nm_vpn_service_plugin_disconnect (NM_VPN_SERVICE_PLUGIN (plugin), NULL);
		else if (plugin_state == NM_VPN_SERVICE_STATE_STARTING)
			nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	default:
		break;
	}
}

static void
service_ip4_config_cb (NMPptpPppService *service,
                       GHashTable *config_hash,
                       NMVpnServicePlugin *plugin)
{
	NMPptpPppServicePrivate *priv = NM_PPTP_PPP_SERVICE_GET_PRIVATE (service);
	GHashTableIter iter;
	char *key;
	GValue *value;
	GVariantBuilder builder;
	GVariant *new_config;
	GVariant *tmp;

        g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	g_hash_table_iter_init (&iter, config_hash);
	while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &value)) {
		if (G_VALUE_HOLDS_STRING (value))
			tmp = g_variant_new_string (g_value_get_string (value));
		else if (G_VALUE_HOLDS_UINT (value))
			tmp = g_variant_new_uint32 (g_value_get_uint (value));
		else if (G_VALUE_HOLDS (value, DBUS_TYPE_G_UINT_ARRAY)) {
			GArray *arr = g_value_get_boxed (value);
			tmp = g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32, arr->data, arr->len, sizeof (guint32));
		} else
			tmp = NULL;

		if (tmp)
			g_variant_builder_add (&builder, "{sv}", key, tmp);
	}

	/* Insert the external VPN gateway into the table, which the pppd plugin
	 * simply doesn't know about.
	 */
	g_variant_builder_add (&builder, "{sv}", NM_PPTP_KEY_GATEWAY, g_variant_new_uint32 (priv->naddr));
	new_config = g_variant_builder_end (&builder);
	g_variant_ref_sink (new_config);

	nm_vpn_service_plugin_set_ip4_config (plugin, new_config);
	g_variant_unref (new_config);
}

static gboolean
real_connect (NMVpnServicePlugin *plugin,
              NMConnection *connection,
              GError **error)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);
	NMSettingVpn *s_vpn;
	const char *gwaddr;

	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	gwaddr = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_GATEWAY);
	if (!gwaddr || !strlen (gwaddr)) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		                     _("Invalid or missing PPTP gateway."));
		return FALSE;
	}

	if (!nm_pptp_properties_validate (s_vpn, error))
		return FALSE;

	if (!nm_pptp_secrets_validate (s_vpn, error))
		return FALSE;

	/* Start our pppd plugin helper service */
	g_clear_object (&priv->service);
	g_clear_object (&priv->connection);

	/* Start our helper D-Bus service that the pppd plugin sends state changes to */
	priv->service = nm_pptp_ppp_service_new (gwaddr, connection, error);
	if (!priv->service)
		return FALSE;

	priv->connection = g_object_ref (connection);

	g_signal_connect (G_OBJECT (priv->service), "plugin-alive", G_CALLBACK (service_plugin_alive_cb), plugin);
	g_signal_connect (G_OBJECT (priv->service), "ppp-state", G_CALLBACK (service_ppp_state_cb), plugin);
	g_signal_connect (G_OBJECT (priv->service), "ip4-config", G_CALLBACK (service_ip4_config_cb), plugin);

	if (getenv ("NM_PPP_DUMP_CONNECTION") || debug)
		nm_connection_dump (connection);

	return nm_pptp_start_pppd_binary (NM_PPTP_PLUGIN (plugin),
	                                  s_vpn,
	                                  nm_pptp_ppp_service_get_gw_address_string (priv->service),
	                                  error);
}

static gboolean
real_need_secrets (NMVpnServicePlugin *plugin,
                   NMConnection *connection,
                   const char **setting_name,
                   GError **error)
{
	NMSettingVpn *s_vpn;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	g_return_val_if_fail (NM_IS_VPN_SERVICE_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn = nm_connection_get_setting_vpn (connection);

	nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_PPTP_KEY_PASSWORD, &flags, NULL);

	/* Don't need the password if it's not required */
	if (flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
		return FALSE;

	/* Don't need the password if we already have one */
	if (nm_setting_vpn_get_secret (NM_SETTING_VPN (s_vpn), NM_PPTP_KEY_PASSWORD))
		return FALSE;

	/* Otherwise we need a password */
	*setting_name = NM_SETTING_VPN_SETTING_NAME;
	return TRUE;
}

static gboolean
ensure_killed (gpointer data)
{
	int pid = GPOINTER_TO_INT (data);

	if (kill (pid, 0) == 0)
		kill (pid, SIGKILL);

	return FALSE;
}

static gboolean
real_disconnect (NMVpnServicePlugin *plugin, GError **err)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);

	if (priv->pid) {
		if (kill (priv->pid, SIGTERM) == 0)
			g_timeout_add (2000, ensure_killed, GINT_TO_POINTER (priv->pid));
		else
			kill (priv->pid, SIGKILL);

		g_message ("Terminated ppp daemon with PID %d.", priv->pid);
		priv->pid = 0;
	}

	g_clear_object (&priv->connection);
	g_clear_object (&priv->service);

	return TRUE;
}

static void
state_changed_cb (GObject *object, NMVpnServiceState state, gpointer user_data)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (object);

	switch (state) {
	case NM_VPN_SERVICE_STATE_STARTED:
		remove_timeout_handler (NM_PPTP_PLUGIN (object));
		break;
	case NM_VPN_SERVICE_STATE_UNKNOWN:
	case NM_VPN_SERVICE_STATE_INIT:
	case NM_VPN_SERVICE_STATE_SHUTDOWN:
	case NM_VPN_SERVICE_STATE_STOPPING:
	case NM_VPN_SERVICE_STATE_STOPPED:
		remove_timeout_handler (NM_PPTP_PLUGIN (object));
		g_clear_object (&priv->connection);
		g_clear_object (&priv->service);
		break;
	default:
		break;
	}
}

static void
dispose (GObject *object)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (object);

	g_clear_object (&priv->connection);
	g_clear_object (&priv->service);

	G_OBJECT_CLASS (nm_pptp_plugin_parent_class)->dispose (object);
}

static void
nm_pptp_plugin_init (NMPptpPlugin *plugin)
{
}

static void
nm_pptp_plugin_class_init (NMPptpPluginClass *pptp_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (pptp_class);
	NMVpnServicePluginClass *parent_class = NM_VPN_SERVICE_PLUGIN_CLASS (pptp_class);

	g_type_class_add_private (object_class, sizeof (NMPptpPluginPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
	parent_class->connect    = real_connect;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect = real_disconnect;
}

NMPptpPlugin *
nm_pptp_plugin_new (void)
{
	NMPptpPlugin *plugin;
	GError *error = NULL;

	plugin = g_initable_new (NM_TYPE_PPTP_PLUGIN, NULL, &error,
	                         NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME,
	                         NM_DBUS_SERVICE_PPTP,
	                         NULL);
	if (plugin)
		g_signal_connect (G_OBJECT (plugin), "state-changed", G_CALLBACK (state_changed_cb), NULL);

	if (debug && error)
		g_message ("Error: failed to create NMPptpPlugin: %s", error->message);
	g_clear_error (&error);

	return plugin;
}

static void
quit_mainloop (NMPptpPlugin *plugin, gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
}

int
main (int argc, char *argv[])
{
	NMPptpPlugin *plugin;
	GMainLoop *main_loop;
	gboolean persist = FALSE;
	GOptionContext *opt_ctx = NULL;
	char *conntrack_module[] = { "/sbin/modprobe", "nf_conntrack_pptp", NULL };
	GError *error = NULL;

	GOptionEntry options[] = {
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &persist, N_("Don't quit when VPN connection terminates"), NULL },
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &debug, N_("Enable verbose debug logging (may expose passwords)"), NULL },
		{NULL}
	};

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	/* locale will be set according to environment LC_* variables */
	setlocale (LC_ALL, "");

	bindtextdomain (GETTEXT_PACKAGE, NM_PPTP_LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	/* Parse options */
	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_translation_domain (opt_ctx, GETTEXT_PACKAGE);
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);

	g_option_context_set_summary (opt_ctx,
	    _("nm-pptp-service provides integrated PPTP VPN capability (compatible with Microsoft and other implementations) to NetworkManager."));

	g_option_context_parse (opt_ctx, &argc, &argv, NULL);
	g_option_context_free (opt_ctx);

	if (getenv ("NM_PPP_DEBUG"))
		debug = TRUE;

	if (debug)
		g_message ("nm-pptp-service (version " DIST_VERSION ") starting...");

	plugin = nm_pptp_plugin_new ();
	if (!plugin)
		exit (EXIT_FAILURE);

	main_loop = g_main_loop_new (NULL, FALSE);

	if (!persist)
		g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), main_loop);

	/* Newer kernels require nf_conntrack_pptp kernel module so that PPTP
	 * worked correctly. Load the module now. Ignore errors, the module
	 * might not exist (older kernels).
	 * https://bugzilla.redhat.com/show_bug.cgi?id=1187328
	 */
	if (!g_spawn_sync (NULL, conntrack_module, NULL, 0, NULL, NULL, NULL, NULL, NULL, &error)) {
		g_warning ("modprobing nf_conntrack_pptp failed: %s", error->message);
		g_error_free (error);
	}

	g_main_loop_run (main_loop);

	g_main_loop_unref (main_loop);
	g_object_unref (plugin);

	exit (EXIT_SUCCESS);
}
